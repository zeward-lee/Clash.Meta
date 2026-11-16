package xhttpstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

const (
	testSecret = "Zx9-test-secret"
	testHmac   = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testFake   = "16030100c5010000c10303"
)

func testCipher(t *testing.T) *StreamCipher {
	t.Helper()
	ciph, err := PickCipher("aes-128-ctr", nil, testSecret+":"+testHmac, map[string]string{"tcp": testFake, "udp": testFake})
	if err != nil {
		t.Fatalf("PickCipher: %v", err)
	}
	return ciph
}

// fakeServer speaks the client handshake described on Conn and echoes the
// payload back, so the test covers both directions of the format.
func fakeServer(t *testing.T, listener net.Listener, ciph *StreamCipher) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	key := Kdf(testSecret, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("server cipher: %v", err)
		return
	}
	prefix := make([]byte, FakePrefixLen)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		t.Errorf("server read prefix: %v", err)
		return
	}
	fake, _ := hex.DecodeString(testFake)
	if !bytes.HasPrefix(prefix, fake) {
		t.Errorf("server prefix does not start with fake-net bytes: %x", prefix[:len(fake)])
	}
	hmacLen := len(ciph.hmac)
	token := make([]byte, 16)
	if _, err := io.ReadFull(conn, token); err != nil {
		t.Errorf("server read token: %v", err)
		return
	}
	if !bytes.Equal(token, ciph.token) {
		t.Errorf("server token mismatch")
		return
	}
	hmac := make([]byte, hmacLen)
	if _, err := io.ReadFull(conn, hmac); err != nil {
		t.Errorf("server read hmac: %v", err)
		return
	}
	if !bytes.Equal(hmac, ciph.hmac) {
		t.Errorf("server hmac mismatch")
		return
	}
	ivLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ivLen); err != nil {
		t.Errorf("server read iv len: %v", err)
		return
	}
	if int(ivLen[0]) != 16 {
		t.Errorf("server iv len = %d, want 16", ivLen[0])
		return
	}
	writeIV := make([]byte, 16)
	if _, err := io.ReadFull(conn, writeIV); err != nil {
		t.Errorf("server read iv: %v", err)
		return
	}
	dec := NewReader(conn, cipher.NewCTR(block, writeIV))

	// Reply handshake: forged prefix, echoed token, empty preamble, IV length
	// and the read IV.
	serverPrefix := make([]byte, FakePrefixLen)
	if _, err := rand.Read(serverPrefix); err != nil {
		t.Errorf("server prefix: %v", err)
		return
	}
	serverIV := make([]byte, 16)
	if _, err := rand.Read(serverIV); err != nil {
		t.Errorf("server iv: %v", err)
		return
	}
	header := append(serverPrefix, ciph.token...)
	header = append(header, 0x00, byte(len(serverIV)))
	header = append(header, serverIV...)
	if _, err := conn.Write(header); err != nil {
		t.Errorf("server write header: %v", err)
		return
	}
	enc := NewWriter(conn, cipher.NewCTR(block, serverIV))

	// The first encrypted bytes are the SOCKS destination.
	dest := make([]byte, 1+1+len("example.com")+2)
	dest[0] = 0x03
	dest[1] = byte(len("example.com"))
	copy(dest[2:], "example.com")
	dest[len(dest)-2] = 0x01
	dest[len(dest)-1] = 0xbb
	gotDest := make([]byte, len(dest))
	if _, err := io.ReadFull(dec, gotDest); err != nil {
		t.Errorf("server read destination: %v", err)
		return
	}
	if !bytes.Equal(gotDest, dest) {
		t.Errorf("server destination = %x, want %x", gotDest, dest)
		return
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(dec, payload); err != nil {
		t.Errorf("server read payload: %v", err)
		return
	}
	if string(payload) != "hello" {
		t.Errorf("server payload = %q", payload)
	}
	if _, err := enc.Write([]byte("world")); err != nil {
		t.Errorf("server write: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
}

func TestStreamHandshakeRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()
	ciph := testCipher(t)
	go fakeServer(t, listener, ciph)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	destination := []byte{0x03, 0x0b}
	destination = append(destination, []byte("example.com")...)
	destination = append(destination, 0x01, 0xbb)
	stream := ciph.StreamConn(conn, destination)
	defer stream.Close()
	if handshaker, ok := stream.(interface{ NeedHandshake() bool }); !ok || !handshaker.NeedHandshake() {
		t.Fatal("fresh Conn should report NeedHandshake")
	}
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("echo = %q, want world", got)
	}
}

func TestReadRejectsForeignToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		prefix := make([]byte, FakePrefixLen)
		_, _ = rand.Read(prefix)
		wrongToken := bytes.Repeat([]byte{0xaa}, 16)
		_, _ = conn.Write(append(prefix, wrongToken...))
	}()

	ciph := testCipher(t)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	stream := ciph.StreamConn(conn, nil)
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Read(make([]byte, 1)); err != ErrInvalidToken {
		t.Fatalf("Read error = %v, want ErrInvalidToken", err)
	}
}

func TestPickCipherRejectsBadPassword(t *testing.T) {
	if _, err := PickCipher("aes-128-ctr", nil, "no-colon", nil); err == nil {
		t.Fatal("password without a hmac part should fail")
	}
	if _, err := PickCipher("aes-128-ctr", nil, "secret:zz", nil); err == nil {
		t.Fatal("non-hex hmac key should fail")
	}
	if _, err := PickCipher("chacha20", nil, testSecret+":"+testHmac, nil); err == nil {
		t.Fatal("unsupported cipher should fail")
	}
}

func TestTokenMatchesVendorFormula(t *testing.T) {
	// md5("<secret>" + "do not hack this protocol please")
	sum := md5.Sum([]byte("secret" + "do not hack this protocol please"))
	if !bytes.Equal(Token("secret"), sum[:]) {
		t.Fatalf("Token(secret) = %x, want %x", Token("secret"), sum)
	}
	if bytes.Equal(Token("secret"), Token("secret2")) {
		t.Fatal("different secrets produced the same token")
	}
}
