package outbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/crypto/chacha20poly1305"
)

func decodeXhttpOption(t *testing.T, mapping map[string]any) XhttpOption {
	t.Helper()
	option := XhttpOption{}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(mapping, &option); err != nil {
		t.Fatalf("decode option: %v", err)
	}
	return option
}

// TestXhttpOptionReadsVendorNode feeds the adapter a node copied from a Heysocks
// subscription (the 21-key shape recovered from the app memory dump) and checks
// that every key the transport needs lands on the option struct.
func TestXhttpOptionReadsVendorNode(t *testing.T) {
	option := decodeXhttpOption(t, map[string]any{
		"name":            "Hey 7 | HK",
		"type":            "xhttp",
		"server":          "203.0.113.9",
		"port":            50775,
		"password":        "transport-secret:00112233445566778899aabbccddeeff",
		"cipher":          "aes-128-ctr",
		"udp":             true,
		"udp-over-tcp":    true,
		"padding-len":     "8-64",
		"fake-net":        map[string]any{"tcp": "16030100", "udp": "16030100"},
		"uuid":            "00000000-0000-0000-0000-000000000000",
		"tls":             true,
		"servername":      "apple.com",
		"alpn":            []any{"h2"},
		"certificate":     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"private-key":     "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
		"clover":          "198.51.100.7",
		"encryption":      "fake-net",
		"network":         "xhttp",
		"up-speed":        "10",
		"xhttp-opts":      map[string]any{"host": "apple.com", "path": "/hEK8lz27"},
	})
	if option.Server != "203.0.113.9" || option.Port != 50775 {
		t.Fatalf("server/port = %s/%d", option.Server, option.Port)
	}
	if option.Cipher != "aes-128-ctr" || !option.UDP || !option.UDPOverTCP {
		t.Fatalf("cipher/udp = %q/%v/%v", option.Cipher, option.UDP, option.UDPOverTCP)
	}
	if option.PaddingLen != "8-64" {
		t.Fatalf("padding-len = %q", option.PaddingLen)
	}
	if option.FakeNet["tcp"] != "16030100" || option.FakeNet["udp"] != "16030100" {
		t.Fatalf("fake-net = %v", option.FakeNet)
	}
	if option.ServerName != "apple.com" || option.XHTTPOpts.Path != "/hEK8lz27" {
		t.Fatalf("servername/xhttp-opts = %q/%q", option.ServerName, option.XHTTPOpts.Path)
	}
	proxy, err := NewXhttp(option)
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if proxy.Type() != C.XHttp {
		t.Fatalf("type = %v", proxy.Type())
	}
	if !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatal("UDP support flags not derived from udp/udp-over-tcp")
	}
	if proxy.option.UDPOverTCPVersion != 0 {
		t.Fatalf("udp-over-tcp-version = %d", proxy.option.UDPOverTCPVersion)
	}
}

func TestNewXhttpRejectsBadNodes(t *testing.T) {
	cases := []map[string]any{
		{"server": "", "port": 1, "password": "a:00"},
		{"server": "example.com", "port": 0, "password": "a:00"},
		{"server": "example.com", "port": 70000, "password": "a:00"},
		{"server": "example.com", "port": 443, "password": "no-hmac-part"},
		{"server": "example.com", "port": 443, "password": "a:zz"},
		{"server": "example.com", "port": 443, "password": "a:00", "cipher": "chacha20"},
		{"server": "example.com", "port": 443, "password": "a:00", "padding-len": "64-8"},
		{"server": "example.com", "port": 443, "password": "a:00", "udp-over-tcp-version": 9},
	}
	for _, mapping := range cases {
		option := decodeXhttpOption(t, mapping)
		if _, err := NewXhttp(option); err == nil {
			t.Fatalf("NewXhttp accepted %v", mapping)
		}
	}
}

// xhttpTestKDF mirrors the vendor VMess AEAD KDF so the test can build a node
// config blob without exporting an encoder from the transport package.
func xhttpTestKDF(secret []byte) []byte {
	creator := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	c := creator
	pBytes := []byte("CHACHA 20 POLY 1305")
	creator = func() hash.Hash { return hmac.New(c, pBytes) }
	h := creator()
	h.Write(secret)
	return h.Sum(nil)
}

func xhttpTestBlob(t *testing.T, optionMap map[string]any) string {
	t.Helper()
	plaintext, err := json.Marshal(optionMap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	seed := []byte("00112233445566778899aabbccddeeff")
	aead, err := chacha20poly1305.New(xhttpTestKDF(seed))
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	nonce := make([]byte, 12)
	ciphertext := append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)
	payload := append(append([]byte{}, seed...), ciphertext...)
	raw := make([]byte, 1+8+len(payload))
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[1:5], 0)
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(seed)))
	copy(raw[9:], payload)
	return "v3\n" + base64.StdEncoding.EncodeToString(raw)
}

// TestXhttpOptionConfigBlob checks that a vendor `password` blob supplies the
// real server, port and transport password, overriding the YAML placeholders.
func TestXhttpOptionConfigBlob(t *testing.T) {
	password := xhttpTestBlob(t, map[string]any{
		"server":      "203.0.113.9",
		"port":        50775,
		"password":    "transport-secret:0011223344556677",
		"cipher":      "aes-128-ctr",
		"udp":         true,
		"udp-over-tcp": true,
		"padding-len": "8-64",
	})
	option := decodeXhttpOption(t, map[string]any{
		"name":     "Hey 7 | HK",
		"type":     "xhttp",
		"server":   "placeholder.invalid",
		"port":     1,
		"password": password,
	})
	proxy, err := NewXhttp(option)
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if proxy.option.Server != "203.0.113.9" || proxy.option.Port != 50775 {
		t.Fatalf("blob server/port not applied: %s/%d", proxy.option.Server, proxy.option.Port)
	}
	if proxy.option.Password != "transport-secret:0011223344556677" {
		t.Fatalf("blob transport password not applied")
	}
	if !proxy.SupportUOT() {
		t.Fatal("blob udp-over-tcp not applied")
	}
	if proxy.Addr() != "203.0.113.9:50775" {
		t.Fatalf("addr = %q", proxy.Addr())
	}
}
