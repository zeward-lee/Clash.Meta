package outbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/sing/common/uot"
	"golang.org/x/crypto/chacha20poly1305"
)

func decodeXhttpOption(t *testing.T, mapping map[string]any) XhttpOption {
	t.Helper()
	option := XhttpOption{}
	// The decoder treats `name` as required, so give the synthetic nodes a name
	// unless the case supplies one.
	if _, ok := mapping["name"]; !ok {
		mapping["name"] = "xhttp-test"
	}
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
		"name":         "Hey 7 | HK",
		"type":         "xhttp",
		"server":       "203.0.113.9",
		"port":         50775,
		"password":     "transport-secret:00112233445566778899aabbccddeeff",
		"cipher":       "aes-128-ctr",
		"udp":          true,
		"udp-over-tcp": true,
		"padding-len":  "8-64",
		"fake-net":     map[string]any{"tcp": "16030100", "udp": "16030100"},
		"uuid":         "00000000-0000-0000-0000-000000000000",
		"tls":          true,
		"servername":   "apple.com",
		"alpn":         []any{"h2"},
		"certificate":  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"private-key":  "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
		"clover":       "198.51.100.7",
		"encryption":   "fake-net",
		"network":      "xhttp",
		"up-speed":     "10",
		"xhttp-opts":   map[string]any{"host": "apple.com", "path": "/hEK8lz27"},
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
	if proxy.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf("udp-over-tcp-version = %d, want the legacy default %d",
			proxy.option.UDPOverTCPVersion, uot.LegacyVersion)
	}
}

// TestXhttpUDPOverTCPVersion covers the version normalisation: 0 means the
// vendor default (legacy), 1/2 are the sing uot versions, anything else is a
// load-time error.
func TestXhttpUDPOverTCPVersion(t *testing.T) {
	base := map[string]any{
		"server":       "node.example",
		"port":         443,
		"password":     "a:00",
		"udp-over-tcp": true,
	}
	for _, version := range []int{uot.LegacyVersion, uot.Version} {
		mapping := map[string]any{"udp-over-tcp-version": version}
		for k, v := range base {
			mapping[k] = v
		}
		proxy, err := NewXhttp(decodeXhttpOption(t, mapping))
		if err != nil {
			t.Fatalf("version %d: NewXhttp: %v", version, err)
		}
		if proxy.option.UDPOverTCPVersion != version {
			t.Fatalf("version %d became %d", version, proxy.option.UDPOverTCPVersion)
		}
		_ = proxy.Close()
	}
	proxy, err := NewXhttp(decodeXhttpOption(t, base))
	if err != nil {
		t.Fatalf("default: NewXhttp: %v", err)
	}
	if proxy.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf("default version = %d, want %d", proxy.option.UDPOverTCPVersion, uot.LegacyVersion)
	}
	_ = proxy.Close()

	for _, bad := range []int{3, 9} {
		mapping := map[string]any{"udp-over-tcp-version": bad}
		for k, v := range base {
			mapping[k] = v
		}
		if _, err := NewXhttp(decodeXhttpOption(t, mapping)); err == nil {
			t.Fatalf("version %d was accepted", bad)
		}
	}
}

// TestXhttpPlainUDPKeepsUOTDefault documents the plain UDP decision: the node
// stays loadable (the vendor subscriptions carry udp without udp-over-tcp) and
// the uot version is normalised anyway, but plain UDP is not advertised as UOT.
func TestXhttpPlainUDPKeepsUOTDefault(t *testing.T) {
	proxy, err := NewXhttp(decodeXhttpOption(t, map[string]any{
		"server":   "node.example",
		"port":     443,
		"password": "a:00",
		"udp":      true,
	}))
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if !proxy.SupportUDP() {
		t.Fatal("udp: true did not enable UDP")
	}
	if proxy.SupportUOT() {
		t.Fatal("udp: true without udp-over-tcp advertised UOT")
	}
	if proxy.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf("version = %d, want %d", proxy.option.UDPOverTCPVersion, uot.LegacyVersion)
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
	// The blob carries the seed as a hex string; the decoder hex-decodes it
	// before deriving the AEAD key, so the encoder must do the same.
	payloadSeed := []byte("00112233445566778899aabbccddeeff")
	seed, err := hex.DecodeString(string(payloadSeed))
	if err != nil {
		t.Fatalf("hex seed: %v", err)
	}
	aead, err := chacha20poly1305.New(xhttpTestKDF(seed))
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	nonce := make([]byte, 12)
	ciphertext := append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)
	payload := append(append([]byte{}, payloadSeed...), ciphertext...)
	raw := make([]byte, 1+8+len(payload))
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[1:5], 0)
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(payloadSeed)))
	copy(raw[9:], payload)
	return "v3\n" + base64.StdEncoding.EncodeToString(raw)
}

// TestXhttpConfigBlobFillsOnlyMissing checks the merge rule: a vendor `password`
// blob supplies the values the YAML leaves out (here cipher, udp, udp-over-tcp,
// padding-len) and always replaces the wrapper password with the transport one.
func TestXhttpConfigBlobFillsOnlyMissing(t *testing.T) {
	password := xhttpTestBlob(t, map[string]any{
		"server":       "203.0.113.9",
		"port":         50775,
		"password":     "transport-secret:0011223344556677",
		"cipher":       "aes-128-ctr",
		"udp":          true,
		"udp-over-tcp": true,
		"padding-len":  "8-64",
		"name":         "blob name",
	})
	option := decodeXhttpOption(t, map[string]any{
		"name":     "Hey 7 | HK",
		"type":     "xhttp",
		"server":   "203.0.113.9",
		"port":     50775,
		"password": password,
	})
	proxy, err := NewXhttp(option)
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if proxy.option.Server != "203.0.113.9" || proxy.option.Port != 50775 {
		t.Fatalf("server/port = %s/%d", proxy.option.Server, proxy.option.Port)
	}
	if proxy.option.Password != "transport-secret:0011223344556677" {
		t.Fatalf("blob transport password not applied")
	}
	if proxy.option.Cipher != "aes-128-ctr" || proxy.option.PaddingLen != "8-64" {
		t.Fatalf("cipher/padding-len = %q/%q", proxy.option.Cipher, proxy.option.PaddingLen)
	}
	if !proxy.SupportUOT() {
		t.Fatal("blob udp-over-tcp not applied")
	}
	if proxy.Name() != "Hey 7 | HK" {
		t.Fatalf("name = %q, the YAML name must win over the blob", proxy.Name())
	}
	if proxy.Addr() != "203.0.113.9:50775" {
		t.Fatalf("addr = %q", proxy.Addr())
	}
	if proxy.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf("version = %d, want %d", proxy.option.UDPOverTCPVersion, uot.LegacyVersion)
	}
}

// TestXhttpConfigBlobDoesNotOverrideYAML is the other half: every key the YAML
// sets is kept, even when the blob disagrees (server/port is the dangerous case,
// it is only warned about).
func TestXhttpConfigBlobDoesNotOverrideYAML(t *testing.T) {
	password := xhttpTestBlob(t, map[string]any{
		"server":   "203.0.113.9",
		"port":     50775,
		"password": "transport-secret:0011223344556677",
		"cipher":   "aes-128-ctr",
		"name":     "blob name",
	})
	proxy, err := NewXhttp(decodeXhttpOption(t, map[string]any{
		"name":     "YAML name",
		"type":     "xhttp",
		"server":   "198.51.100.1",
		"port":     8443,
		"password": password,
		"cipher":   "aes-256-ctr",
	}))
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if proxy.option.Server != "198.51.100.1" || proxy.option.Port != 8443 {
		t.Fatalf("server/port = %s/%d, the YAML values must win", proxy.option.Server, proxy.option.Port)
	}
	if proxy.option.Cipher != "aes-256-ctr" {
		t.Fatalf("cipher = %q, the YAML value must win", proxy.option.Cipher)
	}
	if proxy.Name() != "YAML name" {
		t.Fatalf("name = %q, the blob must never rename a node", proxy.Name())
	}
	if proxy.option.Password != "transport-secret:0011223344556677" {
		t.Fatal("the blob wrapper must still be replaced by its transport password")
	}
}

// TestXhttpConfigBlobMergesFakeNet checks the map is merged per key, not
// replaced: a YAML that only names the tcp prefix still gets the udp one.
func TestXhttpConfigBlobMergesFakeNet(t *testing.T) {
	password := xhttpTestBlob(t, map[string]any{
		"password": "transport-secret:0011223344556677",
		"fake-net": map[string]any{"tcp": "deadbeef", "udp": "16030100"},
	})
	proxy, err := NewXhttp(decodeXhttpOption(t, map[string]any{
		"server":   "node.example",
		"port":     443,
		"password": password,
		"fake-net": map[string]any{"tcp": "16030100"},
	}))
	if err != nil {
		t.Fatalf("NewXhttp: %v", err)
	}
	defer proxy.Close()
	if proxy.option.FakeNet["tcp"] != "16030100" {
		t.Fatalf("fake-net[tcp] = %q, the YAML value must win", proxy.option.FakeNet["tcp"])
	}
	if proxy.option.FakeNet["udp"] != "16030100" {
		t.Fatalf("fake-net[udp] = %q, the blob value must be merged in", proxy.option.FakeNet["udp"])
	}
}
