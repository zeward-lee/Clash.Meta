package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestParseXhttpProxy covers the parser registration: `type: xhttp` must build
// the private outbound and keep udp/udp-over-tcp from the node.
func TestParseXhttpProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "xhttp fixture",
		"type":     "xhttp",
		"server":   "node.example",
		"port":     443,
		"password": "transport-secret:0011223344556677",
		"cipher":   "aes-128-ctr",
		"udp":      true,
		"udp-over-tcp": true,
		"padding-len":  "8-64",
		"fake-net":     map[string]any{"tcp": "16030100"},
	})
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	defer proxy.Close()
	if proxy.Type() != C.XHttp {
		t.Fatalf("type = %v, want %v", proxy.Type(), C.XHttp)
	}
	if proxy.Addr() != "node.example:443" {
		t.Fatalf("addr = %q", proxy.Addr())
	}
	if !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatal("udp flags not applied")
	}
}

func TestParseXhttpProxyRequiresTransportPassword(t *testing.T) {
	if _, err := ParseProxy(map[string]any{
		"name":     "xhttp fixture",
		"type":     "xhttp",
		"server":   "node.example",
		"port":     443,
		"password": "missing-hmac-part",
	}); err == nil {
		t.Fatal("node without a hmac part was accepted")
	}
}
