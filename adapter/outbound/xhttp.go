package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/xhttpstream"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

// XhttpOption is the `type: xhttp` node.
//
// The first block is exactly the option table the vendor core reads: name,
// server, port, password, cipher, udp, udp-over-tcp, udp-over-tcp-version,
// padding-len and fake-net. `password` is the transport password in
// "<secret>:<hmac-hex>" form, or the vendor's encrypted node config blob (see
// xhttpstream.DecodeConfigBlob), in which case the blob supplies the values.
//
// The second block is what a vendor subscription node carries on top. The
// vendor app strips those keys before it hands the node to its core; they are
// accepted here (and marked omitempty) so a node can be pasted from a
// subscription as-is. `uuid` is deliberately not part of the table: the
// protocol has no UUID, and keeping it out keeps the custom-proxy form's
// credential list honest.
type XhttpOption struct {
	BasicOption
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	Password          string            `proxy:"password"`
	Cipher            string            `proxy:"cipher,omitempty"`
	UDP               bool              `proxy:"udp,omitempty"`
	UDPOverTCP        bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int               `proxy:"udp-over-tcp-version,omitempty"`
	PaddingLen        string            `proxy:"padding-len,omitempty"`
	FakeNet           map[string]string `proxy:"fake-net,omitempty"`

	Network           string       `proxy:"network,omitempty"`
	TLS               bool         `proxy:"tls,omitempty"`
	ServerName        string       `proxy:"servername,omitempty"`
	SNI               string       `proxy:"sni,omitempty"`
	ALPN              []string     `proxy:"alpn,omitempty"`
	SkipCertVerify    bool         `proxy:"skip-cert-verify,omitempty"`
	Certificate       string       `proxy:"certificate,omitempty"`
	PrivateKey        string       `proxy:"private-key,omitempty"`
	ClientFingerprint string       `proxy:"client-fingerprint,omitempty"`
	XHTTPOpts         XHTTPOptions `proxy:"xhttp-opts,omitempty"`
	Clover            string       `proxy:"clover,omitempty"`
	Encryption        string       `proxy:"encryption,omitempty"`
	UpSpeed           string       `proxy:"up-speed,omitempty"`
	DownSpeed         string       `proxy:"down-speed,omitempty"`
}

// Xhttp is the private xhttp outbound: a forged HTTP prefix around an
// AES-CTR stream, with the destination sent as the first encrypted bytes.
type Xhttp struct {
	*Base
	option *XhttpOption
	cipher *xhttpstream.StreamCipher
}

// applyConfigBlob replaces the option values with the ones carried inside the
// vendor node config blob when `password` is one.
func applyConfigBlob(option *XhttpOption) error {
	blob, isBlob, err := xhttpstream.DecodeConfigBlob(option.Password)
	if err != nil {
		return fmt.Errorf("xhttp: decode node config: %w", err)
	}
	if !isBlob {
		return nil
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(blob, option); err != nil {
		return fmt.Errorf("xhttp: decode node config fields: %w", err)
	}
	return nil
}

// NewXhttp builds the adapter and resolves every static option up front, so a
// bad node fails at load time instead of on the first connection.
func NewXhttp(option XhttpOption) (*Xhttp, error) {
	if err := applyConfigBlob(&option); err != nil {
		return nil, err
	}
	if option.Server == "" {
		return nil, fmt.Errorf("xhttp: server is required")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("xhttp: invalid port %d", option.Port)
	}
	if _, _, err := xhttpstream.SplitTransportPassword(option.Password); err != nil {
		return nil, err
	}
	if _, _, err := xhttpstream.ParsePaddingLen(option.PaddingLen); err != nil {
		return nil, err
	}
	if option.UDPOverTCPVersion < 0 || option.UDPOverTCPVersion > 2 {
		return nil, fmt.Errorf("xhttp: invalid udp-over-tcp-version %d", option.UDPOverTCPVersion)
	}
	ciph, err := xhttpstream.PickCipher(option.Cipher, nil, option.Password, option.FakeNet)
	if err != nil {
		return nil, fmt.Errorf("xhttp: initialize cipher: %w", err)
	}
	x := &Xhttp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.XHttp,
			ProviderName: option.ProviderName,
			UDP:          option.UDP || option.UDPOverTCP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		cipher: ciph,
	}
	x.dialer = option.NewDialer(x.DialOptions())
	return x, nil
}

// dialStream dials the server and forces the xhttp handshake, so an
// authentication failure surfaces as a dial error rather than on first read.
func (x *Xhttp) dialStream(ctx context.Context, destination []byte) (net.Conn, error) {
	conn, err := x.dialer.DialContext(ctx, "tcp", x.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", x.addr, err)
	}
	streamConn := x.cipher.StreamConn(conn, destination)
	if handshaker, ok := streamConn.(interface{ NeedHandshake() bool }); ok && handshaker.NeedHandshake() {
		if _, handshakeErr := streamConn.Write(nil); handshakeErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%s xhttp handshake error: %w", x.addr, handshakeErr)
		}
	}
	return streamConn, nil
}

// DialContext implements C.ProxyAdapter.
func (x *Xhttp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.NetWork == C.UDP {
		pc, err := x.ListenPacketContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return NewConn(N.NewBindPacketConn(pc, metadata.UDPAddr()), x), nil
	}
	conn, err := x.dialStream(ctx, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, x), nil
}

// ListenPacketContext implements C.ProxyAdapter. UDP runs over the same stream
// with the sing-box UOT framing when udp-over-tcp is on, and over a UDP socket
// with per-datagram frames otherwise.
func (x *Xhttp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := x.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if x.option.UDPOverTCP {
		uotDestination := uot.RequestDestination(uint8(x.option.UDPOverTCPVersion))
		uotMetadata := *metadata
		uotMetadata.Host = uotDestination.Fqdn
		uotMetadata.DstPort = uotDestination.Port
		conn, err := x.dialStream(ctx, serializesSocksAddr(&uotMetadata))
		if err != nil {
			return nil, err
		}
		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if x.option.UDPOverTCPVersion == uot.LegacyVersion {
			return NewPacketConn(uot.NewConn(conn, uot.Request{Destination: destination}), x), nil
		}
		return NewPacketConn(uot.NewLazyConn(conn, uot.Request{Destination: destination}), x), nil
	}
	conn, err := x.dialer.DialContext(ctx, "udp", x.addr)
	if err != nil {
		return nil, fmt.Errorf("%s udp connect error: %w", x.addr, err)
	}
	return NewPacketConn(x.cipher.PacketConn(conn), x), nil
}

// SupportUDP implements C.ProxyAdapter.
func (x *Xhttp) SupportUDP() bool { return x.option.UDP || x.option.UDPOverTCP }

// SupportUOT implements C.ProxyAdapter.
func (x *Xhttp) SupportUOT() bool { return x.option.UDPOverTCP }

// ProxyInfo implements C.ProxyAdapter.
func (x *Xhttp) ProxyInfo() C.ProxyInfo {
	info := x.Base.ProxyInfo()
	info.DialerProxy = x.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter. The transport holds no shared state.
func (x *Xhttp) Close() error { return nil }

var _ C.ProxyAdapter = (*Xhttp)(nil)
