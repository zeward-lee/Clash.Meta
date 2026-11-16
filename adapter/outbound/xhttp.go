package outbound

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/xhttpstream"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

// xhttpHandshakeTimeout bounds the client handshake (header write and the read
// of the echoed token) so a silent or hostile server cannot pin a relay
// goroutine forever. It is clamped by the dial context deadline.
const xhttpHandshakeTimeout = 10 * time.Second

// XhttpOption is the `type: xhttp` node.
//
// The first block is exactly the option table the vendor core reads: name,
// server, port, password, cipher, udp, udp-over-tcp, udp-over-tcp-version,
// padding-len and fake-net. `password` is the transport password in
// "<secret>:<hmac-hex>" form, or the vendor's encrypted node config blob (see
// xhttpstream.DecodeConfigBlob), in which case the blob supplies the values the
// YAML leaves out.
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

// proxyTag reports the `proxy` tag name of a struct field, or "" when the field
// is not part of the option table.
func proxyTag(field reflect.StructField) string {
	tag := field.Tag.Get("proxy")
	if tag == "" || tag == "-" {
		return ""
	}
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i]
		}
	}
	return tag
}

// explicitKeys records the keys the YAML side actually set, before the blob is
// merged in. A key is "set" when its field is non-zero: the YAML decode has
// already collapsed absent keys to their zero value, so a key that is present
// but set to its zero value is indistinguishable from an absent one. That is
// the intended reading for a node table (an explicit `udp: false` and no `udp`
// mean the same thing).
func explicitKeys(option *XhttpOption) map[string]bool {
	keys := make(map[string]bool)
	value := reflect.ValueOf(option).Elem()
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			continue
		}
		name := proxyTag(field)
		if name == "" {
			continue
		}
		if !value.Field(i).IsZero() {
			keys[name] = true
		}
	}
	return keys
}

// fillMissing copies every non-zero blob field into an option field the YAML
// left unset. `name` is never taken from the blob, and nested option tables
// (xhttp-opts) are treated as one value, mirroring how the vendor core reads
// them.
func fillMissing(option *XhttpOption, fromBlob XhttpOption, explicit map[string]bool) {
	dst := reflect.ValueOf(option).Elem()
	src := reflect.ValueOf(fromBlob)
	typ := dst.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			continue
		}
		name := proxyTag(field)
		if name == "" || name == "name" || name == "fake-net" {
			// name belongs to the YAML node; fake-net is merged per key below.
			continue
		}
		if explicit[name] {
			continue
		}
		if !dst.Field(i).CanSet() || src.Field(i).IsZero() {
			continue
		}
		dst.Field(i).Set(src.Field(i))
	}
}

// applyConfigBlob fills the option values the YAML left out from the vendor
// node config blob when `password` is one. YAML always wins: the blob only
// supplies defaults, so an operator can override a node without re-encoding the
// blob. A server/port conflict is logged because it is the one clash that
// silently sends traffic to the wrong host.
func applyConfigBlob(option *XhttpOption) error {
	blob, isBlob, err := xhttpstream.DecodeConfigBlob(option.Password)
	if err != nil {
		return fmt.Errorf("xhttp: decode node config: %w", err)
	}
	if !isBlob {
		return nil
	}
	var fromBlob XhttpOption
	// A blob is an overlay, not a whole node: it may leave out `name`,
	// `server` or `port`, which the decoder treats as required tags. Seed those
	// keys from the YAML value when the blob omits them so the overlay decodes;
	// explicitKeys/fillMissing still keep the YAML values.
	for key, value := range map[string]any{"name": option.Name, "server": option.Server, "port": option.Port} {
		if _, ok := blob[key]; !ok {
			blob[key] = value
		}
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(blob, &fromBlob); err != nil {
		return fmt.Errorf("xhttp: decode node config fields: %w", err)
	}
	explicit := explicitKeys(option)
	if option.Server != "" && fromBlob.Server != "" && option.Server != fromBlob.Server {
		log.Warnln("[Xhttp](%s) config server %q overrides node blob server %q", option.Name, option.Server, fromBlob.Server)
	}
	if option.Port != 0 && fromBlob.Port != 0 && option.Port != fromBlob.Port {
		log.Warnln("[Xhttp](%s) config port %d overrides node blob port %d", option.Name, option.Port, fromBlob.Port)
	}
	fillMissing(option, fromBlob, explicit)
	// fake-net is a map of per-transport prefixes: fill the keys the YAML does
	// not name, keep the ones it does.
	if len(fromBlob.FakeNet) > 0 {
		if option.FakeNet == nil {
			option.FakeNet = make(map[string]string, len(fromBlob.FakeNet))
		}
		for key, value := range fromBlob.FakeNet {
			if _, ok := option.FakeNet[key]; !ok {
				option.FakeNet[key] = value
			}
		}
	}
	// The blob is a wrapper, not a credential: the transport password always
	// comes from inside it.
	if fromBlob.Password != "" {
		option.Password = fromBlob.Password
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
	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("xhttp: unknown udp-over-tcp-version %d", option.UDPOverTCPVersion)
	}
	if option.UDP && !option.UDPOverTCP {
		// The plain UDP frame layout is reconstructed, not yet validated
		// against a live server. Keep the path (the vendor nodes carry `udp`
		// without `udp-over-tcp`) but say so once per node.
		log.Warnln("[Xhttp](%s) udp: true without udp-over-tcp uses the unverified plain UDP framing; prefer udp-over-tcp: true", option.Name)
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

// handshakeDeadline is min(now + xhttpHandshakeTimeout, ctx deadline).
func handshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(xhttpHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

// dialStream dials the server and hands the xhttp handshake to the relay phase
// with the mihomo EarlyConn convention: the forged prefix, token, HMAC and IV
// are written on the first read/write of the returned conn instead of inside
// DialContext. A failure therefore surfaces as an I/O error of the relay (which
// closes the connection) and never blocks the dial path, while the token echo
// is validated on the first read under a deadline.
func (x *Xhttp) dialStream(ctx context.Context, destination []byte) (net.Conn, error) {
	conn, err := x.dialer.DialContext(ctx, "tcp", x.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", x.addr, err)
	}
	streamConn := x.cipher.StreamConn(conn, destination)
	if setter, ok := streamConn.(interface{ SetHandshakeDeadline(time.Time) }); ok {
		setter.SetHandshakeDeadline(handshakeDeadline(ctx))
	}
	if !N.NeedHandshake(streamConn) {
		return streamConn, nil
	}
	return N.NewEarlyConn(streamConn, func() error {
		deadline := handshakeDeadline(ctx)
		_ = streamConn.SetWriteDeadline(deadline)
		_, err := streamConn.Write(nil)
		_ = streamConn.SetWriteDeadline(time.Time{})
		if err != nil {
			// The dial already succeeded; a half-open conn here would leak a
			// socket until the relay notices, so close it now.
			_ = conn.Close()
			return fmt.Errorf("%s xhttp handshake error: %w", x.addr, err)
		}
		return nil
	}), nil
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

// listenPacketContext opens the plain UDP carrier the same way shadowsocks does:
// resolve the server address, ask the dialer for an unconnected socket, then
// bind it to the server with bufio.NewBindPacketConn so interface/routing-mark
// options and the resolved address actually apply.
func (x *Xhttp) listenPacketContext(ctx context.Context) (net.PacketConn, net.Addr, error) {
	addr, err := resolveUDPAddr(ctx, "udp", x.addr, x.option.IPVersion)
	if err != nil {
		return nil, nil, err
	}
	pc, err := x.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, nil, fmt.Errorf("%s udp listen error: %w", x.addr, err)
	}
	return pc, addr, nil
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
			return NewPacketConn(N.NewThreadSafePacketConn(uot.NewConn(conn, uot.Request{Destination: destination})), x), nil
		}
		return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(conn, uot.Request{Destination: destination})), x), nil
	}
	pc, serverAddr, err := x.listenPacketContext(ctx)
	if err != nil {
		return nil, err
	}
	// The socket is bound to the configured server (server/port from the node or
	// its config blob); the destination inside each datagram frame is the
	// per-packet SOCKS address the caller passes to WriteTo.
	carrier := bufio.NewBindPacketConn(pc, serverAddr)
	return NewPacketConn(x.cipher.PacketConn(carrier, serverAddr), x), nil
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
