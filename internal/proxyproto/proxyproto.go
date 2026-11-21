// Package proxyproto implements the PROXY protocol versions 1 and 2 defined by
// HAProxy. It is used by the gateway when it runs behind a CDN or a layer-4
// load balancer: the fronting proxy prepends the original client/server
// endpoints to the byte stream, and Conn consumes that header once so that the
// rest of the server (panel, tunnel authentication, access control, egress IP
// discovery) sees the real peer address instead of the load balancer's.
//
// Security note: the PROXY protocol header is trivially forgeable. Only enable
// it on listeners that are reachable exclusively through a trusted fronting
// proxy (this is what the server configuration flag tunnel.proxy_protocol
// guards). Never sniff the header for arbitrary public clients: a client could
// then spoof its own source address and defeat ACLs.
//
// The package never starts goroutines and performs no I/O besides reading and
// writing the bytes passed to it. All parsers validate lengths and are safe
// against hostile input: they never panic and never allocate more than the
// documented 16 KiB header limit.
package proxyproto

import (
	"errors"
	"net"
	"strconv"
)

// Protocol versions.
const (
	Version1 = 1
	Version2 = 2
)

// Header.Command values. PROXY means the header carries the original
// connection endpoints; LOCAL means the connection was opened by the proxy
// itself (health checks) and the real socket endpoints must be used.
const (
	CommandProxy = "PROXY"
	CommandLocal = "LOCAL"
)

// Header.Family values. TCP4/TCP6 are fully decoded stream transports; UNSPEC
// means no usable address block (LOCAL, PROXY over UNSPEC, or a valid but
// unsupported address family such as UDP/UNIX that was skipped).
const (
	FamilyTCP4   = "TCP4"
	FamilyTCP6   = "TCP6"
	FamilyUNSPEC = "UNSPEC"
)

// TLVTypeCRC32C is the PROXY protocol v2 CRC32C checksum TLV (see section
// 2.2.3 of the specification). Its value is a 32-bit CRC32C (Castagnoli) of
// the whole header in network byte order, computed with the checksum field
// itself zeroed.
const TLVTypeCRC32C = 0x03

var (
	// ErrNoProxyHeader reports that the input does not start with a PROXY
	// protocol v1 or v2 header.
	ErrNoProxyHeader = errors.New("proxyproto: no PROXY protocol header")
	// ErrHeaderTooLong reports that the announced or actual header exceeds the
	// documented limits: 107 bytes for v1 and 16 KiB total for v2.
	ErrHeaderTooLong = errors.New("proxyproto: header exceeds maximum length")
)

// Header is a parsed PROXY protocol header. Version is 1 or 2. Command is
// CommandProxy or CommandLocal. Family is FamilyTCP4, FamilyTCP6 or
// FamilyUNSPEC. SrcIP/DstIP are nil and SrcPort/DstPort are 0 when the family
// carries no endpoints. TLVs holds the raw v2 TLV values keyed by type (v1
// headers never have TLVs; when the same TLV type appears more than once the
// last value wins).
type Header struct {
	Version int
	Command string
	Family  string
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort int
	DstPort int
	TLVs    map[byte][]byte
}

// IsProxy reports whether the header carries the original connection
// endpoints. When it returns false the real socket endpoints must be used.
func (h Header) IsProxy() bool {
	return h.Command == CommandProxy &&
		(h.Family == FamilyTCP4 || h.Family == FamilyTCP6) &&
		h.SrcIP != nil && h.DstIP != nil
}

// SourceAddr returns the original client address carried by the header, or nil
// when the header has no TCP endpoints (LOCAL/UNSPEC).
func (h Header) SourceAddr() net.Addr {
	if !h.IsProxy() {
		return nil
	}
	return &Addr{IP: h.SrcIP, Port: h.SrcPort}
}

// DestinationAddr returns the original target address carried by the header,
// or nil when the header has no TCP endpoints (LOCAL/UNSPEC).
func (h Header) DestinationAddr() net.Addr {
	if !h.IsProxy() {
		return nil
	}
	return &Addr{IP: h.DstIP, Port: h.DstPort}
}

// Addr is the net.Addr implementation returned by Header.SourceAddr and
// Header.DestinationAddr. It satisfies the same contract as *net.TCPAddr while
// keeping the package independent of the address representation used by the
// fronting proxy.
type Addr struct {
	IP   net.IP
	Port int
}

// Network implements net.Addr. PROXY protocol addresses are always TCP.
func (a *Addr) Network() string { return "tcp" }

// String implements net.Addr and renders "host:port" like net.JoinHostPort.
func (a *Addr) String() string {
	if a == nil || a.IP == nil {
		return ""
	}
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
}
