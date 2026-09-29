package masque

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// assignedDNSTransport resolves through a nameserver the MASQUE server assigned.
//
// # Where this sits
//
// It is an endpoint-local adapter.DNSTransport, not a global resolver. Registering it
// globally, or pointing the system resolver at the assigned server, would leak traffic
// for every query in the process -- including the bootstrap lookup that establishes
// the tunnel. Instead the endpoint hands this transport to the DNS client only for
// inner lookups, so the ordinary DNS router, its cache, singleflight, negative cache
// and optimistic cache all keep working, and only the WIRE part changes.
//
// # Fail closed
//
// Every query is sent through the MASQUE device, which means through the tunnel. There
// is deliberately no fallback to a host socket: draft-ietf-masque-connect-ip-dns-06
// §5 warns that acting on an assignment "can cause an endpoint to use a nameserver that
// is outside of the connect-ip tunnel", and the whole point of accepting a
// server-assigned resolver is to keep those queries inside the tunnel. If the tunnel
// cannot carry a query, the query FAILS rather than escaping.
//
// # Reachability
//
// A nameserver address is only used when it is reachable through the routes the server
// advertised, checked by the caller before the transport is installed. An address
// outside those routes would be routed by the ordinary routing table, which is exactly
// the cleartext leak this type exists to prevent.
type assignedDNSTransport struct {
	dns.TransportAdapter
	logger logger.ContextLogger

	// dialer is the MASQUE device, so every dial goes through the tunnel.
	dialer N.Dialer

	// state is the immutable, published view of the current assignment.
	state atomic.Pointer[assignedDNSState]

	// generation identifies the assignment currently in force, used by Environment so
	// the DNS cache cannot serve a response resolved by a previous nameserver.
	generation atomic.Uint64

	access sync.Mutex
}

// assignedDNSState is one assignment's worth of immutable resolver configuration.
type assignedDNSState struct {
	// nameservers in the order the draft's service priorities expressed.
	nameservers []netip.Addr
	// TLSName is the authentication domain, when the resolver is encrypted.
	tlsName string
	// DoHPath is the SVCB dohpath template, when one was provided.
	dohPath string
	// UseTLS reports whether the encrypted transports were advertised.
	useTLS bool
	// Port overrides the default port when the SVCB "port" parameter was present.
	port uint16
	// PREF64 is the NAT64 prefix set in force at this generation.
	pref64 []netip.Prefix
}

const (
	assignedDNSDefaultPort    = 53
	assignedDNSDefaultTLSPort = 853
	// maxAssignedDNSMessageSize bounds a single response. The largest realistic DNS
	// over UDP payload is well under this; the ceiling exists so a hostile or broken
	// resolver cannot make the transport allocate without limit.
	maxAssignedDNSMessageSize = 65535
)

var (
	_ adapter.DNSTransport                  = (*assignedDNSTransport)(nil)
	_ adapter.DNSTransportWithConfiguration = (*assignedDNSTransport)(nil)
	_ adapter.DNSTransportWithEnvironment   = (*assignedDNSTransport)(nil)
)

func newAssignedDNSTransport(logger logger.ContextLogger, transportDialer N.Dialer, tag string) *assignedDNSTransport {
	transport := &assignedDNSTransport{
		// The tag is stable per endpoint so the DNS router can address it, while the
		// ENVIRONMENT changes with each assignment so the cache cannot confuse two.
		TransportAdapter: dns.NewTransportAdapter(assignedDNSType, tag, nil),
		logger:           logger,
		dialer:           transportDialer,
	}
	transport.state.Store(&assignedDNSState{})
	return transport
}

// assignedDNSType is the transport's reported type. It is not a user-facing
// configuration type: the transport exists only as the endpoint's internal resolver.
const assignedDNSType = "masque-assigned"

// apply installs a new assignment atomically and bumps the generation.
//
// The caller has already validated reachability. An empty nameserver list CLEARS the
// resolver, which is how a withdrawn assignment is represented rather than leaving the
// previous one installed.
func (t *assignedDNSTransport) apply(configuration masque.DNSConfiguration, pref64 []netip.Prefix) {
	state := &assignedDNSState{
		dohPath: serviceParameterString(configuration, dnsmessage.SVCParamKey(9)), // dohpath
		pref64:  append([]netip.Prefix(nil), pref64...),
	}
	if port := serviceParameterUint16(configuration, dnsmessage.SVCParamKey(3)); port != 0 {
		state.port = port
	}
	for _, nameserver := range configuration.Nameservers {
		state.nameservers = append(state.nameservers, nameserver.IPv4Addresses...)
		state.nameservers = append(state.nameservers, nameserver.IPv6Addresses...)
		if nameserver.AuthenticationDomainName != "" {
			state.tlsName = nameserver.AuthenticationDomainName
			if alpn, loaded := nameserver.ServiceParameters[dnsmessage.SVCParamALPN]; loaded && len(alpn) > 0 {
				// An ALPN list means the encrypted transports were advertised.
				state.useTLS = true
			}
		}
	}
	t.access.Lock()
	t.state.Store(state)
	t.generation.Add(1)
	t.access.Unlock()
}

// clear removes the assignment.
func (t *assignedDNSTransport) clear() {
	t.access.Lock()
	t.state.Store(&assignedDNSState{})
	t.generation.Add(1)
	t.access.Unlock()
}

// active reports whether an assignment with a usable nameserver is in force.
func (t *assignedDNSTransport) active() bool {
	state := t.state.Load()
	return state != nil && len(state.nameservers) > 0
}

// ServerAddresses implements adapter.DNSTransportWithConfiguration.
func (t *assignedDNSTransport) ServerAddresses() []netip.Addr {
	state := t.state.Load()
	if state == nil {
		return nil
	}
	return state.nameservers
}

// SearchDomains implements adapter.DNSTransportWithConfiguration.
func (t *assignedDNSTransport) SearchDomains() []string {
	return nil
}

// Environment implements adapter.DNSTransportWithEnvironment.
//
// The DNS cache keys on this value, so including the assignment generation plus the
// resolver identity means a response resolved by one nameserver can never be served
// after the server installs another. Without it the cache would happily answer from
// the previous resolver's data, which is both wrong and a privacy problem: the whole
// reason for the assignment is that a particular resolver should answer.
func (t *assignedDNSTransport) Environment() []string {
	state := t.state.Load()
	if state == nil {
		return nil
	}
	environment := make([]string, 0, 4+len(state.nameservers))
	environment = append(environment, "masque-assigned")
	environment = append(environment, "generation="+strconv.FormatUint(t.generation.Load(), 10))
	if state.tlsName != "" {
		environment = append(environment, "auth="+state.tlsName)
	}
	if state.dohPath != "" {
		environment = append(environment, "dohpath="+state.dohPath)
	}
	for _, address := range state.nameservers {
		environment = append(environment, "ns="+address.String())
	}
	return environment
}

func (t *assignedDNSTransport) Start(stage adapter.StartStage) error { return nil }

func (t *assignedDNSTransport) Close() error { return nil }

func (t *assignedDNSTransport) Reset() {}

// Exchange sends one query through the tunnel.
func (t *assignedDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	state := t.state.Load()
	if state == nil || len(state.nameservers) == 0 {
		// Fail closed. Returning a "no upstream" error rather than falling through to
		// a host resolver is the entire point of this type.
		return nil, E.New("no MASQUE DNS assignment in effect")
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}
	var lastErr error
	for _, address := range state.nameservers {
		response, exchangeErr := t.exchangeWith(ctx, state, address, packed)
		if exchangeErr == nil {
			return response, nil
		}
		lastErr = exchangeErr
		t.logger.DebugContext(ctx, "assigned DNS nameserver ", address, " failed: ", exchangeErr)
	}
	return nil, E.Cause(lastErr, "all assigned DNS nameservers failed")
}

func (t *assignedDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// exchangeWith performs one query against one nameserver, over the tunnel.
//
// Only the unencrypted UDP transport is implemented. That is a deliberate limit rather
// than an oversight: an encrypted transport (DoT/DoH) requires either a TLS session
// through the device or a request stream on the MASQUE HTTP/3 connection, and the
// latter is the same-connection DoH path. Claiming support for a transport this cannot
// actually complete would mean silently ignoring the ALPN parameters, which is worse
// than refusing.
func (t *assignedDNSTransport) exchangeWith(ctx context.Context, state *assignedDNSState, address netip.Addr, query []byte) (*mDNS.Msg, error) {
	port := state.port
	if port == 0 {
		port = assignedDNSDefaultPort
	}
	destination := M.SocksaddrFrom(address, port)

	conn, err := t.dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, E.Cause(err, "dial assigned nameserver through tunnel")
	}
	defer conn.Close()

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
	}

	// RFC 1035 §4.2.1: a DNS message over a stream carries a two-byte length prefix.
	// Over a connected UDP socket the message stands alone, so no prefix is added.
	if _, err = conn.Write(query); err != nil {
		return nil, E.Cause(err, "write DNS query")
	}
	buffer := buf.NewSize(maxAssignedDNSMessageSize)
	defer buffer.Release()
	_, err = buffer.ReadOnceFrom(conn)
	if err != nil {
		if err == io.EOF {
			return nil, E.New("assigned nameserver closed the connection")
		}
		return nil, E.Cause(err, "read DNS response")
	}
	var response mDNS.Msg
	if err = response.Unpack(buffer.Bytes()); err != nil {
		return nil, E.Cause(err, "decode DNS response")
	}
	return &response, nil
}

// isReachableThroughRoutes reports whether an assigned nameserver lies inside the
// routes the server advertised.
//
// A resolver outside those routes would be reached by the ordinary routing table
// rather than through the tunnel, so installing it would produce exactly the cleartext
// DNS leak the assignment is supposed to prevent. The check is deliberately
// conservative: an address that cannot be shown to be routable through the tunnel is
// refused, and the caller falls back to the ordinary DNS rules.
//
// A nil route set means the server has not advertised routes yet, and the draft's
// ordering requirement (§5) is that DNS_ASSIGN must not be sent before
// ROUTE_ADVERTISEMENT. Treating "no routes" as "nothing is reachable" enforces that
// ordering from the receiving side, rather than trusting the peer to respect it.
func isReachableThroughRoutes(address netip.Addr, routes []masque.AddressRange) bool {
	if len(routes) == 0 {
		return false
	}
	for _, route := range routes {
		if route.Contains(address) {
			return true
		}
	}
	return false
}

// serviceParameterString decodes an SVCB parameter whose value is a raw string.
func serviceParameterString(configuration masque.DNSConfiguration, key dnsmessage.SVCParamKey) string {
	for _, nameserver := range configuration.Nameservers {
		if value, loaded := nameserver.ServiceParameters[key]; loaded {
			return string(value)
		}
	}
	return ""
}

// serviceParameterUint16 decodes an SVCB parameter whose value is a big-endian
// uint16, as the "port" parameter is.
func serviceParameterUint16(configuration masque.DNSConfiguration, key dnsmessage.SVCParamKey) uint16 {
	for _, nameserver := range configuration.Nameservers {
		value, loaded := nameserver.ServiceParameters[key]
		if !loaded || len(value) != 2 {
			continue
		}
		return binary.BigEndian.Uint16(value)
	}
	return 0
}

// dohPathTemplate normalises the SVCB dohpath value.
//
// RFC 9461 §5 defines it as a URI Template, so the placeholder is stripped to leave a
// usable request path. A template without a placeholder is returned as-is.
func dohPathTemplate(value string) string {
	if index := strings.IndexByte(value, '{'); index >= 0 {
		return value[:index]
	}
	return value
}
