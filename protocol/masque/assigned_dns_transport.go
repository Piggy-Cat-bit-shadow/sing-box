package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
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

	// dohClient issues DoH requests on the SAME HTTP/3 connection the CONNECT-IP tunnel
	// uses. It is nil until the endpoint publishes one, and the DoH path is only taken
	// when it is present: without it there is no same-connection transport to use, and
	// a DoH query sent any other way would not be the thing this path exists to prove.
	dohClient dohRoundTripper

	access sync.Mutex
}

// dohRoundTripper is the narrow capability the assigned-DNS transport needs: the ability
// to issue an ordinary request on the endpoint's existing MASQUE HTTP/3 connection.
//
// It is declared here, rather than taking transport/http's concrete client, so that this
// package cannot reach any further into that client than the one method it uses, and so
// the DoH path can be tested with a double that counts connections.
type dohRoundTripper interface {
	RoundTripHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
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
// # Transport selection
//
// DoH is used when the server advertised a dohpath AND the endpoint has published its
// HTTP/3 client, because that is the only combination that puts the query on the SAME
// connection as the tunnel, which is what draft-ietf-masque-connect-ip-dns-06 §3.5 asks
// for when the proxy is authoritative for the DoH origin.
//
// Otherwise the query goes over plain UDP through the tunnel. That is a deliberate limit
// rather than an oversight: DoT would need a TLS session through the device, which is a
// separate transport with its own certificate story. Claiming to support a transport that
// cannot actually be completed would mean silently ignoring the ALPN parameters, which is
// worse than refusing -- and the UDP path is always available and always inside the tunnel.
func (t *assignedDNSTransport) exchangeWith(ctx context.Context, state *assignedDNSState, address netip.Addr, query []byte) (*mDNS.Msg, error) {
	if state.dohPath != "" {
		if response, err := t.exchangeDoH(ctx, state, address, query); err == nil {
			return response, nil
		} else if t.dohClient == nil {
			// No same-connection HTTP/3 client yet. Fall through to UDP so the query is
			// still answered inside the tunnel; the event is logged because it means the
			// coalescing the draft asks for is not happening.
			t.logger.DebugContext(ctx, "assigned DNS DoH unavailable, using UDP through tunnel: ", err)
		} else {
			return nil, err
		}
	}
	return t.exchangeUDP(ctx, state, address, query)
}

// exchangeDoH sends the query as an RFC 8484 POST on the endpoint's existing HTTP/3
// connection.
//
// The request is addressed to the nameserver's authentication domain (its TLS name), which
// is the origin the connection was authenticated for, and the path comes from the SVCB
// dohpath template. Sending it anywhere else would either be refused by the same-origin
// check or, worse, would be a cross-origin request riding on those credentials.
func (t *assignedDNSTransport) exchangeDoH(ctx context.Context, state *assignedDNSState, address netip.Addr, query []byte) (*mDNS.Msg, error) {
	roundTripper := t.dohClient
	if roundTripper == nil {
		return nil, E.New("no same-connection HTTP/3 client for DoH")
	}
	authority := state.tlsName
	if authority == "" {
		// No authentication domain was advertised, so there is no origin to name. The
		// plain address is used instead, which the same-origin check then compares
		// against the configured authority; it only succeeds when they coincide.
		authority = address.String()
		if port := state.dohPort(); port != 0 {
			authority = netip.AddrPortFrom(address, port).String()
		}
	}
	requestURL := &url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   dohPathTemplate(state.dohPath),
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(query))
	if err != nil {
		return nil, E.Cause(err, "build DoH request")
	}
	request.Header.Set("Content-Type", dnsTransport.MimeType)
	request.Header.Set("Accept", dnsTransport.MimeType)
	// The body length is known, and stating it lets the server reject a truncated query
	// instead of parsing a partial one.
	request.ContentLength = int64(len(query))

	response, err := roundTripper.RoundTripHTTP3(ctx, request)
	if err != nil {
		return nil, E.Cause(err, "DoH request on MASQUE connection")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// Read a bounded prefix so a server that explains the failure has its
		// explanation surfaced, without letting it stream unbounded data into the error.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, maxDoHErrorBodySize))
		return nil, E.New("DoH server returned ", response.Status, formatDoHErrorDetail(detail))
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAssignedDNSMessageSize))
	if err != nil {
		return nil, E.Cause(err, "read DoH response")
	}
	var message mDNS.Msg
	if err = message.Unpack(payload); err != nil {
		return nil, E.Cause(err, "decode DoH response")
	}
	return &message, nil
}

// exchangeUDP performs one query against one nameserver over plain DNS through the tunnel.
func (t *assignedDNSTransport) exchangeUDP(ctx context.Context, state *assignedDNSState, address netip.Addr, query []byte) (*mDNS.Msg, error) {
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

// dohPort reports the port a DoH request should be addressed to.
func (s *assignedDNSState) dohPort() uint16 {
	if s.port != 0 {
		return s.port
	}
	// The dohpath is an HTTP resource, so its default is the HTTPS port, not the DNS one.
	if s.dohPath != "" {
		return 443
	}
	return 0
}

// setDoHClient publishes the client used for same-connection DoH.
func (t *assignedDNSTransport) setDoHClient(client dohRoundTripper) {
	t.access.Lock()
	t.dohClient = client
	t.access.Unlock()
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
		value = value[:index]
	}
	if value == "" {
		// The draft's example carries the path in the template, but a server that
		// advertises only the origin still needs a resource to name. RFC 8484 defines
		// /dns-query as the conventional one.
		return "/dns-query"
	}
	if !strings.HasPrefix(value, "/") {
		return "/" + value
	}
	return value
}

// maxDoHErrorBodySize bounds how much of an error response is quoted back in the error.
//
// A failure explanation is useful; a server streaming megabytes into an error string is
// not. The limit is generous enough for any plausible diagnostic body.
const maxDoHErrorBodySize = 4096

// formatDoHErrorDetail renders an error response body for an error message.
//
// The body is quoted only when it is short enough to be a diagnostic rather than a
// document, so a large or binary body cannot flood the log or the DNS client's error path.
func formatDoHErrorDetail(detail []byte) string {
	if len(detail) == 0 {
		return ""
	}
	text := strings.TrimSpace(string(detail))
	if text == "" {
		return ""
	}
	if len(text) > 256 {
		text = text[:256] + "..."
	}
	return ": " + text
}
