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

	// nextGeneration allocates the generation stamped into each published snapshot. The
	// value itself lives INSIDE the state, so a reader can never observe a resolver list
	// and a generation that disagree.
	nextGeneration uint64

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

// apply installs a new assignment atomically.
//
// The whole assignment is published as ONE immutable snapshot, and the generation is
// allocated inside it. Storing the state and bumping a separate counter were two
// independent atomic operations, so a reader could observe the new resolver list alongside
// the old generation -- and since Environment() keys the DNS cache on the generation, that
// torn pair would let an answer be attributed to an assignment that did not produce it.
//
// An assignment with no configurations CLEARS the resolver, which is how a withdrawal is
// represented rather than leaving the previous one installed.
func (t *assignedDNSTransport) apply(configurations []masque.DNSConfiguration, pref64 []netip.Prefix) {
	t.access.Lock()
	// The generation is allocated and published together, so a reader can never observe the
	// new resolver list with the previous generation.
	t.nextGeneration++
	t.state.Store(buildAssignedDNSState(configurations, pref64, t.nextGeneration))
	t.access.Unlock()
}

// clear removes the assignment.
func (t *assignedDNSTransport) clear() {
	t.apply(nil, nil)
}

// active reports whether an assignment with a usable resolver is in force.
func (t *assignedDNSTransport) active() bool {
	state := t.state.Load()
	return state != nil && state.hasResolvers()
}

// ServerAddresses implements adapter.DNSTransportWithConfiguration.
//
// Every address of every resolver is reported, across configurations, because the framework
// asks one question ("which servers does this transport talk to?") and the answer is the
// union. Per-query routing uses selectForName, not this list.
func (t *assignedDNSTransport) ServerAddresses() []netip.Addr {
	state := t.state.Load()
	if state == nil {
		return nil
	}
	var addresses []netip.Addr
	for _, endpoint := range state.allEndpoints() {
		addresses = append(addresses, endpoint.addresses...)
	}
	return addresses
}

// SearchDomains implements adapter.DNSTransportWithConfiguration.
//
// # Why this is not nil any more
//
// It used to return nil unconditionally while SearchDomains was parsed, stored and
// documented as supported -- state that existed and was never read.
//
// The framework's interface is static: it asks for the search domains of THIS TRANSPORT,
// not of one configuration. The assignment can legitimately carry different search domains
// per configuration, so the honest view is the union, in configuration order, deduplicated.
// Reporting one configuration's list would silently impose it on names belonging to
// another, and reporting nothing would discard what the server sent.
func (t *assignedDNSTransport) SearchDomains() []string {
	state := t.state.Load()
	if state == nil {
		return nil
	}
	var domains []string
	seen := make(map[string]struct{})
	for _, configuration := range state.configurations {
		for _, domain := range configuration.searchDomains {
			if _, loaded := seen[domain]; loaded {
				continue
			}
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains
}

// Environment implements adapter.DNSTransportWithEnvironment.
//
// The DNS cache keys on this value, so it must change whenever the resolver that would
// answer changes. It reports the generation, every resolver's own identity, and the
// configuration boundaries, so two assignments that differ in ANY of those produce
// different cache keys.
//
// The metadata is reported PER RESOLVER rather than one value for the whole assignment. A
// single `auth=` line could only ever describe one nameserver, and reporting the last one
// seen would make two different assignments -- one where resolver A authenticates as
// a.example and one where it authenticates as b.example -- look like the same key.
func (t *assignedDNSTransport) Environment() []string {
	state := t.state.Load()
	if state == nil {
		return nil
	}
	environment := make([]string, 0, 8)
	environment = append(environment, "masque-assigned")
	environment = append(environment, "generation="+strconv.FormatUint(state.generation, 10))
	if len(state.pref64) > 0 {
		// PREF64 is reported because it is part of the assignment's identity even though it
		// does not yet participate in resolution; a change to it is still a change the
		// cache must not conflate with the previous assignment.
		for _, prefix := range state.pref64 {
			environment = append(environment, "pref64="+prefix.String())
		}
	}
	for index, configuration := range state.configurations {
		prefix := "cfg" + strconv.Itoa(index)
		for _, domain := range configuration.internalDomains {
			environment = append(environment, prefix+".internal="+domain)
		}
		for _, domain := range configuration.searchDomains {
			environment = append(environment, prefix+".search="+domain)
		}
		for _, endpoint := range configuration.resolvers {
			for _, address := range endpoint.addresses {
				environment = append(environment, prefix+".ns="+address.String())
			}
			if endpoint.authenticationDomainName != "" {
				environment = append(environment, prefix+".auth="+endpoint.authenticationDomainName)
			}
			if endpoint.dohPath != "" {
				environment = append(environment, prefix+".dohpath="+endpoint.dohPath)
			}
			if endpoint.port != 0 {
				environment = append(environment, prefix+".port="+strconv.Itoa(int(endpoint.port)))
			}
		}
	}
	return environment
}

func (t *assignedDNSTransport) Start(stage adapter.StartStage) error { return nil }

func (t *assignedDNSTransport) Close() error { return nil }

func (t *assignedDNSTransport) Reset() {}

// Exchange sends one query through the tunnel, to the resolver responsible for its name.
//
// # Configuration selection before resolver selection
//
// The name decides WHICH configuration answers; the priority orders the resolvers within
// that configuration. The previous implementation skipped the first step entirely and
// ranked every resolver in the assignment against every other, so a resolver for
// `corp.example.` could answer a public name purely because it had a lower priority number.
//
// # Transport capability is binding
//
// A resolver that advertises only encrypted transports must not be reached in cleartext.
// When `no-default-alpn` is present the server has explicitly said the default transport is
// not offered, so falling back to plain UDP/53 would violate the assignment rather than
// degrade gracefully. In that case an unsupported transport is a FAILURE for that resolver,
// and the next resolver in the same configuration is tried. If none can be used, the query
// fails closed.
func (t *assignedDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	state := t.state.Load()
	if state == nil || !state.hasResolvers() {
		// Fail closed. Returning a "no upstream" error rather than falling through to
		// a host resolver is the entire point of this type.
		return nil, E.New("no MASQUE DNS assignment in effect")
	}
	var name string
	if len(message.Question) > 0 {
		name = message.Question[0].Name
	}
	lookup := state.selectForName(name)
	if !lookup.found {
		// The assignment carries configurations, but none of them covers this name and
		// there is no default. Refusing is correct: answering from a resolver that never
		// claimed the name is exactly the misrouting this model exists to prevent.
		return nil, E.New("no assigned DNS configuration covers ", name)
	}

	packed, err := message.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}
	// Resolvers of the CHOSEN configuration, by priority, so a resolver that cannot be used
	// falls back within its own configuration instead of jumping to an unrelated one.
	var lastErr error
	for _, endpoint := range lookup.configuration.resolversByPreference() {
		response, exchangeErr := t.exchangeWith(ctx, endpoint, packed)
		if exchangeErr == nil {
			return response, nil
		}
		lastErr = exchangeErr
		t.logger.DebugContext(ctx, "assigned DNS resolver ",
			endpoint.describe(), " failed: ", exchangeErr)
	}
	return nil, E.Cause(lastErr, "all assigned DNS resolvers for ", name, " failed")
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
func (t *assignedDNSTransport) exchangeWith(ctx context.Context, endpoint assignedResolverEndpoint, query []byte) (*mDNS.Msg, error) {
	transport, err := endpoint.selectTransport(t.dohClient != nil)
	if err != nil {
		// The resolver's advertised capabilities cannot be honoured. This is returned
		// rather than worked around: see selectTransport for why silently downgrading is
		// not an option when no-default-alpn is present.
		return nil, err
	}
	t.logger.DebugContext(ctx, "assigned DNS resolver ", endpoint.describe(),
		" selected transport ", transport)
	switch transport {
	case assignedTransportDoH:
		return t.exchangeDoH(ctx, endpoint, query)
	case assignedTransportPlainUDP:
		return t.exchangeUDP(ctx, endpoint, query)
	default:
		return nil, E.New("assigned DNS resolver ", endpoint.describe(),
			": transport ", transport, " is not implemented by this client")
	}
}

// assignedTransport names a DNS transport this client can actually use.
type assignedTransport string

const (
	assignedTransportPlainUDP assignedTransport = "udp"
	assignedTransportDoH      assignedTransport = "doh"
	// assignedTransportDoT is recognised and deliberately NOT implemented. Naming it lets
	// the client report "this resolver wants DoT and I cannot do DoT" instead of pretending
	// the resolver has no usable transport at all, which would be a misleading error.
	assignedTransportDoT assignedTransport = "dot"
)

// selectTransport decides how a query reaches this resolver.
//
// # The rule
//
//	dohpath advertised, same-connection DoH available   -> DoH
//	no-default-alpn present                             -> encrypted only (DoH or nothing)
//	otherwise                                           -> DoH when available, else plain UDP
//
// # Why no-default-alpn is binding rather than advisory
//
// The parameter means "do not use the default transport for this ALPN", and its whole
// purpose is to tell a client that unencrypted DNS is NOT offered. Falling back to plain
// UDP/53 in that case does not degrade gracefully; it sends the query in cleartext to a
// server that explicitly said not to, which is a privacy failure the parameter exists to
// prevent. So when it is present and the advertised transports cannot be used, this returns
// an error and the caller tries the next resolver in the same configuration.
//
// # Why DoT is refused rather than attempted
//
// This client has no DoT transport. Reporting that plainly is better than silently using
// something else, because the resolver's operator chose DoT deliberately. Implementing DoT
// is out of scope for this round; refusing is not the same as ignoring.
//
// sameH3DoHAvailable reports whether the same-connection DoH path can be used at all. It is
// passed in rather than read here so the decision is a pure function of the endpoint's
// metadata plus one boolean, which is what makes it directly testable.
func (e assignedResolverEndpoint) selectTransport(sameH3DoHAvailable bool) (assignedTransport, error) {
	if len(e.addresses) == 0 {
		return "", E.New("assigned DNS resolver ", e.describe(), " has no address")
	}

	// 1. The best available transport: same-connection DoH.
	if e.dohPath != "" && e.authenticationDomainName != "" && sameH3DoHAvailable {
		return assignedTransportDoH, nil
	}

	// 2. Whether the DEFAULT transport is still permitted.
	//
	// This is decided by no-default-alpn alone. An ALPN list without it names transports the
	// resolver ALSO offers; it does not withdraw unencrypted DNS. Reading it as a
	// restriction would refuse resolvers that explicitly still allow the default, which
	// would break plain DNS for no reason.
	if !e.noDefaultALPN {
		return assignedTransportPlainUDP, nil
	}

	// 3. Encrypted-only. Nothing may fall through to cleartext.
	if len(e.alpn) == 0 {
		// Encrypted-only was demanded but no protocol was named, so there is nothing to
		// check the client against. Refuse rather than assume.
		return "", E.New("assigned DNS resolver ", e.describe(),
			" requires no-default-alpn but advertises no ALPN")
	}
	if e.offersDoH() {
		if e.dohPath == "" {
			return "", E.New("assigned DNS resolver ", e.describe(),
				" offers DoH but advertises no dohpath, so there is no resource to query")
		}
		if e.authenticationDomainName == "" {
			return "", E.New("assigned DNS resolver ", e.describe(),
				" offers DoH but advertises no authentication domain name")
		}
		// DoH is advertised, has a path and a name, but the same-connection client is not
		// available yet. That is a transient state rather than a capability gap.
		return "", E.New("assigned DNS resolver ", e.describe(),
			" offers DoH but no same-connection HTTP/3 client is available")
	}
	if e.offersDoT() {
		return "", E.New("assigned DNS resolver ", e.describe(),
			" offers DoT, which this client does not implement")
	}
	return "", E.New("assigned DNS resolver ", e.describe(),
		" advertises ALPN ", e.alpn, " with no-default-alpn; none of those transports can be used")
}

// offersDoH reports whether the advertised ALPN list includes a DoH protocol.
func (e assignedResolverEndpoint) offersDoH() bool {
	for _, protocol := range e.alpn {
		if protocol == "h2" || protocol == "h3" {
			return true
		}
	}
	return false
}

// offersDoT reports whether the advertised ALPN list includes DoT.
func (e assignedResolverEndpoint) offersDoT() bool {
	for _, protocol := range e.alpn {
		if protocol == "dot" {
			return true
		}
	}
	return false
}

// describe renders a resolver for logs and errors. It reports the metadata that belongs to
// THIS resolver, which is what makes a misrouting bug legible in a log.
func (e assignedResolverEndpoint) describe() string {
	description := ""
	if len(e.addresses) > 0 {
		description = e.addresses[0].String()
	} else if e.authenticationDomainName != "" {
		description = e.authenticationDomainName
	} else {
		description = "<no address>"
	}
	if e.authenticationDomainName != "" {
		description += " (" + e.authenticationDomainName + ")"
	}
	return description
}

// dnsPort is the port plain DNS should be sent to.
func (e assignedResolverEndpoint) dnsPort() uint16 {
	if e.port != 0 {
		return e.port
	}
	return assignedDNSDefaultPort
}

// dohPort is the port a DoH request should be addressed to.
//
// The dohpath is an HTTP resource, so its default is the HTTPS port; using the plain DNS
// default of 53 would send an HTTPS request to the DNS port.
func (e assignedResolverEndpoint) dohPort() uint16 {
	if e.port != 0 {
		return e.port
	}
	if e.dohPath != "" {
		return 443
	}
	return 0
}

// exchangeDoH sends the query as an RFC 8484 POST on the endpoint's existing HTTP/3
// connection.
//
// EVERY value in the request comes from THIS resolver endpoint. Taking the authority from
// one nameserver and the port or path from another would address the request to an origin
// the connection was never authenticated for: the same-origin check would reject it at
// best, and at worst a future relaxation would let a query be sent under credentials that
// were never presented for that origin.
func (t *assignedDNSTransport) exchangeDoH(ctx context.Context, endpoint assignedResolverEndpoint, query []byte) (*mDNS.Msg, error) {
	roundTripper := t.dohClient
	if roundTripper == nil {
		return nil, E.New("no same-connection HTTP/3 client for DoH")
	}
	// selectTransport only routes here when an authentication domain is present, so this
	// is a guard against a future caller rather than a reachable branch.
	if endpoint.authenticationDomainName == "" {
		return nil, E.New("assigned DNS resolver ", endpoint.describe(),
			" cannot use DoH without an authentication domain name")
	}
	authority := endpoint.authenticationDomainName
	if port := endpoint.dohPort(); port != 0 && port != 443 {
		authority = joinAuthority(endpoint.authenticationDomainName, port)
	}
	requestURL := &url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   dohPathTemplate(endpoint.dohPath),
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
	// One byte PAST the ceiling is read deliberately, so an oversized response is reported
	// as oversized. Reading exactly the ceiling would silently truncate a larger message,
	// and the resulting error would name the DNS decoder rather than the real problem.
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAssignedDNSMessageSize+1))
	if err != nil {
		return nil, E.Cause(err, "read DoH response")
	}
	if len(payload) > maxAssignedDNSMessageSize {
		return nil, E.New("DoH response exceeds ", maxAssignedDNSMessageSize,
			" bytes; refusing to parse a possibly truncated message")
	}
	var message mDNS.Msg
	if err = message.Unpack(payload); err != nil {
		return nil, E.Cause(err, "decode DoH response")
	}
	return &message, nil
}

// joinAuthority appends a port to a host, bracketing an IPv6 literal so the result is a
// valid authority rather than one whose colons are ambiguous.
func joinAuthority(host string, port uint16) string {
	if parsed, err := netip.ParseAddr(host); err == nil && parsed.Is6() && !parsed.Is4In6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// exchangeUDP performs one query against one nameserver over plain DNS through the tunnel.
func (t *assignedDNSTransport) exchangeUDP(ctx context.Context, endpoint assignedResolverEndpoint, query []byte) (*mDNS.Msg, error) {
	if len(endpoint.addresses) == 0 {
		return nil, E.New("assigned DNS resolver ", endpoint.describe(), " has no address")
	}
	destination := M.SocksaddrFrom(endpoint.addresses[0], endpoint.dnsPort())

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

// setDoHClient publishes the client used for same-connection DoH.
//
// It is called ONCE, from the constructor, before the transport can be reached by any
// query: the endpoint publishes it immediately after building the HTTP client and before
// the tunnel exists. The invariant is therefore that dohClient is immutable after
// construction, and Exchange reads it without a lock.
//
// The read is still guarded by a nil check rather than by an assumption, because the field
// is also legitimately nil for a caller that never sets it, and a query must fail closed in
// that case rather than panic.
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
