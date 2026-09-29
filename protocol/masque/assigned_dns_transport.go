package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"mime"
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
	// capability is what this client can currently do. It is remembered so a republish on a
	// capability change does not need the caller to resupply it.
	capability resolverCapability

	// generation is the last allocated generation. The value itself lives INSIDE the
	// published snapshot, so a reader can never observe a resolver list and a generation
	// that disagree; this field only allocates the next one.
	generation uint64
	// pref64 is the current NAT64 prefix set. It is kept for republishing on a capability
	// change, and it is deliberately NOT part of the DNS cache identity because it does not
	// participate in resolution.
	pref64 []netip.Prefix

	// dohClient issues DoH requests on the SAME HTTP/3 connection the CONNECT-IP tunnel
	// uses. It is nil until the endpoint publishes one, and the DoH path is only taken
	// when it is present: without it there is no same-connection transport to use, and
	// a DoH query sent any other way would not be the thing this path exists to prove.
	dohClient dohRoundTripper

	access sync.Mutex
}

// dohRoundTripper is the narrow capability the assigned-DNS transport needs: the ability to
// issue an ordinary request on the MASQUE HTTP/3 connection that ALREADY exists.
//
// # Why the method is "existing"
//
// The generic request API dials when there is no connection, which is correct for a caller
// that owns connection lifetime. For assigned DoH it is wrong: draft-ietf-masque-connect-ip-dns-06
// §3.5 asks for the queries to be COALESCED over the connection the tunnel already uses, so a
// DNS query must never be the reason a second connection appears. Naming the method after that
// requirement is what keeps the guarantee checkable rather than conventional.
//
// It is declared here, rather than taking transport/http's concrete client, so this package
// cannot reach further into that client than the one method it uses, and so the DoH path can be
// tested with a double that counts connections.
type dohRoundTripper interface {
	RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
}

// dohConnectionState reports whether a live HTTP/3 connection exists, and its authority.
//
// It is the same question the endpoint asks when building the capability, exposed here so the
// transport can re-check liveness at query time: a connection can die between the capability
// being computed and a query being sent, and dialing a replacement for a DNS query is exactly
// what must not happen.
type dohConnectionState interface {
	HTTP3ConnectionState() (string, bool)
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
func (t *assignedDNSTransport) apply(configurations []masque.DNSConfiguration, pref64 []netip.Prefix, capability resolverCapability) {
	t.access.Lock()
	defer t.access.Unlock()
	t.applyLocked(configurations, pref64, capability)
}

// applyLocked publishes a new state, allocating a generation ONLY when the effective DNS
// behaviour actually changed.
//
// # Why the generation is not simply incremented
//
// Every UpdateConfiguration used to bump it, and UpdateConfiguration is called for address
// changes, PREF64 updates and route advertisements as well as DNS_ASSIGN. Only some of those
// can change an answer:
//
//	DNS_ASSIGN changed                  -> answers change, new generation
//	internal domains changed            -> routing changes, new generation
//	a resolver became (un)usable,
//	  e.g. because routes changed       -> where queries go changes, new generation
//	PREF64 only                         -> no effect on resolution, SAME generation
//	identical reapply                   -> no change at all, SAME generation
//
// Invalidating the cache for the last two is not free: a reconnect that re-advertises the
// same routes would throw away every cached answer. And always bumping HID the case that
// matters, because a route change that breaks a resolver was indistinguishable from a
// no-op.
//
// The comparison is on a deterministic identity built from resolver-relevant facts, so it
// cannot depend on Go map iteration order.
func (t *assignedDNSTransport) applyLocked(configurations []masque.DNSConfiguration, pref64 []netip.Prefix, capability resolverCapability) {
	t.capability = capability
	// Build with the CURRENT generation first: the identity does not depend on the
	// generation, so this lets us compare before deciding whether to allocate a new one.
	candidate := buildAssignedDNSState(configurations, pref64, t.generation, capability)
	if current := t.state.Load(); current != nil && current.hasAssignment && current.identity == candidate.identity {
		// Effective DNS behaviour is unchanged. Keep the generation, but still publish the
		// new snapshot so PREF64 and other non-DNS state stays current.
		candidate.generation = current.generation
		t.state.Store(candidate)
		t.pref64 = append([]netip.Prefix(nil), pref64...)
		return
	}
	t.generation++
	candidate.generation = t.generation
	t.state.Store(candidate)
	t.pref64 = append([]netip.Prefix(nil), pref64...)
}

// setCapability republishes the state when the client's own capability changed, which happens
// when the tunnel's transport or its routes change.
//
// This exists because usability is a JOINT property of the advertisement and the client: the
// same DNS_ASSIGN becomes usable or unusable depending on whether the tunnel is H3 and which
// ranges were advertised. Without re-evaluating, a tunnel that reconnects over H2 would keep
// offering same-H3 DoH on a connection that no longer exists.
func (t *assignedDNSTransport) setCapability(capability resolverCapability) {
	t.access.Lock()
	defer t.access.Unlock()
	current := t.state.Load()
	if current == nil || !current.hasAssignment {
		return
	}
	// Re-evaluate availability against the NEW capability, keeping the same configurations
	// and the same claims. Rebuilding from the runtime model rather than re-parsing avoids a
	// lossy round-trip through the wire types.
	t.publish(recomputeAvailability(current, capability), capability)
}

// publish installs a state that was built from an existing one, applying the same
// generation rule as applyLocked.
func (t *assignedDNSTransport) publish(candidate *assignedDNSState, capability resolverCapability) {
	t.capability = capability
	candidate.identity = candidate.resolverIdentity()
	current := t.state.Load()
	if current != nil && current.hasAssignment && current.identity == candidate.identity {
		candidate.generation = current.generation
	} else {
		t.generation++
		candidate.generation = t.generation
	}
	t.state.Store(candidate)
}

// clear removes the assignment.
func (t *assignedDNSTransport) clear() {
	t.apply(nil, nil, resolverCapability{})
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
	if state == nil || !state.hasAssignment {
		// Nothing was assigned. Fail closed: returning a "no upstream" error rather than
		// falling through to a host resolver is the entire point of this type.
		return nil, E.New("no MASQUE DNS assignment in effect")
	}
	var name string
	if len(message.Question) > 0 {
		name = message.Question[0].Name
	}

	lookup := state.selectForName(name)
	if !lookup.claimed {
		// The assignment exists, but no configuration CLAIMS this name. That is not a
		// failure -- it is the split-DNS case, and the endpoint must send this query to the
		// ordinary resolver instead. The endpoint decides that, because only it knows the
		// ordinary rules; this transport simply reports that it has no claim.
		return nil, E.New("assigned DNS does not claim ", name)
	}

	packed, err := message.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}

	// Walk the claiming configuration's resolvers by priority.
	//
	// A resolver that cannot be used is a failure for THAT resolver, not for the query:
	// the next one in the same configuration is tried. What must never happen is falling
	// back to a resolver outside this configuration, because those serve different names --
	// and what must never happen either is falling through to a host resolver, because the
	// name is claimed and the claim is what makes the privacy guarantee.
	var lastErr error
	for index, endpoint := range lookup.configuration.resolversByPreference() {
		availability := availabilityFor(lookup, endpoint, index)
		if !availability.usable() {
			lastErr = E.New("assigned DNS resolver ", endpoint.describe(),
				" is unusable: ", availability.reason)
			t.logger.DebugContext(ctx, lastErr)
			continue
		}
		response, exchangeErr := t.exchangeWith(ctx, endpoint, availability, packed)
		if exchangeErr == nil {
			return response, nil
		}
		lastErr = exchangeErr
		t.logger.DebugContext(ctx, "assigned DNS resolver ",
			endpoint.describe(), " failed: ", exchangeErr)
	}
	if lastErr == nil {
		lastErr = E.New("the claiming configuration has no resolvers")
	}
	// FAIL CLOSED. The name is claimed, so there is no acceptable outcome in which someone
	// else answers it.
	return nil, E.Cause(lastErr, "all assigned DNS resolvers for ", name, " failed")
}

// availabilityFor pairs a resolver with its precomputed availability.
//
// The lookup carries the availability list in the CONFIGURATION's order, while the iteration
// above is in PRIORITY order, so the index cannot be reused directly. The match is by the
// resolver's identity instead, which is stable because both lists hold the same values.
func availabilityFor(lookup endpointLookup, endpoint assignedResolverEndpoint, fallbackIndex int) resolverAvailability {
	for index, candidate := range lookup.configuration.resolvers {
		if sameResolver(candidate, endpoint) {
			if index < len(lookup.availability) {
				return lookup.availability[index]
			}
			break
		}
	}
	if fallbackIndex < len(lookup.availability) {
		return lookup.availability[fallbackIndex]
	}
	return resolverAvailability{reason: unusableNoAddress}
}

// sameResolver reports whether two endpoint values describe the same resolver.
//
// The comparison is on the immutable identity fields, not on the whole struct, because the
// metadata slices are not comparable and pointer equality would be wrong after a copy.
func sameResolver(first assignedResolverEndpoint, second assignedResolverEndpoint) bool {
	if first.priority != second.priority ||
		first.authenticationDomainName != second.authenticationDomainName ||
		first.dohPath != second.dohPath ||
		first.port != second.port ||
		first.hasPort != second.hasPort ||
		len(first.addresses) != len(second.addresses) {
		return false
	}
	for index := range first.addresses {
		if first.addresses[index] != second.addresses[index] {
			return false
		}
	}
	return true
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
func (t *assignedDNSTransport) exchangeWith(ctx context.Context, endpoint assignedResolverEndpoint, availability resolverAvailability, query []byte) (*mDNS.Msg, error) {
	// The transport was decided when the effective state was built, so this does not
	// re-derive it and cannot disagree with what the environment reports.
	switch availability.transport {
	case assignedTransportDoH:
		return t.exchangeDoH(ctx, endpoint, query)
	case assignedTransportPlainUDP:
		return t.exchangePlain(ctx, endpoint, availability, query)
	default:
		return nil, E.New("assigned DNS resolver ", endpoint.describe(),
			": transport ", availability.transport, " is not implemented by this client")
	}
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
	// Re-check that the connection is still alive. The capability was computed when the state
	// was published, and a tunnel can go away in between; using the existing-connection API
	// below means a dead connection is reported rather than silently replaced by a new one.
	if state, isState := roundTripper.(dohConnectionState); isState {
		if _, live := state.HTTP3ConnectionState(); !live {
			return nil, E.New("the HTTP/3 connection for same-connection DoH is no longer live")
		}
	}
	// availability() only selects DoH when an authentication domain and a usable template are
	// present, so these are guards against a future caller rather than reachable branches.
	if endpoint.authenticationDomainName == "" {
		return nil, E.New("assigned DNS resolver ", endpoint.describe(),
			" cannot use DoH without an authentication domain name")
	}
	if endpoint.expandedDohPath == "" {
		return nil, E.New("assigned DNS resolver ", endpoint.describe(),
			" cannot use DoH without a usable dohpath")
	}
	// EVERY value in the request comes from THIS resolver. Taking the authority from one
	// nameserver and the port or path from another would address the request to an origin the
	// connection was never authenticated for.
	authority := endpoint.authenticationDomainName
	if endpoint.hasPort && endpoint.port != 443 {
		authority = joinAuthority(endpoint.authenticationDomainName, endpoint.port)
	}

	// RFC 8484 §4.1: "DoH clients using media formats that include the ID field from the DNS
	// message header, such as application/dns-message, SHOULD use a DNS ID of 0 in every DNS
	// request." A varying ID causes semantically equivalent queries to be cached separately.
	//
	// The caller's message is COPIED, never mutated: the DNS router owns it, matches the
	// response against it, and would be corrupted by a silent ID change.
	wireQuery := append([]byte(nil), query...)
	originalID, err := zeroDNSMessageID(wireQuery)
	if err != nil {
		return nil, err
	}

	requestURL := &url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   endpoint.expandedDohPath,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(wireQuery))
	if err != nil {
		return nil, E.Cause(err, "build DoH request")
	}
	request.Header.Set("Content-Type", dnsTransport.MimeType)
	request.Header.Set("Accept", dnsTransport.MimeType)
	// The body length is known, and stating it lets the server reject a truncated query
	// instead of parsing a partial one.
	request.ContentLength = int64(len(wireQuery))

	response, err := roundTripper.RoundTripExistingHTTP3(ctx, request)
	if err != nil {
		return nil, E.Cause(err, "DoH request on MASQUE connection")
	}
	defer response.Body.Close()

	// RFC 8484 §4.2.1: "A successful HTTP response with a 2xx status code is used for any
	// valid DNS response, regardless of the DNS response code." So the whole 2xx range is a
	// success, not just 200 -- a 201 or 204 carrying a DNS body is a valid answer.
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// Read a bounded prefix so a server that explains the failure has its explanation
		// surfaced, without letting it stream unbounded data into the error.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, maxDoHErrorBodySize))
		return nil, E.New("DoH server returned ", response.Status, formatDoHErrorDetail(detail))
	}
	if err = checkDoHMediaType(response); err != nil {
		return nil, err
	}

	// One byte PAST the ceiling is read deliberately, so an oversized response is reported as
	// oversized. Reading exactly the ceiling would silently truncate a larger message, and the
	// resulting error would name the DNS decoder rather than the real problem.
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAssignedDNSMessageSize+1))
	if err != nil {
		return nil, E.Cause(err, "read DoH response")
	}
	if len(payload) > maxAssignedDNSMessageSize {
		return nil, E.New("DoH response exceeds ", maxAssignedDNSMessageSize,
			" bytes; refusing to parse a possibly truncated message")
	}
	if len(payload) == 0 {
		// A 2xx with no body carries no DNS message. Saying so is clearer than a decoder
		// error about a truncated header.
		return nil, E.New("DoH response carried no DNS message")
	}
	var message mDNS.Msg
	if err = message.Unpack(payload); err != nil {
		return nil, E.Cause(err, "decode DoH response")
	}
	// Restore the caller's ID. The router sent this query with that ID and matches the reply
	// against it, so returning the wire ID would break correlation.
	message.Id = originalID
	return &message, nil
}

// zeroDNSMessageID sets the ID field of a packed DNS message to zero and returns the original.
//
// The caller's message is packed before this runs, so the mutation is on our own copy of the
// wire bytes and the caller's mDNS.Msg is untouched.
func zeroDNSMessageID(packed []byte) (uint16, error) {
	if len(packed) < 2 {
		return 0, E.New("DNS message is too short to contain an ID")
	}
	originalID := uint16(packed[0])<<8 | uint16(packed[1])
	packed[0] = 0
	packed[1] = 0
	return originalID, nil
}

// checkDoHMediaType validates the response content type.
//
// RFC 8484 §4.2 defines application/dns-message as the only response type, and §5.4 requires
// both peers to support it. The spec sets no MUST for the client when the header is ABSENT, so
// absence is tolerated; but a response that DECLARES a different type is refused, because
// otherwise an HTML error page from an intercepting proxy would be handed to the DNS decoder
// and reported as a corrupt message rather than as what it is.
//
// The comparison uses proper MIME parsing, so parameters (`; charset=...`) and case do not
// defeat it.
func checkDoHMediaType(response *http.Response) error {
	contentType := response.Header.Get("Content-Type")
	if contentType == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return E.New("DoH response has an unparseable Content-Type: ", contentType)
	}
	if !strings.EqualFold(mediaType, dnsTransport.MimeType) {
		return E.New("DoH response has Content-Type ", mediaType, ", expected ", dnsTransport.MimeType)
	}
	return nil
}

// joinAuthority appends a port to a host, bracketing an IPv6 literal so the result is a
// valid authority rather than one whose colons are ambiguous.
func joinAuthority(host string, port uint16) string {
	if parsed, err := netip.ParseAddr(host); err == nil && parsed.Is6() && !parsed.Is4In6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// exchangePlain performs one query over traditional DNS (RFC 1035) through the tunnel.
//
// # Every address is tried, not just the first
//
// A nameserver structure may carry several IPv4 and IPv6 addresses, and all of them are
// advertised as ways to reach the same resolver. Using only the first would mean a resolver
// whose first address is stale or unreachable is treated as entirely unusable, and the
// remaining addresses -- which the server explicitly offered -- are never contacted.
//
// The order is the wire order, which is the order the server chose. Each attempt is through
// the MASQUE device; nothing here can reach a host resolver.
//
// # A truncated answer is retried over TCP
//
// RFC 1035 §4.2.1: a UDP response with TC set means the answer did not fit and the query
// should be retried over TCP. draft-06 §3.2 defines the unencrypted transport as "UDP port 53
// and TCP port 53", so TCP is part of what this resolver offers and the retry belongs here
// rather than being left to the caller.
//
// The retry goes to an address the advertised routes permit for TCP specifically. A route
// advertised only for UDP does not make the TCP retry reachable, and pretending otherwise
// would put the query on the host network.
func (t *assignedDNSTransport) exchangePlain(ctx context.Context, endpoint assignedResolverEndpoint, availability resolverAvailability, query []byte) (*mDNS.Msg, error) {
	if len(availability.addresses) == 0 {
		return nil, E.New("assigned DNS resolver ", endpoint.describe(), " has no reachable address")
	}
	var lastErr error
	for _, address := range availability.addresses {
		response, err := t.exchangeUDP(ctx, endpoint, address, query)
		if err != nil {
			lastErr = err
			t.logger.DebugContext(ctx, "assigned DNS UDP to ", address, " failed: ", err)
			continue
		}
		if !response.Truncated {
			return response, nil
		}
		// The answer was truncated. Retry over TCP, which is required to produce a complete
		// answer for a response that did not fit in a datagram.
		tcpAddresses := endpoint.tcpReachableAddresses(t.capability.routes)
		if len(tcpAddresses) == 0 {
			return nil, E.New("assigned DNS resolver ", endpoint.describe(),
				" returned a truncated answer, and no address is reachable over TCP through the advertised routes for the retry")
		}
		for _, tcpAddress := range tcpAddresses {
			retried, tcpErr := t.exchangeTCP(ctx, endpoint, tcpAddress, query)
			if tcpErr != nil {
				lastErr = tcpErr
				t.logger.DebugContext(ctx, "assigned DNS TCP to ", tcpAddress, " failed: ", tcpErr)
				continue
			}
			return retried, nil
		}
	}
	if lastErr == nil {
		lastErr = E.New("no address could be reached")
	}
	return nil, E.Cause(lastErr, "assigned DNS resolver ", endpoint.describe(), " unreachable")
}

// exchangeUDP performs one query against one address over UDP through the tunnel.
func (t *assignedDNSTransport) exchangeUDP(ctx context.Context, endpoint assignedResolverEndpoint, address netip.Addr, query []byte) (*mDNS.Msg, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkUDP, M.SocksaddrFrom(address, endpoint.dnsPort()))
	if err != nil {
		return nil, E.Cause(err, "dial assigned nameserver over UDP through tunnel")
	}
	defer conn.Close()
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	// Over a connected UDP socket the DNS message stands alone; RFC 1035 §4.2.1's two-byte
	// length prefix applies only to stream transports.
	if _, err = conn.Write(query); err != nil {
		return nil, E.Cause(err, "write DNS query over UDP")
	}
	buffer := buf.NewSize(maxAssignedDNSMessageSize)
	defer buffer.Release()
	_, err = buffer.ReadOnceFrom(conn)
	if err != nil {
		if err == io.EOF {
			return nil, E.New("assigned nameserver closed the connection")
		}
		return nil, E.Cause(err, "read DNS response over UDP")
	}
	var response mDNS.Msg
	if err = response.Unpack(buffer.Bytes()); err != nil {
		return nil, E.Cause(err, "decode DNS response")
	}
	return &response, nil
}

// exchangeTCP performs one query against one address over TCP through the tunnel.
//
// RFC 1035 §4.2.2: over a stream, the message carries a two-byte big-endian length prefix.
func (t *assignedDNSTransport) exchangeTCP(ctx context.Context, endpoint assignedResolverEndpoint, address netip.Addr, query []byte) (*mDNS.Msg, error) {
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(address, endpoint.dnsPort()))
	if err != nil {
		return nil, E.Cause(err, "dial assigned nameserver over TCP through tunnel")
	}
	defer conn.Close()
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		_ = conn.SetDeadline(deadline)
	}
	if len(query) > 0xffff {
		return nil, E.New("DNS query is too large for the TCP length prefix")
	}
	framed := make([]byte, 0, len(query)+2)
	framed = append(framed, byte(len(query)>>8), byte(len(query)))
	framed = append(framed, query...)
	if _, err = conn.Write(framed); err != nil {
		return nil, E.Cause(err, "write DNS query over TCP")
	}
	var lengthPrefix [2]byte
	if _, err = io.ReadFull(conn, lengthPrefix[:]); err != nil {
		return nil, E.Cause(err, "read DNS response length over TCP")
	}
	responseLength := int(lengthPrefix[0])<<8 | int(lengthPrefix[1])
	if responseLength == 0 {
		return nil, E.New("assigned nameserver returned an empty TCP response")
	}
	if responseLength > maxAssignedDNSMessageSize {
		return nil, E.New("assigned nameserver announced ", responseLength,
			" bytes over TCP, beyond the ", maxAssignedDNSMessageSize, " byte ceiling")
	}
	payload := make([]byte, responseLength)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return nil, E.Cause(err, "read DNS response over TCP")
	}
	var response mDNS.Msg
	if err = response.Unpack(payload); err != nil {
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

// setDoHClient publishes the client used for same-connection DoH.
//
// It is called ONCE, from the constructor, before the transport can be reached by any query:
// the endpoint publishes the HTTP client immediately after building it and before the tunnel
// exists. The invariant is therefore that dohClient is immutable after construction, and
// Exchange reads it without a lock.
//
// The read is still guarded by a nil check rather than by an assumption, because the field is
// also legitimately nil for a caller that never sets it, and a query must fail closed in that
// case rather than panic.
func (t *assignedDNSTransport) setDoHClient(client dohRoundTripper) {
	t.access.Lock()
	t.dohClient = client
	t.access.Unlock()
}

// claimsName reports whether the current assignment claims this name.
//
// This is the question the endpoint asks before choosing between the assigned resolver and the
// ordinary rules, and it is deliberately ANSWERED WITHOUT REFERENCE TO USABILITY: who owns a
// name and whether the owner is currently reachable are different facts, and conflating them
// is how an internal name leaks to a public resolver when its own nameserver is down.
func (t *assignedDNSTransport) claimsName(name string) bool {
	state := t.state.Load()
	if state == nil || !state.hasAssignment {
		return false
	}
	return state.claimsName(name)
}
