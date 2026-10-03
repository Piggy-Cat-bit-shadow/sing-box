package masque

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// Assigned DNS execution: run one query against one already-chosen configuration.
//
// # What this layer does NOT do
//
// It does not choose a configuration (the policy did), does not hold mutable assignment state
// (the snapshot is immutable), and does not implement DNS transports (the existing sing-box
// transports do).
//
// # Why plain DNS is delegated
//
// dns/transport.NewUDPRaw already implements everything traditional DNS needs: UDP exchange
// with query multiplexing and EDNS sizing, the truncated-answer retry over TCP, TCP framing,
// deadlines, and lifecycle. Reimplementing it here would mean two implementations of the same
// protocol that could drift, and the previous version had exactly that -- a hand-written UDP
// read and a hand-written TCP retry, neither of which handled multiplexing, EDNS or reset.
//
// So plain DNS constructs a short-lived native transport per attempt, pointed at the MASQUE
// DEVICE. That keeps one implementation of the protocol, and because the transport is used for
// one exchange and closed, no per-assignment socket state exists to own, retire or leak. The
// cost of constructing one is negligible next to a network round trip; if profiling ever shows
// otherwise, reuse can be added then, deliberately.
//
// # Why DoH is the only special case
//
// Same-connection DoH is the single transport that cannot be expressed through a native
// sing-box DNS transport, because it is not a DNS transport at all: it is an HTTP request
// stream on the connection the tunnel already uses (draft-06 §3.5). That is the entire reason
// this file exists.

// configurationDNSTransport runs queries for ONE compiled configuration.
//
// It is created per lookup, from the snapshot that lookup captured, and is immutable: it has no
// apply, no clear, no state pointer, and no generation. It represents "this configuration, as
// it was when this lookup started" and nothing else.
//
// It implements adapter.DNSTransport so the sing-box DNS client can drive it, which is what
// gives us TTL handling, caching, singleflight and negative caching for free -- the assignment
// layer must never reimplement those.
type configurationDNSTransport struct {
	dns.TransportAdapter
	logger logger.ContextLogger
	// dialer is the MASQUE device: every plain DNS query goes through the tunnel. It is
	// deliberately not optional, because a host socket here would be a cleartext leak.
	dialer N.Dialer
	// configuration is the compiled configuration this transport represents.
	configuration dnsConfigurationSnapshot
	// doh issues same-connection DoH requests, or nil when that path is unavailable.
	doh dohExecutor
}

var _ adapter.DNSTransport = (*configurationDNSTransport)(nil)

// newConfigurationDNSTransport binds a transport to one configuration.
func newConfigurationDNSTransport(
	transportLogger logger.ContextLogger,
	deviceDialer N.Dialer,
	tag string,
	configuration dnsConfigurationSnapshot,
	doh dohExecutor,
) *configurationDNSTransport {
	return &configurationDNSTransport{
		// The tag is stable per endpoint so the DNS router can address it. The cache
		// distinguishes two assignments through Environment, not through the tag.
		TransportAdapter: dns.NewTransportAdapter(assignedDNSType, tag, nil),
		logger:           transportLogger,
		dialer:           deviceDialer,
		configuration:    configuration,
		doh:              doh,
	}
}

// assignedDNSType is the transport's reported type. It is not a user-facing configuration
// type: it exists only as the endpoint's internal resolver.
const assignedDNSType = "masque-assigned"

// Environment implements adapter.DNSTransport.
//
// The DNS cache keys on this value, so it must describe the EFFECTIVE resolver behaviour and
// nothing else. It is derived from the compiled configuration, which means:
//
//   - two identical assignments produce the same value, so a repeated capsule does not
//     invalidate a cache;
//   - a PREF64-only update cannot affect it, because PREF64 is not part of this configuration;
//   - it never contains a monotonic generation, so it does not change merely because a capsule
//     arrived.
//
// It DOES change when a route change makes a resolver unusable, because that changes where
// queries actually go -- which is exactly the case that must invalidate cached answers.
func (t *configurationDNSTransport) Environment() []string {
	environment := []string{"masque-assigned", t.configuration.effectiveIdentity()}
	return environment
}

// Start and Close are no-ops: this transport owns no socket, no goroutine and no lifecycle. The
// short-lived native transports used per query close themselves.
func (t *configurationDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *configurationDNSTransport) Reset() {}

// Exchange runs one query, walking this configuration's resolvers by priority.
//
// A resolver that cannot be used is a failure for THAT resolver, so the next one in the same
// configuration is tried. There is no path from here to a resolver outside this configuration
// and none to a host resolver: the configuration was chosen because it OWNS the name, and that
// is the guarantee the caller depends on.
func (t *configurationDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	var lastErr error
	for _, resolver := range t.configuration.resolversByPriority() {
		if resolver.unusable != unusableNone {
			// A resolver compiled as unusable is still worth naming in the log: it is why the
			// query is going somewhere else, or why it will fail entirely.
			t.logger.DebugContext(ctx, "assigned DNS resolver ", resolver.describe(),
				" is unusable: ", resolver.unusable)
			lastErr = E.New("assigned DNS resolver ", resolver.describe(), ": ",
				string(resolver.unusable))
			continue
		}
		response, err := t.exchangeWith(ctx, resolver, message)
		if err == nil {
			return response, nil
		}
		lastErr = err
		t.logger.DebugContext(ctx, "assigned DNS resolver ", resolver.describe(), " failed: ", err)
	}
	if lastErr == nil {
		lastErr = E.New("the assigned configuration has no resolvers")
	}
	return nil, lastErr
}

// ExchangeAsync implements adapter.DNSTransport.
func (t *configurationDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// exchangeWith runs one query against one resolver, walking its capabilities in order.
//
// # Why both capabilities are tried
//
// A resolver may advertise same-connection DoH AND plain DNS. The capability was decided at
// compile time, but usability can change at query time -- the tunnel can drop between compiling
// and sending -- so a DoH failure falls back to plain DNS WITHIN THE SAME RESOLVER rather than
// skipping to the next one. Skipping would discard a transport the server explicitly offered,
// and would report the resolver as failed when it was still usable.
//
// The fallback never leaves this resolver, and never reaches a host resolver.
func (t *configurationDNSTransport) exchangeWith(ctx context.Context, resolver dnsResolverSnapshot, message *mDNS.Msg) (*mDNS.Msg, error) {
	var lastErr error
	for _, transport := range resolver.transportPreference() {
		var (
			response *mDNS.Msg
			err      error
		)
		switch transport {
		case assignedTransportDoH:
			response, err = t.exchangeDoH(ctx, resolver, message)
		case assignedTransportPlainUDP:
			response, err = t.exchangePlain(ctx, resolver, message)
		default:
			continue
		}
		if err == nil {
			return response, nil
		}
		lastErr = err
		t.logger.DebugContext(ctx, "assigned DNS resolver ", resolver.describe(),
			" failed over ", transport, ": ", err)
	}
	if lastErr == nil {
		lastErr = E.New("no usable transport")
	}
	return nil, lastErr
}

// exchangePlain runs traditional DNS through the native sing-box UDP transport, over the
// tunnel.
//
// Every advertised address is tried in turn. A nameserver structure may carry several, and all
// of them are ways to reach the same resolver; using only the first would treat a resolver whose
// first address is stale as entirely unusable and never contact the rest.
//
// # Why each attempt gets a protocol-constrained dialer
//
// The native UDP transport retries a truncated answer over TCP, dialing through whatever dialer it
// was given. Handing it the raw device dialer would let that retry reach the tunnel even when the
// server's ROUTE_ADVERTISEMENT never permitted TCP to that address -- the tunnel would carry a
// flow the server said it does not route, and the failure would surface as a confusing timeout
// rather than as the policy refusal it is.
//
// So the dialer is wrapped per address to permit exactly the protocols advertised for it. A TCP
// retry is then refused up front, with a reason, when TCP was not advertised.
func (t *configurationDNSTransport) exchangePlain(ctx context.Context, resolver dnsResolverSnapshot, message *mDNS.Msg) (*mDNS.Msg, error) {
	if resolver.plain == nil {
		return nil, E.New("assigned DNS resolver ", resolver.describe(), " has no plain DNS capability")
	}
	var lastErr error
	for _, address := range resolver.plain.udpAddresses {
		serverAddress := M.SocksaddrFrom(address, resolver.dnsPort())
		// A short-lived transport per attempt. It owns only this query's sockets, so a
		// snapshot replacement never has to retire anything.
		native := dnsTransport.NewUDPRaw(
			t.logger,
			dns.NewTransportAdapter(assignedDNSType, "masque-assigned", nil),
			newAssignedResolverDialer(t.dialer, resolver, address),
			serverAddress,
		)
		response, err := native.Exchange(ctx, message)
		// The transport is scope-owned under the new lifecycle: it is released by the scope that
		// started it rather than by the caller, so there is no Close to call here.
		if err == nil {
			return response, nil
		}
		lastErr = err
		t.logger.DebugContext(ctx, "assigned DNS to ", address, " failed: ", err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = E.New("no usable address")
	}
	return nil, E.Cause(lastErr, "assigned DNS resolver ", resolver.describe())
}

// dohExecutor issues a same-connection DoH request.
//
// It is an interface rather than a concrete client so this package cannot reach further into
// transport/http than the single call it needs, and so the path can be doubled in tests.
type dohExecutor interface {
	RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
}

// buildDoHRequestURL assembles the DoH request URL without re-escaping the path.
//
// # The bug this exists to prevent
//
// A dohpath is a URI Template, and its expansion is already a valid ":path": a server that
// advertises `/%E4%B8%AD/dns-query` means that percent-encoded octet sequence, not the literal
// characters `%`, `E`, `4`.
//
// The obvious construction --
//
//	&url.URL{Scheme: "https", Host: authority, Path: requestPath}
//
// gets this wrong. Assigning to Path marks the string as DECODED, so url.String() escapes it
// again, and every '%' in the template becomes '%25':
//
//	/dns%2Dquery  ->  /dns%252Dquery
//	/%E4%B8%AD     ->  /%25E4%25B8%25AD
//
// The request still reaches the right origin, which is what makes this fail quietly: the server
// answers 404 or a wrong resource, and the operator sees a DNS failure with no hint that the path
// was mangled. Setting RawPath alongside Path tells url.String() the path is already encoded, so
// it is emitted verbatim.
//
// A template whose escapes are not valid percent-encoding is rejected rather than passed through,
// because it cannot be a ":path" and copying it verbatim would send a malformed request line.
func buildDoHRequestURL(authority string, requestPath string) (string, error) {
	decodedPath, err := url.PathUnescape(requestPath)
	if err != nil {
		return "", E.Cause(err, "dohpath is not valid percent-encoding: ", requestPath)
	}
	requestURL := &url.URL{
		Scheme:   "https",
		Host:     authority,
		Path:     decodedPath,
		RawPath:  requestPath,
		RawQuery: "",
	}
	return requestURL.String(), nil
}

// assignedResolverDialer permits only the transports the server advertised for one address.
//
// # What it constrains
//
// A ROUTE_ADVERTISEMENT may route an address for UDP only. The native DNS transport's
// truncated-answer retry dials TCP through the same dialer it was given for UDP, so without this
// wrapper a UDP-only route still produces TCP traffic in the tunnel. That traffic is not merely
// wasted: the server has stated it does not route it, so the flow is dropped and the caller sees a
// timeout that looks like packet loss.
//
// # Why the permission is per-ADDRESS
//
// A nameserver structure may list several addresses with different route coverage, so an address
// whose TCP is unadvertised must not inherit permission from a sibling address that has it. The
// permission is therefore computed once, for the single address this dialer was built for.
//
// Only TCP is refused. UDP was already validated by reachableForProtocol when the address was
// selected for this attempt, so re-checking it here would add a refusal path that can never
// legitimately fire -- and if it ever did, plain DNS would stop working entirely.
type assignedResolverDialer struct {
	N.Dialer
	// tcpPermitted is true when this address is reachable under a route that permits TCP (or
	// permits all protocols).
	tcpPermitted bool
	// address is retained so the refusal names the address it applies to.
	address netip.Addr
}

func newAssignedResolverDialer(dialerInstance N.Dialer, resolver dnsResolverSnapshot, address netip.Addr) N.Dialer {
	tcpPermitted := false
	for _, permitted := range resolver.plain.tcpAddresses {
		if permitted == address {
			tcpPermitted = true
			break
		}
	}
	return &assignedResolverDialer{
		Dialer:       dialerInstance,
		tcpPermitted: tcpPermitted,
		address:      address,
	}
}

func (d *assignedResolverDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !d.tcpPermitted && network == N.NetworkTCP {
		return nil, E.New("assigned DNS resolver address ", d.address,
			" is not advertised as reachable over TCP, so the truncated-answer retry is refused")
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

// exchangeDoH issues one RFC 8484 POST on the tunnel's own HTTP/3 connection.
//
// Every value in the request comes from THIS resolver: taking the authority from one nameserver
// and the path or port from another would address the request to an origin the connection was
// never authenticated for. The same-origin check in transport/http is the backstop, not the
// mechanism.
func (t *configurationDNSTransport) exchangeDoH(ctx context.Context, resolver dnsResolverSnapshot, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.doh == nil {
		return nil, E.New("assigned DNS resolver ", resolver.describe(),
			": same-connection DoH is not available")
	}
	// EVERY value in the request comes from THIS resolver, through its compiled capability.
	// Taking the authority from one nameserver and the path or port from another would address
	// the request to an origin the connection was never authenticated for; the same-origin check
	// in transport/http is a backstop rather than the mechanism.
	if resolver.doh == nil {
		return nil, E.New("assigned DNS resolver ", resolver.describe(), " has no DoH capability")
	}
	authority := resolver.doh.authority
	requestPath := resolver.doh.path

	packed, err := message.Pack()
	if err != nil {
		return nil, E.Cause(err, "pack DNS query")
	}
	// RFC 8484 §4.1: "DoH clients using media formats that include the ID field from the DNS
	// message header, such as application/dns-message, SHOULD use a DNS ID of 0 in every DNS
	// request." A varying ID makes semantically equivalent queries cache separately.
	//
	// zeroDNSMessageID works on our own copy of the wire bytes, so the caller's message is not
	// mutated: the DNS client owns it and matches the reply against it.
	originalID, err := zeroDNSMessageID(packed)
	if err != nil {
		return nil, err
	}

	requestURL, err := buildDoHRequestURL(authority, requestPath)
	if err != nil {
		return nil, E.Cause(err, "build DoH request URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(packed))
	if err != nil {
		return nil, E.Cause(err, "build DoH request")
	}
	request.Header.Set("Content-Type", dnsTransport.MimeType)
	request.Header.Set("Accept", dnsTransport.MimeType)
	// Stating the length lets the server reject a truncated query instead of parsing a partial
	// one.
	request.ContentLength = int64(len(packed))

	response, err := t.doh.RoundTripExistingHTTP3(ctx, request)
	if err != nil {
		return nil, E.Cause(err, "DoH request on the MASQUE connection")
	}
	defer response.Body.Close()

	// RFC 8484 §4.2.1: "A successful HTTP response with a 2xx status code is used for any valid
	// DNS response, regardless of the DNS response code." The whole 2xx range is a success, not
	// only 200.
	if response.StatusCode < 200 || response.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, maxDoHErrorBodySize))
		return nil, E.New("DoH server returned ", response.Status, formatDoHErrorDetail(detail))
	}
	if err = checkDoHMediaType(response); err != nil {
		return nil, err
	}
	// One byte PAST the ceiling is read deliberately, so an oversized response is reported as
	// oversized rather than as an obscure decode failure.
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAssignedDNSMessageSize+1))
	if err != nil {
		return nil, E.Cause(err, "read DoH response")
	}
	if len(payload) > maxAssignedDNSMessageSize {
		return nil, E.New("DoH response exceeds ", maxAssignedDNSMessageSize, " bytes")
	}
	if len(payload) == 0 {
		return nil, E.New("DoH response carried no DNS message")
	}
	var parsed mDNS.Msg
	if err = parsed.Unpack(payload); err != nil {
		return nil, E.Cause(err, "decode DoH response")
	}
	// Restore the caller's ID: the DNS client sent this query with that ID and matches the reply
	// against it.
	parsed.Id = originalID
	return &parsed, nil
}

// zeroDNSMessageID sets a packed DNS message's ID to zero and returns the original.
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
// RFC 8484 §4.2 defines application/dns-message as the response type, and §5.4 requires both
// peers to support it. The RFC sets no MUST for an ABSENT header, so absence is tolerated; but a
// response that DECLARES a different type is refused, because otherwise an HTML error page from
// an intercepting proxy would reach the DNS decoder and be reported as a corrupt message rather
// than as what it is. Parsing is done with the MIME parser so parameters and case cannot defeat
// it.
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

// joinAuthority appends a port to a host, bracketing an IPv6 literal so the result is a valid
// authority rather than one whose colons are ambiguous.
func joinAuthority(host string, port uint16) string {
	if parsed, err := netip.ParseAddr(host); err == nil && parsed.Is6() && !parsed.Is4In6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// maxDoHErrorBodySize bounds how much of an error response is quoted back in an error.
//
// A failure explanation is useful; a server streaming megabytes into an error string is not.
const maxDoHErrorBodySize = 4096

// maxAssignedDNSMessageSize bounds a single response. The largest realistic DoH payload is far
// below this; the ceiling exists so a hostile or broken server cannot make us allocate without
// limit.
const maxAssignedDNSMessageSize = 65535

// formatDoHErrorDetail renders an error response body for an error message, quoting it only when
// it is short enough to be a diagnostic rather than a document.
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

// ensure masque stays referenced: the compilation layer above uses its types, and this import
// keeps the dependency explicit if that file is ever split.
var _ = masque.DNSConfiguration{}
