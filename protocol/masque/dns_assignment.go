package masque

import (
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/transport/masque"

	"golang.org/x/net/dns/dnsmessage"
)

// The DNS assignment snapshot: immutable configuration, and the pure policy that reads it.
//
// # Scope, stated once
//
// This consumes a server's DNS_ASSIGN for ONE purpose: choosing the resolver the MASQUE
// endpoint uses when IT resolves a domain destination that it is about to carry through the
// tunnel. That is the endpoint-local inner-resolution path.
//
// It is NOT global DNS configuration. It does not program the sing-box DNS router, does not
// touch the OS resolver, does not install search domains, and does not intercept DNS packets
// that applications send into the TUN device. Those are separate features with separate
// designs; nothing here should drift into them.
//
// # Why the snapshot is immutable
//
// The previous design was a single long-lived transport with a mutable state pointer inside
// it. A lookup loaded that pointer, chose a configuration, and then the exchange loaded it
// AGAIN. Two loads of a mutable pointer are two different assignments, and a single DNS
// lookup issues an A and an AAAA query CONCURRENTLY -- so a capsule arriving mid-lookup could
// produce an IPv4 answer from one assignment and an IPv6 answer from the next.
//
// Immutability removes the possibility rather than narrowing the window: a lookup captures the
// snapshot once, and everything it does afterwards reads that captured value.

// dnsAssignmentSnapshot is one DNS_ASSIGN, fully compiled.
//
// It is pure data. It owns no socket, starts no goroutine, and needs no Close. Replacing it is
// a single pointer store, and an in-flight lookup keeps using the value it captured -- which is
// what makes replacement safe without refcounts, retirement queues or delayed cleanup.
type dnsAssignmentSnapshot struct {
	// configurations are in wire order, each with its claims compiled.
	//
	// There is deliberately NO top-level identity field. The DNS cache key is the PER
	// CONFIGURATION identity, because a lookup has already been bound to one configuration by
	// the time a query runs: the policy decision is what selects it, and the cache only needs to
	// distinguish the resolver behaviour of the configuration actually used. A whole-assignment
	// fingerprint would invalidate that configuration's cached answers when an unrelated
	// configuration changed.
	configurations []dnsConfigurationSnapshot
}

// dnsConfigurationSnapshot is one DNS Configuration, compiled for query-time use.
type dnsConfigurationSnapshot struct {
	// internalDomains are the normalized names this configuration claims, in wire order.
	// The single entry "" means the DNS root (draft-06 §3.5).
	internalDomains []string
	// searchDomains are preserved but NOT applied: see the package documentation. They are
	// kept because discarding parsed configuration loses information a future full-VPN
	// integration would need, and because dropping them silently is worse than keeping them
	// unused and saying so.
	searchDomains []string
	// resolvers are this configuration's nameservers, in wire order. Priority ordering is
	// applied when iterating; the wire order is kept so equal priorities stay deterministic.
	resolvers []dnsResolverSnapshot
}

// dnsResolverSnapshot is ONE nameserver, with its capability already computed.
//
// Everything here is derived from the wire format ONCE, when the capsule arrives. The query
// path performs no parsing, no ALPN decoding, no template expansion and no route arithmetic;
// it reads these fields.
type dnsResolverSnapshot struct {
	priority                 uint16
	addresses                []netip.Addr
	authenticationDomainName string
	// alpn is the validated ALPN set, decoded from the wire format.
	alpn []string
	// noDefaultALPN reports that the server withdrew the plain DNS transport.
	noDefaultALPN bool
	// port is the advertised port; hasPort distinguishes it from an absent one. RFC 9461
	// makes `port` automatically mandatory, so it is never ignored when present.
	port    uint16
	hasPort bool
	// dohPath is the RFC 6570 template as advertised, and expandedPath its RFC 8484 POST
	// expansion. Both are kept so diagnostics can show what the server sent.
	dohPath      string
	expandedPath string
	hasDohPath   bool
	// dohPathErr records why an advertised template is unusable. Non-empty means the DoH
	// capability cannot be compiled, which does NOT by itself make the resolver unusable: a
	// resolver that also offers plain DNS is still usable.
	dohPathErr string
	// mandatory lists the additional mandatory SvcParamKeys the server declared.
	mandatory []dnsmessage.SVCParamKey
	// doh is the same-connection DoH capability, or nil when this resolver cannot use that
	// transport. A pointer-free boolean would be cheaper but this keeps the authority and path
	// together with the fact that they are usable.
	doh *compiledDoH
	// plain is the plain DNS capability, or nil when this resolver cannot use that transport.
	plain *compiledPlain
	// unusable records why this resolver cannot serve queries AT ALL, with unusableNone
	// meaning at least one capability is available.
	//
	// It is derived from the two capabilities rather than replacing them. An earlier model
	// collapsed a resolver to a single transport at compile time, which meant a resolver that
	// offered BOTH same-connection DoH and plain DNS permanently lost the plain path as soon as
	// DoH was selected -- so a DoH failure at query time could not fall back to a transport the
	// server had explicitly advertised.
	unusable unusableReason
}

// compiledDoH is the same-connection DoH capability of one resolver.
type compiledDoH struct {
	// authority is the full origin a request is addressed to: normalized host plus the
	// effective port. It is built once so the compile-time capability decision and the
	// runtime same-origin check cannot disagree about what origin this resolver names.
	authority string
	// path is the RFC 8484 POST expansion of the advertised dohpath.
	path string
}

// compiledPlain is the plain DNS capability of one resolver.
type compiledPlain struct {
	// udpAddresses are the addresses routable through the tunnel for UDP. Empty means plain
	// DNS cannot be used at all.
	udpAddresses []netip.Addr
	// tcpAddresses are the addresses routable for the truncated-answer retry. It may be empty
	// while udpAddresses is not, in which case UDP works but a truncated answer cannot be
	// retried -- which is a legitimate partial capability rather than an error.
	tcpAddresses []netip.Addr
}

// usable reports whether this resolver can serve a query at all.
func (r dnsResolverSnapshot) usable() bool {
	return r.doh != nil || r.plain != nil
}

// transportPreference returns the capabilities in the order they should be attempted.
//
// # Why DoH first, and why that is not an invented preference
//
// draft-06 §3.5 says that when the proxy is authoritative for the DoH origin, the client SHOULD
// send its queries there and SHOULD coalesce them over the tunnel's connection. That is a
// stated preference for the encrypted same-connection transport when it is available, so DoH is
// tried first and plain DNS follows.
//
// The order also has a practical justification that does not depend on reading a preference
// into the draft: the two are not equivalent fallbacks. Plain DNS is what the server offers by
// default, while DoH is the one that keeps queries on the connection the tunnel already uses.
// Preferring it when possible is the point of the coalescing requirement, and falling back to
// plain is still permitted whenever the server left the default transport available.
func (r dnsResolverSnapshot) transportPreference() []assignedTransport {
	preference := make([]assignedTransport, 0, 2)
	if r.doh != nil {
		preference = append(preference, assignedTransportDoH)
	}
	if r.plain != nil {
		preference = append(preference, assignedTransportPlainUDP)
	}
	return preference
}

// hasALPN reports whether the advertised ALPN set contains a protocol.
//
// The comparison is exact: ALPN identifiers are opaque byte strings (RFC 7301), so there is no
// case folding or trimming to do. `H3` is not `h3`.
func (r dnsResolverSnapshot) hasALPN(protocol string) bool {
	for _, advertised := range r.alpn {
		if advertised == protocol {
			return true
		}
	}
	return false
}

// dohAuthority builds the origin this resolver's DoH requests are addressed to.
//
// The port is part of the origin, not a detail applied later: `masque.example` on 443 and
// `masque.example` on 8443 are different origins, and comparing only host names would let a
// request be sent to an origin the connection was never authenticated for.
//
// The port is the advertised one when present, otherwise the HTTPS default. RFC 9461 makes
// `port` automatically mandatory, so an advertised port is honoured rather than replaced.
func (r dnsResolverSnapshot) dohAuthority() string {
	host := normalizeHostName(r.authenticationDomainName)
	port := r.dohPort()
	if port == 443 {
		return host
	}
	return joinAuthority(host, port)
}

// assignedTransport names a DNS transport this client can use.
type assignedTransport string

const (
	// assignedTransportDoH is same-connection DNS over HTTPS: an RFC 8484 POST on the HTTP/3
	// connection the CONNECT-IP tunnel already uses (draft-06 §3.5).
	assignedTransportDoH assignedTransport = "doh"
	// assignedTransportPlainUDP is traditional DNS over UDP port 53 with a TCP retry,
	// carried through the tunnel.
	assignedTransportPlainUDP assignedTransport = "udp"
)

// unusableReason explains why a resolver cannot serve queries. The zero value means usable,
// which keeps the common case the cheap one.
//
// String() exists because sing's error formatting handles builtin string but not a named string
// type, and passing the bare value to E.New panics rather than formatting.
type unusableReason string

func (r unusableReason) String() string {
	if r == unusableNone {
		return "usable"
	}
	return string(r)
}

const (
	unusableNone             unusableReason = ""
	unusableServiceParams    unusableReason = "unsupported or malformed service parameters"
	unusableNoTransport      unusableReason = "no supported transport"
	unusableNoAddress        unusableReason = "no address and no same-connection DoH"
	unusableRouteUnreachable unusableReason = "no address reachable through the advertised routes"
)

// dnsDecision is what the policy returns for a name.
//
// It is deliberately three-valued. A single "is an assignment active" boolean cannot express
// the distinction that matters, and collapsing it is exactly how a claimed name ends up at a
// public resolver: see decide.
type dnsDecision struct {
	// claimed reports that some configuration owns this name.
	claimed bool
	// configuration is the claiming configuration, valid when claimed.
	configuration dnsConfigurationSnapshot
	// usable reports that at least one resolver in the claiming configuration can serve a
	// query right now.
	usable bool
}

// decide answers "which configuration owns this name", and nothing else.
//
// # The three outcomes, and why they must stay distinct
//
//	unclaimed            -> the server never said this name was its business, so the ordinary
//	                        DNS rules apply
//	claimed and usable   -> the claiming configuration's resolvers answer it
//	claimed but unusable -> FAIL, and never fall back
//
// The third is the privacy invariant of split DNS. A claimed name belongs to a resolver the
// server nominated; if that resolver is unreachable, handing the name to a public resolver
// would leak an internal name at exactly the moment the internal path is broken. So ownership
// is decided WITHOUT reference to usability -- that is why unusable resolvers do not make a
// configuration disappear.
//
// # Longest match
//
//	a.corp.example. -> the configuration claiming "corp.example."  (not "example.")
//	b.example.      -> the configuration claiming "example."
//	public.test.    -> the configuration claiming "" (root), if there is one
//
// Matching is on a LABEL boundary, so `notcorp.example` does not match `corp.example`, and it
// is case- and root-dot-insensitive so presentation cannot change routing.
func (s *dnsAssignmentSnapshot) decide(name string) dnsDecision {
	if s == nil || len(s.configurations) == 0 {
		return dnsDecision{}
	}
	normalized := normalizeQueryName(name)

	bestIndex := -1
	bestLength := -1
	for index, configuration := range s.configurations {
		for _, domain := range configuration.internalDomains {
			if !nameMatchesDomain(normalized, domain) {
				continue
			}
			// The root claim has length 0, so any explicit domain is more specific and wins.
			if len(domain) > bestLength {
				bestLength = len(domain)
				bestIndex = index
			}
		}
	}
	if bestIndex < 0 {
		return dnsDecision{}
	}
	configuration := s.configurations[bestIndex]
	return dnsDecision{
		claimed:       true,
		configuration: configuration,
		usable:        configuration.hasUsableResolver(),
	}
}

// hasUsableResolver reports whether any resolver in this configuration can serve a query.
func (c dnsConfigurationSnapshot) hasUsableResolver() bool {
	for _, resolver := range c.resolvers {
		if resolver.unusable == unusableNone {
			return true
		}
	}
	return false
}

// resolversByPriority returns the resolvers ordered by ServicePriority, ties in wire order.
//
// The sort is a stable insertion sort over a list bounded by the capsule parser: it keeps the
// wire order for equal priorities, which a comparison sort would not guarantee.
func (c dnsConfigurationSnapshot) resolversByPriority() []dnsResolverSnapshot {
	ordered := make([]dnsResolverSnapshot, len(c.resolvers))
	copy(ordered, c.resolvers)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].priority < ordered[j-1].priority; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

// normalizeQueryName lowercases a name and strips the root dot, so presentation cannot change
// which configuration is selected.
func normalizeQueryName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// nameMatchesDomain reports whether name is the domain itself or a name UNDER it.
//
// The check is on a LABEL boundary: a plain suffix test would route `notcorp.example` to the
// resolver for `corp.example`, which never claimed it.
//
// The empty domain is the DNS root and matches everything, including the root name itself.
func nameMatchesDomain(name string, domain string) bool {
	if domain == "" {
		return true
	}
	if name == domain {
		return true
	}
	if !strings.HasSuffix(name, domain) {
		return false
	}
	return len(name) > len(domain) && name[len(name)-len(domain)-1] == '.'
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

// resolverCapability is what THIS CLIENT can do right now, as opposed to what the server
// advertised. Availability is a joint property of the two.
type resolverCapability struct {
	// tunnelIsHTTP3 reports that the CONNECT-IP session is running over HTTP/3.
	tunnelIsHTTP3 bool
	// sameH3Authorities are the origins the live HTTP/3 connection is authenticated for.
	sameH3Authorities []string
	// routes is the ROUTE_ADVERTISEMENT in force. A nil slice means none has been advertised,
	// and the draft's §5 ordering rule then means nothing is reachable through the tunnel.
	routes []masque.AddressRange
}

// sameH3OriginAvailable reports whether a resolver's FULL origin matches the live H3
// connection's.
//
// Both sides are complete origins: normalized host is not enough, because two authorities that
// differ only by port are different origins and a request to the wrong one would arrive at a
// server the connection was never authenticated for.
func (c resolverCapability) sameH3OriginAvailable(resolverAuthority string) bool {
	if !c.tunnelIsHTTP3 || resolverAuthority == "" {
		return false
	}
	for _, authority := range c.sameH3Authorities {
		if sameOrigin(authority, resolverAuthority) {
			return true
		}
	}
	return false
}

// compileDNSAssignment builds an immutable snapshot from a parsed assignment.
//
// This is where all wire-to-runtime work happens: service parameters are validated, the
// dohpath template is expanded, and each resolver's transport is decided against the client's
// capability and the advertised routes. The query path then reads the result.
//
// Every slice is COPIED, because the parsed structures belong to the caller and the snapshot is
// read by other goroutines for its lifetime.
func compileDNSAssignment(configurations []masque.DNSConfiguration, capability resolverCapability) *dnsAssignmentSnapshot {
	snapshot := &dnsAssignmentSnapshot{}
	for _, configuration := range configurations {
		compiled := dnsConfigurationSnapshot{
			internalDomains: normalizeInternalDomains(configuration.InternalDomains),
			searchDomains:   normalizeSearchDomains(configuration.SearchDomains),
		}
		for _, nameserver := range configuration.Nameservers {
			compiled.resolvers = append(compiled.resolvers, compileResolver(nameserver, capability))
		}
		snapshot.configurations = append(snapshot.configurations, compiled)
	}
	return snapshot
}

// normalizeInternalDomains normalizes the claimed names.
//
// # Why an empty LIST is not the root
//
// draft-ietf-masque-connect-ip-dns-06 §3.5 defines exactly one way to claim everything:
//
//	"Sending an empty string as an internal domain indicates the DNS root; i.e., that the
//	 corresponding nameserver can resolve all domain names."
//
// It assigns NO meaning to an empty list. An earlier version read `len(...) == 0` as "the
// default configuration", which is a guess the specification does not support and which
// silently converted unclaimed names into claimed ones -- the difference between "resolve this
// publicly" and "fail closed". A configuration with no internal domains therefore claims
// nothing and is never selected.
func normalizeInternalDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		// An empty domain means the root and is preserved as such.
		normalized = append(normalized, normalizeQueryName(domain))
	}
	return normalized
}

// normalizeSearchDomains normalizes search suffixes, dropping a root-only entry which is not a
// meaningful search suffix.
func normalizeSearchDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		normalizedDomain := normalizeQueryName(domain)
		if normalizedDomain == "" {
			continue
		}
		normalized = append(normalized, normalizedDomain)
	}
	return normalized
}

// compileResolver validates one nameserver and compiles its capabilities.
func compileResolver(nameserver masque.DNSNameserver, capability resolverCapability) dnsResolverSnapshot {
	resolver := dnsResolverSnapshot{
		priority: nameserver.ServicePriority,
		addresses: append(append([]netip.Addr(nil),
			nameserver.IPv4Addresses...), nameserver.IPv6Addresses...),
		authenticationDomainName: nameserver.AuthenticationDomainName,
	}

	// The wire value was validated during parsing; re-validating here would mean two sources of
	// truth. An error at this point means the value changed after parsing, which is a
	// programming error, so the resolver is marked unusable rather than trusted.
	parameters, err := masque.ValidateServiceParameters(nameserver)
	if err != nil {
		resolver.unusable = unusableServiceParams
		return resolver
	}
	resolver.alpn = parameters.ALPN
	resolver.noDefaultALPN = parameters.NoDefaultALPN
	resolver.port = parameters.Port
	resolver.hasPort = parameters.HasPort
	resolver.mandatory = append([]dnsmessage.SVCParamKey(nil), parameters.Mandatory...)
	resolver.dohPath = parameters.DohPath
	resolver.hasDohPath = parameters.HasDohPath
	if parameters.HasDohPath {
		expanded, expandErr := masque.ExpandDohPathForPost(parameters.DohPath)
		if expandErr != nil {
			// The template is unusable, so the DoH capability cannot be compiled. That is
			// recorded rather than returned: an advertised but broken dohpath must not by
			// itself make a resolver that also offers plain DNS unusable.
			resolver.dohPathErr = expandErr.Error()
		} else {
			resolver.expandedPath = expanded
		}
	}

	resolver.doh, resolver.plain, resolver.unusable = compileCapabilities(resolver, capability)
	return resolver
}

// compileCapabilities decides which transports this resolver can actually use.
//
// # The rules, and where each comes from
//
//	same-connection DoH requires ALL of:
//	    a valid dohpath                        RFC 9461 §5
//	    ALPN that explicitly includes h3       the transport must be named, not assumed
//	    the current CONNECT-IP session IS h3   draft-06 §3.5 coalescing
//	    this resolver's origin == the session's origin, INCLUDING the port
//
//	plain DNS requires ALL of:
//	    the server did not withdraw it         no-default-alpn absent (draft-06 §3.2)
//	    at least one address routable for UDP  otherwise the query leaves the tunnel
//
// # Why ALPN must name h3 explicitly
//
// An earlier version selected DoH from `hasDohPath` plus a live H3 connection, and never looked
// at ALPN at all. That is wrong in a way that matters: a server advertising `alpn=h2` with a
// dohpath was given an HTTP/3 request. The dohpath says WHERE to POST, not which protocol
// carries it, and RFC 9460 §7.1.2 requires a client to connect only with protocols both sides
// support.
//
// `h2` alone is therefore not enough either: this client implements same-connection DoH over
// HTTP/3 only, and pretending an h2-only resolver is usable over H3 would be exactly the kind
// of guess that produces a working-looking path to the wrong endpoint.
//
// # Why both capabilities are compiled
//
// A resolver may legitimately offer BOTH. Compiling only the preferred one would hide a
// transport the server advertised as soon as the other became unavailable at query time, so
// both are recorded and the executor walks them in order.
func compileCapabilities(resolver dnsResolverSnapshot, capability resolverCapability) (doh *compiledDoH, plain *compiledPlain, reason unusableReason) {
	// Same-connection DoH.
	if resolver.hasDohPath && resolver.dohPathErr == "" {
		authority := resolver.dohAuthority()
		switch {
		case !resolver.hasALPN("h3"):
			// The server did not name HTTP/3, so an HTTP/3 request is not ours to make. A
			// missing ALPN is the same refusal: absent is not a wildcard.
			break
		case !capability.tunnelIsHTTP3:
			// The session is not carried over HTTP/3, so there is no shared connection to
			// coalesce onto. This is a CAPABILITY gap, not a malformed advertisement, and the
			// resolver may still be usable over plain DNS.
			break
		case !capability.sameH3OriginAvailable(authority):
			// The resolver names a different origin than the connection was authenticated for.
			// Sending the request would ride on credentials never presented for it.
			break
		default:
			doh = &compiledDoH{authority: authority, path: resolver.expandedPath}
		}
	}

	// Plain DNS.
	if !resolver.noDefaultALPN && len(resolver.addresses) > 0 {
		udpAddresses := reachableForProtocol(resolver.addresses, capability.routes, protocolUDP)
		if len(udpAddresses) > 0 {
			plain = &compiledPlain{
				udpAddresses: udpAddresses,
				tcpAddresses: reachableForProtocol(resolver.addresses, capability.routes, protocolTCP),
			}
		}
	}

	switch {
	case doh != nil || plain != nil:
		return doh, plain, unusableNone
	case resolver.noDefaultALPN:
		// The server withdrew the plain transport and no encrypted transport could be used.
		// Refusing is required; falling back to cleartext would violate the assignment.
		return nil, nil, unusableNoTransport
	case resolver.hasDohPath:
		// A DoH path was advertised but no usable transport came of it: the resolver offered
		// only an encrypted transport this client cannot carry.
		return nil, nil, unusableNoTransport
	case len(resolver.addresses) == 0:
		return nil, nil, unusableNoAddress
	default:
		// Addresses exist but none is routable for the protocols DNS needs.
		return nil, nil, unusableRouteUnreachable
	}
}

// effectiveIdentity is the deterministic fingerprint of what this configuration would DO.
//
// It is the DNS cache key of the transport bound to this configuration. It contains only facts
// that can change an answer or where a query goes: the claims, the resolvers and their
// metadata, and the COMPILED CAPABILITIES. It deliberately excludes PREF64, search domains,
// capsule arrival order and any monotonic counter, so a repeated capsule or an unrelated update
// does not discard cached answers.
//
// It is computed directly rather than through a whole-snapshot wrapper, because a lookup is
// already bound to one configuration by the time a query runs: the policy decision selected it,
// and the cache only needs to distinguish that configuration's resolver behaviour.
//
// The order is fixed by construction -- configurations and resolvers are in wire order and
// fields are appended in a fixed sequence -- so Go map iteration cannot introduce instability.
//
// Two identical configurations produce the same value, so a repeated capsule does not invalidate
// a cache, and a PREF64-only update cannot affect it because PREF64 is not part of a
// configuration.
//
// It DOES change when a route change makes a resolver unusable, because that changes where
// queries actually go -- the one case that must invalidate cached answers.
func (c dnsConfigurationSnapshot) effectiveIdentity() string {
	var builder strings.Builder
	for _, domain := range c.internalDomains {
		builder.WriteString("|i=")
		builder.WriteString(domain)
	}
	for resolverIndex, resolver := range c.resolvers {
		builder.WriteString("|r")
		builder.WriteString(itoa(resolverIndex))
		builder.WriteString("p=")
		builder.WriteString(itoa(int(resolver.priority)))
		builder.WriteString("a=")
		builder.WriteString(resolver.authenticationDomainName)
		builder.WriteString("d=")
		builder.WriteString(resolver.dohPath)
		if resolver.hasPort {
			builder.WriteString("o=")
			builder.WriteString(itoa(int(resolver.port)))
		}
		if resolver.noDefaultALPN {
			builder.WriteString("!default")
		}
		builder.WriteString("n=")
		for _, protocol := range resolver.alpn {
			builder.WriteString(protocol)
			builder.WriteString(",")
		}
		for _, address := range resolver.addresses {
			builder.WriteString("|")
			builder.WriteString(address.String())
		}
		// The COMPILED CAPABILITIES are the facts that matter most: a route change that flips a
		// resolver from usable to unusable, or that removes the TCP retry path, changes where
		// queries go and whether a truncated answer can be completed.
		builder.WriteString("|u=")
		builder.WriteString(string(resolver.unusable))
		if resolver.doh != nil {
			builder.WriteString("|doh=")
			builder.WriteString(resolver.doh.authority)
			builder.WriteString(resolver.doh.path)
		}
		if resolver.plain != nil {
			builder.WriteString("|udp=")
			for _, address := range resolver.plain.udpAddresses {
				builder.WriteString(address.String())
				builder.WriteString(",")
			}
			// TCP reachability is part of the identity because it is part of the BEHAVIOUR: a
			// truncated UDP answer must be retried over TCP (RFC 1035 section 4.2.1), so losing
			// the TCP route changes what happens to a large response even when the UDP
			// addresses are identical.
			builder.WriteString("|tcp=")
			for _, address := range resolver.plain.tcpAddresses {
				builder.WriteString(address.String())
				builder.WriteString(",")
			}
		}
	}
	return builder.String()
}

// Route protocols as they appear in a ROUTE_ADVERTISEMENT (RFC 9484 §4.7.1): 0 means "all
// protocols", and the rest are IP protocol numbers, so 6 is TCP and 17 is UDP.
const (
	protocolAll = 0
	protocolTCP = 6
	protocolUDP = 17
)

// reachableForProtocol filters addresses to those covered by a route permitting the protocol.
//
// draft-06 §3.2 defines unencrypted DNS as UDP and TCP port 53, and RFC 1035 §4.2.1 requires a
// truncated UDP answer to be retried over TCP. A route advertised for some unrelated protocol
// therefore does NOT make a DNS query reachable, and the two transports are filtered
// separately so a UDP-only route is not mistaken for a working TCP retry path.
func reachableForProtocol(addresses []netip.Addr, routes []masque.AddressRange, protocol uint8) []netip.Addr {
	var reachable []netip.Addr
	for _, address := range addresses {
		for _, route := range routes {
			if route.Protocol != protocolAll && route.Protocol != protocol {
				continue
			}
			if route.Contains(address) {
				reachable = append(reachable, address)
				break
			}
		}
	}
	return reachable
}

// sameOrigin compares two authorities for origin identity.
//
// # What is normalized, and what is deliberately not
//
// Authentication Domain Names arrive as DNS FQDNs (`resolver.example.`) while HTTP authorities
// are written without the root dot (`resolver.example`), and the same name may differ in case.
// Those spellings denote ONE host, so they must compare equal.
//
// Normalization is applied only to a value already known to be a host name, and only for a
// SINGLE trailing root dot. A blanket TrimRight(".") would equate `example..` with `example`
// and would accept an empty name, neither of which is a host.
//
// A PORT MAKES TWO AUTHORITIES DIFFERENT ORIGINS, so the port is compared and never discarded.
// That is why this takes full authorities rather than host names: a DoH request is addressed to
// host AND port, and a comparison that ignored the port would approve a request to an origin the
// connection was never authenticated for.
func sameOrigin(first string, second string) bool {
	firstHost, firstPort := splitHostPort(first)
	secondHost, secondPort := splitHostPort(second)
	if firstPort != secondPort {
		return false
	}
	return equalFoldASCII(normalizeHostName(firstHost), normalizeHostName(secondHost))
}

// splitHostPort separates a host from its port, defaulting to the HTTPS port.
func splitHostPort(authority string) (string, string) {
	// An IPv6 literal keeps its brackets: the colons inside them are not separators.
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing < 0 {
			return authority, "443"
		}
		host := authority[:closing+1]
		rest := authority[closing+1:]
		if rest == "" {
			return host, "443"
		}
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:]
		}
		return authority, "443"
	}
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		return authority[:colon], authority[colon+1:]
	}
	return authority, "443"
}

// normalizeHostName lowercases a host and removes at most ONE trailing root dot.
func normalizeHostName(host string) string {
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ".") && len(host) > 1 {
		host = host[:len(host)-1]
	}
	return host
}

// equalFoldASCII compares two strings case-insensitively over ASCII only.
//
// It is written out rather than using strings.EqualFold so the comparison cannot be affected by
// Unicode case folding, which is not how host names compare.
func equalFoldASCII(first string, second string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range len(first) {
		a, b := first[index], second[index]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'B' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// describe renders a resolver for logs and errors, naming metadata that belongs to THIS
// resolver so a misrouting bug is legible.
func (r dnsResolverSnapshot) describe() string {
	description := "<no address>"
	if len(r.addresses) > 0 {
		description = r.addresses[0].String()
	} else if r.authenticationDomainName != "" {
		description = r.authenticationDomainName
	}
	if r.authenticationDomainName != "" && len(r.addresses) > 0 {
		description += " (" + r.authenticationDomainName + ")"
	}
	return description
}

// assignedDNSDefaultPort is the DNS port used when the server advertised none.
const assignedDNSDefaultPort = 53

// dnsPort is the port plain DNS is sent to.
func (r dnsResolverSnapshot) dnsPort() uint16 {
	if r.hasPort {
		return r.port
	}
	return assignedDNSDefaultPort
}

// dohPort is the port a DoH request is addressed to.
//
// A dohpath names an HTTP resource, so its default is the HTTPS port; using the plain DNS
// default of 53 would send an HTTPS request to the DNS port.
func (r dnsResolverSnapshot) dohPort() uint16 {
	if r.hasPort {
		return r.port
	}
	if r.hasDohPath {
		return 443
	}
	return 0
}

// itoa renders a non-negative int, avoiding a strconv import at every call site.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
