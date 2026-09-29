package masque

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/transport/masque"

	"golang.org/x/net/dns/dnsmessage"
)

// The assigned-DNS runtime model.
//
// # Why the hierarchy is preserved rather than flattened
//
// draft-ietf-masque-connect-ip-dns-06 allows an assignment to carry SEVERAL DNS
// configurations, and the configurations are not interchangeable: each one carries the
// internal domains it is responsible for. A nameserver in the configuration for
// `corp.example.` is the right resolver for `a.corp.example.` and the wrong one for
// `public.test.`.
//
// The previous model collapsed all of it:
//
//	nameservers: [A_IP, B_IP]
//	tlsName  = whichever nameserver was seen last
//	dohPath  = whichever nameserver was seen last
//	port     = whichever nameserver was seen last
//
// That loses three distinct things at once. The configuration boundary is gone, so every
// query goes to the globally lowest-priority resolver regardless of name. The per-resolver
// metadata is gone, so address A can be dialled using B's authentication domain, B's
// dohpath and B's port -- which is not a cosmetic mismatch, because a DoH request addressed
// to B's origin but sent to A's server is a request the connection was never authenticated
// for. And the search domains are gone, so they cannot be reported at all.
//
// The types below keep the hierarchy the wire format defines.

// assignedResolverEndpoint is ONE nameserver, with its own metadata.
//
// Every field here belongs to this endpoint alone. Nothing is inherited from a sibling, and
// nothing is inherited from another configuration.
type assignedResolverEndpoint struct {
	// priority is the SVCB ServiceMode priority. Lower is preferred, and the comparison is
	// only ever made BETWEEN ENDPOINTS OF THE SAME CONFIGURATION.
	priority uint16
	// addresses are the endpoint's reachable addresses, in wire order.
	addresses []netip.Addr
	// authenticationDomainName is the FQDN the endpoint's certificate must match. Empty
	// means this endpoint offers no encrypted transport.
	authenticationDomainName string
	// alpn is the advertised ALPN list. An empty list means no encrypted transport was
	// advertised.
	alpn []string
	// noDefaultALPN is set when the server explicitly forbade the default ALPN. It is the
	// flag that makes "encrypted only" binding rather than a preference.
	noDefaultALPN bool
	// dohPath is the SVCB dohpath URI Template as advertised, when present.
	dohPath string
	// hasDohPath distinguishes an absent template from a present-but-empty one.
	hasDohPath bool
	// expandedDohPath is the RFC 8484 POST expansion of dohPath, computed once. Empty with a
	// nil dohPathErr means no template was advertised.
	expandedDohPath string
	// dohPathErr records why the template is unusable, if it is. It is a string rather than
	// an error so the state stays comparable and copyable.
	dohPathErr string
	// port is the advertised port; hasPort distinguishes it from an absent one.
	port    uint16
	hasPort bool
	// mandatory lists the extra mandatory keys the server declared.
	mandatory []dnsmessage.SVCParamKey
	// invalidServiceParameters records that the nameserver's SvcParams could not be
	// understood. Non-empty means the resolver is incompatible.
	invalidServiceParameters string
}

// resolverCapability describes what THIS CLIENT can currently do, which is what decides
// whether an advertised transport is usable.
//
// # Why the tunnel's transport is part of it
//
// draft-06 §3.5 asks that DoH requests be "coalesced over the same HTTPS connection" as the
// CONNECT-IP tunnel. That is only honest if the tunnel really is that connection. The
// configured protocol version is NOT the same fact: transport/http falls back from H3 to H2,
// so a client configured for version 3 can end up with an H2 tunnel while the H3 code path
// still exists. Asking RoundTripHTTP3 in that state could dial a SECOND connection purely
// for DNS, which defeats the coalescing and creates an extra observable connection.
//
// So the capability is reported by whoever owns the connection, and same-H3 DoH is available
// only when the tunnel really is H3 and a live connection exists.
type resolverCapability struct {
	// tunnelIsHTTP3 reports that the CONNECT-IP tunnel is running over HTTP/3.
	tunnelIsHTTP3 bool
	// sameH3Authorities are the origins the live H3 connection is authenticated for. DoH is
	// offered only to a resolver whose authentication domain matches one of these, because
	// otherwise the request would ride on credentials never presented for that origin.
	// Empty means no usable H3 connection.
	sameH3Authorities []string
	// routes is the ROUTE_ADVERTISEMENT in force. A nil slice means the server has not
	// advertised routes yet, and the draft's §5 ordering rule then means nothing is reachable
	// through the tunnel -- which is what stops an assignment arriving before its routes from
	// being installed.
	routes []masque.AddressRange
}

// sameH3AvailableFor reports whether a resolver's origin can be served on the existing H3
// connection.
func (c resolverCapability) sameH3AvailableFor(authenticationDomainName string) bool {
	if !c.tunnelIsHTTP3 || authenticationDomainName == "" {
		return false
	}
	for _, authority := range c.sameH3Authorities {
		if sameOriginHost(authority, authenticationDomainName) {
			return true
		}
	}
	return false
}

// assignedResolverConfiguration is one configuration: the resolvers responsible for a set
// of internal domains.
//
// # What an empty internal-domain list means, and what it does NOT mean
//
// draft-ietf-masque-connect-ip-dns-06 §3.5 defines exactly one way to claim everything:
//
//	"Sending an empty string as an internal domain indicates the DNS root; i.e.,
//	 that the corresponding nameserver can resolve all domain names."
//
// So `[""]` is the root claim. The draft assigns NO meaning to an EMPTY LIST, and this
// model does not invent one: a configuration with no internal domains claims NOTHING and
// can never be selected for any name.
//
// An earlier version read `len(internalDomains) == 0` as "the default configuration", which
// is a guess the specification does not support. It was not merely tidy-mindedness: it
// silently turned an unclaimed name into a claimed one, which is the difference between
// "resolve this publicly" and "fail closed".
type assignedResolverConfiguration struct {
	// internalDomains are the names this configuration owns, in wire order. The single
	// entry "" means the DNS root (all names); an empty list means no name at all.
	internalDomains []string
	// searchDomains are the search suffixes to append to unqualified names.
	searchDomains []string
	// resolvers are this configuration's nameservers, in wire order. Priority ordering is
	// applied at selection time; the wire order is kept so ties stay deterministic.
	//
	// This list is retained even when EVERY resolver turns out to be unusable, because the
	// CLAIM above is independent of whether we can currently reach a server for it. Dropping
	// the configuration on unreachability would delete the claim and leak the name.
	resolvers []assignedResolverEndpoint
}

// unusableReason explains why a resolver cannot serve queries. It is empty for a usable
// resolver, and the zero value therefore means "usable" -- which keeps the common case the
// cheap one.
type unusableReason string

const (
	// unusableNone marks a resolver that can be used.
	unusableNone unusableReason = ""
	// unusableNoAddress means the resolver offers no transport this client can reach: it has
	// neither a usable tunnel address (for plain DNS) nor a valid same-H3 DoH configuration.
	unusableNoAddress unusableReason = "no usable address or DoH configuration"
	// unusableRoute means none of its addresses is reachable through the advertised routes
	// for the transport it would use.
	unusableRoute unusableReason = "no address reachable through the advertised routes"
	// unusableTransport means its advertised transport cannot be provided by this client.
	unusableTransport unusableReason = "no supported transport"
	// unusableServiceParameters means its SvcParams are malformed or demand something this
	// client cannot honour.
	unusableServiceParameters unusableReason = "unsupported or malformed service parameters"
)

// assignedTransport names a DNS transport this client can actually use.
type assignedTransport string

const (
	// assignedTransportDoH is same-connection DNS over HTTPS: an RFC 8484 POST on the
	// HTTP/3 connection the CONNECT-IP tunnel already uses (draft-06 §3.5).
	assignedTransportDoH assignedTransport = "doh"
	// assignedTransportPlainUDP is traditional DNS over UDP port 53, carried through the
	// tunnel, with a TCP retry when the answer is truncated.
	assignedTransportPlainUDP assignedTransport = "udp"
)

// resolverAvailability is the outcome of evaluating one resolver against the routes and the
// client's capabilities. It is computed when the effective state is built, so selection is a
// pure lookup rather than repeated validation.
type resolverAvailability struct {
	reason unusableReason
	// addresses are the resolver's addresses that are usable for the transport selected.
	// For same-H3 DoH this is empty by design: that transport does not dial the address.
	addresses []netip.Addr
	// transport is the transport that will be used.
	transport assignedTransport
}

// usable reports whether this resolver can serve queries.
func (a resolverAvailability) usable() bool {
	return a.reason == unusableNone
}

// assignedDNSState is one assignment's worth of immutable resolver configuration.
//
// The generation lives INSIDE the state rather than beside it.
//
// Storing the state and incrementing a separate counter were two independent atomic
// operations, so a reader could observe the new state with the old generation. That is not
// theoretical: Environment() keys the DNS cache, so a torn pair would report a generation
// that does not describe the resolver list it accompanies, and a cached answer could be
// attributed to the wrong assignment. One immutable snapshot removes the possibility.
type assignedDNSState struct {
	generation     uint64
	configurations []assignedResolverConfiguration
	pref64         []netip.Prefix
	// availability is parallel to configurations[i].resolvers[j]. It is computed once, at
	// publish time, from the routes and the client's H3 capability, so that selection and
	// environment reporting do not re-evaluate and cannot disagree with each other.
	availability [][]resolverAvailability
	// identity is the deterministic resolver-relevant fingerprint of this state. It is what
	// decides whether a reapply is a real change; see buildAssignedDNSState.
	identity string
	// hasAssignment distinguishes "no assignment at all" from "an assignment whose
	// resolvers are all unusable". The two are different: only the second means the server
	// made a claim we cannot serve, which must fail closed.
	hasAssignment bool
}

// endpointLookup is the result of asking which configuration owns a name.
//
// It carries the WHOLE configuration plus the per-resolver availability, rather than one
// chosen endpoint, because the caller walks the configuration's resolvers by priority and
// needs to know which of them are usable. Selection of a specific resolver is a policy the
// exchange applies, not a property of the lookup.
type endpointLookup struct {
	configuration assignedResolverConfiguration
	availability  []resolverAvailability
	// claimed reports that some configuration owns this name. When it is true the caller
	// MUST NOT fall back to any other resolver, whatever happens next.
	claimed bool
}

// selectForName chooses the configuration responsible for a name, then the
// highest-priority resolver within it.
//
// # Configuration selection: longest matching internal domain
//
// Internal domains are the mechanism by which one server owns `corp.example.` while another
// owns everything else. A name is matched against them by SUFFIX, and the most SPECIFIC
// match wins:
//
//	a.corp.example.  -> configuration owning "corp.example."
//	b.example.       -> configuration owning "example."
//	public.test.     -> the default configuration
//
// Longest-match rather than first-match is what makes overlapping domains behave the way
// DNS itself does. Taking the first match would make the result depend on the order the
// server happened to serialise its configurations, so the same logical assignment could
// route one name two different ways.
//
// A configuration with NO internal domains is the default, and only applies when nothing
// more specific matched.
//
// # Resolver selection: lowest priority WITHIN the chosen configuration
//
// ServicePriority orders resolvers that serve the same domains. It is deliberately not
// compared across configurations: a priority-1 resolver for `corp.example.` must not beat a
// priority-2 resolver for `public.test.` when the query is for a public name, because they
// answer different questions. Treating priority as a global ranking is what the previous
// flattening did, and it is why every query went to one server.
func (s *assignedDNSState) selectForName(name string) endpointLookup {
	if s == nil || len(s.configurations) == 0 {
		return endpointLookup{}
	}
	normalized := normalizeQueryName(name)

	// WHICH configuration claims this name. The longest matching internal domain wins, and
	// "" is the root claim, which matches everything but is by definition the LEAST specific,
	// so it only wins when nothing narrower applies.
	//
	// A configuration with NO internal domains claims nothing and is skipped entirely: that
	// is the difference between [] and [""], and it is what makes split DNS work.
	bestConfiguration := -1
	bestMatchLength := -1
	for index, configuration := range s.configurations {
		for _, domain := range configuration.internalDomains {
			normalizedDomain := normalizeQueryName(domain)
			if !nameMatchesDomain(normalized, normalizedDomain) {
				continue
			}
			// The root claim ("") has length 0, so any explicit domain beats it.
			if len(normalizedDomain) > bestMatchLength {
				bestMatchLength = len(normalizedDomain)
				bestConfiguration = index
			}
		}
	}
	if bestConfiguration < 0 {
		return endpointLookup{}
	}

	// The name IS claimed. From here the answer is that configuration or nothing: a claimed
	// name must never be answered by some other resolver, which is the privacy invariant that
	// makes split DNS safe.
	configuration := s.configurations[bestConfiguration]
	return endpointLookup{
		configuration: configuration,
		availability:  s.availability[bestConfiguration],
		claimed:       true,
	}
}

// claimsName reports whether any configuration claims this name.
//
// This is the question the endpoint must ask BEFORE choosing between the assigned resolver
// and the ordinary DNS rules, and it is deliberately independent of whether a resolver is
// currently usable. "Who owns this name" and "can I reach the owner" are different
// questions, and conflating them is how an internal name leaks to a public resolver when
// its own nameserver is temporarily unreachable.
func (s *assignedDNSState) claimsName(name string) bool {
	if s == nil || len(s.configurations) == 0 {
		return false
	}
	normalized := normalizeQueryName(name)
	for _, configuration := range s.configurations {
		for _, domain := range configuration.internalDomains {
			if nameMatchesDomain(normalized, normalizeQueryName(domain)) {
				return true
			}
		}
	}
	return false
}

// normalizeQueryName lowercases a name and strips the trailing root dot, so that
// `Corp.Example.` and `corp.example` compare equal.
//
// Without this, a suffix match would be case-sensitive and a trailing-dot difference would
// silently route a name to the default configuration.
func normalizeQueryName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// nameMatchesDomain reports whether name is the domain itself or a name UNDER it.
//
// The check is on a LABEL boundary, so `notcorp.example` does not match `corp.example`.
// A plain strings.HasSuffix would match it, which would let an unrelated name be routed to a
// resolver that never claimed it.
func nameMatchesDomain(name string, domain string) bool {
	if domain == "" {
		// The empty internal domain is the DNS root, which matches every name. It is
		// treated as a default rather than as a specific match.
		return true
	}
	if name == domain {
		return true
	}
	if !strings.HasSuffix(name, domain) {
		return false
	}
	// The character before the suffix must be the label separator.
	return len(name) > len(domain) && name[len(name)-len(domain)-1] == '.'
}

// preferredResolver returns the resolver with the lowest priority in this configuration.
//
// Ties are broken by the order the server sent, so the result is deterministic rather than
// dependent on map iteration.
func (c assignedResolverConfiguration) preferredResolver() (assignedResolverEndpoint, bool) {
	if len(c.resolvers) == 0 {
		return assignedResolverEndpoint{}, false
	}
	best := c.resolvers[0]
	for _, resolver := range c.resolvers[1:] {
		if resolver.priority < best.priority {
			best = resolver
		}
	}
	return best, true
}

// resolversByPreference returns every resolver in this configuration ordered by priority,
// so a caller can fall back through them when the preferred one cannot be used.
func (c assignedResolverConfiguration) resolversByPreference() []assignedResolverEndpoint {
	ordered := make([]assignedResolverEndpoint, len(c.resolvers))
	copy(ordered, c.resolvers)
	// Insertion sort: the list is tiny (bounded by the capsule parser) and this keeps the
	// tie order stable, which a map-based sort would not.
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].priority < ordered[j-1].priority; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

// allEndpoints returns every resolver of every configuration, for environment reporting.
func (s *assignedDNSState) allEndpoints() []assignedResolverEndpoint {
	if s == nil {
		return nil
	}
	var endpoints []assignedResolverEndpoint
	for _, configuration := range s.configurations {
		endpoints = append(endpoints, configuration.resolvers...)
	}
	return endpoints
}

// hasResolvers reports whether any configuration carries a usable resolver.
// buildAssignedDNSState converts a parsed assignment into the runtime model.
//
// Every slice and map is COPIED. The parsed structures are owned by the caller that parsed
// them, and the state is published to other goroutines and read for the lifetime of the
// assignment, so retaining a caller's slice would let a later mutation change live resolver
// behaviour. The service parameters are maps of byte slices, which is the case most likely
// to be shared inadvertently, so each value is copied rather than referenced.
func buildAssignedDNSState(configurations []masque.DNSConfiguration, pref64 []netip.Prefix, generation uint64, capability resolverCapability) *assignedDNSState {
	state := &assignedDNSState{
		generation:    generation,
		pref64:        append([]netip.Prefix(nil), pref64...),
		hasAssignment: true,
	}
	for _, configuration := range configurations {
		runtimeConfiguration := assignedResolverConfiguration{
			internalDomains: append([]string(nil), configuration.InternalDomains...),
			searchDomains:   append([]string(nil), configuration.SearchDomains...),
		}
		var availability []resolverAvailability
		for _, nameserver := range configuration.Nameservers {
			endpoint := buildResolverEndpoint(nameserver)
			runtimeConfiguration.resolvers = append(runtimeConfiguration.resolvers, endpoint)
			availability = append(availability, endpoint.availability(capability))
		}
		state.configurations = append(state.configurations, runtimeConfiguration)
		state.availability = append(state.availability, availability)
	}
	state.identity = state.resolverIdentity()
	return state
}

// buildResolverEndpoint converts one nameserver, keeping its metadata its own.
//
// Every slice and map is COPIED. The parsed structures belong to whoever parsed them, and the
// published state is read by other goroutines for the lifetime of the assignment, so
// retaining a caller's slice would let a later mutation change live resolver behaviour. The
// service-parameter map of byte slices is the case most likely to be shared inadvertently.
//
// The values were already validated at the wire boundary; this function does not re-validate,
// it only copies. validateServiceParameters is called again here for the fields it derives
// (alpn, mandatory, port presence) because those are computed, not stored.
func buildResolverEndpoint(nameserver masque.DNSNameserver) assignedResolverEndpoint {
	endpoint := assignedResolverEndpoint{
		priority: nameserver.ServicePriority,
		addresses: make([]netip.Addr, 0,
			len(nameserver.IPv4Addresses)+len(nameserver.IPv6Addresses)),
		authenticationDomainName: nameserver.AuthenticationDomainName,
	}
	endpoint.addresses = append(endpoint.addresses, nameserver.IPv4Addresses...)
	endpoint.addresses = append(endpoint.addresses, nameserver.IPv6Addresses...)

	// The nameserver was validated during parsing, so an error here would mean the value was
	// mutated after parsing. Treat it as unusable rather than panicking.
	parsed, err := masque.ValidateServiceParameters(nameserver)
	if err != nil {
		endpoint.invalidServiceParameters = err.Error()
		return endpoint
	}
	endpoint.alpn = parsed.ALPN
	endpoint.noDefaultALPN = parsed.NoDefaultALPN
	endpoint.port = parsed.Port
	endpoint.hasPort = parsed.HasPort
	endpoint.dohPath = parsed.DohPath
	endpoint.hasDohPath = parsed.HasDohPath
	endpoint.mandatory = append([]dnsmessage.SVCParamKey(nil), parsed.Mandatory...)
	if parsed.HasDohPath {
		expanded, expandErr := masque.ExpandDohPathForPost(parsed.DohPath)
		if expandErr != nil {
			endpoint.dohPathErr = expandErr.Error()
		} else {
			endpoint.expandedDohPath = expanded
		}
	}
	return endpoint
}

func (s *assignedDNSState) hasResolvers() bool {
	if s == nil {
		return false
	}
	for _, configuration := range s.configurations {
		if len(configuration.resolvers) > 0 {
			return true
		}
	}
	return false
}

// Route protocols as they appear in a ROUTE_ADVERTISEMENT (RFC 9484 §4.7.1): 0 means "all
// protocols", and the others are IP protocol numbers, so 6 is TCP and 17 is UDP.
const (
	protocolAll = 0
	protocolTCP = 6
	protocolUDP = 17
)

// availability evaluates this resolver against the client's capability and the advertised
// routes, deciding which transport (if any) will be used.
//
// # Order of the decision, and why
//
//  1. malformed SvcParams -> incompatible. Everything below reads those values, so nothing can
//     be trusted until they are known good.
//  2. same-H3 DoH, when the resolver's origin matches the live tunnel H3 connection. Checked
//     FIRST because it is the transport draft-06 §3.5 asks for, and because it is the only one
//     that needs no reachable nameserver address: the query travels as a request stream on a
//     connection that already exists. This is what makes the draft's §3.6.1 full-tunnel
//     example -- zero addresses, alpn=h2,h3, dohpath -- actually usable rather than a resolver
//     that installs and then fails on its first query.
//  3. otherwise plain DNS, which DOES need an address reachable through the advertised routes
//     for the protocol it will use. UDP and TCP are separate route protocols, and a route
//     advertised only for TCP does not make a UDP query reachable.
func (e assignedResolverEndpoint) availability(capability resolverCapability) resolverAvailability {
	if e.invalidServiceParameters != "" {
		return resolverAvailability{reason: unusableServiceParameters}
	}
	if e.hasDohPath && e.dohPathErr != "" {
		return resolverAvailability{reason: unusableServiceParameters}
	}

	// 2. Same-connection DoH.
	if e.hasDohPath && capability.sameH3AvailableFor(e.authenticationDomainName) {
		return resolverAvailability{reason: unusableNone, transport: assignedTransportDoH}
	}

	// 3. Plain DNS, which needs a reachable address.
	if len(e.addresses) == 0 {
		// No address and no usable DoH. When DoH WAS advertised, say so precisely:
		// "unreachable" would be misleading, and the distinction tells an operator whether
		// the tunnel or the client's capability is at fault.
		if e.hasDohPath {
			return resolverAvailability{reason: unusableTransport}
		}
		return resolverAvailability{reason: unusableNoAddress}
	}
	if e.noDefaultALPN {
		// The server withdrew the default transport, so plain DNS is forbidden and DoH was
		// not usable. That is a refusal, not a downgrade.
		return resolverAvailability{reason: unusableTransport}
	}
	reachable := e.reachableAddresses(capability.routes)
	if len(reachable) == 0 {
		return resolverAvailability{reason: unusableRoute}
	}
	return resolverAvailability{reason: unusableNone, transport: assignedTransportPlainUDP, addresses: reachable}
}

// reachableAddresses filters the resolver's addresses to those routable through the tunnel for
// the protocols plain DNS needs.
//
// # Why the protocol matters
//
// draft-06 §3.2 defines unencrypted DNS as "traditionally sent over UDP port 53 and TCP port
// 53", and a truncated UDP answer must be retried over TCP (RFC 1035 §4.2.1). So a route
// advertised for some unrelated protocol does NOT make a DNS query reachable, and an address
// is only kept when it can actually carry UDP -- the transport queries start on.
//
// TCP availability is reported separately so a truncated answer knows whether its retry is
// possible, instead of discovering it by falling back to the host stack.
func (e assignedResolverEndpoint) reachableAddresses(routes []masque.AddressRange) []netip.Addr {
	var reachable []netip.Addr
	for _, address := range e.addresses {
		if routePermitsProtocol(routes, address, protocolUDP) {
			reachable = append(reachable, address)
		}
	}
	return reachable
}

// tcpReachableAddresses returns the addresses that can also carry TCP, for the
// truncated-answer retry.
func (e assignedResolverEndpoint) tcpReachableAddresses(routes []masque.AddressRange) []netip.Addr {
	var reachable []netip.Addr
	for _, address := range e.addresses {
		if routePermitsProtocol(routes, address, protocolTCP) {
			reachable = append(reachable, address)
		}
	}
	return reachable
}

// routePermitsProtocol reports whether any advertised route covers address AND permits the
// given IP protocol.
//
// A route with Protocol 0 covers every protocol, so 0 matches any request. Otherwise the
// route's protocol must equal the one being asked about. Addresses are compared on the
// address family too: a v4 route never covers a v6 address, however the ranges happen to
// compare.
func routePermitsProtocol(routes []masque.AddressRange, address netip.Addr, protocol uint8) bool {
	for _, route := range routes {
		if route.Protocol != protocolAll && route.Protocol != protocol {
			continue
		}
		if route.Contains(address) {
			return true
		}
	}
	return false
}

// resolverIdentity is the deterministic fingerprint of everything about this state that can
// change what a DNS query returns or where it is sent.
//
// # Why the generation must be derived from this rather than from call counts
//
// publish() used to bump the generation on every apply. That made a PREF64-only update, an
// address-only update and an identical reapply all invalidate the DNS cache, even though
// none of them changes an answer. Wasteful, and worse, it hides the case that DOES matter:
// a ROUTE_ADVERTISEMENT change that makes a resolver unreachable alters effective behaviour
// and must invalidate the cache, and that fact was invisible when everything bumped.
//
// So the identity is built from the resolver-relevant facts only, and the generation is
// allocated only when it differs. PREF64 is deliberately EXCLUDED: it does not participate in
// resolution (this client performs no DNS64 synthesis), so a change to it cannot change an
// answer.
//
// The order is fixed by construction -- configurations and their resolvers are in wire order,
// and the fields are appended in a fixed sequence -- so two equal states always produce equal
// identities and Go map iteration cannot leak in.
func (s *assignedDNSState) resolverIdentity() string {
	if s == nil || len(s.configurations) == 0 {
		return ""
	}
	var builder strings.Builder
	for configIndex, configuration := range s.configurations {
		builder.WriteString("c")
		builder.WriteString(strconv.Itoa(configIndex))
		// The CLAIM is part of the identity: changing which names are owned changes answers
		// even if every resolver stays the same.
		for _, domain := range configuration.internalDomains {
			builder.WriteString("|i=")
			builder.WriteString(normalizeQueryName(domain))
		}
		for _, domain := range configuration.searchDomains {
			builder.WriteString("|s=")
			builder.WriteString(normalizeQueryName(domain))
		}
		for resolverIndex, resolver := range configuration.resolvers {
			builder.WriteString("|r")
			builder.WriteString(strconv.Itoa(resolverIndex))
			builder.WriteString("p=")
			builder.WriteString(strconv.Itoa(int(resolver.priority)))
			builder.WriteString("a=")
			builder.WriteString(resolver.authenticationDomainName)
			builder.WriteString("d=")
			builder.WriteString(resolver.dohPath)
			if resolver.hasPort {
				builder.WriteString("o=")
				builder.WriteString(strconv.Itoa(int(resolver.port)))
			}
			builder.WriteString("n=")
			for _, protocol := range resolver.alpn {
				builder.WriteString(protocol)
				builder.WriteString(",")
			}
			if resolver.noDefaultALPN {
				builder.WriteString("!default")
			}
			for _, address := range resolver.addresses {
				builder.WriteString("|")
				builder.WriteString(address.String())
			}
			// The transport actually selected is the fact that matters most: a route change
			// that flips a resolver from usable to unusable, or from plain to DoH, changes
			// where queries go.
			if len(s.availability) > configIndex && len(s.availability[configIndex]) > resolverIndex {
				availability := s.availability[configIndex][resolverIndex]
				builder.WriteString("|t=")
				builder.WriteString(string(availability.transport))
				builder.WriteString("u=")
				builder.WriteString(string(availability.reason))
				for _, address := range availability.addresses {
					builder.WriteString("|")
					builder.WriteString(address.String())
				}
			}
		}
	}
	return builder.String()
}

// sameOriginHost compares two DNS host names for origin identity.
//
// # What is normalized, and what is deliberately not
//
// Authentication Domain Names arrive as DNS FQDNs (`resolver.example.`) while HTTP
// authorities are written without the root dot (`resolver.example`), and the same name may
// differ in case. Those three spellings denote ONE host, so they must compare equal.
//
// The normalization is applied ONLY to a value already known to be a host name, and only for
// a SINGLE trailing root dot. A blanket TrimRight(".") would make `example..` equal
// `example` and would also silently accept an empty name, neither of which is a host. An
// IPv6 literal keeps its brackets, and any port is stripped and compared separately.
func sameOriginHost(first string, second string) bool {
	firstHost, firstPort := splitHostPort(first)
	secondHost, secondPort := splitHostPort(second)
	if firstPort != secondPort {
		return false
	}
	return equalFoldASCII(normalizeHostName(firstHost), normalizeHostName(secondHost))
}

// splitHostPort separates a host from its port, defaulting to the HTTPS port.
func splitHostPort(authority string) (string, string) {
	// IPv6 literal: the colons inside brackets are not separators.
	if strings.HasPrefix(authority, "[") {
		if closing := strings.IndexByte(authority, ']'); closing >= 0 {
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
// It is written out rather than using strings.EqualFold so that the comparison cannot be
// affected by Unicode case folding, which is not how host names compare.
func equalFoldASCII(first string, second string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range len(first) {
		a, b := first[index], second[index]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// recomputeAvailability rebuilds a state's availability from a new capability, keeping the
// configurations, the claims and the resolvers exactly as they were.
//
// It exists because usability is a JOINT property of what the server advertised and what this
// client can currently do. The same DNS_ASSIGN is usable or unusable depending on whether the
// tunnel is H3 and which ranges were advertised, so a capability change must re-evaluate --
// otherwise a tunnel that reconnects over H2 would keep offering same-H3 DoH on a connection
// that no longer exists, and a route change would leave a now-unreachable resolver installed.
func recomputeAvailability(current *assignedDNSState, capability resolverCapability) *assignedDNSState {
	next := &assignedDNSState{
		configurations: current.configurations,
		pref64:         append([]netip.Prefix(nil), current.pref64...),
		hasAssignment:  current.hasAssignment,
	}
	for _, configuration := range current.configurations {
		var availability []resolverAvailability
		for _, resolver := range configuration.resolvers {
			availability = append(availability, resolver.availability(capability))
		}
		next.availability = append(next.availability, availability)
	}
	return next
}

// describe renders a resolver for logs and errors, naming the metadata that belongs to THIS
// resolver. That is what makes a misrouting bug legible in a log rather than a mystery.
func (e assignedResolverEndpoint) describe() string {
	description := "<no address>"
	if len(e.addresses) > 0 {
		description = e.addresses[0].String()
	} else if e.authenticationDomainName != "" {
		description = e.authenticationDomainName
	}
	if e.authenticationDomainName != "" && len(e.addresses) > 0 {
		description = description + " (" + e.authenticationDomainName + ")"
	}
	return description
}

// dnsPort is the port plain DNS should be sent to.
//
// An advertised `port` applies to the resolver's own transports, so it is honoured here as
// well as for DoH. RFC 9461 makes `port` automatically mandatory, which means a client that
// claims to support the endpoint cannot silently ignore it.
func (e assignedResolverEndpoint) dnsPort() uint16 {
	if e.hasPort {
		return e.port
	}
	return assignedDNSDefaultPort
}

// dohPort is the port a DoH request should be addressed to.
//
// The dohpath is an HTTP resource, so its default is the HTTPS port; using the plain DNS
// default of 53 would send an HTTPS request to the DNS port.
func (e assignedResolverEndpoint) dohPort() uint16 {
	if e.hasPort {
		return e.port
	}
	if e.hasDohPath {
		return 443
	}
	return 0
}

// offersDoH reports whether the advertised ALPN set includes an HTTP transport.
//
// Only h2 and h3 count. This client implements same-connection DoH over H3 exclusively, so
// offersDoH is about what the SERVER advertised; whether the client can use it is decided by
// availability(), which also requires the live tunnel to be H3.
func (e assignedResolverEndpoint) offersDoH() bool {
	for _, protocol := range e.alpn {
		if protocol == "h2" || protocol == "h3" {
			return true
		}
	}
	return false
}
