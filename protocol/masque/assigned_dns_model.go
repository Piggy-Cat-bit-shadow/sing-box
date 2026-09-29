package masque

import (
	"net/netip"
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
	// dohPath is the SVCB dohpath template, when one was advertised.
	dohPath string
	// port is the advertised port, or 0 when none was advertised.
	port uint16
}

// assignedResolverConfiguration is one configuration: the resolvers responsible for a set
// of internal domains.
type assignedResolverConfiguration struct {
	// internalDomains are the names this configuration owns. An EMPTY list means it is the
	// DEFAULT configuration, which serves every name no other configuration claims.
	//
	// That reading follows the draft: configurations exist so different servers can own
	// separate internal domains, and a configuration with none names no domains to own,
	// so it is the catch-all rather than an unreachable one.
	internalDomains []string
	// searchDomains are the search suffixes to append to unqualified names.
	searchDomains []string
	// resolvers are this configuration's nameservers, ordered by priority.
	resolvers []assignedResolverEndpoint
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
	// hasAssignment distinguishes "no assignment" from "an assignment with no usable
	// resolvers". Both serve no queries, but only the second means the server spoke.
	hasAssignment bool
}

// endpointLookup holds the resolver chosen for a query name, along with the configuration it
// came from.
type endpointLookup struct {
	configuration assignedResolverConfiguration
	endpoint      assignedResolverEndpoint
	found         bool
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

	bestConfiguration := -1
	bestMatchLength := -1
	defaultConfiguration := -1

	for index, configuration := range s.configurations {
		if len(configuration.resolvers) == 0 {
			// A configuration with no usable resolver owns nothing: it cannot answer for
			// any name, so it must not capture matching names from one that can.
			continue
		}
		if len(configuration.internalDomains) == 0 {
			if defaultConfiguration < 0 {
				defaultConfiguration = index
			}
			continue
		}
		for _, domain := range configuration.internalDomains {
			normalizedDomain := normalizeQueryName(domain)
			if !nameMatchesDomain(normalized, normalizedDomain) {
				continue
			}
			if len(normalizedDomain) > bestMatchLength {
				bestMatchLength = len(normalizedDomain)
				bestConfiguration = index
			}
		}
	}

	if bestConfiguration < 0 {
		bestConfiguration = defaultConfiguration
	}
	if bestConfiguration < 0 {
		return endpointLookup{}
	}
	configuration := s.configurations[bestConfiguration]
	endpoint, found := configuration.preferredResolver()
	if !found {
		return endpointLookup{}
	}
	return endpointLookup{configuration: configuration, endpoint: endpoint, found: true}
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

// ---------------------------------------------------------------------------
// Building the model from the wire types
// ---------------------------------------------------------------------------

// buildAssignedDNSState converts a parsed assignment into the runtime model.
//
// Every slice and map is COPIED. The parsed structures are owned by the caller that parsed
// them, and the state is published to other goroutines and read for the lifetime of the
// assignment, so retaining a caller's slice would let a later mutation change live resolver
// behaviour. The service parameters are maps of byte slices, which is the case most likely
// to be shared inadvertently, so each value is copied rather than referenced.
func buildAssignedDNSState(configurations []masque.DNSConfiguration, pref64 []netip.Prefix, generation uint64) *assignedDNSState {
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
		for _, nameserver := range configuration.Nameservers {
			runtimeConfiguration.resolvers = append(runtimeConfiguration.resolvers,
				buildResolverEndpoint(nameserver))
		}
		state.configurations = append(state.configurations, runtimeConfiguration)
	}
	return state
}

// buildResolverEndpoint converts one nameserver, keeping its metadata its own.
func buildResolverEndpoint(nameserver masque.DNSNameserver) assignedResolverEndpoint {
	endpoint := assignedResolverEndpoint{
		priority: nameserver.ServicePriority,
		// A fresh slice, so nothing shares backing storage with the parsed message.
		addresses: make([]netip.Addr, 0,
			len(nameserver.IPv4Addresses)+len(nameserver.IPv6Addresses)),
		authenticationDomainName: nameserver.AuthenticationDomainName,
	}
	endpoint.addresses = append(endpoint.addresses, nameserver.IPv4Addresses...)
	endpoint.addresses = append(endpoint.addresses, nameserver.IPv6Addresses...)

	if alpn, loaded := nameserver.ServiceParameters[dnsmessage.SVCParamALPN]; loaded {
		endpoint.alpn = decodeALPNList(alpn)
	}
	if _, loaded := nameserver.ServiceParameters[dnsmessage.SVCParamNoDefaultALPN]; loaded {
		endpoint.noDefaultALPN = true
	}
	if dohPath, loaded := nameserver.ServiceParameters[dnsmessage.SVCParamKey(9)]; loaded {
		endpoint.dohPath = string(dohPath)
	}
	if port, loaded := nameserver.ServiceParameters[dnsmessage.SVCParamKey(3)]; loaded && len(port) == 2 {
		endpoint.port = uint16(port[0])<<8 | uint16(port[1])
	}
	return endpoint
}

// decodeALPNList splits the SVCB alpn parameter.
//
// RFC 9460 section 7.1 defines the value as a sequence of length-prefixed byte strings, so
// `\x02h2\x02h3` is ["h2", "h3"]. A single comma-separated string is also accepted, because
// that is the presentation format operators write and a permissive reader here can only
// avoid false failures, not cause one.
func decodeALPNList(value []byte) []string {
	if len(value) == 0 {
		return nil
	}
	// The length-prefixed form is tried FIRST and accepted only if it consumes the whole
	// value exactly. Trying it first is what the wire format requires; requiring exact
	// consumption is what keeps a comma-separated presentation string from being misread.
	//
	// Without the exactness check this is ambiguous, and the ambiguity is not theoretical:
	// "h2,h3" would parse its first byte ('h' = 104) as a length, overrun immediately, and
	// yield nothing -- while looking like a valid parse of a valid input.
	protocols, ok := decodeLengthPrefixedALPN(value)
	if ok {
		return protocols
	}
	// Fall back to the presentation form.
	var presentation []string
	for _, part := range strings.Split(string(value), ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			presentation = append(presentation, part)
		}
	}
	return presentation
}

// decodeLengthPrefixedALPN parses RFC 9460 section 7.1's sequence of length-prefixed byte
// strings, reporting whether the input was well formed.
func decodeLengthPrefixedALPN(value []byte) ([]string, bool) {
	var protocols []string
	remaining := value
	for len(remaining) > 0 {
		length := int(remaining[0])
		remaining = remaining[1:]
		if length == 0 || length > len(remaining) {
			return nil, false
		}
		protocols = append(protocols, string(remaining[:length]))
		remaining = remaining[length:]
	}
	if len(protocols) == 0 {
		return nil, false
	}
	return protocols, true
}
