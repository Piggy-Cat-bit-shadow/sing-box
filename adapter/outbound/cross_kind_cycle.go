package outbound

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// Cross-kind dependency validation: DNS transport <-> outbound.
//
// # The gap this closes
//
// Each manager validates the graph it can see, and neither sees the edge that closes this cycle:
//
//	dns/udp[remote]  --detour---------->  outbound/socks[proxy]
//	outbound/socks[proxy]  --domain_resolver-->  dns/udp[remote]
//
// dns/transport_adapter.go deliberately routes `detour` into References() and only
// `domain_resolver` into Dependencies(), so dns/transport_manager.go's sort - which reads
// Dependencies() - is blind to the detour edge. adapter/outbound/manager.go's sort only ever walks
// outbound tags, so an outbound's `domain_resolver` (which names a DNS TRANSPORT, not an outbound)
// is not an edge it can follow either. A configuration with those two edges therefore starts
// successfully and fails on the first dial.
//
// # What the failure actually is
//
// Measured through the real load path (box.New/Start, then a dial through the outbound): the
// configuration is constructible and starts, and the first dial never completes. The dial chain is
//
//	outbound.DialContext
//	  -> resolve the server name through dns/udp[remote]
//	    -> the transport dials its server through its detour, outbound/socks[proxy]
//	      -> resolve the server name through dns/udp[remote]   (the same transport)
//
// which blocks on the DNS transport's own connection-pool slot (or the HTTP/2 client's connection
// pool for a DoH transport) held by the outer exchange. It is a hang rather than a stack overflow
// only because those pools serialise the re-entry; remove that serialisation and the same graph is
// unbounded literal recursion, which is a fatal stack exhaustion no recover() can contain. Either
// way there is no startup error and no runtime guard that can make the configuration meaningful, so
// the cycle has to be refused before any traffic exists.
//
// # Why the graph is built here and not per dial
//
// A per-dial hop counter would put a cost on every connection to describe a configuration error
// that is already fully known at start. This runs once, on the object graph the dial path will
// actually use, next to the outbound sort that already exists for the outbound-only case. It is
// started by dns/transport_manager.go because the DNS transport manager is the only component that
// holds both sides: its transports and the outbound manager.
//
// # Why the resolver edge is exact enough
//
// The outbound side of the edge is declared by the outbound's own Adapter, from the same
// DialerOptions its ResolveDialer is built from (see Adapter.DomainResolverReference). It is the
// same edge route/reference.go already walks when it decides which DNS transports are referenced,
// so the two views cannot disagree about what an outbound depends on.
//
// The walk treats a non-empty `domain_resolver` as a dependency unconditionally, exactly as the
// DNS transport manager already treats a DNS transport's `domain_resolver` when it sorts its own
// graph (TransportAdapter.Dependencies). That is the established rule in this tree: the declared
// resolver is an edge, whether or not every path of the outbound ends up consulting it. It is
// conservative in one direction - a proxying outbound whose server is an IP literal makes no local
// lookup, so naming a resolver on it is a declaration the configuration cannot use, and refusing it
// is reporting a configuration error rather than rejecting a legal graph. The other direction -
// letting an unbounded recursion into the dial path because the edge might be unused - is not a
// trade worth making.

// crossKindNodeKind distinguishes the two namespaces in the combined graph.
type crossKindNodeKind uint8

const (
	crossKindDNS crossKindNodeKind = iota
	crossKindOutbound
)

// crossKindNode identifies one node in the combined graph.
//
// The kind is part of the identity rather than implied by the tag because the two namespaces are
// genuinely separate: an outbound and a DNS transport may share a tag, and merging them would let a
// legal configuration look like a cycle (or hide one).
type crossKindNode struct {
	kind crossKindNodeKind
	tag  string
}

func (n crossKindNode) String() string {
	if n.kind == crossKindDNS {
		return "dns/" + n.tag
	}
	return "outbound/" + n.tag
}

// ValidateCrossKindCycles refuses a cycle in the union of the DNS-transport and outbound graphs.
//
// It is called once at StartStateStart, before any transport is started, with the transports the
// DNS transport manager is about to start.
func (m *Manager) ValidateCrossKindCycles(transports []adapter.DNSTransport) error {
	outbounds := make(map[string]adapter.Outbound)
	if m != nil {
		m.access.RLock()
		for _, outbound := range m.outbounds {
			outbounds[outbound.Tag()] = outbound
		}
		m.access.RUnlock()
		if m.endpoint != nil {
			for _, endpoint := range m.endpoint.Endpoints() {
				outbounds[endpoint.Tag()] = endpoint
			}
		}
	}
	transportsByTag := make(map[string]adapter.DNSTransport, len(transports))
	for _, transport := range transports {
		transportsByTag[transport.Tag()] = transport
	}
	if len(transportsByTag) == 0 {
		return nil
	}
	graph := &crossKindGraph{outbounds: outbounds, transports: transportsByTag}
	return graph.validate()
}

type crossKindGraph struct {
	outbounds  map[string]adapter.Outbound
	transports map[string]adapter.DNSTransport
}

// known reports whether the edge target exists. A missing tag is not this check's business: the
// per-kind sorts report it as "dependency not found", and doing it here too would replace a
// precise message with a confusing one.
func (g *crossKindGraph) known(node crossKindNode) bool {
	if node.kind == crossKindDNS {
		_, loaded := g.transports[node.tag]
		return loaded
	}
	_, loaded := g.outbounds[node.tag]
	return loaded
}

// edges returns the outgoing edges of one node, in both directions of the cross-kind boundary.
func (g *crossKindGraph) edges(node crossKindNode) []crossKindNode {
	switch node.kind {
	case crossKindDNS:
		transport := g.transports[node.tag]
		dependencies := transport.Dependencies()
		edges := make([]crossKindNode, 0, len(dependencies)+1)
		// A DNS transport's own dependencies are other DNS transports (domain_resolver). They are
		// included so a cycle that runs through a chain of resolvers is caught as one cycle rather
		// than as several disconnected legal edges.
		for _, dependency := range dependencies {
			edges = append(edges, crossKindNode{kind: crossKindDNS, tag: dependency})
		}
		// The detour is an OUTBOUND, which is the edge no manager's sort reads.
		if referrer, isReferrer := transport.(adapter.Referrer); isReferrer {
			for _, reference := range referrer.References() {
				edges = append(edges, crossKindNode{kind: crossKindOutbound, tag: reference})
			}
		}
		return edges
	default:
		outbound := g.outbounds[node.tag]
		dependencies := outbound.Dependencies()
		edges := make([]crossKindNode, 0, len(dependencies)+1)
		// An outbound's dependencies are outbound tags: a detour, or the members of a group. A
		// nested selector is exactly this edge, which is why a cycle through one is found here.
		for _, dependency := range dependencies {
			edges = append(edges, crossKindNode{kind: crossKindOutbound, tag: dependency})
		}
		if resolver, isResolver := outbound.(interface{ DomainResolverReference() string }); isResolver {
			if server := resolver.DomainResolverReference(); server != "" {
				edges = append(edges, crossKindNode{kind: crossKindDNS, tag: server})
			}
		}
		return edges
	}
}

const (
	crossKindUnvisited uint8 = iota
	crossKindVisiting
	crossKindVisited
)

// validate walks the combined graph depth-first and reports the first back edge it finds.
//
// The walk is recursive like the two per-kind sorts it complements, and like them it terminates at
// the first cycle, so its depth is bounded by the number of nodes rather than by anything the
// configuration can make unbounded. The visiting state is what distinguishes a back edge (a cycle)
// from the diamond that is legal: two paths reaching the same node.
func (g *crossKindGraph) validate() error {
	state := make(map[crossKindNode]uint8, len(g.outbounds)+len(g.transports))
	var path []crossKindNode
	var visit func(node crossKindNode) error
	visit = func(node crossKindNode) error {
		switch state[node] {
		case crossKindVisited:
			return nil
		case crossKindVisiting:
			// Report the cycle from the node it closes on, so the message names exactly the loop
			// rather than everything walked before it.
			start := 0
			for index, element := range path {
				if element == node {
					start = index
					break
				}
			}
			names := make([]string, 0, len(path)-start+1)
			for _, element := range path[start:] {
				names = append(names, element.String())
			}
			names = append(names, node.String())
			return E.New("circular dependency between DNS server and outbound: ", strings.Join(names, " -> "))
		}
		state[node] = crossKindVisiting
		path = append(path, node)
		for _, next := range g.edges(node) {
			if !g.known(next) {
				continue
			}
			if err := visit(next); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		state[node] = crossKindVisited
		return nil
	}
	// Sorted starts, so the reported path is reproducible: map iteration order would make the same
	// configuration name a different entry point on each run, which turns a startup error into
	// something a bug report cannot quote.
	transportTags := make([]string, 0, len(g.transports))
	for tag := range g.transports {
		transportTags = append(transportTags, tag)
	}
	slices.Sort(transportTags)
	for _, tag := range transportTags {
		if err := visit(crossKindNode{kind: crossKindDNS, tag: tag}); err != nil {
			return err
		}
	}
	outboundTags := make([]string, 0, len(g.outbounds))
	for tag := range g.outbounds {
		outboundTags = append(outboundTags, tag)
	}
	slices.Sort(outboundTags)
	for _, tag := range outboundTags {
		if err := visit(crossKindNode{kind: crossKindOutbound, tag: tag}); err != nil {
			return err
		}
	}
	return nil
}
