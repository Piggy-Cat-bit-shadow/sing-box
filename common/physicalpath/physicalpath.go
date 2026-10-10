// Package physicalpath reconstructs, for one root, the ordered sequence of hops a packet
// actually traverses - as opposed to the control-plane path that SELECTED it.
//
// # The three things that are not the same, and are routinely conflated
//
//  1. the SELECTED OUTBOUND ROOT      what a routing rule chose. One tag, reached through
//     the group nesting the rule named.
//  2. the ACTUAL PHYSICAL HOPS        the real encapsulation chain: #0 is nearest to this
//     device, #N is the last dependency reached before the
//     traffic leaves for the destination.
//  3. CONTROL GROUP NODES             a selector, a urltest or a loadbalance. It selects and
//     then disappears: it never wraps a connection, never sees
//     a byte, and is not a hop.
//
// A diagnostic that reports (3) as (2), or that reports (2) in the reverse order, is worse than
// no diagnostic at all: it describes a path the traffic does not take.
//
// # The direction, and the lines that prove it
//
// A configured `detour` is a DEPENDENCY edge. `X.detour = Y` means X consumes Y, so the packet
// reaches X first and Y second. The configured field is the DEPENDENCY, not the predecessor:
// common/dialer/detour.go
//
//	func (d *DetourDialer) init() {                             // :57
//	    dialer, loaded = d.outboundManager.Outbound(d.detour)  // :61  <- Y
//	    d.dialer = dialer                                       // :77
//	}
//	func (d *DetourDialer) DialContext(...) {                   // :80
//	    return dialer.DialContext(ctx, network, destination)    // :85  <- X asks Y to dial
//	}
//
// A proxy outbound builds its dialer from those options and uses it only to reach its own SERVER,
// so its own hop is entered before the dependency is dialled - protocol/socks/outbound.go
//
//	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())  // :134
//	dialClientDialer := clientDialer(outboundDialer, version, options.ServerOptions.Build()) // :157
//	client: socks.NewClient(dialClientDialer, ...)                                          // :162
//	... h.client.DialContext(ctx, network, destination)                                     // :292
//
// The route path states the same order structurally: the chain is built consumer-first and the
// LAST element is the one that is dialled.
//
//	chain := []adapter.Outbound{outbound}       // route/route.go:247
//	chain = append(chain, outbound)             // route/route.go:266
//	leaf := chain[len(chain)-1]                 // route/route.go:899, :956
//
// Therefore, in this package:
//
//	Hops[0] is the outbound the flow's routing selected,
//	Hops[len-1] is the last dependency reached - the exit.
//
// # Read-only, and what that forbids
//
// The walk in this package dials nothing, resolves nothing, starts no goroutine and arms no timer,
// and it consumes no group state: a preview that moved a round-robin cursor, or that pinned a
// sticky-session key, would hand a real flow a different member than the diagnostic just reported.
// See resolveSelection for why the existing Selected() is a preview for every group in this tree,
// and why a caller can always override the answer through Snapshot. Leaves takes no preview at all,
// because it reads the group's DECLARED membership rather than its current choice.
package physicalpath

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// Resolver is the read-only view of the object graph a walk is allowed to use.
//
// It holds a registry lookup, a Snapshot and a frozen clock-free scope - there is no dialer, no
// logger, no context and no clock, so a walk physically cannot dial, log, or time anything. One
// Resolver answers consistently for its whole lifetime: the member a group is reported as having
// selected is decided once and reused, so two questions about one flow cannot disagree.
type Resolver struct {
	lookup    func(tag string) (adapter.Outbound, bool)
	snapshot  Snapshot
	network   string
	decisions map[string]string

	// domainResolverFor reports the DNS server tag an outbound resolves names through, keyed by
	// outbound tag. It is supplied by the caller because the derivation lives in
	// common/dialer.NewDNSQueryOptions - "the transport the outbound would actually use" - and
	// re-deriving it here would be a second answer to a question that already has one.
	domainResolverFor func(tag string) string
	// defaultDomainResolver reports whether the network layer configures a resolver that applies
	// when the outbound declares none.
	defaultDomainResolver bool
}

// NewResolver builds a resolver over a registry lookup.
//
// lookup MUST be read-only and MUST NOT create anything; adapter.OutboundManager.Outbound is the
// canonical implementation, because it answers from the outbound map and falls back to the
// endpoint namespace - the same lookup the dial path performs.
func NewResolver(lookup func(tag string) (adapter.Outbound, bool), snapshot Snapshot) *Resolver {
	return &Resolver{
		lookup:    lookup,
		snapshot:  snapshot,
		decisions: make(map[string]string),
	}
}

// WithNetwork pins the network the walk is answering for. It is only consulted when a group has to
// be asked for a selection, because a group with a per-network answer must not be asked with the
// wrong one.
func (r *Resolver) WithNetwork(network string) *Resolver {
	r.network = network
	return r
}

// WithDomainResolvers installs the DNS-availability view the destination-ownership check needs.
//
// resolverFor may be nil, in which case no outbound is reported as having its own resolver.
func (r *Resolver) WithDomainResolvers(resolverFor func(tag string) string, defaultConfigured bool) *Resolver {
	r.domainResolverFor = resolverFor
	r.defaultDomainResolver = defaultConfigured
	return r
}

// Lookup resolves a tag to the live object, and reports whether it exists.
func (r *Resolver) Lookup(tag string) (adapter.Outbound, bool) {
	if r.lookup == nil {
		return nil, false
	}
	return r.lookup(tag)
}

// CanResolveDestination reports whether an outbound can resolve a destination name before writing
// the request to its peer, and when it cannot, why.
//
// # Why this is a question about the configuration and not about a request
//
// The check runs before any traffic exists, so it cannot observe a lookup. What it can observe is
// whether a lookup would have an authority to go to: an explicitly declared resolver, or a
// resolver the network layer supplies by default. Anything else means every named destination
// would fail closed - which is the contract the ownership flag states, and a start-time fact.
func (r *Resolver) CanResolveDestination(tag string) (bool, string) {
	if r.domainResolverFor != nil && r.domainResolverFor(tag) != "" {
		return true, ""
	}
	if r.defaultDomainResolver {
		return true, ""
	}
	return false, "the configuration declares destination_dns_ownership for this outbound, which " +
		"requires it to resolve the destination before writing the request to its peer, but neither " +
		"the outbound nor the network configures a domain resolver; every named destination would " +
		"fail closed at run time"
}

// Hop is ONE physical hop of a path, in packet order.
type Hop struct {
	// Position is the packet-order index. 0 is nearest to this device.
	Position int
	// DeclaredTag is the tag the configuration named for this hop - the tag a user can search
	// for in their own configuration file.
	DeclaredTag string
	// ResolvedLeafTag is the concrete leaf this hop resolves to, when it differs from
	// DeclaredTag. A hop whose CONFIGURED tag is a group carries the group's tag here and the
	// member's tag in ResolvedLeafTag, because the object that carries the traffic is the
	// member. It is empty when the object's own tag is what was configured.
	ResolvedLeafTag string
	// Type is the outbound type, e.g. "socks" or "masque".
	Type string
	// IsEndpoint is true when this hop is an adapter.Endpoint rather than an outbound: it
	// terminates a tunnel on this device rather than forwarding to another server.
	IsEndpoint bool
	// IsGroup is true when the node at this position is a control-plane object rather than a
	// physical hop. Build NEVER emits a hop with IsGroup set: the field exists so a caller cannot
	// express "a group is a hop" by accident, and so a test can assert its absence.
	IsGroup bool
	// ControlOwner is the tag of the group that selected this hop, or empty when routing named
	// the hop directly.
	ControlOwner string
}

// String renders one hop for a diagnostic: position, tag and type.
func (h Hop) String() string {
	var builder strings.Builder
	builder.WriteString("#")
	builder.WriteString(strconv.Itoa(h.Position))
	builder.WriteString(" ")
	builder.WriteString(h.DeclaredTag)
	if h.ResolvedLeafTag != "" && h.ResolvedLeafTag != h.DeclaredTag {
		builder.WriteString("(")
		builder.WriteString(h.ResolvedLeafTag)
		builder.WriteString(")")
	}
	if h.Type != "" {
		builder.WriteString("[")
		builder.WriteString(h.Type)
		builder.WriteString("]")
	}
	if h.IsEndpoint {
		builder.WriteString(" endpoint")
	}
	if h.IsGroup {
		builder.WriteString(" GROUP-NOT-A-HOP")
	}
	if h.ControlOwner != "" {
		builder.WriteString(" selected-by ")
		builder.WriteString(h.ControlOwner)
	}
	return builder.String()
}

// Path is the reconstructed path of one root.
type Path struct {
	// Root is the tag of the outbound the walk started from.
	Root string
	// ControlPath lists the tags involved in SELECTING, in descent order: the root, then each
	// group as it was entered. It is not packet order and must never be reported as one.
	ControlPath []string
	// Hops is the physical path in PACKET order. Hops[0] is nearest to this device.
	Hops []Hop
	// Unknowns names what could not be resolved, each with the reason. A hop that cannot be
	// determined is reported here and never invented.
	Unknowns []Unknown
}

// Unknown is one thing the read-only walk could not determine, and why.
//
// It exists because an invented hop is the worst possible outcome for a diagnostic: a path that
// lies is worse than one that says "unknown". Every site that would otherwise have to guess
// appends here instead.
type Unknown struct {
	// Node is the tag of the object whose contribution could not be determined.
	Node string
	// Position is the hop index the missing answer belongs at, or -1 when it is not a hop.
	Position int
	// Reason is why it could not be determined.
	Reason string
}

// HasUnknown reports whether any hop of this path could not be determined.
//
// A caller that is about to claim "this path is reachable" MUST check it first: a path with an
// unknown hop is not a path that was verified, it is a path that was partly verified.
func (p Path) HasUnknown() bool {
	return len(p.Unknowns) > 0
}

// Exit returns the last physical hop - the one the traffic leaves from - and false when the path
// has no hop or any hop of it is unknown.
func (p Path) Exit() (Hop, bool) {
	if len(p.Hops) == 0 || p.HasUnknown() {
		return Hop{}, false
	}
	return p.Hops[len(p.Hops)-1], true
}

// GroupsNamed returns the control-plane nodes on this path, for a caller that wants to show
// "selected through" separately from the hops.
func (p Path) GroupsNamed() []string {
	groups := make([]string, 0, len(p.ControlPath))
	for _, tag := range p.ControlPath {
		if tag != p.Root {
			groups = append(groups, tag)
		}
	}
	return groups
}

// Snapshot answers the two questions a read-only walk needs about a group, so a caller - a test, a
// control-plane read, a start-time dry run - can pin the answer instead of letting the walk take
// whatever the live object happens to say.
//
// # Both fields are optional, and that is deliberate
//
// A nil field falls through to the live object through resolveSelection, which is a preview for
// every group in this tree. A caller that must not depend on live state sets the field it cares
// about; a caller that has no opinion leaves it nil and gets the live answer.
type Snapshot struct {
	// Selections overrides the member each group has selected, by group tag. Set the value to
	// "" to state that the member is NOT KNOWABLE, which makes the walk report the group as
	// unknown instead of reading the live selection.
	Selections map[string]string
	// Candidates overrides the members a group can reach, by group tag. It exists so a dry run
	// can validate a membership set that does not depend on what the group currently holds.
	Candidates map[string][]string
}

// Options configures one walk.
type Options struct {
	// Label identifies the caller's root for diagnostics. Defaults to the root's tag.
	Label string
	// Network is the network the path must be able to carry, e.g. "tcp" or "udp". Empty means
	// the caller has no requirement.
	Network string
}

// TagOrOutbound names the root of a walk: a tag to look up, or an object the caller already holds.
type TagOrOutbound struct {
	Tag      string
	Outbound adapter.Outbound
}

// Build reconstructs the physical path under one root.
//
// It is READ-ONLY: no dial, no DNS lookup, no goroutine, no ticker, no timer, no log line. It does
// not clone a group - the objects it visits are the registry's own - and it does not consume a
// group's round-robin cursor. The declared-dependency graph it follows is the same edge set
// adapter/outbound/cross_kind_cycle.go already validates at start, so no second graph exists: group
// edges come from the group's own membership declaration and dependency edges from
// adapter.Outbound.Dependencies, exactly as that validator reads them.
//
// Where the selected leaf is not knowable it is reported in Path.Unknowns rather than invented. A
// cycle returns an error naming the full chain.
//
// # Panics are contained
//
// The walk calls methods on user-configured objects - Dependencies, All, Selected, Tag, Network -
// and an object graph can be malformed in ways that panic: a typed-nil embedded interface is the
// case that has actually been observed, where a struct embeds adapter.Outbound as nil and the
// promoted method dereferences it. A diagnostic that crashes on the configuration it is describing
// is worse than one that reports it, and this is the same containment
// group.ResolveURLTestLeaf applies for the same reason. A partially built Path is discarded: either
// a path is answered or the caller is told it could not be.
func Build(resolver *Resolver, root TagOrOutbound, options Options) (path Path, err error) {
	if resolver == nil {
		return Path{}, E.New("physicalpath: a resolver is required")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			path = Path{}
			err = E.New("physical path walk panicked: ", recovered)
		}
	}()
	label := options.Label
	if label == "" {
		label = root.Tag
	}
	if label == "" && root.Outbound != nil {
		label = root.Outbound.Tag()
	}
	previousNetwork := resolver.network
	if options.Network != "" {
		resolver.network = options.Network
	}
	// The per-walk decision record is cleared here, so one Resolver can answer two walks and each
	// walk is internally consistent without either becoming stale.
	clear(resolver.decisions)
	defer func() {
		resolver.network = previousNetwork
	}()
	path = Path{Root: label}
	entry := root.Outbound
	if entry == nil {
		if root.Tag == "" {
			return Path{}, E.New("physicalpath: a root tag or outbound is required")
		}
		var loaded bool
		entry, loaded = resolver.Lookup(root.Tag)
		if !loaded {
			path.Unknowns = append(path.Unknowns, Unknown{
				Node:     root.Tag,
				Position: -1,
				Reason:   "the root tag does not exist in the registry",
			})
			return path, nil
		}
	}
	if err = resolver.walk(&path, entry, nil, ""); err != nil {
		return Path{}, err
	}
	return path, nil
}

// walk visits one node of the selection graph.
//
// chain is the descent that reached this node, and it is simultaneously the cycle record: this
// mirrors route/route.go's resolveOutbound, which builds the same record for the same reason and
// deliberately has no separate depth limit.
func (r *Resolver) walk(path *Path, node adapter.Outbound, chain []adapter.Outbound, controlOwner string) error {
	if containsNode(chain, node) {
		return cycleObjectsError(chain, node)
	}
	group, isGroup := node.(adapter.OutboundGroup)
	if isGroup {
		// A group is a control-plane object. It is recorded in the CONTROL path and never as a
		// physical hop, because it never carries a byte.
		path.ControlPath = append(path.ControlPath, node.Tag())
		selected, reason := r.resolveSelection(group, node.Tag())
		if selected == nil {
			path.Unknowns = append(path.Unknowns, Unknown{
				Node:     node.Tag(),
				Position: len(path.Hops),
				Reason:   reason,
			})
			return nil
		}
		// The hop this member becomes carries the group as its ControlOwner, and the group's
		// configured tag as its DeclaredTag only when the group itself was what the path named.
		return r.walk(path, selected, append(chain, node), node.Tag())
	}
	// A physical hop.
	hop := Hop{
		Position:        len(path.Hops),
		DeclaredTag:     node.Tag(),
		ResolvedLeafTag: node.Tag(),
		Type:            node.Type(),
		IsGroup:         false,
		ControlOwner:    controlOwner,
	}
	if _, isEndpoint := node.(adapter.Endpoint); isEndpoint {
		hop.IsEndpoint = true
	}
	path.Hops = append(path.Hops, hop)
	// The dependency edge. The CONSUMER is appended first, so the next hop is the dependency:
	// packet order, not configuration order.
	dependencyTag := firstDependency(node)
	if dependencyTag == "" {
		return nil
	}
	dependency, reason := r.lookupDependency(dependencyTag)
	if dependency == nil {
		path.Unknowns = append(path.Unknowns, Unknown{
			Node:     dependencyTag,
			Position: len(path.Hops),
			Reason:   reason,
		})
		return nil
	}
	return r.walk(path, dependency, append(chain, node), node.Tag())
}

// lookupDependency resolves a declared dependency tag through the registry.
func (r *Resolver) lookupDependency(tag string) (adapter.Outbound, string) {
	if r.lookup == nil {
		return nil, "no registry was supplied, so the dependency " + tag + " cannot be resolved"
	}
	outbound, loaded := r.lookup(tag)
	if !loaded {
		return nil, "the declared dependency " + tag + " does not exist in the registry"
	}
	return outbound, ""
}

// resolveSelection answers "which member does this group hand the flow to" without consuming any
// group state, and returns the reason when it cannot.
//
// # Why calling the existing Selected() is a preview here, for every group in this tree
//
// The three group implementations each make the same promise, so the walk does not need a private
// copy of the answer:
//
//   - Selector.Selected (protocol/group/selector.go:118) returns the loaded atomic and nothing else.
//   - URLTest.Selected (protocol/group/urltest.go:207) reads the selected generation and, when that
//     is empty, calls URLTestGroup.Select, which reads the history store and the member list and
//     writes nothing back.
//   - LoadBalance.Selected (protocol/group/loadbalance.go:259) is documented as "a pure preview" and
//     delegates to SelectForFlow(.., commit=false); the round-robin branch takes the cursor with
//     Load() and only advances it with Add(1) when commit is true
//     (protocol/group/loadbalance.go:337-341).
//
// A caller that cannot accept even that still has Snapshot: an entry there replaces the live
// answer, and an explicit empty entry turns it into an unknown.
func (r *Resolver) resolveSelection(group adapter.OutboundGroup, tag string) (adapter.Outbound, string) {
	if r.snapshot.Selections != nil {
		if declared, present := r.snapshot.Selections[tag]; present {
			if declared == "" {
				return nil, "the supplied snapshot states that the member selected by group " +
					tag + " is not knowable"
			}
			if r.lookup == nil {
				return nil, "no registry was supplied, so the snapshot's member " + declared +
					" of group " + tag + " cannot be resolved"
			}
			outbound, loaded := r.lookup(declared)
			if !loaded {
				return nil, "the supplied snapshot names " + declared + " as the member selected by group " +
					tag + ", but no such outbound or endpoint exists"
			}
			return outbound, ""
		}
	}
	// One answer per group per walk. A group whose answer can move - a urltest whose chosen node
	// changes, a balancing group whose flow-keyed choice differs between two callers - would
	// otherwise let two questions about the SAME flow disagree, which is the one thing a
	// diagnostic must not do.
	if r.decisions != nil {
		if decided, present := r.decisions[tag]; present {
			if decided == "" {
				return nil, "group " + tag + " answered no selection earlier in this walk"
			}
			outbound, loaded := r.Lookup(decided)
			if !loaded {
				return nil, "group " + tag + " answered " + decided + " earlier in this walk, but that " +
					"outbound no longer resolves"
			}
			return outbound, ""
		}
	}
	network := r.network
	if network == "" {
		network = NetworkTCP
	}
	selected := group.Selected(network)
	if selected == nil {
		if r.decisions != nil {
			r.decisions[tag] = ""
		}
		return nil, "group " + tag + " has no selected member for " + network
	}
	if r.decisions != nil {
		r.decisions[tag] = selected.Tag()
	}
	return selected, ""
}

// containsNode reports whether the node is already in the descent.
//
// Identity, not the tag, is what closes a loop: a tag is configuration and two objects may share
// one, so a tag comparison could report a cycle that does not exist - or miss one that does.
func containsNode(chain []adapter.Outbound, node adapter.Outbound) bool {
	for _, element := range chain {
		if element == node {
			return true
		}
	}
	return false
}

// firstDependency returns the single declared dependency of an outbound, or "".
//
// An outbound declares its dependencies once, in adapter.NewAdapterWithDialerOptions from the
// dialer options it was built with, so this is the same edge the start-order sort and the
// cross-kind validator read - not a re-derivation from the options.
func firstDependency(outbound adapter.Outbound) string {
	if outbound == nil {
		// A nil Outbound is the typed-nil case: a lookup that reports "loaded" while holding no
		// object. Returning "" reports it as a node with no dependency rather than dereferencing
		// it, because a read-only diagnostic must not panic on a graph it is describing.
		return ""
	}
	dependencies := outbound.Dependencies()
	if len(dependencies) == 0 {
		return ""
	}
	return dependencies[0]
}

// errCycle is the one constructor for the cycle error, so every cycle report has the same shape.
func errCycle(chain string) error {
	return E.New("physical path cycle detected: ", chain)
}

// itoa is strconv.Itoa under a shorter name, so the hop rendering in this package stays readable.
func itoa(value int) string {
	return strconv.Itoa(value)
}

// networksOf reports what an outbound can carry, tolerating a nil slice: a leaf that reports no
// network is a fact the dry run reports rather than a panic.
func networksOf(outbound adapter.Outbound) []string {
	if outbound == nil {
		return nil
	}
	return outbound.Network()
}

// NetworkTCP and NetworkUDP are the two networks a physical path is required to carry. They are
// named here rather than taken from the network package so this package's import set stays
// minimal, but the values are protocol names, not this package's invention.
const (
	NetworkTCP = "tcp"
	NetworkUDP = "udp"
)
