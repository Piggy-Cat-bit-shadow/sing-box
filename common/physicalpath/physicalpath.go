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
// logger, no context and no clock, so a walk physically cannot dial, log, or time anything.
//
// # What a Resolver does NOT hold: anything a walk writes
//
// The network a walk answers for and the answer each group gave DURING that walk are properties of
// one call, not of this view, and they live in the per-call scope `Build` creates (walkScope). That
// is what makes one Resolver safe to keep and share: nothing here is written after construction, so
// two concurrent walks cannot make each other answer for the wrong network, and a walk cannot read
// a decision another walk recorded.
//
// # Concurrency contract
//
// A Resolver is safe for concurrent use by any number of goroutines, PROVIDED the two things the
// caller supplies are safe for concurrent READ:
//
//   - `lookup` must be read-only and must not create anything (adapter.OutboundManager.Outbound is
//     the canonical implementation, and the registry it reads is concurrency-safe for reads).
//   - the Snapshot is COPIED at construction, so the caller's maps are never read again. Mutating
//     them afterwards is not a race and does not change an answer: rebuild the Resolver instead.
//
// The configurable parts are set through With* methods that each return a NEW resolver carrying the
// change and leave the receiver alone, so "configure it" and "keep it immutable once a walk can see
// it" are the same instruction rather than two rules a caller has to obey.
type Resolver struct {
	lookup   func(tag string) (adapter.Outbound, bool)
	snapshot Snapshot
	// network is the network this view answers for when a walk does not name one. It is set at
	// construction (WithNetwork) and never written afterwards.
	network string
	// nodeBudget bounds one Hops enumeration; see DefaultNodeBudget. Set through WithNodeBudget.
	nodeBudget int

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
//
// The Snapshot is FROZEN here: the resolver takes its own copy of both maps (and of each candidate
// slice), so the caller may keep using the maps it passed. See Snapshot for what that does and does
// not promise.
func NewResolver(lookup func(tag string) (adapter.Outbound, bool), snapshot Snapshot) *Resolver {
	return &Resolver{
		lookup:     lookup,
		snapshot:   snapshot.freeze(),
		nodeBudget: DefaultNodeBudget,
	}
}

// configure returns a copy of the resolver with the changes a With* method made applied to it.
//
// Copying rather than assigning is the whole point: a Resolver that a walk can already see must not
// be writable, and a caller that wants a different one asks for a different one.
func (r *Resolver) configure(change func(configured *Resolver)) *Resolver {
	configured := *r
	change(&configured)
	return &configured
}

// WithNetwork returns a resolver that answers for the given network when a walk does not name one.
//
// The receiver is NOT modified. It is only consulted when a group has to be asked for a selection,
// because a group with a per-network answer must not be asked with the wrong one; a walk that names
// its own network through Options overrides the pin for itself and changes nothing here.
func (r *Resolver) WithNetwork(network string) *Resolver {
	return r.configure(func(configured *Resolver) {
		configured.network = network
	})
}

// WithDomainResolvers returns a resolver with the DNS-availability view the destination-ownership
// check needs. The receiver is NOT modified.
//
// resolverFor may be nil, in which case no outbound is reported as having its own resolver.
func (r *Resolver) WithDomainResolvers(resolverFor func(tag string) string, defaultConfigured bool) *Resolver {
	return r.configure(func(configured *Resolver) {
		configured.domainResolverFor = resolverFor
		configured.defaultDomainResolver = defaultConfigured
	})
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
	// ControlPath lists the tags involved in SELECTING, in DESCENT order: the routing decision
	// first, then each group as it was entered, then the leaf.
	//
	// # What this order is, and what it is not
	//
	// It is the order the DECISIONS were taken, which is root-to-leaf by construction. It is NOT
	// packet order and it is not reversed with Hops: a group is a control-plane object that never
	// carries a byte, so it has no position on the wire to be ordered by. Reporting it in wire order
	// would say that the innermost group decided first, which is the opposite of what happened.
	//
	// The last element is the node the descent reached, which is a leaf or an unresolved member -
	// `GroupsNamed` is what a caller wanting only the groups should use.
	ControlPath []string
	// Hops is the physical path in PACKET order: Hops[0] is nearest to this device and the last
	// element is the exit. Packet order is the REVERSE of the dependency descent the configuration
	// expresses, because `x.detour = y` makes x reach its own server through y.
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
	// Hops is in PACKET order, so the hop the traffic LEAVES from is the LAST one, and the hop
	// nearest this device is Hops[0].
	//
	// This is the reading that changed with the direction fix, and it is the one that matters for a
	// caller: a status view that reported Hops[0] as "the exit" would tell an operator their exit is
	// down when the failure was in the first hop. `Path.Entry` makes the nearest hop explicit so a
	// caller never has to reason about which end is which.
	return p.Hops[len(p.Hops)-1], true
}

// Entry returns the hop nearest this device, which is the first one in packet order.
//
// It exists so that "which end is which" is answered by the model rather than by each caller: Hops[0]
// and the last element are both meaningful and they are opposite ends of the same path, so a caller
// that guesses has a fifty percent chance of naming a working hop as the broken one.
func (p Path) Entry() (Hop, bool) {
	if len(p.Hops) == 0 || p.HasUnknown() {
		return Hop{}, false
	}
	return p.Hops[0], true
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
//
// # The caller-supplied maps are FROZEN, not shared
//
// A walk reads these maps without synchronization, so a map the caller can still write would make
// every concurrent walk a data race on the CALLER's data - a race that would be reported inside
// this package and that this package cannot prevent by any amount of internal locking.
//
// NewResolver therefore copies both maps, and each candidate slice with them, at construction:
//
//   - mutating the map afterwards is NOT a data race and does NOT change a single answer, because
//     the resolver no longer reads it;
//   - it also cannot be used to change an answer, which is the deliberate half: a Snapshot is the
//     caller's statement about one moment, and a statement that can be edited under a running walk
//     is not one. A caller that wants different answers builds a different Resolver.
//
// So the contract is neither "the caller must freeze this" nor "concurrent modification is
// supported": the caller may keep using its maps and this package simply never looks at them again.
type Snapshot struct {
	// Selections overrides the member each group has selected, by group tag. Set the value to
	// "" to state that the member is NOT KNOWABLE, which makes the walk report the group as
	// unknown instead of reading the live selection.
	Selections map[string]string
	// Candidates overrides the members a group can reach, by group tag. It exists so a dry run
	// can validate a membership set that does not depend on what the group currently holds.
	Candidates map[string][]string
}

// freeze returns a Snapshot this package owns.
//
// A nil map stays nil, because nil and an empty map mean different things here: nil falls through
// to the live object, while an empty map is a caller stating that nothing is overridden.
func (s Snapshot) freeze() Snapshot {
	frozen := Snapshot{}
	if s.Selections != nil {
		frozen.Selections = make(map[string]string, len(s.Selections))
		for tag, selection := range s.Selections {
			frozen.Selections[tag] = selection
		}
	}
	if s.Candidates != nil {
		frozen.Candidates = make(map[string][]string, len(s.Candidates))
		for tag, candidates := range s.Candidates {
			frozen.Candidates[tag] = append([]string(nil), candidates...)
		}
	}
	return frozen
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
// # Build WRITES nothing the caller can see
//
// Everything the walk needs to remember - the network it is answering for, and the answer each
// group gave during THIS call - lives in the walkScope this function creates and drops. The Resolver
// is read and never written, which is what makes two concurrent builds through one Resolver two
// independent answers rather than a race over one shared record. See Resolver for the concurrency
// contract, and note that the state is PER WALK even single-threaded: two questions about one flow
// cannot disagree, and two flows cannot be confused with one another.
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
	// The per-walk state: the network this call answers for (Options.Network overrides the pinned
	// one for THIS call only) and the decision record. Both are created here and die with the call,
	// so no caller and no other walk can reach them.
	scope := newWalkScope(resolver, options.Network)
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
	if err = scope.walk(&path, entry, nil, ""); err != nil {
		return Path{}, err
	}
	// The walk descends the dependency graph, so it records hops ROOT FIRST - which is the order they
	// are CONFIGURED in, not the order the device reaches them. Packet order is the reverse.
	//
	// # Why the reverse is the correct reading, and how it was decided
	//
	// `exit.detour = entry` means exit reaches its OWN SERVER through entry. That is what putting a
	// dialer in `DetourDialer` means, and it is what the SOCKS client does with it:
	// `sing/protocol/socks/client.go:162` dials `c.serverAddr` through exactly that dialer, with the
	// user's TARGET travelling in the request rather than in the dial. So the device reaches ENTRY's
	// server first, EXIT's server second, and the destination last.
	//
	// This was NOT decided by reading the above. `common/dialer/detour_wire_order_test.go` observes the
	// real `NewDetour` plumbing and records which hop is entered first, for two hops and for three, so
	// the order comes from the dial path rather than from a comment. Its conclusion is that the hop
	// nearest this device is the DEEPEST DEPENDENCY - so `Hops[0]` is the reverse of the walk.
	//
	// The reversal is done here, once, at the single point where the walk's output becomes a Path.
	// Doing it inside the recursion would mean reversing at every level and getting it wrong somewhere;
	// doing it here means there is exactly one place where packet order is established.
	//
	// HONEST LIMIT: this ordering is derived from the DIAL EDGE each hop declares. It is exact for a
	// chain of forwarding proxies, which is what `detour` expresses. It does not model a hop that
	// carries traffic for a server other than the one its dependency names, and it cannot see a route
	// the configuration did not declare.
	reversePacketOrder(&path)
	return path, nil
}

// reversePacketOrder turns the walk's root-first descent into device-first packet order, and keeps
// every index that describes a position consistent with it.
//
// ControlPath is deliberately left in descent order; see the note inside. Only `Hops` is a physical
// list, and only a physical list has a packet order to correct.
func reversePacketOrder(path *Path) {
	for left, right := 0, len(path.Hops)-1; left < right; left, right = left+1, right-1 {
		path.Hops[left], path.Hops[right] = path.Hops[right], path.Hops[left]
	}
	for index := range path.Hops {
		path.Hops[index].Position = index
	}
	// ControlPath is deliberately NOT reversed.
	//
	// # Why the two lists do not move together
	//
	// They answer different questions and their natural orders are different:
	//
	//	ControlPath   WHO DECIDED, in the order the decisions were taken: the routing selects the
	//	              outer group, that group selects the inner one, which selects the leaf. There is
	//	              no physical direction in it at all - a group never carries a byte.
	//	Hops          WHERE THE BYTES GO, nearest this device first.
	//
	// Reversing ControlPath was applying a PHYSICAL correction to a CONTROL-plane list. The selection
	// sequence is root-to-leaf by definition, and packet order does not change who decided what.
	//
	// This is pinned by TestControlPathIsShorterThanThePhysicalPath, which builds a topology whose two
	// orders are provably different and asserts each list against its own rule. (`Path.GroupsNamed`
	// reads the same list for the same reason.)
	//
	// An Unknown's Position names the hop index it belongs at. The walk recorded it before the
	// reversal, so it is remapped through the same permutation rather than left describing a slot that
	// now holds a different hop. A negative Position means "not on the path" and is left alone.
	hopCount := len(path.Hops)
	for index := range path.Unknowns {
		position := path.Unknowns[index].Position
		if position < 0 || position >= hopCount {
			continue
		}
		path.Unknowns[index].Position = hopCount - 1 - position
	}
}

// walkScope is the state of ONE Build call: the network this call answers for, and the answer each
// group gave while this call was running.
//
// # Why this is not on the Resolver
//
// Both fields describe a walk, not a view. Putting them on the Resolver makes every Build a write to
// an object the caller is told is read-only, and two walks through one Resolver then write each
// other's answers: a walk asks a group with the other walk's network, and a decision record cleared
// by one walk answers a question that belongs to the other. That is a defect even with the accesses
// serialised - the value belongs to the wrong walk - so a lock would not fix it, it would only make
// it harder to see. A scope per call fixes it by construction: there is nothing to share.
//
// # And why the record is keyed by IDENTITY
//
// The decision record is keyed by the group OBJECT, not by its tag. A tag is configuration and two
// objects may share one (the package's cycle check says the same thing for the same reason), so a
// tag-keyed record would answer the second group from the first group's decision - reporting a
// member the second group cannot reach, or a cycle that does not exist.
type walkScope struct {
	resolver  *Resolver
	network   string
	decisions walkDecisions
}

// newWalkScope opens the state of one walk. The network named by the walk wins over the pinned one;
// neither is written anywhere. It returns a VALUE, so the scope stays on the caller's stack: a
// diagnostic that a control-plane read runs per flow must not allocate for its own bookkeeping.
func newWalkScope(resolver *Resolver, network string) walkScope {
	if network == "" {
		network = resolver.network
	}
	return walkScope{resolver: resolver, network: network}
}

// walkDecisions is the answer each group gave during ONE walk.
//
// # Why an array with an overflow map, and not a map
//
// A walk reaches one group per level of nesting - one for a selector, two or three for a real
// configuration - so the answers live in an array and only a graph deeper than it reaches the map. A
// map allocated per call would pay for every Build to hold a record that is read at most once, and
// the per-call record must not tempt anyone to move it back onto the Resolver to save an
// allocation. The record is a property of the CALL either way; see walkScope.
type walkDecisions struct {
	answered [8]walkAnswer
	count    int
	// overflow holds the answers of a graph deeper than the array. It is nil until one is needed.
	overflow map[adapter.OutboundGroup]string
}

// walkAnswer is one group's answer, with the group it belongs to as its identity key.
type walkAnswer struct {
	group    adapter.OutboundGroup
	selected string
}

// lookup returns the answer this group gave earlier in this walk, and whether it gave one.
//
// An empty answer that IS present means "this group answered no member", which the caller reports as
// an unknown rather than by asking again.
func (d *walkDecisions) lookup(group adapter.OutboundGroup) (string, bool) {
	for index := 0; index < d.count; index++ {
		if d.answered[index].group == group {
			return d.answered[index].selected, true
		}
	}
	if d.overflow == nil {
		return "", false
	}
	selected, present := d.overflow[group]
	return selected, present
}

// record stores one group's answer for the rest of this walk.
func (d *walkDecisions) record(group adapter.OutboundGroup, selected string) {
	for index := 0; index < d.count; index++ {
		if d.answered[index].group == group {
			d.answered[index].selected = selected
			return
		}
	}
	if d.count < len(d.answered) {
		d.answered[d.count] = walkAnswer{group: group, selected: selected}
		d.count++
		return
	}
	if d.overflow == nil {
		d.overflow = make(map[adapter.OutboundGroup]string, 8)
	}
	d.overflow[group] = selected
}

// walk visits one node of the selection graph.
//
// chain is the descent that reached this node, and it is simultaneously the cycle record: this
// mirrors route/route.go's resolveOutbound, which builds the same record for the same reason and
// deliberately has no separate depth limit.
func (s *walkScope) walk(path *Path, node adapter.Outbound, chain []adapter.Outbound, controlOwner string) error {
	if containsNode(chain, node) {
		return cycleObjectsError(chain, node)
	}
	group, isGroup := node.(adapter.OutboundGroup)
	if isGroup {
		// A group is a control-plane object. It is recorded in the CONTROL path and never as a
		// physical hop, because it never carries a byte.
		path.ControlPath = append(path.ControlPath, node.Tag())
		selected, reason := s.resolveSelection(group, node.Tag())
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
		return s.walk(path, selected, append(chain, node), node.Tag())
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
	// The dependency edge. The CONSUMER is recorded first, so this slice is in DESCENT order - the
	// order the configuration nests the hops in, ROOT first. It is NOT packet order, and it is not
	// reversed here: `Build` reverses the finished slice once, in `reversePacketOrder`, so there is
	// exactly one place where packet order is established.
	//
	// Reversing inside this recursion would be wrong, not just untidy: each level would flip its own
	// suffix and the result would depend on the depth.
	dependencyTag := firstDependency(node)
	if dependencyTag == "" {
		return nil
	}
	dependency, reason := s.resolver.lookupDependency(dependencyTag)
	if dependency == nil {
		path.Unknowns = append(path.Unknowns, Unknown{
			Node:     dependencyTag,
			Position: len(path.Hops),
			Reason:   reason,
		})
		return nil
	}
	return s.walk(path, dependency, append(chain, node), node.Tag())
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
//
// # The decision record is per walk, and keyed by identity
//
// The record lives in the walkScope, so it is created by this Build and read by no other: one walk
// asks a group once, and the answer cannot be another walk's. It is keyed by the group OBJECT
// because a tag is configuration and two objects may share one - a tag-keyed record would answer
// the second group from the first group's decision.
func (s *walkScope) resolveSelection(group adapter.OutboundGroup, tag string) (adapter.Outbound, string) {
	snapshot := s.resolver.snapshot
	if snapshot.Selections != nil {
		if declared, present := snapshot.Selections[tag]; present {
			if declared == "" {
				return nil, "the supplied snapshot states that the member selected by group " +
					tag + " is not knowable"
			}
			if s.resolver.lookup == nil {
				return nil, "no registry was supplied, so the snapshot's member " + declared +
					" of group " + tag + " cannot be resolved"
			}
			outbound, loaded := s.resolver.lookup(declared)
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
	if decided, present := s.decisions.lookup(group); present {
		if decided == "" {
			return nil, "group " + tag + " answered no selection earlier in this walk"
		}
		outbound, loaded := s.resolver.Lookup(decided)
		if !loaded {
			return nil, "group " + tag + " answered " + decided + " earlier in this walk, but that " +
				"outbound no longer resolves"
		}
		return outbound, ""
	}
	network := s.network
	if network == "" {
		network = NetworkTCP
	}
	selected := group.Selected(network)
	if selected == nil {
		s.decisions.record(group, "")
		return nil, "group " + tag + " has no selected member for " + network
	}
	s.decisions.record(group, selected.Tag())
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
