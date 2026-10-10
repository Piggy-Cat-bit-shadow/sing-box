// Package physicalpath's read-only STATUS view: a per-hop report of what the model knows about each
// hop of a path, built on top of the PhysicalPath / ControlPath model and on nothing else.
//
// # What this is, and what it is deliberately not
//
// It is NOT a second outbound manager, a health checker, or a probe. It starts no goroutine, arms no
// timer, opens no socket, resolves nothing, and takes no lock owned by anything else in this tree.
// Every fact in a PathStatus is READ from something that already exists:
//
//	state            an adapter.Lifecycle owner that chooses to report it (HopStateReporter)
//	error            an error the owner has ALREADY observed (HopErrorReporter)
//	generations      two counters the owner already keeps (HopGenerationReporter)
//	mtu              the two capabilities a lower tunnel already publishes (PortMTUProvider and, for a
//	                 transport that encapsulates inside its own packets, PortEncapOverheadProvider)
//	order, tags      the PhysicalPath model, through Entry(), Exit() and Hop.Position
//
// # The one rule that matters most
//
// A hop that reports nothing is reported as UNKNOWN, with a reason. "The object was constructed" is
// NEVER presented as "the peer is reachable": those are different facts, and the second one is not
// observable from here at all. A diagnostic that conflated them would tell an operator a dead node is
// fine, which is worse than saying nothing.
//
// # Read-only, in the strong sense
//
// Nothing in this file may call a method that dials, resolves, starts, stops, or commits anything. The
// only methods it calls on a hop are the ones declared by the optional interfaces below, and every one
// of them is specified as a read of state the owner already holds. A test asserts the negative: no
// method this file calls may be one that mutates the model.
package physicalpath

import (
	"strings"
	"sync"
	"unicode"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// StatusReadiness is what the STATUS view established about one hop, and it is a DIFFERENT axis from the
// lifecycle State below.
//
// The separation is the point. A node can be perfectly constructed, started and free of errors, and this
// view still knows nothing about whether its peer answers - so it reports UNKNOWN readiness rather than
// implying health. Only a hop that publishes evidence of its own can move readiness above UNKNOWN.
type StatusReadiness uint8

const (
	// ReadinessUnknown means nothing about this hop's ability to carry traffic has been established.
	// It is the zero value, so a hop that forgets to report anything gets the honest answer rather
	// than an accidental "healthy".
	ReadinessUnknown StatusReadiness = iota
	// ReadinessConstructed means the object exists and reports itself as built, with no failure
	// recorded. It says NOTHING about the peer.
	ReadinessConstructed
	// ReadinessStarting means the object reports itself as coming up.
	ReadinessStarting
	// ReadinessReady means the object reports evidence that it can carry traffic.
	ReadinessReady
	// ReadinessDegraded means the object reports that it is up but something is wrong.
	ReadinessDegraded
	// ReadinessClosing means teardown has begun and the hop must not be used.
	ReadinessClosing
	// ReadinessClosed means teardown finished.
	ReadinessClosed
	// ReadinessFailed means the object recorded an error. It is not a lifecycle state: an object can be
	// started and still have a recorded failure.
	ReadinessFailed
)

func (r StatusReadiness) String() string {
	switch r {
	case ReadinessConstructed:
		return "constructed"
	case ReadinessStarting:
		return "starting"
	case ReadinessReady:
		return "ready"
	case ReadinessDegraded:
		return "degraded"
	case ReadinessClosing:
		return "closing"
	case ReadinessClosed:
		return "closed"
	case ReadinessFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// LifecycleState is the state a hop owner reports about ITSELF.
//
// It mirrors the vocabulary a lifecycle has (constructed, starting, ready, degraded, closing, closed)
// and is deliberately NOT the same type as StatusReadiness: this is what the owner claims, that is what
// the view was able to establish. A hop that claims Ready and also reports an error is reported as
// FAILED, because a recorded failure is evidence and a self-declared state is a claim.
type LifecycleState uint8

const (
	// LifecycleStateUnknown is the zero value: the owner did not report a state.
	LifecycleStateUnknown LifecycleState = iota
	LifecycleStateConstructed
	LifecycleStateStarting
	LifecycleStateReady
	LifecycleStateDegraded
	LifecycleStateClosing
	LifecycleStateClosed
)

func (s LifecycleState) String() string {
	switch s {
	case LifecycleStateConstructed:
		return "constructed"
	case LifecycleStateStarting:
		return "starting"
	case LifecycleStateReady:
		return "ready"
	case LifecycleStateDegraded:
		return "degraded"
	case LifecycleStateClosing:
		return "closing"
	case LifecycleStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// FailurePhase names WHERE in a hop's own pipeline a failure happened.
//
// # Why a phase and not just an error
//
// "node DNS" and "tunnel" are different problems with different remedies, and an operator reading a log
// line needs to know which one they have. A bare "connection failed" is what this replaces.
//
// # The order is the PATH order, not the phase order
//
// A failure at hop #2 of 3 is reported with its hop index, so the remedy follows the path: everything
// before the failing hop works, everything after it was never reached.
type FailurePhase uint8

const (
	// PhaseUnattributed means the hop reported an error without saying where in its pipeline it
	// happened. It is the honest default: inventing a phase would point the operator at the wrong
	// layer.
	PhaseUnattributed FailurePhase = iota
	// PhaseNodeDNS is resolving the PROXY NODE's own address, which happens before any tunnel exists.
	PhaseNodeDNS
	// PhaseTargetDNS is resolving the DESTINATION inside or through the tunnel.
	PhaseTargetDNS
	// PhaseConnect is establishing the transport to the node.
	PhaseConnect
	// PhaseTLS is the TLS handshake with the node.
	PhaseTLS
	// PhaseQUIC is the QUIC handshake, which is a separate step from TLS inside it.
	PhaseQUIC
	// PhaseTunnel is bringing a tunnel device or session up.
	PhaseTunnel
	// PhasePayloadMTU is a packet or datagram that did not fit its path.
	PhasePayloadMTU
)

func (p FailurePhase) String() string {
	switch p {
	case PhaseNodeDNS:
		return "node DNS"
	case PhaseTargetDNS:
		return "target DNS"
	case PhaseConnect:
		return "connect"
	case PhaseTLS:
		return "TLS"
	case PhaseQUIC:
		return "QUIC"
	case PhaseTunnel:
		return "tunnel"
	case PhasePayloadMTU:
		return "payload MTU"
	default:
		return "unattributed"
	}
}

// HopStatusReporter lets a hop owner publish the state it already keeps.
//
// # Why it is optional, and why that is the design
//
// A hop that does not implement it is reported UNKNOWN with a reason, which is the truthful answer for
// every object in this tree that does not track its own lifecycle: the outbound adapters, the group
// members, the dialers. Making it required would force every one of them to grow state it does not need
// and could not keep honestly.
type HopStatusReporter interface {
	// StatusState reports the lifecycle state the owner is in. LifecycleStateUnknown is the honest
	// answer when the owner does not track one.
	StatusState() LifecycleState
}

// HopErrorReporter lets a hop owner publish an error it has ALREADY observed.
//
// # What the error must and must not contain
//
// It must be an error the owner already produced - this interface is a read, not a probe, and an
// implementation that dials to answer it would make the whole view a health check by the back door.
//
// It must NOT contain credentials, tokens, certificates or user request contents. The view redacts what
// it can recognise (see redactDetail), but redaction is a backstop rather than a licence: an
// implementation that hands over a resolved URL with userinfo has already leaked it into a log line.
type HopErrorReporter interface {
	// StatusLastError returns the last error this hop observed, whether it has since recovered, and the
	// phase it happened in. A nil error means none is recorded.
	StatusLastError() (err error, phase FailurePhase, recovered bool)
}

// HopGenerationReporter lets a hop owner publish the generation its current state belongs to.
//
// # The problem it solves
//
// A hop that is closed and re-started is a NEW generation: the old peer is gone, and its error is
// history rather than a description of the current hop. A view that mixed them would report a failure
// for a hop that has since been rebuilt, which is exactly the kind of lie a diagnostic must not tell.
//
// # The contract
//
// Both counters are the owner's own. They must be MONOTONIC and they must change when the resources they
// describe are replaced. A reporter that returns the same pair across a Close and a re-Start is telling
// the view the two generations are the same hop, and the view will believe it.
type HopGenerationReporter interface {
	// StatusNetworkGeneration reports the network generation the current state belongs to.
	StatusNetworkGeneration() uint64
	// StatusResourceGeneration reports the resource generation the current state belongs to.
	StatusResourceGeneration() uint64
}

// PortMTUProvider is the fixed inner IP capacity a lower tunnel publishes.
//
// It is declared here rather than imported from common/dialer so this package keeps its minimal import
// set, and it is structurally identical to that one: an endpoint implementing either satisfies both.
type PortMTUProvider interface {
	PortMTU() uint32
}

// PortEncapOverheadProvider is the framing a transport adds inside its own inner IP packets.
//
// Only a transport that encapsulates inside the packet it carries implements it - WireGuard is the case
// in this tree - and it is what makes the difference between "what enters this tunnel" and "what may
// travel through it".
type PortEncapOverheadProvider interface {
	PortEncapOverhead() uint32
}

// MTUStatus is every capacity number that can be established about one hop, each with whether it is
// actually known.
//
// # The five numbers, and why they are not interchangeable
//
//	InnerIP         the inner IP MTU: what enters this hop
//	InnerUDPIPv4    InnerIP - 20 - 8: the UDP payload that fits inside it over IPv4
//	InnerUDPIPv6    InnerIP - 40 - 8: the same over IPv6
//	OuterQUICInitial the packet this hop's OWN connection sends over the underlay, when it has one
//	Encapsulated    what this hop adds INSIDE InnerIP before the packet leaves it
//
// A hop with a fixed capacity answers the first four (the fourth not applicable); a hop with none
// answers none of them and says why. The third and fourth are the numbers a protocol STACKED on this hop
// needs, and they are derived here rather than by the caller so two callers cannot disagree.
type MTUStatus struct {
	InnerIP          uint32
	InnerUDPIPv4     uint32
	InnerUDPIPv6     uint32
	OuterQUICInitial uint32
	// Encapsulated is the transport framing the hop adds inside InnerIP, or 0 when it declares none.
	Encapsulated uint32
	// Known reports whether InnerIP was actually established.
	Known bool
	// OuterKnown reports whether OuterQUICInitial was established. It is separate from Known because a
	// hop can have a fixed inner capacity and no outer QUIC connection at all.
	OuterKnown bool
	// Reason says why a number is not known, or names the limitation of the ones that are.
	Reason string
}

// HopStatus is one hop of the path, as this view was able to establish it.
type HopStatus struct {
	// Position is the packet-order index, taken from the model and never recomputed here.
	Position int
	// Tag is the hop's declared tag, and LeafTag the concrete member when a group selected it.
	Tag      string
	LeafTag  string
	Type     string
	Endpoint bool
	// SelectedBy is the control-plane group that chose this hop, when one did.
	SelectedBy string

	// Readiness is what this view established.
	Readiness StatusReadiness
	// ClaimedState is what the hop owner reports about itself, which may be Unknown.
	ClaimedState LifecycleState

	// LastError is the redacted, phase-attributed failure the hop already observed, or empty.
	LastError string
	// LastErrorPhase is where in the hop's pipeline it happened.
	LastErrorPhase FailurePhase
	// LastErrorRecovered is true when the hop has since come back up.
	LastErrorRecovered bool
	// LastErrorGeneration is the generation the failure belonged to. It is compared with the hop's
	// current generations, and a failure from an older one is not shown as current.
	LastErrorGeneration Generation
	// Generations are the hop's current counters.
	Generations Generation

	// MTU is the capacity of this hop.
	MTU MTUStatus

	// Reason says why the readiness is UNKNOWN, when it is.
	Reason string
}

// Generation is a pair of counters identifying one incarnation of a hop's resources.
//
// It is a value rather than two loose fields so a stale error can be recognised by comparing one thing
// with one thing, which is the operation that has to be right.
type Generation struct {
	Network  uint64
	Resource uint64
}

// Current reports whether a failure recorded at this generation still describes the hop.
func (g Generation) Current(other Generation) bool {
	return g == other
}

// ControlNode is one node of the CONTROL path: a group, the decision it published, and whether that
// decision has been committed.
//
// # Why "committed" is here and why it is three-valued
//
// A group's `Selected` is a PREVIEW for every group in this tree: reading it consumes nothing and
// commits nothing. A view that reported a preview as the flow's actual path would describe a route the
// traffic may not take. So the identity is reported only when the group PUBLISHES it (adapter.Referrer
// is exactly that publication), and the commit status says which of the three cases it is: published and
// committed, published but a per-flow choice, or nothing published at all.
type ControlNode struct {
	Tag string
	// Decision is the member tag the group published as its selection, or empty.
	Decision string
	// Committed reports whether the decision is the group's committed choice rather than a per-flow or
	// per-preview answer.
	Committed bool
	// Reason says why a decision is not available, when it is not.
	Reason string
}

// HopFailure names the ONE hop that failed, and where along the path it sits.
//
// # Why it is not called Failure
//
// dryrun.go already exports a `Failure` for the START-TIME validation report, and the two describe
// different things: that one is a configuration that cannot work, this one is a hop that did not work at
// run time. Two types with one name would be a trap for a reader, so this one is named for what it is.
//
// # Why the path order is part of it
//
// "hop 2 of 4, reached after hop 1 and before hops 3 and 4" is the difference between a one-line fix and
// an afternoon: everything before the failing hop works, and everything after it was never tried. The
// fields carry both directions so a reader does not have to reconstruct them.
type HopFailure struct {
	// Hop is the failing hop's tag - the thing an operator greps their configuration for.
	Hop string
	// Position is its packet-order index, and HopCount is how many hops the path has.
	Position int
	HopCount int
	// Phase is where in that hop's pipeline it failed.
	Phase FailurePhase
	// Reached lists the tags BEFORE it, in packet order, which are therefore known to have been entered.
	Reached []string
	// Unreached lists the tags AFTER it, which were never tried.
	Unreached []string
	// Detail is the redacted error text.
	Detail string
	// Recovered reports whether the hop has since come back up.
	Recovered bool
}

// PathStatus is one consistent read of a path's status.
//
// It is a VALUE: every field is a copy, so a caller cannot mutate the model through it and two readers
// cannot observe each other. Nothing in it is recomputed on access.
type PathStatus struct {
	// Root is the outbound tag the walk started from.
	Root string
	// Network is the network the walk answered for, e.g. "tcp".
	Network string
	// ControlPath is the CONTROL chain in packet order, as the model reports it.
	ControlPath []string
	// Controls is the same chain with each group's published decision.
	Controls []ControlNode
	// Hops is the physical path in PACKET ORDER: Hops[0] is nearest this device.
	Hops []HopStatus
	// Exit is the last hop - where the traffic leaves - or empty when the path has no hops or is
	// partly unknown.
	Exit string
	// Entry is the first hop - nearest this device - or empty under the same condition.
	Entry string
	// HopFailure names the failing hop, when one hop reports a failure.
	Failure *HopFailure
	// Unknowns is every question this view could not answer, with the reason. A PathStatus with an
	// unknown is NOT a verified path.
	Unknowns []Unknown
}

// HasUnknown reports whether anything in this PathStatus could not be determined.
func (s PathStatus) HasUnknown() bool {
	return len(s.Unknowns) > 0
}

// Ready reports whether every hop of this path reports evidence that it can carry traffic.
//
// # What true means, and what it does not
//
// It means every hop published a READY state of its own. It does NOT mean the path was tested end to
// end: no hop here proves the NEXT hop's peer answers. A PathStatus with a missing state reports false,
// because "not established" is not ready.
func (s PathStatus) Ready() bool {
	if len(s.Hops) == 0 || s.HasUnknown() || s.Failure != nil {
		return false
	}
	for _, hop := range s.Hops {
		if hop.Readiness != ReadinessReady {
			return false
		}
	}
	return true
}

// StatusView reads the status of paths, and it is the only stateful thing in this file.
//
// # The receiver contract: a nil *StatusView is a legal value
//
// `NewStatusView` returns a `*StatusView`, and a `*StatusView` that is nil is a value this type
// accepts: a field nobody assigned, a box that did not build one, or a typed nil stored in an
// interface. Every method below is safe on it. `SnapshotStatus` answers UNKNOWN with a reason,
// `Connected` reports false and `Disconnect` does nothing, because there is no object graph behind an
// absent view and reporting one would be exactly the lie this file exists to prevent.
//
// It is stated as a contract rather than defended by a check because the check on its own is worse
// than nothing:
//
//	if v != nil && !v.Connected() { ... }
//	v.walk.Lock()          // reached even when v == nil
//
// reads to every later reader as "nil is handled" and then dereferences nil one line further down.
// The reason must also never be a silent empty PathStatus: an empty one has no unknowns and no hops,
// which reads as "a path was walked and nothing was wrong with it".
//
// # The one lock, and what it is deliberately NOT
//
// `access` guards ONE bool: whether this view has been disconnected. It is held for the two
// instructions that read or write that bool and for nothing else, so it is never held across a call
// into a hop.
//
// There is deliberately NO lock around the walk. There was one, and it was a historic artefact: it
// was added while `Resolver` kept the per-walk state - the decision record and the network pin - on
// the Resolver itself, so one Resolver answering two concurrent walks tore. That state now lives in
// the `walkScope` `Build` creates and drops, and `Build` writes nothing the caller can see. The lock
// therefore protected nothing that this package owns; what it did do was serialise snapshots that
// share no writable state, and hold a `sync.Mutex` across calls into outbound adapters this package
// does not control.
//
// That last part was not a cost, it was a defect. `SnapshotStatus` calls `StatusState`,
// `StatusLastError`, `StatusNetworkGeneration`, `StatusResourceGeneration` and `PortMTU` on objects
// supplied from outside this package, and nothing in an interface stops one of them from calling back
// into the view that is reading it - an adapter that also reports its own path is the obvious case.
// `sync.Mutex` is not reentrant, so a lock held across those calls is a self-deadlock waiting for a
// legal implementation. `TestAReentrantReporterDoesNotDeadlockTheView` is that experiment, and
// `TestOneViewsSnapshotsDoNotSerialiseBehindEachOther` is the measurement that the lock was doing no
// work worth that risk.
//
// # Re-entrancy
//
// SnapshotStatus may be called from any goroutine, and - since the walk lock was removed - it may
// also be called from inside a hop's reporter implementation. Such a call performs its own walk; the
// state a walk needs belongs to the call, so the inner one neither sees nor disturbs the outer one.
//
// # Disconnect, and what a concurrent snapshot is allowed to answer
//
// The rule, stated once, because "Disconnect raced a snapshot" has to have one answer:
//
//  1. Disconnect publishes the disconnected generation and returns. It NEVER waits for a snapshot
//     that is in flight: a snapshot's reporter may be slow, blocked on its own I/O, or wedged, and
//     Disconnect runs on the teardown path where blocking is not recoverable.
//  2. A snapshot reads the generation BEFORE it observes anything, and reads it AGAIN after it has
//     finished observing. Both reads must find the view connected for the observed path to be
//     published.
//  3. Therefore a call that STARTS after `Disconnect` returned reports disconnected, and a call
//     whose OBSERVATION straddled the teardown is discarded rather than presented as the current
//     path.
//
// The second read is the half a pre-check alone cannot provide. A walk that began before the teardown
// and finished after it has read some hops from the live graph and some from a graph being
// dismantled; publishing that mixture is precisely the "state of a dead object graph presented as
// current" that Disconnect exists to make unrepresentable. Discarding costs one diagnostic read and
// says something true.
//
// A PathStatus a caller already holds is unaffected: it is a value, and a later teardown cannot
// rewrite it.
type StatusView struct {
	access sync.Mutex
	// disconnected is set by Disconnect. It exists so a view that was detached from a closed box reports
	// that fact rather than reporting the last state it saw, which would be a PathStatus of a dead object
	// graph presented as current.
	disconnected bool
}

// NewStatusView builds a view. It allocates a mutex and nothing else: no goroutine, no timer, no
// registry registration.
//
// A caller that never calls it still has a usable view: see the receiver contract on StatusView.
func NewStatusView() *StatusView {
	return &StatusView{}
}

// Disconnect detaches the view and releases what it holds.
//
// # Why a diagnostic needs a Close at all
//
// The view holds no resources, so this is not about leaking. It is about the ANSWER: after the box that
// owned the path is gone, the last PathStatus describes objects that have been torn down, and a caller
// that kept reading would report a closed tunnel as the current state. Disconnect makes that
// unrepresentable - the next PathStatus answers "this view is disconnected", which is true.
//
// It is safe to call more than once, from any goroutine, and on a nil receiver, which it treats as
// already disconnected.
//
// # It does not wait for anything
//
// This call publishes one bool and returns. It does NOT wait for snapshots that are in flight, and it
// must never be changed to: a snapshot may be inside a reporter that is slow or wedged, and Disconnect
// runs on the teardown path. The linearisation rule in the StatusView comment is what makes not
// waiting correct - the in-flight snapshot discards its own observation when it finishes.
func (v *StatusView) Disconnect() {
	if v == nil {
		return
	}
	v.access.Lock()
	defer v.access.Unlock()
	v.disconnected = true
}

// Connected reports whether the view is still attached to a live object graph.
//
// A nil receiver reports false: it is attached to nothing, and true would be a claim it cannot support.
func (v *StatusView) Connected() bool {
	if v == nil {
		return false
	}
	v.access.Lock()
	defer v.access.Unlock()
	return !v.disconnected
}

// absentStatus is the answer a view that does not exist returns.
//
// It is an UNKNOWN and not an empty PathStatus on purpose. An empty PathStatus has no unknowns and no
// hops, so it reads as "a path was walked and nothing was wrong with it"; nothing was walked, and a
// caller must be told that rather than handed a clean-looking blank.
func absentStatus(root TagOrOutbound, options Options) PathStatus {
	return PathStatus{
		Root:    root.Tag,
		Network: options.Network,
		Unknowns: []Unknown{{
			Node:     root.Tag,
			Position: -1,
			Reason: "there is no status view here: the receiver is nil, so no object graph was read and " +
				"no path can be reported; this is an absent answer and not a path that was found healthy",
		}},
	}
}

// disconnectedStatus is the answer a view that has been detached from its object graph returns.
func disconnectedStatus(root TagOrOutbound, options Options) PathStatus {
	return PathStatus{
		Root:    root.Tag,
		Network: options.Network,
		Unknowns: []Unknown{{
			Node:     root.Tag,
			Position: -1,
			Reason: "the status view has been disconnected from the object graph it described, so it can " +
				"no longer report current state",
		}},
	}
}

// SnapshotStatus reads the status of one path.
//
// resolver must be the same read-only Resolver the model uses; the walk it performs is Build's, so this
// view and the model cannot disagree about the ORDER, the TAGS or the UNKNOWNS of a path. Nothing here
// re-derives an index: Hops[0] is nearest this device because the model says so, and Entry()/Exit()
// name the two ends.
//
// The two generation reads and the rule they implement are stated on the StatusView type. In short: the
// view is read before anything is observed and again after, and an observation that straddled a
// teardown is discarded. Neither read is taken while anything else is locked, so a snapshot never holds
// a lock across a call into a hop and a reporter may call back in.
func (v *StatusView) SnapshotStatus(resolver *Resolver, root TagOrOutbound, options Options) PathStatus {
	if v == nil {
		// The receiver contract: an absent view answers UNKNOWN. See absentStatus for why it is not
		// simply an empty answer.
		return absentStatus(root, options)
	}

	// The generation read on the way IN. It is this snapshot's linearisation point with respect to a
	// teardown that has already happened, and it is also what keeps the walk off an object graph that
	// may have been dismantled.
	if !v.Connected() {
		return disconnectedStatus(root, options)
	}

	path, err := Build(resolver, root, options)
	if err != nil {
		return PathStatus{
			Root:    root.Tag,
			Network: options.Network,
			Unknowns: []Unknown{{
				Node:     root.Tag,
				Position: -1,
				Reason:   "the path could not be walked: " + redactDetail(err.Error()),
			}},
		}
	}

	status := PathStatus{
		Root:        path.Root,
		Network:     options.Network,
		ControlPath: append([]string(nil), path.ControlPath...),
		Unknowns:    append([]Unknown(nil), path.Unknowns...),
	}
	for _, tag := range path.ControlPath {
		status.Controls = append(status.Controls, controlNode(resolver, tag))
	}
	for _, hop := range path.Hops {
		status.Hops = append(status.Hops, resolver.hopStatus(resolver.Lookup, hop))
	}
	if entry, ok := path.Entry(); ok {
		status.Entry = entry.DeclaredTag
	}
	if exit, ok := path.Exit(); ok {
		status.Exit = exit.DeclaredTag
	}
	status.Failure = firstFailure(status.Hops)

	// The generation read on the way OUT. Everything above observed the object graph, and an
	// observation that stretched across a teardown may be half live and half dismantled - the hops
	// before the teardown read from one graph and the hops after it from another. Such an answer is
	// discarded rather than published as current. See the StatusView comment for the full rule.
	if !v.Connected() {
		return disconnectedStatus(root, options)
	}
	return status
}

// controlNode reads one group's published decision without consuming a selection.
//
// It uses the model's own lookup, so a decision that names a member which no longer resolves is reported
// as a reason rather than silently dropped.
//
// The read is contained: see recoverValue for the panic policy.
func controlNode(resolver *Resolver, tag string) ControlNode {
	var node ControlNode
	if panicked, didPanic := recoverValue(func() { node = readControlNode(resolver, tag) }); didPanic {
		return ControlNode{
			Tag: tag,
			Reason: "reading this control node panicked, so no decision can be reported for it (" +
				panicDetail(panicked) + ")",
		}
	}
	return node
}

// readControlNode is controlNode's body, with the containment lifted out of the way of the logic.
func readControlNode(resolver *Resolver, tag string) ControlNode {
	node := ControlNode{Tag: tag}
	outbound, loaded := resolver.Lookup(tag)
	if !loaded {
		node.Reason = "the control node no longer resolves in the registry"
		return node
	}
	group, isGroup := outbound.(adapter.OutboundGroup)
	if !isGroup {
		// The control path can name the root, which is not necessarily a group. That is not a problem
		// and must not be reported as one.
		return node
	}
	referrer, isReferrer := group.(adapter.Referrer)
	if !isReferrer {
		node.Reason = "this group does not publish a selection, which is what a per-flow choice looks like from here"
		return node
	}
	references := referrer.References()
	switch len(references) {
	case 0:
		node.Reason = "the group publishes no member, so no decision is available"
	case 1:
		node.Decision = references[0]
		node.Committed = true
	default:
		// More than one reference is a per-flow group: several members are live at once and which one a
		// given flow takes is not knowable from here. Reporting one of them would be picking.
		node.Reason = "the group publishes more than one member, so its choice is per flow and no single decision describes this path"
	}
	return node
}

// hopStatus reads one hop. It calls only methods that are reads of state the owner already holds.
//
// # Panics are contained, and the answer is UNKNOWN
//
// The methods it calls belong to an object this package does not own, and an adapter's status method is
// exactly the kind of code that can panic - a nil map, a closed channel, a half-initialised field after
// a failed start. A read-only diagnostic that takes down its caller is worse than one that reports it,
// so the panic is contained; and a hop whose state could not be read is UNKNOWN, never READY, and never
// a silent blank. A hop that claimed READY a microsecond before it panicked has not been read, and its
// claim is not evidence.
//
// This is the same containment `Build` applies to a malformed graph, for the same reason.
func (r *Resolver) hopStatus(lookup func(tag string) (adapter.Outbound, bool), hop Hop) HopStatus {
	status := HopStatus{
		Position:   hop.Position,
		Tag:        hop.DeclaredTag,
		LeafTag:    hop.ResolvedLeafTag,
		Type:       hop.Type,
		Endpoint:   hop.IsEndpoint,
		SelectedBy: hop.ControlOwner,
	}
	if hop.IsGroup {
		// The model never emits this, and if it ever did the view must not present it as a hop.
		status.Readiness = ReadinessUnknown
		status.Reason = "the model reported a control group at a hop position, which is not a physical hop"
		return status
	}

	// The object the traffic actually reaches: the resolved leaf when a group selected one, otherwise
	// the declared tag. `lookup` is the registry read the dial path itself uses.
	tag := hop.DeclaredTag
	if hop.ResolvedLeafTag != "" {
		tag = hop.ResolvedLeafTag
	}
	object, loaded := lookup(tag)
	if !loaded || object == nil {
		status.Readiness = ReadinessUnknown
		status.Reason = "the hop does not resolve in the registry, so nothing can be read about it"
		return status
	}

	if panicked, didPanic := recoverValue(func() {
		readHopState(&status, object)
		readHopMTU(&status, object)
	}); didPanic {
		// The half-read fields are dropped with the rest: a claim, or an error, that was read before the
		// panic is not a complete reading of the hop, and reporting it next to "panicked" would invite
		// exactly the "it said ready" conclusion the policy forbids.
		return HopStatus{
			Position:   hop.Position,
			Tag:        hop.DeclaredTag,
			LeafTag:    hop.ResolvedLeafTag,
			Type:       hop.Type,
			Endpoint:   hop.IsEndpoint,
			SelectedBy: hop.ControlOwner,
			Readiness:  ReadinessUnknown,
			Reason: "this hop panicked while it was being read, so nothing about its state was " +
				"established (" + panicDetail(panicked) + ")",
		}
	}
	return status
}

// recoverValue runs one read of code this package does not own and reports what it panicked with.
//
// It is the panic policy of this file, stated once: a reporter is an interface implementation supplied
// from outside, a diagnostic must not take down the caller that asked it a question, and it must not
// turn a failure into a healthy answer either. So a panic is CONTAINED and REPORTED - the caller gets an
// UNKNOWN whose reason names what happened - rather than propagated or swallowed.
//
// The panic value is returned raw and rendered by panicDetail OUTSIDE this deferred frame, so a value
// whose own String method misbehaves fails loudly instead of inside a recover where it would be lost.
func recoverValue(read func()) (panicked any, didPanic bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = recovered
			didPanic = true
		}
	}()
	read()
	return nil, false
}

// panicDetail renders a recovered panic value as one redacted line.
//
// Redaction is not optional here: a panic value is arbitrary text chosen by the code that panicked, and
// the moment a component panics is the moment it is most likely to be quoting what it was doing - a
// URL, a header, a key. A containment field that is not redacted turns containment into a new leak.
func panicDetail(panicked any) string {
	return redactDetail(E.New("", panicked).Error())
}

// readHopState fills the lifecycle and error fields from the optional reporters.
func readHopState(status *HopStatus, object adapter.Outbound) {
	// Claimed state first: it is the owner's own answer and the view reports it as a CLAIM.
	if reporter, isReporter := object.(HopStatusReporter); isReporter {
		status.ClaimedState = reporter.StatusState()
	}

	// Generations, when the owner keeps them. They are read BEFORE the error so an error recorded
	// between the two reads cannot be attributed to a generation that has already moved on.
	if reporter, isReporter := object.(HopGenerationReporter); isReporter {
		status.Generations = Generation{
			Network:  reporter.StatusNetworkGeneration(),
			Resource: reporter.StatusResourceGeneration(),
		}
	}

	if reporter, isReporter := object.(HopErrorReporter); isReporter {
		lastErr, phase, recovered := reporter.StatusLastError()
		if lastErr != nil {
			status.LastError = redactDetail(lastErr.Error())
			status.LastErrorPhase = phase
			status.LastErrorRecovered = recovered
			status.LastErrorGeneration = status.Generations
		}
	}

	// The mapping from claim to readiness, stated once.
	switch {
	case status.LastError != "" && !status.LastErrorRecovered:
		status.Readiness = ReadinessFailed
	case status.ClaimedState == LifecycleStateReady:
		status.Readiness = ReadinessReady
	case status.ClaimedState == LifecycleStateDegraded:
		status.Readiness = ReadinessDegraded
	case status.ClaimedState == LifecycleStateStarting:
		status.Readiness = ReadinessStarting
	case status.ClaimedState == LifecycleStateClosing:
		status.Readiness = ReadinessClosing
	case status.ClaimedState == LifecycleStateClosed:
		status.Readiness = ReadinessClosed
	case status.ClaimedState == LifecycleStateConstructed:
		// A CONSTRUCTED object is reported as constructed and NOT as ready. This is the single most
		// important line in the file: it is the difference between "the object exists" and "the peer
		// answers", and only the first is knowable here.
		status.Readiness = ReadinessConstructed
	default:
		status.Readiness = ReadinessUnknown
		status.Reason = "the hop does not report a lifecycle state, so its readiness is unknown; a " +
			"successfully constructed object is not evidence that its peer is reachable"
	}

	if status.LastError != "" && !status.LastErrorRecovered && status.ClaimedState == LifecycleStateReady {
		status.Reason = "the hop claims to be ready and also reports an unrecovered failure; the " +
			"failure is reported because it is evidence and the claim is not"
	}
}

// readHopMTU fills the capacity fields from the two capabilities a lower tunnel can publish.
func readHopMTU(status *HopStatus, object adapter.Outbound) {
	provider, isProvider := object.(PortMTUProvider)
	if !isProvider {
		status.MTU.Reason = "the hop publishes no fixed inner capacity, so no MTU can be proven for it " +
			"(a hop whose capacity is discovered at run time, or one that does not terminate a tunnel)"
		return
	}
	innerMTU := provider.PortMTU()
	if innerMTU == 0 {
		status.MTU.Reason = "the hop reports a zero inner MTU, which is a refusal to state a capacity " +
			"rather than a capacity of zero bytes"
		return
	}

	status.MTU.Known = true
	status.MTU.InnerIP = innerMTU

	var encapsulated uint32
	if overheadProvider, isOverheadProvider := object.(PortEncapOverheadProvider); isOverheadProvider {
		encapsulated = overheadProvider.PortEncapOverhead()
	}
	status.MTU.Encapsulated = encapsulated

	// The two UDP budgets. They are derived from the SAME arithmetic the rest of this fork uses, and
	// they include the transport's own framing when it declares one, because that framing sits INSIDE
	// the inner IP packet and therefore comes off the same budget.
	const ipv4HeaderPlusUDP = 20 + 8
	const ipv6HeaderPlusUDP = 40 + 8
	if innerMTU > ipv4HeaderPlusUDP+encapsulated {
		status.MTU.InnerUDPIPv4 = innerMTU - ipv4HeaderPlusUDP - encapsulated
	}
	if innerMTU > ipv6HeaderPlusUDP+encapsulated {
		status.MTU.InnerUDPIPv6 = innerMTU - ipv6HeaderPlusUDP - encapsulated
	}

	// The outer QUIC packet this hop sends over the underlay, when it terminates a QUIC connection of
	// its own. It is read from the same capability set: a hop that does not publish it simply does not
	// have one, and saying so is better than deriving a number nothing asked for.
	if outerProvider, isOuterProvider := object.(OuterQUICInitialProvider); isOuterProvider {
		outer := outerProvider.OuterQUICInitialPacketSize()
		if outer > 0 {
			status.MTU.OuterQUICInitial = uint32(outer)
			status.MTU.OuterKnown = true
		}
	}

	// The limitation, stated whenever the numbers are not the whole story.
	switch {
	case encapsulated > 0:
		status.MTU.Reason = "the two UDP budgets already subtract this transport's own framing (" +
			itoa(int(encapsulated)) + " bytes) because it sits inside the inner IP packet"
	case status.MTU.OuterKnown:
		status.MTU.Reason = "the outer QUIC initial packet size is this hop's OWN connection to its " +
			"server, not an inner capacity, and it is bounded by the underlay rather than by this hop"
	default:
		status.MTU.Reason = "this hop publishes no outer QUIC packet size"
	}
}

// OuterQUICInitialProvider is implemented by a hop that terminates a QUIC connection of its own over the
// underlay and can state the packet size it uses for it.
//
// It is separate from PortMTUProvider because the two are different numbers in different layers: a
// MASQUE client publishes both an inner capacity and the size of the packet it brings its own connection
// up with, and conflating them is exactly the error the interface exists to make unrepresentable.
type OuterQUICInitialProvider interface {
	OuterQUICInitialPacketSize() int
}

// firstFailure picks the failing hop, and it picks the FIRST one in packet order.
//
// # Why the first, and not the worst
//
// Packet order is causal order: a packet reaches hop 0 before hop 1, so if hop 0 failed, nothing after it
// was ever tried. Reporting a later hop's stale error instead would name a symptom as the cause.
func firstFailure(hops []HopStatus) *HopFailure {
	for index, hop := range hops {
		if hop.Readiness != ReadinessFailed {
			continue
		}
		failure := &HopFailure{
			Hop:       hop.Tag,
			Position:  hop.Position,
			HopCount:  len(hops),
			Phase:     hop.LastErrorPhase,
			Detail:    hop.LastError,
			Recovered: hop.LastErrorRecovered,
		}
		for earlier := 0; earlier < index; earlier++ {
			failure.Reached = append(failure.Reached, hops[earlier].Tag)
		}
		for later := index + 1; later < len(hops); later++ {
			failure.Unreached = append(failure.Unreached, hops[later].Tag)
		}
		return failure
	}
	return nil
}

// String renders one failure as the single line an operator needs.
func (f HopFailure) String() string {
	var builder strings.Builder
	builder.WriteString("hop #")
	builder.WriteString(itoa(f.Position))
	builder.WriteString(" of ")
	builder.WriteString(itoa(f.HopCount))
	builder.WriteString(" ")
	builder.WriteString(f.Hop)
	builder.WriteString(" failed at phase ")
	builder.WriteString(f.Phase.String())
	if len(f.Reached) > 0 {
		builder.WriteString(" (reached: ")
		builder.WriteString(strings.Join(f.Reached, " -> "))
		builder.WriteString(")")
	}
	if len(f.Unreached) > 0 {
		builder.WriteString(" (never tried: ")
		builder.WriteString(strings.Join(f.Unreached, " -> "))
		builder.WriteString(")")
	}
	if f.Recovered {
		builder.WriteString(" [since recovered]")
	}
	builder.WriteString(": ")
	builder.WriteString(f.Detail)
	return builder.String()
}

// redactDetail removes everything from an error message that must never reach a log or a report.
//
// # What it removes, and why a denylist is the right shape here
//
// The list is deliberately generous, because the cost of a false positive is a slightly less useful
// message and the cost of a false negative is a leaked credential in a bug report:
//
//	user:password@host        URL userinfo, which is how a proxy password leaks
//	scheme://...?...token=... query parameters named like secrets
//	password= / token= / ...  key-value forms
//	password="..." / "password":"..."   the quoted value, and the quoted key of a JSON body
//	access_token / db_password          a longer name ENDING in a keyword, after `_`
//	Authorization: Bearer ...           the header, whose WHOLE value goes, scheme included
//	BEGIN ... PRIVATE KEY     PEM bodies, which are multi-line
//
// # What it does NOT do
//
// It does not attempt to redact an arbitrary secret with no marker, because nothing can: a bare
// high-entropy string is indistinguishable from a tag or a hostname. That limitation is the reason the
// reporter's contract forbids handing one over in the first place - this function is a backstop, not a
// licence.
func redactDetail(detail string) string {
	if detail == "" {
		return ""
	}

	// PEM bodies first: they are multi-line, so a line-oriented pass would leave most of one behind.
	if marker := strings.Index(detail, "-----BEGIN"); marker >= 0 {
		detail = detail[:marker] + "[redacted PEM body]"
	}

	var builder strings.Builder
	builder.Grow(len(detail))
	index := 0
	for index < len(detail) {
		// URL userinfo: everything between "//" and the "@" that follows it, when it contains a colon.
		if strings.HasPrefix(detail[index:], "//") {
			if at := strings.IndexByte(detail[index:], '@'); at > 0 {
				userinfo := detail[index+2 : index+at]
				if strings.ContainsRune(userinfo, ':') && !strings.ContainsAny(userinfo, " \t") {
					builder.WriteString("//[redacted]@")
					index += at + 1
					continue
				}
			}
		}
		// An Authorization header carries a whole scheme plus credential, so the WHOLE value goes -
		// "Bearer sk-live-..." would otherwise leave the credential itself in place, which is the
		// failure mode the keyword pass has on its own.
		if header, width := authorizationHeaderAt(detail, index); width > 0 {
			builder.WriteString(header)
			builder.WriteString("[redacted]")
			index += width
			continue
		}
		// key=value and key: value forms whose key looks like a secret.
		if keyword, width := secretKeywordAt(detail, index); width > 0 {
			builder.WriteString(keyword)
			builder.WriteString("[redacted]")
			index += width
			continue
		}
		builder.WriteByte(detail[index])
		index++
	}
	return builder.String()
}

// authorizationHeaderAt recognises an Authorization header and consumes its entire value, including the
// auth scheme.
//
// It is separate from secretKeywordAt because "Bearer <token>" and "Basic <base64>" are two words rather
// than one value, and redacting only the first would leave exactly the part that matters.
func authorizationHeaderAt(detail string, index int) (string, int) {
	if index > 0 {
		previous := rune(detail[index-1])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) {
			// The same boundary rule secretKeywordAt uses, and it must match: an `Authorization` that
			// starts after an underscore is still an Authorization header, and it MUST take this path
			// rather than the keyword path. The keyword path stops at the first space, which would
			// redact the word "Bearer" and leave the credential itself sitting in the message.
			return "", 0
		}
	}
	const keyword = "authorization"
	if len(detail)-index < len(keyword) || !strings.EqualFold(detail[index:index+len(keyword)], keyword) {
		return "", 0
	}
	rest := detail[index:]
	valueStart := len(keyword)
	switch {
	case strings.HasPrefix(rest[valueStart:], ":"):
		valueStart++
	case strings.HasPrefix(rest[valueStart:], "="):
		valueStart++
	default:
		return "", 0
	}
	for valueStart < len(rest) && rest[valueStart] == ' ' {
		valueStart++
	}
	if valueStart >= len(rest) {
		return "", 0
	}
	end := valueStart
	for end < len(rest) && rest[end] != '\n' && rest[end] != '\r' {
		end++
	}
	return rest[:valueStart], end
}

// secretKeywords are the key names whose values are always removed. Matching is case-insensitive and
// requires the key to be preceded by a non-letter, so a word that merely ENDS in one of them is safe.
var secretKeywords = []string{
	"password", "passwd", "pwd",
	"token", "secret", "apikey", "api_key", "access_key", "private_key", "privatekey",
	"authorization", "auth", "credential", "credentials",
	"psk", "preshared_key", "pre_shared_key", "uuid",
}

// secretKeywordAt reports whether a secret assignment starts at index, and how many bytes it consumes.
//
// It returns the literal prefix to emit (the keyword and its separator, so the message still reads) and
// the length to skip.
//
// # The four shapes it must recognise
//
// The bare form is the easy one, and it was the only one this used to match:
//
//	password=hunter2          key=value
//	password: hunter2         key: value
//
// Three more are ordinary renderings of the same fact, and a backstop that misses them is a backstop
// against the tidy case only:
//
//	password="hunter2"        the value is quoted, which is what an ini or env rendering does
//	"password":"hunter2"      the KEY is quoted, which is what a JSON body echoed into an error does
//	access_token=ya29...      the key is a longer name ENDING in a keyword
//
// The last one is why the boundary rule is about the SEPARATOR and not about being a whole word. The
// keyword has to start at the beginning of a name, or after a character that cannot be part of one -
// which is what keeps `mypassword=` readable - and that character set includes `_`, because
// `access_token`, `refresh_token`, `db_password` and `user_password` are one name, not two.
func secretKeywordAt(detail string, index int) (string, int) {
	if index > 0 {
		previous := rune(detail[index-1])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) {
			// A keyword that continues a word is not a key: `mypassword=` is somebody else's field.
			// `_` is deliberately NOT in this set - see the shape list above.
			return "", 0
		}
	}
	rest := detail[index:]
	lowered := strings.ToLower(rest)
	for _, keyword := range secretKeywords {
		if !strings.HasPrefix(lowered, keyword) {
			continue
		}
		after := rest[len(keyword):]
		// A quoted key, as a JSON body renders one: the closing quote of the key sits between the
		// keyword and its separator.
		quotedKey := false
		if strings.HasPrefix(after, `"`) || strings.HasPrefix(after, `'`) {
			quotedKey = true
			after = after[1:]
		}
		separator := ""
		switch {
		case strings.HasPrefix(after, "="):
			separator = "="
		case strings.HasPrefix(after, ": "):
			separator = ": "
		case strings.HasPrefix(after, ":"):
			separator = ":"
		default:
			continue
		}
		valueStart := len(keyword) + len(separator)
		if quotedKey {
			valueStart++
		}
		value := rest[valueStart:]
		// A quoted VALUE, which is how an ini or env rendering writes one. Skipping the opening quote is
		// what makes the scan below stop at the closing one instead of at the opening one, which would
		// find an empty value and leave the secret in place.
		for len(value) > 0 && value[0] == ' ' {
			valueStart++
			value = value[1:]
		}
		if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`) {
			valueStart++
			value = value[1:]
		}
		end := len(value)
		for offset, character := range value {
			if character == ' ' || character == '\t' || character == '\n' || character == '\r' ||
				character == ',' || character == '&' || character == '"' {
				// These terminators are the ones that separate one field from the next in the shapes
				// above. Nothing else is a terminator on purpose: a character that merely LOOKS like a
				// delimiter inside a secret would truncate the redaction and leave the tail of the
				// secret in the message, which is a leak rather than an over-redaction. A closing
				// single quote is not a terminator for exactly that reason - the scan runs past it and
				// takes it with the value.
				end = offset
				break
			}
		}
		// Only redact when there IS a value; otherwise the message keeps reading naturally.
		if end == 0 {
			continue
		}
		return rest[:valueStart], valueStart + end
	}
	return "", 0
}
