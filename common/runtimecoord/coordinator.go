// Package runtimecoord holds the runtime resource policy: which network-bound resources exist, when
// they are told the network changed, and how their recovery is coalesced and cancelled.
//
// # What it is not
//
// It is not a lifecycle framework and not a state machine for protocols. adapter.Lifecycle still
// owns construction → start → close; each protocol still owns its own runtime state (a WireGuard
// device, a MASQUE session, a DNS pool). The coordinator answers exactly three questions that must
// have one answer across the core:
//
//	which generation is current?          (published, monotone, one observation)
//	is a rebuild owed for it?             (pull: Stale)
//	and is this burst one rebind or many? (per-resource window, coalesced, cancelable)
//
// # Why it exists at all
//
// Before it, every expensive resource decided those questions on its own, and the answers
// disagreed: a reset fanned out to every endpoint, each with its own timer, and a background probe
// could wake a suspended tunnel engine. The rules are in docs/fork/runtime-lifecycle-phase1.5.md.
package runtimecoord

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Coordinator publishes the current network generation to registered resources.
//
// Concurrency contract: the coordinator's lock guards only its bookkeeping - the epoch, the
// registration set, and the change channel. Everything that can call back into a component runs
// with that lock released, because those calls take locks of their own. A registration's own lock
// guards only that registration's state.
type Coordinator struct {
	access      sync.Mutex
	epoch       uint64
	changed     chan struct{}
	closed      bool
	registrated map[*Registration]struct{}
}

// New returns a coordinator whose epoch starts at zero.
//
// A zero epoch means "no reset has happened yet", which is the correct description of a core that
// has just started: every resource registered against it belongs to generation zero.
func New() *Coordinator {
	return &Coordinator{
		changed:     make(chan struct{}),
		registrated: make(map[*Registration]struct{}),
	}
}

// Epoch reports the current generation.
func (c *Coordinator) Epoch() uint64 {
	if c == nil {
		return 0
	}
	c.access.Lock()
	defer c.access.Unlock()
	return c.epoch
}

// Advance publishes a new generation to every registered resource.
//
// It is called once per network reset, after the manager has advanced its own epoch, so the two
// counters describe the same transition. An advance that does not change the epoch is a no-op: a
// caller reporting the same value twice must not produce two sweeps.
//
// The change channel is closed and replaced rather than sent to, so every current and future reader
// observes the transition exactly once.
func (c *Coordinator) Advance(epoch uint64) {
	if c == nil {
		return
	}
	c.access.Lock()
	if c.closed || epoch <= c.epoch {
		c.access.Unlock()
		return
	}
	c.epoch = epoch
	previous := c.changed
	c.changed = make(chan struct{})
	registrations := make([]*Registration, 0, len(c.registrated))
	for registration := range c.registrated {
		registrations = append(registrations, registration)
	}
	c.access.Unlock()

	close(previous)

	// Outside the lock: a resource's reaction takes locks of its own.
	for _, registration := range registrations {
		registration.observeEpoch(epoch)
	}
}

// Close stops the coordinator. Later advances and registrations are refused, and every registration
// is invalidated so a scheduled recovery observes cancellation instead of running against a core
// that is going away.
func (c *Coordinator) Close() error {
	if c == nil {
		return nil
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	previous := c.changed
	c.changed = make(chan struct{})
	registrations := make([]*Registration, 0, len(c.registrated))
	for registration := range c.registrated {
		registrations = append(registrations, registration)
	}
	c.registrated = nil
	c.access.Unlock()

	close(previous)
	for _, registration := range registrations {
		registration.invalidate()
	}
	return nil
}

// GenerationChanged returns a channel closed when the network generation next advances.
//
// The snapshot and the channel are read under one lock, so a caller cannot observe "unchanged" and
// then wait on a channel that was already closed by the transition it just missed.
func (c *Coordinator) GenerationChanged() (uint64, <-chan struct{}) {
	if c == nil {
		return 0, closedChannel()
	}
	c.access.Lock()
	defer c.access.Unlock()
	return c.epoch, c.changed
}

// Register adds a resource to the coordinator.
//
// The returned registration is valid until its remove function is called; the caller must call that
// from its owner's cleanup, so a torn-down resource is never reached by a later sweep. A nil
// coordinator yields an inert registration, which keeps a test double or a service-less core simple.
func (c *Coordinator) Register(label string) (*Registration, func()) {
	if c == nil {
		registration := newRegistration(nil, label)
		return registration, registration.invalidate
	}
	registration := newRegistration(c, label)
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		registration.invalidate()
		return registration, func() {}
	}
	// A resource that registers on a generation that has already moved must know it, or the
	// registration would look current until the next reset.
	registration.epoch = c.epoch
	// A fresh registration has not built anything against any generation yet, so there is nothing
	// for it to be stale about. It becomes stale when a LATER generation is published.
	registration.observed = true
	c.registrated[registration] = struct{}{}
	c.access.Unlock()
	remove := func() {
		c.access.Lock()
		if c.registrated != nil {
			delete(c.registrated, registration)
		}
		c.access.Unlock()
		registration.invalidate()
	}
	return registration, remove
}

// Registration is one resource's view of the coordinator.
//
// It carries the per-resource decisions the coordinator must not centralise: the recovery window,
// the last rebind, and whether a rebind is already scheduled.
type Registration struct {
	coordinator *Coordinator
	label       string

	access sync.Mutex
	closed bool
	epoch  uint64
	// observed is whether the generation this registration was built against has been acted on.
	// It is what makes Stale() mean "this resource still belongs to a previous network" rather than
	// merely "the counter moved": observing a notification is not rebuilding the resource.
	observed    bool
	pending     bool
	lastRebind  time.Time
	rebindCount uint64
	// window overrides adapter.RecoveryWindow when non-zero; tests set it.
	window time.Duration
}

func newRegistration(coordinator *Coordinator, label string) *Registration {
	return &Registration{coordinator: coordinator, label: label}
}

// Label is the resource's display name, used in logs.
func (r *Registration) Label() string { return r.label }

// SetRecoveryWindow overrides the window between rebinds. Tests set it; production leaves it zero
// and uses adapter.RecoveryWindow.
func (r *Registration) SetRecoveryWindow(window time.Duration) {
	r.access.Lock()
	r.window = window
	r.access.Unlock()
}

// Epoch reports the generation this registration last observed.
func (r *Registration) Epoch() uint64 {
	r.access.Lock()
	defer r.access.Unlock()
	return r.epoch
}

// Closed reports whether the registration has been invalidated by a removal or a coordinator close.
func (r *Registration) Closed() bool {
	r.access.Lock()
	defer r.access.Unlock()
	return r.closed
}

// RebindCount reports how many rebinds this registration has granted permission for. Telemetry and
// tests.
func (r *Registration) RebindCount() uint64 {
	r.access.Lock()
	defer r.access.Unlock()
	return r.rebindCount
}

// observeEpoch records the new generation for this resource.
//
// A rebind already scheduled for a previous generation is cancelled. That is deliberate: a network
// change invalidates the reason the rebind was scheduled for, and a resource that is still broken on
// the new network will ask again through its own failure signal. It is also what stops a burst of
// resets from producing a burst of rebuilds.
func (r *Registration) observeEpoch(epoch uint64) {
	r.access.Lock()
	if r.closed || epoch <= r.epoch {
		r.access.Unlock()
		return
	}
	r.epoch = epoch
	r.observed = false
	r.pending = false
	// The previous window described a network that no longer exists. A failure on the new one is a
	// new fact and may be acted on immediately; if it does not fail, nothing happens, which is the
	// correct cost of a reset for a resource that is actually healthy.
	r.lastRebind = time.Time{}
	r.access.Unlock()
}

// invalidate makes the registration inert: nothing it schedules will run.
func (r *Registration) invalidate() {
	r.access.Lock()
	r.closed = true
	r.pending = false
	r.access.Unlock()
}

// ScheduleRebind decides whether this trigger earns a rebind for this resource.
//
// It returns true when the caller owns the rebind and must run it, reporting the outcome with
// CompleteRebind; false when the trigger was coalesced - the resource is closing, has no
// coordinator, already has a rebind in flight, or is inside the window of one that already ran.
//
// The window is the whole point: a give-up, a wake and a manual reset arriving together, or a burst
// of ten resets, are one rebind. Only a *new* failure signal re-arms it, and a network change
// re-arms it because the previous window described a different network.
func (r *Registration) ScheduleRebind(reason adapter.RebindReason) bool {
	if r == nil {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return false
	}
	if r.pending {
		return false
	}
	window := r.window
	if window == 0 {
		window = adapter.RecoveryWindow
	}
	if !r.lastRebind.IsZero() && time.Since(r.lastRebind) < window {
		return false
	}
	// Armed here, not when the rebind finishes. A rebind that completes instantly must still leave
	// the window consumed, or a burst of triggers - each of which completes before the next arrives
	// - would earn one rebind per trigger. That is the whole point of the window.
	r.lastRebind = time.Now()
	r.pending = true
	r.rebindCount++
	return true
}

// CompleteRebind records that the caller's rebind finished, releasing the in-flight mark.
//
// The window stays consumed whether it succeeded or failed: the retry cadence is the handshake
// cycle's, not a busy loop. A failure is reported by the resource's own logs, and the next proven
// failure after the window earns another attempt.
func (r *Registration) CompleteRebind() {
	if r == nil {
		return
	}
	r.access.Lock()
	r.pending = false
	r.access.Unlock()
}

// Stale reports whether the resource belongs to a previous generation.
//
// It is the pull side of the same decision: a resource with no continuous recovery worker - a DNS
// pool, an HTTP client - asks this at the moment it is about to reuse something, instead of being
// pushed a notification.
func (r *Registration) Stale() bool {
	if r == nil {
		return false
	}
	if r.coordinator == nil {
		return false
	}
	r.access.Lock()
	closed := r.closed
	observed := r.observed
	epoch := r.epoch
	r.access.Unlock()
	if closed {
		return true
	}
	if !observed {
		return true
	}
	return r.coordinator.Epoch() > epoch
}

// Acknowledge records that the caller has rebuilt the resource against the current generation.
//
// It is what separates "the epoch moved" from "this resource is current". A push notification only
// tells a resource that the network changed; the resource is still holding sockets bound to the old
// network until it acts. Until it says so here, Stale() keeps reporting true, so a reuse check
// cannot mistake an un-rebuilt resource for a current one.
func (r *Registration) Acknowledge() {
	if r == nil {
		return
	}
	r.access.Lock()
	if !r.closed && r.coordinator != nil {
		r.epoch = r.coordinator.Epoch()
		r.observed = true
	}
	r.access.Unlock()
}

// WakeAllowsRebind reports whether a device-wake nudge may rebind this resource.
//
// The stale predicate belongs to the caller - a wake with a healthy session must cost nothing. The
// registration supplies only the window, so a wake arriving right after a give-up rebind does not
// become a second one.
func (r *Registration) WakeAllowsRebind() bool {
	if r == nil {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return false
	}
	window := r.window
	if window == 0 {
		window = adapter.RecoveryWindow
	}
	if r.lastRebind.IsZero() {
		return true
	}
	return time.Since(r.lastRebind) >= window
}

var closedChan = func() chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}()

func closedChannel() <-chan struct{} { return closedChan }

// ContextWithProbeOrigin records why a measurement is running.
//
// # Why the origin must come from the caller
//
// The automatic/foreground distinction cannot be derived from `force`: an automatic recheck after a
// connection failure is forced too, and it is not demand. It cannot come from the caller's context
// either, because the context is rebuilt from the group's own (see operationContext). So it is
// declared explicitly by the entry point that knows, and travels with the operation.
//
// The default, for any caller that does not declare an origin, is AUTOMATIC. That is the safe
// direction: an automatic round may not wake an idle resource, and getting the default wrong that
// way only delays recovery until real traffic, while the other default would let a periodic timer
// keep a tunnel engine alive.
type probeOriginKey struct{}

const (
	// ProbeAutomatic is periodic maintenance: a health round, a recheck after a connection failure,
	// an interface-update re-test. It must not wake a suspended resource.
	ProbeAutomatic = false
	// ProbeForeground is a measurement a person asked for, or that the product treats as demand.
	// It may wake a suspended resource, because that is what the user is waiting on.
	ProbeForeground = true
)

// ContextWithProbeOrigin marks a measurement as automatic or foreground.
func ContextWithProbeOrigin(ctx context.Context, foreground bool) context.Context {
	return context.WithValue(ctx, probeOriginKey{}, foreground)
}

// ProbeOriginIsForeground reports whether a measurement was declared as foreground. A context that
// declares nothing is automatic.
func ProbeOriginIsForeground(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	foreground, _ := ctx.Value(probeOriginKey{}).(bool)
	return foreground
}

// MeasurementContext marks a measurement as background work.
//
// # Why the decision is made at the entry point rather than read from the operation's context
//
// A URLTest health round does not run on the caller's context. The group rebuilds one from its own
// Box context (see URLTestGroup.operationContext) so that Close still cancels and Box services stay
// reachable, and the caller contributes only a deadline and cancellation - its VALUES are dropped.
// A marker carried on the caller's context therefore never reaches the dial, which is how a round
// silently lost its origin.
//
// The origin is taken from the caller BEFORE that rebuild and re-applied to the operation's context,
// so the decision survives the layering rather than depending on it.
//
// The default, for a caller that declares nothing, is background work: see ProbeAutomatic.
//
// The operation's own context is passed through unchanged (deadline, cancellation and all); only the
// origin is added.
func MeasurementContext(operation context.Context, foreground bool) context.Context {
	if foreground {
		return ContextWithProbeOrigin(operation, ProbeForeground)
	}
	return adapter.ContextWithBackgroundProbe(operation)
}
