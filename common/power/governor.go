// Package power is the single authority for how much background work this fork is allowed to do.
//
// # Why one authority rather than a flag per protocol
//
// The Apple packet tunnel already tells the core when the device goes to sleep and wakes:
//
//	NEPacketTunnelProvider.sleep() -> commandServer.pause() -> PauseManager.DevicePause()
//	NEPacketTunnelProvider.wake()  -> commandServer.wake()  -> PauseManager.DeviceWake()
//
// and the network monitor already tells it when the path is paused or restored. What did NOT exist
// was one place that turns those signals plus real traffic into an answer a subsystem can ask for.
// The alternative - every health checker, DNS transport, QUIC session and statistics sampler
// deciding for itself whether "paused" means it should stop - is how a codebase ends up with dozens
// of slightly different sleep policies and no way to reason about any of them.
//
// So this package owns the state and the thresholds, and subsystems only ask. See docs for the
// policy.
//
// # What this package deliberately does not do
//
// It does not close anything, clear anything, or reset anything. Transitions only change what is
// ALLOWED; the owner of a connection or a cache decides what to do about that, and the brief this
// was built from is explicit that a device going to sleep must not kill a transfer in progress.
package power

import (
	"context"
	"sync"
	"time"
)

// State is how much background work the current conditions permit.
type State uint8

const (
	// StateActive is normal operation: the device is awake and nothing is being suppressed.
	StateActive State = iota
	// StateWaking is the window just after a wake, during which the business data path is already up
	// but speculative work is released in stages rather than all at once.
	//
	// The brief's requirement is that a wake must not be a storm: twenty subsystems deciding at the
	// same instant to refresh, probe and re-test is a burst of radio and CPU that arrives exactly when
	// the user is looking at the screen. Staggering costs nothing when the device is about to be used
	// for a while anyway, and it is the difference between a wake and a spike.
	StateWaking
	// StateQuiescent is the device asleep or backgrounded, but recently enough that real business may
	// still arrive - a voice call already in progress, a background upload. Speculative maintenance
	// stops here; nothing that is carrying traffic is touched.
	StateQuiescent
	// StateDeepIdle is a pause that has held with no real traffic for Policy.DeepIdleAfter. Only the
	// protocols' own correctness timers keep running.
	StateDeepIdle
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateWaking:
		return "waking"
	case StateQuiescent:
		return "quiescent"
	case StateDeepIdle:
		return "deep-idle"
	default:
		return "unknown"
	}
}

// Allow is what a state permits. It is a value rather than a set of methods so a reader can see the
// whole policy for a state at once, and so an unset field is visibly "not allowed" instead of
// silently inherited.
type Allow struct {
	// HealthCheck permits proxy health checks and URL tests.
	HealthCheck bool
	// ProviderRefresh permits periodic provider, subscription and Geo updates.
	ProviderRefresh bool
	// NetworkProbe permits latency and network-quality probing.
	NetworkProbe bool
	// Statistics permits pushing UI snapshots and connection listings.
	Statistics bool
}

// allowAll is what ACTIVE means, and it is the zero-configuration behaviour: a build with no policy
// installed must behave exactly as it did before this package existed.
var allowAll = Allow{HealthCheck: true, ProviderRefresh: true, NetworkProbe: true, Statistics: true}

// Policy is every threshold and every permission, in one place.
//
// The brief is explicit that these values must not be scattered across modules, because a sleep
// policy that is spread out cannot be reviewed - and because the first symptom of getting one of
// them wrong is a user's call dropping, which is a poor way to find out.
type Policy struct {
	// DeepIdleAfter is how long a pause must hold with no real traffic before maintenance stops
	// entirely. It is deliberately generous: the cost of waiting is a little battery, and the cost of
	// not waiting is interrupting something a person is using.
	DeepIdleAfter time.Duration
	// Quiescent is what is permitted while the device is paused but has not yet gone deep idle.
	Quiescent Allow
	// DeepIdle is what is permitted once it has.
	DeepIdle Allow
	// WakeStagger is how long each category waits after a wake before it may run again. Zero means
	// "at once", which is the pre-existing behaviour for any field left unset.
	WakeStagger WakeStagger
}

// WakeStagger delays the resumption of speculative work after a wake.
//
// It exists because a wake is the moment every subsystem is told to come back, and the ones that are
// cheap to delay are also the ones that cost the most radio: a health check that runs immediately
// competes with the request the user woke the phone to make.
type WakeStagger struct {
	HealthCheck     time.Duration
	ProviderRefresh time.Duration
	NetworkProbe    time.Duration
	Statistics      time.Duration
}

// longest is the point at which every category has been released, and therefore the point at which
// the governor stops being WAKING.
func (s WakeStagger) longest() time.Duration {
	longest := s.HealthCheck
	for _, other := range []time.Duration{s.ProviderRefresh, s.NetworkProbe, s.Statistics} {
		if other > longest {
			longest = other
		}
	}
	return longest
}

// DefaultPolicy is the built-in policy.
//
// DeepIdleAfter is provisional tuning, not a measured optimum: long enough that a call, a track or a
// background upload that is genuinely running keeps its maintenance, short enough that a phone left
// in a pocket stops waking for work nobody asked for.
func DefaultPolicy() Policy {
	return Policy{
		DeepIdleAfter: 2 * time.Minute,
		// Quiescent keeps statistics and provider refresh off - they are speculative and cost radio -
		// but leaves health checking and probing alone, because a tunnel whose liveness is not checked
		// is a tunnel that fails silently the moment the user picks the phone up.
		Quiescent: Allow{HealthCheck: true, NetworkProbe: true},
		// Deep idle keeps nothing speculative. Protocol correctness timers are not gated here: they
		// belong to the session that owns them, not to this policy.
		DeepIdle: Allow{},
		// Provisional tuning, from the brief's suggested ranges, not measured optima. Orders are
		// staggered rather than the values being precise: what matters is that a health check does not
		// start in the same instant as a provider refresh.
		WakeStagger: WakeStagger{
			HealthCheck:     5 * time.Second,
			ProviderRefresh: 15 * time.Second,
			NetworkProbe:    5 * time.Second,
			Statistics:      10 * time.Second,
		},
	}
}

// Observer is notified when the state changes. It must not block: it is called from whichever
// goroutine caused the transition.
type Observer func(state State)

// Governor is the state machine. Its zero value is not usable; call NewGovernor.
type Governor struct {
	access sync.Mutex
	policy Policy

	state        State
	devicePaused bool
	// networkPaused is tracked separately from devicePaused because they mean different things and
	// have different recoveries: a device wake with no network is not usable, and a network that comes
	// back while the device is asleep must not re-enable speculative work.
	networkPaused bool

	// idleTimer promotes Quiescent to DeepIdle. It is armed on entering the pause and disarmed by any
	// real traffic, which is what makes the transition traffic-driven rather than a fixed countdown
	// from the moment the screen went off.
	idleTimer *time.Timer
	// idleGeneration is the era of the current deadline. Every invalidation bumps it, and a callback
	// captured its own value when it was armed: a callback whose generation is no longer current
	// belongs to a deadline that has been superseded and must not act at all.
	//
	// This is not belt-and-braces. time.Timer.Stop() cannot recall a callback that has ALREADY begun,
	// and that callback goes on to take the lock. Without an era check it would clear the reference to
	// the replacement timer and put the governor into DEEP_IDLE - ignoring the traffic that had just
	// bought another DeepIdleAfter. The mutex does not help: both goroutines are correctly
	// synchronised and the sequence is still wrong, so the race detector cannot see it either.
	idleGeneration uint64
	// wakeTimer promotes WAKING to ACTIVE once every staggered category has been released.
	wakeTimer *time.Timer
	// wakeGeneration is the same idea for the wake stagger: a stagger superseded by a newer wake must
	// not release work early on its predecessor's schedule.
	wakeGeneration uint64
	// wokeAt is when the current wake began, and is what Allow() measures each category against.
	wokeAt time.Time
	closed bool

	observers []Observer
	// pendingNotify is set by a transition and cleared by flushNotifications, which runs after the
	// lock is released. See setStateLocked.
	pendingNotify bool
	// idleCallbackEntered, when set, runs at the very start of the idle timer callback BEFORE the lock
	// is taken. It exists so a test can force the one interleaving that cannot be reached by sleeping:
	// a callback that has already committed to running but has not yet acquired the lock, while
	// ObserveTraffic resets the deadline underneath it. Set before the timer is armed and never
	// mutated afterwards, so it needs no synchronisation of its own.
	idleCallbackEntered func()

	// stateChanged is closed and replaced on every transition, so a subsystem can wait for the state
	// to move without polling. See WaitActive.
	stateChanged chan struct{}
}

// NewGovernor builds a governor for the given policy.
func NewGovernor(policy Policy) *Governor {
	return &Governor{
		policy:       policy,
		state:        StateActive,
		stateChanged: make(chan struct{}),
	}
}

// State reports the current state.
func (g *Governor) State() State {
	g.access.Lock()
	defer g.access.Unlock()
	return g.state
}

// Allow reports what the current state permits.
func (g *Governor) Allow() Allow {
	g.access.Lock()
	defer g.access.Unlock()
	return g.allowLocked()
}

func (g *Governor) allowLocked() Allow {
	switch g.state {
	case StateWaking:
		// Released one category at a time, measured from the wake rather than counted down by a timer
		// each: a caller asking "may I run" gets the answer for its own category, and no subsystem has
		// to own a stagger of its own.
		elapsed := time.Since(g.wokeAt)
		stagger := g.policy.WakeStagger
		return Allow{
			HealthCheck:     elapsed >= stagger.HealthCheck,
			ProviderRefresh: elapsed >= stagger.ProviderRefresh,
			NetworkProbe:    elapsed >= stagger.NetworkProbe,
			Statistics:      elapsed >= stagger.Statistics,
		}
	case StateQuiescent:
		return g.policy.Quiescent
	case StateDeepIdle:
		return g.policy.DeepIdle
	default:
		return allowAll
	}
}

// Active reports whether speculative background work may run.
//
// A closed governor reports false, which is the same answer WaitActive gives and for the same
// reason: it cannot authorise work against a lifecycle that has ended. Reporting true here would mean
// a subsystem holding a stale reference - which is exactly what a failed construction leaves behind -
// could act on a governor that is no longer being driven.
func (g *Governor) Active() bool {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return false
	}
	return g.state == StateActive
}

// DevicePaused records that the device went to sleep or the app was backgrounded.
func (g *Governor) DevicePaused() {
	defer g.flushNotifications()
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed || g.devicePaused {
		return
	}
	g.devicePaused = true
	g.recomputeLocked()
}

// DeviceWake records that the device woke.
func (g *Governor) DeviceWake() {
	defer g.flushNotifications()
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed || !g.devicePaused {
		return
	}
	g.devicePaused = false
	if g.networkPaused {
		// No path: there is nothing to release yet. The stagger begins when the network returns.
		g.recomputeLocked()
		return
	}
	g.beginWakingLocked()
}

// beginWakingLocked releases the business path at once and staggers the rest. Caller holds the lock.
func (g *Governor) beginWakingLocked() {
	if g.idleTimer != nil {
		g.idleTimer.Stop()
		g.idleTimer = nil
	}
	stagger := g.policy.WakeStagger
	longest := stagger.longest()
	if longest <= 0 {
		g.setStateLocked(StateActive)
		return
	}
	g.wokeAt = time.Now()
	g.setStateLocked(StateWaking)
	if g.wakeTimer != nil {
		g.wakeTimer.Stop()
		g.wakeTimer = nil
	}
	// Same era discipline as the idle deadline, and it is needed for the same reason: a stagger that
	// has already begun cannot be recalled by Stop(), and if a NEWER wake has since put the governor
	// back into WAKING, the old callback would end that new stagger early on its predecessor's
	// schedule. The state check alone does not catch that - the state IS WAKING, just not this
	// callback's WAKING.
	g.wakeGeneration++
	generation := g.wakeGeneration
	g.wakeTimer = time.AfterFunc(longest, func() {
		defer g.flushNotifications()
		g.access.Lock()
		defer g.access.Unlock()
		if g.closed || generation != g.wakeGeneration {
			return
		}
		g.wakeTimer = nil
		if g.state != StateWaking {
			return
		}
		g.setStateLocked(StateActive)
	})
}

// NetworkPaused records that the device lost its path.
//
// It suppresses speculative work for the same reason a device pause does, and a stronger one: with no
// path, a health check or a probe cannot succeed, so running one spends radio to learn nothing. The
// two signals are tracked separately because their recoveries differ, not because one implies the
// other.
func (g *Governor) NetworkPaused() {
	defer g.flushNotifications()
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed || g.networkPaused {
		return
	}
	g.networkPaused = true
	g.recomputeLocked()
}

// NetworkWake records that the path came back.
func (g *Governor) NetworkWake() {
	defer g.flushNotifications()
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed || !g.networkPaused {
		return
	}
	g.networkPaused = false
	if !g.devicePaused && g.state != StateActive {
		// The path came back with the device awake: the business path is usable again, and the
		// speculative categories are released in the same staggered order as after a device wake.
		g.beginWakingLocked()
		return
	}
	g.recomputeLocked()
}

// ObserveTraffic records that real business traffic moved.
//
// This is the traffic-driven half of the design, and what it does NOT do is the point: it does not
// return the governor to ACTIVE, because that would re-enable every speculative subsystem - provider
// refresh, probing, statistics - for a device that is still asleep and merely forwarded one push
// notification's request. The brief calls that a wake storm, and it is how a power optimisation pays
// for itself twice over.
//
// What it does is move the deadline. The traffic already has its link; the countdown to DEEP_IDLE
// restarts from now, because "idle" means no real activity for DeepIdleAfter; and DEEP_IDLE itself is
// lifted back to QUIESCENT so the link that is in use keeps the little maintenance QUIESCENT permits.
//
// Activity is per FLOW, so a single long-lived transfer does not keep pushing the deadline out and the
// governor may reach DEEP_IDLE while one is running. That is safe and intended: DEEP_IDLE stops
// speculative work and releases only genuinely idle reusable pools, and never terminates an active
// flow.
//
// It is deliberately cheap - one lock, and a timer reset only while something is suppressing - because
// the forwarding path calls it. It must NOT be called for the core's own liveness traffic.
func (g *Governor) ObserveTraffic() {
	defer g.flushNotifications()
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return
	}
	if g.state == StateActive {
		// The common case, and the cheapest: nothing to do.
		return
	}
	if g.state == StateDeepIdle {
		g.setStateLocked(StateQuiescent)
	}
	// The deadline is RESET, not destroyed.
	//
	// Stopping the timer without re-arming it looks equivalent and is not: nothing else arms it,
	// because recomputeLocked - its only other caller - runs on device and network signals alone. A
	// single transient request would therefore strand the governor in QUIESCENT for as long as the
	// device stayed paused, and QUIESCENT still permits health checks and probes. The deepest saving
	// state would become unreachable after the first background push of the night, which is the
	// opposite of what this package is for.
	//
	// "Idle" means no real activity for DeepIdleAfter, so an activity moves the deadline rather than
	// cancelling it.
	if g.devicePaused || g.networkPaused {
		g.resetIdleTimerLocked()
	}
}

// resetIdleTimerLocked restarts the countdown to DEEP_IDLE from now. Caller holds the lock and has
// already established that something is suppressing.
func (g *Governor) resetIdleTimerLocked() {
	g.cancelIdleTimerLocked()
	g.armIdleTimerLocked()
}

// recomputeLocked decides the state from the signals, and is the only place a transition to
// Quiescent or DeepIdle is begun.
func (g *Governor) recomputeLocked() {
	if !g.devicePaused && !g.networkPaused {
		g.cancelIdleTimerLocked()
		g.setStateLocked(StateActive)
		return
	}
	// Somebody is suppressing: the device is asleep, or there is no path. Speculative work stops at
	// once - there is nothing for it to achieve - and the countdown to DEEP_IDLE starts.
	g.setStateLocked(StateQuiescent)
	g.armIdleTimerLocked()
}

func (g *Governor) armIdleTimerLocked() {
	if g.idleTimer != nil || g.policy.DeepIdleAfter <= 0 {
		return
	}
	g.idleGeneration++
	generation := g.idleGeneration
	g.idleTimer = time.AfterFunc(g.policy.DeepIdleAfter, func() {
		defer g.flushNotifications()
		if g.idleCallbackEntered != nil {
			g.idleCallbackEntered()
		}
		g.access.Lock()
		defer g.access.Unlock()
		// First, and before anything is mutated: does this callback still own the deadline?
		//
		// A superseded callback must not clear g.idleTimer - that reference now belongs to a newer
		// timer, and clearing it would leave a live timer that nothing can stop - and must not touch
		// the state.
		if g.closed || generation != g.idleGeneration {
			return
		}
		g.idleTimer = nil
		// Either suppression is enough to have reached here; both being lifted means recompute
		// already returned to ACTIVE and disarmed this timer.
		if !g.devicePaused && !g.networkPaused {
			return
		}
		g.setStateLocked(StateDeepIdle)
	})
}

// cancelIdleTimerLocked invalidates the pending countdown.
//
// It bumps the generation as well as stopping the timer, because Stop() cannot recall a callback that
// has already started - see the era check in the callback itself.
func (g *Governor) cancelIdleTimerLocked() {
	if g.idleTimer != nil {
		g.idleTimer.Stop()
		g.idleTimer = nil
	}
	g.idleGeneration++
}

// setStateLocked applies a transition and wakes anything waiting on one.
//
// It does NOT call the observers. It records that they are owed a notification, and
// flushNotifications delivers it after the caller has released the lock.
//
// The reason is not tidiness. An observer's job is to react to a state change, and the most useful
// reaction - releasing connections that only exist to be reused - takes locks of its own. Calling one
// while holding this lock makes the governor a lock-ordering hazard for every subsystem that observes
// it, and the deadlock would appear only under the combination of a sleep and a connection close.
func (g *Governor) setStateLocked(state State) {
	if g.state == state {
		return
	}
	g.state = state
	close(g.stateChanged)
	g.stateChanged = make(chan struct{})
	g.pendingNotify = true
}

// flushNotifications delivers any notification setStateLocked owed, and must be called with the lock
// RELEASED. Entry points arrange that with `defer g.flushNotifications()` placed before the deferred
// unlock, so the unlock runs first.
func (g *Governor) flushNotifications() {
	g.access.Lock()
	if !g.pendingNotify {
		g.access.Unlock()
		return
	}
	g.pendingNotify = false
	state := g.state
	observers := g.observers
	g.access.Unlock()
	for _, observer := range observers {
		observer(state)
	}
}

// WaitActive blocks until the governor is ACTIVE, or the context ends. It reports whether it is
// active.
//
// It exists so a subsystem can wait for the device instead of polling for it: a ticker that fires
// every second only to discover it is asleep is the cost this package is meant to remove.
func (g *Governor) WaitActive(ctx context.Context) bool {
	for {
		g.access.Lock()
		if g.closed {
			// A closed governor cannot authorise work: reporting "active" here would let a subsystem
			// proceed against a lifecycle that has ended.
			g.access.Unlock()
			return false
		}
		if g.state == StateActive || g.state == StateWaking {
			// WAKING counts: the business path is up, and a subsystem waiting to do work should not be
			// held for the sake of a stagger that applies to speculative categories. The fine-grained
			// question is Allow(), which answers per category.
			g.access.Unlock()
			return true
		}
		changed := g.stateChanged
		g.access.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

// WaitProviderRefresh blocks until the provider-refresh category is permitted, or the context ends.
//
// It is the alternative to polling for work that is periodic AND deferrable. A remote rule-set
// refresh does not need to happen at a particular moment, only before the rules go stale, so it can
// wait for the device rather than waking it - which is the whole difference between a schedule that
// costs a radio wakeup at 3am and one that costs nothing until the phone is picked up.
//
// The wait is on transitions, so it is exact for the pauses it exists for: while the device is
// QUIESCENT or DEEP IDLE the answer cannot change without a transition. During WAKING it becomes
// permitted at the moment the state becomes ACTIVE, which raises a transition too, because
// provider refresh carries the longest stagger.
func (g *Governor) WaitProviderRefresh(ctx context.Context) bool {
	return g.waitFor(ctx, func(allow Allow) bool { return allow.ProviderRefresh })
}

func (g *Governor) waitFor(ctx context.Context, permitted func(Allow) bool) bool {
	for {
		g.access.Lock()
		if g.closed {
			g.access.Unlock()
			return false
		}
		if permitted(g.allowLocked()) {
			g.access.Unlock()
			return true
		}
		changed := g.stateChanged
		g.access.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

// AddObserver registers a state observer. It is called synchronously on every transition.
func (g *Governor) AddObserver(observer Observer) {
	g.access.Lock()
	defer g.access.Unlock()
	g.observers = append(g.observers, observer)
}

// Close stops the governor. It is idempotent.
func (g *Governor) Close() {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return
	}
	g.closed = true
	g.cancelIdleTimerLocked()
	if g.wakeTimer != nil {
		g.wakeTimer.Stop()
		g.wakeTimer = nil
	}
	g.wakeGeneration++
	close(g.stateChanged)
}
