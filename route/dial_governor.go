package route

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
)

// The reconnect governor bounds how many outbound dials may be in flight at once in the window
// after a network transition.
//
// # Why a window rather than a permanent limit
//
// A path change invalidates connections in bulk: every stream that was using the old path fails
// around the same moment and is re-dialled by its application at the same moment. That is a
// thundering herd of TCP handshakes, TLS handshakes, and - for anything with a tunnel - another
// round of QUIC or HTTP setup, all landing while the radio is already busy re-establishing. Bounding
// that burst is the point.
//
// Outside the window there is nothing to bound. A steady stream of dials on a working network is not
// a herd, and limiting it would be a permanent tax paid for a rare event. So the governor is inert
// by default and one atomic-free time comparison takes it out of the dial path entirely.
//
// # Why interactive traffic is never delayed
//
// The prompt's constraint is explicit: recovery must not get slower for the person holding the
// phone. A dial whose traffic class says a human is waiting on it - interactive or realtime - is
// never queued, whatever the governor is doing. Only the classes that have no latency expectation,
// default and bulk, can wait, and only for as long as the budget below.
//
// # Why the bound is soft
//
// A hard bound would turn a slow dial into an unbounded wait: if enough connections were stuck, a
// new dial could sit behind them for as long as they took. That is a worse failure than the herd.
// After dialGovernorBudget a dial stops waiting and proceeds unbounded, so the governor can only
// ever smooth the start of a burst - never delay recovery indefinitely, and never serialise it
// globally.

const (
	// dialGovernorWindow is how long a transition keeps the bound in place. It is short on purpose:
	// it covers the burst that follows the transition and nothing else.
	dialGovernorWindow = 3 * time.Second
	// dialGovernorLimit is the number of non-priority dials allowed to proceed at once inside the
	// window. It is deliberately generous - the herd being smoothed is tens of simultaneous
	// handshakes, and a limit near the number of file descriptors an app opens at once costs
	// nothing while a small one would.
	dialGovernorLimit = 24
	// dialGovernorBudget is how long a dial may wait for a slot before giving up on the governor and
	// proceeding anyway.
	dialGovernorBudget = 500 * time.Millisecond
	// dialGovernorJitter is the range of the pause between attempts. It exists so that dials
	// released together do not re-attempt together, which is the same synchronised wakeup the herd
	// is made of.
	dialGovernorJitter = 12 * time.Millisecond
)

// dialGovernor is the window and the slot count. It is zero-value inert: an unopened window applies
// to nothing.
type dialGovernor struct {
	access sync.Mutex
	// windowEnd is when the bound stops applying. The zero time means it never applied.
	windowEnd time.Time
	// active counts non-priority dials currently inside the gate.
	active int
	// limit is the slot count, overridable in tests.
	limit int
	// budget is the give-up delay, overridable in tests.
	budget time.Duration
	// jitter is the retry pause range, overridable in tests.
	jitter time.Duration
}

// open starts (or extends) the window. Called on a network transition.
func (g *dialGovernor) open(now time.Time) {
	end := now.Add(dialGovernorWindow)
	g.access.Lock()
	if end.After(g.windowEnd) {
		g.windowEnd = end
	}
	g.access.Unlock()
}

// isPriority reports whether a class is exempt from the bound.
//
// Interactive and realtime are a person waiting; default and bulk are not. ClassDefault is included
// on the bounded side deliberately: it is what an unconfigured flow resolves to, which is most
// traffic, and exempting it would leave the governor covering only what an operator happened to
// label - which is not where the herd comes from.
func isPriority(class trafficclass.Class) bool {
	return class == trafficclass.ClassInteractive || class == trafficclass.ClassRealtime
}

// enter waits for a slot if the window is open and the class is bounded, and returns the release
// function. The caller MUST call it exactly once, on every path, including error paths.
func (g *dialGovernor) enter(ctx context.Context, class trafficclass.Class) func() {
	if isPriority(class) {
		return noopRelease
	}
	limit, budget, jitter := g.settings()
	g.access.Lock()
	windowEnd := g.windowEnd
	open := time.Now().Before(windowEnd)
	if open && g.active < limit {
		g.active++
		g.access.Unlock()
		return g.release
	}
	g.access.Unlock()
	if !open {
		return noopRelease
	}

	deadline := time.Now().Add(budget)
	for {
		if ctx != nil && ctx.Err() != nil {
			// The caller is already gone; do not hold a slot for a dial that will not happen.
			return noopRelease
		}
		if !time.Now().Before(deadline) {
			// Out of patience. Proceeding unbounded is the documented trade: a soft bound delays the
			// start of a burst, it does not queue behind it.
			return noopRelease
		}
		time.Sleep(time.Duration(rand.Int64N(int64(jitter))) + jitter/2)
		g.access.Lock()
		if time.Now().After(g.windowEnd) {
			g.access.Unlock()
			return noopRelease
		}
		if g.active < limit {
			g.active++
			g.access.Unlock()
			return g.release
		}
		g.access.Unlock()
	}
}

func (g *dialGovernor) release() {
	g.access.Lock()
	if g.active > 0 {
		g.active--
	}
	g.access.Unlock()
}

// settings resolves the constants, with the test overrides applied.
func (g *dialGovernor) settings() (int, time.Duration, time.Duration) {
	limit, budget, jitter := dialGovernorLimit, dialGovernorBudget, dialGovernorJitter
	g.access.Lock()
	if g.limit > 0 {
		limit = g.limit
	}
	if g.budget > 0 {
		budget = g.budget
	}
	if g.jitter > 0 {
		jitter = g.jitter
	}
	g.access.Unlock()
	return limit, budget, jitter
}

func noopRelease() {}

// activeCount is for tests and diagnostics.
func (g *dialGovernor) activeCount() int {
	g.access.Lock()
	defer g.access.Unlock()
	return g.active
}

// enterDialGate is the connection manager's side of the governor.
func (m *ConnectionManager) enterDialGate(ctx context.Context, class trafficclass.Class) func() {
	return m.dialGovernor.enter(ctx, class)
}

// DialGovernorOpen reports whether the governor window is currently open.
func (m *ConnectionManager) DialGovernorOpen() bool {
	m.dialGovernor.access.Lock()
	defer m.dialGovernor.access.Unlock()
	return time.Now().Before(m.dialGovernor.windowEnd)
}
