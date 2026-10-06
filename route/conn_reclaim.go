package route

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
)

// ReclaimReason says WHY managed connections are being reclaimed. The reason is not cosmetic: the
// callers that used to share one entry point (CloseAll) mean very different things, and treating a
// path change like a shutdown is what made a Wi-Fi roam kill every stream the device was running.
//
// Audit, before this file existed:
//
//	ResetNetwork / interface update -> connectionManager.CloseAll()   every stream, unconditionally
//	Pause                           -> CloseIdleConnections()          idle only, already correct
//	ReleaseMemory (OOM killer)      -> ResetNetwork + idle            aggressive, and deliberate
//	Close (shutdown)                -> CloseAll()                      correct
//
// So the reason-aware split already existed for pause and memory pressure, and the ONE place that
// was wrong was the transition path, which reached for the shutdown primitive. That is what
// ReclaimNetworkTransition changes; the other reasons are kept so the distinction is explicit at the
// call site rather than implied by which method somebody happened to call.
type ReclaimReason uint8

const (
	// ReclaimNetworkTransition is a path change: a new interface, a new gateway, a new SSID.
	//
	// Drain, do not kill. A connection that is still moving bytes is left alone and given the chance
	// to finish on the old path while new connections use the new one. Only connections that are
	// PROVEN IDLE are reclaimed immediately, and the rest are followed by a sweep so that "drain"
	// cannot mean "forever".
	ReclaimNetworkTransition ReclaimReason = iota
	// ReclaimIdle is pause, background or a gentle memory release: reclaim what is idle, never a
	// stream that is in use.
	ReclaimIdle
	// ReclaimDeadPath is a HARD transition: the device has no default interface at all, so no
	// connection can still be reaching anywhere. There is nothing to drain and nothing to preserve.
	//
	// This is what distinguishes hard from medium in practice. A medium transition - a new gateway,
	// a new SSID, a different interface - leaves open the possibility that a socket still works, so
	// it drains and lets the socket prove otherwise. A hard one has already answered that question,
	// and holding the connections would only keep memory and file descriptors alive on a device that
	// is, by definition, likely to be under pressure.
	ReclaimDeadPath
	// ReclaimShutdown is teardown. Everything goes, including active streams, because there is
	// nothing left to serve them.
	ReclaimShutdown
)

// How long a connection must have been silent before a transition may reclaim it.
//
// This is deliberately longer than any interactive gap a user would notice and far shorter than the
// lifetime of a blackholed socket, which is the failure this bounds: a stream whose path is gone
// stops moving bytes, and without a bound it would sit in the list until shutdown.
const drainIdleGrace = 20 * time.Second

// How often the drain sweep re-examines connections that a transition left behind. It only runs
// while old-generation connections exist, and stops as soon as they are gone.
const drainSweepInterval = 15 * time.Second

// managedConnState is the per-connection lifecycle record the reclaim policies decide on.
//
// It is embedded in both tracked connection types, which is the only reason its methods are
// pointers: the enclosing value must implement managedConn.
type managedConnState struct {
	// createdAt is when the connection entered the list.
	createdAt time.Time
	// generation is the transition counter at that moment. A connection whose generation is behind
	// the manager's belongs to a path the device has left - a drain candidate, NOT a corpse.
	generation uint64
	// lastActive is the last observed successful byte transfer, in Unix seconds.
	//
	// Zero means no transfer has been observed YET, which is not the same as idle. How long that is
	// allowed to stand is what activityObservable decides.
	lastActive atomic.Int64
	// activityObservable is false once the connection has been handed to the kernel.
	//
	// It separates two states that "lastActive == 0" used to conflate, and they have opposite
	// reclaim policies:
	//
	//	true  (an ordinary connection)  nothing has been transferred, so the clock runs from
	//	                                createdAt. A flow that is never used is idle after the
	//	                                grace and may be reclaimed.
	//	false (kernel-owned)            bytes move between descriptors in the kernel and NOTHING in
	//	                                userspace will ever observe this connection again. Its
	//	                                silence is not evidence of idleness, so it is protected on a
	//	                                transition and reclaimed only by pause or shutdown.
	//
	// Conflating them protected every never-used UDP flow for the life of the tunnel, which turned
	// the drain into a leak.
	activityObservable atomic.Bool
}

// markKernelOwned records that this connection's bytes no longer pass through userspace.
//
// It is set ONLY on a confirmed handover - the splice call returning success - never on the
// possibility of one. A connection that merely implements SyscallConn has not been spliced, and
// treating it as unobservable would exempt it from the drain for no reason.
func (s *managedConnState) markKernelOwned() {
	s.activityObservable.Store(false)
}

func (s *managedConnState) reclaimState() *managedConnState { return s }

// touch records that this connection moved bytes.
//
// One atomic load on the common path and a store at most once a second: the reclaim policies decide
// on a scale of seconds, so sub-second precision would buy nothing and would put a store in the
// forwarding path of every single write.
func (s *managedConnState) touch() {
	now := time.Now().Unix()
	if s.lastActive.Load() != now {
		s.lastActive.Store(now)
	}
}

// countBytes is the N.CountFunc form of touch, for the packet copy paths.
//
// It exists so that packet activity is observed through the copy engine's own counting protocol
// rather than by a wrapper type in the connection chain: see packetConnectionCopy.
func (s *managedConnState) countBytes(n int64) {
	if n > 0 {
		s.touch()
	}
}

// managedConnStateOf walks a connection's upstream chain looking for the lifecycle record this
// manager attaches, and reports nil when the connection is not one of ours.
//
// The walk is necessary rather than a plain type assertion: by the time a connection reaches the
// copy loops it may sit under the dialer's power counters or a protocol's own wrapper, and asserting
// only on the outermost value would observe nothing for exactly those connections.
func managedConnStateOf(conn any) *managedConnState {
	for depth := 0; conn != nil && depth < 32; depth++ {
		if state, isManaged := conn.(interface {
			reclaimState() *managedConnState
		}); isManaged {
			return state.reclaimState()
		}
		upstream, hasUpstream := conn.(common.WithUpstream)
		if !hasUpstream {
			return nil
		}
		next := upstream.Upstream()
		if next == conn {
			return nil
		}
		conn = next
	}
	return nil
}

// idleFor reports how long the connection has been silent, and whether that is knowable at all.
//
// The false return is the important one: it says "no transfer was ever observed", which the callers
// must read as "cannot be proven idle" rather than "idle since creation".
func (s *managedConnState) idleFor(now time.Time) (time.Duration, bool) {
	if !s.activityObservable.Load() {
		// Kernel-owned: silence here is not idleness, it is the absence of an instrument.
		return 0, false
	}
	last := s.lastActive.Load()
	if last == 0 {
		// Observable and not yet used. The clock runs from creation, so a flow that never carries
		// anything becomes reclaimable once it is older than the grace rather than being protected
		// forever.
		return now.Sub(s.createdAt), true
	}
	return now.Sub(time.Unix(last, 0)), true
}

// managedConn is what the manager keeps in its list. CloseAll only ever needed io.Closer; the
// reclaim policies need to ask a connection about itself.
type managedConn interface {
	Close() error
	reclaimState() *managedConnState
}

// reclaimPolicy is the decision table, kept in one place so the reasons are comparable by reading
// rather than by tracing four call sites.
type reclaimPolicy struct {
	// provenIdleFor > 0 reclaims connections silent for at least that long.
	provenIdleFor time.Duration
	// closeAll reclaims everything, observed activity or not.
	closeAll bool
	// releaseFlows releases shaper-parked flows first, which is required whenever the sockets they
	// write to may be closed: a parked flow is not inside a write, so closing its socket would not
	// wake it.
	releaseFlows bool
	// drain marks the transition boundary and starts the sweep.
	drain bool
}

// drainGrace and sweepEvery resolve the production windows, with the test overrides applied.
func (m *ConnectionManager) drainGrace() time.Duration {
	if m.drainIdleGraceOverride > 0 {
		return m.drainIdleGraceOverride
	}
	return drainIdleGrace
}

func (m *ConnectionManager) sweepEvery() time.Duration {
	if m.drainSweepIntervalOverride > 0 {
		return m.drainSweepIntervalOverride
	}
	return drainSweepInterval
}

func reclaimPolicyFor(reason ReclaimReason) reclaimPolicy {
	switch reason {
	case ReclaimNetworkTransition:
		return reclaimPolicy{provenIdleFor: drainIdleGrace, releaseFlows: false, drain: true}
	case ReclaimIdle:
		return reclaimPolicy{provenIdleFor: drainIdleGrace, releaseFlows: false}
	case ReclaimDeadPath:
		return reclaimPolicy{closeAll: true, releaseFlows: true}
	default:
		return reclaimPolicy{closeAll: true, releaseFlows: true}
	}
}

// Reclaim applies the policy for reason and reports how many connections it closed.
//
// Note what a transition does NOT do: it does not close a connection whose activity has been
// observed recently, and it does not close one whose activity cannot be observed at all. It closes
// what it can prove is idle, marks the rest as belonging to the previous path, and leaves a sweep
// running to reclaim them as they fall silent.
func (m *ConnectionManager) Reclaim(reason ReclaimReason) int {
	policy := reclaimPolicyFor(reason)
	if policy.releaseFlows && m.scheduler != nil {
		m.scheduler.ReleaseAll()
	}
	if policy.closeAll {
		count := m.Count()
		m.CloseAll()
		return count
	}

	now := time.Now()
	var staleGeneration uint64
	if policy.drain {
		staleGeneration = m.generation.Add(1)
	}

	m.access.Lock()
	var closers []managedConn
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		conn := element.Value
		state := conn.reclaimState()
		// A drained connection is only a candidate once it belongs to a path the device has left.
		// Without this check the sweep would also reclaim connections dialled AFTER the transition,
		// which are on the network the device is actually using.
		eligible := true
		if policy.drain {
			eligible = state.generation < staleGeneration
		}
		if eligible && policy.provenIdleFor > 0 {
			if idle, known := state.idleFor(now); !known || idle < m.drainGrace() {
				eligible = false
			}
		}
		if eligible {
			closers = append(closers, conn)
			m.connections.Remove(element)
		}
		element = nextElement
	}
	m.access.Unlock()

	for _, closer := range closers {
		common.Close(closer)
	}
	if policy.drain {
		// What is left is what drained. Counted after the pass rather than before it, so the number
		// is connections this transition actually spared and not connections it happened to see.
		drained := m.Count()
		m.transitions.recordTransition(drained, len(closers))
		// Open the reconnect governor's window. The connections that were just invalidated are about
		// to be re-dialled by their applications, all at once; this is the burst it smooths.
		m.dialGovernor.open(time.Now())
		// Only worth starting when the pass left something behind; otherwise there is nothing for a
		// sweep to find.
		if drained > 0 {
			m.beginDrainSweep()
		}
		if m.reclaimLog != nil {
			m.reclaimLog(reason, len(closers), staleGeneration)
		}
	}
	return len(closers)
}

// beginDrainSweep keeps reclaiming connections the transition left behind until none are left.
//
// Drain that never ends is a leak, and drain that ends on a timer kills working connections. The
// sweep is how both are avoided at once: it re-asks the same question as the immediate pass - is
// this connection provably idle? - so a stream that is still transferring is never reclaimed no
// matter how long ago the transition was, and one that has fallen silent is reclaimed promptly.
func (m *ConnectionManager) beginDrainSweep() {
	m.sweepAccess.Lock()
	defer m.sweepAccess.Unlock()
	if m.sweepTimer != nil {
		return
	}
	m.scheduleDrainSweepLocked()
}

func (m *ConnectionManager) scheduleDrainSweepLocked() {
	m.sweepTimer = time.AfterFunc(m.sweepEvery(), func() {
		m.sweepAccess.Lock()
		m.sweepTimer = nil
		m.sweepAccess.Unlock()
		remaining := m.sweepStaleConnections()
		if remaining {
			m.sweepAccess.Lock()
			// Only if nothing else restarted it, and only while the manager is alive.
			if m.sweepTimer == nil && !m.closed.Load() {
				m.scheduleDrainSweepLocked()
			}
			m.sweepAccess.Unlock()
		}
	})
}

// sweepStaleConnections reclaims provably idle connections from previous generations and reports
// whether any old-generation connection is still held.
func (m *ConnectionManager) sweepStaleConnections() bool {
	now := time.Now()
	current := m.generation.Load()
	m.access.Lock()
	var closers []managedConn
	remaining := false
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		conn := element.Value
		state := conn.reclaimState()
		if state.generation < current {
			if idle, known := state.idleFor(now); known && idle >= m.drainGrace() {
				closers = append(closers, conn)
				m.connections.Remove(element)
				element = nextElement
				continue
			}
			remaining = true
		}
		element = nextElement
	}
	m.access.Unlock()
	for _, closer := range closers {
		common.Close(closer)
	}
	if len(closers) > 0 {
		m.transitions.recordSweep(len(closers))
		if m.reclaimLog != nil {
			m.reclaimLog(ReclaimNetworkTransition, len(closers), current)
		}
	}
	return remaining
}

// stopDrainSweep is called from Close: a timer that fires into a torn-down manager would be a use
// after the lifecycle that owns it has ended.
func (m *ConnectionManager) stopDrainSweep() {
	m.sweepAccess.Lock()
	defer m.sweepAccess.Unlock()
	if m.sweepTimer != nil {
		m.sweepTimer.Stop()
		m.sweepTimer = nil
	}
}

// networkTransitionReclaimer is the capability resetNetworkLocked asks for.
//
// It lives here rather than on adapter.ConnectionManager because the reason is a route-level policy
// decision: the adapter interface describes what a connection manager IS, and this describes what
// this fork's network lifecycle additionally does with one. Asking for the capability keeps the
// drain from becoming a breaking change for every implementation that has no reclaim policy - those
// keep the previous, conservative "close everything" semantics.
type networkTransitionReclaimer interface {
	Reclaim(reason ReclaimReason) int
}
