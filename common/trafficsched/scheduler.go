package trafficsched

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
)

// lane is one of the two service classes the scheduler arbitrates between.
type lane uint8

const (
	laneHigh lane = iota
	laneNormal
	laneCount
)

// Mode selects what the scheduler controls, which is the design question "gate admission, or own
// the service slot?". Both are implemented because the answer is a measurement, not an opinion;
// see the package benchmark for the numbers and the conclusion.
type Mode uint8

const (
	// ModeAdmission is the cheap model. A high-priority write is never delayed; a NORMAL write is
	// admitted only while no high-priority write is in flight, so NORMAL yields to work that has
	// already started. It touches nothing that is already buffered in the kernel, so it can only
	// change who starts next, never what is already queued.
	ModeAdmission Mode = iota

	// ModeService is the strict model. The scheduler owns a single service slot: exactly one
	// managed write is in flight at any instant, and the next slot is granted by lane - high
	// priority first, with one NORMAL grant forced after every HighPerNormal high-priority grants
	// so a saturated high-priority lane cannot starve NORMAL. It bounds how much NORMAL data can
	// be handed to the outbound between two high-priority writes, at the cost of serialising
	// every managed write.
	ModeService

	// ModePaced is the only model that changes how much NORMAL data is ALREADY queued ahead of a
	// high-priority write, rather than only who starts next. The NORMAL lane may admit at most
	// NormalRate bytes per second, accumulated into a NormalBurst byte burst, and only while the
	// scheduler is armed. High-priority traffic is never paced.
	//
	// It is the model with a physical argument behind it and the model with a real cost: a rate
	// set below the uplink's real capacity is a throughput loss on bulk traffic, so it is only
	// useful when the rate can be known or learned. See the package benchmark for the measured
	// difference between this and the other two.
	ModePaced
)

// DefaultHighIdleWindow is how long NORMAL traffic stays scheduled after the last high-priority
// write.
//
// This is a product knob, not a mechanism. While armed, NORMAL writes are arbitrated; while
// disarmed every flow takes the immediate path and the scheduler is pure pass-through. A window
// shorter than the gap between two interactive requests would disarm between them and let the
// queue refill with exactly the traffic the window exists to keep short.
const DefaultHighIdleWindow = 2 * time.Second

// DefaultHighPerNormal is how many consecutive high-priority grants are served before one NORMAL
// grant is forced.
//
// It is the whole priority policy: high-priority traffic is preferred, and NORMAL traffic keeps a
// guaranteed floor so it cannot be starved by a saturated high-priority lane. The value bounds
// how many NORMAL writes may be started between two high-priority writes.
const DefaultHighPerNormal = 4

// DefaultNormalBurst is the byte burst the NORMAL lane may accumulate while pacing.
const DefaultNormalBurst = 64 * 1024

// paceTick is how often the pacing mode refills its token bucket and re-runs the grant loop.
// It is only ever running while the scheduler is armed.
const paceTick = time.Millisecond

// Options configures a Scheduler. The zero value is usable and selects the defaults.
type Options struct {
	Mode           Mode
	HighPerNormal  int
	HighIdleWindow time.Duration
	// NormalRate is the NORMAL lane's admission rate in bytes per second, used by ModePaced.
	// Zero means the lane is not paced.
	NormalRate int64
	// NormalBurst is the byte burst the paced NORMAL lane may accumulate.
	NormalBurst int
}

func (o Options) withDefaults() Options {
	if o.HighPerNormal <= 0 {
		o.HighPerNormal = DefaultHighPerNormal
	}
	if o.HighIdleWindow <= 0 {
		o.HighIdleWindow = DefaultHighIdleWindow
	}
	if o.NormalBurst <= 0 {
		o.NormalBurst = DefaultNormalBurst
	}
	return o
}

// Scheduler arbitrates the upload write path of every managed flow.
//
// # Lifetime
//
// One scheduler is shared by every flow of one box, because contention is a property of the
// shared uplink and never of one connection: a per-connection scheduler would have nothing to
// arbitrate. It is owned by the connection manager, which creates and finalises flows.
//
// # Cost when nothing contends
//
// A NORMAL flow with no recent high-priority activity takes one atomic load and returns: nothing
// is enqueued, nothing is locked, nothing is allocated. That is what makes it safe to leave
// installed. It is also deliberately behavioural rather than configuration-gated: a scheduler
// that is off by default is a scheduler nobody measures.
type Scheduler struct {
	options Options

	// armed is set while a high-priority flow has written recently. It is the fast-path
	// predicate, read once per NORMAL write, which is why it is an atomic.Bool rather than a
	// clock reading.
	armed          atomic.Bool
	highLastActive atomic.Int64

	closeOnce sync.Once
	closeCh   chan struct{}

	mu         sync.Mutex
	cond       *sync.Cond
	closed     bool
	lanes      [laneCount]laneState
	flows      map[*Flow]struct{}
	highStreak int
	// inflightService counts the single service slot in ModeService.
	inflightService int
	// highInflight counts high-priority writes in progress in ModeAdmission, which is what a
	// NORMAL write yields to.
	highInflight int
	// normalTokens is the paced NORMAL lane's byte credit, refilled from normalLastRefill.
	normalTokens     float64
	normalLastRefill time.Time
}

type laneState struct {
	queue []*Flow
	// head avoids an O(n) shift per grant without a ring buffer of its own.
	head int
}

func (l *laneState) empty() bool { return l.head >= len(l.queue) }

func (l *laneState) push(f *Flow) { l.queue = append(l.queue, f) }

func (l *laneState) pop() *Flow {
	if l.empty() {
		return nil
	}
	f := l.queue[l.head]
	l.queue[l.head] = nil
	l.head++
	if l.empty() {
		l.queue = l.queue[:0]
		l.head = 0
	}
	return f
}

// remove takes f out of the queue. It is used by Flow.Close, which must be able to release a
// parked flow from another goroutine.
func (l *laneState) remove(f *Flow) bool {
	for index := l.head; index < len(l.queue); index++ {
		if l.queue[index] == f {
			copy(l.queue[index:], l.queue[index+1:])
			l.queue = l.queue[:len(l.queue)-1]
			if l.empty() {
				l.queue = l.queue[:0]
				l.head = 0
			}
			return true
		}
	}
	return false
}

// NewScheduler creates a scheduler. It allocates nothing per flow and starts no goroutine until a
// high-priority flow actually writes.
func NewScheduler(options Options) *Scheduler {
	scheduler := &Scheduler{
		options: options.withDefaults(),
		closeCh: make(chan struct{}),
		flows:   make(map[*Flow]struct{}),
	}
	scheduler.cond = sync.NewCond(&scheduler.mu)
	scheduler.normalTokens = float64(scheduler.options.NormalBurst)
	scheduler.normalLastRefill = time.Now()
	return scheduler
}

// NewFlow registers a logical flow and returns its scheduler handle.
//
// The class is fixed for the life of the flow. It is resolved once from the outbound chain, and
// the scheduler stays blind to why: it never sees a tag, a protocol or a destination.
func (s *Scheduler) NewFlow(class trafficclass.Class) *Flow {
	flow := &Flow{sched: s, high: class.IsHighPriority()}
	flow.lane = laneNormal
	if flow.high {
		flow.lane = laneHigh
	}
	s.mu.Lock()
	s.flows[flow] = struct{}{}
	s.mu.Unlock()
	return flow
}

// Armed reports whether high-priority activity is recent enough for NORMAL traffic to be
// scheduled. Exported for tests and diagnostics.
func (s *Scheduler) Armed() bool { return s.armed.Load() }

// AdmittedBytes reports how many bytes have passed through the gate for this flow.
//
// It is the only way to tell a scheduler that is really in the write path from one that was
// silently unwrapped away: both look identical from the outside, and only the second means the
// feature does nothing.
func (f *Flow) AdmittedBytes() int64 {
	if f == nil {
		return 0
	}
	return f.admitted.Load()
}

// Flow is one managed flow's handle on the scheduler.
//
// wait and done are confined to the flow's copy goroutine: only one write per flow can be in
// flight, because the copy loop that owns it is sequential. Close is the exception and is safe
// from any goroutine, which is what lets a shutdown release a flow parked in the scheduler.
type Flow struct {
	sched *Scheduler
	lane  lane
	high  bool

	// admitted counts the bytes this flow has handed to the outbound through the gate. It is
	// per-flow, so the atomic is uncontended; it exists because "did the bytes really pass
	// through the scheduler" is otherwise unobservable, and a scheduler that silently stopped
	// being in the path would look exactly like a working one.
	admitted atomic.Int64

	// grants counts the writes the scheduler actually arbitrated, as opposed to the ones that
	// took the uncontended fast path. It is incremented on the slow path only, so the fast path
	// pays for exactly one atomic add.
	grants atomic.Int64

	// pending and gated belong to the owning copy goroutine. pending is additionally read under
	// s.mu by the grant loop.
	pending int
	gated   bool

	// holdsSlot is true between a grant and its release, and is the field the slot bookkeeping
	// turns on. It is NOT the same as gated: gated records that this wait took the scheduled
	// path, while holdsSlot records that the flow currently owns a slot and must hand it back -
	// which Close has to be able to do from another goroutine after wait has already returned.
	//
	// It is written under s.mu.
	holdsSlot bool
	// queuedAt is when the flow last entered its lane, used by the paced lane's starvation
	// escape hatch. Written under s.mu.
	queuedAt time.Time
	// closed is written under s.mu.
	closed bool
}

// wait blocks until the flow may hand n bytes to the outbound.
//
// The fast path is the reason the scheduler can be left installed: a NORMAL flow whose lane is not
// contended returns after one atomic load.
func (f *Flow) wait(n int) error {
	if f == nil {
		return nil
	}
	f.admitted.Add(int64(n))
	if !f.high && !f.sched.armed.Load() {
		return nil
	}
	if f.sched.inert() {
		return nil
	}
	return f.sched.waitSlow(f, n)
}

// inert reports whether the scheduler is installed but deliberately not scheduling.
//
// This is the production default. The contention experiment measured that the models which only
// reorder writes buy nothing, so the honest configuration is one that provably does nothing until
// a rate the path actually sustains is available: the gate still observes every byte, but no
// flow is ever queued, no lock is ever taken and no disarm goroutine ever starts.
func (s *Scheduler) inert() bool {
	return s.options.Mode == ModePaced && s.options.NormalRate <= 0
}

// done releases the service slot the flow holds, if any.
//
// It must run exactly once per successful wait, whatever the write returned: an upstream error
// does not free the slot by itself, and leaking it would stall the lane for every other flow.
func (f *Flow) done() {
	if f == nil || !f.gated {
		return
	}
	f.gated = false
	s := f.sched
	s.mu.Lock()
	if f.holdsSlot {
		s.releaseGrantLocked(f)
		s.grantLocked()
	}
	s.mu.Unlock()
}

// Close unregisters the flow and releases anything parked on it. It is idempotent and safe to
// call from any goroutine.
func (f *Flow) Close() error {
	if f == nil {
		return nil
	}
	s := f.sched
	s.mu.Lock()
	if _, registered := s.flows[f]; !registered {
		s.mu.Unlock()
		return nil
	}
	delete(s.flows, f)
	f.closed = true
	for laneIndex := range s.lanes {
		s.lanes[laneIndex].remove(f)
	}
	if f.holdsSlot {
		// A granted flow that never reached its write still owns a slot.
		s.releaseGrantLocked(f)
	}
	s.grantLocked()
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

// Close shuts the scheduler down and releases every parked flow with ErrClosed.
func (s *Scheduler) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.mu.Lock()
		s.closed = true
		for laneIndex := range s.lanes {
			s.lanes[laneIndex].queue = nil
			s.lanes[laneIndex].head = 0
		}
		s.inflightService = 0
		s.highInflight = 0
		s.flows = make(map[*Flow]struct{})
		s.cond.Broadcast()
		s.mu.Unlock()
	})
	return nil
}

func (s *Scheduler) waitSlow(f *Flow, n int) error {
	s.mu.Lock()
	if s.closed || f.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	f.pending = n
	f.gated = true
	f.grants.Add(1)
	f.queuedAt = time.Now()
	s.refillLocked()
	s.lanes[f.lane].push(f)
	s.grantLocked()
	for !f.holdsSlot && !s.closed && !f.closed {
		s.cond.Wait()
	}
	if s.closed || f.closed {
		// The flow is being torn down. If it was granted in the same instant, the grant has to
		// be handed back here or the lane would stall on a slot nobody owns.
		if f.holdsSlot {
			s.releaseGrantLocked(f)
			s.grantLocked()
		}
		f.gated = false
		s.mu.Unlock()
		return ErrClosed
	}
	s.mu.Unlock()
	return nil
}

// releaseGrantLocked undoes the bookkeeping a grant performed. It must be called exactly once per
// grant, from done() on the normal path and from waitSlow/Close when a grant is abandoned.
func (s *Scheduler) releaseGrantLocked(f *Flow) {
	f.holdsSlot = false
	switch s.options.Mode {
	case ModeAdmission:
		if f.high {
			s.highInflight--
		}
	case ModePaced:
		// The credit was spent at admission; there is nothing to give back.
	default:
		s.inflightService--
	}
}

// refillLocked advances the paced NORMAL lane's token bucket to the current time.
func (s *Scheduler) refillLocked() {
	if s.options.Mode != ModePaced || s.options.NormalRate <= 0 {
		return
	}
	now := time.Now()
	elapsed := now.Sub(s.normalLastRefill)
	if elapsed <= 0 {
		return
	}
	s.normalLastRefill = now
	s.normalTokens += float64(s.options.NormalRate) * elapsed.Seconds()
	if s.normalTokens > float64(s.options.NormalBurst) {
		s.normalTokens = float64(s.options.NormalBurst)
	}
}

// pacedLaneReadyLocked reports whether the NORMAL lane's head write may start.
//
// A write no larger than the burst is always eventually coverable, and the refill timer runs every
// paceTick, so waiting is bounded by the bucket's own refill - no escape hatch is needed or wanted,
// because an escape hatch is exactly what would let the queue refill.
//
// A write LARGER than the whole burst can never be covered and would wait forever. That case is
// admitted immediately: it is a single oversized write, it happens at most once per such write,
// and the alternative is a deadlock.
func (s *Scheduler) pacedLaneReadyLocked() bool {
	next := s.lanes[laneNormal].queue[s.lanes[laneNormal].head]
	if next.pending > s.options.NormalBurst {
		return true
	}
	return s.normalTokens >= float64(next.pending)
}

// grantLocked hands out as many permits as the current mode allows.
//
// It runs with s.mu held, from every point that can create capacity: a new waiter, a completed
// write, a closed flow.
func (s *Scheduler) grantLocked() {
	for !s.closed {
		laneIndex := s.pickLocked()
		if laneIndex < 0 {
			return
		}
		l := &s.lanes[laneIndex]
		flow := l.pop()
		if flow == nil {
			return
		}
		if laneIndex == int(laneHigh) && l.empty() {
			s.highStreak = 0
		}
		flow.holdsSlot = true
		if flow.high {
			s.arm()
		}
		switch s.options.Mode {
		case ModeAdmission:
			if flow.high {
				s.highInflight++
			}
		case ModePaced:
			if !flow.high {
				s.normalTokens -= float64(flow.pending)
				if s.normalTokens < 0 {
					s.normalTokens = 0
				}
			}
		default:
			s.inflightService++
		}
		s.cond.Broadcast()
	}
}

// pickLocked chooses the next lane to serve, or -1 when nothing can be served right now.
//
// Within a lane the queue is FIFO round-robin, so one large flow cannot starve a small one: a
// granted flow that wants to write again goes to the back of its lane.
func (s *Scheduler) pickLocked() int {
	highReady := !s.lanes[laneHigh].empty()
	normalReady := !s.lanes[laneNormal].empty()
	switch s.options.Mode {
	case ModePaced:
		// High priority is never paced; the NORMAL lane may only start a write its credit
		// already covers, which is what keeps bulk data out of the shared queue rather than
		// merely reordering it.
		if highReady {
			return int(laneHigh)
		}
		if !normalReady {
			return -1
		}
		if s.options.NormalRate <= 0 || !s.armed.Load() || s.pacedLaneReadyLocked() {
			return int(laneNormal)
		}
		return -1
	case ModeAdmission:
		// High-priority writes are never delayed; a NORMAL write waits only while a
		// high-priority write is actually in flight.
		if highReady {
			return int(laneHigh)
		}
		if normalReady && s.highInflight == 0 {
			return int(laneNormal)
		}
		return -1
	default:
		// The single service slot is free only if nothing is in flight.
		if s.serviceSlotBusy() {
			return -1
		}
		switch {
		case highReady && (!normalReady || s.highStreak < s.options.HighPerNormal):
			if normalReady {
				s.highStreak++
			}
			return int(laneHigh)
		case normalReady:
			s.highStreak = 0
			return int(laneNormal)
		case highReady:
			return int(laneHigh)
		default:
			return -1
		}
	}
}

// serviceSlotBusy reports whether the single ModeService slot is taken.
func (s *Scheduler) serviceSlotBusy() bool { return s.inflightService > 0 }

// arm records high-priority activity and starts the disarm timer if it is not already running.
func (s *Scheduler) arm() {
	s.highLastActive.Store(time.Now().UnixNano())
	if s.armed.CompareAndSwap(false, true) {
		go s.disarmLoop()
	}
}

// disarmLoop clears the armed flag once high-priority activity has been idle for the window.
//
// One goroutine exists while the scheduler is armed, and none while it is not, so a configuration
// with no interactive traffic pays nothing beyond one atomic load per NORMAL write.
func (s *Scheduler) disarmLoop() {
	interval := s.options.HighIdleWindow / 8
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	if s.options.Mode == ModePaced && s.options.NormalRate > 0 && interval > paceTick {
		// The paced lane needs a refill and a grant attempt on a fine timer; the disarm timer is
		// too coarse to be the only thing that ever releases a NORMAL write.
		interval = paceTick
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-timer.C:
		}
		if s.options.Mode == ModePaced && s.options.NormalRate > 0 {
			s.mu.Lock()
			s.refillLocked()
			s.grantLocked()
			s.mu.Unlock()
		}
		if s.idleFor() < s.options.HighIdleWindow {
			timer.Reset(interval)
			continue
		}
		s.armed.Store(false)
		// Disarming must also release anything parked on the pacer. The paced lane holds a write
		// back on credit, not on a slot, so a parked NORMAL flow has nobody else to wake it.
		s.mu.Lock()
		s.grantLocked()
		s.mu.Unlock()
		// A high-priority grant may have landed between the check and the store. If it did, this
		// goroutine takes responsibility for the re-arm, and the CompareAndSwap guarantees that
		// exactly one goroutine owns each arm.
		if s.idleFor() < s.options.HighIdleWindow {
			if s.armed.CompareAndSwap(false, true) {
				timer.Reset(interval)
				continue
			}
			return
		}
		return
	}
}

func (s *Scheduler) idleFor() time.Duration {
	last := s.highLastActive.Load()
	if last == 0 {
		return time.Duration(1<<62 - 1)
	}
	return time.Since(time.Unix(0, last))
}
