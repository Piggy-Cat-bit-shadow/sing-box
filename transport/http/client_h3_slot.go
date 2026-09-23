//go:build with_quic

package http

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

// Pool slot health model.
//
// A pool slot wraps ONE QUIC connection to the MASQUE authority. The states
// below exist because "the connection context is alive" is NOT sufficient to
// decide whether a slot can carry a new tunnel. That was measured, not assumed:
// after the server sends GOAWAY the connection context still reports nil, while
// OpenRequestStream fails with "connection in graceful shutdown". A pool that
// only checked the context would keep assigning tunnels to a connection that
// can never accept them.
//
// The state machine:
//
//	healthy  -> usable for new tunnels
//	draining -> GOAWAY received; existing tunnels live on, no NEW tunnels
//	cooldown -> recently failed to establish; skipped until the deadline
//	dead     -> connection unusable; replaced by a fresh slot
//
// Only `healthy` is eligible for a new tunnel.
type http3SlotState int

const (
	http3SlotHealthy http3SlotState = iota
	http3SlotDraining
	http3SlotCooldown
	http3SlotDead
)

func (s http3SlotState) String() string {
	switch s {
	case http3SlotHealthy:
		return "healthy"
	case http3SlotDraining:
		return "draining"
	case http3SlotCooldown:
		return "cooldown"
	case http3SlotDead:
		return "dead"
	default:
		return "unknown"
	}
}

// http3PoolSlot is one independently congestion-controlled QUIC connection.
//
// Every mutable field is guarded by access. The earlier revision guarded only
// the connection fields and kept active-tunnel accounting out of the struct
// entirely, which made least-active selection impossible to implement safely.
type http3PoolSlot struct {
	transport *http3.Transport
	access    sync.Mutex

	conn     *http3.ClientConn
	quicConn *quic.Conn
	rawConn  net.Conn

	quicConfig *quic.Config

	// state drives selection. See the state machine comment above.
	state http3SlotState
	// active counts logical proxy tunnels currently held by callers. It is
	// incremented only AFTER a stream is successfully opened, and decremented
	// exactly once per tunnel, so a failed open can never leak a count.
	active int
	// consecutiveFailures and lastFailure drive the cooldown decision.
	consecutiveFailures int
	lastFailure         time.Time
	// cooldownUntil is when a cooldown slot becomes eligible again.
	cooldownUntil time.Time
	// created and lastUsed support idle shrink and tie-breaking.
	created  time.Time
	lastUsed time.Time
	// drainingSince records when GOAWAY was observed, for logging and tests.
	drainingSince time.Time
}

// http3SlotHealth is a read-only snapshot for selection, logging and tests.
type http3SlotHealth struct {
	State               http3SlotState
	Active              int
	ConsecutiveFailures int
	LastFailure         time.Time
	Created             time.Time
	LastUsed            time.Time
	DrainingSince       time.Time
	// Connected reports whether a ClientConn object exists and its context is
	// alive. It is NOT sufficient for health on its own; see the state machine.
	Connected bool
}

// health reads the slot's state under its lock.
func (s *http3PoolSlot) health() http3SlotHealth {
	s.access.Lock()
	defer s.access.Unlock()
	connected := s.conn != nil && s.conn.Context().Err() == nil
	return http3SlotHealth{
		State:               s.state,
		Active:              s.active,
		ConsecutiveFailures: s.consecutiveFailures,
		LastFailure:         s.lastFailure,
		Created:             s.created,
		LastUsed:            s.lastUsed,
		DrainingSince:       s.drainingSince,
		Connected:           connected,
	}
}

// eligible reports whether a new tunnel may be assigned to this slot.
//
// A cooldown slot becomes eligible again once its deadline passes, which is what
// lets a transiently failing slot recover without the authority being poisoned.
func (s *http3PoolSlot) eligible(now time.Time) bool {
	s.access.Lock()
	defer s.access.Unlock()
	switch s.state {
	case http3SlotHealthy:
		return true
	case http3SlotCooldown:
		return !now.Before(s.cooldownUntil)
	case http3SlotDraining, http3SlotDead:
		// A draining slot must never take a new tunnel, even after its existing
		// tunnels finish: quic-go closes the connection once streams empty.
		return false
	default:
		return false
	}
}

// acquireActive records that a logical tunnel now occupies this slot.
//
// It is called ONLY after a request stream was successfully opened, so the
// count reflects real tunnels rather than attempts.
func (s *http3PoolSlot) acquireActive() {
	s.access.Lock()
	s.active++
	s.lastUsed = time.Now()
	s.access.Unlock()
}

// releaseActive decrements the active count exactly once per tunnel.
//
// Callers wrap it in sync.Once, so a double Close cannot double-decrement.
func (s *http3PoolSlot) releaseActive() {
	s.access.Lock()
	if s.active > 0 {
		s.active--
	}
	s.access.Unlock()
}

// markDraining moves the slot out of rotation without disturbing existing
// tunnels. Called when GOAWAY is observed, i.e. when OpenRequestStream reports
// that the connection is in graceful shutdown.
func (s *http3PoolSlot) markDraining(reason error) (changed bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.state == http3SlotDraining || s.state == http3SlotDead {
		return false
	}
	s.state = http3SlotDraining
	s.drainingSince = time.Now()
	s.lastFailure = time.Now()
	_ = reason
	return true
}

// markFailure records an establishment or open failure and applies a cooldown.
//
// A failure does NOT make the slot dead on its own: a single transient error
// must not remove capacity, so the slot goes to cooldown and returns later.
// Only repeated failures or an unusable connection escalate to dead.
func (s *http3PoolSlot) markFailure(now time.Time, cooldown time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	s.consecutiveFailures++
	s.lastFailure = now
	if s.state == http3SlotDead || s.state == http3SlotDraining {
		return
	}
	s.state = http3SlotCooldown
	s.cooldownUntil = now.Add(cooldown)
}

// markHealthy clears failure history after a confirmed success.
func (s *http3PoolSlot) markHealthy() {
	s.access.Lock()
	defer s.access.Unlock()
	s.state = http3SlotHealthy
	s.consecutiveFailures = 0
	s.cooldownUntil = time.Time{}
	s.lastUsed = time.Now()
}

// markDead permanently retires the slot for this pool generation.
func (s *http3PoolSlot) markDead() {
	s.access.Lock()
	defer s.access.Unlock()
	s.state = http3SlotDead
}

// shouldClose reports whether the slot can be closed and dropped.
//
// A draining slot is only closed once it has no active tunnels, because it still
// carries live traffic. A dead slot can go immediately.
func (s *http3PoolSlot) shouldClose() bool {
	s.access.Lock()
	defer s.access.Unlock()
	switch s.state {
	case http3SlotDead:
		return true
	case http3SlotDraining:
		return s.active == 0
	default:
		return false
	}
}

// h3GoAwayErrorText is the exact message quic-go returns from
// OpenRequestStream once a GOAWAY has been received.
//
// It is matched by string because quic-go's errGoAway is unexported
// (http3/client.go: `var errGoAway = errors.New("connection in graceful
// shutdown")`), so there is no sentinel to compare against. The message was
// MEASURED on the exact call path this client uses (a pooled ClientConn plus
// OpenRequestStream after http3.Server.Shutdown), not inferred:
//
//	OpenRequestStream ERR_TEXT="connection in graceful shutdown" TYPE=*errors.errorString
//
// If a future quic-go changes this string the detection degrades to "not
// detected", which is a missed optimisation rather than a correctness bug: the
// slot then fails at open time and is handled by the failure path instead.
const h3GoAwayErrorText = "connection in graceful shutdown"

// isGoAwayError reports whether an error means the connection is draining.
func isGoAwayError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), h3GoAwayErrorText)
}

// logPoolEvent emits a debug-level pool lifecycle event.
//
// Every event is DEBUG, never INFO: a pool that logged each slot transition at
// info level would produce steady noise on a busy server, and none of these are
// operator-actionable events. Passing nil logger is supported so a client built
// without one stays silent instead of panicking.
func (c *http3ClientImpl) logPoolEvent(event string, slot *http3PoolSlot, err error) {
	if c.logger == nil {
		return
	}
	health := slot.health()
	args := []any{
		event,
		" state=", health.State,
		" active=", health.Active,
		" failures=", health.ConsecutiveFailures,
	}
	if err != nil {
		args = append(args, " err=", err)
	}
	c.logger.Debug(args...)
}

// totalActive reports how many live tunnels the whole pool carries. It exists
// for tests and for the diagnostic snapshot; a leaked count here means
// least-active selection is silently avoiding a slot.
func (c *http3ClientImpl) totalActive() int {
	total := 0
	for _, slot := range c.slots {
		total += slot.health().Active
	}
	return total
}
