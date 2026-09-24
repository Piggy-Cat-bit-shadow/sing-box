package http

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

// unauthenticatedLimiter bounds unauthenticated traffic per source IP. It is
// only consulted before a request has authenticated, so it can never throttle
// legitimate proxy traffic.
//
// The key is the normalized source IP without the port, so a single host
// cannot multiply its budget by opening many connections. The map is bounded
// by maxTracked and entries expire after idleTimeout, so an attacker sending
// from random addresses cannot grow the map without bound.
// cleanupInterval is how many acquired slots pass between full expiry sweeps.
//
// Sweeping on every request made acquire O(tracked IPs) per request, so with
// max_tracked_ips=4096 every request scanned 4096 entries under the mutex. Expiry
// is now amortized: a sweep runs periodically and whenever the map approaches its
// cap, which keeps memory bounded without paying O(n) on the hot path.
const cleanupInterval = 256

type unauthenticatedLimiter struct {
	access sync.Mutex
	limits option.UnauthenticatedLimits
	states map[netip.Addr]*unauthenticatedState
	// acquisitions counts acquire calls since the last sweep. It is read and
	// written only under access.
	acquisitions int
	// accounted counts every request the limiter has accounted, including a
	// failed authentication that was admitted. It exists for tests and is only
	// ever mutated under access, so it adds no lock traffic on the hot path.
	accounted int
	// entriesVisited counts the state entries expireLocked has walked. It exists
	// for tests: it is the direct measurement of the amortized-expiry claim,
	// which is that a single request must not pay O(tracked IPs). Like the
	// counters above it is only mutated under access.
	entriesVisited int
	// capRejections counts new-source admissions refused because the map was
	// already full. It exists for tests, to prove the full-map path fails closed
	// in constant time instead of running a per-request eviction scan.
	capRejections int
	// atCapSweeps counts consecutive at-cap requests since the last sweep on the
	// full-map path. It rate-limits that sweep so a flood of new sources cannot
	// force an O(tracked IPs) scan per request.
	atCapSweeps int
}

type unauthenticatedState struct {
	// concurrent counts requests currently being served for this IP.
	concurrent int
	// tokens is the current token bucket level, burst being the maximum.
	tokens float64
	// lastRefill is when tokens were last topped up.
	lastRefill time.Time
	// lastSeen drives idle expiry.
	lastSeen time.Time
}

func newUnauthenticatedLimiter(limits option.UnauthenticatedLimits) *unauthenticatedLimiter {
	if !limits.Enabled {
		return nil
	}
	if limits.MaxTrackedIPs <= 0 {
		limits.MaxTrackedIPs = option.DefaultUnauthenticatedMaxTrackedIPs
	}
	if limits.IdleTimeout <= 0 {
		limits.IdleTimeout = option.DefaultUnauthenticatedIdleTimeout
	}
	return &unauthenticatedLimiter{
		limits: limits,
		states: make(map[netip.Addr]*unauthenticatedState),
	}
}

// normalizedIP converts a source address to a comparable key. IPv4-mapped IPv6
// addresses are unwrapped so that "::ffff:1.2.3.4" and "1.2.3.4" share one
// budget, and the port is dropped entirely.
func normalizedIP(source string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(source)
	if err != nil {
		host = source
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	if address.Is4In6() {
		address = address.Unmap()
	}
	return address, true
}

// acquire records an unauthenticated request and reports whether it is allowed.
// The returned release function must be called when the request finishes.
func (l *unauthenticatedLimiter) acquire(source string, now time.Time) (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	address, valid := normalizedIP(source)
	if !valid {
		// An unparseable source cannot be attributed; fail open rather than
		// blocking traffic that the limiter cannot reason about.
		return func() {}, true
	}
	l.access.Lock()
	defer l.access.Unlock()
	l.accounted++
	// Amortized expiry. The sweep must NOT also be forced merely because the map
	// is at its cap: with the cap reached and a flood of new sources arriving,
	// "at the cap" is true on every single request, which would make expireLocked
	// an O(tracked IPs) scan per request -- exactly the amplification the
	// amortized design exists to remove. The at-cap case is instead handled once
	// below, when a NEW source actually needs admitting.
	l.acquisitions++
	if l.acquisitions >= cleanupInterval {
		l.acquisitions = 0
		l.expireLocked(now)
	}
	state, loaded := l.states[address]
	if !loaded {
		// The map is full and this source is new. Run ONE expiry sweep and then
		// fail closed rather than scanning per request.
		//
		// The previous behaviour evicted an entry to make room, which meant a
		// flood of random source addresses turned every request into an O(n)
		// candidate scan plus a partial selection sort, all while holding
		// l.access. Since a source that keeps changing its address can never
		// build a meaningful token budget anyway, admitting it buys nothing:
		// refusing it is both cheaper and stricter.
		//
		// Note this only affects NEW unauthenticated sources. Already-tracked
		// sources keep their own token and concurrency state, so an attacker
		// cannot reset an existing source's budget by filling the map.
		if len(l.states) >= l.limits.MaxTrackedIPs {
			// At the cap. Sweep for genuinely idle entries, but only on the
			// amortized cadence: sweeping on every at-cap request would
			// reintroduce O(tracked IPs) per request precisely when the map is
			// full, which is the state an address-flooding source is trying to
			// create.
			l.atCapSweeps++
			if l.atCapSweeps >= cleanupInterval {
				l.atCapSweeps = 0
				l.expireLocked(now)
			}
			if len(l.states) >= l.limits.MaxTrackedIPs {
				l.capRejections++
				return func() {}, false
			}
		}
		state = &unauthenticatedState{
			tokens:     float64(l.limits.Burst),
			lastRefill: now,
			lastSeen:   now,
		}
		l.states[address] = state
	}
	// Refill the token bucket for the elapsed time.
	elapsed := now.Sub(state.lastRefill)
	if elapsed > 0 {
		state.tokens += elapsed.Seconds() * l.limits.RequestsPerSecond
		if state.tokens > float64(l.limits.Burst) {
			state.tokens = float64(l.limits.Burst)
		}
		state.lastRefill = now
	}
	state.lastSeen = now
	if state.tokens < 1 {
		return func() {}, false
	}
	if state.concurrent >= l.limits.MaxConcurrentPerIP {
		return func() {}, false
	}
	state.tokens--
	state.concurrent++
	// The release below is ONE-SHOT PER ACQUISITION.
	//
	// Decrementing whatever slot the IP currently holds is not enough: with
	// max_concurrent_per_ip=2, request A and request B can both be admitted, and
	// then a double A.release() would decrement a second time and hand B's slot
	// away, letting a third request in while B is still running. The guard
	// "current.concurrent > 0" only stops the counter going negative; it does
	// not make the release idempotent.
	//
	// sync.Once ties the decrement to THIS acquisition, so calling release any
	// number of times has the effect of calling it exactly once. It adds no
	// global locking to the hot path: the only shared state is the release's own
	// once flag, and the decrement itself takes the same l.access it always did.
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			l.access.Lock()
			defer l.access.Unlock()
			if current, ok := l.states[address]; ok && current.concurrent > 0 {
				current.concurrent--
			}
		})
	}, true
}

// allowed is a convenience wrapper for callers that do not need to hold a slot.
func (l *unauthenticatedLimiter) allowed(source string, now time.Time) bool {
	release, ok := l.acquire(source, now)
	if !ok {
		return false
	}
	release()
	return true
}

// expireLocked drops entries that have been idle for longer than the timeout
// and are not currently serving a request.
func (l *unauthenticatedLimiter) expireLocked(now time.Time) {
	deadline := now.Add(-l.limits.IdleTimeout)
	l.entriesVisited += len(l.states)
	for address, state := range l.states {
		if state.concurrent == 0 && state.lastSeen.Before(deadline) {
			delete(l.states, address)
		}
	}
}

// visitedCount reports how many state entries expiry sweeps have walked. It
// exists for tests.
func (l *unauthenticatedLimiter) visitedCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.entriesVisited
}

// accountedCount reports how many requests the limiter has accounted. It exists
// for tests: unlike trackedCount it does not depend on sweep timing.
func (l *unauthenticatedLimiter) accountedCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.accounted
}

// trackedCount reports the number of tracked IPs. It exists for tests.
func (l *unauthenticatedLimiter) trackedCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return len(l.states)
}

// capRejectionCount reports how many new sources were refused because the map
// was full. It exists for tests.
func (l *unauthenticatedLimiter) capRejectionCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.capRejections
}
