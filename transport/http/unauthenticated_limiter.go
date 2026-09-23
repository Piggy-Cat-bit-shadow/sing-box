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
type unauthenticatedLimiter struct {
	access sync.Mutex
	limits option.UnauthenticatedLimits
	states map[netip.Addr]*unauthenticatedState
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
	l.expireLocked(now)
	state, loaded := l.states[address]
	if !loaded {
		// Enforce the tracked-IP cap before adding a new entry so a flood of
		// random addresses cannot grow the map.
		if len(l.states) >= l.limits.MaxTrackedIPs {
			l.evictLocked(now)
			if len(l.states) >= l.limits.MaxTrackedIPs {
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
	return func() {
		l.access.Lock()
		defer l.access.Unlock()
		if current, ok := l.states[address]; ok && current.concurrent > 0 {
			current.concurrent--
		}
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
	for address, state := range l.states {
		if state.concurrent == 0 && state.lastSeen.Before(deadline) {
			delete(l.states, address)
		}
	}
}

// evictLocked frees space when the tracked-IP cap is reached. It first drops
// expired entries (handled by the caller) and then removes the least recently
// seen idle entries until there is room for one more.
func (l *unauthenticatedLimiter) evictLocked(now time.Time) {
	need := len(l.states) - l.limits.MaxTrackedIPs + 1
	if need <= 0 {
		return
	}
	type candidate struct {
		address  netip.Addr
		lastSeen time.Time
	}
	candidates := make([]candidate, 0, len(l.states))
	for address, state := range l.states {
		if state.concurrent > 0 {
			// Never evict an IP with an in-flight unauthenticated request:
			// that would let it reset its own budget.
			continue
		}
		candidates = append(candidates, candidate{address: address, lastSeen: state.lastSeen})
	}
	// Partial selection sort: only the oldest `need` entries matter.
	for evicted := 0; evicted < need && len(candidates) > 0; evicted++ {
		oldest := 0
		for index := 1; index < len(candidates); index++ {
			if candidates[index].lastSeen.Before(candidates[oldest].lastSeen) {
				oldest = index
			}
		}
		delete(l.states, candidates[oldest].address)
		candidates[oldest] = candidates[len(candidates)-1]
		candidates = candidates[:len(candidates)-1]
	}
	_ = now
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
