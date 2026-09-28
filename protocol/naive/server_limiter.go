package naive

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

// serverLimiter bounds what a peer can hold on this inbound.
//
// # What it does and does not cover
//
// It covers the resource-holding stages the lifecycle audit measured as
// unbounded: a connection that completes TLS and then goes silent, a connection
// whose request headers never finish, and an idle HTTP/2 connection. Those are
// all PRE-AUTHENTICATION or PRE-TUNNEL states: a peer that never authenticates
// can otherwise hold sockets, goroutines and file descriptors indefinitely.
//
// It does NOT throttle authenticated proxy traffic. Once a tunnel exists, its
// bytes are never counted here, because a Naive tunnel is legitimately
// long-lived and often silent -- it carries a user's browsing session, which can
// be idle for minutes between requests. A limiter that treated that silence as
// abuse would disconnect working clients.
//
// # Two independent bounds
//
//   - maxConnections is global: the host's total exposure.
//   - maxConnectionsPerIP bounds one offender, so a single source cannot consume
//     the whole global budget.
//
// They are separate because they fail differently. Without the global bound, a
// distributed source exhausts the host. Without the per-IP bound, one source
// exhausts the host while staying inside its own share.
//
// # Why the algorithm is shared with unauthenticatedLimiter
//
// transport/http's unauthenticatedLimiter already solved the hard parts of this
// problem for the HTTP inbound: amortized expiry so the hot path is not O(tracked
// IPs), a bounded map so an address flood cannot grow memory without limit, and a
// one-shot release so a double release cannot hand away another request's slot.
//
// The same three hazards exist here, so the same three answers are used rather
// than reinvented. The difference is the unit being counted: that limiter counts
// REQUESTS, this one counts CONNECTIONS, because a Naive client holds one
// connection for the life of a tunnel.
//
// A nil limiter is valid and means "no limits configured"; every method tolerates
// it, so an unconfigured inbound takes no locks and allocates no map.
type serverLimiter struct {
	access sync.Mutex
	limits option.NaiveServerLimits

	// perIP counts currently-open connections per source address.
	perIP map[netip.Addr]*serverLimiterEntry

	// total counts currently-open connections across all sources.
	total int

	// acquisitions counts admissions since the last sweep, so expiry is amortized
	// rather than O(tracked IPs) on every connection.
	acquisitions int

	// Sweep cadence and counters. These exist so tests can prove the amortization
	// and the fail-closed-at-cap behaviour instead of trusting the comments.
	entriesVisited int
	capRejections  int
	atCapSweeps    int
}

// sweepInterval is how many admissions pass between full expiry sweeps. It
// matches the HTTP limiter's cadence so the two cannot disagree about what
// "amortized" means.
const sweepInterval = 256

type serverLimiterEntry struct {
	concurrent int
	lastSeen   time.Time
}

// newServerLimiter returns nil when no limit is configured, which is the signal
// for every call site to take its unlimited path.
func newServerLimiter(limits option.NaiveServerLimits) *serverLimiter {
	if limits.MaxConnections <= 0 && limits.MaxConnectionsPerIP <= 0 {
		return nil
	}
	if limits.MaxConnectionsPerIP > 0 && limits.MaxTrackedIPs <= 0 {
		limits.MaxTrackedIPs = option.DefaultNaiveMaxTrackedIPs
	}
	return &serverLimiter{
		limits: limits,
		perIP:  make(map[netip.Addr]*serverLimiterEntry),
	}
}

// normalizedAddr converts a source address to a comparable key.
//
// IPv4-mapped IPv6 addresses are unwrapped so "::ffff:1.2.3.4" and "1.2.3.4"
// share one budget: without this, a peer could hold twice its allowance by
// alternating representations of the same address. The port is dropped for the
// same reason -- otherwise every new connection would look like a new source.
func normalizedAddr(source string) (netip.Addr, bool) {
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

// acquire records an open connection and reports whether it is admitted. The
// returned release must be called exactly once when the connection ends; it is
// idempotent, so a caller that closes on several paths cannot corrupt the count.
func (l *serverLimiter) acquire(source string, now time.Time) (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	address, valid := normalizedAddr(source)
	if !valid {
		// An unparseable source cannot be attributed to a key. Failing open here
		// matches the HTTP limiter and avoids blocking traffic the limiter cannot
		// reason about -- but the GLOBAL bound below still applies, so this cannot
		// be used to escape all limits.
		return l.acquireGlobalOnly(now)
	}

	l.access.Lock()
	defer l.access.Unlock()

	l.acquisitions++
	if l.acquisitions >= sweepInterval {
		l.acquisitions = 0
		l.expireLocked(now)
	}

	// Global bound first: it is the cheaper check and the one that protects the
	// host as a whole.
	if l.limits.MaxConnections > 0 && l.total >= l.limits.MaxConnections {
		l.capRejections++
		return func() {}, false
	}

	entry, loaded := l.perIP[address]
	if !loaded {
		// The map is full and this source is new. Sweep once for genuinely idle
		// entries, then fail closed.
		//
		// Failing closed rather than evicting is deliberate, and is the same
		// decision the HTTP limiter documents: a source that keeps changing its
		// address can never build a meaningful allowance anyway, so admitting it
		// buys nothing while an eviction would let it displace a tracked source's
		// budget. The sweep is rate-limited so a flood of new sources cannot force
		// an O(tracked IPs) scan per connection.
		if l.limits.MaxConnectionsPerIP > 0 && len(l.perIP) >= l.limits.MaxTrackedIPs {
			l.atCapSweeps++
			if l.atCapSweeps >= sweepInterval {
				l.atCapSweeps = 0
				l.expireLocked(now)
			}
			if len(l.perIP) >= l.limits.MaxTrackedIPs {
				l.capRejections++
				return func() {}, false
			}
		}
		entry = &serverLimiterEntry{lastSeen: now}
		l.perIP[address] = entry
	}

	entry.lastSeen = now
	if l.limits.MaxConnectionsPerIP > 0 && entry.concurrent >= l.limits.MaxConnectionsPerIP {
		return func() {}, false
	}

	entry.concurrent++
	l.total++

	// The release is ONE-SHOT PER ACQUISITION, for the reason the HTTP limiter
	// documents at length: decrementing "whatever slot the address currently
	// holds" is not idempotent, so a double release would hand away a slot still
	// in use and admit one more connection than the limit allows.
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			l.access.Lock()
			defer l.access.Unlock()
			if current, ok := l.perIP[address]; ok && current.concurrent > 0 {
				current.concurrent--
				current.lastSeen = time.Now()
			}
			if l.total > 0 {
				l.total--
			}
		})
	}, true
}

// acquireGlobalOnly applies only the global bound, for sources whose address
// cannot be parsed.
func (l *serverLimiter) acquireGlobalOnly(now time.Time) (func(), bool) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.limits.MaxConnections > 0 && l.total >= l.limits.MaxConnections {
		l.capRejections++
		return func() {}, false
	}
	l.total++
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			l.access.Lock()
			defer l.access.Unlock()
			if l.total > 0 {
				l.total--
			}
		})
	}, true
}

// expireLocked drops per-IP entries that hold no connections and have not been
// seen for longer than the limiter's idle window.
//
// The entry window is independent of any connection idle_timeout: it only decides
// how long a source is REMEMBERED after it stops connecting. Basing it on the
// connection timeout would let a long idle_timeout pin one entry per source
// forever, which is the map-growth problem the cap exists to prevent.
func (l *serverLimiter) expireLocked(now time.Time) {
	deadline := now.Add(-option.DefaultNaiveLimiterIdleTimeout)
	l.entriesVisited += len(l.perIP)
	for address, entry := range l.perIP {
		if entry.concurrent == 0 && entry.lastSeen.Before(deadline) {
			delete(l.perIP, address)
		}
	}
}

// --- test-only accessors -------------------------------------------------
//
// These exist so the limiter's invariants can be asserted directly rather than
// inferred from traffic. Each takes the lock, so they add no hot-path cost.

func (l *serverLimiter) trackedCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return len(l.perIP)
}

func (l *serverLimiter) totalCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.total
}

func (l *serverLimiter) visitedCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.entriesVisited
}

func (l *serverLimiter) capRejectionCount() int {
	if l == nil {
		return 0
	}
	l.access.Lock()
	defer l.access.Unlock()
	return l.capRejections
}
