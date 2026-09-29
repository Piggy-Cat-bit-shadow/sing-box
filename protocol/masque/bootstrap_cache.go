package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	E "github.com/sagernet/sing/common/exceptions"
)

// Bootstrap resolution for the MASQUE server hostname.
//
// # Why this is separate from every other resolver in the file
//
// The MASQUE server hostname must be resolved BEFORE any tunnel exists, so this path
// must never consult the tunnel, the server's DNS assignment, or the same-connection
// DoH. Doing so would be circular: connecting needs the address, and the address would
// need the connection.
//
// # What it adds over the plain resolver
//
// The DNS router already resolves the name, with its own cache and TTLs. What it does
// NOT provide is recovery: if the resolver is unreachable during a reconnect, the
// lookup fails and the MASQUE client retries on a 1s-to-1m backoff with no memory of
// where the server was. On a network that has just changed, that is the difference
// between reconnecting in a second and not reconnecting until the resolver returns.
//
// So this keeps a bounded, in-memory record of addresses that have WORKED, and uses it
// only when a fresh lookup cannot produce an answer.
//
// # This is not a DNS cache
//
// The DNS router's cache owns TTLs, negative caching, singleflight and optimistic
// caching. This is connection-recovery state: it remembers which addresses the server
// actually answered on, which the DNS layer cannot know. It never serves a resolution
// result to anything else, and it is not persisted.

const (
	// bootstrapFreshTimeout bounds a fresh lookup during recovery.
	//
	// The system resolver can take 20-30 seconds to fail, which would make a reconnect
	// during a resolver outage appear to hang. Three seconds matches the reference
	// implementation's order of magnitude and is short enough that the cached fallback
	// is reached promptly.
	bootstrapFreshTimeout = 3 * time.Second
	// defaultMaxBootstrapCandidates bounds the cache.
	//
	// A server hostname resolving to more addresses than this is either misconfigured
	// or hostile; either way the candidate list must not grow without limit, so the
	// freshest answers are kept and the rest dropped.
	defaultMaxBootstrapCandidates = 8
)

// bootstrapResolution is the resolution function this type wraps. It is a field rather
// than a direct call into the DNS router so the failover logic can be tested without a
// live router.
type bootstrapResolution func(ctx context.Context) ([]netip.Addr, error)

// bootstrapCache remembers addresses the MASQUE server has answered on, so a reconnect
// can proceed when the resolver is temporarily unusable.
type bootstrapCache struct {
	access sync.Mutex
	// candidates is the last known-good set, in preference order. The first entry is the
	// most recently successful address.
	candidates []netip.Addr
	// winner is the address the last successful connection used, if any.
	winner netip.Addr
	// maxCandidates bounds the list.
	maxCandidates int
}

func newBootstrapCache() *bootstrapCache {
	return &bootstrapCache{maxCandidates: defaultMaxBootstrapCandidates}
}

// resolve produces the candidate list for a connection attempt.
//
// # Fresh-first ordering
//
// A successful fresh lookup is ordered FIRST and the cached entries follow, deduplicated.
// The cached winner is deliberately NOT promoted ahead of a fresh answer: after a network
// change the previous winner may be entirely unreachable -- a working IPv6 address on the
// old Wi-Fi says nothing about the new one -- so a fresh answer is the better guess about
// what works now.
//
// # Cold start
//
// With nothing cached, a failed fresh lookup is returned as a failure. There is no
// invented address and no silent fallback.
//
// # Recovery
//
// With a cache present, a fresh lookup that fails, times out, or returns nothing falls
// back to the cache. This is the case that makes the difference: a resolver outage
// during a reconnect storm would otherwise be unrecoverable.
func (c *bootstrapCache) resolve(ctx context.Context, fresh bootstrapResolution) ([]netip.Addr, error) {
	freshCtx, cancel := context.WithTimeout(ctx, bootstrapFreshTimeout)
	defer cancel()

	freshAddresses, freshErr := fresh(freshCtx)
	if len(freshAddresses) > 0 {
		// Fresh answers lead, and the cached addresses that the fresh answer did not
		// mention follow.
		//
		// Returning only the fresh set would be wrong in the case the draft's ordering
		// rule exists for: a resolver that answers with a SUBSET of what previously
		// worked -- which is exactly what a partially recovered network produces -- would
		// discard addresses that are still reachable. The merge is the whole point of
		// keeping a cache.
		merged := c.recordAndMerge(freshAddresses)
		return merged, nil
	}

	c.access.Lock()
	defer c.access.Unlock()
	if len(c.candidates) == 0 {
		// Cold start: nothing to fall back to. Report the real error rather than a
		// synthesised one, and do not invent an address.
		if freshErr == nil {
			freshErr = E.New("bootstrap resolution returned no addresses")
		}
		return nil, freshErr
	}
	// Recovery: the cache is the fallback. The fresh error is not returned, because the
	// point of the fallback is that the caller can proceed.
	ordered := make([]netip.Addr, 0, len(c.candidates))
	if c.winner.IsValid() {
		ordered = append(ordered, c.winner)
	}
	for _, address := range c.candidates {
		if address == c.winner {
			continue
		}
		ordered = append(ordered, address)
	}
	return ordered, nil
}

// recordAndMerge updates the cache from a successful fresh resolution and returns the
// ordered candidate list the caller should use.
//
// It is called with FRESH addresses only, so the cache always reflects a resolution that
// actually succeeded rather than an accumulation of historical guesses.
func (c *bootstrapCache) recordAndMerge(fresh []netip.Addr) []netip.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	merged := make([]netip.Addr, 0, len(fresh)+len(c.candidates))
	seen := make(map[netip.Addr]struct{}, len(fresh)+len(c.candidates))
	for _, address := range fresh {
		if _, loaded := seen[address]; loaded {
			continue
		}
		seen[address] = struct{}{}
		merged = append(merged, address)
	}
	// Carry over previously known addresses the fresh answer did not mention, so a
	// resolver returning a subset does not discard addresses that were working.
	for _, address := range c.candidates {
		if _, loaded := seen[address]; loaded {
			continue
		}
		seen[address] = struct{}{}
		merged = append(merged, address)
	}
	if len(merged) > c.maxCandidates {
		// Keep the freshest, which are at the front.
		merged = merged[:c.maxCandidates]
	}
	// A fresh-resolution result is a complete snapshot rather than a truncation: the
	// caller iterates it, so it must be the same list the cache holds.
	c.candidates = append([]netip.Addr(nil), merged...)
	return merged
}

// promote records that an address actually completed a connection, moving it to the
// front of the FALLBACK order.
//
// This only affects what the cache offers when a fresh lookup fails. The next successful
// fresh resolution still leads, because record() puts fresh addresses first.
func (c *bootstrapCache) promote(address netip.Addr) {
	if !address.IsValid() {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.winner = address
	// Move it to the front of the stored list as well, so the ordering survives even if
	// the winner is cleared.
	for i, candidate := range c.candidates {
		if candidate == address {
			c.candidates = append(c.candidates[:i], c.candidates[i+1:]...)
			break
		}
	}
	c.candidates = append([]netip.Addr{address}, c.candidates...)
	if len(c.candidates) > c.maxCandidates {
		c.candidates = c.candidates[:c.maxCandidates]
	}
}

// cachedCount reports the number of remembered addresses. It exists for tests.
func (c *bootstrapCache) cachedCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.candidates)
}

// hasCache reports whether recovery is possible at all.
func (c *bootstrapCache) hasCache() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.candidates) > 0
}

// bootstrapDialer wraps a dialer so a domain destination is resolved through the
// bootstrap cache while IP destinations pass through untouched.
//
// # Why a wrapper rather than a change to common/dialer
//
// common/dialer is shared by every protocol in the tree. Adding MASQUE-specific
// connection-recovery state there would put it on the path of protocols that have no
// such requirement, and would make the behaviour depend on which outbound happened to
// dial first. Wrapping at the MASQUE boundary keeps the recovery state per-endpoint,
// which is what the requirement actually is.
type bootstrapDialer struct {
	N.Dialer
	cache   *bootstrapCache
	resolve bootstrapResolution
}

func newBootstrapDialer(dialer N.Dialer, cache *bootstrapCache, resolve bootstrapResolution) *bootstrapDialer {
	return &bootstrapDialer{Dialer: dialer, cache: cache, resolve: resolve}
}

// DialContext resolves a domain through the cache, then dials the resulting addresses in
// the order the cache produced.
//
// A non-domain destination is passed straight through: there is nothing to resolve, and
// the IP is already the thing to connect to.
func (d *bootstrapDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsDomain() {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	addresses, err := d.cache.resolve(ctx, d.resolve)
	if err != nil {
		return nil, E.Cause(err, "bootstrap resolve ", destination.Fqdn)
	}
	if len(addresses) == 0 {
		return nil, E.New("bootstrap resolve ", destination.Fqdn, ": no addresses")
	}
	resolved := M.SocksaddrFrom(addresses[0], destination.Port)
	conn, err := d.Dialer.DialContext(ctx, network, resolved)
	if err != nil {
		return nil, err
	}
	// The address that actually connected is the one worth remembering, which is the
	// only way this cache learns anything the DNS layer does not already know.
	d.cache.promote(addresses[0])
	return conn, nil
}
