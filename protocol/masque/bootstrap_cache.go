package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
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

// promote records that an address actually completed a connection.
//
// # What it deliberately does NOT do
//
// It does not reorder c.candidates. The previous version moved the winner to the front of
// the stored list, which directly contradicted this type's own documented rule that a FRESH
// resolution leads and the cache only supplies the remainder. Because recordAndMerge
// preserves the stored list when it merges, a promoted address would have been carried to
// the front of the fresh result too -- so a stale winner could outrank a fresh answer, which
// is the exact failure the fresh-first rule exists to prevent ("a working IPv6 address on
// the old Wi-Fi says nothing about the new one").
//
// The winner is remembered separately, in c.winner, which is what the FALLBACK path uses to
// order recovery. That is sufficient: on a fresh success the fresh order wins, and on a
// fresh failure the winner goes first.
func (c *bootstrapCache) promote(address netip.Addr) {
	if !address.IsValid() {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.winner = address
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
	cache *bootstrapCache
	// resolver binds a hostname to a resolution function, so the cache's recovery logic
	// never has to know which name it is recovering.
	resolver *bootstrapResolver
	// candidates is the most recent resolution, published for the QUIC racer.
	//
	// The racer needs the whole list to race at handshake level, and re-resolving for it
	// would double the lookups and could return a different answer than the one this
	// dialer just used. The cache already ordered the list; publishing it is how that
	// ordering reaches the racer instead of being thrown away here.
	candidates atomic.Pointer[[]netip.Addr]
}

func newBootstrapDialer(outboundDialer N.Dialer, cache *bootstrapCache, resolver *bootstrapResolver) *bootstrapDialer {
	return &bootstrapDialer{Dialer: outboundDialer, cache: cache, resolver: resolver}
}

// bootstrapCandidates returns the address list from the most recent successful resolution,
// or nil if none has happened yet.
func (d *bootstrapDialer) bootstrapCandidates() []netip.Addr {
	pointer := d.candidates.Load()
	if pointer == nil {
		return nil
	}
	return *pointer
}

// resolveCandidates produces the ordered candidate list for a connection attempt, using the
// cache's recovery rules, and publishes it for the racer.
func (d *bootstrapDialer) resolveCandidates(ctx context.Context, fqdn string) ([]netip.Addr, error) {
	addresses, err := d.cache.resolve(ctx, d.resolver.resolve(fqdn))
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, E.New("bootstrap resolution returned no addresses")
	}
	published := append([]netip.Addr(nil), addresses...)
	d.candidates.Store(&published)
	return addresses, nil
}

// DialContext resolves a domain through the cache, then tries the resulting addresses IN
// ORDER until one connects.
//
// # Why the whole list matters
//
// Trying only the first address would make the cache's entire fallback ordering
// decorative. The point of keeping a list is that the first entry can be stale -- a
// address that worked on the previous network may now be unroutable -- so a dialer that
// gives up after it has discarded the recovery state it was handed.
//
// A non-domain destination is passed straight through: there is nothing to resolve, and
// the IP is already the thing to connect to.
func (d *bootstrapDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsDomain() {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	addresses, err := d.resolveCandidates(ctx, destination.Fqdn)
	if err != nil {
		return nil, E.Cause(err, "bootstrap resolve ", destination.Fqdn)
	}
	var dialErrors []error
	for _, address := range addresses {
		conn, dialErr := d.Dialer.DialContext(ctx, network, M.SocksaddrFrom(address, destination.Port))
		if dialErr != nil {
			dialErrors = append(dialErrors, dialErr)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		// The address that actually connected is the one worth remembering, which is
		// the only way this cache learns anything the DNS layer does not already know.
		d.cache.promote(address)
		return conn, nil
	}
	return nil, E.Cause(E.Errors(dialErrors...),
		"bootstrap dial ", destination.Fqdn, ": all ", len(addresses), " resolved addresses failed")
}

// buildBootstrapResolution adapts an outbound dialer into a resolver factory for the
// bootstrap cache.
//
// # Why this is the right seam
//
// common/dialer already carries the configured `domain_resolver` and the whole DNS router
// behind it, and it exposes that through dialer.ResolveDialer. Using it means the bootstrap
// path keeps every existing guarantee for free -- the rule set, the cache, TTLs,
// singleflight, the strategy -- and this package adds only the recovery layer on top.
//
// Inventing a second resolver here would have been a new configuration surface and a second
// source of truth for the same question, which is exactly the conflation the three DNS roles
// exist to prevent.
//
// # Why it returns a factory
//
// The cache's resolution function takes no hostname because the cache does not care which
// name it is recovering; the NAME belongs to the caller. So this returns a closure factory
// bound to the router, and the dialer binds the actual FQDN. Threading the name through the
// cache instead would mean the recovery logic had to know about MASQUE hostnames, which is
// not its concern.
//
// The second return value reports whether the dialer can resolve at all. When it cannot,
// the caller must leave the original dialer and a nil hook in place: substituting a wrapper
// that can only fail would turn a working endpoint into a broken one.
func buildBootstrapResolution(outboundDialer N.Dialer, router adapter.DNSRouter) (*bootstrapResolver, bool) {
	resolveDialer, isResolveDialer := outboundDialer.(dialer.ResolveDialer)
	if !isResolveDialer {
		return nil, false
	}
	if router == nil {
		return nil, false
	}
	// The query options come from the resolve dialer, so the configured
	// `domain_resolver` -- its strategy, timeout and cache controls -- is honoured rather
	// than re-derived here.
	// The query options carry the configured strategy, timeout and cache controls, so the
	// bootstrap lookup honours `domain_resolver` rather than re-deriving any of it.
	queryOptions := resolveDialer.QueryOptions()
	return &bootstrapResolver{router: router, queryOptions: queryOptions}, true
}

// bootstrapResolver binds a hostname to a resolution function, and exposes the strategy the
// resolver was configured with so the QUIC race can order its candidates consistently with
// the DNS layer's own preference.
type bootstrapResolver struct {
	router       adapter.DNSRouter
	queryOptions adapter.DNSQueryOptions
	// fqdnResolve, when set, replaces the router. It exists so the recovery logic can be
	// tested without a live DNS router, which is the same reason
	// bootstrapResolution is a function rather than a direct call.
	fqdnResolve func(fqdn string) bootstrapResolution
}

func (r *bootstrapResolver) resolve(fqdn string) bootstrapResolution {
	if r.fqdnResolve != nil {
		return r.fqdnResolve(fqdn)
	}
	return func(ctx context.Context) ([]netip.Addr, error) {
		return r.router.Lookup(ctx, fqdn, r.queryOptions)
	}
}

func (r *bootstrapResolver) strategy() C.DomainStrategy {
	return r.queryOptions.Strategy
}
