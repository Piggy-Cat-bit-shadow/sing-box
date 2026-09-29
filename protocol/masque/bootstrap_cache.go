package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
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

// bootstrapCache remembers where the MASQUE server was last reached, so a reconnect can
// proceed when DNS is temporarily unusable.
//
// # The whole model, deliberately
//
//	lastFresh   the most recent successful DNS answer
//	lastWinner  the address that most recently completed a QUIC handshake
//
// That is all of it. There is no TTL engine, no persistent cache, no union of historical
// addresses, and no accumulation: the sing-box DNS router already owns DNS caching, and this
// owns exactly one thing it cannot know -- which address the SERVER actually answered on.
//
// # Why a fresh success REPLACES rather than merges
//
// An earlier version returned `fresh ++ (cached \ fresh)`, carrying over addresses the fresh
// answer had not mentioned, on the theory that a resolver answering with a subset should not
// discard addresses that still work. The effect on a WITHDRAWN address is a stale-DNS hazard:
// when the operator removes an address from the record, the recovery state puts it back and we
// keep dialling something the resolver no longer publishes, with no TTL to expire it.
//
// A successful DNS answer is authoritative about where the server is. The cache exists only to
// cover the case where that answer cannot be obtained.
type bootstrapCache struct {
	access sync.Mutex
	// lastFresh is the most recent successful resolution.
	lastFresh []netip.Addr
	// lastWinner is the address that most recently completed a handshake. It is preferred
	// when falling back, and only while it is still part of lastFresh.
	lastWinner netip.Addr
	// maxCandidates bounds the list, because a hostname resolving to more addresses than
	// this is either misconfigured or hostile.
	maxCandidates int
}

func newBootstrapCache() *bootstrapCache {
	return &bootstrapCache{maxCandidates: defaultMaxBootstrapCandidates}
}

// resolve produces the candidate list for one connection attempt.
//
//	fresh answer non-empty -> use it, and remember it
//	fresh failed/empty     -> use the remembered answer, winner first
//	nothing remembered     -> report the real error, and invent nothing
//
// The fresh lookup is always attempted, on every connection, because a server can move and a
// network can change. Reusing a remembered list without asking DNS again would keep dialling an
// address that is no longer published, and it would fail silently: a stale address that still
// answers looks exactly like success.
func (c *bootstrapCache) resolve(ctx context.Context, fresh bootstrapResolution) ([]netip.Addr, error) {
	freshCtx, cancel := context.WithTimeout(ctx, bootstrapFreshTimeout)
	defer cancel()

	freshAddresses, freshErr := fresh(freshCtx)
	if len(freshAddresses) > 0 {
		return c.recordFresh(freshAddresses), nil
	}

	c.access.Lock()
	defer c.access.Unlock()
	if len(c.lastFresh) == 0 {
		// Nothing to fall back to. Report the real error rather than a synthesised one, and
		// do not invent an address.
		if freshErr == nil {
			freshErr = E.New("bootstrap resolution returned no addresses")
		}
		return nil, freshErr
	}
	// Recovery. The last known-good address goes first when it is still one of the addresses
	// DNS last published, because it is the one that demonstrably worked.
	ordered := make([]netip.Addr, 0, len(c.lastFresh))
	if c.lastWinner.IsValid() {
		ordered = append(ordered, c.lastWinner)
	}
	for _, address := range c.lastFresh {
		if address == c.lastWinner {
			continue
		}
		ordered = append(ordered, address)
	}
	return ordered, nil
}

// recordFresh replaces the remembered answer with a successful resolution and returns the
// candidate list the caller should use.
//
// It is called with FRESH addresses only, so the remembered answer always reflects a resolution
// that actually succeeded rather than an accumulation of historical guesses. A winner that the
// fresh answer no longer lists is dropped, so recovery stops preferring an address the resolver
// has withdrawn.
func (c *bootstrapCache) recordFresh(fresh []netip.Addr) []netip.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	snapshot := make([]netip.Addr, 0, len(fresh))
	seen := make(map[netip.Addr]struct{}, len(fresh))
	for _, address := range fresh {
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		snapshot = append(snapshot, address)
	}
	if len(snapshot) > c.maxCandidates {
		snapshot = snapshot[:c.maxCandidates]
	}
	// The snapshot IS the candidate list: the caller iterates it, so it must be the same list
	// the cache holds rather than a copy that could drift.
	c.lastFresh = snapshot
	if c.lastWinner.IsValid() {
		if _, stillListed := seen[c.lastWinner]; !stillListed {
			c.lastWinner = netip.Addr{}
		}
	}
	return snapshot
}

// promote records that an address completed a QUIC handshake.
//
// This is the only thing this cache learns that the DNS layer cannot know, and it only affects
// the FALLBACK ordering: a fresh answer always leads, because after a network change the
// previous winner may be an address on the network we just left.
func (c *bootstrapCache) promote(address netip.Addr) {
	if !address.IsValid() {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.lastWinner = address
}

// hasRecovery reports whether a fallback is possible at all.
func (c *bootstrapCache) hasRecovery() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.lastFresh) > 0
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
}

func newBootstrapDialer(outboundDialer N.Dialer, cache *bootstrapCache, resolver *bootstrapResolver) *bootstrapDialer {
	return &bootstrapDialer{Dialer: outboundDialer, cache: cache, resolver: resolver}
}

// resolveCandidates produces the ordered candidate list for a connection attempt, using the
// cache's recovery rules.
//
// It is called on EVERY new connection attempt, including reconnects after a network change.
// An earlier version published the list and let the racer reuse it, which meant that after the
// first successful connection DNS was never consulted again -- so a server that moved, or a
// network that changed, kept being dialled at its old address. That fails silently, because a
// stale address that still answers looks exactly like success.
func (d *bootstrapDialer) resolveCandidates(ctx context.Context, fqdn string) ([]netip.Addr, error) {
	addresses, err := d.cache.resolve(ctx, d.resolver.resolve(fqdn))
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, E.New("bootstrap resolution returned no addresses")
	}
	return addresses, nil
}

// DialContext resolves a domain through the cache, then tries the resulting addresses IN
// ORDER until one connects.
//
// This is the non-QUIC path (a caller that dials the hostname directly rather than through the
// racer).
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
