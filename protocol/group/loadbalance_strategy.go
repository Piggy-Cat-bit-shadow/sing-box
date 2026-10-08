package group

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"golang.org/x/net/publicsuffix"
)

// The strategies a loadbalance group accepts.
//
// The names are sing-box's own spelling of the semantics Mihomo's Clash-derived clients
// implement under `round-robin`, `consistent-hashing` and `sticky-sessions`. They are
// reimplemented here rather than copied: the behaviour is what travels, not the code.
const (
	loadBalanceStrategyRoundRobin     = "round_robin"
	loadBalanceStrategyConsistentHash = "consistent_hashing"
	loadBalanceStrategyStickySessions = "sticky_sessions"
)

// loadBalanceDefaultAffinityTTL and loadBalanceDefaultAffinityLimit bound the
// sticky-sessions cache.
//
// The values match the reference implementation's, which is what a user migrating a
// configuration expects, and the limit is the part that matters: an affinity cache keyed
// by source and destination is keyed by something an attacker controls, so it must be
// bounded independently of how many keys arrive.
const (
	loadBalanceDefaultAffinityTTL   = 10 * time.Minute
	loadBalanceDefaultAffinityLimit = 1000
)

// loadBalanceHashRetries bounds how many times a hashing strategy may step to another
// member when its first choice is not currently healthy. Beyond a few steps the walk is
// no longer a hash with a fallback, it is a scan, and the scan is what runs next anyway.
const loadBalanceHashRetries = 5

// loadBalanceDestinationKey derives the identity a destination-pinned strategy hashes on.
//
// # The order of preference, and why
//
// A domain is preferred over an address because it is the logical target: when DNS answers
// with a different family for the second connection, the flow is still the same flow. A
// literal address is used when there is no domain, because then the address IS the target.
//
// # What is deliberately not in the key
//
//	port     the reference implementation does not include it, and two ports on one host
//	         are one destination from the point of view of which egress serves it
//	network  TCP and UDP to the same target from the same client belong together
//	source   that is what separates this from the sticky strategy
//
// An empty result is meaningful: it says the metadata carries no destination identity, and
// the caller must not hash on nothing (every such flow would collapse onto one member).
func loadBalanceDestinationKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	if host := loadBalanceHost(metadata); host != "" {
		if address, err := netip.ParseAddr(host); err == nil {
			return loadBalanceCanonicalAddr(address)
		}
		return loadBalanceCanonicalDomain(host)
	}
	if address := loadBalanceDestinationAddr(metadata); address.IsValid() {
		return loadBalanceCanonicalAddr(address)
	}
	return ""
}

// loadBalanceSessionKey derives the identity the sticky strategy pins on: the source and
// the destination together.
//
// The separator is not decoration. Concatenating the two halves without one lets
// ("10.0.0.1", "0.0.2.2") and ("10.0.0.10", ".0.2.2") collide onto one key, which is a
// silent cross-client affinity: one client would be pinned to another's egress.
func loadBalanceSessionKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	destination := loadBalanceDestinationKey(metadata)
	if destination == "" {
		return ""
	}
	source := loadBalanceCanonicalAddr(metadata.Source.Addr)
	if source == "" {
		// A flow with no source identity still gets destination affinity rather than
		// none: dropping the key entirely would turn this strategy into round-robin
		// without saying so.
		return destination
	}
	return source + "\x00" + destination
}

// loadBalanceHost returns the domain the flow was addressed to, if it has one.
//
// Both spellings are consulted because the two arrive at different points: Domain is set
// by the request or the sniffer, and Destination.Fqdn is what an inbound that carried a
// domain put on the destination itself.
func loadBalanceHost(metadata *adapter.InboundContext) string {
	if metadata.Domain != "" {
		return metadata.Domain
	}
	if metadata.Destination.IsFqdn() {
		return metadata.Destination.Fqdn
	}
	return ""
}

func loadBalanceDestinationAddr(metadata *adapter.InboundContext) netip.Addr {
	if metadata.Destination.IsFqdn() {
		return netip.Addr{}
	}
	if address := metadata.Destination.Addr; address.IsValid() {
		return address
	}
	// The resolved candidates are the last resort, and only when the destination itself
	// carries no address. Their order is DNS's, so this is not a stable identity across
	// resolver answers; a flow that reaches here has no domain to pin on and the
	// alternative is no key at all.
	if len(metadata.DestinationAddresses) > 0 {
		return metadata.DestinationAddresses[0]
	}
	return netip.Addr{}
}

// loadBalanceCanonicalAddr renders an address in one spelling.
//
// Unmap first: an IPv4-mapped IPv6 address and its four-byte form are the same destination,
// and hashing them separately would put one client's flows to one host on two members.
func loadBalanceCanonicalAddr(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}
	return address.Unmap().String()
}

// loadBalanceCanonicalDomain renders a domain in one spelling.
//
// The reference implementation hashes the registrable domain, so every host under one
// site is one identity. That is what makes the hash useful - a page pulling from four
// subdomains stays on one egress - and it is also why this strategy is not the default.
func loadBalanceCanonicalDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// A single trailing dot is a fully qualified name and the same name as without it.
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return etld
	}
	// No registrable domain to find: a single-label host, or a name whose suffix is not
	// in the public suffix list. The host itself is still the logical target, and using
	// it keeps two such hosts apart instead of collapsing both onto one member through
	// an empty key.
	return host
}

// loadBalanceHash is FNV-1a over the key bytes.
//
// Inlined rather than taken from hash/fnv because the standard hasher is an interface
// value: one allocation per selection on the hot path, for a function that is a dozen
// instructions.
func loadBalanceHash(key string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= prime64
	}
	return hash
}

// jumpHash maps a key to a bucket in [0, buckets) with the property that growing the
// bucket count moves about one key in `buckets` and leaves the rest where they were.
//
// That property is the whole reason to use it: adding or removing a member must not
// re-map every flow, or the affinity such a strategy exists to provide would break
// whenever the member list changed. It is Google's jump consistent hash, computed from
// the published algorithm rather than copied from a client implementation.
//
// buckets must be positive; the caller guarantees it.
func jumpHash(key uint64, buckets int32) int32 {
	var (
		bucket int64
		next   int64
	)
	for next < int64(buckets) {
		bucket = next
		key = key*2862933555777941757 + 1
		next = int64(float64(bucket+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}
	return int32(bucket)
}

// loadBalanceAffinity is the sticky-sessions cache.
//
// # Why it is not a timer-swept map
//
// An entry's expiry is only ever interesting when the key is read again, so expiry is
// evaluated on read and the map is swept on write once it is at its bound. That removes
// the sweeper goroutine and its timer entirely: there is nothing to leak on close, and
// nothing that can outlive the group.
//
// # Why eviction is FIFO and not LRU
//
// Both are bounded and both are predictable. FIFO needs a queue index and no list
// surgery, so a write is a map store and an append. The strategies that use this cache
// re-pin a key when they read a dead member, so the entries that matter are refreshed by
// use; the ones evicted are the ones nothing has read for longest.
//
// # Why the queue is stamped and compacted
//
// The bound on the map is not a bound on the queue, and the queue is what holds the
// memory. Two things are needed to make it one:
//
//   - Every queue node carries the insertion sequence of the pin it was appended for,
//     and the entry carries the same stamp. A node may only evict the key it still owns.
//     Without that, a key that expired (leaving its node behind) and was then pinned
//     again (appending a new node) would be evicted by its OWN stale node the moment the
//     head reached it -- the fresh pin would be dropped while an older key survived,
//     which is the opposite of FIFO.
//   - The queue is compacted to its live nodes once it has grown past twice the bound.
//     Pins that expire before the head ever reaches them would otherwise accumulate one
//     node per key ever seen, for ever, while the map stayed at its limit. The
//     compaction is amortized O(1): it only runs after at least `limit` further appends,
//     because it leaves at most `limit` live nodes behind.
type loadBalanceAffinity struct {
	access sync.Mutex

	entries map[string]loadBalanceAffinityEntry
	// order is the insertion queue, addressed by head. A node whose pin is gone is
	// skipped when the head reaches it, and dropped in bulk by compactLocked.
	order []loadBalanceOrderNode
	head  int
	// sequence stamps each appended node. It is monotonic and never reused, which is
	// what lets a node prove it still owns its key.
	sequence uint64

	ttl   time.Duration
	limit int

	// now is injectable so a test can expire entries without sleeping.
	now func() time.Time
}

// loadBalanceOrderNode is one position in the insertion queue.
type loadBalanceOrderNode struct {
	key      string
	sequence uint64
}

type loadBalanceAffinityEntry struct {
	memberTag string
	expiresAt time.Time
	// sequence is the stamp of the queue node that owns this pin.
	sequence uint64
}

func newLoadBalanceAffinity(ttl time.Duration, limit int) *loadBalanceAffinity {
	if ttl <= 0 {
		ttl = loadBalanceDefaultAffinityTTL
	}
	if limit <= 0 {
		limit = loadBalanceDefaultAffinityLimit
	}
	return &loadBalanceAffinity{
		entries: make(map[string]loadBalanceAffinityEntry),
		ttl:     ttl,
		limit:   limit,
		now:     time.Now,
	}
}

// member returns the member tag this key is pinned to, if the pin has not expired.
func (a *loadBalanceAffinity) member(key string) (string, bool) {
	if a == nil || key == "" {
		return "", false
	}
	a.access.Lock()
	defer a.access.Unlock()
	entry, loaded := a.entries[key]
	if !loaded {
		return "", false
	}
	if !a.now().Before(entry.expiresAt) {
		delete(a.entries, key)
		return "", false
	}
	return entry.memberTag, true
}

// pin records that this key is served by this member tag.
func (a *loadBalanceAffinity) pin(key string, memberTag string) {
	if a == nil || key == "" || memberTag == "" {
		return
	}
	a.access.Lock()
	defer a.access.Unlock()

	now := a.now()
	if entry, loaded := a.entries[key]; loaded {
		// Re-pinning an existing key refreshes it in place, and keeps the node that
		// already owns the key: the queue keeps its original position so a hot key
		// cannot extend the queue for ever, and the node that will eventually evict
		// this key is the one it was inserted with.
		entry.memberTag = memberTag
		entry.expiresAt = now.Add(a.ttl)
		a.entries[key] = entry
		return
	}
	if len(a.entries) >= a.limit {
		a.sweepLocked(now)
	}
	for len(a.entries) >= a.limit && a.head < len(a.order) {
		node := a.order[a.head]
		a.head++
		entry, loaded := a.entries[node.key]
		if !loaded || entry.sequence != node.sequence {
			// The pin this node was appended for is gone -- expired, evicted, or
			// replaced by a later insertion. A stale node must not evict whatever
			// holds the key now.
			continue
		}
		delete(a.entries, node.key)
	}
	a.sequence++
	a.entries[key] = loadBalanceAffinityEntry{memberTag: memberTag, expiresAt: now.Add(a.ttl), sequence: a.sequence}
	a.order = append(a.order, loadBalanceOrderNode{key: key, sequence: a.sequence})
	if len(a.order) >= 2*a.limit {
		a.compactLocked()
	}
}

// compactLocked drops every node that no longer owns a live pin, preserving the relative
// order of the nodes that remain. The caller holds the lock.
//
// The filter is in place: a kept node is always written at an index no greater than the
// one it is read from, so no node is overwritten before it has been examined.
func (a *loadBalanceAffinity) compactLocked() {
	live := a.order[:0]
	for _, node := range a.order[a.head:] {
		entry, loaded := a.entries[node.key]
		if loaded && entry.sequence == node.sequence {
			live = append(live, node)
		}
	}
	a.order = live
	a.head = 0
}

// sweepLocked drops every expired entry. The caller holds the lock.
func (a *loadBalanceAffinity) sweepLocked(now time.Time) {
	for key, entry := range a.entries {
		if !now.Before(entry.expiresAt) {
			delete(a.entries, key)
		}
	}
}

// size reports how many pins are held, expired or not. It exists for tests and for
// diagnostics, not for selection.
func (a *loadBalanceAffinity) size() int {
	if a == nil {
		return 0
	}
	a.access.Lock()
	defer a.access.Unlock()
	return len(a.entries)
}

// queueRetained reports how many queue nodes are still held, consumed or not: it is the
// memory the insertion queue occupies. Like size, it exists for tests and diagnostics.
func (a *loadBalanceAffinity) queueRetained() int {
	if a == nil {
		return 0
	}
	a.access.Lock()
	defer a.access.Unlock()
	return len(a.order)
}

// queuePending reports how many nodes the head has still to walk. Like size, it exists
// for tests and diagnostics.
func (a *loadBalanceAffinity) queuePending() int {
	if a == nil {
		return 0
	}
	a.access.Lock()
	defer a.access.Unlock()
	return len(a.order) - a.head
}
