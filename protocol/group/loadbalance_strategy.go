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
type loadBalanceAffinity struct {
	access sync.Mutex

	entries map[string]loadBalanceAffinityEntry
	// order is the insertion queue, addressed by head. It is only compacted when the
	// queue outgrows its useful length, so the common case is two appends.
	order []string
	head  int

	ttl   time.Duration
	limit int

	// now is injectable so a test can expire entries without sleeping.
	now func() time.Time
}

type loadBalanceAffinityEntry struct {
	memberTag string
	expiresAt time.Time
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
	if _, loaded := a.entries[key]; loaded {
		// Re-pinning an existing key refreshes it in place; the queue keeps its original
		// position so a hot key cannot extend the queue for ever.
		a.entries[key] = loadBalanceAffinityEntry{memberTag: memberTag, expiresAt: now.Add(a.ttl)}
		return
	}
	if len(a.entries) >= a.limit {
		a.sweepLocked(now)
	}
	for len(a.entries) >= a.limit && a.head < len(a.order) {
		oldest := a.order[a.head]
		a.head++
		if entry, loaded := a.entries[oldest]; loaded {
			delete(a.entries, oldest)
			_ = entry
		}
	}
	if a.head > 0 && a.head >= len(a.order) {
		a.order = a.order[:0]
		a.head = 0
	}
	a.entries[key] = loadBalanceAffinityEntry{memberTag: memberTag, expiresAt: now.Add(a.ttl)}
	a.order = append(a.order, key)
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
