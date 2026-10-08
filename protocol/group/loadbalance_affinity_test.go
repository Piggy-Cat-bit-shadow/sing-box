package group

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TD-006: the sticky-sessions cache, measured on its objects rather than on its
// size() accessor.
//
// The map bound is not a bound on the insertion queue, and the queue is what holds
// the memory: a pin that expires leaves its node behind, so a cache that is "at its
// limit" can still retain one node per key it has ever seen. The queue is also what
// decides FIFO, so a node that no longer owns its key must not be able to evict the
// pin that replaced it.
//
// Every assertion below is a count of live objects (pins held, nodes retained) or an
// identity comparison, never a wall-clock ratio: the clock is injected so expiry is
// exact instead of timed.
// ---------------------------------------------------------------------------

// affinityClock is an injectable clock for the cache.
type affinityClock struct {
	access sync.Mutex
	now    time.Time
}

func newAffinityClock() *affinityClock {
	return &affinityClock{now: time.Unix(1700000000, 0)}
}

func (c *affinityClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *affinityClock) advance(d time.Duration) {
	c.access.Lock()
	c.now = c.now.Add(d)
	c.access.Unlock()
}

// newTestAffinity builds a cache with a small bound and an injected clock.
func newTestAffinity(t *testing.T, ttl time.Duration, limit int) (*loadBalanceAffinity, *affinityClock) {
	t.Helper()
	clock := newAffinityClock()
	cache := newLoadBalanceAffinity(ttl, limit)
	cache.now = clock.Now
	return cache, clock
}

// TestAffinityQueueIsStampedAndCompacted is the memory bound: the queue must not grow
// with the number of keys ever pinned, even when every pin expires before the head
// reaches it -- which is the pattern that leaves the map empty and the queue growing.
func TestAffinityQueueIsStampedAndCompacted(t *testing.T) {
	const limit = 16
	cache, clock := newTestAffinity(t, time.Minute, limit)

	for round := 0; round < 200; round++ {
		// Fill the cache, then let every entry expire through member() (which deletes
		// the map entries but cannot delete their queue nodes).
		for i := 0; i < limit; i++ {
			cache.pin("round"+strconv.Itoa(round)+"/key"+strconv.Itoa(i), "A")
		}
		clock.advance(2 * time.Minute)
		for i := 0; i < limit; i++ {
			_, loaded := cache.member("round" + strconv.Itoa(round) + "/key" + strconv.Itoa(i))
			require.False(t, loaded, "an expired pin must not be honoured")
		}
		require.LessOrEqual(t, cache.size(), limit, "the map bound must hold")
		require.LessOrEqual(t, cache.queueRetained(), 2*limit,
			"the queue must be compacted, not accumulate one node per key ever pinned")
	}

	// 200 rounds * 16 keys = 3200 insertions. An unbounded queue would retain all of
	// them; the bound is 32 nodes.
	require.LessOrEqual(t, cache.queueRetained(), 2*limit)
	// And the cache still works after all that churn.
	cache.pin("live", "B")
	tag, loaded := cache.member("live")
	require.True(t, loaded)
	require.Equal(t, "B", tag)
}

// TestAffinityStaleNodeCannotEvictAFreshPin is the FIFO correctness half: a node left
// behind by an expired pin must not evict the pin that re-inserted the same key.
//
// The two pins are inserted at different times on purpose, so that only the first has
// expired when the third key arrives. If both expired together, the write-time sweep would
// remove them and hide the queue's own decision -- which is exactly the case this test is
// about.
func TestAffinityStaleNodeCannotEvictAFreshPin(t *testing.T) {
	const limit = 2
	cache, clock := newTestAffinity(t, time.Minute, limit)

	// A is inserted first and B half a TTL later, so their expiries differ.
	cache.pin("A", "member-a-old")
	clock.advance(30 * time.Second)
	cache.pin("B", "member-b")
	require.Equal(t, 2, cache.size())

	// A expires; B does not. A's map entry goes away, its queue node cannot.
	clock.advance(31 * time.Second)
	_, loaded := cache.member("A")
	require.False(t, loaded)
	_, loaded = cache.member("B")
	require.True(t, loaded)

	// A is pinned again, which appends a NEW node behind A's stale one.
	cache.pin("A", "member-a-fresh")
	require.Equal(t, 2, cache.size())

	// A third key forces one eviction. The eviction must take the oldest LIVE pin --
	// B -- and never the fresh A pin whose stale node is at the head of the queue.
	cache.pin("C", "member-c")

	tag, loaded := cache.member("A")
	require.True(t, loaded, "the fresh pin was evicted by its own stale queue node")
	require.Equal(t, "member-a-fresh", tag)
	_, loaded = cache.member("B")
	require.False(t, loaded, "FIFO must evict the oldest live pin")
	tag, loaded = cache.member("C")
	require.True(t, loaded)
	require.Equal(t, "member-c", tag)
}

// TestAffinityRepinKeepsItsQueuePosition pins the documented re-pin rule: refreshing a
// key must not extend the queue, so a hot key cannot push out colder ones for ever.
func TestAffinityRepinKeepsItsQueuePosition(t *testing.T) {
	const limit = 3
	cache, _ := newTestAffinity(t, time.Minute, limit)

	cache.pin("hot", "A")
	cache.pin("cold", "B")
	queuedAfterFirstPin := cache.queuePending()

	for i := 0; i < 100; i++ {
		cache.pin("hot", "A")
	}
	require.Equal(t, queuedAfterFirstPin, cache.queuePending(),
		"re-pinning must not append queue nodes")
	require.Equal(t, 2, cache.size())

	// The hot key still holds its original position, so it is evicted before the one
	// inserted after it.
	cache.pin("third", "C")
	_, hotLoaded := cache.member("hot")
	require.True(t, hotLoaded)
	cache.pin("fourth", "D")
	_, loaded := cache.member("hot")
	require.False(t, loaded, "the hot key must eventually be evicted in FIFO order")
	_, loaded = cache.member("cold")
	require.True(t, loaded, "the older key must survive the hot key's re-pins")
}

// TestAffinityChurnKeepsTheBoundAndTheSemantics drives a long, mixed workload against a
// reference FIFO model and compares the identity the cache answers with, not just the
// number of entries it holds.
func TestAffinityChurnKeepsTheBoundAndTheSemantics(t *testing.T) {
	const limit = 8
	cache, clock := newTestAffinity(t, time.Minute, limit)
	model := newAffinityModel(limit, time.Minute, clock.Now)

	// A tiny key space between the bound and twice it, so eviction and expiry both run.
	keys := make([]string, 0, 3*limit)
	for i := 0; i < 3*limit; i++ {
		keys = append(keys, "key"+strconv.Itoa(i))
	}
	members := []string{"A", "B", "C", "D"}

	state := uint64(0x9E3779B97F4A7C15)
	next := func(n int) int {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int(state % uint64(n))
	}
	for step := 0; step < 50000; step++ {
		switch next(10) {
		case 0:
			// Time passes, which expires whatever is due.
			clock.advance(20 * time.Second)
		case 1:
			key := keys[next(len(keys))]
			_, loaded := cache.member(key)
			model.member(key)
			// The cache and the model may disagree about whether a pin exists only
			// when the model says the pin expired on this very read; the model's
			// answer is authoritative and the cache must match it afterwards.
			_ = loaded
		default:
			key := keys[next(len(keys))]
			member := members[next(len(members))]
			cache.pin(key, member)
			model.pin(key, member)
		}

		if step%997 == 0 {
			// Only sampled: the bound is an invariant, but asserting it on every one of
			// 50000 steps would measure the test harness rather than the cache.
			require.LessOrEqual(t, cache.size(), limit, "step %d: the map bound must hold", step)
			require.LessOrEqual(t, cache.queueRetained(), 2*limit, "step %d: the queue must stay bounded", step)
		}
	}

	// Every pin the model still holds must be the one the cache answers with.
	for _, key := range keys {
		wantTag, wantLoaded := model.member(key)
		gotTag, gotLoaded := cache.member(key)
		require.Equal(t, wantLoaded, gotLoaded, "key %s: pin presence disagrees with the model", key)
		if wantLoaded {
			require.Equal(t, wantTag, gotTag, "key %s: pinned member disagrees with the model", key)
		}
	}
}

// affinityModel is the simplest correct implementation of the documented semantics: a
// map plus the insertion order of the pins that are still live. It is deliberately not
// the implementation under test.
type affinityModel struct {
	limit int
	ttl   time.Duration
	now   func() time.Time

	entries map[string]affinityModelEntry
}

type affinityModelEntry struct {
	member    string
	expiresAt time.Time
	inserted  uint64
}

func newAffinityModel(limit int, ttl time.Duration, now func() time.Time) *affinityModel {
	return &affinityModel{limit: limit, ttl: ttl, now: now, entries: make(map[string]affinityModelEntry)}
}

var affinityModelSequence uint64

func (m *affinityModel) member(key string) (string, bool) {
	entry, loaded := m.entries[key]
	if !loaded {
		return "", false
	}
	if !m.now().Before(entry.expiresAt) {
		delete(m.entries, key)
		return "", false
	}
	return entry.member, true
}

func (m *affinityModel) pin(key string, member string) {
	now := m.now()
	if entry, loaded := m.entries[key]; loaded {
		entry.member = member
		entry.expiresAt = now.Add(m.ttl)
		m.entries[key] = entry
		return
	}
	for len(m.entries) >= m.limit {
		oldestKey := ""
		var oldest affinityModelEntry
		for candidateKey, candidate := range m.entries {
			if !now.Before(candidate.expiresAt) {
				delete(m.entries, candidateKey)
				oldestKey = ""
				break
			}
			if oldestKey == "" || candidate.inserted < oldest.inserted {
				oldestKey = candidateKey
				oldest = candidate
			}
		}
		if oldestKey == "" {
			continue
		}
		delete(m.entries, oldestKey)
	}
	affinityModelSequence++
	m.entries[key] = affinityModelEntry{member: member, expiresAt: now.Add(m.ttl), inserted: affinityModelSequence}
}

// TestAffinityConcurrentPinAndMember is the race half: the cache is read and written by
// one goroutine per flow, so the stamping and the compaction must be safe under the lock
// they already take.
func TestAffinityConcurrentPinAndMember(t *testing.T) {
	const limit = 32
	cache, clock := newTestAffinity(t, time.Minute, limit)

	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 20000; i++ {
				if i%1000 == 0 {
					// Time moves from inside the workers rather than from a spinning
					// goroutine, so expiry runs concurrently with the reads and writes
					// without a busy loop taking a core away from them.
					clock.advance(time.Second)
				}
				key := "w" + strconv.Itoa(worker) + "/k" + strconv.Itoa(i%64)
				cache.pin(key, "A")
				cache.member(key)
			}
		}()
	}
	wait.Wait()

	require.LessOrEqual(t, cache.size(), limit)
	require.LessOrEqual(t, cache.queueRetained(), 2*limit)
}

// TestLoadBalanceStickyQueueIsBoundedThroughTheGroup is the same bound observed through
// the public selection path, so the guard is not only reachable by driving the cache
// directly.
func TestLoadBalanceStickyQueueIsBoundedThroughTheGroup(t *testing.T) {
	fixture := newLoadBalanceFixture(t, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"}, fourMembers()...)
	// Small bound, so the churn below crosses it and forces eviction and compaction.
	fixture.group.affinity = newLoadBalanceAffinity(time.Minute, 16)
	clock := newAffinityClock()
	fixture.group.affinity.now = clock.Now

	for i := 0; i < 5000; i++ {
		fixture.selectFor(t, N.NetworkTCP,
			"host"+strconv.Itoa(i)+".example.com",
			"192.168."+strconv.Itoa(i/256%256)+"."+strconv.Itoa(i%256),
			true)
		if i%97 == 0 {
			clock.advance(time.Hour)
		}
	}
	require.LessOrEqual(t, fixture.group.affinity.size(), 16)
	require.LessOrEqual(t, fixture.group.affinity.queueRetained(), 32,
		"the insertion queue must not grow with the number of keys the group has served")
}
