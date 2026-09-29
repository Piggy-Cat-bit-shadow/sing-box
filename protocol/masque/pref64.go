package masque

import (
	"net/netip"
	"sync"
)

// PREF64 state, kept entirely separate from DNS assignment state.
//
// # Why it is separate
//
// PREF64 conveys NAT64 prefixes. This client parses, validates, replaces and exposes them, and
// performs no synthesis: it does not answer AAAA with a synthesized address, does not perform
// A lookups on an AAAA NODATA, and does not rewrite DNSSEC. So PREF64 has no effect on any DNS
// answer and no effect on where a query is sent.
//
// That makes it WRONG to fold into the DNS assignment. An earlier version kept PREF64 inside the
// DNS assignment state and included it in the DNS cache environment, so a PREF64-only capsule
// invalidated the entire DNS cache -- throwing away answers that PREF64 cannot possibly have
// changed. Removing it is not tidiness: it is the difference between a cache that survives a
// server re-advertising its NAT64 prefixes and one that does not.
//
// When synthesis is eventually implemented, it becomes a resolution input and can be joined to
// the DNS state deliberately, at that point, with tests that say why.

// pref64State is the NAT64 prefix set currently in force.
//
// Like the DNS assignment snapshot it is pure data: no socket, no goroutine, no lifecycle. The
// prefix slice is copied on publish and never mutated afterwards, so a reader that captured it
// keeps seeing the prefixes that were in force when it looked.
type pref64State struct {
	prefixes []netip.Prefix
}

// pref64Store holds the published PREF64 state.
//
// It is a separate lock-protected value rather than an atomic pointer only because updates need
// to read-then-write to decide whether anything changed; the read path takes the lock briefly and
// copies nothing but a pointer.
type pref64Store struct {
	access sync.Mutex
	state  *pref64State
}

// publish replaces the prefix set.
//
// An EMPTY capsule is a WITHDRAWAL, not a no-op: draft-06 §4.2 says "An empty PREF64 capsule
// invalidates any previously received NAT64 Prefixes", which is why an empty non-nil slice is
// meaningful and distinct from publishing nothing at all. A withdrawal arrives as an empty
// prefix list through this same call, so no separate clear path exists -- and none should, since
// two ways to express the same state is how they drift apart.
func (s *pref64Store) publish(prefixes []netip.Prefix) {
	s.access.Lock()
	defer s.access.Unlock()
	s.state = &pref64State{prefixes: append([]netip.Prefix(nil), prefixes...)}
}

// snapshot returns the current prefix set, which the caller must not modify.
func (s *pref64Store) snapshot() []netip.Prefix {
	s.access.Lock()
	defer s.access.Unlock()
	if s.state == nil {
		return nil
	}
	return s.state.prefixes
}
