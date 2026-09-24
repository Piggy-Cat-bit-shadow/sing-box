//go:build with_quic

package httpclient

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// newAuthorityTrackingTransport builds a transport with only the broken-state
// map wired, so the tracking bound can be exercised without any network.
func newAuthorityTrackingTransport(t *testing.T) *http3FallbackTransport {
	t.Helper()
	transport := &http3FallbackTransport{
		schedule: option.HTTP3FallbackSchedule{
			InitialBackoff: time.Minute,
			MaxBackoff:     time.Hour,
			Multiplier:     2,
			ResetOnSuccess: true,
		},
		broken: make(map[string]http3BrokenEntry),
	}
	return transport
}

// TestAuthorityTrackingIsBoundedUnderRecentEntries is the regression for the
// unbounded-growth hole: when every tracked authority is RECENT, the retention
// sweep frees nothing, so a naive insert path grows the map without limit.
//
// The cap must hold even when nothing is reclaimable.
func TestAuthorityTrackingIsBoundedUnderRecentEntries(t *testing.T) {
	transport := newAuthorityTrackingTransport(t)

	// Fill exactly to the cap with entries that are recent and therefore NOT
	// reclaimable by the retention sweep.
	for i := range maxTrackedAuthorities {
		transport.markH3Broken(authorityName(i))
	}
	require.LessOrEqual(t, len(transport.broken), maxTrackedAuthorities,
		"filling to the cap must not exceed it")
	require.Len(t, transport.broken, maxTrackedAuthorities,
		"the fill should reach the cap exactly")

	// Now hammer with many brand-new authorities. None of these may grow the
	// map past the cap, because no existing entry can be reclaimed.
	for i := range 10000 {
		transport.markH3Broken(newAuthorityName(i))
	}
	require.LessOrEqual(t, len(transport.broken), maxTrackedAuthorities,
		"the authority map must never exceed its cap; got %d", len(transport.broken))
}

// TestAuthorityTrackingPreservesExistingEntries proves the bound is achieved by
// declining NEW authorities, not by evicting established ones. An authority
// already tracked keeps its escalation history and keeps working.
func TestAuthorityTrackingPreservesExistingEntries(t *testing.T) {
	transport := newAuthorityTrackingTransport(t)

	for i := range maxTrackedAuthorities {
		transport.markH3Broken(authorityName(i))
	}

	// An established authority must still be reported as broken and must keep
	// escalating.
	established := authorityName(0)
	before := transport.broken[established].backoff
	require.True(t, transport.h3Broken(established),
		"an established authority must still report its open window")

	transport.markH3Broken(established)
	require.Greater(t, transport.broken[established].backoff, before,
		"an established authority must keep escalating")

	require.True(t, transport.h3Broken(established))

	// Flood with new authorities; the established one must survive.
	for i := range 5000 {
		transport.markH3Broken(newAuthorityName(i))
	}
	_, stillTracked := transport.broken[established]
	require.True(t, stillTracked,
		"a full map must not evict an established authority in favour of a new one")
	require.True(t, transport.h3Broken(established),
		"the established authority must remain functional")
}

// TestAuthorityTrackingReclaimsExpiredEntries proves the bound still reclaims
// genuinely stale entries, so the cap does not permanently pin memory either.
func TestAuthorityTrackingReclaimsExpiredEntries(t *testing.T) {
	transport := newAuthorityTrackingTransport(t)

	// Entries that are expired AND untouched beyond the retention window are
	// exactly what the sweep exists to reclaim.
	stale := time.Now().Add(-2 * authorityRetention)
	for i := range maxTrackedAuthorities {
		transport.broken[authorityName(i)] = http3BrokenEntry{
			until: stale,
			seen:  stale,
		}
	}
	require.Len(t, transport.broken, maxTrackedAuthorities)

	// A new authority arriving at the cap triggers the sweep, which frees all
	// the stale entries.
	transport.markH3Broken(newAuthorityName(0))
	require.Less(t, len(transport.broken), maxTrackedAuthorities,
		"a cap-triggered sweep must reclaim stale entries; got %d", len(transport.broken))
	require.LessOrEqual(t, len(transport.broken), maxTrackedAuthorities)
}

// TestAuthorityTrackingUntrackedAuthorityIsNotBroken proves an authority that
// could not be admitted degrades honestly: it is simply not tracked, so HTTP/3
// is attempted rather than being falsely reported as broken.
func TestAuthorityTrackingUntrackedAuthorityIsNotBroken(t *testing.T) {
	transport := newAuthorityTrackingTransport(t)

	for i := range maxTrackedAuthorities {
		transport.markH3Broken(authorityName(i))
	}
	admitted := 0
	for i := range 10000 {
		name := newAuthorityName(i)
		transport.markH3Broken(name)
		if _, tracked := transport.broken[name]; tracked {
			admitted++
			// A tracked authority must report its window as open.
			require.True(t, transport.h3Broken(name))
		} else {
			// An untracked authority must NOT be reported as broken, otherwise
			// it would be pinned to HTTP/2 forever with no way to recover.
			require.False(t, transport.h3Broken(name),
				"an untracked authority must not be reported as broken")
		}
	}
	require.Zero(t, admitted, "a full map must admit none of the new authorities")
}

func authorityName(i int) string {
	return "authority-" + itoa(i) + ".example:443"
}

func newAuthorityName(i int) string {
	return "new-authority-" + itoa(i) + ".example:443"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
