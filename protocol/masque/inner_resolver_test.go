package masque

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// These tests cover the address-family preference used by the inner TCP race.
//
// The behaviour they pin is small but easy to get silently wrong, and getting it
// wrong is invisible in the common case: with a single-family answer there is no
// race at all, so a bad preference only shows up on dual-stack targets -- exactly
// the case the race exists for.

func TestPreferIPv6FollowsExplicitStrategy(t *testing.T) {
	t.Parallel()

	// A deliberate misordering: the address list leads with IPv4, so a strategy
	// that were ignored would produce the WRONG answer here. If the list agreed
	// with the strategy the test could pass by accident.
	ipv4First := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
	}

	require.True(t, preferIPv6(C.DomainStrategyPreferIPv6, ipv4First),
		"prefer_ipv6 must win over the resolver's ordering")
	require.False(t, preferIPv6(C.DomainStrategyPreferIPv4, ipv4First),
		"prefer_ipv4 must be honoured")
}

func TestPreferIPv6UsesAnswerOrderWhenStrategyIsAsIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		addresses []netip.Addr
		want      bool
	}{
		{
			name:      "v4 first",
			addresses: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("2001:db8::1")},
			want:      false,
		},
		{
			name:      "v6 first",
			addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("1.2.3.4")},
			want:      true,
		},
		{
			name:      "v4 only",
			addresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
			want:      false,
		},
		{
			name:      "v6 only",
			addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			want:      true,
		},
		{
			name:      "empty answer",
			addresses: nil,
			want:      false,
		},
		{
			// An IPv4-mapped IPv6 address is an IPv4 address in IPv6 clothing. The
			// DNS layer can return these, and treating one as native IPv6 would
			// start the race on the wrong family.
			name:      "v4-mapped first",
			addresses: []netip.Addr{netip.MustParseAddr("::ffff:1.2.3.4"), netip.MustParseAddr("2001:db8::1")},
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, preferIPv6(C.DomainStrategyAsIS, tc.addresses))
		})
	}
}

func TestPreferIPv6ZeroStrategyIsTreatedAsAsIs(t *testing.T) {
	t.Parallel()

	// DomainStrategyAsIS is the ZERO value, which is what an omitted strategy
	// decodes to, so the default path is this one. It must behave as "no
	// preference" rather than as an error or a silent IPv4 lock-in.
	require.EqualValues(t, 0, C.DomainStrategyAsIS,
		"DomainStrategyAsIS must remain the zero value, or an omitted strategy would "+
			"silently mean something else")

	addresses := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("1.2.3.4")}
	require.True(t, preferIPv6(C.DomainStrategyAsIS, addresses),
		"an omitted strategy must fall through to the answer order")
}

func TestPreferIPv6IgnoresInvalidAddresses(t *testing.T) {
	t.Parallel()

	// The DNS layer should never return an invalid address, but if one appeared
	// first it must be skipped rather than deciding the family.
	addresses := []netip.Addr{
		{},
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("1.2.3.4"),
	}
	require.True(t, preferIPv6(C.DomainStrategyAsIS, addresses),
		"an invalid leading address must not be read as IPv4")
}

// TestDefaultInnerFallbackDelayMatchesTheStandard pins the value to the standard
// Happy Eyeballs delay.
//
// It is asserted against the dependency's constant rather than a literal so that
// this fork follows the library if it ever moves, and the test names the number so
// a change is visible rather than silent.
func TestDefaultInnerFallbackDelayMatchesTheStandard(t *testing.T) {
	t.Parallel()

	require.Equal(t, N.DefaultFallbackDelay, DefaultInnerFallbackDelay,
		"the inner race must use the standard fallback delay, not a new tunable")
	require.Positive(t, DefaultInnerFallbackDelay)
	require.LessOrEqual(t, DefaultInnerFallbackDelay.Milliseconds(), int64(500),
		"a fallback delay above ~500ms would make dual-stack targets noticeably slow")
}
