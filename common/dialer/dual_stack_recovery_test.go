package dialer

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for direct dual-stack recovery (§9, §10, §11, §41, §94).
//
// These cover the decision of WHETHER recovery runs and what it is allowed to reconsider.
// The dial itself is covered by the scheduler tests.

func TestValidRecoveryDomainRejectsUnusableSniffedValues(t *testing.T) {
	// A sniffed domain is attacker-influenced: it is parsed from bytes the remote peer chose
	// and is about to be given to a resolver.
	rejected := []string{
		"",
		"192.0.2.1",
		"2001:db8::1",
		"exa\x00mple.test",
		"exa mple.test",
		"example.test\n",
		"example.test/path",
		".",
		".example.test",
		"example..test",
		"localhost",
	}
	for _, domain := range rejected {
		require.Empty(t, validRecoveryDomain(domain),
			"a malformed sniffed domain must not be resolved: %q", domain)
	}

	require.Equal(t, "example.test", validRecoveryDomain("example.test"))
	require.Equal(t, "example.test", validRecoveryDomain("example.test."))
	require.Equal(t, "a-b.example.test", validRecoveryDomain("a-b.example.test"))
}

func TestAddressRecoveryDisabledByMarker(t *testing.T) {
	// The recursion guard. A DNS exchange may travel through a direct outbound; if that
	// outbound ran recovery, resolving a name would require resolving a name.
	ctx := context.Background()
	require.False(t, addressRecoveryDisabled(ctx), "a plain context allows recovery")

	guarded := withoutAddressRecovery(ctx)
	require.True(t, addressRecoveryDisabled(guarded),
		"a context marked for an internal lookup must not trigger recovery")
}

func TestRecoverCandidatesRefusesWithoutRouter(t *testing.T) {
	// No DNS router means no configured resolver, and the system resolver is never used:
	// on a proxy that would leak the user's queries outside the tunnel.
	dialer := &resolveDialer{}
	require.Nil(t, dialer.recoverCandidates(context.Background(), M.ParseSocksaddr("192.0.2.1:443")))
}

func TestRecoverCandidatesRefusesForDomainDestinations(t *testing.T) {
	// A domain destination is already resolved by the normal path; recovering here would
	// duplicate that work.
	dialer := &resolveDialer{}
	require.Nil(t, dialer.recoverCandidates(context.Background(), M.ParseSocksaddr("example.test:443")))
}

func TestRecoverCandidatesRefusesWhenGuarded(t *testing.T) {
	dialer := &resolveDialer{}
	ctx := withoutAddressRecovery(context.Background())
	require.Nil(t, dialer.recoverCandidates(ctx, M.ParseSocksaddr("192.0.2.1:443")))
}

func TestRecoverCandidatesRefusesWithoutSniffedDomain(t *testing.T) {
	dialer := &resolveDialer{}
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Destination: M.ParseSocksaddr("192.0.2.1:443"),
	})
	require.Nil(t, dialer.recoverCandidates(ctx, M.ParseSocksaddr("192.0.2.1:443")),
		"with no sniffed domain there is nothing to recover")
}

func TestRecoveryPlanKeepsTheOriginalAndTheStrategy(t *testing.T) {
	// The full §41 shape: the client connected to an IPv6 literal, DNS returns both families,
	// and the strategy prefers IPv4. The plan must lead with IPv4 while keeping the original
	// IPv6 address as a candidate.
	original := mustAddr(t, "2001:db8::1")
	recovered := []netip.Addr{
		mustAddr(t, "192.0.2.1"),
		mustAddr(t, "2001:db8::99"),
	}

	plan := planCandidates(MergeOriginalDestination(original, recovered, C.DomainStrategyPreferIPv4), original, C.DomainStrategyPreferIPv4)
	require.Equal(t, mustAddr(t, "192.0.2.1"), plan.candidates[0].address,
		"prefer_ipv4 must lead with the recovered IPv4 address")
	require.False(t, plan.preferIPv6)

	var hasOriginal bool
	for _, candidate := range plan.candidates {
		if candidate.address == original {
			hasOriginal = true
		}
	}
	require.True(t, hasOriginal, "the address the client chose must remain a candidate")
}
