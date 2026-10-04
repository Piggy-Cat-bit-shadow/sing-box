package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the FakeIP boundary at the fast-path decision.
//
// # Why FakeIP must never be bypassed
//
// A FakeIP address is synthetic: it exists only inside sing-box and maps back to a domain. Handing
// one to the platform as a native bypass would send a connection to an address that means nothing
// outside the process - and it would skip the unmapping that resolves which domain the client
// actually wanted, so every rule that depends on that domain would be evaluated against a
// meaningless address instead.

// fakeIPMetadata is a TUN flow whose destination is a synthetic FakeIP address.
func fakeIPMetadata() adapter.InboundContext {
	return fastBypassMetadata(N.NetworkTCP, M.ParseSocksaddr("198.18.0.5:443"))
}

// TestFakeIPDestinationIsNeverBypassed is §6.1.
func TestFakeIPDestinationIsNeverBypassed(t *testing.T) {
	router, outbound := eligibleRouter(t)
	require.True(t, outbound.canBypass.Load() == 1,
		"the fixture must be bypass-capable, or this test would pass for the wrong reason")

	metadata := fakeIPMetadata()
	packetDestination := metadata.Destination

	// Sanity: without the FakeIP flag this destination WOULD be bypassed, so the assertion below
	// is about the flag rather than about an unusable fixture.
	require.True(t, router.canFastBypass(&metadata, packetDestination,
		[]adapter.Outbound{outbound}, outbound).BypassAllowed(),
		"a plain literal destination is bypassable, which is what makes the next assertion "+
			"meaningful")

	// With the FakeIP marker set, it must not be.
	metadata.FakeIP = true
	require.False(t, router.canFastBypass(&metadata, packetDestination,
		[]adapter.Outbound{outbound}, outbound).BypassAllowed(),
		"a FakeIP destination is synthetic and exists only inside sing-box; handing it to the "+
			"platform would connect to an address that means nothing outside the process and would "+
			"skip the unmapping that recovers the domain the client actually asked for")
}

// TestRewrittenDestinationIsNeverBypassed is §6.1's companion.
//
// FakeIP unmapping rewrites the destination. Any difference between the destination the flow was
// created for and the one the rules produced means a rewrite happened, and the userspace path must
// dial the rewritten target.
func TestRewrittenDestinationIsNeverBypassed(t *testing.T) {
	router, outbound := eligibleRouter(t)

	metadata := fakeIPMetadata()
	packetDestination := metadata.Destination

	// The unmapping replaced the synthetic address with the real one.
	metadata.Destination = M.ParseSocksaddr("93.184.216.34:443")

	require.False(t, router.canFastBypass(&metadata, packetDestination,
		[]adapter.Outbound{outbound}, outbound).BypassAllowed(),
		"a destination that differs from the one the flow was created for was rewritten by a "+
			"rule; the rewritten target is the one the userspace path must dial")
}

var _ = C.TypeTun
