package tun

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// TestInboundCloseReleasesAutoRedirectOutputMark closes an inbound that holds the auto-redirect
// output mark and requires the claim to be handed back.
//
// The case it stands for is the discarded constructor: adapter/inbound.Manager.Create runs an inbound
// constructor outside the lock that installs its tag, and when a concurrent Create installed the same
// tag first the loser is closed with common.Close. NewInbound claims the mark as its last side effect,
// so that loser owns a claim nobody else can release - and the surviving box would then stamp the
// discarded tun's mark on every dial it makes.
//
// The inbound is built the way NewInbound leaves it rather than through NewInbound itself: on every
// platform without SO_MARK support the constructor fails before the claim (sing-tun's NewAutoRedirect
// returns os.ErrInvalid), so the constructor cannot be driven here.
func TestInboundCloseReleasesAutoRedirectOutputMark(t *testing.T) {
	networkManager, err := route.NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)

	const mark = uint32(0x2024)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))

	// The fields NewInbound sets on the claim path, and nothing else: no stack, no interface and no
	// redirect were built, so Close only has this claim to release.
	inbound := &Inbound{
		tag:                           "tun-in",
		networkManager:                networkManager,
		autoRedirectOutputMark:        mark,
		autoRedirectOutputMarkClaimed: true,
	}

	require.NoError(t, inbound.Close())
	require.Zero(t, networkManager.AutoRedirectOutputMark(), "a closed inbound must not keep the mark alive")

	// A second close must not hand the same claim back twice: were the mark taken again in between, a
	// repeat release would strip it from the new owner.
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))
	require.NoError(t, inbound.Close())
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark())

	var _ adapter.NetworkManager = networkManager
}

// TestInboundCloseWithoutAClaimReleasesNothing keeps the release tied to the claim: an inbound that
// never took the mark - platform auto-redirect, a netns instance, or no auto-redirect at all - must
// not clear a mark that belongs to someone else.
func TestInboundCloseWithoutAClaimReleasesNothing(t *testing.T) {
	networkManager, err := route.NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(0x2024))

	inbound := &Inbound{
		tag:            "tun-in",
		networkManager: networkManager,
	}
	require.NoError(t, inbound.Close())
	require.Equal(t, uint32(0x2024), networkManager.AutoRedirectOutputMark())
}
