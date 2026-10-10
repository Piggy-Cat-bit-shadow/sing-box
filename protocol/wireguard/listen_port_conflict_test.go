package wireguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// `detour` and `listen_port` are mutually exclusive, and the refusal must happen at CONSTRUCTION.
//
// # Why the pair is illegal rather than merely unusual
//
// `listen_port` is a request for a socket other hosts can reach, which only the standard bind can
// provide, and the standard bind is reachable only through the local dialer. A detour removes that
// dialer: the detour outbound owns the socket, so the endpoint has no local port to bind and the
// configured port would be written into the device's configuration while nothing listened on it.
//
// The check below is what makes that combination unreachable from a real configuration, which is why
// the capability boundary in transport/wireguard is a second line of defence rather than the first:
// by the time a bind could refuse the port, this construction has already refused the setup.
//
// It is asserted at construction, with an otherwise empty context, because that is the strongest
// form: no router, no endpoint manager and no network are needed to be told the configuration is
// contradictory.
func TestDetourConflictsWithListenPort(t *testing.T) {
	endpoint, err := NewEndpoint(
		context.Background(),
		nil,
		log.NewNOPFactory().Logger(),
		"wg-detour",
		option.WireGuardEndpointOptions{
			DialerOptions: option.DialerOptions{Detour: "proxy"},
			ListenPort:    51820,
		},
	)
	require.Error(t, err, "a detour endpoint with a listen_port must be refused at construction")
	require.ErrorContains(t, err, "listen_port")
	require.ErrorContains(t, err, "detour")
	require.Nil(t, endpoint)
}

// The reverse: a listen_port with NO detour is not refused by that check.
//
// This is the negative control for the test above. Without it, a check that rejected every
// listen_port would look like a passing conflict rule, and the listening endpoint - the one that
// actually owns the port - could never be configured at all. The network manager is the real one
// from route, so nothing here is a stub that could accept a configuration the product rejects.
func TestListenPortWithoutDetourIsNotRejectedByTheConflictCheck(t *testing.T) {
	networkManager, err := route.NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)

	endpoint, err := NewEndpoint(
		ctx,
		nil,
		log.NewNOPFactory().Logger(),
		"wg-listen",
		option.WireGuardEndpointOptions{
			// A valid 32-byte key and one peer, so the only thing this test can fail on is the
			// conflict rule rather than an unrelated missing field.
			PrivateKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			ListenPort: 51820,
			Peers: []option.WireGuardPeer{{
				Address:    "127.0.0.1",
				Port:       51821,
				PublicKey:  "yMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqk=",
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			}},
		},
	)
	require.NoError(t, err,
		"a listen_port without a detour is a legal configuration; refusing it here would mean the "+
			"conflict rule rejects the only setup that can own the port")
	require.NotNil(t, endpoint)
}
