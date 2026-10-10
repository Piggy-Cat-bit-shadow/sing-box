package wireguard

import (
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// A public option whose zero value panics from a goroutine nothing can recover is a defect at this
// repository's own boundary, and this is the detector for it.
//
// # Why it is not the embedder's problem alone
//
// EgressPoolOptions is public, its fields are public, and the pool it configures dereferences three of
// them unconditionally - from wireguard-go's own goroutines, reached through BindUpdate, which the
// recovery worker calls. A nil InterfaceMonitor therefore does not fail a Start that a caller can see;
// it kills the process from RoutineTUNEventReader (sing-tun udp_egress.go:119, reached from
// :88-119 SetEgressPort <- StdNetBind.Open <- Device.BindUpdate).
//
// The in-tree callers are all correct, so this changes nothing for a configuration that starts today.
// What it protects is the boundary itself: an option struct that cannot be filled in wrongly without a
// diagnosable error.
func TestAEgressPoolWithoutAMonitorIsRefusedRatherThanPanicking(t *testing.T) {
	manager := &egressFixtureNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](t.Context(), manager)
	outbound, err := dialer.NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)
	_, egressEnabled := outbound.UDPListenerControl()
	require.True(t, egressEnabled,
		"the fixture dialer does not advertise the listener capability, so Endpoint.Start would never "+
			"build an egress pool and this test would prove nothing")

	// Exactly the three cases the pool dereferences. Each is refused at Start with a message naming
	// which field is missing, instead of panicking on a goroutine later.
	cases := []struct {
		name    string
		options tun.UDPEgressPoolOptions
		missing string
	}{
		{
			name:    "no options at all",
			options: tun.UDPEgressPoolOptions{},
			missing: "InterfaceMonitor",
		},
		{
			name: "a monitor but no finder",
			options: tun.UDPEgressPoolOptions{
				Logger:           log.NewNOPFactory().Logger(),
				InterfaceMonitor: egressFixtureMonitor(),
			},
			missing: "InterfaceFinder",
		},
		{
			name: "a monitor and a finder but no logger",
			options: tun.UDPEgressPoolOptions{
				InterfaceFinder:  control.NewDefaultInterfaceFinder(),
				InterfaceMonitor: egressFixtureMonitor(),
			},
			missing: "Logger",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint, err := NewEndpoint(EndpointOptions{
				Context:           ctx,
				Logger:            log.NewNOPFactory().Logger(),
				Tag:               "wg-egress",
				Dialer:            outbound,
				MTU:               1420,
				Address:           []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
				PrivateKey:        testPrivateKey,
				EgressPoolOptions: testCase.options,
				Peers: []PeerOptions{{
					Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
					PublicKey:  testListenPeerPublicKey,
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				}},
			})
			require.NoError(t, err, "the refusal belongs to Start, which is where the pool is built")
			t.Cleanup(func() { _ = endpoint.Close() })
			require.NoError(t, endpoint.Initialize(nil))

			err = endpoint.Start(false)
			require.Error(t, err, "a zero-valued egress pool option must be refused, not dereferenced")
			require.ErrorContains(t, err, testCase.missing,
				"the refusal must name the field that is missing, or the operator cannot fix it")
			require.ErrorContains(t, err, "wg-egress", "and the endpoint it belongs to")
		})
	}
}

// The positive control, and the one that keeps this from becoming a false refusal: the same
// configuration WITH every field filled must start, exactly as it does today.
func TestACompleteEgressPoolStillStarts(t *testing.T) {
	manager := &egressFixtureNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](t.Context(), manager)
	outbound, err := dialer.NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)

	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Tag:        "wg-egress-ok",
		Dialer:     outbound,
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		// Filled exactly as protocol/wireguard, protocol/openvpn and protocol/tailscale fill it.
		EgressPoolOptions: tun.UDPEgressPoolOptions{
			Logger:           log.NewNOPFactory().Logger(),
			InterfaceFinder:  manager.InterfaceFinder(),
			InterfaceMonitor: manager.InterfaceMonitor(),
			IsExempt:         func() bool { return false },
		},
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = endpoint.Close() })
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))

	port := endpoint.currentListenPort(endpoint.device.Load())
	require.NotZero(t, port, "the endpoint with a complete egress pool must still own a real port")
	require.NotNil(t, endpoint.egressPool, "and must actually have built the pool")
}

// egressFixtureNetworkManager advertises the listener capability, which is what makes Endpoint.Start
// take the standard-bind branch and build an egress pool. It deliberately does NOT auto-fill the
// monitor, so a test can supply a nil one.
type egressFixtureNetworkManager struct {
	adapter.NetworkManager
}

func (m *egressFixtureNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (m *egressFixtureNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return egressFixtureMonitor()
}

func (m *egressFixtureNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (m *egressFixtureNetworkManager) AutoDetectInterface() bool { return true }
func (m *egressFixtureNetworkManager) AutoRedirectOutputMark() uint32 {
	return 0
}

func (m *egressFixtureNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network string, address string, conn syscall.RawConn) error { return nil }
}

func (m *egressFixtureNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return func(network string, address string, conn syscall.RawConn) error { return nil }
}

var _ adapter.NetworkManager = (*egressFixtureNetworkManager)(nil)

// egressFixtureMonitor is a DefaultInterfaceMonitor with a fixed answer, following the shape
// route/interface_transition_coalescing_test.go uses for the same purpose.
type egressFixtureMonitorState struct {
	current *control.Interface
}

func egressFixtureMonitor() tun.DefaultInterfaceMonitor {
	return &egressFixtureMonitorState{current: &control.Interface{Index: 1, Name: "en0"}}
}

func (m *egressFixtureMonitorState) Start() error { return nil }
func (m *egressFixtureMonitorState) Close() error { return nil }
func (m *egressFixtureMonitorState) DefaultInterface() *control.Interface {
	return m.current
}
func (m *egressFixtureMonitorState) OverrideAndroidVPN() bool { return false }
func (m *egressFixtureMonitorState) AndroidVPNEnabled() bool  { return false }
func (m *egressFixtureMonitorState) RegisterCallback(
	tun.DefaultInterfaceUpdateCallback,
) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (m *egressFixtureMonitorState) UnregisterCallback(
	*list.Element[tun.DefaultInterfaceUpdateCallback],
) {
}
func (m *egressFixtureMonitorState) RegisterMyInterface(string) {}
func (m *egressFixtureMonitorState) MyInterfaces() []string     { return nil }
