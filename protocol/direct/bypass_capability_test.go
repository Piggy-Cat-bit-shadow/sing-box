package direct

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the direct outbound's bypass capability.
//
// # Why these are built from real options rather than from a flag
//
// The earlier version of this file set an `isEmpty` boolean and asserted on it, which pinned the
// signal but not the judgement behind it: any change to how emptiness was computed passed these
// tests while changing the feature. These build the profile from real option values, so what is
// asserted is the answer the outbound would actually give.

func bypassable(options option.DialerOptions) *Outbound {
	return &Outbound{semantics: dialer.NativeBypassSemantics(options)}
}

func TestCanBypassRequiresSemanticallyEmptyOptions(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")

	plain := bypassable(option.DialerOptions{})
	require.True(t, plain.CanBypass(N.NetworkTCP, address),
		"a plain direct outbound may carry a connection directly")
	require.True(t, plain.CanBypass(N.NetworkUDP, address),
		"the same holds for UDP")

	// Every one of these makes the userspace dialer do something a platform connect does not, so
	// the connection must stay on the userspace path. The option's own value is irrelevant; what
	// matters is that an operator asked for it.
	configured := map[string]option.DialerOptions{
		"bind_interface": {
			AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "en0"},
		},
		"routing_mark": {
			AbstractDialerOptions: option.AbstractDialerOptions{RoutingMark: 0x1234},
		},
		"connect_timeout": {
			AbstractDialerOptions: option.AbstractDialerOptions{
				ConnectTimeout: badoption.Duration(5 * time.Second),
			},
		},
		"network_strategy": {
			AbstractDialerOptions: option.AbstractDialerOptions{
				NetworkStrategy: func() *option.NetworkStrategy {
					strategy := option.NetworkStrategy(C.NetworkStrategyDefault)
					return &strategy
				}(),
			},
		},
		"fallback_delay": {
			AbstractDialerOptions: option.AbstractDialerOptions{
				FallbackDelay: badoption.Duration(300 * time.Millisecond),
			},
		},
		"protect_path": {
			AbstractDialerOptions: option.AbstractDialerOptions{ProtectPath: "/proc/self"},
		},
		"netns": {
			AbstractDialerOptions: option.AbstractDialerOptions{NetNs: "ns1"},
		},
	}
	for name, options := range configured {
		t.Run(name, func(t *testing.T) {
			outbound := bypassable(options)
			require.NotEqual(t, dialer.BlockerNone, outbound.BypassBlockers(N.NetworkTCP, address))
			require.NotEqual(t, dialer.BlockerNone, outbound.BypassBlockers(N.NetworkUDP, address))
		})
	}
}

func TestCanBypassRejectsNonTCPAndNonUDP(t *testing.T) {
	plain := bypassable(option.DialerOptions{})
	address := netip.MustParseAddr("93.184.216.34")

	// ICMP keeps its existing Flow semantics; this optimisation does not apply to it.
	require.False(t, plain.CanBypass(N.NetworkICMP, address))
	require.False(t, plain.CanBypass("", address))
	require.False(t, plain.CanBypass("ip", address))
}

func TestCanBypassRejectsUnusableAddresses(t *testing.T) {
	plain := bypassable(option.DialerOptions{})

	require.False(t, plain.CanBypass(N.NetworkTCP, netip.Addr{}),
		"an invalid address cannot be dialled by anyone")

	zoned := netip.MustParseAddr("fe80::1").WithZone("en0")
	require.False(t, plain.CanBypass(N.NetworkTCP, zoned),
		"a zoned address cannot be expressed through an interface keyed by address alone, so it "+
			"is left to the userspace path")
}

func TestCanBypassPreservesTheLoopbackGuard(t *testing.T) {
	// The direct outbound refuses to dial its own addresses, which is what prevents a TUN from
	// routing a connection back into itself. A bypass is a connect performed by the platform
	// rather than by this dialer, so this guard is the only thing standing between the fast path
	// and that loop.
	// A /24 whose network address is not the destination. The exact-address spelling is refused on
	// Darwin and allowed elsewhere, deliberately (see TestBypassAgreesWithTheDialPathOnSelfAddresses),
	// so a test that wants to pin the guard uses this form.
	selfPrefix := netip.MustParsePrefix("10.0.0.0/24")
	plain := bypassable(option.DialerOptions{})
	plain.myAddresses.Store([]netip.Prefix{selfPrefix})

	require.False(t, plain.CanBypass(N.NetworkTCP, netip.MustParseAddr("10.0.0.1")),
		"a destination inside this outbound's own prefix must not be bypassed")
	require.Contains(t, plain.BypassBlockers(N.NetworkTCP, netip.MustParseAddr("10.0.0.1")).String(),
		"this host's own address")

	require.True(t, plain.CanBypass(N.NetworkTCP, netip.MustParseAddr("93.184.216.34")),
		"an unrelated destination is unaffected by the guard")
}

// --- per-flow semantics -------------------------------------------------------------------

// TestCanBypassDistinguishesOptionPresenceFromFlowRelevance is the case this round exists for.
//
// The production topology's direct outbound carries domain_resolver and nothing else. Comparing the
// configuration refused every flow through it; comparing the semantics does not, because a literal
// destination never reaches the resolver.
//
// The control is the second half: the same outbound must still refuse when the resolver WOULD take
// part, which is what stops this from being a blanket relaxation.
func TestCanBypassDistinguishesOptionPresenceFromFlowRelevance(t *testing.T) {
	withResolver := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
		},
	})

	require.False(t, withResolver.IsEmpty(),
		"an outbound with a domain resolver is not empty: it resolves names")

	ipv4 := netip.MustParseAddr("93.184.216.34")
	ipv6 := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")

	require.True(t, withResolver.CanBypass(N.NetworkTCP, ipv4),
		"but a literal-IPv4 flow through it never reaches the resolver, so the platform's own "+
			"connect reproduces it exactly")
	require.True(t, withResolver.CanBypass(N.NetworkTCP, ipv6),
		"and the same for IPv6 under a strategy that does not restrict families")
	require.True(t, withResolver.CanBypass(N.NetworkUDP, ipv4))

	// The control. A hard family restriction DOES reach the literal destination, because the dial
	// path applies it to the original attempt and not only to resolved candidates. Without this
	// half, the assertions above would pass just as well if the resolver option were ignored.
	strict := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
		},
	})
	strict.familyStrategy = func() C.DomainStrategy { return C.DomainStrategyIPv4Only }

	require.False(t, strict.CanBypass(N.NetworkTCP, ipv6),
		"ipv4_only excludes a literal IPv6 destination in the userspace path, so the platform's "+
			"connect is NOT equivalent and the bypass must be refused")
	require.Contains(t, strict.BypassBlockers(N.NetworkTCP, ipv6).String(), "family strategy")
	require.True(t, strict.CanBypass(N.NetworkTCP, ipv4),
		"while a literal IPv4 destination is exactly what that policy permits")

	strict6 := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
		},
	})
	strict6.familyStrategy = func() C.DomainStrategy { return C.DomainStrategyIPv6Only }
	require.False(t, strict6.CanBypass(N.NetworkTCP, ipv4))
	require.True(t, strict6.CanBypass(N.NetworkTCP, ipv6))
}

// TestCanBypassKeepsATCPOnlyOptionOffTheUDPPath pins the other half of flow-sensitivity.
//
// tcp_fast_open is applied to the TCP dialer and never to a UDP socket. A profile that refused both
// networks for it would be safe and would refuse a bypass the operator could have had.
func TestCanBypassKeepsATCPOnlyOptionOffTheUDPPath(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")

	fastOpen := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true},
	})
	require.False(t, fastOpen.CanBypass(N.NetworkTCP, address),
		"tcp_fast_open changes the TCP connect and is not reproduced natively")
	require.True(t, fastOpen.CanBypass(N.NetworkUDP, address),
		"but it is never applied to a UDP socket, so a UDP flow through the same outbound is "+
			"still exactly a plain connect")

	keepAlive := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{DisableTCPKeepAlive: true},
	})
	require.False(t, keepAlive.CanBypass(N.NetworkTCP, address))
	require.True(t, keepAlive.CanBypass(N.NetworkUDP, address))

	// reuse_addr is applied to the UDP listener only, so it is the mirror image.
	reuseAddr := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{ReuseAddr: true},
	})
	require.False(t, reuseAddr.CanBypass(N.NetworkUDP, address),
		"reuse_addr is applied to the UDP listener")
	require.True(t, reuseAddr.CanBypass(N.NetworkTCP, address),
		"and reaches the TCP dialer nowhere")

	// An explicitly configured UDP fragment is a UDP socket option. The constructor's own default
	// is not: it is not a configuration, and treating it as one would refuse every direct outbound
	// in this fork.
	explicitFragment := bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			UDPFragment: func() *bool { value := false; return &value }(),
		},
	})
	require.False(t, explicitFragment.CanBypass(N.NetworkUDP, address))
	require.True(t, explicitFragment.CanBypass(N.NetworkTCP, address))
}

// --- global network policy (§16, §17, §18) ---------------------------------------------

// networkManagerStub reports a fixed set of global defaults.
type networkManagerStub struct {
	adapter.NetworkManager
	options adapter.NetworkOptions
}

func (m *networkManagerStub) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *networkManagerStub) Close() error                                               { return nil }
func (m *networkManagerStub) DefaultOptions() adapter.NetworkOptions {
	return m.options
}

// TestCanBypassFailsClosedWithGlobalNetworkPolicy is §17.
//
// Each of these makes the userspace dialer do something a native connect does not: bind to an
// interface, mark packets, or select an interface by strategy. Bypassing would silently discard
// the policy.
func TestCanBypassFailsClosedWithGlobalNetworkPolicy(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")
	networkStrategy := C.NetworkStrategyDefault

	cases := map[string]adapter.NetworkOptions{
		"default_interface":        {BindInterface: "en0"},
		"default_mark":             {RoutingMark: 0x1234},
		"default_network_strategy": {NetworkStrategy: &networkStrategy},
		"default_network_type":     {NetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}},
		"default_fallback_network_type": {
			FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeCellular},
		},
		"default_fallback_delay": {FallbackDelay: 300 * time.Millisecond},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			outbound := bypassable(option.DialerOptions{})
			outbound.network = &networkManagerStub{options: options}
			require.False(t, outbound.CanBypass(N.NetworkTCP, address),
				"%s is set globally, so the userspace dialer applies policy a native bypass does "+
					"not; the connection must not take the fast path", name)
			require.Contains(t, outbound.BypassBlockers(N.NetworkTCP, address).String(),
				"ambient network policy")
		})
	}
}

// TestCanBypassAllowedWithNoGlobalPolicy is the control.
//
// Without this, a guard that always returned false would pass the test above.
func TestCanBypassAllowedWithNoGlobalPolicy(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")

	outbound := bypassable(option.DialerOptions{})
	outbound.network = &networkManagerStub{options: adapter.NetworkOptions{}}
	require.True(t, outbound.CanBypass(N.NetworkTCP, address),
		"a plain outbound with no global policy may carry the connection directly")

	// A nil manager means no global policy exists to lose.
	noManager := bypassable(option.DialerOptions{})
	require.True(t, noManager.CanBypass(N.NetworkTCP, address))
}

// TestIsEmptyStaysConservativeForTheDetourCheck pins that the emptiness question was NOT relaxed
// along with the bypass question.
//
// They are different questions about the same options. "Does a detour to this outbound make sense?"
// asks whether the outbound does anything at all, and a resolver does something. "May this flow
// bypass?" asks whether the outbound would do anything for THIS flow, and for a literal
// destination a resolver does not.
func TestIsEmptyStaysConservativeForTheDetourCheck(t *testing.T) {
	require.True(t, bypassable(option.DialerOptions{}).IsEmpty())
	require.False(t, bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
		},
	}).IsEmpty(), "a resolver is not nothing, even though it is nothing for a literal flow")
	require.False(t, bypassable(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "en0"},
	}).IsEmpty())
}

// TestAnUnbuiltProfileRefuses is the fail-closed default at the outbound level.
//
// NewOutbound always builds the profile, so this is about the outbound that was constructed some
// other way - which is a pattern this file used to use itself. The zero profile must refuse rather
// than permit, or that construction mistake becomes a bypassed connection.
func TestAnUnbuiltProfileRefuses(t *testing.T) {
	unbuilt := &Outbound{}
	address := netip.MustParseAddr("93.184.216.34")

	require.False(t, unbuilt.CanBypass(N.NetworkTCP, address),
		"an outbound that never interpreted its options cannot claim equivalence with a plain connect")
	require.Contains(t, unbuilt.BypassBlockers(N.NetworkTCP, address).String(), "never interpreted")
	require.False(t, unbuilt.IsEmpty(),
		"and it is certainly not an outbound that does nothing")

	// The control: the same outbound with the profile built from empty options does bypass.
	require.True(t, bypassable(option.DialerOptions{}).CanBypass(N.NetworkTCP, address))
}
