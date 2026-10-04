package main

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// The loadbalance group, from a configuration file to a connection.
//
// The route package's tests resolve the chain through the real resolver; these tests go one
// level further out and prove the parts only a real box exercises: the type decodes from
// configuration, the manager accepts or refuses the dependency graph, and a flow routed
// through the group reaches the member the rotation named.

func loadBalanceOptions(members []string, strategy string) option.Options {
	return option.Options{
		Route: &option.RouteOptions{Final: "lb"},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeLoadBalance, Tag: "lb", Options: &option.LoadBalanceOutboundOptions{
				Outbounds: members,
				Strategy:  strategy,
			}},
		},
	}
}

// TestLoadBalanceRejectsUnusableConfigurations is the fail-early requirement: a group that
// cannot balance must not start and then misbehave.
func TestLoadBalanceRejectsUnusableConfigurations(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options option.Options
	}{
		{
			name:    "no members",
			options: loadBalanceOptions(nil, "round_robin"),
		},
		{
			name:    "unknown member",
			options: loadBalanceOptions([]string{"absent"}, "round_robin"),
		},
		{
			name:    "unknown strategy",
			options: loadBalanceOptions([]string{"direct"}, "random"),
		},
		{
			name:    "strategy spelling from another client",
			options: loadBalanceOptions([]string{"direct"}, "consistent-hashing"),
		},
		{
			name: "expected_status without url",
			options: func() option.Options {
				options := loadBalanceOptions([]string{"direct"}, "round_robin")
				options.Outbounds[0].Options.(*option.LoadBalanceOutboundOptions).ExpectedStatus = "204"
				return options
			}(),
		},
		{
			name: "unparseable url",
			options: func() option.Options {
				options := loadBalanceOptions([]string{"direct"}, "round_robin")
				options.Outbounds[0].Options.(*option.LoadBalanceOutboundOptions).URL = "not a url"
				return options
			}(),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(globalCtx)
			defer cancel()
			instance, err := box.New(box.Options{Context: ctx, Options: testCase.options})
			if err == nil {
				err = instance.Start()
				_ = instance.Close()
			}
			require.Error(t, err, "a group that cannot balance must not start")
		})
	}
}

// TestLoadBalanceRejectsACycle is the cycle requirement.
//
// A group whose member list leads back to itself would recurse at routing time; the manager's
// dependency walk refuses it at start. A loadbalance group depends on ALL its members, not
// only on the one it happens to be using, which is what makes the walk able to see a cycle
// that a flow could reach.
func TestLoadBalanceRejectsACycle(t *testing.T) {
	options := option.Options{
		Route: &option.RouteOptions{Final: "lb"},
		Outbounds: []option.Outbound{
			{Type: C.TypeLoadBalance, Tag: "lb", Options: &option.LoadBalanceOutboundOptions{
				Outbounds: []string{"mid"},
			}},
			{Type: C.TypeSelector, Tag: "mid", Options: &option.SelectorOutboundOptions{
				Outbounds: []string{"lb"},
			}},
		},
	}
	ctx, cancel := context.WithCancel(globalCtx)
	defer cancel()
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err == nil {
		err = instance.Start()
		_ = instance.Close()
	}
	require.Error(t, err, "lb -> selector -> lb must be refused when the configuration loads")
}

// TestLoadBalanceRotatesRealConnections is the data-plane proof at the box level.
//
// The group's members are a live outbound and one that always refuses. If the rotation reaches
// the data plane, consecutive flows alternate success and failure; if the group answered every
// flow with its first member - which is what a strategy that is never consulted looks like from
// outside - every flow would succeed. The refusal is the observable, so the test cannot pass by
// the members being indistinguishable.
func TestLoadBalanceRotatesRealConnections(t *testing.T) {
	options := option.Options{
		Route: &option.RouteOptions{Final: "lb"},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "live"},
			{Type: C.TypeBlock, Tag: "refusing", Options: &option.StubOptions{}},
			{Type: C.TypeLoadBalance, Tag: "lb", Options: &option.LoadBalanceOutboundOptions{
				Outbounds: []string{"live", "refusing"},
				Strategy:  "round_robin",
			}},
		},
	}
	startInstance(t, options)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	dial := func() (net.Conn, error) {
		return dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	}

	// The helper serves testPort itself, so the live member's destination is reachable and the
	// refusing member's is not attempted at all.
	results := make([]bool, 0, 4)
	for flow := 0; flow < 4; flow++ {
		results = append(results, testPingPongWithConn(t, testPort, dial) == nil)
	}
	require.Equal(t, []bool{true, false, true, false}, results,
		"consecutive flows must alternate between the live member and the refusing one; "+
			"all succeeding would mean every flow took the first member")
}
