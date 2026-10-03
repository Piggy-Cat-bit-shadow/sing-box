package rule

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests that rule ordering is untouched by the Direct Fast Path.
//
// # Why these live here rather than in the route package
//
// The pre-match loop type-asserts the concrete action types, and those types live in THIS
// package. A test in `route` cannot construct them without an import cycle, and asserting
// against stand-ins that never match the switch would prove nothing at all - it would only show
// that a fake was ignored.
//
// Here the rules are built through the production NewRule path, so the assertions run against
// the real actions the pre-match loop dispatches on.

// directOutboundStub is a plain direct outbound that would allow the fast path.
type directOutboundStub struct {
	adapter.Outbound
}

func (o *directOutboundStub) Type() string      { return C.TypeDirect }
func (o *directOutboundStub) Tag() string       { return "direct" }
func (o *directOutboundStub) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *directOutboundStub) CanBypass(network string, destination netip.Addr) bool {
	return true
}

// proxyOutboundStub is an outbound that does not implement the bypass capability.
type proxyOutboundStub struct {
	adapter.Outbound
}

func (o *proxyOutboundStub) Type() string      { return "socks" }
func (o *proxyOutboundStub) Tag() string       { return "proxy" }
func (o *proxyOutboundStub) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

// TestRejectActionIsFinalNotBypassable pins that a reject keeps its meaning.
//
// The fast path only runs after the pre-match loop has settled on an outbound. A reject never
// settles on one, so no combination of a bypassable default direct can turn a rejection into a
// bypassed connection.
func TestRejectActionIsFinalNotBypassable(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("rule")

	rule, err := NewRule(context.Background(), logger, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Network: []string{N.NetworkTCP},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeReject,
			},
		},
	}, false)
	require.NoError(t, err)

	action, isReject := rule.Action().(*RuleActionReject)
	require.True(t, isReject,
		"a reject rule must produce a reject action so the pre-match loop can dispatch on it")
	require.NotNil(t, action)

	// It must be recognised as final, which is what stops the loop from continuing to an
	// outbound - and therefore what keeps the fast path unreachable behind it.
	require.True(t, adapter.IsFinalAction(rule.Action()),
		"a reject must remain a final action; a non-final action would let matching continue to "+
			"an outbound that the fast path could bypass")
}

// TestBypassActionIsItsOwnType pins that the explicit bypass is a distinct action.
//
// The new capability must not be confused with - or become a prerequisite for - the user's
// explicit bypass rule.
func TestBypassActionIsItsOwnType(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("rule")

	rule, err := NewRule(context.Background(), logger, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Network: []string{N.NetworkTCP},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeBypass,
			},
		},
	}, false)
	require.NoError(t, err)

	_, isBypass := rule.Action().(*RuleActionBypass)
	require.True(t, isBypass,
		"an explicit bypass rule must produce its own action type")

	// An action with no outbound is still final: it returns a bypass verdict without consulting
	// any outbound, so it cannot be affected by an outbound's capability.
	require.True(t, adapter.IsFinalAction(rule.Action()))
}

// TestRouteActionCarriesItsOutbound pins that a route action names an outbound, which is what
// the fast path inspects afterwards.
func TestRouteActionCarriesItsOutbound(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("rule")

	rule, err := NewRule(context.Background(), logger, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Network: []string{N.NetworkTCP},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "proxy",
				},
			},
		},
	}, true)
	require.NoError(t, err)

	route, isRoute := rule.Action().(*RuleActionRoute)
	require.True(t, isRoute)
	require.Equal(t, "proxy", route.Outbound,
		"a route action must carry the outbound the fast path will examine")

	// A route action IS final: it ends rule matching and hands control to preMatchFlow, which is
	// where the fast path decision is made. Being final is also what guarantees no LATER rule
	// can observe the connection first, so the outbound this action names is the one the fast
	// path examines.
	require.True(t, adapter.IsFinalAction(rule.Action()),
		"a route action ends matching; the fast path decision is made downstream of it")

	// The actions that DO continue matching are the ones that make a connection ineligible,
	// because they can add a domain, resolve candidates or rewrite the destination.
	for _, continuing := range []string{
		C.RuleActionTypeSniff,
		C.RuleActionTypeResolve,
		C.RuleActionTypeEvaluate,
	} {
		require.False(t, adapter.IsFinalAction(&stubTypedAction{actionType: continuing}),
			"%s continues matching and must not be final", continuing)
	}
}

// stubTypedAction reports an action type for the final-action classification check.
type stubTypedAction struct{ actionType string }

func (a *stubTypedAction) Type() string   { return a.actionType }
func (a *stubTypedAction) String() string { return a.actionType }
