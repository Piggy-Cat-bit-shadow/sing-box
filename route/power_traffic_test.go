package route

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/power"

	"github.com/stretchr/testify/require"
)

// TestRouterForwardsRealTrafficToTheGovernor is the glue that makes traffic-driven wake real.
//
// The discrimination this rests on is that the router's entry point sees traffic the DEVICE asked
// for, while the core's own liveness traffic - URLTest probes, DNS queries - dials its outbound or
// its transport directly and never arrives here. If that were wrong, the governor would be woken by
// the very maintenance it gates, and would keep the device out of the idle state that maintenance
// is supposed to stop in.
func TestRouterForwardsRealTrafficToTheGovernor(t *testing.T) {
	policy := power.DefaultPolicy()
	policy.DeepIdleAfter = 20 * time.Millisecond
	governor := power.NewGovernor(policy)
	t.Cleanup(governor.Close)

	router := &Router{powerGovernor: governor}

	// Put it to sleep and let it reach deep idle.
	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == power.StateDeepIdle },
		3*time.Second, 5*time.Millisecond)

	router.observeTraffic()

	require.Equal(t, power.StateQuiescent, governor.State(),
		"real traffic did not reach the governor, so a sleeping device would never notice it is in use")

	// And it must NOT return to ACTIVE: a push notification's request would otherwise re-enable every
	// speculative subsystem at once, which is the wake storm the brief names.
	require.False(t, governor.Allow().ProviderRefresh)
	require.False(t, governor.Allow().Statistics)
}

// TestRouterWithoutAGovernorIsSafe is the compatibility half: a Router built directly, which is what
// most of this package's tests do, has no governor and must behave exactly as before.
func TestRouterWithoutAGovernorIsSafe(t *testing.T) {
	router := &Router{}
	require.NotPanics(t, router.observeTraffic)
}
