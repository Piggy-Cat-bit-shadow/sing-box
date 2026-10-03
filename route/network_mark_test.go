package route

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the auto-redirect output mark registry.
//
// # The defect these pin
//
// A TUN inbound claims a PROCESS-GLOBAL output mark during its CONSTRUCTOR:
//
//	NewInbound -> networkManager.RegisterAutoRedirectOutputMark(mark)
//
// The registry refuses a second claim, because only one auto-redirect can be active. But it has no
// release path at all, and the constructor can fail AFTER claiming: the DNS-mode and mark
// registration steps that follow it return errors.
//
// A failed constructor is discarded without Close, so the claim is never released. The manager then
// permanently believes an auto-redirect is configured, and a LATER, VALID configuration is refused
// with "only one auto-redirect can be configured" even though nothing is running and no TUN exists.

// newMarkTestManager returns a manager with an empty mark registry.
func newMarkTestManager(t *testing.T) *NetworkManager {
	t.Helper()
	manager := &NetworkManager{}
	require.EqualValues(t, 0, manager.AutoRedirectOutputMark(),
		"a fresh manager has no mark registered")
	return manager
}

// TestFailedConstructorDoesNotLeakTheOutputMark is the release blocker.
//
// The claim must be releasable, so a constructor that fails after claiming can undo it.
func TestFailedConstructorDoesNotLeakTheOutputMark(t *testing.T) {
	manager := newMarkTestManager(t)

	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023),
		"the first claim succeeds")

	// The constructor failed after this point, so it must be able to give the claim back.
	manager.UnregisterAutoRedirectOutputMark()

	require.EqualValues(t, 0, manager.AutoRedirectOutputMark(),
		"a failed constructor must be able to release the mark it claimed. Without a release "+
			"path the claim is permanent: a later VALID configuration with auto_redirect is "+
			"refused with \"only one auto-redirect can be configured\" although nothing is running")

	// And a later configuration can now claim it.
	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023),
		"a subsequent valid configuration must be able to claim the mark")
}

// TestSecondClaimIsStillRefused is the positive control.
//
// The release must not weaken the rule it exists to support.
func TestSecondClaimIsStillRefused(t *testing.T) {
	manager := newMarkTestManager(t)

	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023))
	err := manager.RegisterAutoRedirectOutputMark(0x2024)
	require.Error(t, err,
		"two simultaneous auto-redirects must still be refused")

	require.EqualValues(t, 0x2023, manager.AutoRedirectOutputMark(),
		"and the refused claim must not have replaced the active one")
}

// TestUnregisterWithoutClaimIsSafe covers Close on a TUN that never claimed.
func TestUnregisterWithoutClaimIsSafe(t *testing.T) {
	manager := newMarkTestManager(t)

	manager.UnregisterAutoRedirectOutputMark()
	require.EqualValues(t, 0, manager.AutoRedirectOutputMark(),
		"releasing without a claim must not corrupt the registry")

	// It must not have marked anything as free-and-in-use either.
	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023))
}

// TestRepeatedRegisterAfterReleaseDoesNotAccumulate is the steady state.
func TestRepeatedRegisterAfterReleaseDoesNotAccumulate(t *testing.T) {
	manager := newMarkTestManager(t)

	for attempt := 0; attempt < 50; attempt++ {
		require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023),
			"cycle %d must be able to claim, because the previous one released", attempt)
		manager.UnregisterAutoRedirectOutputMark()
	}
}
