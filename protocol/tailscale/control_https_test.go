//go:build with_tailscale

package tailscale

import (
	"os"
	"testing"

	"github.com/sagernet/tailscale/envknob"

	"github.com/stretchr/testify/require"
)

// The coordinator channel must default to port 443.
//
// # The failure this pins
//
// The control client starts on port 80 and only migrates to 443 once it observes the connection
// is dead. A DPI middlebox that freezes the port-80 channel after the Upgrade produces no such
// observation, so the node reads as offline for ~15 minutes after every start. The knob is
// tailscale's own TS_FORCE_NOISE_443.
func TestForceNoise443DefaultIsOn(t *testing.T) {
	// The package init already ran for this process; assert what it produced.
	require.Equal(t, "true", os.Getenv(forceNoise443EnvVar))
	require.True(t, envknob.RegisterBool(forceNoise443EnvVar)())
}

// An explicit operator value must win, including "false".
func TestForceNoise443HonoursAnExplicitValue(t *testing.T) {
	t.Setenv(forceNoise443EnvVar, "false")
	// t.Setenv is reverted after the test, so re-apply the package default for later tests in
	// this process.
	t.Cleanup(func() {
		if _, isSet := os.LookupEnv(forceNoise443EnvVar); isSet {
			return
		}
		applyForceNoise443()
	})

	applyForceNoise443()
	require.Equal(t, "false", os.Getenv(forceNoise443EnvVar),
		"an explicit value must not be overwritten by the fork's default")
}
