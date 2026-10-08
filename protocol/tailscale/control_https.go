//go:build with_tailscale

package tailscale

import (
	"os"

	"github.com/sagernet/tailscale/envknob"
)

// forceNoise443EnvVar makes the tailscale coordinator connection use port 443.
//
// # The failure it prevents
//
// The control client starts its Noise channel on port 80 and only moves to 443 when the
// connection is observed to be dead. Behind a DPI middlebox that freezes the port-80 channel
// after the HTTP Upgrade, nothing tells the client the socket is gone: it keeps writing to it
// and the node shows as offline for roughly fifteen minutes after every start, with the exit
// node limping along on the stale DERP map. Forcing the coordinator channel onto 443 removes
// the frozen path entirely.
//
// The knob is upstream's own (tailscale reads TS_FORCE_NOISE_443), not a bespoke switch, so
// there is no new configuration surface and no behaviour invented here. An explicit value from
// the environment - including "false" - always wins, so an operator can turn it back off.
const forceNoise443EnvVar = "TS_FORCE_NOISE_443"

func init() {
	applyForceNoise443()
}

func applyForceNoise443() {
	if _, isSet := os.LookupEnv(forceNoise443EnvVar); isSet {
		return
	}
	// Setenv rather than os.Setenv: controlhttp may already have registered the knob, in which
	// case the value it parsed at registration time has to move with the environment. Writing
	// only the environment would leave that already-parsed value reading false.
	envknob.Setenv(forceNoise443EnvVar, "true")
}
