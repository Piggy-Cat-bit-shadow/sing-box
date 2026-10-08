package interop

import (
	"os"
	"strings"
)

// The live gate.
//
// Two independent halves — a build tag and an environment variable — and both
// must be present before a single reference process is spawned. The reason is
// that the two halves fail differently:
//
//   - The build tag is what a maintainer controls when building. Without it the
//     test binary cannot even be asked to run live, so a stray environment
//     variable in a CI image cannot start xray processes.
//   - The environment variable is what a maintainer controls when running.
//     Without it, a binary built with `-tags liveinterop` (a whole-repository
//     build for some other purpose) still will not spawn anything.
//
// When the gate is off, every live test SKIPS and the skip text is the exact
// command that would turn it on. It never fails: in this environment there is no
// reference binary and no network, and a failing test would be indistinguishable
// from a real protocol regression.

// LiveInteropEnvVar is the environment-variable half of the gate.
const LiveInteropEnvVar = "RUN_LIVE_XRAY_INTEROP"

// LiveInteropBuildTag is the build-tag half of the gate. It is spelled without
// the leading `-tags` so it can also be used in a message.
const LiveInteropBuildTag = "liveinterop"

// LiveInteropEnableCommand is the copy-paste command that enables the live half.
//
// It is built from the same constants the gate checks, so a rename cannot leave
// the skip message pointing at a tag or variable that no longer exists — the
// most common way a "how to enable me" message becomes a lie.
const LiveInteropEnableCommand = "cd test && " + LiveInteropEnvVar + "=1 XRAY_BINARY=/path/to/xray \\\n" +
	"  go test -tags \"$(cat ../release/DEFAULT_BUILD_TAGS)," + LiveInteropBuildTag + "\" -count=1 -timeout 20m -v -run TestLiveInterop ./interop/"

// LiveInteropGateReason returns the reason the live half is disabled, or the
// empty string when both halves of the gate are satisfied.
//
// Both inputs are parameters rather than read from the process so the message
// itself is testable in the default (non-live) build: the wording is the only
// thing a maintainer sees when a test skips, and a typo in it is invisible until
// someone cannot work out how to run the suite.
func LiveInteropGateReason(buildTag bool, envValue string) string {
	if !buildTag {
		return "reference interop is disabled: build tag `" + LiveInteropBuildTag + "` is not set.\n" +
			"Enable it exactly like this:\n  " + LiveInteropEnableCommand
	}
	if envValue != "1" {
		return "reference interop is disabled: " + LiveInteropEnvVar + " is not set to 1.\n" +
			"Enable it exactly like this:\n  " + LiveInteropEnableCommand
	}
	return ""
}

// LiveInteropSkipReason evaluates the gate against this process.
func LiveInteropSkipReason() string {
	return LiveInteropGateReason(liveInteropBuildTag, os.Getenv(LiveInteropEnvVar))
}

// H3EnableEnvVar is the extra gate on the HTTP/3 scenario.
//
// H3 gets a third gate of its own rather than riding on the live gate because it
// is the one scenario the harness cannot probe honestly: readiness for a QUIC
// listener cannot be established by connecting to it, and XHTTP-over-H3 support
// in the reference is a property of the installed build rather than of the
// protocol revision. Running it by mistake would produce a failure that a
// maintainer could not tell apart from a transport bug, so it is opt-in.
const H3EnableEnvVar = "INTEROP_ENABLE_H3"

// H3GateReason returns the reason the H3 scenario is disabled, or the empty
// string when it is enabled.
func H3GateReason() string {
	if os.Getenv(H3EnableEnvVar) != "1" {
		return "the XHTTP-over-HTTP/3 scenario is opt-in: set " + H3EnableEnvVar + "=1 to run it.\n" +
			"It is separate from the live gate because a QUIC listener cannot be readiness-probed " +
			"with a TCP connect, and H3 support in the reference depends on the installed build " +
			"rather than on the protocol revision.\n" +
			"Enable it exactly like this:\n  " + strings.Replace(LiveInteropEnableCommand, LiveInteropEnvVar+"=1", LiveInteropEnvVar+"=1 "+H3EnableEnvVar+"=1", 1)
	}
	return ""
}

// LiveInteropCapabilityReason reports why this BUILD cannot run a scenario, or
// the empty string when it can.
//
// The scenario is refused rather than attempted because every one of these
// combinations fails inside box.New, before the reference is dialled, with an
// error about the build rather than about the protocol. A skip that names the
// missing tag is the truthful report; a failure would read as an interop bug.
func LiveInteropCapabilityReason(scenario Scenario) string {
	var missing []string
	if !buildHasUTLS {
		missing = append(missing, "with_utls (REALITY and uTLS)")
	}
	if scenario.Transport == TransportXHTTP && !buildHasXHTTP {
		missing = append(missing, "with_xhttp (the XHTTP client transport)")
	}
	if scenario.H3 && !buildHasQUIC {
		missing = append(missing, "with_quic (HTTP/3)")
	}
	if len(missing) == 0 {
		return ""
	}
	return "reference interop cannot run scenario " + scenario.Name + ": this build lacks " +
		strings.Join(missing, ", ") + ".\nBuild with the repository's default tags: " + LiveInteropEnableCommand
}
