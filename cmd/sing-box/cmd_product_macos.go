//go:build jiejie_client_macos

package main

// The Jiejie macOS product exposes a deliberately SMALL command surface.
//
// # Why this exists at all
//
// The shipped core is driven by a wrapper (`jiejie start|stop|restart|status|logs|web`)
// and by launchd. The commands it actually needs are exactly three:
//
//	run      launchd's ProgramArguments
//	check    the wrapper validates a candidate config before restarting
//	version  the wrapper and CI report the build
//
// Every other top-level command is development, packaging or server-operator
// tooling that nothing in this deployment invokes. Leaving them registered costs
// twice: their command trees link into the binary, and `sing-box --help`
// advertises a dozen surfaces that are not supported product features.
//
// # Why a predicate here rather than build constraints on every command file
//
// The alternative was a `//go:build !jiejie_client_macos` line on each of the ~90
// command files. That is a large diff spread across upstream-owned files, and every
// upstream sync would conflict with it. Gating the single AddCommand call per
// command is one line per command in files this fork already owns, and the linker
// still drops the entire unregistered subtree -- which is where the size comes from.
//
// This does NOT rely on "the init() happens not to be called". Each excluded
// command's registration is explicitly conditioned on this predicate, and
// cmd_product_macos_test.go asserts the resulting surface is exactly {check, run,
// version} so an upstream sync that adds a command cannot quietly widen it.

// productExcludesCommand reports whether this product withholds a top-level command.
//
// Each entry names what would have to start invoking it for it to come back. The
// list is derived from the real deployment, not from "a desktop user might want it".
// productExcludesCommand reports the commands the macOS product withholds by
// RUNTIME decision rather than by build constraint.
//
// # Why only two commands are left here
//
// This predicate used to gate ten command families. It was effective at hiding them
// from `--help`, and ineffective at everything else: a Go package whose init() calls
// AddCommand is still compiled and linked even when that call is skipped, so the
// command trees and their dependencies stayed in the binary. The measurement that
// settled it -- geosite, maxminddb, the adguard converter and the schema generator
// were all still linked and all still in `go list -deps` -- is recorded in the
// commit that replaced those gates with build constraints.
//
// Those families now carry `//go:build !jiejie_client_macos`, so they are absent
// from the macOS compilation entirely rather than hidden at runtime. What remains
// here are the two cases a build constraint cannot express:
//
//	completion   Cobra synthesises this command itself, so there is no file to
//	             constrain. Withholding it is a flag on the root command.
//	netns-holder it must STAY REGISTERED on Linux: cmd_run.go passes its Use string
//	             to box.New as the re-exec argument for the network namespace, so
//	             removing the symbol breaks the Linux build even though the command
//	             is never typed. It is Hidden instead, which is what keeps it out of
//	             `--help`.
func productExcludesCommand(name string) bool {
	switch name {
	case "completion":
		// No interactive shell exists in this deployment; `jiejie` is the only
		// entry point. Every other build keeps it.
		return true
	}
	return false
}
