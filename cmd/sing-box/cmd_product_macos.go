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
func productExcludesCommand(name string) bool {
	switch name {
	case "api":
		// A CLI gRPC client for the daemon. The Dashboard is the only management
		// surface this product has, and it speaks the same API over gRPC-Web.
		return true
	case "completion":
		// Generates shell completion scripts. There is no interactive shell in this
		// deployment; `jiejie` is the only entry point.
		return true
	case "format":
		// Reformats configuration files. Configs here are edited by hand and
		// validated with `check`, which is what the wrapper calls.
		return true
	case "generate":
		// Certificate, key, ECH, VAPID and WireGuard generation for server
		// operators. This is a client core.
		return true
	case "geoip":
		// GeoIP database tooling.
		return true
	case "geosite":
		// GeoSite data tooling.
		return true
	case "merge":
		// Build-time configuration composition for packaging pipelines.
		return true
	case "rule-set":
		// Rule-set compilation, conversion and upgrade, used when PUBLISHING
		// rule-sets. This core consumes them at runtime through route.rule_set.
		return true
	case "schema":
		// Documentation generation. docs/schema.json is produced in CI, not by the
		// shipped binary.
		return true
	case "tools":
		// fetch / connect / stun / networkquality / synctime diagnostics.
		return true
	}
	// NOTE: netns-holder is deliberately NOT withheld.
	//
	// It is a hidden command, so it never appears in `--help`, and cmd_run.go passes
	// its Use string to box.New as the re-exec argument for the Linux network
	// namespace. Removing the symbol breaks the build; withholding only the
	// registration would leave the symbol present but unreachable, which is exactly
	// what "hidden" already means.
	return false
}
