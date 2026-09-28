//go:build jiejie_client_macos

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The macOS product CLI surface is part of the product definition, not an
// implementation detail that happens to fall out of link order.
//
// These tests exist because the surface is easy to widen BY ACCIDENT. An upstream
// sync that adds a command, a new file whose init() calls AddCommand, or a change
// to the exclusion predicate would all silently restore a command this deployment
// does not use -- and nothing else in CI would notice, because a binary with more
// commands still passes every functional test.
//
// The expected set is asserted as an EXACT set rather than a subset for that
// reason: "at least run/check/version" would pass on a binary that had quietly
// regained every removed command.

// TestProductCLISurfaceIsExactlyRuntimeEssentials pins the shipped command set.
func TestProductCLISurfaceIsExactlyRuntimeEssentials(t *testing.T) {
	t.Parallel()

	registered := make(map[string]bool)
	for _, command := range mainCommand.Commands() {
		registered[command.Name()] = true
	}

	// `help` is NOT in this set: Cobra synthesises it at execution time rather than
	// registering a command object, so it does not appear in mainCommand.Commands()
	// even though `sing-box help` works. It is asserted behaviourally instead, by
	// the shipped-binary check in CI.
	//
	// `netns-holder` IS registered but marked Hidden, and it must stay registered:
	// cmd_run.go passes its Use string to box.New as the re-exec argument for a
	// Linux network namespace, so removing the symbol breaks the Linux build even
	// though the command is never typed.
	expected := map[string]bool{
		"run":          true, // launchd's ProgramArguments
		"check":        true, // the wrapper validates a candidate config
		"version":      true, // the wrapper and CI report the build
		"netns-holder": true, // hidden; a symbol cmd_run.go needs, not a user command
	}

	for name := range expected {
		require.True(t, registered[name],
			"the product CLI must provide %q; it is how this core is started and validated", name)
	}
	for name := range registered {
		require.True(t, expected[name],
			"unexpected command %q in the macOS product CLI; either it is needed by the "+
				"deployment and belongs in the expected set, or it should be withheld via "+
				"productExcludesCommand", name)
	}

	require.Len(t, registered, len(expected),
		"the macOS product CLI must expose exactly %d commands", len(expected))
}

// TestProductExcludesTheDevelopmentTooling pins each excluded command individually,
// so a failure names the command that came back rather than only reporting a count.
func TestProductExcludesTheDevelopmentTooling(t *testing.T) {
	t.Parallel()

	// Every entry here is a command that was present in the shipped binary before
	// this round and is deliberately gone.
	//
	// `lxd` is NOT in this list because its source was deleted outright in the
	// previous round: there is no registration left to withhold, and asserting on it
	// here would be asserting something this predicate is not responsible for. The
	// audit script covers package absence instead.
	//
	// `netns-holder` is NOT in this list either: it is Hidden rather than withheld,
	// because cmd_run.go needs its Use string as the re-exec argument for the Linux
	// network namespace.
	for _, name := range []string{
		"api",        // the Dashboard is the only management surface
		"completion", // no interactive shell in this deployment
		"format",     // configs are edited by hand, then `check`ed
		"generate",   // server-operator key/certificate generation
		"geoip",      // GeoIP tooling
		"geosite",    // GeoSite tooling
		"merge",      // packaging-time config composition
		"rule-set",   // rule-set publishing tooling
		"schema",     // docs generation, done in CI
		"tools",      // fetch/connect/stun/networkquality/synctime
	} {
		require.True(t, productExcludesCommand(name),
			"%q must be withheld from the macOS product CLI", name)
	}
}

// TestProductKeepsRuntimeEssentials is the positive half, asserted separately so a
// predicate that excluded EVERYTHING would fail loudly here rather than producing a
// confusing "unexpected command" error above.
func TestProductKeepsRuntimeEssentials(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"run", "check", "version"} {
		require.False(t, productExcludesCommand(name),
			"%q is required by the deployment and must NOT be withheld", name)
	}
}

// TestOtherBuildsKeepTheFullCLI proves the narrowing is a property of THIS product
// only. The predicate lives in a profile-tagged file, so a build without the tag
// must withhold nothing -- otherwise a generic or Linux-server build would silently
// lose commands that scripts and documentation may rely on.
//
// This test runs under the macOS tag set, so it asserts the tag-scoped half: that
// the macOS predicate is NOT the identity function. The complementary half is
// covered by cmd_product_other.go compiling to a constant false, which the
// non-macOS build verifies by construction.
func TestMacOSPredicateIsNotIdentity(t *testing.T) {
	t.Parallel()

	var excluded, kept int
	for _, name := range []string{"run", "check", "version", "api", "tools", "schema"} {
		if productExcludesCommand(name) {
			excluded++
		} else {
			kept++
		}
	}
	require.Positive(t, excluded, "the macOS profile must withhold something")
	require.Positive(t, kept, "the macOS profile must keep the runtime essentials")
}
