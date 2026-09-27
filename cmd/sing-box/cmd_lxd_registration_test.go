//go:build with_lxd

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// CLI registration tests for the `lxd` command surface.
//
// # Why these inspect the cobra tree and not the source
//
// The launcher decides whether a core supports daemon mode by running
//
//	<core> lxd --help
//
// and checking the output for `--state-dir`. That is an acceptance test against the
// REAL command tree, so the thing worth asserting is that the tree contains what the
// launcher looks for. A source-level grep would pass on a command that was declared
// but never added to mainCommand, or whose flags were renamed - exactly the failures
// that would make the launcher report "no lxd support" again.
//
// These run only under `with_lxd`, because without the tag the command does not exist
// and its absence is the correct behaviour (asserted in the sibling file).

// findSubcommand returns the named direct child of parent, or nil.
func findSubcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, child := range parent.Commands() {
		if child.Name() == name {
			return child
		}
	}
	return nil
}

// TestLxdCommandIsRegisteredOnMainCommand is the primary registration assertion.
//
// It checks mainCommand itself rather than a package-level variable, so a command that
// was built but never attached fails here.
func TestLxdCommandIsRegisteredOnMainCommand(t *testing.T) {
	lxd := findSubcommand(mainCommand, "lxd")
	require.NotNil(t, lxd,
		"`lxd` must be registered on mainCommand; without it `sing-box lxd --help` "+
			"fails with 'unknown command' and the launcher reports no daemon support")
	require.NotEmpty(t, lxd.Short, "the lxd command needs a Short description for --help")
}

// TestLxdHelpAdvertisesTheLauncherProbeFlags pins the exact contract the launcher
// checks for.
//
// The launcher runs `lxd --help` and greps for `--state-dir`. If that flag is renamed
// the launcher silently concludes the core has no daemon mode, which is a failure that
// looks like a missing feature rather than a rename - so it is asserted directly.
func TestLxdHelpAdvertisesTheLauncherProbeFlags(t *testing.T) {
	lxd := findSubcommand(mainCommand, "lxd")
	require.NotNil(t, lxd)

	// The probe flag.
	require.NotNil(t, lxd.PersistentFlags().Lookup("state-dir"),
		"`--state-dir` must exist: it is the flag the launcher greps for in `lxd --help`")

	// The rest of the daemon surface the launcher and an operator drive.
	for _, name := range []string{
		"service",     // install / uninstall / status / copy
		"dry-run",     // side-effect-free service install check
		"exec-dir",    // where the root-owned copy lives
		"invite-out",  // pairing invite written to a file
		"invite-name", // the paired client's name
		"purge",       // uninstall + delete state
		"keep-copy",   // uninstall but keep the root copy
		"run",         // force the core up
		"config-force",
	} {
		require.NotNil(t, lxd.Flags().Lookup(name),
			"`lxd --%s` must exist", name)
	}

	// The help text must actually CONTAIN the strings the launcher greps for. A flag
	// can exist and still be hidden from help, which would defeat the probe.
	help := lxd.UsageString()
	require.Contains(t, help, "--state-dir",
		"`lxd --help` output must contain --state-dir, because that is what the launcher checks")
	require.Contains(t, help, "--service",
		"`lxd --help` output must contain --service")
}

// TestLxdClientSubcommandsAreRegistered pins the client-management surface.
func TestLxdClientSubcommandsAreRegistered(t *testing.T) {
	lxd := findSubcommand(mainCommand, "lxd")
	require.NotNil(t, lxd)

	client := findSubcommand(lxd, "client")
	require.NotNil(t, client, "`lxd client` must exist: it manages trusted launcher clients")

	for _, name := range []string{"add", "list", "remove"} {
		require.NotNilf(t, findSubcommand(client, name),
			"`lxd client %s` must be registered", name)
	}
}

// TestLxdClientAddAcceptsInviteOut pins the pairing flag used by the installer path.
func TestLxdClientAddAcceptsInviteOut(t *testing.T) {
	lxd := findSubcommand(mainCommand, "lxd")
	require.NotNil(t, lxd)
	client := findSubcommand(lxd, "client")
	require.NotNil(t, client)
	add := findSubcommand(client, "add")
	require.NotNil(t, add)

	require.NotNil(t, add.Flags().Lookup("invite-out"),
		"`lxd client add --invite-out` must exist; the installer writes the invite to a "+
			"file rather than scraping stdout")
	require.NotNil(t, add.Flags().Lookup("name"),
		"`lxd client add --name` labels the paired client")
}

// TestLxdServiceFlagDocumentsEveryMode pins the --service vocabulary.
//
// These are the values the launcher and the installer script pass. A missing mode is a
// command that fails at runtime, so the vocabulary is asserted rather than assumed.
func TestLxdServiceFlagDocumentsEveryMode(t *testing.T) {
	lxd := findSubcommand(mainCommand, "lxd")
	require.NotNil(t, lxd)

	flag := lxd.Flags().Lookup("service")
	require.NotNil(t, flag)

	for _, mode := range []string{"install", "install-user", "copy", "uninstall", "status"} {
		require.Contains(t, flag.Usage, mode,
			"`--service` must document the %q mode", mode)
	}

	// The status mode's EXIT CODES are a contract: the launcher distinguishes
	// "installed and running" (0) from "needs reinstall" (2) from "not installed" (3)
	// from "copy only" (4) from "not running" (5) by exit status, not by parsing text.
	for _, code := range []string{"0", "2", "3", "4", "5"} {
		require.Contains(t, flag.Usage, code,
			"`--service` must document exit code %s for the status mode; the launcher "+
				"branches on it", code)
	}
}
