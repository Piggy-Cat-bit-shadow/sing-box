//go:build jiejie_client_macos

package jiejie_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Audit of the macOS CLIENT fixture.
//
// This is the counterpart to TestJiejieProductionFixture*, which audits the
// production SERVER fixture. The two are deliberately different files with
// different rules: the server fixture is one known VPS topology and must contain
// nothing else, while the client fixture is the widest set of things a desktop
// core must be able to load.
//
// # Why the MASQUE endpoint is asserted here
//
// `masque-client` was UNREGISTERED in the macOS client profile even though the
// whole implementation was compiled in, so a valid configuration failed with
// "unknown endpoint type". The registry audit in
// macos_client_registry_audit_test.go now asserts the registration directly; this
// file asserts the other half, that the FIXTURE actually exercises it.
//
// The two are not redundant. A registry test proves the type resolves; a fixture
// test proves the configuration a user would write is covered by
// `sing-box check` in CI. Without the fixture entry, the registration could be
// removed again and only the unit test would object - the end-to-end config check
// would never have referenced the type at all.
//
// This was verified rather than assumed: building the client with the
// registration removed makes the fixture fail with
// "endpoints[0]: unknown endpoint type: masque-client".

// clientFixtureDir returns the directory holding the macOS client fixtures.
func clientFixtureDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("macos-client")
	_, err := os.Stat(dir)
	require.NoError(t, err, "the macOS client fixture directory must exist")
	return dir
}

// TestClientFixtureTemplateExercisesMASQUEClient is the fixture half of the
// masque-client registration fix.
func TestClientFixtureTemplateExercisesMASQUEClient(t *testing.T) {
	t.Parallel()

	path := filepath.Join(clientFixtureDir(t), "jiejie-macos-client-fixture.json.tmpl")
	content, err := os.ReadFile(path)
	require.NoError(t, err, "read the client fixture template")
	text := string(content)

	require.Contains(t, text, `"type": "masque-client"`,
		"the client fixture must contain a masque-client endpoint, or the "+
			"registration fix is not covered by the end-to-end config check")

	// The endpoint must be WIRED INTO ROUTING, not merely parsed. A selector
	// member that does not resolve fails configuration loading, which is what makes
	// the fixture a real guard rather than a decorative entry.
	require.Contains(t, text, "masque-out",
		"the masque-client endpoint must be referenced by tag from the routing "+
			"configuration, or the fixture would not catch an unresolvable endpoint")

	// The port placeholder must exist, because check-macos-client-config.sh fails
	// on any unsubstituted placeholder and this test should name the cause.
	require.Contains(t, text, "__MASQUE_PORT__",
		"the masque-client endpoint must use the port placeholder so the config "+
			"checker substitutes it")
}

// TestClientFixtureTemplateDoesNotUseMASQUEServer asserts the fixture never
// enables the server role.
//
// A fixture that configured `masque-server` would fail the config check in the
// client profile - which is correct, but it would be failing for the wrong reason
// and would obscure the role-split assertion. Keeping the fixture client-only
// means the audit failure, if any, always points at the real invariant.
func TestClientFixtureTemplateDoesNotUseMASQUEServer(t *testing.T) {
	t.Parallel()

	path := filepath.Join(clientFixtureDir(t), "jiejie-macos-client-fixture.json.tmpl")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(content)

	require.NotContains(t, text, `"type": "masque-server"`,
		"the macOS client fixture must not configure the MASQUE server role")
}

// TestClientExampleConfigsCarryTheMASQUEEndpoint keeps the operator-facing example
// consistent with the fixture.
//
// The example is the file a user copies. If the fixture exercised masque-client
// but the example did not, the feature would be invisible to every user and the
// example would silently under-demonstrate the profile.
func TestClientExampleConfigsCarryTheMASQUEEndpoint(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"example-config.json"} {
		path := filepath.Join(clientFixtureDir(t), name)
		content, err := os.ReadFile(path)
		require.NoError(t, err, "read %s", name)
		text := string(content)

		require.Contains(t, text, `"masque-client"`,
			"%s must show the masque-client endpoint; it is the file users copy", name)
		require.Contains(t, text, "masque-out",
			"%s must wire the endpoint into the outbound groups", name)
	}
}

// TestClientFixtureDoesNotCarryServerOnlyTypes asserts the client fixture stays
// within the client profile.
//
// The client registry deliberately omits redirect, tproxy, tor, ssh and the large
// endpoint trees. A fixture that named one of them would fail `sing-box check`,
// but with a message about an unknown type rather than about the fixture being
// wrong, which is a worse failure to debug.
func TestClientFixtureDoesNotCarryServerOnlyTypes(t *testing.T) {
	t.Parallel()

	path := filepath.Join(clientFixtureDir(t), "jiejie-macos-client-fixture.json.tmpl")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(content)

	for _, forbidden := range []string{
		`"type": "redirect"`,
		`"type": "tproxy"`,
		`"type": "tor"`,
		`"type": "ssh"`,
		`"type": "openvpn"`,
		`"type": "openconnect"`,
		`"type": "tailscale"`,
		`"type": "wireguard"`,
	} {
		require.NotContains(t, text, forbidden,
			"the macOS client fixture must not use the server-only or trimmed type %s",
			strings.TrimSuffix(strings.TrimPrefix(forbidden, `"type": "`), `"`))
	}
}
