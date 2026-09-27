package deprecated

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// These tests pin Note.Impending's version arithmetic, and in particular the
// invariant that guards a MIS-AUTHORED deprecation note.
//
// # The bug they were written for
//
// Impending panics when a note's ScheduledVersion is already BEHIND the running
// version, because that means the note outlived its own removal and the code it
// deprecates should have been deleted. It decided "the running version is a real
// release" by checking badversion's PreReleaseIdentifier for emptiness.
//
// That is not the same question as "is this a SemVer prerelease". badversion splits
// a version into Major/Minor/Patch plus a prerelease field, and for a version whose
// prerelease is NOT of the form `-<name>.<digits>` it leaves that field EMPTY while
// keeping whatever it could parse. The fork's own version string is exactly such a
// case:
//
//	1.15.0-jiejie-masquerade.6
//
// badversion reports no PreReleaseIdentifier for it, so the guard read the fork's
// development build as a stable 1.15.0 release. Three notes are scheduled for
// removal in 1.14.0, so versionMinor was 14-15 = -1 and every one of them panicked:
//
//	outbound-dns-rule-item, missing-domain-resolver, legacy-domain-strategy-options
//
// MEASURED before the fix, with a binary stamped to the real fork version:
//
//	panic: invalid deprecated note: missing-domain-resolver
//
// reachable from ordinary configuration: any dial through an outbound addressed by
// a DOMAIN, with two or more DNS transports configured and no
// route.default_domain_resolver. It killed the root daemon instead of printing the
// warning the note exists to print.
//
// Upstream never sees this because it ships `1.15.0-beta.N`, whose prerelease
// badversion does parse. The crash needed the fork's version string.
//
// # What must not change
//
// The panic is NOT weakened or removed. For a version that SemVer agrees is a true
// stable release - "1.15.0" - a note scheduled for removal in an earlier minor still
// panics, exactly as upstream intends. Only the question "is this stable?" is
// answered correctly now.

const (
	// The fork's own development version: a plain `major.minor.patch` with a
	// non-`<name>.<digits>` suffix.
	forkVersion = "1.15.0-jiejie-masquerade.6"
)

// withVersion runs fn with C.Version set to version, restoring it afterwards.
//
// C.Version is a plain package variable that the linker stamps via -ldflags, so a
// test can set it directly. t.Cleanup restores it even if fn fails.
func withVersion(t *testing.T, version string, fn func()) {
	t.Helper()
	previous := C.Version
	C.Version = version
	t.Cleanup(func() { C.Version = previous })
	fn()
}

// pendingNote is a note whose scheduled removal is BEHIND the version under test,
// which is the condition the panic exists to catch.
func pendingNote(scheduled string) Note {
	return Note{
		Name:              "test-mis-authored-note",
		Description:       "a note that outlived its scheduled removal",
		DeprecatedVersion: "1.0.0",
		ScheduledVersion:  scheduled,
	}
}

// TestImpendingDoesNotPanicForTheForkVersion is the regression test for the crash
// that shipped: under the fork's real version string, evaluating any note whose
// scheduled removal has passed must return a verdict rather than killing the
// process.
//
// Before the fix this test panicked instead of failing, which is what the original
// defect looked like from the outside.
func TestImpendingDoesNotPanicForTheForkVersion(t *testing.T) {
	withVersion(t, forkVersion, func() {
		require.NotPanics(t, func() {
			// 1.14.0 is behind 1.15.x: this is the note shape that crashed.
			pendingNote("1.14.0").Impending()
		}, "the fork version %q is a development build, not a stable release; "+
			"a passed removal schedule must not panic", forkVersion)

		// The real notes that were armed in the shipped binary.
		for _, name := range []string{
			"outbound-dns-rule-item",
			"missing-domain-resolver",
			"legacy-domain-strategy-options",
		} {
			note := noteByName(t, name)
			require.Equal(t, "1.14.0", note.ScheduledVersion,
				"%s is expected to be scheduled behind the fork version; if this "+
					"changed, the reproduction this test guards has moved", name)
			require.NotPanics(t, func() { note.Impending() },
				"note %q panicked under the fork version", name)
		}
	})
}

// TestImpendingDoesNotPanicForPrereleaseVersions covers the two prerelease shapes
// the fork may legitimately use. Neither is a stable release, so neither may panic.
func TestImpendingDoesNotPanicForPrereleaseVersions(t *testing.T) {
	for _, version := range []string{
		"1.15.0-beta.1",  // the shape upstream ships: parsed by badversion
		"1.15.0-alpha.7", // same family, different identifier
	} {
		version := version
		t.Run(version, func(t *testing.T) {
			withVersion(t, version, func() {
				require.NotPanics(t, func() {
					pendingNote("1.14.0").Impending()
				}, "%q is a prerelease and must not trip the stable-release panic", version)
			})
		})
	}
}

// TestImpendingPanicsForATrueStableRelease is the other half of the contract: the
// guard must KEEP firing for a genuine stable release. If this test is ever deleted
// or relaxed, the mis-authored-note check has been silently disarmed.
func TestImpendingPanicsForATrueStableRelease(t *testing.T) {
	withVersion(t, "1.15.0", func() {
		require.PanicsWithValue(t, "invalid deprecated note: test-mis-authored-note", func() {
			pendingNote("1.14.0").Impending()
		}, "a truly stable release with a passed removal schedule must still panic")
	})
}

// TestImpendingDoesNotPanicForUnknownVersion pins the unstamped-build behaviour.
//
// `go test` and a plain `go build` leave C.Version as "unknown". semver.IsValid
// rejects it, so Impending returns false before any arithmetic. A developer running
// the test suite or an unstamped build must never crash on a deprecation note.
func TestImpendingDoesNotPanicForUnknownVersion(t *testing.T) {
	withVersion(t, "unknown", func() {
		require.NotPanics(t, func() {
			pendingNote("1.14.0").Impending()
		}, "an unstamped build must not panic")
		require.False(t, pendingNote("1.14.0").Impending(),
			"an unknown version can never be a passed removal schedule")
	})
}

// TestImpendingScheduleBoundary pins the <= 1 window that the return value encodes,
// so the fix cannot quietly change WHEN a warning is emitted. It is the behaviour
// the three panicking notes relied on to warn at all.
func TestImpendingScheduleBoundary(t *testing.T) {
	withVersion(t, forkVersion, func() {
		// current minor is 15.
		require.True(t, pendingNote("1.14.0").Impending(), "passed schedule warns")
		require.True(t, pendingNote("1.15.0").Impending(), "same minor warns")
		require.True(t, pendingNote("1.16.0").Impending(), "one minor ahead warns")
		require.False(t, pendingNote("1.17.0").Impending(), "two minors ahead is silent")
		require.False(t, Note{}.Impending(), "a note with no schedule never warns")
	})
}

// TestImpendingMatchesSemverOnStability states the invariant the fix implements, so
// a future rewrite of the guard is held to it rather than to badversion's field
// layout.
func TestImpendingMatchesSemverOnStability(t *testing.T) {
	cases := map[string]bool{
		"1.15.0-jiejie-masquerade.6": false, // fork development build
		"1.15.0-beta.1":              false,
		"1.15.0-alpha.7":             false,
		"1.15.0-rc.1":                false,
		"1.15.0":                     true, // the only stable shape here
	}
	for version, stable := range cases {
		require.Equal(t, stable, isStableRelease(version),
			"stability verdict for %q", version)
	}
}

// noteByName returns the registered note with the given name, so the test names the
// notes it protects without duplicating their definitions.
func noteByName(t *testing.T, name string) Note {
	t.Helper()
	for _, note := range Options {
		if note.Name == name {
			return note
		}
	}
	t.Fatalf("no registered deprecation note named %q; the regression test needs "+
		"updating if the note was removed or renamed", name)
	return Note{}
}
