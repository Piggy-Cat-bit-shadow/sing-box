package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// GVISOR MUST NOT BE SHIPPED.
//
// # Why this is an inverted invariant rather than a deleted test
//
// Phase 1 found that shipping with_gvisor meant shipping gVisor's TCP stack, and the pinned
// upstream gVisor dereferences a nil handshake in handleConnecting (LX 048) - an unrecoverable
// crash inside gVisor's own goroutine. That finding was correct, and the patched fork was the
// correct response to it while gVisor shipped.
//
// The product condition has since changed: the Android UI no longer depends on
// "stack": "mixed"/"gvisor", so gVisor is retired from shipped artifacts and the fork is no longer
// load-bearing. The risk is gone because the exposure is gone, NOT because 048 was never real.
//
// Deleting this test would delete the only thing that notices the exposure coming back. It is
// therefore INVERTED: no shipped variant may name with_gvisor, and re-adding it to the Android
// builder fails CI with an instruction to re-run the product review and restore/re-audit 048.
//
// # Why it asks the builder instead of scanning files
//
// The phase-1 tripwire read the profile tag files and concluded "no profile names with_gvisor",
// while the Android libbox artifacts were compiled WITH with_gvisor: the libbox builder composes
// its own tag sets. A scan of text files is not a check on what ships. This test asks the same
// function the builders use, which is the property that made it catch the real thing.

const gvisorTag = "with_gvisor"

// gvisorReenableInstruction is the message every failure here shares, so a future maintainer who
// trips it is told what to do rather than merely told they broke a test.
const gvisorReenableInstruction = "gVisor was intentionally retired after the Android UI stopped " +
	"depending on mixed/gvisor. Re-enabling it requires a new product review and restoring and " +
	"re-auditing LX 048 (the nil-handshake crash in handleConnecting), including the patched " +
	"dependency fork and the artifact tripwire. See docs/fork/upstream-sync-2026-10.md."

// gvisorShippedVariants reports which shipped variants compile the gVisor netstack.
func gvisorShippedVariants() []string {
	var variants []string
	for _, variant := range sortedTagVariants() {
		if HasBuildTag(variant, gvisorTag) {
			variants = append(variants, variant)
		}
	}
	return variants
}

// TestNoShippedVariantShipsGVisor is the inverted invariant: the default state is gVisor-free, and
// any variant that names the tag fails CI.
func TestNoShippedVariantShipsGVisor(t *testing.T) {
	for _, variant := range sortedTagVariants() {
		if HasBuildTag(variant, gvisorTag) {
			t.Fatalf("%s compiles with_gvisor.\n%s", variant, gvisorReenableInstruction)
		}
	}
	// And the platforms the product decision named, explicitly, so the failure text says which one
	// regressed rather than only that something did.
	for _, variant := range []string{"android-main", "android-legacy", "apple"} {
		if HasBuildTag(variant, gvisorTag) {
			t.Fatalf("%s ships with_gvisor; the Android UI no longer requires mixed/gvisor and no "+
				"Apple product ever did.\n%s", variant, gvisorReenableInstruction)
		}
	}
}

// TestAndroidShipsWithoutGVisor states the product outcome positively: Android is a shipped
// variant, it resolves tags, and gVisor is not among them. This is what proves the default Android
// path does not need gVisor to start a tun.
func TestAndroidShipsWithoutGVisor(t *testing.T) {
	for _, variant := range []string{"android-main", "android-legacy"} {
		tags := ResolveBuildTags(variant)
		if len(tags) == 0 {
			t.Fatalf("%s resolves to no tags at all; the assertion below would be vacuous", variant)
		}
		if slices.Contains(tags, gvisorTag) {
			t.Fatalf("%s still ships with_gvisor.\n%s", variant, gvisorReenableInstruction)
		}
	}
}

// TestProfileTagFilesDoNotCarryGVisor keeps the two sources of tags from drifting: the profile
// files must not gain the tag behind the builder's back, because then a check like the old
// tripwire would pass while a different build path shipped gVisor.
func TestProfileTagFilesDoNotCarryGVisor(t *testing.T) {
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "release", "DEFAULT_BUILD_TAGS*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no release/DEFAULT_BUILD_TAGS* files found; this test would pass vacuously")
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), gvisorTag) {
			t.Fatalf("%s names %s; the gVisor tag is injected by the Android libbox build path only. "+
				"If a profile is meant to carry it, the 048 audit and this test must be updated together",
				filepath.Base(path), gvisorTag)
		}
	}
}

// TestGVisorForkIsNotLoadBearing is the dependency half of the inverted invariant.
//
// # Why this reports the dependency edge instead of failing on it
//
// The SHIPPED exposure is what made 048 a crash surface, and that is asserted above: no variant
// compiles with_gvisor. The remaining dependency edge cannot be removed yet for a concrete reason -
// protocol/tun still imports gVisor behind the with_gvisor build tag, so the module graph keeps
// requiring it until the upstream Go TUN stack (a1b01b4) replaces that code path. That is
// upstream's own ordering: ede8d9a "Remove dependency on gVisor" FOLLOWS the Go stack.
//
// Failing here would make CI red for a correct mid-migration state, which trains people to ignore
// the check. Passing silently would lose the fact. So the tag re-enable tripwire is the assertion
// (it fails), and the dependency edge is recorded against a named migration.
func TestGVisorForkIsNotLoadBearing(t *testing.T) {
	// The tripwire: the moment a shipped variant compiles the tag again, this fails and names the
	// reason. That is the property that matters and the one a reader must not lose.
	if shipped := gvisorShippedVariants(); len(shipped) > 0 {
		t.Fatalf("a shipped variant compiles with_gvisor again (%v), so the retired fork is "+
			"load-bearing once more.\n%s", shipped, gvisorReenableInstruction)
	}
	// The pending half, recorded so the migration cannot be forgotten: while the fork replacement
	// is still present, the Go TUN stack migration is what removes it.
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	const forkReplace = "replace github.com/sagernet/gvisor => github.com/Piggy-Cat-bit-shadow/gvisor"
	if strings.Contains(string(data), forkReplace) {
		t.Log("PENDING: go.mod still replaces gVisor with the retired fork. The shipped exposure is " +
			"already zero (asserted above); the dependency edge is removed by the Go TUN stack " +
			"migration (upstream a1b01b4, then ede8d9a), because protocol/tun still imports gVisor " +
			"behind the build tag. When that lands this branch must become a failure.")
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the module root above the test directory")
		}
		dir = parent
	}
}

// XHTTP must be in the shipped compositions, not merely available behind a tag.
//
// # The Phase-1 lesson, applied again
//
// The gVisor invariant exists because a profile looked correct while the Android builder injected a
// tag that no profile file named. The same class of mistake in the other direction is worse for a
// transport: the code compiles, the tests pass, and the feature simply is not in the artifact the
// user installed. These tests assert against ResolveBuildTags - the composition the builders
// actually use and the provenance record is written from - not against the profile text.
func TestShippedVariantsCarryXHTTP(t *testing.T) {
	for _, variant := range []string{"android-main", "android-legacy", "apple"} {
		t.Run(variant, func(t *testing.T) {
			if !HasBuildTag(variant, "with_xhttp") {
				t.Fatalf("variant %s must ship the XHTTP transport", variant)
			}
			if !HasBuildTag(variant, "with_quic") {
				t.Fatalf("variant %s needs with_quic for the XHTTP HTTP/3 path", variant)
			}
		})
	}
}

// The profile tag files must name with_xhttp too. Two sources of truth that disagree is exactly how
// the gVisor invariant was silently broken, so they are asserted to agree rather than assumed to.
func TestProfileTagFilesCarryXHTTP(t *testing.T) {
	root := repoRoot(t)
	for _, name := range []string{"DEFAULT_BUILD_TAGS", "DEFAULT_BUILD_TAGS_OTHERS", "DEFAULT_BUILD_TAGS_WINDOWS"} {
		content, err := os.ReadFile(filepath.Join(root, "release", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "with_xhttp") {
			t.Fatalf("release/%s must name with_xhttp, or the profile and the builder disagree", name)
		}
	}
}
