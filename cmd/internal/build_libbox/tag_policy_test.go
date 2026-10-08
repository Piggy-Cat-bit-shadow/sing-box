package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The gVisor invariant, checked against the REAL build-tag composition.
//
// # Why this test exists instead of a file scan
//
// The phase-1 tripwire read the profile tag files and concluded "no profile names with_gvisor",
// while the Android libbox artifacts were compiled WITH with_gvisor: the libbox builder appends
// its own tags, and Android gains the gVisor tag there. A scan of text files is not a check on
// what ships. This test asks the same function the builders use.
//
// # The invariant
//
// Shipping with_gvisor means shipping gVisor's TCP stack, and the pinned upstream gVisor
// dereferences a nil handshake in handleConnecting (LX 048) - an unrecoverable crash inside
// gVisor's own goroutine. So:
//
//	if a variant compiles with_gvisor, the gVisor dependency must be our patched fork;
//	if no variant compiles it, the patch must not be silently assumed necessary.
//
// If upstream fixes 048, the module assertion below is the tripwire that says "re-audit and
// retire the fork".

const gvisorTag = "with_gvisor"

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

// TestAndroidShipsGVisorAndAppleDoesNot pins the intentional difference recorded by the commit
// that enabled gVisor for Android, so a change in either direction is noticed rather than inferred.
func TestAndroidShipsGVisorAndAppleDoesNot(t *testing.T) {
	android := gvisorShippedVariants()
	if !slices.Contains(android, "android-main") {
		t.Fatal("android-main no longer compiles with_gvisor; the Android client asks for " +
			"stack mixed/gvisor and would fail to start a tun, and the 048 exposure changes")
	}
	if !slices.Contains(android, "android-legacy") {
		t.Fatal("android-legacy no longer compiles with_gvisor")
	}
	if HasBuildTag("apple", gvisorTag) {
		t.Fatal("the apple variant now compiles with_gvisor; the Apple products deliberately keep " +
			"their existing stack choices and adding gVisor there needs the 048 audit repeated")
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

// TestGVisorPinIsThePatchedFork is the dependency half of the invariant: with gVisor shipped, the
// linked module must be our fork, and the fork must still carry the guard.
//
// It reads go.mod the way the module system does, rather than trusting a comment.
func TestGVisorPinIsThePatchedFork(t *testing.T) {
	if len(gvisorShippedVariants()) == 0 {
		t.Skip("no shipped variant compiles with_gvisor; the pin is not load-bearing here")
	}
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	goMod := string(data)
	const wantReplace = "replace github.com/sagernet/gvisor => github.com/Piggy-Cat-bit-shadow/gvisor"
	if !strings.Contains(goMod, wantReplace) {
		t.Fatalf("with_gvisor is shipped but go.mod does not replace the gVisor module with the "+
			"patched fork.\nwant a line starting: %s\n"+
			"Without it, the nil-handshake crash (LX 048) is back in the Android artifacts.", wantReplace)
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
