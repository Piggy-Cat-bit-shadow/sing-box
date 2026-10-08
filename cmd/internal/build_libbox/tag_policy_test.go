package main

import (
	"os"
	"path/filepath"
	"regexp"
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
	if shipped := gvisorShippedVariants(); len(shipped) > 0 {
		t.Fatalf("these shipped variants compile with_gvisor again: %v\n%s",
			shipped, gvisorReenableInstruction)
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

// TestGVisorIsRetiredFromTheModuleGraph is the dependency half of the inverted invariant, and since
// the Go TUN stack landed it is a HARD FAILURE rather than a report.
//
// # Why it used to report instead of failing, and why that is over
//
// While the migration was in flight this branch logged PENDING: the shipped exposure was already
// zero (asserted above), but the dependency edge could not be removed yet because the code path
// that needed gVisor had not been replaced, so failing would have made CI red for a tree that was
// correct and mid-migration - which trains people to ignore the check. That condition is gone. The
// Go TUN stack is in, nothing in this module imports gVisor, and the retired fork's replace
// directive is gone from go.mod. The edge is now removable, so it must be removed, and this test
// says so instead of keeping a note.
//
// # What "retired" means precisely
//
// `github.com/sagernet/gvisor` may still appear in go.mod as an `// indirect` requirement, because
// sing-tun itself contains with_gvisor-tagged packages and the module graph therefore still names
// the module. That is acceptable and is upstream's own end state. What is NOT acceptable, and what
// this test fails on, is the dependency becoming ACTIVE again in this module:
//
//   - a replace directive pinning gVisor to the retired fork (or to anything else);
//   - gVisor listed in the direct require block, which is only possible if something here imports
//     it;
//   - any .go file in this module importing github.com/sagernet/gvisor.
func TestGVisorIsRetiredFromTheModuleGraph(t *testing.T) {
	root := repoRoot(t)
	modData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	modContent := string(modData)

	const forkReplace = "replace github.com/sagernet/gvisor"
	if strings.Contains(modContent, forkReplace) {
		t.Fatalf("go.mod still replaces gVisor (%s...). The fork is RETIRED: gVisor no longer ships, "+
			"so the nil-handshake guard it carried has nothing to protect.\n%s",
			forkReplace, gvisorReenableInstruction)
	}

	// A direct require is the module graph's way of saying "a package in this module imports it".
	// Only the block before the first `require (` ... `)` indirection marker matters, so the check
	// walks the file rather than pattern-matching a substring anywhere.
	for _, line := range strings.Split(modContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, gvisorModule) {
			continue
		}
		if strings.Contains(trimmed, "// indirect") {
			// sing-tun's with_gvisor-tagged packages keep this in the graph. Fine.
			continue
		}
		t.Fatalf("go.mod lists %s as an ACTIVE requirement (%q). It must be `// indirect` or absent; "+
			"an active requirement means something in this module imports gVisor again.\n%s",
			gvisorModule, trimmed, gvisorReenableInstruction)
	}

	// The import scan is the assertion the go.mod shape is a proxy for, and it is the one that
	// cannot be fooled by a hand-edited go.mod. Nested modules (clients/apple, test/) have their own
	// graphs and are deliberately not part of this one.
	//
	// It matches IMPORT LINES, not the bare module path, because this file and the CI check both
	// name the module in strings; a substring scan would flag the tripwire itself and be useless.
	var importers []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if path == root {
				return nil
			}
			if name == "clients" || name == "build" || name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !gvisorImportLine.Match(content) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		importers = append(importers, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(importers) > 0 {
		slices.Sort(importers)
		t.Fatalf("these files import %s again: %v\n%s",
			gvisorModule, importers, gvisorReenableInstruction)
	}
}

const gvisorModule = "github.com/sagernet/gvisor"

// gvisorImportLine matches a Go import spec for the module: optional alias, then the quoted path on
// its own line. `const x = "github.com/sagernet/gvisor"` is not an import and must not match.
var gvisorImportLine = regexp.MustCompile(`(?m)^\s*(?:[._[:alnum:]]+\s+)?"github\.com/sagernet/gvisor(?:/[^"]*)?"\s*$`)

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
