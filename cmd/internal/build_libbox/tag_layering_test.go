package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
	"github.com/sagernet/sing-box/cmd/internal/mobilebuildtags"
)

// The layering contract, as opposed to the value contract in tag_golden_test.go.
//
// The golden test proves the refactor did not change any resolved tag set. These tests prove the
// REFACTOR ITSELF is in place and stays in place: that Android's shared concerns come from
// cmd/internal/mobilebuildtags rather than from an Apple-named package, that the Apple layer
// depends on the mobile layer and not the reverse, and that the mobile low-memory tag still
// cannot reach the common set. Without these, a later edit could re-point Android at
// applebuildtags, produce byte-identical tags, and every value test would stay green - which is
// exactly how the mislabelling survived this long.

// The import paths, quoted exactly as they appear in an import block, so a prose mention of a
// package name in a comment cannot satisfy - or trip - the dependency-direction checks.
const (
	appleBuildTagsImport  = `"github.com/sagernet/sing-box/cmd/internal/applebuildtags"`
	mobileBuildTagsImport = `"github.com/sagernet/sing-box/cmd/internal/mobilebuildtags"`
)

// TestAndroidResolvedTagsAreTheMobileSharedSet pins the Android composition: the shared set comes
// from mobilebuildtags, the mobile geometry layer is appended to it, and the only per-variant
// difference is the legacy variant's removal of with_naive_outbound. Android contributes no tag of
// its own, so there is no Android-only layer to assert - and deliberately no empty one to maintain.
//
// The geometry is the OTHER mobile layer, not an Android-only tag: it comes from
// mobilebuildtags.LowMemoryTags(), the same set Apple receives through gomobile's -tags-not-macos.
// Android adopted it as a deliberate, measured decision; see ResolveBuildTags for the numbers and
// TestSharedMobileSetNeverCarriesLowMemory for why it must stay out of the shared set itself.
func TestAndroidResolvedTagsAreTheMobileSharedSet(t *testing.T) {
	shared := mobilebuildtags.SharedTags()
	if len(shared) == 0 {
		t.Fatal("the mobile shared set is empty; the assertions below would be vacuous")
	}
	geometry := mobilebuildtags.LowMemoryTags()
	if len(geometry) == 0 {
		t.Fatal("the mobile geometry set is empty; the assertions below would be vacuous")
	}

	main := ResolveBuildTags("android-main")
	wantMain := append(append([]string{}, shared...), geometry...)
	if !slices.Equal(main, wantMain) {
		t.Fatalf("android-main = %v, want the mobile shared set plus the mobile geometry %v", main, wantMain)
	}
	for _, tag := range main {
		if !slices.Contains(shared, tag) && !slices.Contains(geometry, tag) {
			t.Fatalf("android-main ships %q, which no mobile layer defines; Android must not acquire "+
				"a tag from a layer it does not own", tag)
		}
	}

	legacy := ResolveBuildTags("android-legacy")
	wantLegacy := append(filterTags(shared, "with_naive_outbound"), geometry...)
	if !slices.Equal(legacy, wantLegacy) {
		t.Fatalf("android-legacy = %v, want the mobile shared set minus with_naive_outbound plus the "+
			"mobile geometry %v", legacy, wantLegacy)
	}
}

// TestAndroidShipsTheMobileGeometry states the decision positively, so that dropping it is a test
// failure with a reason rather than a silent reversion to a geometry no Android artifact would
// then share with its own tests.
//
// Android and iOS now ship the same buffer size, which is what makes the low-memory gate's coverage
// apply to Android at all: scripts/ci/test-low-memory.sh runs the data paths at 16 KiB, and if
// Android reverted to 32 KiB the gate would keep passing while testing a geometry Android no longer
// ships - the exact "coverage that reads as coverage" failure that script's header describes.
func TestAndroidShipsTheMobileGeometry(t *testing.T) {
	for _, variant := range []string{"android-main", "android-legacy"} {
		t.Run(variant, func(t *testing.T) {
			tags := ResolveBuildTags(variant)
			if len(tags) == 0 {
				t.Fatalf("%s resolves to no tags at all; the assertion below would be vacuous", variant)
			}
			if !slices.Contains(tags, mobilebuildtags.LowMemoryTag) {
				t.Fatalf("%s does not ship %q. Android adopted the 16 KiB mobile geometry as a "+
					"measured decision (see ResolveBuildTags); reverting it requires re-measuring "+
					"common/bufgeom and re-pointing scripts/ci/test-low-memory.sh at whatever "+
					"geometry Android actually ships",
					variant, mobilebuildtags.LowMemoryTag)
			}
		})
	}
}

// TestAppleVariantReadsTheAppleSourceOfTruth is the other half of the composition contract: the
// Apple variant is not the mobile shared set spelled out again, it is the Apple layer's answer. If
// Apple ever gains a Darwin-only tag, the provenance record and the artifact must both see it, and
// this test is what forces the builder to keep asking Apple rather than a copied list.
func TestAppleVariantReadsTheAppleSourceOfTruth(t *testing.T) {
	apple := ResolveBuildTags("apple")
	if !slices.Equal(apple, applebuildtags.CommonTags()) {
		t.Fatalf("the apple variant = %v, want the Apple layer's common set %v", apple, applebuildtags.CommonTags())
	}
	if len(apple) == 0 {
		t.Fatal("the apple variant resolves to no tags; this test would be vacuous")
	}
}

// TestSharedMobileSetNeverCarriesLowMemory restates the macOS invariant at the MOBILE layer, where
// the tag is now defined.
//
// The Apple layer has its own version of this test against the platform table. This one exists
// because the tag can now be mis-filed into a set the Apple tests never look at: putting it in
// mobilebuildtags.SharedTags() would reach Android (harmless there today, but unrequested) and
// reach macOS in a mixed gomobile build, where -tags-not-macos cannot remove it. A green Apple
// suite would not notice, because the Apple suite asks the Apple layer.
func TestSharedMobileSetNeverCarriesLowMemory(t *testing.T) {
	if slices.Contains(mobilebuildtags.SharedTags(), mobilebuildtags.LowMemoryTag) {
		t.Fatalf("the mobile SHARED set contains %q. gomobile applies -tags to every target, macOS "+
			"included, and -tags-not-macos cannot remove a tag -tags already enabled - so this "+
			"enables 16 KiB buffers on macOS in the real ios,macos build. The geometry belongs in "+
			"LowMemoryTags, which Apple passes through -tags-not-macos",
			mobilebuildtags.LowMemoryTag)
	}
	if !slices.Contains(mobilebuildtags.LowMemoryTags(), mobilebuildtags.LowMemoryTag) {
		t.Fatalf("the mobile geometry set does not contain %q; iOS would silently revert to 32 KiB "+
			"buffers and the low-memory gate would test a configuration nothing ships",
			mobilebuildtags.LowMemoryTag)
	}
	if slices.Contains(ResolveBuildTags("apple"), mobilebuildtags.LowMemoryTag) {
		t.Fatalf("the apple variant's resolved tags contain %q; the macOS artifact would ship "+
			"mobile geometry", mobilebuildtags.LowMemoryTag)
	}
}

// TestSharedTagCompositionIsNotOwnedByTheApplePackage is the dependency-direction check.
//
// It is static, like the gVisor import scan in tag_policy_test.go, and for the same reason: the
// property is "which file decides", and no behavioural test can observe that. A future change that
// re-points Android's shared set at applebuildtags would produce identical tags and pass every
// value test here - the defect would be invisible until the two platforms needed to diverge, which
// is the moment this refactor exists to make safe.
func TestSharedTagCompositionIsNotOwnedByTheApplePackage(t *testing.T) {
	root := repoRoot(t)

	mainSource := readGoSource(t, filepath.Join(root, "cmd", "internal", "build_libbox", "main.go"))
	if strings.Contains(mainSource, appleBuildTagsImport) {
		t.Fatalf("cmd/internal/build_libbox/main.go imports cmd/internal/applebuildtags again. This " +
			"file composes the ANDROID and the shared set, so an Apple import here makes an " +
			"Apple-named package the source of truth for Android - the exact layering violation the " +
			"mobilebuildtags package removed. Apple-only composition belongs in tags.go")
	}
	if !strings.Contains(mainSource, mobileBuildTagsImport) {
		t.Fatalf("cmd/internal/build_libbox/main.go no longer imports %s; the shared and Android tag "+
			"sets must be composed from the mobile source of truth", mobileBuildTagsImport)
	}

	mobileSource := readGoSource(t, filepath.Join(root, "cmd", "internal", "mobilebuildtags", "tags.go"))
	if strings.Contains(mobileSource, appleBuildTagsImport) {
		t.Fatalf("cmd/internal/mobilebuildtags imports cmd/internal/applebuildtags. The dependency " +
			"must run the other way: the shared mobile layer cannot know about the Apple layer, or " +
			"Apple-only concerns become mobile defaults")
	}

	appleSource := readGoSource(t, filepath.Join(root, "cmd", "internal", "applebuildtags", "tags.go"))
	if !strings.Contains(appleSource, mobileBuildTagsImport) {
		t.Fatalf("cmd/internal/applebuildtags no longer imports %s. The Apple layer must build its "+
			"common set from the mobile shared set rather than declaring a second copy of it",
			mobileBuildTagsImport)
	}
}

// TestFrozenTagSetsCoverEveryShippedVariant keeps the golden map honest: a variant added to
// sortedTagVariants - and therefore to libbox.provenance - without a frozen pre-refactor value
// would otherwise be silently unproven.
func TestFrozenTagSetsCoverEveryShippedVariant(t *testing.T) {
	if len(sortedTagVariants()) == 0 {
		t.Fatal("no shipped variants are declared; this test would be vacuous")
	}
	for _, variant := range sortedTagVariants() {
		if _, known := frozenResolvedTags[variant]; !known {
			t.Fatalf("shipped variant %q has no frozen tag set; capture its pre-refactor value before "+
				"adding it, or the no-functional-change claim does not cover it", variant)
		}
	}
}

// readGoSource reads a Go file for a source-level layering check. Failure is fatal: a check that
// silently skipped a missing file would pass in exactly the case where the file moved.
func readGoSource(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
