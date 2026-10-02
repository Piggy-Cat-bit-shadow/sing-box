package main

import (
	"testing"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
)

// The contract these tests used to enforce - that this command's tag lists equal the builder's -
// is now enforced by the compiler, because both import cmd/internal/applebuildtags.
//
// The old test parsed the builder's SOURCE TEXT and compared string slices. That catches a tag
// added to one copy and not the other. It cannot catch a question asked wrongly in both copies,
// which is how the mixed-target macOS leak survived with both lists byte-identical and this
// test green.
//
// What remains worth testing is the semantics a caller depends on.

// TestCanonicalTagsMatchTheSharedDefinition checks the command reports what the package defines.
func TestCanonicalTagsMatchTheSharedDefinition(t *testing.T) {
	for _, platform := range applebuildtags.ApplePlatforms() {
		got := canonicalAppleTags(platform.Name)
		want := applebuildtags.FullDeploymentTags(platform.Name)
		if len(got) != len(want) {
			t.Fatalf("%s: got %d tags, want %d", platform.Name, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: tag %d = %q, want %q", platform.Name, i, got[i], want[i])
			}
		}
	}
}

// TestMobilePlatformsCarryLowMemoryAndMacOSDoesNot is the semantic contract, stated per
// platform rather than per tag-list.
func TestMobilePlatformsCarryLowMemoryAndMacOSDoesNot(t *testing.T) {
	for _, platform := range applebuildtags.ApplePlatforms() {
		tags := canonicalAppleTags(platform.Name)
		hasLowMemory := false
		for _, tag := range tags {
			if tag == applebuildtags.LowMemoryTag {
				hasLowMemory = true
			}
		}
		if platform.LowMemory && !hasLowMemory {
			t.Fatalf("%s must carry %q", platform.Name, applebuildtags.LowMemoryTag)
		}
		if !platform.LowMemory && hasLowMemory {
			t.Fatalf("%s must not carry %q", platform.Name, applebuildtags.LowMemoryTag)
		}
	}
}

// TestCommonSetNeverCarriesLowMemory is the invariant that makes the mixed-target leak
// impossible: the set gomobile receives via -tags is shared by every target, so a mobile-only
// tag in it would reach macOS where -tags-not-macos cannot remove it.
func TestCommonSetNeverCarriesLowMemory(t *testing.T) {
	for _, tag := range applebuildtags.CommonTags() {
		if tag == applebuildtags.LowMemoryTag {
			t.Fatalf("the common set contains %q; it would be enabled on macOS too", applebuildtags.LowMemoryTag)
		}
	}
	if commonAppleTagString() == "" {
		t.Fatal("the common tag string must not be empty")
	}
}

// TestMobileOnlySetCarriesTheTag confirms the per-platform channel still does its job.
func TestMobileOnlySetCarriesTheTag(t *testing.T) {
	hasLowMemory := false
	for _, tag := range applebuildtags.LowMemoryMobileTags() {
		if tag == applebuildtags.LowMemoryTag {
			hasLowMemory = true
		}
	}
	if !hasLowMemory {
		t.Fatalf("the mobile-only set must carry %q or iOS would lose its geometry", applebuildtags.LowMemoryTag)
	}
	if lowMemoryAppleTagString() == "" {
		t.Fatal("the mobile-only tag string must not be empty")
	}
}
