package mobilebuildtags

import (
	"slices"
	"strings"
	"testing"
)

// These tests guard the mobile source of truth itself, so a mistake shows up here rather than only
// as a surprising artifact in a downstream builder.

// TestSharedTagsHaveNoDuplicates keeps the shared set a set.
//
// Duplicates are not harmless in this system: the tags are joined into a -tags flag and into the
// libbox.provenance record, and the provenance file is diffed by consumers. A duplicated tag
// changes those bytes while looking like a no-op in the source, and it is the kind of edit a merge
// makes silently.
func TestSharedTagsHaveNoDuplicates(t *testing.T) {
	shared := SharedTags()
	if len(shared) == 0 {
		t.Fatal("the shared set is empty; the callers would emit a -tags flag with no content")
	}
	seen := make(map[string]bool, len(shared))
	for _, tag := range shared {
		if seen[tag] {
			t.Fatalf("the shared set contains %q twice", tag)
		}
		seen[tag] = true
	}
}

// TestLowMemoryIsSeparateFromTheSharedSet is the mobile-layer statement of the invariant the Apple
// layer also asserts: the geometry tag is in the mobile package, but never in the set that is
// applied to every gomobile target.
func TestLowMemoryIsSeparateFromTheSharedSet(t *testing.T) {
	if slices.Contains(SharedTags(), LowMemoryTag) {
		t.Fatalf("SharedTags() contains %q. gomobile's -tags applies to every target including "+
			"macOS, and -tags-not-macos cannot remove a tag -tags already enabled", LowMemoryTag)
	}
	if !slices.Contains(LowMemoryTags(), LowMemoryTag) {
		t.Fatalf("LowMemoryTags() does not contain %q; iOS would lose the geometry the low-memory "+
			"gate exists to test", LowMemoryTag)
	}
	if LowMemoryTag != "with_low_memory" {
		t.Fatalf("LowMemoryTag = %q, want %q; the sing fork selects its 16 KiB buffer geometry on "+
			"exactly this build constraint", LowMemoryTag, "with_low_memory")
	}
	if got := LowMemoryTagString(); !strings.Contains(got, LowMemoryTag) {
		t.Fatalf("LowMemoryTagString() = %q, must contain %q", got, LowMemoryTag)
	}
}

// TestAccessorsReturnCopies pins the copy semantics the callers rely on.
//
// The builder layers per-variant tags on top of these sets. If the accessors returned the backing
// slice, the first variant to append would rewrite the shared definition for every later caller in
// the process - and in the builder that is the second Android variant, which would compile with
// the first one's tags while every test that resolves tags in isolation stayed green.
func TestAccessorsReturnCopies(t *testing.T) {
	for _, accessor := range []struct {
		name string
		get  func() []string
	}{
		{"SharedTags", SharedTags},
		{"LowMemoryTags", LowMemoryTags},
	} {
		t.Run(accessor.name, func(t *testing.T) {
			first := accessor.get()
			if len(first) == 0 {
				t.Fatal("accessor returned an empty set; the mutation check would be vacuous")
			}
			first[0] = "mutated_in_place"
			second := accessor.get()
			if second[0] == "mutated_in_place" {
				t.Fatalf("%s returns the backing slice; a caller appending to it would mutate the "+
					"source of truth for every later caller", accessor.name)
			}
		})
	}
}
