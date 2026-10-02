package applebuildtags

import (
	"strings"
	"testing"
)

// The four target combinations that must be covered, including the mixed case the previous
// tests never exercised.
var targetCombinations = []string{
	"ios",
	"macos",
	"ios,macos",
	"ios,iossimulator,tvos,tvossimulator,macos",
}

// TestMixedTargetNeverEnablesLowMemoryOnMacOS is the regression for the leak.
//
// # The bug this catches
//
// gomobile's -tags applies to EVERY target, while -tags-not-macos only ADDS the named tags for
// the non-macOS targets. It cannot remove a tag the common set already enabled.
//
// The previous code derived one flag from the target list - "is any target mobile?" - and put
// with_low_memory in the common -tags when the answer was yes. For `ios,macos` that enabled
// low-memory geometry on macOS, and the accompanying -tags-not-macos was powerless to undo it.
// The Apple CI builds exactly `ios,macos`, so this reached the real macOS artifact.
//
// The earlier tests checked the mobile set and the desktop set SEPARATELY - lowMemory=true and
// lowMemory=false - and both were correct in isolation. Neither asked what happens when one
// build contains both, which is why the bug survived a green contract test.
func TestMixedTargetNeverEnablesLowMemoryOnMacOS(t *testing.T) {
	common := TargetTags("ios,macos")
	for _, tag := range common {
		if tag == LowMemoryTag {
			t.Fatalf("the COMMON tag set for a mixed target contains %q; "+
				"gomobile applies -tags to every target, so this enables low-memory "+
				"geometry on macOS where -tags-not-macos cannot remove it", LowMemoryTag)
		}
	}
}

// TestCommonTagsNeverContainLowMemory is the structural invariant behind the leak.
//
// It is asserted over every combination rather than the mixed one alone, because the rule is
// about the common set as a concept: a mobile-only tag must never be able to reach a target
// that does not want it.
func TestCommonTagsNeverContainLowMemory(t *testing.T) {
	for _, target := range targetCombinations {
		t.Run(target, func(t *testing.T) {
			for _, tag := range TargetTags(target) {
				if tag == LowMemoryTag {
					t.Fatalf("common tags for %q contain %q", target, LowMemoryTag)
				}
			}
		})
	}

	// And the common set with no target at all.
	for _, tag := range CommonTags() {
		if tag == LowMemoryTag {
			t.Fatalf("CommonTags() contains %q", LowMemoryTag)
		}
	}
}

// TestFinalSemanticsPerPlatform is the end-to-end statement of intent, over all four
// combinations: iOS and tvOS ship low-memory geometry, macOS never does.
func TestFinalSemanticsPerPlatform(t *testing.T) {
	for _, target := range targetCombinations {
		t.Run(target, func(t *testing.T) {
			shipsLowMemory := make(map[string]bool, len(applePlatforms))
			for _, platform := range applePlatforms {
				shipsLowMemory[platform.Name] = true
			}

			for _, platform := range applePlatforms {
				if !targetIncludes(target, platform.Name) {
					continue
				}
				got := containsTag(FullDeploymentTags(platform.Name), LowMemoryTag)
				if platform.LowMemory && !got {
					t.Fatalf("%s must ship %q in build %q", platform.Name, LowMemoryTag, target)
				}
				if !platform.LowMemory && got {
					t.Fatalf("%s must NOT ship %q in build %q", platform.Name, LowMemoryTag, target)
				}
			}
			_ = shipsLowMemory
		})
	}
}

// TestTargetShipsLowMemoryOnlyWhenEveryPlatformDoes pins the "every, not any" rule.
//
// This is the single decision the leak got wrong. With a mixed list the honest answer is "some
// do, some do not", and the only way to express that to gomobile is the common set without the
// tag plus the per-platform set.
func TestTargetShipsLowMemoryOnlyWhenEveryPlatformDoes(t *testing.T) {
	cases := map[string]bool{
		"ios":           true,
		"iossimulator":  true,
		"tvos":          true,
		"tvossimulator": true,
		"macos":         false,
		"ios,macos":     false, // MIXED: the regression
		"ios,iossimulator,tvos,tvossimulator,macos": false, // MIXED
		"ios,iossimulator,tvos,tvossimulator":       true,
		"macos,ios":                                 false, // order must not matter
		"":                                          false,
		"unknownplatform":                           false,
	}
	for target, expected := range cases {
		t.Run(target, func(t *testing.T) {
			if got := TargetShipsLowMemory(target); got != expected {
				t.Fatalf("TargetShipsLowMemory(%q) = %v, want %v", target, got, expected)
			}
		})
	}
}

// TestUnknownPlatformDoesNotAcquireLowMemory guards the fail-closed direction.
//
// A platform this package has not been told about must not silently receive mobile geometry.
// Guessing "mobile" for anything unrecognised is how a new Apple target would ship a buffer
// size nobody chose.
func TestUnknownPlatformDoesNotAcquireLowMemory(t *testing.T) {
	for _, target := range []string{"watchos", "visionos", "xros", "ios-simulator", "IOS"} {
		if PlatformShipsLowMemory(target) {
			t.Fatalf("unknown target %q must not be treated as low-memory", target)
		}
	}
}

// TestPerPlatformTagsCarryTheLowMemoryTag confirms the tag does travel - just through the
// channel that can express per-platform intent.
func TestPerPlatformTagsCarryTheLowMemoryTag(t *testing.T) {
	if !containsTag(LowMemoryMobileTags(), LowMemoryTag) {
		t.Fatalf("the per-platform set must carry %q, or iOS would lose its geometry", LowMemoryTag)
	}
	if tagString := LowMemoryTagString(); !strings.Contains(tagString, LowMemoryTag) {
		t.Fatalf("LowMemoryTagString() = %q, must contain %q", tagString, LowMemoryTag)
	}
}

// TestCommonTagsAreStableAcrossTargets records that the common set does not vary by target.
//
// It must not: if it varied, a tag could appear for one target and not another with no
// per-platform flag able to correct it - which is the leak in a different costume.
func TestCommonTagsAreStableAcrossTargets(t *testing.T) {
	reference := TargetTagString("macos")
	for _, target := range targetCombinations {
		if got := TargetTagString(target); got != reference {
			t.Fatalf("common tags for %q = %q, want the same as macOS %q", target, got, reference)
		}
	}
}

// TestEveryPlatformHasADeclaredGeometry ensures the platform table has no silent gaps: a
// platform present in gomobile but missing here would report "no low memory" by default, which
// is fail-closed but should still be a deliberate omission.
func TestEveryPlatformHasADeclaredGeometry(t *testing.T) {
	// The gomobile Apple targets this project builds for.
	expected := []string{"ios", "iossimulator", "tvos", "tvossimulator", "macos"}
	for _, name := range expected {
		var found bool
		for _, platform := range applePlatforms {
			if platform.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("platform %q has no declared geometry", name)
		}
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func targetIncludes(bindTarget string, platform string) bool {
	for _, target := range splitTargets(bindTarget) {
		if target == platform {
			return true
		}
	}
	return false
}
