package main

import (
	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
)

// Canonical Apple build tag sets.
//
// # Why this file exists
//
// The tags the Apple client is built with were assembled inline in this command, while
// the low-memory CI gate and the memory benchmark each kept their own list. Three lists
// that are supposed to agree will eventually disagree, and the failure is silent: the
// tests keep passing against a tag set no shipped binary uses, which is worse than having
// no coverage because it reads as coverage.
//
// This is now the single definition. The builder, the low-memory gate and the benchmark
// matrix all read it, and a mismatch is a build failure rather than a surprise on a device.
//
// # What the sets mean
//
//	mobile shared set   every mobile platform, Android and Apple alike; owned by
//	                    cmd/internal/mobilebuildtags
//	Apple common set    the -tags set gomobile receives for EVERY Apple target: the mobile shared
//	                    set plus any genuinely Darwin-only tags (none today)
//	Apple mobile-only   with_low_memory, passed via -tags-not-macos so ONLY iOS/tvOS get it
//
// The distinction that matters most is the last one. with_low_memory halves buf.BufferSize
// from 32 KiB to 16 KiB, which moves the in-place framing boundary in the Shadowsocks
// writer - the boundary a production crash came out of. iOS and tvOS are built with it;
// macOS is NOT, and adding it there would make macOS tests exercise a geometry macOS does
// not ship.
//
// # Where the tags come from
//
// The feature tags every mobile platform ships, and the with_low_memory geometry tag, live in
// cmd/internal/mobilebuildtags; Android composes its set from that package and never reads an
// Apple one. This file is the Apple-facing layer: it re-exports the Apple view from
// cmd/internal/applebuildtags, which owns the gomobile target table, the per-target composition
// rule and any Apple-only tags. Keeping the Apple import here rather than in main.go is what lets
// a layering test assert that the Android composition path cannot reach the Apple package.
//
// The Apple tag lists are imported from cmd/internal/applebuildtags, not repeated.
//
// They used to be defined here AND in cmd/internal/appletags, kept in agreement by a test that
// parsed this file's source. That caught a tag added to one copy but not the other; it could
// not catch a question asked wrongly in both. The mixed-target macOS leak was exactly that -
// both lists identical, contract test green, defect in how the shared set was derived.
//
// See applebuildtags.CommonTags for why a mobile-only tag must never enter the common set.

// appleCommonTags is the Apple variant's -tags set: the COMMON set every Apple target receives.
//
// It is the Apple composition, not the mobile shared set spelled out again, so an Apple-only tag
// added in cmd/internal/applebuildtags reaches the Apple variant's built artifact and provenance
// record without a second edit here.
func appleCommonTags() []string {
	return applebuildtags.CommonTags()
}

// AppleDeploymentTags is the full tag set a single Apple platform ships.
//
// It describes the SEMANTIC result for that platform. What gomobile is handed is different:
// the common set via -tags, plus the mobile-only set via -tags-not-macos. See CommonTagString
// and LowMemoryTagString.
func AppleDeploymentTags(platform string) []string {
	return applebuildtags.FullDeploymentTags(platform)
}

// AppleDeploymentTagString is AppleDeploymentTags joined for -tags.
func AppleDeploymentTagString(platform string) string {
	return applebuildtags.FullDeploymentTagString(platform)
}

// CommonTagString is the tag set gomobile receives via -tags for ANY Apple target.
func CommonTagString() string {
	return applebuildtags.CommonTagString()
}

// LowMemoryTagString is the mobile-only tag set gomobile receives via -tags-not-macos.
func LowMemoryTagString() string {
	return applebuildtags.LowMemoryTagString()
}

// appleDeploymentTagsForTarget returns the COMMON tag set for a gomobile -target value.
//
// It deliberately ignores which platforms are in the list. A previous version inspected the
// target, decided "some target here is mobile", and folded with_low_memory into the common set.
// For `ios,macos` - which is what the Apple CI builds - that enabled low-memory geometry on
// macOS, and the accompanying -tags-not-macos could not remove it, because -tags had already
// turned it on.
//
// The common set is now the same for every Apple target by construction, so there is no
// target for the bug to depend on.
func appleDeploymentTagsForTarget(bindTarget string) []string {
	return applebuildtags.TargetTags(bindTarget)
}
