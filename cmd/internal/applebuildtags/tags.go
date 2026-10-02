// Package applebuildtags is the single source of truth for the build tags the Apple
// (iOS, tvOS, macOS) targets ship with.
//
// # Why this package exists
//
// The same tag lists previously existed twice - once in the libbox builder and once in the
// tag-reporting helper - because both are package main and neither could import the other.
// They were kept in agreement by a test that parsed the other file's source text and compared
// the results.
//
// That arrangement has a specific failure mode beyond mere duplication: the parser compares
// the lists, so it catches a tag added to one and not the other, but it cannot catch a
// QUESTION that was never asked twice. The mixed-target macOS leak existed with both lists
// byte-identical and the contract test green, because the defect was in how the shared set was
// derived, not in whether the two copies matched.
//
// A real import makes the duplication impossible rather than merely detected.
//
// # The distinction that matters
//
// with_low_memory halves buf.BufferSize from 32 KiB to 16 KiB, which moves the in-place framing
// boundary in the Shadowsocks writer - the boundary a production crash came out of. iOS and
// tvOS ship with it. macOS does NOT, and enabling it there would make macOS exercise a memory
// geometry macOS never ships.
package applebuildtags

import (
	"sort"
	"strings"
)

// LowMemoryTag is the tag that selects the smaller buffer geometry.
//
// It is mobile-only. See TargetTags and CommonTags for why it must never appear in a tag set
// shared with macOS.
const LowMemoryTag = "with_low_memory"

// sharedTags apply to every Apple target, macOS included.
var sharedTags = []string{
	"with_quic",
	"with_wireguard",
	"with_utls",
	"with_naive_outbound",
	"with_clash_api",
	"with_usbip",
	"with_openvpn",
	"with_openconnect",
	"badlinkname",
	"tfogo_checklinkname0",
	"with_tailscale",
	"ts_omit_logtail",
	"ts_omit_ssh",
	"ts_omit_drive",
	"ts_omit_taildrop",
	"ts_omit_webclient",
	"ts_omit_doctor",
	"ts_omit_capture",
	"ts_omit_kube",
	"ts_omit_aws",
	"ts_omit_synology",
	"ts_omit_bird",
}

// darwinTags apply to every Apple target as well: these are Darwin-wide, not per-platform.
var darwinTags = []string{
	"with_dhcp",
	"grpcnotrace",
}

// LowMemoryMobileTags is the per-platform tag set gomobile applies to iOS and tvOS ONLY.
//
// This is the set that must be passed as -tags-not-macos=<these> rather than being folded into
// the common -tags. See CommonTags.
func LowMemoryMobileTags() []string {
	return []string{LowMemoryTag}
}

// CommonTags returns the tags that apply to EVERY Apple target in the build.
//
// # Why with_low_memory is never here
//
// gomobile's -tags flag applies to all targets. A tag named in -tags is therefore enabled for
// macOS no matter what -tags-not-macos says: -tags-not-macos can add a tag for the non-macOS
// targets, but it cannot REMOVE one the common set already turned on.
//
// So folding a mobile-only tag into the common set silently enables it on macOS in a mixed
// target build, and no per-platform flag can undo it. That is not a hypothetical: the Apple CI
// builds `ios,macos`, so a leak here reaches the real macOS artifact.
//
// The rule this function encodes: the common set contains only what every target shares.
// Mobile-only geometry travels exclusively through LowMemoryMobileTags.
func CommonTags() []string {
	tags := make([]string, 0, len(sharedTags)+len(darwinTags))
	tags = append(tags, sharedTags...)
	tags = append(tags, darwinTags...)
	return tags
}

// CommonTagString is CommonTags joined for gomobile's -tags flag.
func CommonTagString() string {
	return strings.Join(CommonTags(), ",")
}

// LowMemoryTagString is the mobile-only set joined for gomobile's -tags-not-macos flag.
func LowMemoryTagString() string {
	return strings.Join(LowMemoryMobileTags(), ",")
}

// TargetPlatform describes one gomobile Apple target and whether it ships low-memory geometry.
type TargetPlatform struct {
	// Name is the gomobile target identifier, e.g. "ios" or "macos".
	Name string
	// LowMemory reports whether this platform ships the smaller buffer geometry.
	LowMemory bool
}

// applePlatforms enumerates every gomobile Apple target and its memory geometry.
//
// This is the SINGLE definition of which Apple platforms are low-memory. Anything that needs
// to know - the builder, the tag reporter, the contract tests - asks here rather than deciding
// for itself.
var applePlatforms = []TargetPlatform{
	{Name: "ios", LowMemory: true},
	{Name: "iossimulator", LowMemory: true},
	{Name: "tvos", LowMemory: true},
	{Name: "tvossimulator", LowMemory: true},
	{Name: "macos", LowMemory: false},
}

// ApplePlatforms returns every known Apple target and its geometry.
func ApplePlatforms() []TargetPlatform {
	platforms := make([]TargetPlatform, len(applePlatforms))
	copy(platforms, applePlatforms)
	return platforms
}

// PlatformShipsLowMemory reports whether a single gomobile target identifier ships the
// low-memory geometry.
//
// An unknown target reports false: a platform this package has not been told about must not
// silently acquire mobile geometry, which is the failure this package exists to prevent.
func PlatformShipsLowMemory(target string) bool {
	target = strings.TrimSpace(target)
	for _, platform := range applePlatforms {
		if platform.Name == target {
			return platform.LowMemory
		}
	}
	return false
}

// TargetShipsLowMemory reports whether a gomobile -target value ships low-memory geometry.
//
// bindTarget is a comma-separated list, e.g. "ios,macos". It reports true only when EVERY
// target in the list is a low-memory platform.
//
// # Why "every" and not "any"
//
// This is the exact question the mixed-target leak got wrong. With `ios,macos`, asking "is any
// target low-memory?" answers yes, and a caller that then folds the tag into the shared set
// enables it on macOS too.
//
// For a MIXED target list the honest answer is "some do, some do not", and the only correct
// way to express that to gomobile is the common set without the tag, plus the per-platform
// set. Returning false for a mixed list is what makes TargetTags produce exactly that.
func TargetShipsLowMemory(bindTarget string) bool {
	targets := splitTargets(bindTarget)
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if !PlatformShipsLowMemory(target) {
			return false
		}
	}
	return true
}

// TargetTags returns the COMMON tag set for a gomobile -target value.
//
// It is the same set for every Apple target combination, by construction: the tags shared by
// all Apple targets. Per-platform geometry is not here and cannot be, which is what makes the
// macOS leak structurally impossible rather than merely fixed.
func TargetTags(bindTarget string) []string {
	_ = bindTarget // kept for signature stability and future per-target divergence
	return CommonTags()
}

// TargetTagString is TargetTags joined for -tags.
func TargetTagString(bindTarget string) string {
	return strings.Join(TargetTags(bindTarget), ",")
}

// SortedTags returns a sorted copy, for callers comparing two sets where ordering must not
// matter and for stable reporting.
func SortedTags(tags []string) []string {
	sorted := make([]string, len(tags))
	copy(sorted, tags)
	sort.Strings(sorted)
	return sorted
}

// FullDeploymentTags returns every tag a specific platform ships, canonical set plus its
// geometry. It describes the SEMANTIC result for one platform and is not what gomobile is
// handed - the flags are the common set plus the per-platform set.
//
// It exists so tests and reports can state "iOS has with_low_memory, macOS does not" without
// re-deriving it from flags, which is where the leak hid.
func FullDeploymentTags(target string) []string {
	tags := CommonTags()
	if PlatformShipsLowMemory(target) {
		tags = append(tags, LowMemoryTag)
	}
	return SortedTags(tags)
}

// FullDeploymentTagString is FullDeploymentTags joined, for -ldflags-style reporting.
func FullDeploymentTagString(target string) string {
	return strings.Join(FullDeploymentTags(target), ",")
}

func splitTargets(bindTarget string) []string {
	parts := strings.Split(bindTarget, ",")
	targets := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			targets = append(targets, trimmed)
		}
	}
	return targets
}
