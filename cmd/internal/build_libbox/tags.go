package main

import (
	"sort"
	"strings"
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
//	AppleSharedTags    every Apple target, including macOS
//	AppleDarwinTags    added on top of the shared set for Apple targets
//	AppleNonMacOSTags  shared + darwin + the memory geometry the phones actually ship
//
// The distinction that matters most is the last one. with_low_memory halves buf.BufferSize
// from 32 KiB to 16 KiB, which moves the in-place framing boundary in the Shadowsocks
// writer - the boundary a production crash came out of. iOS and tvOS are built with it;
// macOS is NOT, and adding it there would make macOS tests exercise a geometry macOS does
// not ship.

// appleSharedTags are applied to every Apple target.
var appleSharedTags = []string{
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

// appleDarwinTags are added for Apple targets.
var appleDarwinTags = []string{
	"with_dhcp",
	"grpcnotrace",
}

// appleLowMemoryTag is what the iOS and tvOS builds add, and macOS does not.
const appleLowMemoryTag = "with_low_memory"

// appleDeploymentTags returns the tags an Apple build uses for a target family.
//
// lowMemory reports whether the target is a phone/tablet/tv family: iOS, tvOS and their
// simulators get with_low_memory; macOS does not.
func appleDeploymentTags(lowMemory bool) []string {
	tags := make([]string, 0, len(appleSharedTags)+len(appleDarwinTags)+1)
	tags = append(tags, appleSharedTags...)
	tags = append(tags, appleDarwinTags...)
	if lowMemory {
		tags = append(tags, appleLowMemoryTag)
	}
	return tags
}

// AppleDeploymentTags is the exported form, for tooling that needs the shipped set.
//
// It is sorted so a caller comparing two sets is not defeated by ordering, and returned as
// a fresh slice so a caller cannot mutate the canonical lists.
func AppleDeploymentTags(lowMemory bool) []string {
	tags := appleDeploymentTags(lowMemory)
	sort.Strings(tags)
	return tags
}

// AppleDeploymentTagString is AppleDeploymentTags joined for -tags.
func AppleDeploymentTagString(lowMemory bool) string {
	return strings.Join(AppleDeploymentTags(lowMemory), ",")
}

// appleDeploymentTagsForTarget maps a gomobile -target value to the tags that family ships.
//
// iOS and tvOS (and their simulators) get with_low_memory because libbox passes
// -tags-not-macos=with_low_memory; macOS is built without it. Deriving the set from the
// target means the builder cannot disagree with AppleDeploymentTags about which platforms
// are low-memory.
func appleDeploymentTagsForTarget(bindTarget string) []string {
	lowMemory := false
	for _, target := range strings.Split(bindTarget, ",") {
		switch strings.TrimSpace(target) {
		case "ios", "iossimulator", "tvos", "tvossimulator":
			lowMemory = true
		}
	}
	return appleDeploymentTags(lowMemory)
}
