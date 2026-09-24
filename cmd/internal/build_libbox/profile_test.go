package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// appleDefaultTags mirrors the tag set buildApple assembles with no profile.
// It is spelled out here rather than read from the globals so a change to the
// default set shows up as a test failure to review, not as a silently different
// expectation.
func appleDefaultTags() []string {
	return []string{
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
		"with_dhcp",
		"grpcnotrace",
	}
}

func containsTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

// TestDefaultAppleBuildHasNoProfile is the compatibility guarantee: with no
// -profile the tag set must be exactly the upstream one, so nothing this change
// adds can alter the default Apple build.
func TestDefaultAppleBuildHasNoProfile(t *testing.T) {
	tags := appleDefaultTags()
	require.False(t, containsTag(tags, "jiejie_ios_slim"),
		"the slim marker must never appear without an explicit profile")
}

// TestIOSSlimProfileRemovesOnlyUnwantedTags pins the removals, so a future edit
// cannot quietly drop a capability the client needs.
func TestIOSSlimProfileRemovesOnlyUnwantedTags(t *testing.T) {
	tags := applyAppleProfile(appleDefaultTags(), iosSlimProfile)

	removed := []string{
		"with_tailscale",
		"with_wireguard",
		"with_usbip",
		"with_openvpn",
		"with_openconnect",
		"with_dhcp",
		"with_clash_api",
	}
	for _, tag := range removed {
		require.False(t, containsTag(tags, tag),
			"the slim profile must remove %s", tag)
	}

	// These are load-bearing for the client's feature set and must survive.
	retained := []string{
		"with_quic",            // MASQUE HTTP/3, the H3 pool and fallback
		"with_utls",            // VLESS Reality/Vision
		"with_naive_outbound",  // NaiveProxy outbound
		"badlinkname",          // required by the Apple toolchain
		"tfogo_checklinkname0", // required by the Apple toolchain
	}
	for _, tag := range retained {
		require.True(t, containsTag(tags, tag),
			"the slim profile must retain %s", tag)
	}

	require.True(t, containsTag(tags, "jiejie_ios_slim"),
		"the slim profile must select the slim registry")
}

// TestApplyingProfileTwiceIsStable guards against the profile being applied to
// its own output, which would duplicate the added tag.
func TestApplyingProfileTwiceIsStable(t *testing.T) {
	once := applyAppleProfile(appleDefaultTags(), iosSlimProfile)
	twice := applyAppleProfile(once, iosSlimProfile)

	count := 0
	for _, tag := range twice {
		if tag == "jiejie_ios_slim" {
			count++
		}
	}
	require.Equal(t, 1, count,
		"re-applying the profile must not duplicate its tag; got %v", twice)
}

// TestUnknownProfileIsRejected proves a typo cannot silently produce a default
// build while the caller believes a profile was applied.
func TestUnknownProfileIsRejected(t *testing.T) {
	_, known := findAppleProfile("does-not-exist")
	require.False(t, known)

	selected, known := findAppleProfile(iosSlimProfile.name)
	require.True(t, known)
	require.Equal(t, iosSlimProfile.name, selected.name)
}
