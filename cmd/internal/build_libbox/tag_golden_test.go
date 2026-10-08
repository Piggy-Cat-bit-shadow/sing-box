package main

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
	"github.com/sagernet/sing-box/cmd/internal/mobilebuildtags"
)

// The before/after proof for the mobilebuildtags refactor.
//
// # Why these are frozen literals and not expressions
//
// The refactor moved the source of Android's tag set out of an Apple-named package and split the
// mobile shared set, the Apple-only layer and the low-memory geometry into explicit layers. The
// hard requirement was NO functional change: every shipped variant must resolve byte-for-byte the
// tags it resolved before. A test that recomputes the expected value from the new code cannot show
// that - it would agree with whatever the new code does, including a mistake.
//
// So these literals were captured by running ResolveBuildTags and the tag-set helpers against the
// tree BEFORE the change (branch `testing`, the refactor's parent commit) and pasted here
// verbatim, in the order the functions return them. Any reordering, tag addition or removal now
// fails this test, which is the only way an "identical output" claim is worth anything.
//
// # Why order is part of the freeze
//
// The tags are joined into gomobile's -tags flag and into the libbox.provenance record. Reordering
// does not change which code compiles, but it DOES change the provenance bytes a consumer reads,
// and a consumer that diffs that file would see a change while the comment above claimed none.
// Comparing the joined string, rather than a set, makes both observable effects part of the
// contract.

// frozenResolvedTags is ResolveBuildTags(variant) joined with commas, captured before the refactor.
//
// The two Android entries were updated when Android adopted the mobile buffer geometry: both
// variants now append with_low_memory, so they are no longer byte-identical to the pre-refactor
// tree. That change is INTENTIONAL and separately justified - see ResolveBuildTags for the
// measurement - and it is recorded here rather than hidden by deleting the entries, because a
// frozen value that stopped being compared would prove nothing. The apple and unknown entries
// remain the pre-refactor bytes: macOS must not acquire the geometry.
var frozenResolvedTags = map[string]string{
	"android-main": "with_quic,with_wireguard,with_utls,with_naive_outbound,with_xhttp," +
		"with_clash_api,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0," +
		"with_tailscale,ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient," +
		"ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird," +
		"with_dhcp,grpcnotrace,with_low_memory",
	"android-legacy": "with_quic,with_wireguard,with_utls,with_xhttp,with_clash_api,with_usbip," +
		"with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_tailscale," +
		"ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor," +
		"ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_dhcp,grpcnotrace," +
		"with_low_memory",
	"apple": "with_quic,with_wireguard,with_utls,with_naive_outbound,with_xhttp,with_clash_api," +
		"with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_tailscale," +
		"ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor," +
		"ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_dhcp,grpcnotrace",
	// An unknown variant resolves to nothing. Frozen rather than omitted so a future variant added
	// to ResolveBuildTags without updating sortedTagVariants is visible here as well.
	"unknown": "",
}

// preRefactorCommonTags is the MOBILE SHARED set as captured before the refactor, kept separate
// from frozenResolvedTags["android-main"] on purpose.
//
// The two strings were equal until Android adopted the mobile geometry, and that equality was
// load-bearing: it proved the shared set and the Android composition were the same thing. Android
// now ships the geometry ON TOP of the shared set, so the Android composition is SUPPOSED to
// differ. A single string would force a choice between freezing the wrong value and not freezing
// the shared set at all. macOS must still resolve exactly this value, which is what the Apple
// comparison below asserts.
const preRefactorCommonTags = "with_quic,with_wireguard,with_utls,with_naive_outbound,with_xhttp," +
	"with_clash_api,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0," +
	"with_tailscale,ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient," +
	"ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird," +
	"with_dhcp,grpcnotrace"

// frozenApplePlatformTags is FullDeploymentTagString(platform) for every gomobile Apple target,
// captured before the refactor.
var frozenApplePlatformTags = map[string]string{
	"ios": "badlinkname,grpcnotrace,tfogo_checklinkname0,ts_omit_aws,ts_omit_bird,ts_omit_capture," +
		"ts_omit_doctor,ts_omit_drive,ts_omit_kube,ts_omit_logtail,ts_omit_ssh,ts_omit_synology," +
		"ts_omit_taildrop,ts_omit_webclient,with_clash_api,with_dhcp,with_low_memory,with_naive_outbound," +
		"with_openconnect,with_openvpn,with_quic,with_tailscale,with_usbip,with_utls,with_wireguard,with_xhttp",
	"iossimulator": "badlinkname,grpcnotrace,tfogo_checklinkname0,ts_omit_aws,ts_omit_bird,ts_omit_capture," +
		"ts_omit_doctor,ts_omit_drive,ts_omit_kube,ts_omit_logtail,ts_omit_ssh,ts_omit_synology," +
		"ts_omit_taildrop,ts_omit_webclient,with_clash_api,with_dhcp,with_low_memory,with_naive_outbound," +
		"with_openconnect,with_openvpn,with_quic,with_tailscale,with_usbip,with_utls,with_wireguard,with_xhttp",
	"tvos": "badlinkname,grpcnotrace,tfogo_checklinkname0,ts_omit_aws,ts_omit_bird,ts_omit_capture," +
		"ts_omit_doctor,ts_omit_drive,ts_omit_kube,ts_omit_logtail,ts_omit_ssh,ts_omit_synology," +
		"ts_omit_taildrop,ts_omit_webclient,with_clash_api,with_dhcp,with_low_memory,with_naive_outbound," +
		"with_openconnect,with_openvpn,with_quic,with_tailscale,with_usbip,with_utls,with_wireguard,with_xhttp",
	"tvossimulator": "badlinkname,grpcnotrace,tfogo_checklinkname0,ts_omit_aws,ts_omit_bird,ts_omit_capture," +
		"ts_omit_doctor,ts_omit_drive,ts_omit_kube,ts_omit_logtail,ts_omit_ssh,ts_omit_synology," +
		"ts_omit_taildrop,ts_omit_webclient,with_clash_api,with_dhcp,with_low_memory,with_naive_outbound," +
		"with_openconnect,with_openvpn,with_quic,with_tailscale,with_usbip,with_utls,with_wireguard,with_xhttp",
	"macos": "badlinkname,grpcnotrace,tfogo_checklinkname0,ts_omit_aws,ts_omit_bird,ts_omit_capture," +
		"ts_omit_doctor,ts_omit_drive,ts_omit_kube,ts_omit_logtail,ts_omit_ssh,ts_omit_synology," +
		"ts_omit_taildrop,ts_omit_webclient,with_clash_api,with_dhcp,with_naive_outbound,with_openconnect," +
		"with_openvpn,with_quic,with_tailscale,with_usbip,with_utls,with_wireguard,with_xhttp",
}

// TestResolvedTagSetsAreByteIdenticalToThePreRefactorTree freezes every shipped variant's resolved
// tags, so that any change to the composition has to be made deliberately here as well.
//
// It was a pure no-functional-change proof for the layering refactor. It is now a freeze with one
// recorded exception: the two Android variants gained with_low_memory when Android adopted the
// mobile buffer geometry, which is a functional change made on purpose and justified in
// ResolveBuildTags. The Apple and unknown entries are still the pre-refactor bytes, which is what
// keeps the macOS half of the proof intact.
func TestResolvedTagSetsAreByteIdenticalToThePreRefactorTree(t *testing.T) {
	for variant, want := range frozenResolvedTags {
		t.Run(variant, func(t *testing.T) {
			got := strings.Join(ResolveBuildTags(variant), ",")
			if got != want {
				t.Fatalf("ResolveBuildTags(%q) changed across the layering refactor.\n got: %s\nwant: %s\n"+
					"If the change is intentional, the tag composition, the provenance record and this "+
					"frozen value must be updated together - and the report must say why.",
					variant, got, want)
			}
		})
	}
}

// TestAppleDeploymentTagSetsAreByteIdenticalToThePreRefactorTree freezes the per-platform Apple
// view as well. The macOS entry is the one that matters most: it is the set the mixed-target leak
// would have moved with_low_memory into, so a refactor that made that possible would show up here
// as a changed string rather than as a passing test.
func TestAppleDeploymentTagSetsAreByteIdenticalToThePreRefactorTree(t *testing.T) {
	for _, platform := range applebuildtags.ApplePlatforms() {
		t.Run(platform.Name, func(t *testing.T) {
			want, known := frozenApplePlatformTags[platform.Name]
			if !known {
				t.Fatalf("platform %q is new since the frozen capture; add its pre-refactor value "+
					"before trusting this test", platform.Name)
			}
			got := applebuildtags.FullDeploymentTagString(platform.Name)
			if got != want {
				t.Fatalf("%s deployment tags changed across the layering refactor.\n got: %s\nwant: %s",
					platform.Name, got, want)
			}
		})
	}
}

// TestMobileGeometryStringsAreByteIdenticalToThePreRefactorTree freezes the two strings the
// gomobile flags are built from. The common string must be the mobile shared set, and the
// mobile-only string must remain exactly one tag.
//
// The shared-set comparisons use preRefactorCommonTags rather than frozenResolvedTags
// ["android-main"]: Android's resolved set now has the geometry appended, so comparing the SHARED
// set against it would either fail or, worse, be "fixed" by folding the geometry into sharedTags -
// which is the macOS leak this package exists to prevent.
func TestMobileGeometryStringsAreByteIdenticalToThePreRefactorTree(t *testing.T) {
	if got, want := mobilebuildtags.SharedTagString(), preRefactorCommonTags; got != want {
		t.Fatalf("mobilebuildtags.SharedTagString() = %q, want the pre-refactor common set %q", got, want)
	}
	if got, want := applebuildtags.CommonTagString(), preRefactorCommonTags; got != want {
		t.Fatalf("applebuildtags.CommonTagString() = %q, want the pre-refactor common set %q", got, want)
	}
	if got, want := mobilebuildtags.LowMemoryTagString(), "with_low_memory"; got != want {
		t.Fatalf("mobilebuildtags.LowMemoryTagString() = %q, want %q", got, want)
	}
	if got, want := applebuildtags.LowMemoryTagString(), "with_low_memory"; got != want {
		t.Fatalf("applebuildtags.LowMemoryTagString() = %q, want %q", got, want)
	}
}
