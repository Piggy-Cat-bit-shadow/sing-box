// Package mobilebuildtags is the single source of truth for the build tags the MOBILE
// libbox artifacts ship with - Android and Apple alike.
//
// # Why this package exists
//
// The Android and Apple libbox builders ship the same feature set, and that set previously lived
// in cmd/internal/applebuildtags. Nothing about with_quic, with_xhttp or the Tailscale omit
// flags is Apple-specific. So an Apple-named package was the source of truth for Android: a
// maintainer changing what Android ships had to edit a package whose name and documentation said
// Apple, and every reader of the Android composition had to know that the Apple package was
// really the mobile package.
//
// That mislabelling is the kind that survives review, because the resolved tag set is right.
// Only the ownership is wrong, so no test fails and no binary changes. The failure it sets up is
// concrete the first time the platforms need to diverge: the obvious way to add an Apple-only tag
// is to append it to the Apple package's common list, and Android silently acquires it, because
// Android was reading that list. The reverse - an Android-only tag - has nowhere to live at all.
//
// # The layering
//
//	A. sharedTags      every mobile platform ships these, so both builders read them here
//	D. lowMemoryTags   the smaller buffer geometry, a MOBILE concern rather than an Apple one
//
// Apple-only tags and the Apple platform geometry live in cmd/internal/applebuildtags, which
// depends on this package. This package must never import it: the dependency direction is the
// whole point, and cmd/internal/build_libbox's layering test asserts it against the source.
// Android currently has no tag of its own, so there is no Android-only layer to declare; inventing
// an empty one would be a historical shell rather than an abstraction.
//
// # Why with_low_memory is in this package but NOT in the shared set
//
// with_low_memory halves buf.BufferSize from 32 KiB to 16 KiB and UDPBufferSize from 16 KiB to
// 8 KiB (the sing fork's common/buf/buffer_low_memory.go). It moves the in-place framing boundary
// in the Shadowsocks writer - the boundary a production crash came out of. It is a mobile
// concern, and it is named here because it was previously reachable only through an Apple-named
// package, which implied macOS was part of the decision. It is not:
//
//   - gomobile's -tags applies to EVERY target, macOS included;
//   - -tags-not-macos can ADD a tag for the non-macOS targets, but it cannot REMOVE one that
//     -tags already enabled.
//
// So a mobile-only tag placed in the shared set is enabled on macOS in a mixed target build and no
// per-platform flag can undo it. That is not hypothetical: the Apple CI builds `ios,macos`, so a
// leak here reaches the real macOS artifact and makes macOS exercise a buffer geometry it never
// ships. The shared set therefore contains only what every target shares, and the geometry
// travels exclusively through LowMemoryTags - for Apple, via applebuildtags.LowMemoryMobileTags
// and gomobile's -tags-not-macos.
package mobilebuildtags

import "strings"

// sharedTags are the feature tags EVERY mobile platform ships - layer A.
//
// with_dhcp and grpcnotrace were historically filed as "Darwin-wide" in applebuildtags. They are
// not Darwin-meaningful, and Android already compiled both, because the Apple common set WAS the
// Android shared set. with_dhcp gates include/dhcp.go, the platform-independent DHCP transport,
// and grpcnotrace is grpc-go's own tracing switch. Moving them here records what was already true
// rather than changing it; leaving them under a Darwin label while Android read that label is
// exactly the mislabelling this package exists to remove.
var sharedTags = []string{
	"with_quic",
	"with_wireguard",
	"with_utls",
	"with_naive_outbound",
	// XHTTP is a mainstream VLESS transport in current Xray deployments, so the shipped clients
	// carry it rather than leaving it opt-in: a node configured with it must work in the app. It
	// needs with_quic for its HTTP/3 path, which this set already has.
	"with_xhttp",
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
	"with_dhcp",
	"grpcnotrace",
}

// SharedTags returns a copy of the feature tags every mobile platform ships.
//
// It returns a copy rather than the backing slice because callers layer per-variant tags on top
// (the debug tag, and the Android legacy variant's removal of with_naive_outbound). A caller that
// appended to the returned slice would otherwise mutate the source of truth for every later caller
// in the same process, which in the builder means the second Android variant silently inheriting
// the first one's tags.
func SharedTags() []string {
	tags := make([]string, len(sharedTags))
	copy(tags, sharedTags)
	return tags
}

// SharedTagString is SharedTags joined for a compiler or gomobile -tags flag.
func SharedTagString() string {
	return strings.Join(SharedTags(), ",")
}

// LowMemoryTag selects the smaller buffer geometry (BufferSize 16 KiB, UDPBufferSize 8 KiB).
//
// It is mobile-only. See the package comment for why it must never appear in SharedTags: a tag
// there reaches macOS in a mixed `ios,macos` build where -tags-not-macos cannot remove it.
const LowMemoryTag = "with_low_memory"

// lowMemoryTags is the mobile-only geometry set - layer D.
//
// The Apple builder hands this to gomobile as -tags-not-macos rather than folding it into -tags;
// see LowMemoryTag. It is one tag today, and it stays a set rather than a bare string because the
// gomobile flag and the reporting helpers are set-shaped and a second geometry knob must not
// require reshaping them.
var lowMemoryTags = []string{LowMemoryTag}

// LowMemoryTags returns a copy of the mobile-only geometry set.
func LowMemoryTags() []string {
	tags := make([]string, len(lowMemoryTags))
	copy(tags, lowMemoryTags)
	return tags
}

// LowMemoryTagString is LowMemoryTags joined for gomobile's -tags-not-macos flag.
func LowMemoryTagString() string {
	return strings.Join(LowMemoryTags(), ",")
}
