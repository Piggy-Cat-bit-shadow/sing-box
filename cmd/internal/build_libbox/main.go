package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
	"github.com/sagernet/sing-box/cmd/internal/mobilebuildtags"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
)

var (
	debugEnabled bool
	target       string
	platform     string
	// withTailscale bool
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	// flag.BoolVar(&withTailscale, "with-tailscale", false, "build tailscale for iOS and tvOS")
}

func main() {
	flag.Parse()

	build_shared.FindMobile()

	switch target {
	case "android":
		buildAndroid()
	case "apple":
		buildApple()
	}

	writeProvenance()
}

// writeProvenance records exactly which source revision and version string the
// artifacts in this directory were built with. The Android client reads this
// file, so "which core is in this APK" has one authoritative answer.
// sortedTagVariants lists the shipped variants in a stable order for the provenance record.
func sortedTagVariants() []string {
	return []string{"android-main", "android-legacy", "apple"}
}

func writeProvenance() {
	content := "commit=" + buildCommit + "\n" +
		"version=" + buildVersion + "\n"
	// The tags each shipped variant was compiled with. A consumer can read this to know whether
	// an artifact contains a given capability (for example with_gvisor) without parsing the build
	// scripts, and a CI check can assert the invariant that capability implies the matching
	// dependency pin.
	for _, variant := range sortedTagVariants() {
		content += "tags." + variant + "=" + strings.Join(ResolveBuildTags(variant), ",") + "\n"
	}
	for _, name := range []string{"libbox.provenance", filepath.Join("..", "sing-box-for-android", "app", "libs", "libbox.provenance")} {
		if dir := filepath.Dir(name); dir != "." {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				continue
			}
		}
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			log.Warn("write ", name, ": ", err)
			continue
		}
		log.Info("wrote ", name, " (commit=", buildCommit, " version=", buildVersion, ")")
	}
}

// resolvedTags are the build tags actually compiled into each shipped variant, recorded so a
// consumer can answer "does this artifact include X" without re-deriving the composition.
//
// This exists because a check that reads the profile tag FILES is not the same as a check on what
// the artifacts are built with: the libbox builder composes its own tag sets. The 048 gVisor crash
// was found exactly through that gap - a tripwire that only read the profile files reported "no
// profile names with_gvisor" while the Android artifacts did compile it. The gap is still real
// even though this particular tag is gone, which is why the resolution is still recorded here and
// why the inverse invariant is asserted against the RESOLVED tags rather than the files.
var resolvedTags = map[string][]string{}

// ResolveBuildTags returns the build tags for the named shipped variant. It is the single source
// of truth for tag composition: the builders below call it, the provenance record is written from
// it, and a test asserts the gVisor invariant against it.
//
// # Why both Android variants carry the mobile geometry
//
// Every Android variant appends mobilebuildtags.LowMemoryTags(), so the shipped artifacts compile
// buf.BufferSize 16 KiB and UDPBufferSize 8 KiB instead of 32 KiB and 16 KiB. The geometry is a
// MOBILE concern in the layering - mobilebuildtags owns it, not applebuildtags - and Android is a
// mobile platform, so it reads the same layer iOS receives through gomobile's -tags-not-macos.
// This is not a fold into sharedTags: sharedTags is also what the Apple common set is built from,
// and a tag there would reach macOS in the real ios,macos build where -tags-not-macos cannot
// remove it.
//
// The decision was made from measurement (common/bufgeom, HOST BENCHMARK on darwin/arm64), not
// from "phones have less memory":
//
//   - Live heap per flow, GC-observed: 65664 bytes at 32 KiB against 32896 at 16 KiB, two buffers
//     per flow, identical at 32, 128 and 512 concurrent flows. At 512 flows that is 32.8 MiB
//     against 16.4 MiB - 16.4 MiB of resident heap at a concurrency this host can hold.
//   - Bulk TCP is NOT bounded by the geometry. copyExtended grows the read buffer past
//     IncreaseBufferAfter (512 KiB) to 65535 bytes: for an 8 MiB transfer both geometries hand
//     over a largest buffer of 65535 (155 WriteBuffer calls at 32 KiB against 173 at 16 KiB), so
//     the extra work is confined to a flow's first 512 KiB rather than charged to every byte.
//   - Short flows pay exactly that prefix: 16 reads of 16 KiB instead of 8 of 32 KiB per 256 KiB,
//     with 15 against 22 allocations per transfer. Measured loopback throughput at 32/128/512
//     concurrent flows and at 256 KiB and 4 MiB transfers had overlapping sample ranges in both
//     directions, so no regression or improvement is resolvable above this host's noise; the
//     deterministic cost is the doubled read count.
//   - UDP is geometry-independent per datagram: a datagram is bounded by the MTU (well under
//     8192), the packet copy loop's allocations per datagram are identical (2067 per 2048
//     datagrams in both geometries) and only the pooled capacity differs.
//
// The 50 MiB NetworkExtension budget is deliberately NOT part of this reasoning. It is an Apple
// extension limit, not a cross-platform truth, and half of the heap saving above would still not
// be a claim about fitting inside it.
//
// The risk this geometry was believed to carry - the in-place framing boundary in the Shadowsocks
// writer, which a production crash came out of - is tested at this geometry rather than argued
// away. The default suite cannot reach the combination that panicked, which is why
// scripts/ci/test-low-memory.sh exists; the Android variants now build the geometry that gate
// covers.
func ResolveBuildTags(variant string) []string {
	switch variant {
	case "android-main":
		tags := append([]string{}, sharedTags...)
		tags = append(tags, mobilebuildtags.LowMemoryTags()...)
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		return tags
	case "android-legacy":
		tags := filterTags(sharedTags, "with_naive_outbound")
		tags = append(tags, mobilebuildtags.LowMemoryTags()...)
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		return tags
	case "apple":
		// The Apple variant's shared set is read from the APPLE source of truth, not from the
		// mobile shared set directly: if Apple ever gains a Darwin-only tag, the provenance record
		// and the built artifact must both see it. That composition lives in tags.go so this file -
		// which owns the Android composition - does not import the Apple package at all.
		tags := appleCommonTags()
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		return tags
	default:
		return nil
	}
}

// HasBuildTag reports whether the resolved tag set for a variant includes a tag.
func HasBuildTag(variant, tag string) bool {
	return slices.Contains(ResolveBuildTags(variant), tag)
}

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	// memcTags []string
	debugTags []string
)

// buildVersion is the value baked into constant.Version, and buildCommit is the
// source revision it was built from. Both are resolved ONCE here and then written
// to libbox.provenance next to the artifacts, so a consumer (the Android client)
// reads the version from the same record that produced the binary instead of
// re-deriving it from a possibly-advanced checkout.
var (
	buildVersion string
	buildCommit  string
)

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	buildVersion = currentTag
	buildCommit = build_shared.ReadCommit()
	sharedFlags = append(sharedFlags, "-ldflags", build_shared.LinkerFlags(currentTag, false))
	debugFlags = append(debugFlags, "-ldflags", build_shared.LinkerFlags(currentTag, true))

	// The shared feature set lives in cmd/internal/mobilebuildtags because Android and Apple both
	// ship it, and it is not Apple's to define. Reading it from an Apple-named package - which is
	// what this builder did - meant the natural way to add an Apple-only tag was to append to that
	// package's common list, and Android silently acquired it. One definition, owned by the layer
	// both platforms share, is what makes that mistake impossible rather than merely detectable.
	sharedTags = append(sharedTags, mobilebuildtags.SharedTags()...)

	// Android no longer ships with_gvisor.
	//
	// It did: the Android UI asked for "stack": "mixed"/"gvisor" and sing-tun therefore had to be
	// compiled with gVisor's netstack, so this builder appended with_gvisor to both Android
	// variants. That product decision has been reversed - the Android UI no longer depends on
	// mixed/gvisor - and gVisor is retired from shipped artifacts.
	//
	// The retirement is deliberately NOT "delete the line and move on". Going back to shipping
	// gVisor would re-expose the 048 crash surface and re-require the patched fork, so the
	// invariant is now inverted and asserted: no shipped variant may name with_gvisor, and
	// TestNoShippedVariantShipsGVisor fails if one does. See docs/fork/lx-stability-audit-phase1.md
	// for why 048 was a real risk when it shipped, and docs/fork/upstream-sync-2026-10.md for the
	// retirement.
	// The mobile geometry tag is NOT appended to sharedTags above. It is a mobile concern Apple
	// delivers per platform through gomobile's -tags-not-macos flag, and it is read from
	// mobilebuildtags by the Apple composition in tags.go. Folding it in here would enable it on
	// macOS in gomobile's mixed -target build, where -tags-not-macos cannot remove it.
	debugTags = append(debugTags, "debug")
}

type AndroidBuildConfig struct {
	AndroidAPI int
	OutputName string
	Tags       []string
}

func filterTags(tags []string, exclude ...string) []string {
	excludeMap := make(map[string]bool)
	for _, tag := range exclude {
		excludeMap[tag] = true
	}
	var result []string
	for _, tag := range tags {
		if !excludeMap[tag] {
			result = append(result, tag)
		}
	}
	return result
}

func checkJavaVersion() {
	var javaPath string
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		javaPath = "java"
	} else {
		javaPath = filepath.Join(javaHome, "bin", "java")
	}

	javaVersion, err := shell.Exec(javaPath, "--version").ReadOutput()
	if err != nil {
		log.Fatal(E.Cause(err, "check java version"))
	}
	if !strings.Contains(javaVersion, "openjdk 17") {
		log.Fatal("java version should be openjdk 17")
	}
}

func getAndroidBindTarget() string {
	if platform != "" {
		return platform
	} else if debugEnabled {
		return "android/arm64"
	}
	return "android"
}

func buildAndroidVariant(config AndroidBuildConfig, bindTarget string) {
	args := []string{
		"bind",
		"-v",
		"-o", config.OutputName,
		"-target", bindTarget,
		"-androidapi", strconv.Itoa(config.AndroidAPI),
		"-javapkg=io.nekohasekai",
		"-libname=box",
	}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	args = append(args, "-tags", strings.Join(config.Tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-android", "app", "libs")
	if rw.IsDir(copyPath) {
		copyPath, _ = filepath.Abs(copyPath)
		err = rw.CopyFile(config.OutputName, filepath.Join(copyPath, config.OutputName))
		if err != nil {
			log.Fatal(err)
		}
		log.Info("copied ", config.OutputName, " to ", copyPath)
	}
}

func buildAndroid() {
	build_shared.FindSDK()
	checkJavaVersion()

	bindTarget := getAndroidBindTarget()

	// Build main variant (SDK 24)
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 24,
		OutputName: "libbox.aar",
		Tags:       ResolveBuildTags("android-main"),
	}, bindTarget)

	// Build legacy variant (SDK 21, no naive outbound)
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 21,
		OutputName: "libbox-legacy.aar",
		Tags:       ResolveBuildTags("android-legacy"),
	}, bindTarget)
}

func buildApple() {
	var bindTarget string
	if platform != "" {
		bindTarget = platform
	} else if debugEnabled {
		bindTarget = "ios"
	} else {
		bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"
	}

	args := []string{
		"bind",
		"-v",
		"-target", bindTarget,
		"-libname=box",
		// The mobile-only geometry, applied per platform. The tag itself is defined in
		// cmd/internal/mobilebuildtags and reaches gomobile through the Apple view in tags.go. This
		// is the ONLY channel that can express "iOS gets it, macOS does not": -tags below is common
		// to every target, so a mobile-only tag placed there would reach macOS regardless of this
		// flag.
		"-tags-not-macos=" + LowMemoryTagString(),
		"-iosversion=15.0",
		"-macosversion=13.0",
		"-tvosversion=17.0",
	}
	//if !withTailscale {
	//	args = append(args, "-tags-macos="+strings.Join(memcTags, ","))
	//}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	// The COMMON tag set. iOS, tvOS and their simulators additionally receive
	// with_low_memory through -tags-not-macos above.
	//
	// This set is identical for every Apple target by construction, because -tags applies to
	// all of them. Folding the mobile-only tag in here would enable it on macOS in a mixed
	// build, and no per-platform flag could undo that.
	tags := appleDeploymentTagsForTarget(bindTarget)
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	args = append(args, "-tags", strings.Join(tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-apple")
	if rw.IsDir(copyPath) {
		targetDir := filepath.Join(copyPath, "Libbox.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("Libbox.xcframework", targetDir)
		log.Info("copied to ", targetDir)
	}
}
