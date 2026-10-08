package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
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
func ResolveBuildTags(variant string) []string {
	switch variant {
	case "android-main":
		tags := append([]string{}, sharedTags...)
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		return tags
	case "android-legacy":
		tags := filterTags(sharedTags, "with_naive_outbound")
		if debugEnabled {
			tags = append(tags, debugTags...)
		}
		return tags
	case "apple":
		tags := append([]string{}, sharedTags...)
		tags = append(tags, darwinTags...)
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
	darwinTags  []string
	// memcTags    []string
	notMemcTags []string
	debugTags   []string
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

	// The Apple tag content lives in tags.go so the builder, the low-memory CI gate and
	// the memory benchmark all read ONE definition. Three hand-maintained lists that are
	// supposed to agree eventually do not, and the failure is silent: the tests keep
	// passing against a tag set nothing ships.
	sharedTags = append(sharedTags, applebuildtags.CommonTags()...)

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
	notMemcTags = append(notMemcTags, applebuildtags.LowMemoryMobileTags()...)
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
		// The mobile-only geometry, applied per platform. This is the ONLY channel that can
		// express "iOS gets it, macOS does not": -tags below is common to every target, so a
		// mobile-only tag placed there would reach macOS regardless of this flag.
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
