package main

import (
	"flag"
	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
func writeProvenance() {
	content := "commit=" + buildCommit + "\n" +
		"version=" + buildVersion + "\n"
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

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	androidTags []string
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

	// Android-only tags. with_gvisor selects sing-tun's gVisor netstack, which is
	// the stack the Android client asks for ("stack": "mixed"/"gvisor"); without
	// this tag sing-tun compiles stack_gvisor_stub.go and starting a tun fails with
	// "gVisor is not included in this build". It is deliberately NOT in the shared
	// Apple list, so the Apple artifacts keep their existing stack choices.
	androidTags = append(androidTags, "with_gvisor")
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
	mainTags := append([]string{}, sharedTags...)
	mainTags = append(mainTags, androidTags...)
	// mainTags = append(mainTags, memcTags...)
	if debugEnabled {
		mainTags = append(mainTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 24,
		OutputName: "libbox.aar",
		Tags:       mainTags,
	}, bindTarget)

	// Build legacy variant (SDK 21, no naive outbound)
	legacyTags := filterTags(sharedTags, "with_naive_outbound")
	legacyTags = append(legacyTags, androidTags...)
	// legacyTags = append(legacyTags, memcTags...)
	if debugEnabled {
		legacyTags = append(legacyTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 21,
		OutputName: "libbox-legacy.aar",
		Tags:       legacyTags,
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
