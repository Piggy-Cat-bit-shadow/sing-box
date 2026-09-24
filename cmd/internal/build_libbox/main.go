package main

import (
	"flag"
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
	profile      string
	// withTailscale bool
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	flag.StringVar(&profile, "profile", "", "build profile; empty keeps upstream behaviour. Known: jiejie-ios-slim")
	// flag.BoolVar(&withTailscale, "with-tailscale", false, "build tailscale for iOS and tvOS")
}

// appleProfile describes an opt-in Apple build profile.
//
// A profile exists so that the Jiejie client can be built smaller WITHOUT
// changing what the default `-target apple` invocation produces. Upstream's
// behaviour must stay byte-for-byte what it was: the default path applies no
// profile, so nothing here can regress it.
type appleProfile struct {
	// name is the value accepted by -profile.
	name string
	// removeTags are dropped from the default Apple tag set.
	removeTags []string
	// addTags are appended after the removals.
	addTags []string
}

// iosSlimProfile is the Jiejie iOS slim client profile.
//
// Every removed tag was chosen because a mobile proxy client does not use the
// component, and each removal was checked against a real configuration before
// being adopted (see test/jiejie/jiejie-ios-client-fixture.json):
//
//   - with_tailscale / with_wireguard: no Tailscale or WireGuard endpoint is
//     configured by this client. Dropping tailscale also removes the largest
//     single dependency tree.
//   - with_usbip, with_openvpn, with_openconnect: server-side or desktop-only
//     transports with no place on iOS.
//   - with_dhcp: the client resolves through configured DNS transports; it does
//     not need a DHCP DNS transport.
//   - with_clash_api: the in-app client does not expose the Clash API.
//
// What is deliberately KEPT, because the client needs it:
//
//   - with_quic    : MASQUE HTTP/3, the H3 pool, the H3 fallback schedule.
//   - with_utls    : VLESS Reality/Vision needs a uTLS fingerprint.
//   - with_naive_outbound : the NaiveProxy outbound.
//   - with_acme / with_ccm / with_ocm / with_cloudflared : client-side features.
//   - badlinkname / tfogo_checklinkname0 : required by the Apple toolchain.
//
// The tag set is only half the trim; jiejie_ios_slim also selects a reduced
// registry, which is what actually removes the hysteria/tuic/vmess/trojan
// protocol packages from the import graph.
var iosSlimProfile = appleProfile{
	name: "jiejie-ios-slim",
	removeTags: []string{
		"with_tailscale",
		"with_wireguard",
		"with_usbip",
		"with_openvpn",
		"with_openconnect",
		"with_dhcp",
		"with_clash_api",
	},
	addTags: []string{
		"jiejie_ios_slim",
	},
}

// appleProfiles is the set of accepted -profile values.
var appleProfiles = []appleProfile{iosSlimProfile}

// findAppleProfile returns the named profile, or false when name is not known.
func findAppleProfile(name string) (appleProfile, bool) {
	for _, candidate := range appleProfiles {
		if candidate.name == name {
			return candidate, true
		}
	}
	return appleProfile{}, false
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

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	sharedFlags = append(sharedFlags, "-ldflags", build_shared.LinkerFlags(currentTag, false))
	debugFlags = append(debugFlags, "-ldflags", build_shared.LinkerFlags(currentTag, true))

	sharedTags = append(sharedTags, "with_quic", "with_wireguard", "with_utls", "with_naive_outbound", "with_clash_api", "with_usbip", "with_openvpn", "with_openconnect", "badlinkname", "tfogo_checklinkname0")
	darwinTags = append(darwinTags, "with_dhcp", "grpcnotrace")
	// memcTags = append(memcTags, "with_tailscale")
	sharedTags = append(sharedTags, "with_tailscale", "ts_omit_logtail", "ts_omit_ssh", "ts_omit_drive", "ts_omit_taildrop", "ts_omit_webclient", "ts_omit_doctor", "ts_omit_capture", "ts_omit_kube", "ts_omit_aws", "ts_omit_synology", "ts_omit_bird")
	notMemcTags = append(notMemcTags, "with_low_memory")
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
		"-tags-not-macos=with_low_memory",
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

	tags := append(sharedTags, darwinTags...)
	//if withTailscale {
	//	tags = append(tags, memcTags...)
	//}
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	// Apply an optional profile. With no -profile the tag set is exactly what it
	// was before profiles existed, so upstream behaviour is untouched.
	if profile != "" {
		selected, known := findAppleProfile(profile)
		if !known {
			var names []string
			for _, candidate := range appleProfiles {
				names = append(names, candidate.name)
			}
			log.Fatal("unknown -profile ", profile, "; known profiles: ", strings.Join(names, ", "))
		}
		tags = applyAppleProfile(tags, selected)
		log.Info("profile ", selected.name, ": tags ", strings.Join(tags, ","))
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

// applyAppleProfile returns tags with the profile's removals applied and its
// additions appended.
//
// A tag the profile asks to remove but which is not present is not an error: the
// default set is upstream's and may change, and a silent no-op is safer than a
// build failure over a tag that was never there.
//
// It is idempotent: applying the same profile twice yields the same set, so a
// tag is never duplicated if this is ever called on its own output.
func applyAppleProfile(tags []string, selected appleProfile) []string {
	removed := make(map[string]bool, len(selected.removeTags))
	for _, tag := range selected.removeTags {
		removed[tag] = true
	}
	filtered := make([]string, 0, len(tags)+len(selected.addTags))
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if removed[tag] {
			continue
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		filtered = append(filtered, tag)
	}
	for _, tag := range selected.addTags {
		if seen[tag] {
			continue
		}
		seen[tag] = true
		filtered = append(filtered, tag)
	}
	return filtered
}
