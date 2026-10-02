// Command appletags prints the canonical Apple build tag set.
//
// # Why a separate command
//
// The low-memory CI gate and the memory benchmark both need the tags the Apple client is
// actually built with. They previously read release/DEFAULT_BUILD_TAGS_OTHERS, which is the
// NON-Windows desktop client set and does not match what libbox builds - so those checks
// were testing a configuration no Apple binary ships.
//
// Printing from the same Go source the builder uses means there is one definition, and a
// consumer that cannot read it FAILS rather than falling back to a guess.
//
// Usage:
//
//	appletags -low-memory=true    iOS/tvOS tag set (with_low_memory)
//	appletags -low-memory=false   macOS tag set
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
)

func main() {
	platform := flag.String("platform", "ios", "Apple platform: ios, iossimulator, tvos, tvossimulator, macos")
	lowMemory := flag.Bool("low-memory", true, "deprecated shorthand: true selects ios, false selects macos")
	oneLine := flag.Bool("oneline", true, "emit comma-separated tags on one line")
	common := flag.Bool("common", false, "emit the COMMON tag set gomobile receives via -tags for any Apple target")
	mobileOnly := flag.Bool("mobile-only", false, "emit the mobile-only set gomobile receives via -tags-not-macos")
	flag.Parse()

	// -low-memory=true/false is retained so existing gates keep working, but it is a
	// two-platform shorthand for what is really a per-platform question. Selecting a platform
	// is the honest interface, and it is what makes the mixed-target case expressible.
	selected := *platform
	if flagPassed("low-memory") && selected == "ios" {
		if *lowMemory {
			selected = "ios"
		} else {
			selected = "macos"
		}
	}

	if *common {
		// The set shared by every Apple target. It must never contain the mobile-only tag:
		// -tags applies to all targets, so a mobile-only tag here would reach macOS.
		tags := applebuildtags.CommonTags()
		if len(tags) == 0 {
			fmt.Fprintln(os.Stderr, "appletags: the common Apple tag set is empty; refusing to emit")
			os.Exit(1)
		}
		emit(tags, *oneLine)
		return
	}
	if *mobileOnly {
		tags := applebuildtags.LowMemoryMobileTags()
		if len(tags) == 0 {
			fmt.Fprintln(os.Stderr, "appletags: the mobile-only tag set is empty; refusing to emit")
			os.Exit(1)
		}
		emit(tags, *oneLine)
		return
	}

	// One platform's full set: canonical tags plus its geometry, if it has any.
	if !knownPlatform(selected) {
		fmt.Fprintf(os.Stderr, "appletags: unknown platform %q; refusing to guess its memory geometry\n", selected)
		os.Exit(1)
	}
	tags := canonicalAppleTags(selected)
	if len(tags) == 0 {
		fmt.Fprintln(os.Stderr, "appletags: the canonical Apple tag set is empty; refusing to emit")
		os.Exit(1)
	}
	if applebuildtags.PlatformShipsLowMemory(selected) && !containsTag(tags, applebuildtags.LowMemoryTag) {
		fmt.Fprintln(os.Stderr, "appletags: this platform ships low-memory geometry but the tag is missing")
		os.Exit(1)
	}
	if !applebuildtags.PlatformShipsLowMemory(selected) && containsTag(tags, applebuildtags.LowMemoryTag) {
		fmt.Fprintln(os.Stderr, "appletags: this platform must not contain with_low_memory")
		os.Exit(1)
	}
	emit(tags, *oneLine)
}

func emit(tags []string, oneLine bool) {
	if oneLine {
		fmt.Println(strings.Join(tags, ","))
		return
	}
	for _, tag := range tags {
		fmt.Println(tag)
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func knownPlatform(platform string) bool {
	for _, known := range applebuildtags.ApplePlatforms() {
		if known.Name == platform {
			return true
		}
	}
	return false
}

// flagPassed reports whether a flag was set on the command line, so the deprecated shorthand
// does not override an explicit -platform.
func flagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
