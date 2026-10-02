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
)

func main() {
	lowMemory := flag.Bool("low-memory", true, "emit the iOS/tvOS tag set including with_low_memory")
	oneLine := flag.Bool("oneline", true, "emit comma-separated tags on one line")
	flag.Parse()

	// Import the canonical definition rather than restating it.
	tags := canonicalAppleTags(*lowMemory)
	if len(tags) == 0 {
		fmt.Fprintln(os.Stderr, "appletags: the canonical Apple tag set is empty; refusing to emit")
		os.Exit(1)
	}
	if !*lowMemory {
		for _, tag := range tags {
			if tag == "with_low_memory" {
				fmt.Fprintln(os.Stderr, "appletags: the macOS set must not contain with_low_memory")
				os.Exit(1)
			}
		}
	} else {
		found := false
		for _, tag := range tags {
			if tag == "with_low_memory" {
				found = true
			}
		}
		if !found {
			fmt.Fprintln(os.Stderr, "appletags: the iOS/tvOS set must contain with_low_memory")
			os.Exit(1)
		}
	}

	if *oneLine {
		fmt.Println(strings.Join(tags, ","))
		return
	}
	for _, tag := range tags {
		fmt.Println(tag)
	}
}
