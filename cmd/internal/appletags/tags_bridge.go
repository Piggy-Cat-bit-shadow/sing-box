package main

import (
	"github.com/sagernet/sing-box/cmd/internal/applebuildtags"
)

// The Apple tag lists are imported from cmd/internal/applebuildtags, not repeated here.
//
// This file previously held a byte-for-byte copy of the builder's lists and relied on a test
// that parsed the builder's source to keep them equal. Two copies kept in sync by a parser
// cannot catch a question asked wrongly in both places, which is exactly how the mixed-target
// macOS leak survived a green contract test. One imported definition cannot diverge at all.

// canonicalAppleTags returns the full tag set a single Apple platform ships.
func canonicalAppleTags(platform string) []string {
	return applebuildtags.FullDeploymentTags(platform)
}

// canonicalAppleTagString is canonicalAppleTags joined for -tags.
func canonicalAppleTagString(platform string) string {
	return applebuildtags.FullDeploymentTagString(platform)
}

// commonAppleTagString is the tag set gomobile receives via -tags for ANY Apple target.
func commonAppleTagString() string {
	return applebuildtags.CommonTagString()
}

// lowMemoryAppleTagString is the mobile-only set gomobile receives via -tags-not-macos.
func lowMemoryAppleTagString() string {
	return applebuildtags.LowMemoryTagString()
}
