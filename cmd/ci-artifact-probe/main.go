// Copyright 2026 The sing-box Authors. All rights reserved.
// Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.

// Command ci-artifact-probe links the package set a libbox build compiles and prints what the
// artifact actually contains, so a release check can assert the provenance against the policy
// instead of reading the build scripts.
//
// # Why a linked artifact and not a script scan
//
// The phase-1 tripwire read the profile tag files and reported "no profile names with_gvisor"
// while the Android libbox artifacts were compiled WITH with_gvisor: the libbox builder appends
// its own tags. A scan of text files is not a check on what ships. This probe is built with a tag
// set and then inspected with `go version -m`, which answers from the artifact itself:
//
//	go build -tags "$(cat release/DEFAULT_BUILD_TAGS),with_gvisor" \
//	    -buildmode=c-archive -o probe.a ./cmd/ci-artifact-probe
//	go version -m probe.a | grep gvisor
//
// With the tag, probe_gvisor.go is compiled and the gVisor module appears in the provenance.
// Without it, that file is excluded and gVisor does not appear at all, which is what makes the
// provenance a statement about the tag set rather than about the module graph.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("sing-box artifact probe")
	os.Exit(0)
}
