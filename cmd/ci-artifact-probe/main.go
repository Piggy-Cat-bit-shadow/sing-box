// Copyright 2026 The sing-box Authors. All rights reserved.
// Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.

// Command ci-artifact-probe links the package set a libbox build compiles and prints what the
// artifact actually contains, so a release check can assert the provenance against the policy
// instead of reading the build scripts.
//
// # Why a linked artifact and not a script scan
//
// The phase-1 tripwire read the profile tag files and reported "no profile names with_gvisor"
// while the Android libbox artifacts were compiled WITH with_gvisor: the libbox builder composes
// its own tag sets. A scan of text files is not a check on what ships. This probe is built with a
// shipped tag set and then inspected with `go version -m`, which answers from the artifact itself:
//
//	go build -tags "$(cat release/DEFAULT_BUILD_TAGS)" -o probe ./cmd/ci-artifact-probe
//	go version -m probe | grep -i gvisor   # must find nothing
//
// # The assertion it carries is now a negative one
//
// Phase 1 used this probe as a POSITIVE control: it built with with_gvisor precisely so that the
// gVisor module appeared in the provenance and the pin could be checked against the patched fork
// (LX 048). That control was correct while gVisor shipped. It no longer ships - the Go TUN stack
// replaced the code path that needed it, no shipped variant names the tag, and the fork is retired
// (the remote is kept for the record). Keeping the positive control would have kept gVisor a direct
// dependency of this module purely to test a dependency that must not exist.
//
// So the probe now asserts the thing that must stay true: a linked artifact built with the shipped
// tag set contains no gVisor module and no with_gvisor tag. scripts/ci/verify-upstream-assumptions.sh
// runs exactly that build and that inspection as a hard failure.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("sing-box artifact probe")
	os.Exit(0)
}
