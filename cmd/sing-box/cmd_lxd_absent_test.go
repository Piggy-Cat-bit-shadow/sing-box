//go:build !with_lxd

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The mirror of cmd_lxd_registration_test.go: without `with_lxd` the command must be
// ABSENT, and the binary must still build.
//
// # Why the absence needs asserting
//
// `with_lxd` is what gates the daemon, so a build without it must not carry the
// command - but the package also has to compile, because `go build ./...` and the
// server profile run without the tag. The stub in lxd/stub.go exists for the second
// half; this asserts the first.
//
// A regression here would be quiet in the wrong direction: if the tag were dropped
// from cmd_lxd_lx.go, every non-LXD build would start linking the whole daemon, and
// the only symptom would be a larger binary.

// TestLxdCommandIsAbsentWithoutTheTag asserts the command was not registered.
func TestLxdCommandIsAbsentWithoutTheTag(t *testing.T) {
	for _, child := range mainCommand.Commands() {
		require.NotEqual(t, "lxd", child.Name(),
			"`lxd` must not be registered without the with_lxd build tag; the daemon "+
				"is gated on it, and cmd/sing-box/cmd_lxd_lx.go carries the constraint")
	}
}
