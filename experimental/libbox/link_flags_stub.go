//go:build !unix && !windows

package libbox

import (
	"net"
)

// linkFlags is unimplemented here.
//
// Only the platforms this package builds for are excluded from the stub: unix takes its IFF_* bits
// from syscall (link_flags_unix.go) and windows takes its own from syscall (link_flags_windows.go).
// Anywhere else the raw flag word has no convention this package knows, so reaching this is a
// programming error and says so loudly.
func linkFlags(rawFlags uint32) net.Flags {
	panic("stub!")
}
