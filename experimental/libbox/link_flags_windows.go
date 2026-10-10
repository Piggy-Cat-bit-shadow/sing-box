//go:build windows

package libbox

import (
	"net"
	"syscall"
)

// linkFlags is the counterpart of link_flags_unix.go for windows.
//
// # Why windows is not the stub
//
// Upstream stubs linkFlags on every non-unix platform, on the grounds that libbox is bound only for
// Android and Apple platforms and reaching it elsewhere is a programming error. That reasoning does
// not hold in this tree. libbox is compiled here for windows, it is linted for windows (the
// GOOS=windows nolint in service.go), seven of its eight test files run on windows, and
// platformInterfaceWrapper.NetworkInterfaces calls linkFlags unconditionally for every interface it
// lists. The stub therefore is not an unreachable guard on this platform: it is a reachable process
// abort inside a VPN library, reached by a test that was added here.
//
// The mapping itself has nothing platform-specific left in it, so there is nothing to stub: it is a
// pure function of the raw flag word, and the only platform dependency was always where the IFF_*
// bits come from. This file takes them from syscall, exactly as the unix file does, so both builds
// read their own platform's constants rather than a copied table.
//
// # The values differ between platforms, and that is correct
//
// The Windows IFF_* convention is not the BSD one: IFF_LOOPBACK is 4 rather than 8,
// IFF_POINTTOPOINT is 8 rather than 0x10, IFF_MULTICAST is 16 rather than 0x1000. The raw word this
// function maps is produced by the embedding platform adapter, so what matters is that the bits are
// read with the same convention the producer wrote them in - which is what using syscall here
// guarantees.
//
// IFF_RUNNING has no counterpart in the Windows syscall package, so net.FlagRunning cannot be
// derived from the flag word on this platform and is not set. Windows reports link state through
// IfOperStatus in the adapter addresses rather than through this word, and inventing the bit from
// another field would be a mapping this function's input does not carry.
func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}
