//go:build !windows

package tun

import (
	"errors"
	"syscall"
)

// isConnectionRefused reports whether an error is the operating system refusing a connection.
//
// On every POSIX platform Go's syscall.ECONNREFUSED IS the errno the kernel reports, so the ordinary
// comparison is the correct one and there is nothing to translate. See the Windows twin for the
// platform where that is not true, and why.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isConnectionReset reports whether an error is the peer having reset the connection.
//
// On POSIX, syscall.ECONNRESET is the errno the kernel reports. See the Windows twin.
func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
