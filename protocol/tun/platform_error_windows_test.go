//go:build windows

package tun

import (
	"errors"
	"syscall"
)

// Windows error numbers, named here because Go's syscall package does not define these two.
//
// # Why this cannot be `errors.Is(err, syscall.ECONNREFUSED)` on Windows
//
// Go's syscall package defines ECONNREFUSED on Windows as a SYNTHETIC value,
// `Errno(APPLICATION_ERROR + iota)` = 536870934, which is a marker Go uses internally rather than an
// errno any Windows API returns. The real failure arrives as a raw `syscall.Errno` carrying one of the
// documented Windows codes below. MEASURED on this host, for a real refusal produced by a closed
// loopback port:
//
//	dial tcp 127.0.0.1:57037: connectex: No connection could be made because the target machine
//	actively refused it.
//	  layer *net.OpError
//	  layer *os.SyscallError
//	  layer syscall.Errno   <- 1225 (ERROR_CONNECTION_REFUSED), NOT 536870934
//
// and for a real mid-connection RST produced by SO_LINGER 0:
//
//	read tcp ...: wsarecv: An existing connection was forcibly closed by the remote host.
//	  layer syscall.Errno   <- 10054 (WSAECONNRESET), NOT 536870934 + 54
//
// so the documented, portable-looking comparison silently returns false for a refusal or a reset that
// really happened. The assertions the tests make are unchanged - the kernel refused the connection,
// and the kernel reset it, both observed through real loopback sockets - only the identity of the
// error is platform-specific.
const (
	// errorConnectionRefused is ERROR_CONNECTION_REFUSED, what ConnectEx reports.
	errorConnectionRefused = 1225
	// wsaConnectionRefused is WSAECONNREFUSED, what the classic socket API reports.
	wsaConnectionRefused = 10061
	// wsaConnectionReset is WSAECONNRESET, the "existing connection was forcibly closed" error.
	wsaConnectionReset = 10054
)

// isConnectionRefused reports whether an error is the operating system refusing a connection.
//
// The accepted set is exactly the codes for that one condition, so a connection that failed for a
// different reason - a timeout, an unreachable network, a permission error - still fails the
// assertion.
func isConnectionRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	if errno, isErrno := errnoOf(err); isErrno {
		return errno == errorConnectionRefused || errno == wsaConnectionRefused
	}
	return false
}

// isConnectionReset reports whether an error is the peer having reset the connection.
func isConnectionReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	if errno, isErrno := errnoOf(err); isErrno {
		return errno == wsaConnectionReset
	}
	return false
}

// errnoOf digs the underlying syscall.Errno out of a wrapped network error.
//
// errors.Is cannot be used for these comparisons, and that is the point: Go's synthetic
// ECONNREFUSED/ECONNRESET values on Windows do not equal the errno the API returned, so the numeric
// value has to be read directly rather than compared through the error chain.
func errnoOf(err error) (uintptr, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	return uintptr(errno), true
}
