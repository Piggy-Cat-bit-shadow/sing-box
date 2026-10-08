package wireguard

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

// familyTolerantListenerControl keeps one address family's bind failure from killing the other.
//
// # The failure it prevents
//
// The standard bind opens a udp4 socket and a udp6 socket on the same port. On a machine whose
// default interface is outside the IPv6 stack - the common "IP version 6" unticked on the
// adapter, where IPV6_UNICAST_IF answers WSAEINVAL - the udp6 socket's control hook fails.
// wireguard-go treats only EAFNOSUPPORT as "this family is unavailable" and closes the healthy
// udp4 socket for anything else, leaving the device with NO sockets at all: every WireGuard
// endpoint is dead from startup with "address family not supported by protocol", and the
// handshake-rebind recovery cannot help because there is nothing to rebind.
//
// The udp6 wildcard is the socket that can be given up on. If its control hook fails, the family
// is not usable through the interface the operator asked to bind to, which is exactly what
// EAFNOSUPPORT says, so reporting it that way lets the bind keep the working udp4 socket. A
// failure on any other socket stays fatal: there is no second socket to fall back to, and
// swallowing it would hide a real configuration error.
//
// The socket is never created when the control fails, so this degrades to "no v6 socket" rather
// than "an unbound v6 socket"; an unbound socket would defeat the interface binding and could
// send v6 traffic out of the wrong path.
func familyTolerantListenerControl(listenerControl control.Func) control.Func {
	if listenerControl == nil {
		return nil
	}
	return func(network, address string, rawConn syscall.RawConn) error {
		err := listenerControl(network, address, rawConn)
		if err == nil {
			return nil
		}
		if network != "udp6" {
			return err
		}
		socksaddr := M.ParseSocksaddr(address)
		if socksaddr.Addr.IsValid() && !socksaddr.Addr.IsUnspecified() {
			return err
		}
		return syscall.EAFNOSUPPORT
	}
}
