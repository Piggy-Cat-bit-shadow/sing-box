package wireguard

import (
	"errors"
	"syscall"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/stretchr/testify/require"
)

// A failure to bind the IPv6 wildcard must not take the IPv4 socket down with it.
//
// # The failure this pins
//
// The standard bind opens udp4 and udp6 on the same port. On a machine whose default interface is
// outside the IPv6 stack - the usual "IP version 6" unticked on the adapter, where IPV6_UNICAST_IF
// answers WSAEINVAL - the udp6 control hook fails. wireguard-go only reads EAFNOSUPPORT as "this
// family is unavailable" and closes the healthy udp4 socket for any other error, leaving the
// device with no sockets at all: every WireGuard endpoint is dead from startup, and the
// handshake-rebind recovery has nothing to rebind.
//
// The wrapper translates a failure on the udp6 WILDCARD into EAFNOSUPPORT so the bind keeps the
// working v4 socket. The socket is never created, so this is a clean degrade to IPv4-only rather
// than an unbound v6 socket that could escape the interface the operator chose.
func TestIPv6WildcardBindFailureKeepsIPv4Socket(t *testing.T) {
	var udp6Attempts int
	control := familyTolerantListenerControl(func(network, address string, rawConn syscall.RawConn) error {
		if network == "udp6" {
			udp6Attempts++
			// WSAEINVAL's closest syscall spelling; the point is that it is NOT EAFNOSUPPORT.
			return syscall.EINVAL
		}
		return nil
	})

	bind, isStdNetBind := conn.NewStdNetBind(control).(*conn.StdNetBind)
	require.True(t, isStdNetBind)

	receiveFuncs, _, err := bind.Open(0)
	require.NoError(t, err, "a failing IPv6 wildcard must not fail the whole bind")
	require.NotEmpty(t, receiveFuncs, "the surviving IPv4 socket must still provide a receive function")
	require.Greater(t, udp6Attempts, 0, "the control hook must actually have run for udp6")
	require.NoError(t, bind.Close())
}

// A control failure on anything other than the v6 wildcard stays fatal: there is no other socket
// to fall back to, and swallowing it would hide a real error.
func TestOtherBindFailuresStayFatal(t *testing.T) {
	testCases := []struct {
		name    string
		network string
		address string
	}{
		{name: "ipv4 wildcard", network: "udp4", address: "0.0.0.0:0"},
		{name: "ipv6 is non-wildcard", network: "udp6", address: "[2001:db8::1]:0"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			control := familyTolerantListenerControl(func(network, address string, rawConn syscall.RawConn) error {
				return syscall.EINVAL
			})
			err := control(testCase.network, testCase.address, nil)
			require.ErrorIs(t, err, syscall.EINVAL,
				"only the udp6 wildcard may be degraded; %s must keep failing", testCase.network)
		})
	}
}

// A nil control stays nil, so the bind falls back to its own default behaviour rather than an
// always-succeeding stub.
func TestNilControlStaysNil(t *testing.T) {
	require.Nil(t, familyTolerantListenerControl(nil))
}

// The wrapper must not change an address or network it accepts.
func TestControlPassesSuccessThrough(t *testing.T) {
	called := false
	control := familyTolerantListenerControl(func(network, address string, rawConn syscall.RawConn) error {
		called = true
		return nil
	})
	require.NoError(t, control("udp4", "0.0.0.0:0", nil))
	require.True(t, called)

	// And a v6 wildcard that the underlying control accepts is still accepted.
	require.NoError(t, control("udp6", "[::]:0", nil))
	require.False(t, M.ParseSocksaddr("[::]:0").Addr.Is4())
}

// A non-EAFNOSUPPORT error on the v4 wildcard must not be silently converted either.
func TestIPv4FailureIsNotConverted(t *testing.T) {
	sentinel := errors.New("socket option failed")
	control := familyTolerantListenerControl(func(network, address string, rawConn syscall.RawConn) error {
		return sentinel
	})
	require.ErrorIs(t, control("udp4", "0.0.0.0:0", nil), sentinel)
}
