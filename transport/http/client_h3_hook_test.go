//go:build with_quic

package http

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/quic-go"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/stretchr/testify/require"
)

// Tests for the HTTP3ConnDialer seam.
//
// The seam exists so the MASQUE client can race bootstrap candidates at QUIC handshake
// completion. The property that matters for every OTHER caller is that it changes
// nothing: with the hook unset, this package must dial exactly as it did before.

// hookRecordingDialer records that the plain path was taken.
type hookRecordingDialer struct {
	dials int
}

func (d *hookRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials++
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *hookRecordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, N.ErrUnknownNetwork
}

// TestHTTP3HookUnsetUsesTheExistingDialPath proves that with no hook, acquire() dials
// through the client's own dialer -- i.e. the pre-existing code path, not the seam.
func TestHTTP3HookUnsetUsesTheExistingDialPath(t *testing.T) {
	t.Parallel()

	dialer := &hookRecordingDialer{}
	impl := &http3ClientImpl{
		dialer:    dialer,
		server:    M.ParseSocksaddr("127.0.0.1:443"),
		tlsConfig: hookTestTLSConfig(t),
		// The transport is what NewClientConn wraps; the dial fails long before it is
		// reached, so a nil one is never dereferenced here.
		transport: nil,
	}
	// No connDialer. The call must reach the dialer rather than a hook.
	require.Nil(t, impl.connDialer, "the hook must be nil unless a caller sets it")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := impl.acquire(ctx)
	// The handshake cannot complete against a socket nobody is listening on, so this is
	// expected to fail. What is asserted is that it got as far as dialing.
	require.Error(t, err)
	require.Equal(t, 1, dialer.dials,
		"with no hook, acquire must dial through the client's own dialer")
}

// TestHTTP3HookIsUsedWhenSet proves the seam is actually reachable, so the test above
// cannot pass because the field is never read.
func TestHTTP3HookIsUsedWhenSet(t *testing.T) {
	t.Parallel()

	dialer := &hookRecordingDialer{}
	var hookCalled bool
	var receivedServer M.Socksaddr
	impl := &http3ClientImpl{
		dialer: dialer,
		server: M.ParseSocksaddr("127.0.0.1:443"),
		connDialer: func(ctx context.Context, hookDialer N.Dialer, server M.Socksaddr, tlsConfig aTLS.Config, quicConfig *quic.Config) (net.Conn, *quic.Conn, error) {
			hookCalled = true
			receivedServer = server
			// Deliberately does NOT dial: the hook owns that.
			return nil, nil, context.DeadlineExceeded
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := impl.acquire(ctx)
	require.Error(t, err)

	require.True(t, hookCalled, "a set hook must be invoked")
	require.Equal(t, "127.0.0.1", receivedServer.Addr.String(),
		"the hook must receive the server the client was configured with")
	require.Equal(t, 0, dialer.dials,
		"when the hook is set, the client must NOT dial directly; the hook owns dialing")
}

// hookTestTLSConfig builds a real aTLS client config.
//
// qtls.DialEarly dereferences the config before any handshake begins, so a nil one
// panics rather than failing the dial.
func hookTestTLSConfig(t *testing.T) aTLS.Config {
	t.Helper()
	config, err := tls.NewSTDClient(t.Context(), logger.NOP(), "localhost",
		option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Insecure: true})
	require.NoError(t, err)
	return config
}
