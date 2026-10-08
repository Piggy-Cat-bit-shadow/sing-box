package vless

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// wrapEncryption bounds the post-quantum handshake with the dial deadline,
// because Handshake works on a bare net.Conn and would otherwise block forever
// on a half-alive node. It must arm the WRITE side only.
//
// Why that matters: on an XHTTP conn the deadlines are one-shot. An expired read
// deadline closes the late-bound download body and clearing it cannot reopen
// it, so arming both directions (what SetDeadline does) hands the caller a conn
// whose download side is already dead whenever the handshake overruns the
// deadline but still succeeds — a connection that looks healthy and fails on
// its first read.

// deadlineRecordingConn records which deadline setters were called.
type deadlineRecordingConn struct {
	net.Conn
	bothCalled  bool
	writeCalled bool
	readCalled  bool
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.bothCalled = true
	return nil
}

func (c *deadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	c.writeCalled = true
	return nil
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.readCalled = true
	return nil
}

func (c *deadlineRecordingConn) Read(b []byte) (int, error)  { return 0, errors.New("handshake stub") }
func (c *deadlineRecordingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *deadlineRecordingConn) Close() error                { return nil }
func (c *deadlineRecordingConn) LocalAddr() net.Addr         { return M.Socksaddr{} }
func (c *deadlineRecordingConn) RemoteAddr() net.Addr        { return M.Socksaddr{} }

// The dial deadline is applied to the write direction and never to the read
// direction.
func TestWrapEncryptionArmsWriteDeadlineOnly(t *testing.T) {
	testDeadline(t, 10*time.Second)

	dialer := &vlessDialer{
		// A non-nil instance is all wrapEncryption needs to take the guarded path;
		// the handshake itself fails on the stub conn, which is fine — the deadline
		// is armed before it runs.
		encryption: &encryption.ClientInstance{},
	}
	conn := &deadlineRecordingConn{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, _ = dialer.wrapEncryption(ctx, conn)

	require.False(t, conn.bothCalled,
		"wrapEncryption called SetDeadline: that arms the read side too, and an "+
			"expired XHTTP read deadline permanently closes the download body")
	require.False(t, conn.readCalled,
		"wrapEncryption armed the read deadline; the handshake read is guarded by closing the conn instead")
	require.True(t, conn.writeCalled,
		"wrapEncryption did not arm the write deadline: the handshake is unbounded again")
}

// A dial context with no deadline (ordinary proxied traffic) must leave the
// conn's deadlines alone.
func TestWrapEncryptionWithoutDeadlineTouchesNothing(t *testing.T) {
	testDeadline(t, 10*time.Second)

	dialer := &vlessDialer{encryption: &encryption.ClientInstance{}}
	conn := &deadlineRecordingConn{}

	_, _ = dialer.wrapEncryption(context.Background(), conn)

	require.False(t, conn.bothCalled || conn.writeCalled || conn.readCalled,
		"wrapEncryption armed a deadline although the dial context carries none")
}
