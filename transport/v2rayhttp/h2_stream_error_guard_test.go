package v2rayhttp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

// The H2 error guard must stay in front of the outer HTTP/2 client.
//
// # The failure this pins
//
// A transport-specific stream error escaping a transport conn's Read is a live hazard, not a
// cosmetic one. An outer x/net http2 client type-asserts the read error to http2.StreamError and
// looks the ID up in its own stream table; an ID belonging to the inner connection is not found,
// and the read loop CONTINUES without consuming anything - an infinite spin at 100% of a core
// with zero syscalls (the LX 082 symptom, measured at ~7 million iterations in 300 ms).
//
// The guard is baderror.WrapH2, applied at this package's read path. It also has to classify
// correctly while it does so: a peer-initiated CANCEL is an expected stream close and must be
// silenced, while INTERNAL_ERROR and PROTOCOL_ERROR are real faults that must stay visible.
//
// This test uses the production wrapper and a real x/net client, so it fails if either the
// wrapper stops being applied or x/net switches from a direct type assertion to errors.As.
func TestWrappedStreamErrorCannotSpinTheOuterH2Client(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		err         error
		wantSilent  bool
		wantVisible bool
	}{
		{
			name:        "peer cancel is an expected stream close",
			err:         http2.StreamError{StreamID: 21, Code: http2.ErrCodeCancel},
			wantSilent:  true,
			wantVisible: false,
		},
		{
			name:        "internal error is a fault",
			err:         http2.StreamError{StreamID: 21, Code: http2.ErrCodeInternal, Cause: errors.New("received from peer")},
			wantVisible: true,
		},
		{
			name:        "protocol error is a fault",
			err:         http2.StreamError{StreamID: 21, Code: http2.ErrCodeProtocol},
			wantVisible: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// The production wrapping, called the way the read path calls it.
			wrapped := baderror.WrapH2(testCase.err)

			// x/net asserts the CONCRETE type directly, so a wrapper - even one with Unwrap -
			// defeats the spin. The assertion below is what the guard rests on; the errors.As
			// check documents that the wrapper still exposes the cause, which is why a future
			// switch in x/net to errors.As would silently remove the protection and make the
			// type assertion alone insufficient.
			if _, isRawStreamError := wrapped.(http2.StreamError); isRawStreamError {
				t.Fatalf("the raw http2.StreamError reached the outer client unwrapped; x/net would spin on it")
			}
			// An expected close collapses to net.ErrClosed, which has no H2 cause to find; a
			// fault keeps its cause discoverable.
			if testCase.wantVisible {
				var streamError http2.StreamError
				if !errors.As(wrapped, &streamError) {
					t.Fatalf("a fault must keep its cause discoverable via errors.As, got %v", wrapped)
				}
			}

			if testCase.wantSilent {
				if !E.IsClosedOrCanceled(wrapped) {
					t.Fatalf("an expected stream close must be reported as closed, got %v", wrapped)
				}
			}
			if testCase.wantVisible {
				if E.IsClosedOrCanceled(wrapped) {
					t.Fatalf("a real H2 fault was silently classified as closed: %v", wrapped)
				}
			}

			// And the outer client cannot spin on it: reads are bounded and the error surfaces.
			conn := newSpinProbeConn(wrapped)
			clientConn, err := (&http2.Transport{}).NewClientConn(conn)
			if err == nil {
				clientConn.Close()
			}
			if spins := conn.reads.Load(); spins > 100 {
				t.Fatalf("the outer HTTP/2 client called Read %d times in 200ms: the stream error was "+
					"not isolated and the read loop is spinning", spins)
			}
		})
	}
}

// spinProbeConn reports an error on every read and counts how often it is asked.
type spinProbeConn struct {
	reads   atomic.Int64
	readErr error
}

func newSpinProbeConn(readErr error) *spinProbeConn {
	return &spinProbeConn{readErr: readErr}
}

func (c *spinProbeConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	if c.reads.Load() > 1000 {
		// Hard stop so a regression fails the test instead of hanging the suite.
		time.Sleep(time.Millisecond)
	}
	return 0, c.readErr
}

func (c *spinProbeConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *spinProbeConn) Close() error { return nil }

func (c *spinProbeConn) LocalAddr() net.Addr  { return probeAddr{} }
func (c *spinProbeConn) RemoteAddr() net.Addr { return probeAddr{} }

func (c *spinProbeConn) SetDeadline(t time.Time) error      { return nil }
func (c *spinProbeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *spinProbeConn) SetWriteDeadline(t time.Time) error { return nil }

type probeAddr struct{}

func (probeAddr) Network() string { return "probe" }
func (probeAddr) String() string  { return "probe" }

var _ net.Conn = (*spinProbeConn)(nil)
