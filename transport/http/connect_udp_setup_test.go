package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// CONNECT-UDP target setup: the response is withheld until the target is ready, and
// datagrams that arrive during setup are buffered within a bound.
//
// # The behaviour being replaced
//
// The handler used to send "200 OK" and flush BEFORE the router dialled the target. A
// DNS or dial failure therefore surfaced after the client had been told the tunnel was
// up, leaving it with a silent dead tunnel that it could not distinguish from a quiet
// target. These tests pin the corrected order and the two failure mappings.

// TestDeferredSuccessWithholdsDeliveryUntilReady proves a datagram is not delivered on
// the strength of a response that has not been sent.
func TestDeferredSuccessWithholdsDeliveryUntilReady(t *testing.T) {
	stream := &datagramFeedingStream{datagrams: [][]byte{{0x00, 'a'}, {0x00, 'b'}}}

	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	conn.deferUntilTargetReady()
	defer conn.Close()

	// Nothing may be delivered while the target is unconfirmed, even though the
	// datagrams have already arrived.
	select {
	case packet := <-conn.packets:
		packet.Release()
		t.Fatal("a datagram was delivered before the target was confirmed; the client " +
			"would be receiving tunnel traffic on the strength of a 200 that has not " +
			"been sent yet")
	case <-time.After(300 * time.Millisecond):
	}

	// Confirming the target releases exactly the buffered datagrams, in order.
	require.NoError(t, conn.PacketConnHandshakeSuccess(nil))

	first := awaitQueuedPacket(t, conn)
	require.Equal(t, []byte("a"), first.Bytes(),
		"buffered datagrams must be released in ARRIVAL order")
	first.Release()

	second := awaitQueuedPacket(t, conn)
	require.Equal(t, []byte("b"), second.Bytes())
	second.Release()
}

// TestDeferredSuccessReportsSetupFailure proves the outcome reaches the handler.
func TestDeferredSuccessReportsSetupFailure(t *testing.T) {
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	conn.deferUntilTargetReady()
	defer conn.Close()

	setupErr := errors.New("dial tcp 192.0.2.1:443: connection refused")
	require.NoError(t, conn.HandshakeFailure(setupErr))

	err := conn.AwaitReady(context.Background())
	require.Error(t, err, "the handler must learn that setup failed so it can return an "+
		"HTTP error instead of a 200")
	require.ErrorContains(t, err, "connection refused")
}

// TestDeferredSuccessReportsReady proves the success path settles too, so a handler is
// never left waiting.
func TestDeferredSuccessReportsReady(t *testing.T) {
	conn := newHTTP3PacketConnForTest(t)

	done := make(chan error, 1)
	go func() { done <- conn.AwaitReady(context.Background()) }()

	require.NoError(t, conn.PacketConnHandshakeSuccess(nil))
	select {
	case err := <-done:
		require.NoError(t, err, "a confirmed target must release the handler")
	case <-time.After(5 * time.Second):
		t.Fatal("AwaitReady did not return after the target was confirmed; the handler " +
			"would hang and never send a response")
	}
}

// TestDeferredSuccessIsIdempotent proves a second report cannot panic or flip the
// result.
//
// The router reports success and may still report a failure while tearing down, so
// double-settling is a realistic sequence and must be harmless: closing a channel twice
// panics, and flipping the outcome would make the handler's decision depend on teardown
// ordering.
func TestDeferredSuccessIsIdempotent(t *testing.T) {
	conn := newHTTP3PacketConnForTest(t)
	require.NoError(t, conn.PacketConnHandshakeSuccess(nil))

	// Must not panic, and must not change the outcome.
	require.NotPanics(t, func() {
		_ = conn.HandshakeFailure(errors.New("late teardown failure"))
		_ = conn.PacketConnHandshakeSuccess(nil)
	})
	require.NoError(t, conn.AwaitReady(context.Background()),
		"the first reported outcome must stand; a late teardown report must not flip a "+
			"confirmed tunnel into a failure")
}

// TestEarlyDatagramQueueIsBoundedByCount proves the packet bound.
//
// A client may send immediately after its request, so early datagrams must be kept - but
// the bound is what stops a flooding client from spending server memory while the target
// is still being dialled.
func TestEarlyDatagramQueueIsBoundedByCount(t *testing.T) {
	conn := newHTTP3PacketConnForTest(t)
	defer conn.Close()

	accepted := 0
	for range maxEarlyDatagramPackets * 4 {
		if conn.bufferEarlyDatagram(buf.As([]byte("x"))) {
			accepted++
		}
	}
	require.Equal(t, maxEarlyDatagramPackets, accepted,
		"the early queue must stop accepting at the packet bound; unbounded buffering "+
			"during setup is a memory-amplification primitive")
}

// TestEarlyDatagramQueueIsBoundedByBytes proves the byte bound applies independently.
//
// The two bounds exist because neither alone is sufficient: a small count of maximum-size
// datagrams can exceed the byte budget, and a large count of empty datagrams can exceed
// the packet budget without spending any bytes.
func TestEarlyDatagramQueueIsBoundedByBytes(t *testing.T) {
	conn := newHTTP3PacketConnForTest(t)
	defer conn.Close()

	const chunk = 16 << 10
	accepted := 0
	for range 64 {
		if conn.bufferEarlyDatagram(buf.As(make([]byte, chunk))) {
			accepted++
		}
	}
	require.LessOrEqual(t, accepted*chunk, maxEarlyDatagramBytes,
		"the early queue must stop at the byte bound even when the packet count is "+
			"still below its own limit")

	// And a further datagram must be refused once the byte budget is spent.
	require.False(t, conn.bufferEarlyDatagram(buf.As(make([]byte, chunk))),
		"a datagram that would exceed the byte bound must be refused")
}

// TestEarlyDatagramsBufferedWithNoCountPenalty proves empty datagrams are still counted
// against the packet bound, so a client cannot bypass it by sending zero-length ones.
func TestEarlyDatagramBytesBoundCoversZeroLength(t *testing.T) {
	conn := newHTTP3PacketConnForTest(t)
	defer conn.Close()

	accepted := 0
	for range maxEarlyDatagramPackets * 4 {
		if conn.bufferEarlyDatagram(buf.As(nil)) {
			accepted++
		}
	}
	require.Equal(t, maxEarlyDatagramPackets, accepted,
		"zero-length datagrams spend no bytes, so only the PACKET bound stops them; "+
			"without it a client could queue unbounded buffers for free")
}

// TestSetupFailureMapsToHTTPStatus pins the failure mapping.
func TestSetupFailureMapsToHTTPStatus(t *testing.T) {
	cases := []struct {
		name            string
		err             error
		wantStatus      int
		wantProxyStatus string
	}{
		{
			name:       "deadline maps to 504",
			err:        context.DeadlineExceeded,
			wantStatus: 504,
		},
		{
			name:       "timeout maps to 504",
			err:        &net.OpError{Op: "dial", Err: timeoutError{}},
			wantStatus: 504,
		},
		{
			name:            "dns failure maps to 502 with the standard token",
			err:             &net.DNSError{Err: "no such host", Name: "example.invalid"},
			wantStatus:      502,
			wantProxyStatus: "sing-box; error=dns_error",
		},
		{
			name:       "a generic dial failure maps to 502 with no token",
			err:        errors.New("dial tcp: connection refused"),
			wantStatus: 502,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := newStatusRecorder()
			rejectConnectUDPSetup(recorder, testCase.err)
			require.Equal(t, testCase.wantStatus, recorder.status)
			require.Equal(t, testCase.wantProxyStatus, recorder.header.Get("Proxy-Status"),
				"Proxy-Status must appear ONLY where an RFC 9209 token matches the "+
					"meaning exactly; an approximate token tells the client something "+
					"specific and wrong")
		})
	}
}

// TestSetupFailureDoesNotLeakInternals proves the response carries no detail about the
// target or the server's internals.
func TestSetupFailureDoesNotLeakInternals(t *testing.T) {
	recorder := newStatusRecorder()
	rejectConnectUDPSetup(recorder, errors.New(
		"dial tcp 10.1.2.3:443: connect: connection refused (resolver 127.0.0.1:53)"))

	require.Empty(t, recorder.body,
		"the failure response must carry no body; echoing the cause would leak the "+
			"target address and the upstream resolver to the client")
	require.NotContains(t, recorder.header.Get("Proxy-Status"), "10.1.2.3")
	require.NotContains(t, recorder.header.Get("Proxy-Status"), "127.0.0.1")
}

// newHTTP3PacketConnForTest builds a connection with deferred success enabled.
func newHTTP3PacketConnForTest(t *testing.T) *http3PacketConn {
	t.Helper()
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	conn.deferUntilTargetReady()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// timeoutError reports itself as a timeout, for the mapping test.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// statusRecorder is a minimal ResponseWriter that records the status and headers.
type statusRecorder struct {
	header http.Header
	status int
	body   []byte
}

func newStatusRecorder() *statusRecorder {
	return &statusRecorder{header: make(http.Header)}
}

func (r *statusRecorder) Header() http.Header { return r.header }

func (r *statusRecorder) WriteHeader(status int) { r.status = status }

func (r *statusRecorder) Write(p []byte) (int, error) {
	r.body = append(r.body, p...)
	return len(p), nil
}
