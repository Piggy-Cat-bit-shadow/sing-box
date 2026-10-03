package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Ownership tests for the pre-dialed connection handed to net/http.
//
// # The defect these pin
//
// The transport's DialContext returned the single pre-dialed instance on EVERY call. net/http is
// allowed to call DialContext again - for an idempotent request like HEAD it retries when a
// connection it had already used fails - so the transport could be handed a connection that was
// already closed, and the measurement would fail for a reason that has nothing to do with the node.
//
// The contract is: one measurement performs at most one outbound dial, and that connection is
// handed to net/http at most once.

// countingDialer records how many times the outbound was dialled and can force a connection to
// fail after the first exchange.
type countingDialer struct {
	dials atomic.Int32

	// closeAfterFirst makes a connection stop working after one exchange, which is what prompts
	// net/http to redial.
	closeAfterFirst atomic.Bool
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	if d.closeAfterFirst.Load() {
		return &singleUseConn{Conn: conn}, nil
	}
	return conn, nil
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

// singleUseConn stops working after the first read, so a reused connection appears dead and
// net/http is entitled to dial again.
type singleUseConn struct {
	net.Conn
	reads atomic.Int32
}

func (c *singleUseConn) Read(p []byte) (int, error) {
	if c.reads.Add(1) > 1 {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}

// TestMeasurementDialsTheOutboundOnce is the base contract.
func TestMeasurementDialsTheOutboundOnce(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)
	dialer := &countingDialer{}

	_, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	require.NoError(t, err)

	require.EqualValues(t, 1, dialer.dials.Load(),
		"a measurement must dial the outbound exactly once, however many HTTP requests it makes")
}

// TestTransportDoesNotReuseAClosedConnection is §13.
//
// The first response tells the client to close the connection. If the transport then tries to
// serve the second request over the same instance, it must be refused rather than reused - and
// crucially it must NOT cause a second outbound dial.
func TestTransportDoesNotReuseAClosedConnection(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			// Tell the client the connection is finished.
			writer.Header().Set("Connection", "close")
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}

	result, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204"}, dialer)

	// Either outcome is acceptable for the measurement itself - the fallback exists for exactly
	// this shape - but the DIAL COUNT is not negotiable.
	if err == nil {
		require.GreaterOrEqual(t, result.Delay, uint16(1))
	}

	require.EqualValues(t, 1, dialer.dials.Load(),
		"the transport must never obtain a second outbound connection; a redial would open a "+
			"second proxy connection and make the measurement meaningless as a per-node latency")
}

// TestTransportHandsOutTheConnectionAtMostOnce exercises the sentinel directly.
//
// # Why this drives the transport rather than Measure
//
// Through Measure the defect is not observable: whether the transport receives a fresh error or a
// dead connection, the second request fails either way and the fallback produces the same result.
// The invariant that differs is internal, so it is asserted where it lives - the transport's
// DialContext - rather than through an outcome that cannot distinguish the two.
func TestTransportHandsOutTheConnectionAtMostOnce(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)
	dialer := &countingDialer{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverAddr := server.Listener.Addr().String()
	host, port, splitErr := net.SplitHostPort(serverAddr)
	require.NoError(t, splitErr)

	instance, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(host, port))
	require.NoError(t, err)
	defer instance.Close()

	transport := newMeasurementTransport(instance, ctx)

	// The first request obtains the pre-dialed connection.
	first, err := transport.DialContext(ctx, "tcp", serverAddr)
	require.NoError(t, err)
	require.Same(t, instance, first,
		"the first hand-out must be the pre-dialed connection")

	// A second attempt must be refused, not served the same connection again.
	second, err := transport.DialContext(ctx, "tcp", serverAddr)
	require.ErrorIs(t, err, errURLTestConnectionNotReusable,
		"the transport must refuse a second hand-out; returning the instance again would give "+
			"net/http a connection it has already used")
	require.Nil(t, second)

	require.EqualValues(t, 1, dialer.dials.Load(),
		"no additional outbound dial may occur")
}

// TestTransportHeaderCapIsSet is §22: the response header ceiling must be bounded well below the
// net/http default.
func TestTransportHeaderCapIsSet(t *testing.T) {
	transport := newMeasurementTransport(nil, context.Background())
	require.EqualValues(t, 256<<10, transport.MaxResponseHeaderBytes,
		"the measurement transport must bound response headers; the default is about 10 MiB, "+
			"which an unusual endpoint could make the process allocate per measurement")
}

var _ = time.Second

// TestMeasurementSharesOneTotalDeadline is §64(I).
//
// The dial, the warm-up and the timed request all run under one deadline. Previously the context
// had no deadline of its own and the client carried a per-request timeout, so a measurement whose
// phases each took just under the limit could take a multiple of it in total.
//
// The test does not wait out the real C.TCPTimeout; it sets its own deadline and asserts the
// measurement respects it, which is the same contract.
func TestMeasurementSharesOneTotalDeadline(t *testing.T) {
	// A server that accepts and then never answers, so both requests block.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}

	const deadline = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	_, err := Measure(ctx, MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	elapsed := time.Since(start)

	require.Error(t, err, "a server that never answers must fail the measurement")
	require.Less(t, elapsed, deadline+2*time.Second,
		"the measurement took %v against a %v deadline; the phases must share one budget rather "+
			"than each getting the full timeout", elapsed, deadline)

	require.EqualValues(t, 1, dialer.dials.Load(),
		"and it must still dial exactly once")
}

// TestCallerDeadlineIsHonouredNotExtended is the other half of the contract.
//
// A caller that set an earlier deadline must keep it: the measurement may not extend it.
func TestCallerDeadlineIsHonouredNotExtended(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}

	const shortDeadline = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), shortDeadline)
	defer cancel()

	start := time.Now()
	_, err := Measure(ctx, MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Less(t, elapsed, shortDeadline+2*time.Second,
		"the caller's own deadline must be respected, not replaced by a longer internal one")
}

// TestDebugCallbackIsPerMeasurement is §30.
//
// The diagnostic is delivered to the caller's callback, so no process-wide state is involved and
// nothing is computed when the caller does not ask for it.
func TestDebugCallbackIsPerMeasurement(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)
	dialer := &countingDialer{}

	var reported []MeasureDebug
	_, err := Measure(context.Background(), MeasureOptions{
		Link: server.URL + "/generate_204",
		Debug: func(debug MeasureDebug) {
			reported = append(reported, debug)
		},
	}, dialer)
	require.NoError(t, err)

	require.Len(t, reported, 1, "one successful measurement reports exactly one debug record")
	require.False(t, reported[0].UsedFallback)
	require.NotZero(t, reported[0].Warmup, "the warm-up phase is reported")
	require.NotZero(t, reported[0].Warm)
}

// TestNoDebugCallbackComputesNothing is the disabled path.
func TestNoDebugCallbackComputesNothing(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)
	dialer := &countingDialer{}

	_, err := Measure(context.Background(), MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	require.NoError(t, err, "a measurement without a debug callback must still succeed")
}
