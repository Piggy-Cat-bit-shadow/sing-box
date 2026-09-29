//go:build with_quic

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// End-to-end test of the property the same-connection API exists for: a CONNECT-IP tunnel and
// the DoH requests that ride along with it must travel on ONE QUIC connection.
//
// # Why this cannot be inferred from the unit tests
//
// The unit tests prove the plumbing: that acquire() memoizes, that the generic path uses it,
// that DoH selects the generic path. All of those could hold while the real system still
// opened two connections -- for instance if the tunnel and the DoH client were built from
// different Client values, or if a connection reset between them.
//
// So these tests drive the PRODUCTION tunnel path -- OpenTunnelWithInfo, the same call the
// MASQUE session makes -- against a REAL HTTP/3 server, and count the QUIC connections the
// server accepted rather than anything the client reports about itself. One is the only
// acceptable answer.
//
// # Why the tunnel is exercised with REAL BYTES at the end
//
// A CONNECT-IP tunnel and an ordinary HTTP request have different lifecycles, and an earlier
// defect forced both through one shape that closed the write side when the request was sent.
// That is correct for a request and fatal for a tunnel: the first proxy write then failed with
// "write on closed stream". A test that stops at the 200 cannot see it, so these tests also
// write through the tunnel and read the echo back after the DoH traffic has run. The defect
// being guarded against here is subtler still -- a tunnel whose write side is closed by cleanup
// SHARED with the request path -- and it is only observable the same way.

// countingTunnelServer is a real HTTP/3 server that serves both an extended CONNECT tunnel
// and ordinary requests, and counts the QUIC connections it accepts.
type countingTunnelServer struct {
	address  string
	server   *http3.Server
	closed   chan struct{}
	access   sync.Mutex
	conns    []*quic.Conn
	tunnels  int
	requests int
	// dohAnswer is returned for POSTs to the DoH path.
	dohAnswer []byte
}

func (s *countingTunnelServer) connectionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.conns)
}

func (s *countingTunnelServer) streamCounts() (tunnels int, requests int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.tunnels, s.requests
}

// startCountingTunnelServer starts the server on loopback.
//
// It enables Extended CONNECT and datagrams, because a CONNECT-IP tunnel needs both, and
// the client under test refuses to use a connection whose settings do not advertise them.
func startCountingTunnelServer(t *testing.T, dohAnswer []byte) *countingTunnelServer {
	t.Helper()
	server := &countingTunnelServer{closed: make(chan struct{}), dohAnswer: dohAnswer}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			server.access.Lock()
			if request.Method == http.MethodConnect {
				server.tunnels++
			} else {
				server.requests++
			}
			answer := server.dohAnswer
			server.access.Unlock()

			if request.Method == http.MethodConnect {
				// A CONNECT-IP stream is answered with 200 and then STAYS OPEN as the tunnel:
				// it echoes payload back. The handler must NOT return after the 200, or the
				// stream would be closed and the tunnel would be dead on its write side --
				// which is exactly the regression these tests cover.
				writer.WriteHeader(http.StatusOK)
				if flusher, isFlusher := writer.(http.Flusher); isFlusher {
					flusher.Flush()
				}
				buffer := make([]byte, 4096)
				for {
					read, readErr := request.Body.Read(buffer)
					if read > 0 {
						if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
							return
						}
						if flusher, isFlusher := writer.(http.Flusher); isFlusher {
							flusher.Flush()
						}
					}
					if readErr != nil {
						return
					}
				}
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(answer)
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			// The tunnel is long-lived, so the idle timeout must not close it while the
			// test is still using it.
			MaxIdleTimeout:  60 * time.Second,
			EnableDatagrams: true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			server.access.Lock()
			server.conns = append(server.conns, conn)
			server.access.Unlock()
			return ctx
		},
	}
	go func() {
		_ = server.server.Serve(packetConn)
		close(server.closed)
	}()
	t.Cleanup(func() {
		_ = server.server.Close()
		<-server.closed
	})
	return server
}

// newSameConnClient builds a real transport/http client pointed at a loopback server.
//
// It is assembled from the client's own fields rather than through NewClientWithTLS, which
// resolves a full outbound dialer from the service registry -- a configuration-layer concern.
// The tunnel and request branches are reachable with the fields set, exactly as the other
// HTTP/3 tests in this package do it.
func newSameConnClient(t *testing.T, address string) *Client {
	t.Helper()
	client := dialerForTunnel(t, address)
	// The tunnel path falls back to HTTP/2 and HTTP/1 when HTTP/3 is unavailable, and the
	// fallback must fail here rather than silently produce a tunnel this test did not ask for.
	client.tlsDialer = nil
	return client
}

// writeAndReadThroughTunnel writes a payload to the tunnel and reads the echo back.
//
// This is the assertion that matters for a shared lifecycle: a tunnel whose write side was
// closed by some other stream's cleanup accepts no bytes at all, and a read-only check would
// not notice.
func writeAndReadThroughTunnel(t *testing.T, tunnel io.ReadWriteCloser, payload string) {
	t.Helper()
	_, err := tunnel.Write([]byte(payload))
	require.NoError(t, err,
		"the tunnel must remain writable; a write side closed by shared cleanup fails here with 'write on closed stream'")

	buffer := make([]byte, len(payload))
	if deadlineSetter, isDeadlineSetter := tunnel.(interface{ SetReadDeadline(time.Time) error }); isDeadlineSetter {
		_ = deadlineSetter.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	_, err = io.ReadFull(tunnel, buffer)
	require.NoError(t, err, "the tunnel must remain readable")
	require.Equal(t, payload, string(buffer), "the echo must carry exactly what was written")
}

// TestTunnelAndDoHShareOneConnection is the Stage 7 acceptance test.
//
// It opens a CONNECT-IP tunnel through the production path, then issues several DoH requests,
// and requires the server to have accepted exactly ONE QUIC connection for all of them. A
// second connection would mean the coalescing the draft asks for is not happening, and the
// privacy property the design claims -- that inner DNS queries and tunnel traffic are
// indistinguishable as one flow -- would be false.
func TestTunnelAndDoHShareOneConnection(t *testing.T) {
	t.Parallel()

	answer := []byte("dns-wire-response")
	server := startCountingTunnelServer(t, answer)
	client := newSameConnClient(t, server.address)

	// 1. Open a CONNECT-IP tunnel. This is the production call the MASQUE session makes, so the
	//    connection beneath it is the one acquire() memoizes rather than one this test built.
	tunnel, tunnelTransport, err := client.OpenTunnelWithInfo(context.Background(), "connect-ip", "/")
	require.NoError(t, err)
	require.Equal(t, TunnelTransportHTTP3, tunnelTransport,
		"the tunnel must be established over HTTP/3, which is the fact a same-connection DoH decision depends on")
	defer tunnel.Close()

	// The tunnel works BEFORE the requests, so the comparison at the end is meaningful.
	writeAndReadThroughTunnel(t, tunnel, "tunnel-before")

	// 2. Issue DoH requests. Every one must reuse the connection the tunnel is on, which is the
	//    whole claim: these are separate HTTP/3 streams, not a second connection.
	const dohRequestCount = 8
	var waitGroup sync.WaitGroup
	errors := make(chan error, dohRequestCount)
	for index := range dohRequestCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
				"https://"+server.address+"/dns-query", stringReader("query-"+strconv.Itoa(index)))
			if requestErr != nil {
				errors <- requestErr
				return
			}
			response, roundTripErr := client.RoundTripExistingHTTP3(context.Background(), request)
			if roundTripErr != nil {
				errors <- roundTripErr
				return
			}
			payload, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				errors <- readErr
				return
			}
			if string(payload) != string(answer) {
				errors <- E.New("unexpected DoH payload: ", string(payload))
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for requestErr := range errors {
		require.NoError(t, requestErr)
	}

	// 3. The proof: ONE connection carried the tunnel and every DoH request.
	require.Equal(t, 1, server.connectionCount(),
		"the tunnel and all DoH requests must share exactly one QUIC connection; a second connection means the DoH traffic is not coalesced and the privacy claim is false")

	tunnels, requests := server.streamCounts()
	require.Equal(t, 1, tunnels, "exactly one CONNECT-IP stream")
	require.Equal(t, dohRequestCount, requests,
		"each DoH request must be its own HTTP/3 stream on the shared connection")

	// 4. THE assertion this test was missing: the tunnel is still writable AND still readable
	//    afterwards. A request lifecycle that closed more than its own stream -- or cleanup
	//    shared between the two lifecycles -- leaves a tunnel that can be read but never
	//    written again, and only a real write after the requests can see that.
	writeAndReadThroughTunnel(t, tunnel, "tunnel-after")

	// And the connection itself must still be alive, since it is what both lifecycles sit on.
	clientConn, live := client.http3.(*http3ClientImpl).existingConn()
	require.True(t, live, "the shared connection must still be memoized and alive")
	require.NoError(t, clientConn.Context().Err(), "the shared connection must not have been closed by either lifecycle")
}

// stringReader is a tiny io.Reader for bodies, avoiding strings.NewReader so that the
// ContentLength is deliberately left unset -- which is the case the request path has to
// handle by treating an unknown length honestly.
type simpleReader struct {
	data []byte
	read bool
}

func (r *simpleReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(p, r.data)
	return n, nil
}

func stringReader(value string) *simpleReader {
	return &simpleReader{data: []byte(value)}
}

// TestDoHRequestDoesNotCreateASecondConnectionWhenTunnelExists is the negative half.
//
// It asserts that the connection count stays at one across many sequential requests, so a
// per-request connection (a plausible regression if the request path stopped using the
// memoized connection) is caught even though every individual request would still succeed.
func TestDoHRequestDoesNotCreateASecondConnectionWhenTunnelExists(t *testing.T) {
	t.Parallel()

	server := startCountingTunnelServer(t, []byte("answer"))
	client := newSameConnClient(t, server.address)

	tunnel, tunnelTransport, err := client.OpenTunnelWithInfo(context.Background(), "connect-ip", "/")
	require.NoError(t, err)
	require.Equal(t, TunnelTransportHTTP3, tunnelTransport,
		"the negative case is only meaningful if the tunnel really is on HTTP/3")
	defer tunnel.Close()

	for range 5 {
		request, requestErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+server.address+"/dns-query", stringReader("q"))
		require.NoError(t, requestErr)
		response, roundTripErr := client.RoundTripExistingHTTP3(context.Background(), request)
		require.NoError(t, roundTripErr)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
	}

	require.Equal(t, 1, server.connectionCount(),
		"sequential requests must never open another connection")

	// The tunnel must have survived the requests: a per-request connection is one failure mode,
	// and a request path that tears down what it shares is the other.
	writeAndReadThroughTunnel(t, tunnel, "still-alive")
}
