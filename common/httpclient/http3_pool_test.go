//go:build with_quic

package httpclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/option"
)

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------

// TestHTTP3PoolSizeDefault proves that an absent http3_connection_pool resolves
// to size 1, which callers treat as plain upstream behaviour.
func TestHTTP3PoolSizeDefault(t *testing.T) {
	size, err := (*option.HTTP3ConnectionPoolOptions)(nil).Build()
	if err != nil {
		t.Fatalf("absent pool options must be valid: %v", err)
	}
	if size != 1 {
		t.Fatalf("an absent pool must resolve to size 1, got %d", size)
	}
}

func TestHTTP3PoolSizeExplicitOne(t *testing.T) {
	size, err := (&option.HTTP3ConnectionPoolOptions{Size: 1}).Build()
	if err != nil {
		t.Fatalf("size 1 must be valid: %v", err)
	}
	if size != 1 {
		t.Fatalf("size 1 must resolve to 1, got %d", size)
	}
}

func TestHTTP3PoolRejectsInvalidSize(t *testing.T) {
	if _, err := (&option.HTTP3ConnectionPoolOptions{Size: -1}).Build(); err == nil {
		t.Fatal("a negative pool size must be rejected")
	}
	if _, err := (&option.HTTP3ConnectionPoolOptions{Size: option.MaxHTTP3ConnectionPoolSize + 1}).Build(); err == nil {
		t.Fatal("an oversized pool must be rejected")
	}
	if _, err := (&option.HTTP3ConnectionPoolOptions{Size: 2, Strategy: "adaptive"}).Build(); err == nil {
		t.Fatal("an unsupported strategy must be rejected")
	}
}

func TestHTTP3PoolStrategyDefaultsToRoundRobin(t *testing.T) {
	for _, strategy := range []string{"", option.HTTP3PoolStrategyRoundRobin} {
		if _, err := (&option.HTTP3ConnectionPoolOptions{Size: 2, Strategy: strategy}).Build(); err != nil {
			t.Fatalf("strategy %q must be accepted: %v", strategy, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Selection semantics (no network)
//
// These exercise pick() directly, which is where the replay-safety rule lives.
// ---------------------------------------------------------------------------

// recordingPool records which pool member index pick() chose. It exists only
// in tests and does not add any hook to production code.
type recordingPool struct {
	*http3Transport
	onPick func(int)
}

func selectionProbe(size int, onPick func(int)) *recordingPool {
	transports := make([]*http3.Transport, size)
	for index := range transports {
		transports[index] = &http3.Transport{}
	}
	return &recordingPool{
		http3Transport: &http3Transport{transports: transports},
		onPick:         onPick,
	}
}

// pick mirrors http3Transport.pick but reports the chosen index.
func (p *recordingPool) pick(request *http.Request) *http3.Transport {
	transport := p.http3Transport.pick(request)
	for index, candidate := range p.transports {
		if candidate == transport {
			p.onPick(index)
			break
		}
	}
	return transport
}

func TestHTTP3PoolPickSizeOneAlwaysFirst(t *testing.T) {
	var picked []int
	pool := selectionProbe(1, func(index int) { picked = append(picked, index) })
	request := mustRequest(t, http.MethodGet, "https://example.com/", nil, nil)
	for range 10 {
		pool.pick(request)
	}
	if len(picked) != 10 {
		t.Fatalf("expected 10 picks, got %d", len(picked))
	}
	for _, index := range picked {
		if index != 0 {
			t.Fatalf("size 1 must always pick member 0, saw %d", index)
		}
	}
}

// TestHTTP3PoolPickNonReplayableStableMember is the safety-critical rule: a
// request whose body cannot be rewound must always use one member, so a failed
// attempt can never replay a consumed body on another connection.
func TestHTTP3PoolPickNonReplayableStableMember(t *testing.T) {
	var picked []int
	pool := selectionProbe(2, func(index int) { picked = append(picked, index) })

	request := mustRequest(t, http.MethodPost, "https://example.com/",
		io.NopCloser(strings.NewReader("one-shot")), nil)
	request.GetBody = nil
	if requestReplayable(request) {
		t.Fatal("precondition: the request must be non-replayable")
	}
	for range 20 {
		pool.pick(request)
	}
	for _, index := range picked {
		if index != 0 {
			t.Fatalf("a non-replayable request must keep using member 0, saw %d", index)
		}
	}
}

func TestHTTP3PoolPickReplayableRotates(t *testing.T) {
	var picked []int
	pool := selectionProbe(2, func(index int) { picked = append(picked, index) })
	request := mustRequest(t, http.MethodPost, "https://example.com/",
		strings.NewReader("rewindable"),
		func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("rewindable")), nil })
	if !requestReplayable(request) {
		t.Fatal("precondition: the request must be replayable")
	}
	for range 10 {
		pool.pick(request)
	}
	if !containsAll(picked, 2) {
		t.Fatalf("a replayable request must rotate across both members, saw %v", picked)
	}
}

func TestHTTP3PoolPickBodylessRotates(t *testing.T) {
	var picked []int
	pool := selectionProbe(4, func(index int) { picked = append(picked, index) })
	request := mustRequest(t, http.MethodGet, "https://example.com/", nil, nil)
	for range 8 {
		pool.pick(request)
	}
	if !containsAll(picked, 4) {
		t.Fatalf("a bodyless request must rotate across all members, saw %v", picked)
	}
}

func TestHTTP3PoolConcurrentPick(t *testing.T) {
	var (
		access sync.Mutex
		counts = make(map[int]int)
	)
	pool := selectionProbe(4, func(index int) {
		access.Lock()
		counts[index]++
		access.Unlock()
	})
	const (
		workers    = 16
		iterations = 100
	)
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Go(func() {
			for range iterations {
				request := mustRequest(t, http.MethodGet, "https://example.com/", nil, nil)
				pool.pick(request)
			}
		})
	}
	waitGroup.Wait()
	access.Lock()
	defer access.Unlock()
	if len(counts) != 4 {
		t.Fatalf("all 4 members must be used under concurrency, saw %v", counts)
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	if total != workers*iterations {
		t.Fatalf("expected %d picks, got %d", workers*iterations, total)
	}
}

// ---------------------------------------------------------------------------
// Real QUIC connections
// ---------------------------------------------------------------------------

// TestHTTP3ConnectionPoolCreatesIndependentQUICConnections is the end-to-end
// proof that size=2 yields two genuinely separate QUIC connections rather than
// two streams sharing one connection.
func TestHTTP3ConnectionPoolCreatesIndependentQUICConnections(t *testing.T) {
	server, address, connections := startCountingH3Server(t, 2)
	defer server.Close()

	pool := newTestPool(t, 2)
	runConcurrentRequests(t, pool, address, 32)

	if observed := connections.count(); observed < 2 {
		t.Fatalf("expected at least 2 independent QUIC connections, observed %d", observed)
	}
}

// TestHTTP3ConnectionPoolSizeOneSingleConnection is the size=1 equivalence
// check: one transport must never open a second QUIC connection.
func TestHTTP3ConnectionPoolSizeOneSingleConnection(t *testing.T) {
	server, address, connections := startCountingH3Server(t, 1)
	defer server.Close()

	pool := newTestPool(t, 1)
	runConcurrentRequests(t, pool, address, 32)

	if observed := connections.count(); observed != 1 {
		t.Fatalf("size=1 must use exactly 1 QUIC connection, observed %d", observed)
	}
}

// TestHTTP3PoolCloseClosesEveryMember asserts Close() tears down all members
// and is idempotent.
func TestHTTP3PoolCloseClosesEveryMember(t *testing.T) {
	pool := newTestPool(t, 3)
	if err := pool.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second close must be safe: %v", err)
	}
	pool.CloseIdleConnections()
}

// TestHTTP3FallbackPoolCloseClosesH2 verifies the fallback wrapper closes both
// the pool and the HTTP/2 fallback.
func TestHTTP3FallbackPoolCloseClosesH2(t *testing.T) {
	closed := false
	transport := &http3FallbackTransport{
		h3Pool:     newTestPool(t, 2),
		h2Fallback: &closeTrackingTransport{onClose: func() { closed = true }},
		schedule:   (*option.HTTP3FallbackOptions)(nil).Build(),
		broken:     make(map[string]http3BrokenEntry),
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !closed {
		t.Fatal("closing the pool transport must also close the HTTP/2 fallback")
	}
}

// TestHTTP3PoolFailureIsPerAuthority documents that broken state is keyed by
// authority rather than by pool member, so one dead member or one unreachable
// server cannot permanently poison the whole pool.
func TestHTTP3PoolFailureIsPerAuthority(t *testing.T) {
	transport := &http3FallbackTransport{
		h3Pool:     newTestPool(t, 2),
		h2Fallback: &closeTrackingTransport{},
		schedule:   (*option.HTTP3FallbackOptions)(nil).Build(),
		broken:     make(map[string]http3BrokenEntry),
	}
	defer transport.Close()

	transport.markH3Broken("a.example:443")
	if !transport.h3Broken("a.example:443") {
		t.Fatal("a.example must be marked broken")
	}
	if transport.h3Broken("b.example:443") {
		t.Fatal("b.example must not inherit a.example's broken state")
	}
	transport.clearH3Broken("a.example:443")
	if transport.h3Broken("a.example:443") {
		t.Fatal("a successful round trip must clear the broken state")
	}
}

// TestHTTP3PoolNonReplayableNotRetriedOnOtherMember confirms end-to-end that a
// non-replayable request is never silently moved to a second connection. The
// server rejects the first authority's member, and the one-shot body must not
// be sent twice.
func TestHTTP3PoolNonReplayableBodySentAtMostOnce(t *testing.T) {
	var (
		access sync.Mutex
		bodies []string
	)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		payload, _ := io.ReadAll(request.Body)
		access.Lock()
		bodies = append(bodies, string(payload))
		access.Unlock()
		writer.WriteHeader(http.StatusOK)
	})
	server, address, _ := startH3ServerWithHandler(t, handler)
	defer server.Close()

	pool := newTestPool(t, 2)
	defer pool.Close()
	request, err := http.NewRequest(http.MethodPost, "https://"+address+"/", strings.NewReader("one-shot-body"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.GetBody = nil
	response, err := pool.RoundTrip(request)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	response.Body.Close()
	access.Lock()
	defer access.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("a non-replayable body must be sent exactly once, got %d", len(bodies))
	}
	if bodies[0] != "one-shot-body" {
		t.Fatalf("unexpected body %q", bodies[0])
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type connectionCounter struct {
	access sync.Mutex
	conns  map[*quic.Conn]struct{}
}

func (c *connectionCounter) add(conn *quic.Conn) {
	c.access.Lock()
	c.conns[conn] = struct{}{}
	c.access.Unlock()
}

func (c *connectionCounter) count() int {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.conns)
}

func testServerTLSConfig(t testing.TB) *stdTLS.Config {
	t.Helper()
	certificate := generateTestCertificate(t)
	return &stdTLS.Config{
		Certificates: []stdTLS.Certificate{certificate},
		NextProtos:   []string{http3.NextProtoH3},
	}
}

func testClientTLSConfig(t testing.TB) *stdTLS.Config {
	t.Helper()
	return &stdTLS.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}
}

// startCountingH3Server starts a real HTTP/3 server on loopback and returns it
// together with the address to dial and a counter of accepted QUIC
// connections.
func startCountingH3Server(t *testing.T, _ int) (*http3.Server, string, *connectionCounter) {
	t.Helper()
	return startH3ServerWithHandler(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	}))
}

func startH3ServerWithHandler(t testing.TB, handler http.Handler) (*http3.Server, string, *connectionCounter) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	counter := &connectionCounter{conns: make(map[*quic.Conn]struct{})}
	server := &http3.Server{
		Handler:    handler,
		TLSConfig:  testServerTLSConfig(t),
		QUICConfig: &quic.Config{},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			counter.add(conn)
			return ctx
		},
	}
	go func() {
		_ = server.Serve(udpConn)
		udpConn.Close()
	}()
	// Give the listener a moment to be ready before the first dial.
	time.Sleep(50 * time.Millisecond)
	return server, udpConn.LocalAddr().String(), counter
}

// newTestPool builds a pool of `size` independent HTTP/3 transports pointed at
// a loopback server with an insecure test TLS config.
func newTestPool(t testing.TB, size int) *http3Transport {
	t.Helper()
	transports := make([]*http3.Transport, 0, size)
	for range size {
		transports = append(transports, &http3.Transport{
			TLSClientConfig: testClientTLSConfig(t),
			QUICConfig:      &quic.Config{},
		})
	}
	return &http3Transport{transports: transports}
}

func runConcurrentRequests(t *testing.T, pool *http3Transport, address string, requests int) {
	t.Helper()
	var waitGroup sync.WaitGroup
	errs := make(chan error, requests)
	for range requests {
		waitGroup.Go(func() {
			request, err := http.NewRequest(http.MethodGet, "https://"+address+"/", nil)
			if err != nil {
				errs <- err
				return
			}
			response, err := pool.RoundTrip(request)
			if err != nil {
				errs <- err
				return
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
		})
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("pooled round trip failed: %v", err)
		}
	}
}

func mustRequest(t *testing.T, method, rawURL string, body io.Reader, getBody func() (io.ReadCloser, error)) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.GetBody = getBody
	return request
}

func containsAll(values []int, size int) bool {
	seen := make(map[int]struct{}, size)
	for _, value := range values {
		seen[value] = struct{}{}
	}
	return len(seen) == size
}

type closeTrackingTransport struct {
	closed  bool
	onClose func()
}

func (c *closeTrackingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    request,
		Header:     make(http.Header),
	}, nil
}

func (c *closeTrackingTransport) CloseIdleConnections() {}

func (c *closeTrackingTransport) Close() error {
	if !c.closed {
		c.closed = true
		if c.onClose != nil {
			c.onClose()
		}
	}
	return nil
}

// generateTestCertificate creates a throwaway self-signed certificate for
// loopback HTTP/3 tests. No real secret or production certificate is involved.
func generateTestCertificate(t testing.TB) stdTLS.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-box-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return stdTLS.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTestPoolB is the testing.TB form of newTestPool, usable from benchmarks.
func newTestPoolB(tb testing.TB, size int) *http3Transport {
	return newTestPool(tb, size)
}

// bodyRecordingTransport stands in for the HTTP/2 fallback and records exactly
// what body bytes it is asked to send.
type bodyRecordingTransport struct {
	access sync.Mutex
	bodies []string
	calls  int
}

func (b *bodyRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	b.access.Lock()
	b.calls++
	b.access.Unlock()
	var received string
	if request.Body != nil {
		payload, err := io.ReadAll(request.Body)
		if err == nil {
			received = string(payload)
		}
	}
	b.access.Lock()
	b.bodies = append(b.bodies, received)
	b.access.Unlock()
	return newTestResponse(request), nil
}

func (b *bodyRecordingTransport) CloseIdleConnections() {}

func (b *bodyRecordingTransport) Close() error { return nil }

func (b *bodyRecordingTransport) snapshot() (int, []string) {
	b.access.Lock()
	defer b.access.Unlock()
	return b.calls, append([]string(nil), b.bodies...)
}

// TestHTTP3NonReplayableBodyIsNotReplayedToH2 is the replay-safety regression for
// the generic transport.
//
// The non-ErrNoCachedConn branch used to clone and retry unconditionally, before
// any replayability check, so a request with a one-shot body could reach the
// HTTP/2 fallback with a body the HTTP/3 attempt had already consumed.
//
// This test drives the decision function directly with a failing probe and
// inspects what the fallback actually receives. Driving it end to end through
// RoundTripOpt is not viable in a unit test: a stub transport there spins on a
// real dial until the 5s idle timeout. The decision logic is what regressed, so
// that is what is tested, and the end-to-end path stays covered by the
// TestHTTP3PoolNonReplayableBodySentAtMostOnce integration test.
func TestHTTP3NonReplayableBodyIsNotReplayedToH2(t *testing.T) {
	probeFailure := errors.New("http3 probe failed")

	testCases := []struct {
		name           string
		payload        string
		provideGetBody bool
		expectFallback bool
	}{
		{
			name:           "one-shot body is not replayed",
			payload:        "one-shot-payload",
			provideGetBody: false,
			expectFallback: false,
		},
		{
			name:           "rewindable body is replayed",
			payload:        "rewindable-payload",
			provideGetBody: true,
			expectFallback: true,
		},
		{
			name:           "bodyless request is replayed",
			payload:        "",
			provideGetBody: false,
			expectFallback: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fallback := &bodyRecordingTransport{}
			transport := &http3FallbackTransport{
				h3Pool:     newStubH3Pool(),
				h2Fallback: fallback,
				schedule:   (*option.HTTP3FallbackOptions)(nil).Build(),
				broken:     make(map[string]http3BrokenEntry),
			}

			request := buildProbeRequest(t, testCase.payload, testCase.provideGetBody)

			_, err := transport.handleProbeFailure(request, probeFailure)

			calls, bodies := fallback.snapshot()
			if testCase.expectFallback {
				if err != nil {
					t.Fatalf("a replayable request must fall back: %v", err)
				}
				if calls != 1 {
					t.Fatalf("expected exactly one fallback call, got %d", calls)
				}
				if testCase.payload != "" && bodies[0] != testCase.payload {
					t.Fatalf("the fallback received %q, want exactly %q", bodies[0], testCase.payload)
				}
				return
			}

			if err == nil {
				t.Fatal("a non-replayable request must fail rather than be retried")
			}
			if calls != 0 {
				t.Fatalf("the HTTP/2 fallback must NOT be called for a non-replayable request, "+
					"but it was called %d time(s) with bodies %q", calls, bodies)
			}
		})
	}
}

// buildProbeRequest constructs the request shapes the replay decision cares about.
func buildProbeRequest(t *testing.T, payload string, provideGetBody bool) *http.Request {
	t.Helper()
	var body io.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}
	request, err := http.NewRequest(http.MethodPost, "https://broken.example/upload", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload == "" {
		request.Body = nil
	}
	if !provideGetBody {
		request.GetBody = nil
	}
	return request
}

// newTestResponse builds a minimal successful response for the fake transports.
func newTestResponse(request *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    request,
		Header:     make(http.Header),
	}
}

// stubH3Pool is a pool whose probe always fails with a chosen error, so the
// non-ErrNoCachedConn branch of roundTripHTTP3 can be driven deterministically.
type stubH3Pool struct{}

func newStubH3Pool() *stubH3Pool {
	return &stubH3Pool{}
}

// pick returns a live member so the caller reaches the round trip rather than a
// nil dereference.
func (p *stubH3Pool) pick(request *http.Request) *http3.Transport {
	return &http3.Transport{}
}

func (p *stubH3Pool) CloseIdleConnections() {}

func (p *stubH3Pool) Close() error { return nil }
