package urltest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// HTTPS coverage for the unified-delay measurement.
//
// The plain-HTTP reuse test proves the transport is shared, but the interesting case is TLS: a
// second handshake would be both a large cost and a different code path. These tests use a local
// TLS server whose certificate is trusted through the project's own root pool, so no production
// code needs to skip verification and nothing depends on the public internet.

// certificateStore is a CertificateStore that trusts one pool.
type certificateStore struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (s *certificateStore) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (s *certificateStore) Close() error                                               { return nil }
func (s *certificateStore) Pool() *x509.CertPool                                       { return s.pool }
func (s *certificateStore) ExclusiveAnchors() bool                                     { return false }

// tlsContext returns a context whose root pool trusts the given certificate.
func tlsContext(t *testing.T, server *httptest.Server) context.Context {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	// ContextWith registers the value under the interface type the production lookup asks for.
	// The pointer form would store a *CertificateStore under a key nothing reads.
	return service.ContextWith(context.Background(), adapter.CertificateStore(&certificateStore{pool: pool}))
}

// tlsTarget is a local HTTPS endpoint that counts requests and TLS handshakes.
type tlsTarget struct {
	server     *httptest.Server
	requests   atomic.Int32
	handshakes atomic.Int32
}

func newTLSTarget(t *testing.T, perRequest func(index int) time.Duration) *tlsTarget {
	t.Helper()
	target := &tlsTarget{}
	target.server = httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := int(target.requests.Add(1)) - 1
		if delay := perRequest(index); delay > 0 {
			time.Sleep(delay)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	// Count handshakes at the TLS layer, which is what "reused the connection" means here.
	target.server.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			target.handshakes.Add(1)
			return nil, nil
		},
	}
	target.server.StartTLS()
	t.Cleanup(target.server.Close)
	return target
}

// TestHTTPSUsesOneTLSConnectionForBothRequests is §35.
func TestHTTPSUsesOneTLSConnectionForBothRequests(t *testing.T) {
	target := newTLSTarget(t, func(int) time.Duration { return 0 })
	ctx := tlsContext(t, target.server)

	result, err := Measure(ctx, MeasureOptions{Link: target.server.URL + "/generate_204"}, directDialer{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, result.StatusCode)

	require.EqualValues(t, 2, target.requests.Load(),
		"a successful measurement is exactly two HEAD requests")
	require.EqualValues(t, 1, target.handshakes.Load(),
		"both requests must travel over ONE TLS connection; a second handshake would mean the "+
			"warm-up paid for a handshake the measured request then repeated")
}

// TestHTTPSTLSColdPathStaysInTheWarmUp is §36.
func TestHTTPSTLSColdPathStaysInTheWarmUp(t *testing.T) {
	// The first request is slow, standing in for a cold TLS handshake; the second is fast. The
	// reported delay must follow the second, not the cold path.
	const coldPath = 140 * time.Millisecond
	target := newTLSTarget(t, func(index int) time.Duration {
		if index == 0 {
			return coldPath
		}
		return 0
	})
	ctx := tlsContext(t, target.server)

	result, phases := measureWithPhases(t, ctx, target.server.URL+"/generate_204", directDialer{})

	// The bound is the warm-up phase's own measured duration, which contains the injected cold
	// path, rather than a flat millisecond constant: see measureWithPhases. A slow host moves the
	// bound with the measurement instead of turning a correct decomposition red.
	requireColdPathAbsorbedByTheWarmUp(t, result, phases, coldPath, "cold TLS response")
	require.GreaterOrEqual(t, result.Delay, uint16(1))
}

// TestHTTPSWarmUpAlsoServesAsTheReuseWarmUp confirms the first request is what establishes the
// reusable TLS connection, so removing it would be visible here.
func TestHTTPSWarmUpAlsoServesAsTheReuseWarmUp(t *testing.T) {
	target := newTLSTarget(t, func(int) time.Duration { return 0 })
	ctx := tlsContext(t, target.server)

	_, err := Measure(ctx, MeasureOptions{Link: target.server.URL + "/generate_204"}, directDialer{})
	require.NoError(t, err)

	// One handshake for two requests is the property; this restates it against the TLS layer
	// specifically so a future change to transport handling fails here.
	require.EqualValues(t, 1, target.handshakes.Load())
	require.EqualValues(t, 2, target.requests.Load())
}
