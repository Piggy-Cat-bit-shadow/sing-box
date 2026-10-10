//go:build with_quic

package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// What an HTTP/3 attempt is allowed to prove.
//
// # The verdict this file is about
//
// `http3FallbackTransport` remembers, per authority, that HTTP/3 did not work, and every later
// request for that authority goes straight to the H2 fallback while the memory is live: 5 minutes
// on the first failure, doubling on each further one, capped at 48 hours. So arming it is a
// decision with a long tail, and it has to be armed by an attempt that actually says something
// about the authority.
//
// # The defect these tests pin
//
// An attempt the CALLER ended says nothing about HTTP/3. The caller's context is cancelled by a
// closed client, an abandoned DNS query, a rule-set refresh that lost its consumer, a shutdown -
// none of which is a fact about the server. Every one of them used to reach `markH3Broken`: the
// first `RoundTripOpt` fails with the caller's cancellation, the error is not `ErrNoCachedConn`, and
// the memory was armed. Pre-fix, a burst of cancellations for one authority is enough to move that
// authority onto HTTP/2 for five minutes and to climb the ladder from there.
//
// The rule is the one this tree already applies in the two sibling implementations of the same
// decision - `transport/v2rayxhttp`'s breaker ("context.Canceled is neutral", SPEC 094) and the
// HTTP/3 CONNECT setup path (a caller cancellation is not an H3 verdict) - and the one
// `docs/fork/RC-CERTIFICATE.md` states for this class of state.
//
// The tests drive the REAL decision (`RoundTrip` -> `roundTripHTTP3` -> the race) with a fake
// dialer, so they cannot pass by testing a helper in isolation: the assertion is on the transport's
// own remembered state after a real attempt.

const h3VerdictAuthority = "verdict.example:443"

var (
	errH3VerdictAttempt = errors.New("http3 attempt failed")
	errH3VerdictH2      = errors.New("h2 fallback failed")
)

// h3VerdictStubTransport is the H2 half. Its only job is to fail, so the test observes the H3
// verdict rather than a response.
type h3VerdictStubTransport struct {
	err error
}

func (s *h3VerdictStubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, s.err
}

func (s *h3VerdictStubTransport) CloseIdleConnections() {}

func (s *h3VerdictStubTransport) Close() error { return nil }

// newH3VerdictHarness builds the fallback transport around a caller-supplied dialer.
//
// The fallback delay is deliberately an hour: the race's own timer must never be the event that
// ends the attempt, so in every test below the only thing that happens to the in-flight attempt is
// what the test itself does. That is what makes the interleavings deterministic rather than
// timing-dependent.
func newH3VerdictHarness(dial func(ctx context.Context) (*quic.Conn, error)) *http3FallbackTransport {
	return &http3FallbackTransport{
		h3Transport: &http3.Transport{
			TLSClientConfig: &stdTLS.Config{InsecureSkipVerify: true},
			QUICConfig:      &quic.Config{},
			Dial: func(ctx context.Context, _ string, _ *stdTLS.Config, _ *quic.Config) (*quic.Conn, error) {
				return dial(ctx)
			},
		},
		h2Fallback:    &h3VerdictStubTransport{err: errH3VerdictH2},
		fallbackDelay: time.Hour,
		broken:        make(map[string]http3BrokenEntry),
	}
}

func h3VerdictRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+h3VerdictAuthority+"/generate_204", nil)
	require.NoError(t, err)
	return request
}

// TestACallerCancellationDoesNotArmTheHTTP3Verdict is the finding.
//
// The attempt is in flight and blocked in the dialer; the caller then cancels. The attempt ends
// with the caller's cancellation, which is not a fact about the authority, so nothing may be
// remembered.
func TestACallerCancellationDoesNotArmTheHTTP3Verdict(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	transport := newH3VerdictHarness(func(ctx context.Context) (*quic.Conn, error) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return nil, errH3VerdictAttempt
	})

	ctx, cancel := context.WithCancel(context.Background())
	request := h3VerdictRequest(t, ctx)

	finished := make(chan error, 1)
	go func() {
		_, roundTripErr := transport.RoundTrip(request)
		finished <- roundTripErr
	}()

	<-entered
	cancel()
	close(release)

	require.Error(t, <-finished, "the request must fail: the caller left")
	require.False(t, transport.h3Broken(h3VerdictAuthority),
		"a request the CALLER cancelled proves nothing about HTTP/3, so it must not arm the "+
			"per-authority verdict. Arming it sends every later request for this authority to the "+
			"H2 fallback for five minutes - and each further cancellation doubles that - on evidence "+
			"that was never about the server")
}

// TestAnAlreadyCancelledRequestDoesNotArmTheHTTP3Verdict is the same rule at the other end of the
// window: the caller was already gone before the attempt started.
//
// This is the shape a shutdown or a lost consumer produces, and it is the cheapest one to hit: the
// request context is done before the first `RoundTripOpt`.
func TestAnAlreadyCancelledRequestDoesNotArmTheHTTP3Verdict(t *testing.T) {
	transport := newH3VerdictHarness(func(ctx context.Context) (*quic.Conn, error) {
		return nil, errH3VerdictAttempt
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := h3VerdictRequest(t, ctx)

	_, err := transport.RoundTrip(request)
	require.Error(t, err, "a cancelled request cannot succeed")
	require.False(t, transport.h3Broken(h3VerdictAuthority),
		"a request that was cancelled before it started is not evidence about the authority")
}

// TestAGenuineHTTP3FailureStillArmsTheVerdict is the positive control.
//
// It is what stops the fix from being "never remember anything": with the caller still waiting, the
// same failure must arm exactly the state the fast path exists for.
func TestAGenuineHTTP3FailureStillArmsTheVerdict(t *testing.T) {
	transport := newH3VerdictHarness(func(ctx context.Context) (*quic.Conn, error) {
		return nil, errH3VerdictAttempt
	})

	request := h3VerdictRequest(t, context.Background())
	_, err := transport.RoundTrip(request)
	require.Error(t, err)
	require.True(t, transport.h3Broken(h3VerdictAuthority),
		"an HTTP/3 failure on a live request is exactly the evidence the per-authority verdict "+
			"exists for; without it the fallback would relose the same race on every request")
	require.Equal(t, 5*time.Minute, transport.broken[h3VerdictAuthority].backoff,
		"and it must arm the documented first rung")
}

// # The ladder this does NOT test, and why it cannot be reached
//
// `markH3Broken` doubles the rung of a live entry, and `h3Broken` short-circuits the attempt while
// an entry is live - so while the rung is set, no HTTP/3 attempt is made and no further failure can
// double it. Combined with `h3Broken` DELETING an expired entry (line-verified), a sequence of
// failures separated in time always starts again from the first rung, and the 48h cap is reachable
// only by failures that are concurrent inside one window. That is a product decision about the
// ladder rather than a defect this round may change, so it is reported and not touched here.
