package http

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the NEGATIVE side of the authority-promotion rule: only a
// uniformly transport-establishment failure may be upgraded to "HTTP/3
// unavailable". Everything else must keep its own error, because retrying it
// over HTTP/2 would either fail identically or hide a real configuration
// problem behind a silent downgrade.

// TestPromotionRequiresEveryAttemptToFailOnTransport is the core restriction.
// A pool that exhausted with even one non-transport failure must not condemn the
// authority.
func TestPromotionRequiresEveryAttemptToFailOnTransport(t *testing.T) {
	client := &http3ClientImpl{}
	transportErr := &timeoutNetError{}

	cases := []struct {
		name              string
		transportFailures int
		attempts          int
		maxAttempts       int
		lastErr           error
		wantUnavailable   bool
	}{
		{
			name:              "all attempts failed on transport",
			transportFailures: 3,
			attempts:          3,
			maxAttempts:       3,
			lastErr:           transportErr,
			wantUnavailable:   true,
		},
		{
			name:              "one attempt failed for another reason",
			transportFailures: 2,
			attempts:          3,
			maxAttempts:       3,
			lastErr:           errors.New("HTTP/3 CONNECT: 407"),
			wantUnavailable:   false,
		},
		{
			name:              "no transport failures at all",
			transportFailures: 0,
			attempts:          2,
			maxAttempts:       2,
			lastErr:           errors.New("status"),
			wantUnavailable:   false,
		},
		{
			name:              "pool was not fully exhausted",
			transportFailures: 1,
			attempts:          1,
			maxAttempts:       3,
			lastErr:           transportErr,
			wantUnavailable:   false,
		},
		{
			name:              "nil error cannot be promoted",
			transportFailures: 1,
			attempts:          2,
			maxAttempts:       2,
			lastErr:           nil,
			wantUnavailable:   false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := client.promoteExhaustedTransportFailure(
				testCase.lastErr, testCase.transportFailures, testCase.attempts, testCase.maxAttempts)
			if testCase.lastErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, testCase.wantUnavailable, errors.Is(err, ErrHTTP3Unavailable),
				"promotion decision was wrong for %q", testCase.name)
		})
	}
}

// TestTransportEstablishmentClassification pins which errors count. A silent
// UDP blackhole (timeout) and an answered-but-refused transport both count;
// everything else does not.
func TestTransportEstablishmentClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"handshake timeout (blackhole)", &timeoutNetError{}, true},
		{"plain error", errors.New("something else"), false},
		{"context cancellation", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, isHTTP3TransportEstablishmentFailure(testCase.err))
		})
	}
}

// TestPostWriteFailuresAreNeverPromoted is the replay-safety companion: a failure
// after the CONNECT header was written carries its own error and must never be
// turned into a fallback signal, because falling back would replay the CONNECT.
func TestPostWriteFailuresAreNeverPromoted(t *testing.T) {
	client := &http3ClientImpl{}
	postWrite := errors.New("HTTP/3 CONNECT: stream reset after header was sent")

	// A post-write failure never increments the transport-failure counter,
	// because openStream returns directly rather than continuing the attempt
	// loop. Feeding zero transport failures models that faithfully.
	err := client.promoteExhaustedTransportFailure(postWrite, 0, 1, 1)
	require.False(t, errors.Is(err, ErrHTTP3Unavailable),
		"a post-write failure must not trigger an authority fallback")
	require.ErrorIs(t, err, postWrite,
		"the original post-write error must be preserved")
}

// timeoutNetError is a net.Error that reports a timeout, matching the shape of a
// QUIC handshake timeout against a blackholed peer.
type timeoutNetError struct{}

func (*timeoutNetError) Error() string   { return "i/o timeout" }
func (*timeoutNetError) Timeout() bool   { return true }
func (*timeoutNetError) Temporary() bool { return true }

var _ net.Error = (*timeoutNetError)(nil)
