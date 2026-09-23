//go:build with_quic

package http

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests assert the BEHAVIOUR of the HTTP/3 fallback backoff, not merely
// that the configuration decodes.
//
// An earlier revision parsed http3_fallback into an option struct but the MASQUE
// client kept using hardcoded 5s/5m constants with a fixed x2 and a fixed reset,
// so the option had no effect. Testing JSON decode would not have caught that, so
// these tests drive the real escalation state machine and read the resulting
// windows.

// newScheduleOnlyClient builds a Client with only the backoff state under test.
// No transport is involved, so the state machine can be driven without network
// access or real sleeps.
func newScheduleOnlyClient(schedule option.HTTP3FallbackSchedule) *Client {
	return &Client{http3Schedule: schedule}
}

// http3WindowExpired reports whether the avoidance window has elapsed. Unlike
// http3Available it ignores whether an HTTP/3 client exists, so the schedule
// state machine can be tested without a network.
func (c *Client) http3WindowExpired() bool {
	brokenUntil := c.http3BrokenUntil.Load()
	return brokenUntil == 0 || time.Now().UnixNano() >= brokenUntil
}

func scheduleFrom(t *testing.T, initial, maximum time.Duration, multiplier float64, reset *bool) option.HTTP3FallbackSchedule {
	t.Helper()
	return resolveClientHTTP3Schedule(&option.HTTP3FallbackOptions{
		InitialBackoff: badoption.Duration(initial),
		MaxBackoff:     badoption.Duration(maximum),
		Multiplier:     multiplier,
		ResetOnSuccess: reset,
	})
}

// TestClientFallbackBackoffSequenceUsesConfiguration is the core P0-4 assertion:
// a configured 100ms/400ms/x2 schedule must produce exactly 100, 200, 400, 400.
func TestClientFallbackBackoffSequenceUsesConfiguration(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 100*time.Millisecond, 400*time.Millisecond, 2, &reset)
	client := newScheduleOnlyClient(schedule)

	expected := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond, // clamped at max_backoff
		400 * time.Millisecond,
	}
	for index, want := range expected {
		client.markHTTP3Broken()
		got := time.Duration(client.http3Escalation.Load())
		require.Equal(t, want, got,
			"failure #%d must apply the configured backoff, got %v want %v", index+1, got, want)
	}
}

// TestClientFallbackBackoffDefaultIsUpstream proves an unconfigured client keeps
// the inherited upstream schedule.
func TestClientFallbackBackoffDefaultIsUpstream(t *testing.T) {
	client := newScheduleOnlyClient(resolveClientHTTP3Schedule(nil))

	client.markHTTP3Broken()
	require.Equal(t, upstreamHTTP3BackoffInitial, time.Duration(client.http3Escalation.Load()),
		"an unconfigured client must start at the upstream initial backoff")
}

// TestClientFallbackResetOnSuccessTrue proves reset_on_success=true restarts the
// schedule after a successful HTTP/3 use.
func TestClientFallbackResetOnSuccessTrue(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 100*time.Millisecond, 400*time.Millisecond, 2, &reset)
	client := newScheduleOnlyClient(schedule)

	client.markHTTP3Broken()
	client.markHTTP3Broken()
	require.Equal(t, 200*time.Millisecond, time.Duration(client.http3Escalation.Load()))

	client.clearHTTP3Broken()
	require.Zero(t, client.http3Escalation.Load(),
		"reset_on_success=true must clear the escalation history")

	client.markHTTP3Broken()
	require.Equal(t, 100*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"after a reset the schedule must restart at initial_backoff")
}

// TestClientFallbackResetOnSuccessFalseKeepsEscalation is the other half.
func TestClientFallbackResetOnSuccessFalseKeepsEscalation(t *testing.T) {
	reset := false
	schedule := scheduleFrom(t, 100*time.Millisecond, 400*time.Millisecond, 2, &reset)
	client := newScheduleOnlyClient(schedule)

	client.markHTTP3Broken()
	client.markHTTP3Broken()
	require.Equal(t, 200*time.Millisecond, time.Duration(client.http3Escalation.Load()))

	client.clearHTTP3Broken()
	require.Equal(t, 200*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"reset_on_success=false must preserve the escalation history")

	client.markHTTP3Broken()
	require.Equal(t, 400*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"escalation must continue from the preserved value")
}

// TestClientHTTP3AvailabilityWindow covers the broken-until half of the state,
// including the P0-5 lifecycle property: expiry must NOT discard the escalation.
func TestClientHTTP3AvailabilityWindow(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 40*time.Millisecond, 400*time.Millisecond, 2, &reset)
	client := newScheduleOnlyClient(schedule)

	require.Zero(t, client.http3BrokenUntil.Load(), "a fresh client must have no avoidance window")

	client.markHTTP3Broken()
	require.NotZero(t, client.http3BrokenUntil.Load(), "a failure must open an avoidance window")
	require.False(t, client.http3WindowExpired(), "the window must not be expired immediately")

	// Wait out the window. This is a sub-100ms backoff by construction, so the
	// test is fast while still exercising real time.
	deadline := time.Now().Add(2 * time.Second)
	for !client.http3WindowExpired() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, client.http3WindowExpired(), "the window must expire after the backoff elapses")
}

// TestClientBackoffSurvivesWindowExpiry is the P0-5 regression: a serial
// failure -> expiry -> failure sequence must CONTINUE to escalate rather than
// restart at the initial backoff.
//
// The previous implementation stored the window and the escalation in one record
// and deleted the record on expiry, so the escalation was lost and the second
// failure restarted at initial_backoff.
func TestClientBackoffSurvivesWindowExpiry(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 20*time.Millisecond, 400*time.Millisecond, 2, &reset)
	client := newScheduleOnlyClient(schedule)

	client.markHTTP3Broken()
	require.Equal(t, 20*time.Millisecond, time.Duration(client.http3Escalation.Load()))

	// Let the window expire.
	deadline := time.Now().Add(2 * time.Second)
	for !client.http3WindowExpired() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	require.True(t, client.http3WindowExpired(), "precondition: the window must have expired")

	// A retry fails. The backoff must grow, not restart.
	client.markHTTP3Broken()
	require.Equal(t, 40*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"an expired window must not discard the escalation history")

	// And again, to prove the growth continues rather than oscillating.
	deadline = time.Now().Add(2 * time.Second)
	for !client.http3WindowExpired() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	client.markHTTP3Broken()
	require.Equal(t, 80*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"repeated failure -> expiry -> failure must keep escalating")
}

// TestClientScheduleIsClonedPerClient proves two clients with different
// configuration do not share state.
func TestClientScheduleIsClonedPerClient(t *testing.T) {
	reset := true
	fast := newScheduleOnlyClient(scheduleFrom(t, 10*time.Millisecond, 80*time.Millisecond, 2, &reset))
	slow := newScheduleOnlyClient(resolveClientHTTP3Schedule(nil))

	fast.markHTTP3Broken()
	require.Equal(t, 10*time.Millisecond, time.Duration(fast.http3Escalation.Load()))
	require.Zero(t, slow.http3Escalation.Load(),
		"marking one client broken must not affect another")

	slow.markHTTP3Broken()
	require.Equal(t, upstreamHTTP3BackoffInitial, time.Duration(slow.http3Escalation.Load()))
	require.Equal(t, 10*time.Millisecond, time.Duration(fast.http3Escalation.Load()))
}
