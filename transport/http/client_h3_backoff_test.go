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

// http3WindowElapsed reports whether the avoidance window has elapsed. Unlike
// http3Available it ignores whether an HTTP/3 client exists, so the schedule
// state machine can be tested without a network.
func (c *Client) http3WindowElapsed() bool {
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

// TestClientFallbackBackoffDefaultIsUpstream is the regression for the two-client
// confusion.
//
// There are TWO HTTP/3 clients in this codebase with DIFFERENT inherited
// defaults: common/httpclient uses 5m -> 48h, while this MASQUE client has always
// used 5s -> x2 -> 5m with a reset on success. option.HTTP3FallbackOptions.Build()
// returns the former, so using it as this client's default would silently change
// the behaviour of every existing MASQUE user. This test pins all four properties
// of the MASQUE default.
func TestClientFallbackBackoffDefaultIsUpstream(t *testing.T) {
	schedule := resolveClientHTTP3Schedule(nil)

	require.Equal(t, 5*time.Second, schedule.InitialBackoff,
		"the MASQUE client's default initial backoff is 5s, not common/httpclient's 5m")
	require.Equal(t, 5*time.Minute, schedule.MaxBackoff,
		"the MASQUE client's default maximum backoff is 5m, not common/httpclient's 48h")
	require.Equal(t, 2.0, schedule.Multiplier)
	require.True(t, schedule.ResetOnSuccess)

	// And the running state machine must produce exactly 5s, 10s, 20s, ... 5m.
	client := newScheduleOnlyClient(schedule)
	expected := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		5 * time.Minute,
		5 * time.Minute,
	}
	for index, want := range expected {
		client.markHTTP3Broken()
		require.Equal(t, want, time.Duration(client.http3Escalation.Load()),
			"unconfigured failure #%d must follow the inherited 5s/x2/5m schedule", index+1)
	}

	// A success resets it back to 5s.
	client.clearHTTP3Broken()
	client.markHTTP3Broken()
	require.Equal(t, 5*time.Second, time.Duration(client.http3Escalation.Load()),
		"a successful HTTP/3 use must reset an unconfigured client to 5s")
}

// TestClientFallbackMultiplierOneIsFixedBackoff covers the multiplier boundary.
//
// multiplier == 1 must mean "fixed backoff", not "jump to max". The previous
// implementation treated next <= current as an overflow and returned max_backoff,
// so multiplier 1 went straight to the ceiling on the first repeat.
func TestClientFallbackMultiplierOneIsFixedBackoff(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 100*time.Millisecond, 10*time.Second, 1, &reset)
	client := newScheduleOnlyClient(schedule)

	for index := range 5 {
		client.markHTTP3Broken()
		require.Equal(t, 100*time.Millisecond, time.Duration(client.http3Escalation.Load()),
			"multiplier=1 must hold the backoff fixed at initial_backoff (iteration %d)", index+1)
	}
}

// TestClientFallbackMultiplierBelowOneFallsBackToDefault rejects a shrinking
// schedule.
func TestClientFallbackMultiplierBelowOneFallsBackToDefault(t *testing.T) {
	reset := true
	schedule := scheduleFrom(t, 100*time.Millisecond, 10*time.Second, 0.5, &reset)
	require.Equal(t, 2.0, schedule.Multiplier,
		"a multiplier below 1 is not a schedule and must fall back to the default")

	schedule = scheduleFrom(t, 100*time.Millisecond, 10*time.Second, 0, &reset)
	require.Equal(t, 2.0, schedule.Multiplier)
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
	require.False(t, client.http3WindowElapsed(), "the window must not be expired immediately")

	// Wait out the window. This is a sub-100ms backoff by construction, so the
	// test is fast while still exercising real time.
	deadline := time.Now().Add(2 * time.Second)
	for !client.http3WindowElapsed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, client.http3WindowElapsed(), "the window must expire after the backoff elapses")
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
	for !client.http3WindowElapsed() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	require.True(t, client.http3WindowElapsed(), "precondition: the window must have expired")

	// A retry fails. The backoff must grow, not restart.
	client.markHTTP3Broken()
	require.Equal(t, 40*time.Millisecond, time.Duration(client.http3Escalation.Load()),
		"an expired window must not discard the escalation history")

	// And again, to prove the growth continues rather than oscillating.
	deadline = time.Now().Add(2 * time.Second)
	for !client.http3WindowElapsed() && time.Now().Before(deadline) {
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
