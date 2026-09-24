package http

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// These tests pin the HTTP/3 avoidance state machine. The three states are
// deliberately distinct, and the single-flight probe belongs ONLY to the third:
//
//	A. never broken          -> every caller uses H3, nobody is "the probe"
//	B. broken, window open   -> every caller uses H2, NOTHING probes
//	C. broken, window expired-> exactly ONE caller probes; the rest use H2
//
// State B is the one that is easy to get backwards. Probing inside the backoff
// window would defeat the backoff entirely, turning a server that is failing
// into a per-request QUIC establishment attempt.

func newProbeDecisionClient(t *testing.T) *Client {
	t.Helper()
	client := newScheduleOnlyClient(option.HTTP3FallbackSchedule{
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     5 * time.Minute,
		Multiplier:     2,
		ResetOnSuccess: true,
	})
	require.NotNil(t, client)
	return client
}

type probeDecision struct {
	useH3   bool
	isProbe bool
}

// runConcurrentDecisions fires n decisions as simultaneously as possible and
// returns the tally, so the single-flight property is tested under real
// concurrency rather than by calling the function in a loop.
func runConcurrentDecisions(t *testing.T, client *Client, n int) (probes, usedH3, onHTTP2 int) {
	t.Helper()
	results := make(chan probeDecision, n)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range n {
		waitGroup.Go(func() {
			<-start
			useH3, isProbe := client.http3ProbeDecision()
			results <- probeDecision{useH3: useH3, isProbe: isProbe}
		})
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for result := range results {
		if result.isProbe {
			probes++
		}
		if result.useH3 {
			usedH3++
		} else {
			onHTTP2++
		}
	}
	return probes, usedH3, onHTTP2
}

// TestProbeDecisionStateAHealthy covers state A: a client that has never failed
// must use HTTP/3 for every caller and must not create a "probe" out of ordinary
// traffic.
func TestProbeDecisionStateAHealthy(t *testing.T) {
	client := newProbeDecisionClient(t)
	require.Zero(t, client.http3BrokenUntil.Load(),
		"precondition: a fresh client has never been marked broken")

	probes, usedH3, onHTTP2 := runConcurrentDecisions(t, client, 64)
	require.Equal(t, 0, probes, "a healthy client has no probe owner")
	require.Equal(t, 64, usedH3, "every healthy caller must use HTTP/3")
	require.Equal(t, 0, onHTTP2, "no healthy caller may be pushed to HTTP/2")
	require.False(t, client.probeActive.Load(),
		"a healthy client must not leave the probe slot held")
}

// TestProbeDecisionStateBBackoffActive is the core regression: while the window
// is open, NOTHING may probe HTTP/3, no matter how many callers arrive or how
// often the probe slot happens to be free.
func TestProbeDecisionStateBBackoffActive(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(time.Hour).UnixNano())
	require.False(t, client.http3WindowElapsed(), "precondition: the window is open")

	probes, usedH3, onHTTP2 := runConcurrentDecisions(t, client, 64)
	require.Equal(t, 0, probes,
		"NOTHING may probe while the backoff window is open; got %d", probes)
	require.Equal(t, 0, usedH3,
		"no caller may use HTTP/3 while the window is open; got %d", usedH3)
	require.Equal(t, 64, onHTTP2, "every caller must go to HTTP/2 immediately")
	require.False(t, client.probeActive.Load(),
		"a backoff must not consume the probe slot")
}

// TestProbeDecisionStateBSequentialRequestsNeverProbe is the sequential form of
// the same rule: a burst could be dismissed as a race, but a serial client
// hammering the same path must also never probe during backoff.
func TestProbeDecisionStateBSequentialRequestsNeverProbe(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(time.Hour).UnixNano())

	for i := range 100 {
		useH3, isProbe := client.http3ProbeDecision()
		require.False(t, useH3, "request %d must use HTTP/2 during backoff", i)
		require.False(t, isProbe, "request %d must not probe during backoff", i)
	}
	require.False(t, client.probeActive.Load(),
		"100 sequential requests must not hold the probe slot")
}

// TestProbeDecisionStateCExpiredSingleFlight covers state C: once the window
// expires, exactly one caller probes while the rest proceed on HTTP/2.
func TestProbeDecisionStateCExpiredSingleFlight(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	require.True(t, client.http3WindowElapsed(), "precondition: the window has expired")

	probes, usedH3, onHTTP2 := runConcurrentDecisions(t, client, 64)
	require.Equal(t, 1, probes, "exactly one recovery probe; got %d", probes)
	require.Equal(t, 1, usedH3, "only the probe owner uses HTTP/3; got %d", usedH3)
	require.Equal(t, 63, onHTTP2, "every other caller uses HTTP/2; got %d", onHTTP2)
}

// TestProbeDecisionStateCNotRepeatedWhileHeld proves the single-flight slot is
// genuinely exclusive: while one probe is in flight, later callers must not
// start more probes.
func TestProbeDecisionStateCNotRepeatedWhileHeld(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())

	useH3, isProbe := client.http3ProbeDecision()
	require.True(t, useH3)
	require.True(t, isProbe, "the first caller after expiry becomes the probe")

	for i := range 10 {
		useH3, isProbe := client.http3ProbeDecision()
		require.False(t, isProbe, "caller %d must not start a second probe", i)
		require.False(t, useH3, "caller %d must use HTTP/2 while the probe is in flight", i)
	}

	client.finishProbe()
	// Only once the probe is released, and while still expired, may another
	// caller take it.
	_, isProbe = client.http3ProbeDecision()
	require.True(t, isProbe, "the slot must be reusable after the probe concludes")
	client.finishProbe()
}

// TestProbeFailureEscalatesAndStopsProbing proves a failed probe both reopens
// the window and stops further probing until that window expires again.
func TestProbeFailureEscalatesAndStopsProbing(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())

	_, isProbe := client.http3ProbeDecision()
	require.True(t, isProbe)
	firstEscalation := client.http3Escalation.Load()
	require.Zero(t, firstEscalation, "the first failure starts from no escalation")

	client.markHTTP3Broken()
	client.finishProbe()

	require.False(t, client.http3WindowElapsed(), "the failure must reopen the window")
	require.NotZero(t, client.http3Escalation.Load(), "the failure must escalate the backoff")
	require.Greater(t, client.http3Escalation.Load(), firstEscalation)

	// The reopened window must again forbid probing.
	for i := range 16 {
		useH3, isProbe := client.http3ProbeDecision()
		require.False(t, useH3, "request %d must not use H3 in the reopened window", i)
		require.False(t, isProbe, "request %d must not probe in the reopened window", i)
	}
}

// TestProbeSuccessRestoresHealthyState proves a successful probe returns the
// client to state A.
func TestProbeSuccessRestoresHealthyState(t *testing.T) {
	client := newProbeDecisionClient(t)
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	client.http3Escalation.Store(int64(time.Minute))

	_, isProbe := client.http3ProbeDecision()
	require.True(t, isProbe)
	client.clearHTTP3Broken()
	client.finishProbe()

	require.Zero(t, client.http3BrokenUntil.Load(), "success clears the deadline")
	require.Zero(t, client.http3Escalation.Load(),
		"reset_on_success clears the escalation history")

	// Back to state A: everyone uses H3, nobody probes.
	probes, usedH3, _ := runConcurrentDecisions(t, client, 32)
	require.Equal(t, 0, probes)
	require.Equal(t, 32, usedH3)
}

// TestProbeSuccessWithoutResetKeepsEscalationHistory covers reset_on_success =
// false: a success clears the window but must NOT clear how far the backoff had
// escalated, so the next failure continues from where it left off.
func TestProbeSuccessWithoutResetKeepsEscalationHistory(t *testing.T) {
	client := newScheduleOnlyClient(option.HTTP3FallbackSchedule{
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     5 * time.Minute,
		Multiplier:     2,
		ResetOnSuccess: false,
	})
	require.NotNil(t, client)

	// Escalate twice so there is a history worth preserving.
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	client.markHTTP3Broken()
	client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	client.markHTTP3Broken()
	escalated := client.http3Escalation.Load()
	require.NotZero(t, escalated)

	// A successful probe clears the window but keeps the history.
	client.clearHTTP3Broken()
	require.Zero(t, client.http3BrokenUntil.Load(), "success clears the window")
	require.Equal(t, escalated, client.http3Escalation.Load(),
		"reset_on_success=false must preserve the escalation history")

	// The next failure therefore continues escalating rather than restarting.
	client.markHTTP3Broken()
	require.Greater(t, client.http3Escalation.Load(), escalated,
		"the next failure must continue from the preserved history")
}

// TestProbeDecisionConcurrentStress runs the decision under -race with a mix of
// expiry, failure and success so the state transitions are exercised while many
// callers contend. It asserts the invariants rather than exact counts, because
// the window legitimately changes underneath the callers.
func TestProbeDecisionConcurrentStress(t *testing.T) {
	client := newProbeDecisionClient(t)

	var probeOwners atomic.Int64
	var violations atomic.Int64

	var waitGroup sync.WaitGroup
	stop := make(chan struct{})

	// Callers: record if two probes are ever held at once.
	for range 8 {
		waitGroup.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				useH3, isProbe := client.http3ProbeDecision()
				if isProbe {
					if probeOwners.Add(1) != 1 {
						violations.Add(1)
					}
					if !useH3 {
						violations.Add(1)
					}
					probeOwners.Add(-1)
					client.finishProbe()
				}
			}
		})
	}

	// State churn: alternate the window between open and expired.
	for range 200 {
		client.markHTTP3Broken()
		client.http3BrokenUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	}
	client.clearHTTP3Broken()
	close(stop)
	waitGroup.Wait()

	require.Zero(t, violations.Load(),
		"at most one probe may be held at a time, and a probe owner must use H3")
	require.False(t, client.probeActive.Load(),
		"the probe slot must be free once every probe concluded")
}
