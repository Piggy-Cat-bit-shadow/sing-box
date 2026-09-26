package http

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// The unauthenticated limiter must key on the source IP, and a NAT rebind must not
// mint a fresh budget.
//
// TestUnauthenticatedLimiterIgnoresPort already covers the plain case: three requests
// from one IP on three ports share one bucket. What this file adds is the REGRESSION
// SHAPE, which is what a NAT actually does and what an attacker would do on purpose:
//
//	same source IP, a NEW source port, repeatedly
//
// measured against the limits the production minimal topology actually configures.
//
// # The rates are read from the option semantics, not assumed
//
// An earlier attempt at the live version of this set requests_per_second to 0
// expecting "no refill". That is wrong, and option/http_unauthenticated_limits.go
// says why: Build() treats every non-positive field as UNSET and substitutes the
// default, so 0 becomes DefaultUnauthenticatedRPS (10/s) and burst 0 would become
// DefaultUnauthenticatedBurst (20). The budget then refills between probes and the
// limiter legitimately admits the second request - which reads as a keying defect and
// is a fixture mistake. TestLimiterOptionsTreatZeroAsUnset pins that behaviour
// explicitly so the mistake cannot be made silently again.

// TestLimiterOptionsTreatZeroAsUnset documents the option semantics the rate choice
// above depends on.
//
// It is a regression on the OPTION layer rather than on the limiter: if a future
// change made 0 mean "no refill", a test that relied on 0 would start measuring
// something different, and this test would fail first and explain why.
func TestLimiterOptionsTreatZeroAsUnset(t *testing.T) {
	built := (&option.UnauthenticatedLimitsOptions{Enabled: true}).Build()
	require.Equal(t, option.DefaultUnauthenticatedRPS, built.RequestsPerSecond,
		"requests_per_second 0 must mean UNSET and become the default, not \"no refill\"")
	require.Equal(t, option.DefaultUnauthenticatedBurst, built.Burst)
	require.Equal(t, option.DefaultUnauthenticatedMaxConcurrent, built.MaxConcurrentPerIP)
	require.Equal(t, time.Duration(option.DefaultUnauthenticatedIdleTimeout), built.IdleTimeout)
	require.Equal(t, option.DefaultUnauthenticatedMaxTrackedIPs, built.MaxTrackedIPs)

	// A negative value is treated the same way, which is worth stating because
	// "-1 means unlimited" is a common convention this option does NOT follow.
	negative := (&option.UnauthenticatedLimitsOptions{
		Enabled:           true,
		RequestsPerSecond: -1,
		Burst:             -1,
	}).Build()
	require.Equal(t, option.DefaultUnauthenticatedRPS, negative.RequestsPerSecond,
		"a negative requests_per_second must fall back to the default, NOT mean unlimited")
	require.Equal(t, option.DefaultUnauthenticatedBurst, negative.Burst)
}

// TestUnauthenticatedLimiterSurvivesRepeatedPortChurn is the regression.
//
// One source IP churns its port ten times. With a rate slow enough that nothing
// refills within the test, only the first request may be admitted; every later one
// must be refused. A limiter keyed on address:port would admit all ten.
func TestUnauthenticatedLimiterSurvivesRepeatedPortChurn(t *testing.T) {
	// Positive values, so Build() keeps them as written: one token per 1000 seconds,
	// burst 1, and an idle timeout far longer than the test.
	limits := (&option.UnauthenticatedLimitsOptions{
		Enabled:            true,
		RequestsPerSecond:  0.001,
		Burst:              1,
		MaxConcurrentPerIP: 1,
		IdleTimeout:        badoption.Duration(10 * time.Minute),
		MaxTrackedIPs:      16,
	}).Build()
	require.Equal(t, 0.001, limits.RequestsPerSecond,
		"the fixture must keep the rate it configured, or the test measures the default")
	require.Equal(t, 1, limits.Burst)

	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	// The first request from the IP consumes the only token.
	require.True(t, limiter.allowed("203.0.113.7:40000", now),
		"the first request must be admitted; there is a budget to spend")

	// Now churn the port. Every one of these is the same peer.
	for _, port := range []int{40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009} {
		source := "203.0.113.7:" + itoa(port)
		require.False(t, limiter.allowed(source, now),
			"a request from %s must be refused: it is the SAME source IP as the one that "+
				"already spent the budget, and only the port changed. Admitting it means "+
				"the limiter keys on address:port, so any peer - and any NAT - can mint "+
				"unlimited unauthenticated budget by churning its source port", source)
	}

	require.Equal(t, 1, limiter.trackedCount(),
		"all ten ports of one IP must share exactly ONE limiter entry")
}

// TestUnauthenticatedLimiterPortChurnDoesNotMultiplyConcurrency is the same
// regression for the concurrency bound rather than the token bucket.
//
// A peer that is already at max_concurrent_per_ip must not be able to open a second
// concurrent slot by changing its port. The two bounds are separate fields and a
// change that made only the token bucket port-insensitive would leave this one open.
func TestUnauthenticatedLimiterPortChurnDoesNotMultiplyConcurrency(t *testing.T) {
	limits := (&option.UnauthenticatedLimitsOptions{
		Enabled:            true,
		RequestsPerSecond:  1000, // Plenty of tokens, so ONLY the concurrency bound bites.
		Burst:              1000,
		MaxConcurrentPerIP: 1,
		IdleTimeout:        badoption.Duration(10 * time.Minute),
		MaxTrackedIPs:      16,
	}).Build()

	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	release, allowed := limiter.acquire("203.0.113.7:40000", now)
	require.True(t, allowed, "the first request must be admitted")

	// A concurrent request from the SAME IP on a different port must be refused.
	releaseSecond, allowedSecond := limiter.acquire("203.0.113.7:40001", now)
	require.False(t, allowedSecond,
		"a second CONCURRENT request from the same IP on a different port must be "+
			"refused: max_concurrent_per_ip is 1 and the port must not create a second "+
			"slot")
	releaseSecond()

	// Releasing the first frees the slot for the same IP, on any port.
	release()
	releaseThird, allowedThird := limiter.acquire("203.0.113.7:40002", now)
	require.True(t, allowedThird,
		"once the slot is released the same IP must be admissible again, whatever "+
			"port it uses")
	releaseThird()

	require.Equal(t, 1, limiter.trackedCount(),
		"three ports of one IP must share exactly ONE limiter entry")
}

// TestUnauthenticatedLimiterTrackedSourceIsTheBareIP states the key directly.
//
// It is the narrowest possible form of the invariant, so a failure here points at
// normalizedIP rather than at the bucket arithmetic.
func TestUnauthenticatedLimiterTrackedSourceIsTheBareIP(t *testing.T) {
	for _, testCase := range []struct {
		source string
		want   string
	}{
		{"203.0.113.7:40000", "203.0.113.7"},
		{"203.0.113.7:1", "203.0.113.7"},
		{"203.0.113.7:65535", "203.0.113.7"},
		{"[2001:db8::1]:40000", "2001:db8::1"},
		{"[2001:db8::1]:1", "2001:db8::1"},
		{"[::ffff:203.0.113.7]:40000", "203.0.113.7"},
	} {
		t.Run(testCase.source, func(t *testing.T) {
			address, valid := normalizedIP(testCase.source)
			require.True(t, valid, "the source must normalize: %s", testCase.source)
			require.Equal(t, testCase.want, address.String(),
				"the limiter key must be the source IP with NO port and NO v4-mapped "+
					"prefix, so a port change can never create a new bucket")
		})
	}
}

// itoa is a tiny local integer formatter, so this file does not need strconv for one
// call site.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [8]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
