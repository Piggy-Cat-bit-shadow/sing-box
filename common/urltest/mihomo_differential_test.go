package urltest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Differential test against Mihomo's unified-delay=true result.
//
// # The reference implementation
//
//	start := time.Now()
//	instance, err := DialContext(...)
//	firstResp, err := client.Do(req)
//	if unifiedDelay {
//	    secondStart := time.Now()
//	    secondResp, secondErr := client.Do(req)
//	    if secondErr == nil {
//	        resp = secondResp
//	        start = secondStart
//	    }
//	}
//	delay = time.Since(start)
//
// The contract this test fixes is the RELATIONSHIP between the two request durations and the
// reported value, not a physical constant. With a fake server whose first response takes X and
// whose second takes Y, a conforming implementation reports approximately Y - never
// Dial + X + Y.

func TestReportedDelayApproximatesTheWarmRequestNotTheColdPath(t *testing.T) {
	const (
		coldDelay = 140 * time.Millisecond
		warmDelay = 30 * time.Millisecond
	)

	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return coldDelay
		}
		return warmDelay
	})

	result, phases := measureWithPhases(t, context.Background(), server.url(), directDialer{})

	// A conforming implementation lands near warmDelay. The bound is the warm-up phase's own
	// measured duration rather than a flat constant, so a slow host moves the bound with the
	// measurement; see measureWithPhases. It still excludes both wrong answers, because the
	// warm-up phase contains coldDelay: reporting the cold path, or the sum, is at or above it.
	requireColdPathAbsorbedByTheWarmUp(t, result, phases, coldDelay, "cold response")

	require.GreaterOrEqual(t, int(result.Delay), int((warmDelay/2)/time.Millisecond),
		"the warm request's own cost must still be present; got %dms", result.Delay)
}

func TestReportedDelayIsNotTheSumOfBothRequests(t *testing.T) {
	// The two responses still add up to the same 200ms the flat bound was written against, but
	// they are no longer 100ms each. Equal halves made the relative bound undecidable: the warm-up
	// phase and the measured request were the same length, so "the reported delay is the timed
	// request's, not the sum" could not be told from the numbers - measured over ten runs on a
	// correct implementation, the warm-up phase read 100.5-101.5ms and the reported delay
	// 100-101ms. A cold path that dominates the warm one is what this property needs, and the sum
	// it excludes is unchanged.
	const (
		first  = 150 * time.Millisecond
		second = 50 * time.Millisecond
	)
	const sum = 200

	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return first
		}
		return second
	})

	result, phases := measureWithPhases(t, context.Background(), server.url(), directDialer{})

	// Reporting the sum would land at or above the warm-up phase's own measured duration, which
	// contains `first`; the relative bound excludes it without depending on how long the host
	// takes to answer.
	requireColdPathAbsorbedByTheWarmUp(t, result, phases, first, "first response")

	// It must still be a real measurement of the second request, not a constant or zero.
	require.GreaterOrEqual(t, int(result.Delay), int(second/4/time.Millisecond),
		"the result must reflect an actual request duration")
	require.Less(t, int(result.Delay), sum-40,
		"the two responses are %d ms together; a result near that would mean both were "+
			"accumulated", sum)
}
