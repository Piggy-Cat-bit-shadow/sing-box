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

	reported, err := URLTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	// A conforming implementation lands near warmDelay. The bounds are deliberately loose so CI
	// scheduling cannot make this flaky, while still excluding the two wrong answers:
	//   - reporting the cold path (>= coldDelay)
	//   - reporting the sum (>= coldDelay + warmDelay)
	require.Less(t, int(reported), int(coldDelay/time.Millisecond),
		"the reported delay must come from the WARM request, not from the cold path; "+
			"got %dms, which is at or above the %dms cold response", reported, coldDelay/time.Millisecond)

	require.GreaterOrEqual(t, int(reported), int((warmDelay/2)/time.Millisecond),
		"the warm request's own cost must still be present; got %dms", reported)
}

func TestReportedDelayIsNotTheSumOfBothRequests(t *testing.T) {
	const (
		first  = 100 * time.Millisecond
		second = 100 * time.Millisecond
	)

	server := newDelayServer(t, func(int) time.Duration { return first })

	reported, err := URLTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	const sum = 200
	require.Less(t, int(reported), sum-40,
		"reporting ~%dms would mean both requests were accumulated; the warm-up must not count "+
			"towards the result (got %dms)", sum, reported)

	// It must still be a real measurement of the second request, not a constant or zero.
	require.GreaterOrEqual(t, int(reported), int(second/4/time.Millisecond),
		"the result must reflect an actual request duration")
}
