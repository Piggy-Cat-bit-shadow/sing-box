package sniff_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Agent F, round 5: attack the two-half predicate that replaced the zero-margin one.
//
// # What is under attack
//
//	sniff_stream_test.go:393  require.Never(t, func() bool { return sniffGoroutinesFromCallback() > before+1 }, ...)
//	sniff_stream_test.go:397  require.Eventually(t, func() bool { return sniffGoroutinesFromCallback() <= before }, ...)
//
// The secondary half allows ONE transient frame (my MEASURED round-4 finding). The primary half requires
// the census to RETURN to the baseline, on the argument that "a leaked goroutine never does".
//
// # The claim that argument makes, and the case it does not cover
//
// `require.Eventually(<= before)` is satisfied by the FIRST evaluation whose condition holds, so it
// proves that the census WAS at the baseline at some point inside a 2 s window - not that it never
// left it. A goroutine that SniffStream leaves behind and which then exits on its own is therefore
// invisible to BOTH halves: the secondary tolerates one extra frame, and the primary merely waits for
// the extra frame to go away.
//
// That is not a hypothetical shape. "PeekStream must not leave a goroutine behind" is a statement about
// the moment the call RETURNS; a worker that outlives the call by a few hundred milliseconds was left
// behind by it, whatever it does afterwards. This file injects exactly that worker and shows both
// halves pass while it is demonstrably alive.
func TestAgentFASelfTerminatingWorkerIsInvisibleToBothHalves(t *testing.T) {
	before := sniffGoroutines()

	// The injected worker: alive for 400 ms after SniffStream would have returned, then gone. It names
	// this package, which is the only property the census looks at.
	const lifetime = 400 * time.Millisecond
	exited := make(chan struct{})
	go func() {
		time.Sleep(lifetime)
		close(exited)
	}()

	// It must be alive and counted before anything is concluded, or this proves nothing.
	require.Eventually(t, func() bool { return sniffGoroutines() == before+2 },
		2*time.Second, 5*time.Millisecond,
		"the injected worker plus this callback frame must read baseline+2; without that the worker "+
			"was never observable and the rest of this test is empty")

	// --- the SECONDARY half, in the production shape: 200 ms at 20 ms ticks ---
	secondaryFired := false
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		done := make(chan bool, 1)
		go func() { done <- sniffGoroutinesFromCallback() > before+1 }()
		if <-done {
			secondaryFired = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// --- the PRIMARY half, verbatim: the census must return to the baseline inside 2 s ---
	primaryPassed := assert.Eventually(t, func() bool { return sniffGoroutinesFromCallback() <= before },
		2*time.Second, 20*time.Millisecond)

	select {
	case <-exited:
	default:
		t.Fatal("the worker had not exited; this test is only about a worker that DOES exit")
	}

	t.Logf("MEASURED one worker left behind for %s: secondary fired=%v, primary passed=%v, "+
		"final census=%d (baseline %d)", lifetime, secondaryFired, primaryPassed,
		sniffGoroutines(), before)

	require.False(t, secondaryFired,
		"the one-frame allowance is supposed to tolerate a single extra frame; if this fires the "+
			"secondary half is stricter than the fix claims and this finding is retracted")
	require.True(t, primaryPassed,
		"the primary half is expected to PASS here - that is the finding: it confirms the census "+
			"returned to the baseline, which it did, because the left-behind worker exited by itself")
}

// TestAgentFAWorkerThatOutlivesTheWindowIsCaught is the control for the finding above: the same worker
// held open past the primary's window must fail it, so the blind spot is a bounded lifetime and not a
// broken instrument.
func TestAgentFAWorkerThatOutlivesTheWindowIsCaught(t *testing.T) {
	before := sniffGoroutines()

	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	go func() {
		entered <- struct{}{}
		<-gate
	}()
	<-entered

	// A worker held open forever is exactly the case the primary half exists for. Its window is 2 s,
	// so a 300 ms window here is enough to show the condition never holds while the worker lives.
	// A plain loop, not assert.Eventually: a probe that EXPECTS the condition never to hold cannot use
	// a helper that reports its own failure when the condition never holds.
	held := false
	probeDeadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(probeDeadline) {
		done := make(chan bool, 1)
		go func() { done <- sniffGoroutinesFromCallback() <= before }()
		if <-done {
			held = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.False(t, held,
		"a worker held open must keep the census above the baseline for the whole window; if the "+
			"primary half passed here it is vacuous and the fix proves nothing")

	close(gate)
	require.Eventually(t, func() bool { return sniffGoroutinesFromCallback() <= before },
		2*time.Second, 20*time.Millisecond,
		"and the census must return once the worker is released, or the correction is wrong")
	t.Logf("MEASURED a worker held open: the primary half is not satisfied during a 300 ms window, "+
		"and the census returns to %d once released", before)
}
