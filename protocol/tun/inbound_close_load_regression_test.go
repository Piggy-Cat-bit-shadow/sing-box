package tun

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Fast teardown under load, exercised on the real Inbound.Close path.
//
// # What this file is and is not
//
// TASK 2.B asks for a Box.Close under a loaded Box: several endpoints, a URL-test round, DNS
// activity, a pending recovery, a blocked flow and a WireGuard/MASQUE resource, all live when Close
// arrives. That whole scene cannot be built here: it needs real listeners and the integration
// harness that lives in the separate `test/` module (which root `go test ./...` does not run), and
// two of the resources named are owned by other agents. Building it out of fakes that the test
// itself defines would prove only that the fakes stop, which is the vacuous test this file exists to
// avoid.
//
// What CAN be built is the part of that scene that is real production code in this package: the TUN
// inbound, with a live Go stack, several accepted-but-blackholed TCP flows, and the exact teardown
// sequence Box.Close drives. The assertions below are therefore about `Inbound.Close` and
// `Inbound.InterfaceUpdated`, not about a stand-in.

// TestInboundCloseUnderBlackholeLoadIsBoundedAndTerminal drives the real teardown path with several
// flows stuck in the blackhole state, then keeps provoking the inbound after Close to prove nothing
// can be restarted.
//
// # Why each assertion is here
//
// Bounded: the daemon's stop path has a deadline, so a Close that can block indefinitely turns one
// wedged flow into a wedged app. The test gives Close three seconds and fails if it needs more.
//
// Baseline goroutines: every accepted flow owns a goroutine in the stack plus one in the handler.
// Close has to unwind them; a teardown that returns while they run is a wake-lock bug.
//
// Terminal: the transition callback and the stack reset are the two ways the system tells a live
// stack "the world changed". After Close they must be inert. This is the "nothing can be
// resurrected" half of TASK 2.B, asserted on behaviour (no new frames, no new accepts) rather than
// on a flag.
func TestInboundCloseUnderBlackholeLoadIsBoundedAndTerminal(t *testing.T) {
	baseline := settleGoroutines()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	harness := newBlackholeStack(t, ctx)

	// The Inbound is assembled around the already-started stack rather than through Start, which
	// would create a real platform interface. Close and InterfaceUpdated are the methods under
	// test and neither of them reads any other field.
	inbound := &Inbound{
		ctx:      ctx,
		tunStack: harness.stack,
		tunIf:    harness.device,
	}

	const flows = 6
	for index := range flows {
		harness.emit(t, uint16(43000+index), uint16(30000+index))
	}
	require.EqualValues(t, flows, harness.handler.acceptCount.Load())
	require.Greater(t, runtime.NumGoroutine(), baseline,
		"the flows under load must have added goroutines, or this test cannot detect a leak")

	started := time.Now()
	closeReturned := make(chan error, 1)
	go func() {
		closeReturned <- inbound.Close()
	}()
	select {
	case err := <-closeReturned:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Inbound.Close did not return within its deadline under load")
	}
	require.Less(t, time.Since(started), 3*time.Second)

	for index := range flows {
		require.Error(t, harness.waitForRead(t, uint16(30000+index), 2*time.Second),
			"flow %d survived the teardown", index)
	}

	// Nothing resurrected after Close. A network transition and a stack reset are exactly the
	// events that start work on a live stack, so they are driven here after the close.
	settledFrames := harness.outbound.Load()
	settledAccepts := harness.handler.acceptCount.Load()

	inbound.InterfaceUpdated(context.Background())
	harness.stack.ResetNetwork()

	// A new flow cannot even enter: the link the device writes into is closed.
	_, err := harness.device.WritePackets([][]byte{blackholeSYN(
		netip.MustParseAddr("198.18.0.2"), 44000,
		netip.MustParseAddr("1.1.1.1"), 40000,
	)})
	require.ErrorIs(t, err, os.ErrClosed)

	time.Sleep(300 * time.Millisecond)
	require.Equal(t, settledFrames, harness.outbound.Load(),
		"the stack emitted frames after Close was provoked with a transition and a reset")
	require.Equal(t, settledAccepts, harness.handler.acceptCount.Load(),
		"a flow was accepted after Close")

	// Close is idempotent, so a second teardown must not re-walk anything or error.
	require.NoError(t, inbound.Close())

	deadline := time.Now().Add(3 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not return to the baseline of %d (now %d) after teardown",
				baseline, runtime.NumGoroutine())
		}
		time.Sleep(25 * time.Millisecond)
	}
}
