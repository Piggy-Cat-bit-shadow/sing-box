package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the health recheck a traffic failure requests.
//
// # The two defects these pin
//
// A failed business connection cleared the selection and asked for a health recheck with force =
// false. Because the node's measurement was still fresh, the batch SKIPPED it - so no probe ran at
// all, and the following selection simply re-evaluated the same history. The node that had just
// failed to carry traffic was eligible to be chosen again on the strength of the measurement that
// had already been contradicted.
//
// The recheck also had no worker-level single-flight. Every failing connection started its own
// goroutine, so a burst produced a burst of goroutines even though the measurement itself collapsed
// to one. On a mobile device that is the traffic pattern a health check exists to avoid.

// recheckCountingOutbound counts how many times it is actually probed.
type recheckCountingOutbound struct {
	adapter.Outbound
	tag     string
	probes  atomic.Int32
	dialErr error
}

func (o *recheckCountingOutbound) Type() string      { return "stub" }
func (o *recheckCountingOutbound) Tag() string       { return o.tag }
func (o *recheckCountingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *recheckCountingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.probes.Add(1)
	if o.dialErr != nil {
		return nil, o.dialErr
	}
	return &stubConn{}, nil
}

func (o *recheckCountingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.probes.Add(1)
	if o.dialErr != nil {
		return nil, o.dialErr
	}
	return &stubPacketConn{}, nil
}

// TestTrafficFailureForcesAHealthRecheck is §4.
//
// The node's measurement is fresh. A traffic failure must still cause a real probe; otherwise the
// recheck is a no-op and selection re-reads the very evidence the failure just contradicted.
func TestTrafficFailureForcesAHealthRecheck(t *testing.T) {
	node := &recheckCountingOutbound{tag: "node-a"}

	group, storage := newGroupFixture(t, "https://probe.example/generate_204", node)

	// A FRESH measurement: the batch would normally skip this node.
	storage.StoreURLTestHistoryFor("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	require.Equal(t, int32(0), node.probes.Load())

	group.selected.Store(&selectedState{tcp: node, udp: node})

	// A business connection fails through this node.
	group.clearSelectionFor(N.NetworkTCP, node)

	// The recheck runs in the background; wait for it to actually probe.
	require.Eventually(t, func() bool { return node.probes.Load() > 0 },
		3*time.Second, 5*time.Millisecond,
		"a traffic failure must force a real health probe; with force=false the fresh measurement "+
			"is skipped, so nothing is re-measured and selection re-reads the evidence the failure "+
			"just contradicted")
}

// TestRecheckSingleFlightCollapsesABurst is §5.
//
// Many concurrent traffic failures must not create many recheck goroutines.
func TestRecheckSingleFlightCollapsesABurst(t *testing.T) {
	// The probe blocks, so the recheck stays in flight while the burst arrives.
	release := make(chan struct{})
	node := &blockingRecheckOutbound{tag: "node-a", release: release}

	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	const burst = 100
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < burst; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			group.requestHealthRecheck()
		}()
	}
	close(start)
	waitGroup.Wait()

	// Let the single in-flight probe finish.
	close(release)
	require.Eventually(t, func() bool { return node.probes.Load() >= 1 },
		3*time.Second, 5*time.Millisecond)

	// The assertion is on WORKERS, not probes.
	//
	// Counting probes would pass either way: the health function's own `checking` guard already
	// collapses concurrent measurements, so a per-failure goroutine still produces one probe. What
	// that design does produce is one short-lived goroutine per failure, which is what this pins.
	require.Equal(t, int32(1), group.recheckRuns.Load(),
		"%d concurrent traffic failures must start exactly ONE recheck worker; starting a "+
			"goroutine per failure creates a burst of short-lived goroutines on every flap", burst)

	require.Equal(t, int32(1), node.probes.Load(),
		"and that one worker must perform one health round, not one per failure")
}

// blockingRecheckOutbound blocks its probe until released, so a recheck stays in flight.
type blockingRecheckOutbound struct {
	adapter.Outbound
	tag     string
	probes  atomic.Int32
	release chan struct{}
}

func (o *blockingRecheckOutbound) Type() string      { return "stub" }
func (o *blockingRecheckOutbound) Tag() string       { return o.tag }
func (o *blockingRecheckOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *blockingRecheckOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.probes.Add(1)
	select {
	case <-o.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &stubConn{}, nil
}

func (o *blockingRecheckOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

var _ = urltest.MeasurementScope{}
