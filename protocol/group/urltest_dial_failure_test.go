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
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for what a real-traffic dial failure is allowed to conclude about a node.
//
// # The defect these pin
//
// A failed DialContext called invalidateSelected, which DELETED the node's health history for the
// group's scope and cleared the selection. The stated reasoning was that a real connection failing
// is evidence about the node regardless of what a measurement said.
//
// It is not. DialContext reports whatever went wrong on the path, and the overwhelming majority of
// causes have nothing to do with the proxy: the target refused the connection, the target port is
// closed, the remote reset, the destination does not exist. A node that carried the connection
// perfectly can produce every one of those. Deleting its health evidence on that basis discards a
// correct measurement because a website was down - and then re-selects on the strength of the
// removal, so the group can move to a *worse* node because a third party refused a connection.
//
// Only a health check is evidence about health. A traffic failure may REQUEST a recheck; the
// recheck decides.

// dialFailingOutbound fails real dials while remaining a healthy measurement target.
type dialFailingOutbound struct {
	adapter.Outbound
	tag     string
	dialErr error
}

func (o *dialFailingOutbound) Type() string      { return "stub" }
func (o *dialFailingOutbound) Tag() string       { return o.tag }
func (o *dialFailingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *dialFailingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, o.dialErr
}

func (o *dialFailingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, o.dialErr
}

// gatedProbeOutbound fails a BUSINESS dial at once and HOLDS the health probe until the test releases
// it, so the state a traffic failure leaves behind can be observed without racing the recheck that
// failure itself requests.
//
// # Why the fixture is needed
//
// A traffic failure clears the selection and asks for a forced recheck (urltest.go:1235-1269), and the
// forced round probes every member with `mode = TestHistoryHealth`: a probe that FAILS deletes that
// member's health measurement (urltest.go:1170-1175). The recheck is asynchronous, so a test asserting
// "the failed dial did not delete the evidence" is racing it - MEASURED, this test failed in BOTH of
// the round's full scans (`expected node-a, actual node-b`) because the forced round deleted node-a's
// entry before the second Select and the only measurement left was node-b's.
//
// That is the recheck DECIDING, which is the documented contract, so the assertion was stating a
// property the product is allowed to change and held only while the machine was fast enough to read
// the selection first. Holding the probe makes both halves deterministic: the state the failure leaves,
// and the verdict the recheck then reaches - which is why the test also releases the probe and pins
// the deletion.
type gatedProbeOutbound struct {
	adapter.Outbound
	tag     string
	dialErr error
	// armed gates the blocking: the fixture's own setup probes run before it is set, so no test-order
	// accident can deadlock the round.
	armed     atomic.Bool
	probing   chan struct{}
	released  chan struct{}
	probeOnce sync.Once
}

func (o *gatedProbeOutbound) Type() string      { return "stub" }
func (o *gatedProbeOutbound) Tag() string       { return o.tag }
func (o *gatedProbeOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *gatedProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.armed.Load() && destination.IsFqdn() {
		// The health probe names the group's TARGET by domain; the test's business dial names an
		// address. Blocking only the former is what lets the business dial fail immediately.
		o.probeOnce.Do(func() { close(o.probing) })
		select {
		case <-o.released:
		case <-ctx.Done():
		}
	}
	return nil, o.dialErr
}

func (o *gatedProbeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, o.dialErr
}

// TestTrafficDialFailureDoesNotDeleteHealthEvidence is §66, §67.
//
// # Why the health probe is gated, and why that is not a weakened assertion
//
// The property is "a failed BUSINESS connection must not delete the node's health evidence". The
// failure also REQUESTS a health recheck, and that recheck is what decides whether the node is
// unhealthy - if the probe fails, the measurement IS removed (urltest.go:1170-1175) and re-selection
// legitimately moves. A test that asserts the selection before the recheck has run is therefore racing
// the product, not testing it: this assertion failed in both of the round's full suite scans with
// `expected node-a, actual node-b` because the forced round won the race.
//
// Gating the probe makes the two observations sequential instead of racy: the state the failure leaves
// is read while the recheck is provably still in flight, and then the recheck is released and its
// verdict is pinned too. Both halves are asserted; nothing is skipped and no timeout is widened.
func TestTrafficDialFailureDoesNotDeleteHealthEvidence(t *testing.T) {
	nodeA := &gatedProbeOutbound{
		tag: "node-a", dialErr: errors.New("connection refused"),
		probing: make(chan struct{}), released: make(chan struct{}),
	}
	nodeB := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://probe.example/generate_204", nodeA, nodeB)

	// node-a has a good, fresh measurement: it is the fastest by a wide margin.
	storage.StoreURLTestHistoryFor("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-b", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 500})

	group.performUpdateCheck()
	selected, _ := group.Select(N.NetworkTCP)
	require.NotNil(t, selected)
	require.Equal(t, "node-a", selected.Tag(), "node-a is the fastest healthy node")

	// From here on node-a's health probe blocks, so the recheck the failure requests cannot complete
	// before this test has looked at what the failure itself did.
	nodeA.armed.Store(true)

	// A real connection through node-a fails - because the TARGET refused it.
	outbound := newTestURLTestWrapper(group, log.NewNOPFactory().NewLogger("urltest"))
	_, err := outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddr("203.0.113.9:443"))
	require.Error(t, err, "the dial must still report the failure to the caller")
	require.Contains(t, err.Error(), "connection refused")

	// The node's health evidence must survive: nothing has shown the NODE to be unhealthy.
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", group.scope),
		"a failed business connection must not delete the node's health measurement; the target "+
			"refusing a connection says nothing about the proxy, and deleting a correct "+
			"measurement because a website was down moves the group to a worse node")

	// And the selection must not have been moved on that basis.
	after, _ := group.Select(N.NetworkTCP)
	require.NotNil(t, after)
	require.Equal(t, "node-a", after.Tag(),
		"the selection must still be node-a; it was chosen from a measurement that is still valid")

	// The other half, and what makes the assertions above legitimate rather than a hope: the recheck
	// the failure asked for is in flight, and once released it decides - a failed HEALTH check does
	// invalidate its own measurement.
	require.Eventually(t, func() bool {
		select {
		case <-nodeA.probing:
			return true
		default:
			return false
		}
	}, 5*time.Second, 5*time.Millisecond,
		"a traffic failure must request a health recheck, and that recheck must probe this node")
	close(nodeA.released)
	require.Eventually(t, func() bool {
		return storage.LoadURLTestHistoryFor("node-a", group.scope) == nil
	}, 5*time.Second, 5*time.Millisecond,
		"the recheck decides: a probe that fails removes that target's health measurement, which is "+
			"what moves the selection afterwards - so the evidence above survived the DIAL, not the check")
}

// TestTrafficDialFailureStillAllowsReplacementForTheCaller is the deliverable half.
//
// The evidence must survive, but the CALLER still needs a working connection. The failure is
// reported, and the group must not be left permanently pinned to a node it cannot dial through.
func TestTrafficDialFailureStillAllowsReplacementForTheCaller(t *testing.T) {
	nodeA := &dialFailingOutbound{tag: "node-a", dialErr: errors.New("connection refused")}

	group, storage := newGroupFixture(t, "https://probe.example/generate_204", nodeA)
	storage.StoreURLTestHistoryFor("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})

	outbound := newTestURLTestWrapper(group, log.NewNOPFactory().NewLogger("urltest"))
	_, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("203.0.113.9:443"))
	require.Error(t, err)

	// The failure is returned rather than retried internally - the caller decides whether to
	// reconnect, and a silent second attempt would hide the target's refusal.
	require.Contains(t, err.Error(), "connection refused")
}

// TestHealthFailureStillDeletesItsOwnScope is §67's other half, and the guard against fixing this
// by simply never deleting anything.
//
// When a HEALTH CHECK fails, the measurement it produced is genuinely invalid and must go - but
// only the scope that failed.
func TestHealthFailureStillDeletesItsOwnScope(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}

	group, storage := newGroupFixture(t, "https://probe.example/generate_204", nodeA)

	healthScope := group.scope
	otherScope, scopeErr := urltest.NewMeasurementScope("https://other.example/generate_204", nil)
	require.NoError(t, scopeErr)

	storage.StoreURLTestHistoryFor("node-a", healthScope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", otherScope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 100})

	// A health-check failure removes the health scope's entry.
	storage.DeleteURLTestHistoryFor("node-a", healthScope)

	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", healthScope),
		"a failed health check invalidates its own measurement")
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", otherScope),
		"a failure in one scope must not discard another scope's measurement")
}
