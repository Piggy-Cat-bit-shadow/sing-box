package group

import (
	"context"
	"errors"
	"net"
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

// TestTrafficDialFailureDoesNotDeleteHealthEvidence is §66, §67.
func TestTrafficDialFailureDoesNotDeleteHealthEvidence(t *testing.T) {
	nodeA := &dialFailingOutbound{tag: "node-a", dialErr: errors.New("connection refused")}
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

	// A real connection through node-a fails - because the TARGET refused it.
	outbound := &URLTest{group: group, ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("urltest")}
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

	outbound := &URLTest{group: group, ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("urltest")}
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
