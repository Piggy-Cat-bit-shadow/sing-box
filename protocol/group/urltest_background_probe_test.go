package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Background probes and idle resources.
//
// A URLTest round must not wake a tunnel engine that the idle policy released, and it must not
// destroy that member's health evidence when it finds it asleep. The distinction is made in two
// places and both are pinned here:
//
//   - the measurement context carries the background-probe marker for automatic rounds, so an
//     idle-aware endpoint refuses the dial instead of resuming (invariant 4);
//   - the group treats the resulting sentinel as "not measured" rather than "unhealthy", so a
//     timer firing cannot move the selection.
//
// docs/fork/runtime-lifecycle-phase1.5.md, invariants 4 and 5.

// probeMarkingOutbound records whether the probe that reached it was background work, and fails
// with the suspended sentinel when it was - exactly what the WireGuard endpoint does.
type probeMarkingOutbound struct {
	adapter.Outbound
	tag string

	access       sync.Mutex
	dials        int
	background   int
	dialErr      error
	suspendedErr error
}

func (o *probeMarkingOutbound) Type() string      { return "probe-marking" }
func (o *probeMarkingOutbound) Tag() string       { return o.tag }
func (o *probeMarkingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *probeMarkingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.dials++
	background := adapter.IsBackgroundProbe(ctx)
	if background {
		o.background++
	}
	err := o.dialErr
	suspended := o.suspendedErr
	o.access.Unlock()
	if background && suspended != nil {
		return nil, suspended
	}
	if err != nil {
		return nil, err
	}
	return &stubConn{}, nil
}

func (o *probeMarkingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	_, err := o.DialContext(ctx, N.NetworkUDP, destination)
	return nil, err
}

func (o *probeMarkingOutbound) counts() (dials, background int) {
	o.access.Lock()
	defer o.access.Unlock()
	return o.dials, o.background
}

// A periodic health round is background work, and it does NOT remove a suspended member's health
// evidence.
func TestAutomaticHealthProbeIsMarkedAndSuspendedMembersKeepTheirEvidence(t *testing.T) {
	member := &probeMarkingOutbound{
		tag:          "idle-wg",
		suspendedErr: adapter.ErrResourceSuspended,
	}
	group, storage := newGroupFixture(t, "https://probe.example/generate_204", member)
	scope, err := urltest.NewMeasurementScope("https://probe.example/generate_204", nil)
	require.NoError(t, err)

	// The member has health evidence from before the device went idle.
	previous := &adapter.URLTestHistory{Time: time.Now(), Delay: 42}
	storage.StoreHealthHistory("idle-wg", scope, previous)

	// An automatic round: no probe origin declared, which is the default and therefore background.
	// Forced, because an unforced round would SKIP a member whose evidence is still fresh - which is
	// a different (also correct) behaviour, covered by the interval test below. A forced automatic
	// round is the recheck-after-connection-failure path, and it is still not demand.
	group.CheckOutbounds(context.Background(), true)

	dials, background := member.counts()
	require.Greater(t, dials, 0, "the round must have attempted a measurement")
	require.Equal(t, dials, background,
		"every automatic measurement must be marked as background work, or an idle endpoint would be woken to be measured")

	// The sentinel must not have been recorded as a failure: the evidence is still there, and it is
	// the same value.
	after := storage.LoadURLTestHistoryFor("idle-wg", scope)
	require.NotNil(t, after,
		"a suspended member's health evidence must survive a probe it could not serve")
	require.EqualValues(t, previous.Delay, after.Delay,
		"the evidence must be untouched, not replaced by a failure")
}

// A member whose evidence is still fresh is not measured at all, and that is what preserves it when
// the endpoint is idle: the probe never reaches it.
func TestFreshEvidenceSkipsTheMemberEntirely(t *testing.T) {
	member := &probeMarkingOutbound{tag: "idle-wg"}
	// A non-zero interval is what enables the freshness check.
	group, storage := newGroupFixtureInterval(t, "https://probe.example/generate_204", 30*time.Minute, member)
	scope, err := urltest.NewMeasurementScope("https://probe.example/generate_204", nil)
	require.NoError(t, err)
	previous := &adapter.URLTestHistory{Time: time.Now(), Delay: 42}
	storage.StoreHealthHistory("idle-wg", scope, previous)

	group.CheckOutbounds(context.Background(), false)

	dials, _ := member.counts()
	require.Zero(t, dials, "fresh evidence must skip the member, so an idle endpoint is not touched at all")
	after := storage.LoadURLTestHistoryFor("idle-wg", scope)
	require.NotNil(t, after)
	require.EqualValues(t, 42, after.Delay)
}

// A foreground measurement (a person pressed Test) is not marked: it is demand, and it may wake the
// resource.
func TestForegroundProbeIsNotMarkedAsBackground(t *testing.T) {
	member := &probeMarkingOutbound{tag: "node", suspendedErr: adapter.ErrResourceSuspended}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", member)

	foreground := runtimecoord.ContextWithProbeOrigin(context.Background(), runtimecoord.ProbeForeground)
	group.CheckOutbounds(foreground, true)

	dials, background := member.counts()
	require.Greater(t, dials, 0)
	require.Zero(t, background,
		"a user-initiated measurement is demand and must not be marked as background work")
}

// The sentinel itself: it is a local idle decision, not a path failure, and a caller must be able to
// tell it apart from a network error.
func TestSuspendedSentinelIsNotANetworkError(t *testing.T) {
	require.True(t, adapter.IsResourceSuspended(adapter.ErrResourceSuspended))
	require.False(t, adapter.IsResourceSuspended(net.ErrClosed))
	require.False(t, adapter.IsResourceSuspended(context.Canceled))
	require.False(t, adapter.IsResourceSuspended(errors.New("connection refused")))

	// And it survives wrapping, because transports wrap their errors routinely.
	wrapped := errors.Join(errors.New("dial failed"), adapter.ErrResourceSuspended)
	require.True(t, adapter.IsResourceSuspended(wrapped))
}

// newGroupFixtureInterval is newGroupFixture with a non-zero interval, which enables the freshness
// skip. The plain fixture passes 0, which disables it.
func newGroupFixtureInterval(t *testing.T, link string, interval time.Duration, members ...adapter.Outbound) (*URLTestGroup, *urltest.HistoryStorage) {
	t.Helper()
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	group, err := NewURLTestGroup(
		ctx,
		&stubOutboundManager{},
		log.NewNOPFactory().NewLogger("group"),
		members,
		link,
		interval,
		0,
		0,
		false,
	)
	require.NoError(t, err)
	return group, service.PtrFromContext[urltest.HistoryStorage](ctx)
}
