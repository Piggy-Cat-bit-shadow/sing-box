package group

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Tests for the URLTest group's scoped selection and atomic published state.

// stubOutbound is a group member that records dial attempts and can be made to fail.
//
// typeName lets a test state the member's KIND, which the global-penalty classifier consults:
// a direct member dials the destination itself, so its errno describes the destination, while
// every proxy member's synchronous error is a first hop of its own. An empty name is reported
// as "stub", a proxy-like member, which is what the older tests expect.
type stubOutbound struct {
	adapter.Outbound
	tag      string
	typeName string
	dialErr  error
	dialed   int
	dialLock sync.Mutex
}

func (o *stubOutbound) Type() string {
	if o.typeName != "" {
		return o.typeName
	}
	return "stub"
}
func (o *stubOutbound) Tag() string       { return o.tag }
func (o *stubOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *stubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialLock.Lock()
	o.dialed++
	err := o.dialErr
	o.dialLock.Unlock()
	if err != nil {
		return nil, err
	}
	return &stubConn{}, nil
}

func (o *stubOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.dialLock.Lock()
	o.dialed++
	err := o.dialErr
	o.dialLock.Unlock()
	if err != nil {
		return nil, err
	}
	return &stubPacketConn{}, nil
}

func (o *stubOutbound) dialCount() int {
	o.dialLock.Lock()
	defer o.dialLock.Unlock()
	return o.dialed
}

type stubConn struct{ net.Conn }

func (c *stubConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { return nil }
func (c *stubConn) LocalAddr() net.Addr              { return nil }
func (c *stubConn) RemoteAddr() net.Addr             { return nil }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

type stubPacketConn struct{ net.PacketConn }

func (c *stubPacketConn) Close() error { return nil }

// newGroupFixture builds a URLTestGroup over the given members with a real HistoryStorage.

// newTestURLTestWrapper builds a wrapper around an existing group, with the group published the way
// Start publishes it. It exists because the group pointer is now atomic rather than a plain field.
func newTestURLTestWrapper(group *URLTestGroup, logger log.ContextLogger) *URLTest {
	wrapper := &URLTest{ctx: context.Background(), logger: logger}
	wrapper.group.Store(group)
	return wrapper
}

func newGroupFixture(t *testing.T, link string, members ...adapter.Outbound) (*URLTestGroup, *urltest.HistoryStorage) {
	t.Helper()
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	group, err := NewURLTestGroup(
		ctx,
		&stubOutboundManager{},
		log.NewNOPFactory().NewLogger("group"),
		members,
		link,
		0,
		0,
		0,
		false,
	)
	require.NoError(t, err)
	return group, service.PtrFromContext[urltest.HistoryStorage](ctx)
}

// stubOutboundManager satisfies the manager the group constructor requires.
type stubOutboundManager struct {
	adapter.OutboundManager
}

func (m *stubOutboundManager) Outbounds() []adapter.Outbound { return nil }
func (m *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return nil, false
}

// --- scope-aware selection (§19, §20, §45) ---------------------------------------------

func TestGroupSelectsOnlyFromItsOwnScope(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/generate_204", nodeA, nodeB)

	// Measurements exist, but against a DIFFERENT target - and they rank the SECOND member as by
	// far the fastest. If the group consulted them it would select node-b on that basis.
	otherScope, err := urltest.NewMeasurementScope("https://b.example/generate_204", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", otherScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 900})
	storage.StoreURLTestHistoryFor("node-b", otherScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 5})

	selected, _ := group.Select(N.NetworkTCP)
	require.NotNil(t, selected,
		"with no measurement of its own target the group falls back to a member, so a connection "+
			"can still be attempted while the first measurement runs")
	require.Equal(t, "node-a", selected.Tag(),
		"selection must ignore a result measured against a different target; using it would have "+
			"picked node-b on the strength of the other target's 5ms")

	// The fallback is what returned node-a, not the foreign delay: the group's own scope is empty.
	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", group.scope))
	require.Nil(t, storage.LoadURLTestHistoryFor("node-b", group.scope))
}

func TestGroupSelectsFromItsOwnScope(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/generate_204", nodeA, nodeB)

	ownScope, err := urltest.NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	// An empty link and the explicit default both normalise to the same target, so this also
	// proves the group's scope matches the canonical form.
	storage.StoreURLTestHistoryFor("node-a", ownScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 90})
	storage.StoreURLTestHistoryFor("node-b", ownScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 30})

	selected, exists := group.Select(N.NetworkTCP)
	require.True(t, exists)
	require.Equal(t, "node-b", selected.Tag(), "the group must pick the faster node from its own scope")
}

func TestGroupScopeUsesTheCanonicalTarget(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}

	// Constructed with an empty link, which means the default target.
	group, storage := newGroupFixture(t, "", nodeA)

	defaultScope, err := urltest.NewMeasurementScope("", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", defaultScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 25})

	selected, exists := group.Select(N.NetworkTCP)
	require.True(t, exists, "the empty link must resolve to the same scope as the explicit default")
	require.Equal(t, "node-a", selected.Tag())
}

func TestGroupRejectsAnInvalidTarget(t *testing.T) {
	// An unusable target must fail at construction, not three minutes later when every
	// measurement silently fails.
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	_, err := NewURLTestGroup(
		ctx,
		&stubOutboundManager{},
		log.NewNOPFactory().NewLogger("group"),
		[]adapter.Outbound{&stubOutbound{tag: "node-a"}},
		"ftp://example.com/test",
		0, 0, 0, false,
	)
	require.Error(t, err, "an unusable URL test target must be refused at construction")
}

// --- interval skipping is scoped (§45) -------------------------------------------------

func TestBatchDoesNotSkipBasedOnAnotherScope(t *testing.T) {
	// A fresh result against target A must not cause target B's test to be skipped. This is the
	// regression that made a group appear healthy while never measuring its own target.
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	storage := service.PtrFromContext[urltest.HistoryStorage](ctx)

	nodeA := &stubOutbound{tag: "node-a", dialErr: errStubDial}

	scopeA, err := urltest.NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: 15,
	})

	// Run a batch against target B with a long interval and force=false. The fresh result for
	// target A must not suppress it.
	linkB := "https://b.example/generate_204"
	before := nodeA.dialCount()
	URLTestOutbounds(ctx, &stubOutboundManager{}, storage,
		log.NewNOPFactory().NewLogger("batch"), []adapter.Outbound{nodeA}, linkB, time.Hour, false)

	require.Greater(t, nodeA.dialCount(), before,
		"the node must be measured for target B even though target A has a fresh result")
}

func TestBatchSkipsWhenItsOwnScopeIsFresh(t *testing.T) {
	// The inverse: a fresh result for the SAME target may skip, which is the behaviour the
	// interval exists for.
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	storage := service.PtrFromContext[urltest.HistoryStorage](ctx)

	nodeA := &stubOutbound{tag: "node-a"}

	link := "https://a.example/generate_204"
	scope, err := urltest.NewMeasurementScope(link, nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", scope, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: 15,
	})

	before := nodeA.dialCount()
	URLTestOutbounds(ctx, &stubOutboundManager{}, storage,
		log.NewNOPFactory().NewLogger("batch"), []adapter.Outbound{nodeA}, link, time.Hour, false)

	require.Equal(t, before, nodeA.dialCount(),
		"a fresh result for the same target may be reused instead of re-measured")
}

// --- published state is one generation (§23, §24, §25, §47) ----------------------------

func TestSelectedStateIsPublishedAsOneGeneration(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeA, nodeB)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})

	group.performUpdateCheck()

	state := group.selected.Load()
	require.NotNil(t, state)
	require.NotNil(t, state.tcp, "the update must publish a TCP choice")
	require.Equal(t, "node-a", state.tcp.Tag())
}

func TestSelectedStateIsRaceFreeUnderConcurrentAccess(t *testing.T) {
	// Real traffic reads the selection while the background check replaces it. Before the state
	// was a single atomic pointer this was a data race between writing two interface fields and
	// reading them.
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeA, nodeB)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	group.performUpdateCheck()

	// Channels coordinate the goroutines instead of sleeps, so the interleaving is real rather
	// than hoped for.
	start := make(chan struct{})
	var waitGroup sync.WaitGroup

	for worker := 0; worker < 4; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < 300; iteration++ {
				state := group.selected.Load()
				if state == nil {
					continue
				}
				// Reading BOTH fields from one snapshot is the property under test: a reader
				// must never see a half-updated pair.
				if state.tcp != nil {
					_ = state.tcp.Tag()
				}
				if state.udp != nil {
					_ = state.udp.Tag()
				}
				_, _ = group.Select(N.NetworkTCP)
				_, _ = group.Select(N.NetworkUDP)
			}
		}()
	}

	// Writers replace the generation concurrently.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for iteration := 0; iteration < 200; iteration++ {
			group.performUpdateCheck()
		}
	}()

	close(start)
	waitGroup.Wait()
}

// --- business failure invalidates only the failing network (§27-§29, §48) --------------
//
// # What these tests can and cannot assert
//
// There is ONE delay measurement per (node, target): Measure dials over TCP and speaks HTTP over
// it, and Select reads that single value for both networks. So any change to the measurement
// affects both selections, and "the other network's selection is unaffected" cannot mean "the
// measurement survives" - it means the code must not CLEAR the other network's choice.
//
// These tests therefore assert the field-level guarantee, which is exactly the anti-cross-clear
// requirement and is what the code controls. Whether a later re-selection returns to the same
// node depends on the remaining history, which is a separate question.
//
// The assertion is made on the state published by the invalidation itself, because the invalidation
// deliberately triggers a re-selection immediately afterwards: with the measurement preserved (as
// a UDP failure requires), the re-selection may legitimately return to the same node. Reading the
// state after that round would test the selection policy rather than the anti-cross-clear rule.
//
// The point of clearing the failing network at all is that a node which has just failed a real
// connection must not keep receiving traffic merely because an earlier test said it was fast.

func TestTCPFailureClearsOnlyTheTCPSelection(t *testing.T) {
	nodeA := &stubOutbound{tag: "node-a", dialErr: errStubDial}
	nodeB := &stubOutbound{tag: "node-b"}
	nodeAReal, nodeBReal := &stubOutbound{tag: "node-a"}, &stubOutbound{tag: "node-b"}

	nodeAOut := &stubOutbound{tag: "node-a"}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})

	// Pin a known generation so the assertion is about the invalidation, not about selection.
	group.selected.Store(&selectedState{tcp: nodeAOut, udp: nodeBOut})

	// clearSelected is the generation-publishing half of the invalidation, without the
	// re-selection that follows it - so the cleared fields can be observed directly.
	group.clearSelected(N.NetworkTCP, nodeAOut)

	state := group.selected.Load()
	require.Nil(t, state.tcp, "the failing TCP selection must be cleared immediately")
	require.Same(t, nodeBOut, state.udp,
		"a TCP failure must not clear the UDP selection")

	// The full traffic-failure path clears the selection but PRESERVES the measurement.
	//
	// A failed business connection is not evidence about the node: the target may have refused
	// it, its port may be closed, or the remote may have reset. Deleting a correct measurement on
	// that basis would let a website being down move the group to a worse node.
	group.clearSelectionFor(N.NetworkTCP, nodeAOut)

	require.Nil(t, group.selected.Load().tcp,
		"the failing TCP selection is still cleared, so the next connection can use another node")
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", scope),
		"a traffic failure must not discard the measurement for this target; only a failed "+
			"health check is evidence about health")

	_ = nodeA
	_ = nodeB
	_ = nodeAReal
	_ = nodeBReal
}

func TestUDPFailureClearsOnlyTheUDPSelection(t *testing.T) {
	nodeAOut := &stubOutbound{tag: "node-a"}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})

	group.selected.Store(&selectedState{tcp: nodeBOut, udp: nodeAOut})

	group.clearSelected(N.NetworkUDP, nodeAOut)

	state := group.selected.Load()
	require.Nil(t, state.udp, "the failing UDP selection must be cleared immediately")
	require.Same(t, nodeBOut, state.tcp,
		"a UDP failure must not clear the TCP selection")

	group.clearSelectionFor(N.NetworkUDP, nodeAOut)

	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", scope),
		"the measurement describes the TCP path, and a UDP failure says nothing about it, so "+
			"discarding it would throw away correct information")
}

func TestFailureOfANonSelectedNodeLeavesSelectionAlone(t *testing.T) {
	// A concurrent update may already have replaced the selection. Clearing then would undo that
	// newer decision, so the failing outbound is compared against the current one first.
	nodeAOut := &stubOutbound{tag: "node-a"}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 30})

	group.selected.Store(&selectedState{tcp: nodeBOut, udp: nodeBOut})

	// node-a failed, but node-b is selected now.
	group.clearSelectionFor(N.NetworkUDP, nodeAOut)

	state := group.selected.Load()
	require.Same(t, nodeBOut, state.tcp, "an unrelated failure must not disturb the TCP selection")
	require.Same(t, nodeBOut, state.udp, "an unrelated failure must not clear a newer selection")
}

func TestListenPacketFailureClearsTheUDPSelection(t *testing.T) {
	// The traffic entry point must actually reach the invalidation: a group that keeps selecting a
	// node whose UDP handling fails would keep failing every packet connection.
	nodeAOut := &stubOutbound{tag: "node-a", dialErr: errStubDial}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	group.selected.Store(&selectedState{tcp: nodeBOut, udp: nodeAOut})

	_, packetErr := listenThrough(group, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, packetErr)

	state := group.selected.Load()
	require.NotEqual(t, "node-a", tagOf(state.udp),
		"the UDP selection must move off the node that just failed")
	require.Same(t, nodeBOut, state.tcp, "a UDP failure must not disturb the TCP selection")
}

func TestDialFailureClearsTheTCPSelection(t *testing.T) {
	nodeAOut := &stubOutbound{tag: "node-a", dialErr: errStubDial}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)
	scope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	group.selected.Store(&selectedState{tcp: nodeAOut, udp: nodeBOut})

	_, dialErr := dialThrough(group, N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, dialErr)

	state := group.selected.Load()
	require.NotEqual(t, "node-a", tagOf(state.tcp),
		"the TCP selection must move off the node that just failed")
	require.Same(t, nodeBOut, state.udp, "a TCP failure must not disturb the UDP selection")
}

func TestDialFailureIsScopedToThisTarget(t *testing.T) {
	// A traffic failure preserves every measurement, including this group's own.
	//
	// The scoping property is still asserted - a failure must never disturb another target's
	// measurement - but the stronger statement now holds too: it does not disturb its own, because
	// a failed business connection is not evidence that the node is unhealthy. Reconciling the two
	// is what the health recheck is for.
	nodeAOut := &stubOutbound{tag: "node-a", dialErr: errStubDial}
	nodeBOut := &stubOutbound{tag: "node-b"}

	group, storage := newGroupFixture(t, "https://a.example/x", nodeAOut, nodeBOut)

	ownScope, err := urltest.NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	otherScope, err := urltest.NewMeasurementScope("https://b.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", ownScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", otherScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 75})

	// Pin the failing node as the selection so the traffic path actually exercises the failure.
	group.selected.Store(&selectedState{tcp: nodeAOut, udp: nodeAOut})

	_, dialErr := dialThrough(group, N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, dialErr)

	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", ownScope),
		"a failed business connection must not discard this group's own measurement; only a "+
			"failed health check is evidence about health")
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", otherScope),
		"a failure against this group's target must not discard another target's measurement")
}

func tagOf(outbound adapter.Outbound) string {
	if outbound == nil {
		return ""
	}
	return outbound.Tag()
}

var errStubDial = commonErr("stub dial failure")

type commonErr string

func (e commonErr) Error() string { return string(e) }

// The traffic entry points live on the URLTest wrapper, so the tests drive them there - that is
// the code real connections execute.
func referencingOutbound(group *URLTestGroup) []string {
	return newTestURLTestWrapper(group, nil).References()
}

func dialThrough(group *URLTestGroup, network string, destination M.Socksaddr) (net.Conn, error) {
	return newTestURLTestWrapper(group, log.NewNOPFactory().NewLogger("group")).DialContext(
		context.Background(), network, destination)
}

func listenThrough(group *URLTestGroup, destination M.Socksaddr) (net.PacketConn, error) {
	return newTestURLTestWrapper(group, log.NewNOPFactory().NewLogger("group")).ListenPacket(
		context.Background(), destination)
}
