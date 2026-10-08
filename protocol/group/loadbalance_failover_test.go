package group

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Live dial failure feedback and the bounded failover retry: classification, penalties,
// generation scoping, the TTL, and the two-attempt bound.
//
// Every test drives the group through DialWithFailover - the capability the route path asks
// for - rather than through the penalty helpers, because the failure mode this feature is
// most likely to have is a penalty that is recorded but never read, or a retry that never
// runs. A test that called recordPenalty directly would pass with the whole thing unwired.
// The one exception is the generation and TTL tests, which must be able to place a NEWER
// record against an OLDER clock than any dial could.

// setDialError changes the shared stub's dial outcome while a test runs, so a sequence of
// attempts is expressed by the test rather than by a sleep. The stub itself, its dial counter
// and its connection double are the ones the URLTest tests already use.
func (o *stubOutbound) setDialError(err error) {
	o.dialLock.Lock()
	o.dialErr = err
	o.dialLock.Unlock()
}

// failoverLogger records what the group reported, so "the selection move is logged" is an
// assertion rather than a claim.
type failoverLogger struct {
	log.ContextLogger
	access   sync.Mutex
	messages []string
}

func (l *failoverLogger) Info(args ...any) {
	l.access.Lock()
	l.messages = append(l.messages, F.ToString(args...))
	l.access.Unlock()
	l.ContextLogger.Info(args...)
}

func (l *failoverLogger) Debug(args ...any) {
	l.access.Lock()
	l.messages = append(l.messages, F.ToString(args...))
	l.access.Unlock()
	l.ContextLogger.Debug(args...)
}

func (l *failoverLogger) contains(fragment string) bool {
	l.access.Lock()
	defer l.access.Unlock()
	for _, message := range l.messages {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

// failoverHarness owns the context every group in one test shares: the history storage and
// the network-generation coordinator.
type failoverHarness struct {
	ctx         context.Context
	coordinator *runtimecoord.Coordinator
	storage     *urltest.HistoryStorage
	manager     *loadBalanceManager
	// tags is the insertion order of the outbounds added to the manager, so a group that
	// does not state its members lists them in the order the test built them.
	tags []string
}

func newFailoverHarness(t *testing.T) *failoverHarness {
	t.Helper()
	coordinator := runtimecoord.New()
	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = service.ContextWith[*runtimecoord.Coordinator](ctx, coordinator)
	return &failoverHarness{
		ctx:         ctx,
		coordinator: coordinator,
		storage:     service.PtrFromContext[urltest.HistoryStorage](ctx),
		manager:     &loadBalanceManager{members: map[string]adapter.Outbound{}},
	}
}

func (h *failoverHarness) add(members ...adapter.Outbound) {
	for _, member := range members {
		if _, loaded := h.manager.members[member.Tag()]; !loaded {
			h.tags = append(h.tags, member.Tag())
		}
		h.manager.members[member.Tag()] = member
	}
}

func (h *failoverHarness) group(t *testing.T, tag string, groupLogger log.ContextLogger, options option.LoadBalanceOutboundOptions) *LoadBalance {
	t.Helper()
	if len(options.Outbounds) == 0 {
		options.Outbounds = h.tags
	}
	if groupLogger == nil {
		groupLogger = log.NewNOPFactory().NewLogger("loadbalance")
	}
	ctx := service.ContextWith[adapter.OutboundManager](h.ctx, h.manager)
	created, err := NewLoadBalance(ctx, nil, groupLogger, tag, options)
	require.NoError(t, err)
	group, isGroup := created.(*LoadBalance)
	require.True(t, isGroup)
	require.NoError(t, group.Start(adapter.StartStateStart, &adapter.Scope{}))
	// A group created here is resolvable by a later one, which is how the nested case is
	// built: the outer group lists the inner group's tag.
	h.manager.members[tag] = group
	t.Cleanup(func() {
		require.NoError(t, group.Close())
	})
	return group
}

// failoverContext is the hard deadline every test dials on, so a regression fails fast
// instead of hanging the suite.
func failoverContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func failoverMetadata(domain string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Network: N.NetworkTCP,
		Domain:  domain,
		Source:  M.ParseSocksaddrHostPort("192.168.1.9", 40000),
	}
}

func penaltyCountOf(group *LoadBalance, tag string) int {
	table := group.penalties.Load()
	if table == nil {
		return 0
	}
	entry, loaded := table.entries[tag]
	if !loaded {
		return 0
	}
	return entry.count
}

func failoverDestination() M.Socksaddr {
	return M.ParseSocksaddr("203.0.113.9:443")
}

// --- 1. classification ------------------------------------------------------------------

// timeoutDialError is a net.Error timeout that is not one of the sentinel values, so the
// Timeout() branch of the classifier is exercised on its own.
type timeoutDialError struct{}

func (timeoutDialError) Error() string   { return "i/o timeout" }
func (timeoutDialError) Timeout() bool   { return true }
func (timeoutDialError) Temporary() bool { return true }

func TestLoadBalanceDialFailureClassification(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		err      error
		pathDead bool
	}{
		{"no failure", nil, false},
		{"caller cancelled", context.Canceled, false},
		{"wrapped caller cancellation", errors.Join(errors.New("dial failed"), context.Canceled), false},
		{"connection refused", syscall.ECONNREFUSED, false},
		{"wrapped connection refused", errors.Join(errors.New("dial failed"), syscall.ECONNREFUSED), false},
		{"connection reset", syscall.ECONNRESET, false},
		{"wrapped connection reset", errors.Join(errors.New("read failed"), syscall.ECONNRESET), false},
		{"plain failure", errors.New("something else"), false},
		{"attempt deadline", context.DeadlineExceeded, true},
		{"wrapped attempt deadline", errors.Join(errors.New("dial failed"), context.DeadlineExceeded), true},
		{"socket deadline", os.ErrDeadlineExceeded, true},
		{"wrapped socket deadline", errors.Join(errors.New("write failed"), os.ErrDeadlineExceeded), true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"network unreachable", syscall.ENETUNREACH, true},
		{"timed out", syscall.ETIMEDOUT, true},
		{"wrapped network unreachable", errors.Join(errors.New("dial failed"), syscall.ENETUNREACH), true},
		{"dialer timeout", timeoutDialError{}, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.pathDead, isPathDeadDialError(testCase.err),
				"classification of %v", testCase.err)
		})
	}
}

// --- 2-4. the attempt sequence ----------------------------------------------------------

// TestLoadBalanceFailoverUsesThePrimaryWhenItWorks is the no-op case: nothing about the
// normal path changes.
func TestLoadBalanceFailoverUsesThePrimaryWhenItWorks(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	require.Equal(t, 1, nodeA.dialCount(), "the preferred member is dialled exactly once")
	require.Equal(t, 0, nodeB.dialCount(), "a working primary must not be second-guessed")
	require.Equal(t, uint64(1), group.CommittedSelections(), "one flow, one committed decision")
	require.Equal(t, 0, penaltyCountOf(group, "node-a"), "a success is not a failure")
	require.Equal(t, 0, penaltyCountOf(group, "node-b"))
}

// TestLoadBalanceFailoverRetriesAnAlternateAndMovesSelection is the feature's happy path.
func TestLoadBalanceFailoverRetriesAnAlternateAndMovesSelection(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	nodeA.setDialError(context.DeadlineExceeded)
	harness.add(nodeA, nodeB)
	groupLogger := &failoverLogger{ContextLogger: log.NewNOPFactory().NewLogger("loadbalance")}
	group := harness.group(t, "lb", groupLogger, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.NoError(t, err, "the alternate carried the flow")
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	require.Equal(t, 2, nodeA.dialCount()+nodeB.dialCount(), "exactly two attempts")
	require.Equal(t, 1, nodeA.dialCount())
	require.Equal(t, 1, nodeB.dialCount())
	require.Equal(t, 1, penaltyCountOf(group, "node-a"), "the path-dead member is penalised once")
	require.Equal(t, 0, penaltyCountOf(group, "node-b"), "the alternate produced proof of life")
	require.Equal(t, uint64(2), group.CommittedSelections(),
		"the retry re-ran the selection, so the move is part of the group's state")
	require.True(t, groupLogger.contains("moved a flow"),
		"the selection move must be observable, not silent: %v", groupLogger.messages)
}

// TestLoadBalanceFailoverStopsAfterTwoAttemptsAndReturnsTheOriginalError covers the bound
// and the error identity together.
func TestLoadBalanceFailoverStopsAfterTwoAttemptsAndReturnsTheOriginalError(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	primaryErr := errors.Join(errors.New("open connection"), context.DeadlineExceeded)
	nodeA.setDialError(primaryErr)
	nodeB.setDialError(syscall.ENETUNREACH)
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.Error(t, err)
	require.Nil(t, conn)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the FIRST failure is what the caller sees")
	require.Equal(t, 2, nodeA.dialCount()+nodeB.dialCount(), "at most two attempts, never a third")
	require.Equal(t, 1, penaltyCountOf(group, "node-a"))
	require.Equal(t, 1, penaltyCountOf(group, "node-b"))
}

// --- 5-6. neutral failures --------------------------------------------------------------

func TestLoadBalanceFailoverDoesNotRetryACancelledCaller(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	nodeA.setDialError(context.Canceled)
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.ErrorIs(t, err, context.Canceled, "the caller's cancellation is reported unchanged")
	require.Nil(t, conn)
	require.Equal(t, 1, nodeA.dialCount(), "a cancelled flow must not consume a second member")
	require.Equal(t, 0, nodeB.dialCount())
	require.Equal(t, 0, penaltyCountOf(group, "node-a"), "the node did not fail; the caller left")
	require.Equal(t, uint64(1), group.CommittedSelections())
}

func TestLoadBalanceFailoverDoesNotRetryARefusedDestination(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	nodeA.setDialError(syscall.ECONNREFUSED)
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	require.Nil(t, conn)
	require.Equal(t, 1, nodeA.dialCount(), "the node answered; a second member cannot fix that")
	require.Equal(t, 0, nodeB.dialCount())
	require.Equal(t, 0, penaltyCountOf(group, "node-a"))
}

// --- 7. proof of life -------------------------------------------------------------------

// TestLoadBalanceProofOfLifeClearsADemotedMember is the recovery path, and it is also what
// makes the TTL safe: a demoted member is still dialled as an ALTERNATE, which is where it
// earns the successful dial that clears it.
func TestLoadBalanceProofOfLifeClearsADemotedMember(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	// node-a is demoted by three path-dead failures and no success in between.
	for i := 0; i < loadBalancePenaltyThreshold; i++ {
		require.Equal(t, i+1, group.recordPenalty(nodeA))
	}
	demoted := group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.NotNil(t, demoted)
	require.Equal(t, "node-b", demoted.Tag(), "a demoted member is out of the primary rotation")

	// The primary is now node-b and it dies; the retry has nothing left but the demoted
	// node-a, which is exactly the alternate slot that lets a member come back.
	nodeB.setDialError(context.DeadlineExceeded)
	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	require.Equal(t, 0, penaltyCountOf(group, "node-a"),
		"the successful dial is proof of life and clears the record")
	require.Equal(t, 1, penaltyCountOf(group, "node-b"))

	// And it competes normally again rather than staying out of the rotation.
	recovered := group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.NotNil(t, recovered)
	require.Equal(t, "node-a", recovered.Tag())
}

// --- 8. emergency ranking ---------------------------------------------------------------

// TestLoadBalanceEmergencyRankingOnlyAtTheThreshold pins both halves: below the threshold the
// distribution and its order are untouched, and at the threshold the ranked order takes over.
func TestLoadBalanceEmergencyRankingOnlyAtTheThreshold(t *testing.T) {
	members := func() (*stubOutbound, *stubOutbound, *stubOutbound, *stubOutbound) {
		return &stubOutbound{tag: "node-a"}, &stubOutbound{tag: "node-b"},
			&stubOutbound{tag: "node-c"}, &stubOutbound{tag: "node-d"}
	}
	configuredTags := []string{"node-a", "node-b", "node-c", "node-d"}

	// Below the threshold: configuration order, with latency deliberately inverted so a
	// ranking by latency would be visible if it happened.
	below := newFailoverHarness(t)
	nodeA, nodeB, nodeC, nodeD := members()
	below.add(nodeA, nodeB, nodeC, nodeD)
	belowGroup := below.group(t, "lb", nil, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	})
	below.storage.StoreHealthHistory("node-a", belowGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	below.storage.StoreHealthHistory("node-b", belowGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 200})
	below.storage.StoreHealthHistory("node-c", belowGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	below.storage.StoreHealthHistory("node-d", belowGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	for i := 0; i < loadBalancePenaltyThreshold-1; i++ {
		belowGroup.recordPenalty(nodeA)
	}
	var order []string
	for i := 0; i < len(configuredTags); i++ {
		selected := belowGroup.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, true)
		require.NotNil(t, selected)
		order = append(order, selected.Tag())
	}
	require.Equal(t, configuredTags, order,
		"below the threshold the rotation order is configuration order, latency untouched")

	// At the threshold: penalty ascending, then latency ascending. node-c is lowest-latency
	// among the unpenalised, so it leads.
	at := newFailoverHarness(t)
	nodeA, nodeB, nodeC, nodeD = members()
	at.add(nodeA, nodeB, nodeC, nodeD)
	atGroup := at.group(t, "lb", nil, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "https://probe.example/generate_204",
	})
	at.storage.StoreHealthHistory("node-a", atGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	at.storage.StoreHealthHistory("node-b", atGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 200})
	at.storage.StoreHealthHistory("node-c", atGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	at.storage.StoreHealthHistory("node-d", atGroup.healthScope, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	for i := 0; i < loadBalancePenaltyThreshold; i++ {
		atGroup.recordPenalty(nodeA)
	}
	order = nil
	for i := 0; i < 3; i++ {
		selected := atGroup.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, true)
		require.NotNil(t, selected)
		order = append(order, selected.Tag())
	}
	require.Equal(t, []string{"node-c", "node-d", "node-b"}, order,
		"the demoted member is out, and the survivors are ranked by measured latency")
	require.NotContains(t, order, "node-a")
}

// --- 9. generation scoping --------------------------------------------------------------

// TestLoadBalancePenaltyIsScopedToTheNetworkGeneration is the fork's correction to the
// reference: a penalty earned on one network must not demote a member on the next.
func TestLoadBalancePenaltyIsScopedToTheNetworkGeneration(t *testing.T) {
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	for i := 0; i < loadBalancePenaltyThreshold; i++ {
		group.recordPenalty(nodeA)
	}
	preview := group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.Equal(t, "node-b", preview.Tag(), "the demoted member is out within its generation")

	// The network is reset. The record belongs to the generation it was made in, so it must
	// stop applying without any successful dial having happened.
	harness.coordinator.Advance(1)

	preview = group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.Equal(t, "node-a", preview.Tag(),
		"a record from generation N must not demote a member in generation N+1")

	// A record made in the new generation is judged on its own, not added to the old count.
	require.Equal(t, 1, group.recordPenalty(nodeA))
	require.Equal(t, 1, penaltyCountOf(group, "node-a"),
		"the first failure of the new generation starts a new record")
	preview = group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.Equal(t, "node-a", preview.Tag())
}

// --- 10. TTL ----------------------------------------------------------------------------

// TestLoadBalancePenaltyExpiresWithoutATimer is the second correction: a transient that no
// probe revisits must not demote for ever, and nothing has to run for it to stop.
func TestLoadBalancePenaltyExpiresWithoutATimer(t *testing.T) {
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	harness.add(nodeA, nodeB)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	now := time.Now()
	group.now = func() time.Time { return now }
	for i := 0; i < loadBalancePenaltyThreshold; i++ {
		group.recordPenalty(nodeA)
	}
	require.Nil(t, group.health.Load(), "no health checker exists, so no probe can be what expires this")
	preview := group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.Equal(t, "node-b", preview.Tag())

	// Only the clock moves. No timer ran, no goroutine woke up, no dial succeeded.
	now = now.Add(loadBalancePenaltyTTL + time.Second)
	preview = group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, false)
	require.Equal(t, "node-a", preview.Tag(),
		"an expired record stops demoting, evaluated lazily at selection time")

	// And an expired record is forgotten rather than extended: one fresh failure is one
	// failure, not a re-armed threshold.
	require.Equal(t, 1, group.recordPenalty(nodeA))
}

// --- 11. the bound with many candidates -------------------------------------------------

// TestLoadBalanceFailoverIsBoundedToTwoAttemptsOutOfTen is the bound stated as a cost: a
// group with ten members must not dial ten times when every one of them is dead.
func TestLoadBalanceFailoverIsBoundedToTwoAttemptsOutOfTen(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	members := make([]*stubOutbound, 0, 10)
	for i := 0; i < 10; i++ {
		member := &stubOutbound{tag: "node-" + string(rune('a'+i))}
		member.setDialError(syscall.EHOSTUNREACH)
		members = append(members, member)
		harness.add(member)
	}
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.Error(t, err)
	require.Nil(t, conn)

	total := 0
	penalised := 0
	for _, member := range members {
		total += member.dialCount()
		if penaltyCountOf(group, member.Tag()) > 0 {
			penalised++
		}
	}
	require.Equal(t, 2, total, "exactly two attempts, not one per candidate")
	require.Equal(t, 2, penalised, "each failed attempt is its own member's record")
	require.Equal(t, uint64(2), group.CommittedSelections())
}

// --- 12. strategy preservation ----------------------------------------------------------

// TestLoadBalanceFailoverPreservesTheStrategies pins that the retry does not become a second
// selection policy: with every member healthy, each strategy behaves exactly as it did.
func TestLoadBalanceFailoverPreservesTheStrategies(t *testing.T) {
	ctx := failoverContext(t)

	t.Run("round_robin", func(t *testing.T) {
		harness := newFailoverHarness(t)
		var members []*stubOutbound
		for _, tag := range []string{"A", "B", "C", "D"} {
			member := &stubOutbound{tag: tag}
			members = append(members, member)
			harness.add(member)
		}
		group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})
		var dialed []string
		for i := 0; i < 4; i++ {
			previous := make([]int, len(members))
			for j, member := range members {
				previous[j] = member.dialCount()
			}
			_, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
			require.NoError(t, err)
			for j, member := range members {
				if member.dialCount() > previous[j] {
					dialed = append(dialed, member.Tag())
				}
			}
		}
		require.Equal(t, []string{"A", "B", "C", "D"}, dialed)
	})

	t.Run("consistent_hashing", func(t *testing.T) {
		harness := newFailoverHarness(t)
		var members []*stubOutbound
		for _, tag := range []string{"A", "B", "C", "D"} {
			member := &stubOutbound{tag: tag}
			members = append(members, member)
			harness.add(member)
		}
		group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"})
		first := group.SelectForFlow(failoverMetadata("shop.example.com"), N.NetworkTCP, true)
		require.NotNil(t, first)
		for i := 0; i < 16; i++ {
			again := group.SelectForFlow(failoverMetadata("shop.example.com"), N.NetworkTCP, true)
			require.Equal(t, first.Tag(), again.Tag(), "the same destination keeps its member")
		}
	})

	t.Run("sticky_sessions", func(t *testing.T) {
		harness := newFailoverHarness(t)
		var members []*stubOutbound
		for _, tag := range []string{"A", "B", "C", "D"} {
			member := &stubOutbound{tag: tag}
			members = append(members, member)
			harness.add(member)
		}
		group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "sticky_sessions"})
		first := group.SelectForFlow(failoverMetadata("login.example.com"), N.NetworkTCP, true)
		require.NotNil(t, first)
		for i := 0; i < 8; i++ {
			again := group.SelectForFlow(failoverMetadata("login.example.com"), N.NetworkTCP, true)
			require.Equal(t, first.Tag(), again.Tag(), "a pinned session stays pinned")
		}
	})
}

// TestLoadBalanceHashDoesNotRemapEveryKeyWhenAMemberIsDemoted is the invariant the hash
// strategy exists for, restated for the failure ledger.
func TestLoadBalanceHashDoesNotRemapEveryKeyWhenAMemberIsDemoted(t *testing.T) {
	harness := newFailoverHarness(t)
	var members []*stubOutbound
	for _, tag := range []string{"A", "B", "C", "D"} {
		member := &stubOutbound{tag: tag}
		members = append(members, member)
		harness.add(member)
	}
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "consistent_hashing"})

	// Distinct registrable identities, because the hash key is the registrable domain: every
	// host under one site is deliberately one key.
	hosts := make([]string, 0, 64)
	before := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		host := "site" + strconv.Itoa(i) + ".example"
		hosts = append(hosts, host)
		selected := group.SelectForFlow(failoverMetadata(host), N.NetworkTCP, true)
		require.NotNil(t, selected)
		before = append(before, selected.Tag())
	}

	for i := 0; i < loadBalancePenaltyThreshold; i++ {
		group.recordPenalty(members[1]) // B
	}

	moved, kept := 0, 0
	for i, host := range hosts {
		selected := group.SelectForFlow(failoverMetadata(host), N.NetworkTCP, true)
		require.NotNil(t, selected)
		if selected.Tag() == before[i] {
			kept++
			continue
		}
		moved++
		require.Equal(t, "B", before[i],
			"only keys that pointed at the demoted member may move; %s moved from %s", host, before[i])
	}
	require.Greater(t, moved, 0, "the keys on the demoted member must have somewhere to go")
	require.Greater(t, kept, 0, "a penalty must not re-map every key")
	require.Less(t, moved, len(hosts))
}

// --- 13. structural isolation -----------------------------------------------------------

// TestLoadBalanceFailoverStaysInsideTheConfiguredList proves the isolation is structural: a
// group can only ever name a member of its own published list, so the "AI pool" style
// restriction - which is expressed as a route rule pointing at a group whose member list IS
// the pool - needs no traffic-class filter inside selection.
func TestLoadBalanceFailoverStaysInsideTheConfiguredList(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	// A resolvable outbound that is NOT a member. If any selection ever answered with it,
	// the group would have left its configured list.
	unlisted := &stubOutbound{tag: "unlisted"}
	nodeA.setDialError(syscall.ENETUNREACH)
	nodeB.setDialError(syscall.ENETUNREACH)
	harness.add(nodeA, nodeB, unlisted)
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{
		Strategy:  "round_robin",
		Outbounds: []string{"node-a", "node-b"},
	})

	for i := 0; i < 5; i++ {
		conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
		require.Error(t, err)
		require.Nil(t, conn)
	}
	require.Equal(t, 0, unlisted.dialCount(), "a group must never dial outside its member list")
	require.Equal(t, 10, nodeA.dialCount()+nodeB.dialCount(), "two attempts per call, both inside the list")

	// And with every member demoted, the fail-open answer is still one of them.
	nodeA.setDialError(nil)
	for _, member := range []*stubOutbound{nodeA, nodeB} {
		for i := 0; i < loadBalancePenaltyThreshold; i++ {
			group.recordPenalty(member)
		}
	}
	selected := group.SelectForFlow(failoverMetadata("example.com"), N.NetworkTCP, true)
	require.NotNil(t, selected, "a group with every member demoted still has to answer")
	require.Contains(t, []string{"node-a", "node-b"}, selected.Tag())
}

// TestLoadBalanceNestedFailoverStaysInsideTheNestedList pins the other half: the outer group
// chose the nested group, and which member serves the flow stays the nested group's decision,
// inside the nested group's own list.
func TestLoadBalanceNestedFailoverStaysInsideTheNestedList(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	nodeA := &stubOutbound{tag: "node-a"}
	nodeB := &stubOutbound{tag: "node-b"}
	unlisted := &stubOutbound{tag: "unlisted"}
	nodeA.setDialError(context.DeadlineExceeded)
	harness.add(nodeA, nodeB, unlisted)

	inner := harness.group(t, "inner", nil, option.LoadBalanceOutboundOptions{
		Strategy:  "round_robin",
		Outbounds: []string{"node-a", "node-b"},
	})
	outer := harness.group(t, "outer", nil, option.LoadBalanceOutboundOptions{
		Strategy:  "round_robin",
		Outbounds: []string{"inner"},
	})

	conn, err := outer.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.NoError(t, err, "the nested group's own failover carried the flow")
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	require.Equal(t, 1, nodeA.dialCount())
	require.Equal(t, 1, nodeB.dialCount())
	require.Equal(t, 0, unlisted.dialCount(), "the nested failover stayed inside the nested list")
	require.Equal(t, uint64(1), outer.CommittedSelections(),
		"the outer group chose the nested group once; the replacement is the nested group's")
	require.Equal(t, uint64(2), inner.CommittedSelections(),
		"the nested group's retry re-ran its own selection")
	require.Equal(t, 1, penaltyCountOf(inner, "node-a"))
	require.Equal(t, 0, penaltyCountOf(outer, "inner"),
		"the nested group succeeded, so the outer member it chose is not penalised")
}

// --- 14. restart and leak ---------------------------------------------------------------

// TestLoadBalanceFailoverRepeatedCyclesDoNotLeak is the resource guard: the failure ledger,
// the retest valve and the retry own no timer and no worker, so thirty cycles must not
// accumulate anything.
func TestLoadBalanceFailoverRepeatedCyclesDoNotLeak(t *testing.T) {
	ctx := failoverContext(t)

	// Warm up, so one-off runtime goroutines are already running.
	warm := newFailoverHarness(t)
	warmA := &stubOutbound{tag: "node-a"}
	warmB := &stubOutbound{tag: "node-b"}
	warmA.setDialError(context.DeadlineExceeded)
	warm.add(warmA, warmB)
	warmGroup := warm.group(t, "lb", nil, option.LoadBalanceOutboundOptions{
		Strategy: "round_robin",
		URL:      "http://127.0.0.1:1/generate_204",
	})
	_, err := warmGroup.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
	require.NoError(t, err)
	require.NoError(t, warmGroup.Close())

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	for cycle := 0; cycle < 30; cycle++ {
		harness := newFailoverHarness(t)
		nodeA := &stubOutbound{tag: "node-a"}
		nodeB := &stubOutbound{tag: "node-b"}
		nodeA.setDialError(context.DeadlineExceeded)
		harness.add(nodeA, nodeB)
		group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{
			Strategy: "round_robin",
			URL:      "http://127.0.0.1:1/generate_204",
		})
		conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.NoError(t, conn.Close())
		require.Equal(t, 1, penaltyCountOf(group, "node-a"))
		require.False(t, group.retest.running.Load(), "the retest valve is not left armed")
		require.NoError(t, group.Close())
	}

	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()
	require.LessOrEqual(t, after, before+5,
		"30 select/penalise/close cycles must not accumulate goroutines; before=%d after=%d", before, after)
}

// TestLoadBalanceFailoverIsRaceFreeUnderConcurrentFailures drives the ledger from many
// goroutines while another flips members and advances the network generation, so `-race`
// exercises the read-modify-write, the generation check and the lazy expiry together.
//
// The assertions are structural rather than exact: with a member recovering and the generation
// moving mid-run, which member serves which flow is not a fixed answer. What must hold is that
// no flow dials outside the list, no flow makes more than two attempts, and the run completes.
func TestLoadBalanceFailoverIsRaceFreeUnderConcurrentFailures(t *testing.T) {
	ctx := failoverContext(t)
	harness := newFailoverHarness(t)
	members := make([]*stubOutbound, 0, 4)
	for i := 0; i < 4; i++ {
		member := &stubOutbound{tag: "node-" + string(rune('a'+i))}
		member.setDialError(context.DeadlineExceeded)
		members = append(members, member)
		harness.add(member)
	}
	group := harness.group(t, "lb", nil, option.LoadBalanceOutboundOptions{Strategy: "round_robin"})

	const (
		workers = 8
		rounds  = 25
	)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for i := 0; i < rounds; i++ {
				conn, err := group.DialWithFailover(ctx, failoverMetadata("example.com"), N.NetworkTCP, failoverDestination())
				if err == nil && conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	// One writer flips member outcomes and advances the generation underneath the readers.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for i := 0; i < rounds; i++ {
			members[i%len(members)].setDialError(nil)
			harness.coordinator.Advance(uint64(i + 1))
			members[(i+1)%len(members)].setDialError(context.DeadlineExceeded)
		}
	}()
	close(start)
	waitGroup.Wait()

	require.LessOrEqual(t, group.CommittedSelections(), uint64(workers*rounds*2),
		"at most two committed decisions per flow")
}

// TestLoadBalanceRetestValveThrottlesFromTheEndOfTheRun pins the valve on its own, because
// the alternative - a real forced round - would need a health checker and a clock.
func TestLoadBalanceRetestValveThrottlesFromTheEndOfTheRun(t *testing.T) {
	var valve loadBalanceRetestValve
	start := time.Unix(1_700_000_000, 0)
	require.True(t, valve.begin(start, loadBalanceForcedRetestInterval), "the first round is allowed")
	require.False(t, valve.begin(start, loadBalanceForcedRetestInterval),
		"a concurrent failure must be collapsed into the round already running")

	// The run took ten seconds. The window is measured from the END, so the next round is
	// still refused until a full interval after this moment.
	end := start.Add(10 * time.Second)
	valve.end(end)
	require.False(t, valve.begin(end.Add(loadBalanceForcedRetestInterval-time.Second), loadBalanceForcedRetestInterval),
		"the window starts at the end of the previous run, not its start")
	require.True(t, valve.begin(end.Add(loadBalanceForcedRetestInterval), loadBalanceForcedRetestInterval))
	valve.end(end.Add(loadBalanceForcedRetestInterval))
}
