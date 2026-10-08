package group

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// fakeTransport is an in-tree test double implementing adapter.DNSTransport. Its
// behaviour is injectable per test and it counts every Exchange, so the group's
// fan/anti-storm/single-flight claims are asserted on observed calls rather than
// on internal flags.
type fakeTransport struct {
	adapter.DNSTransport
	tag           string
	transportType string

	calls atomic.Int64

	access   sync.Mutex
	behavior func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)
	// firstCallBehavior, when set, applies to this member's first call only; later calls use
	// behavior. See setFirstCallBehavior for why a test needs the distinction.
	firstCallBehavior func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)
	onEnter           func()
}

var errFake = errors.New("fake transport failure")

func newFakeTransport(tag string) *fakeTransport {
	return &fakeTransport{tag: tag, transportType: "test"}
}

func (f *fakeTransport) Type() string                                               { return f.transportType }
func (f *fakeTransport) Tag() string                                                { return f.tag }
func (f *fakeTransport) Dependencies() []string                                     { return nil }
func (f *fakeTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (f *fakeTransport) Close() error                                               { return nil }
func (f *fakeTransport) Reset()                                                     {}

// Store satisfies adapter.FakeIPTransport so a fake can stand in for a fakeip
// member when the manager's own capability check runs.
func (f *fakeTransport) Store() adapter.FakeIPStore { return nil }

func (f *fakeTransport) setBehavior(behavior func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)) {
	f.access.Lock()
	f.behavior = behavior
	f.access.Unlock()
}

// succeed makes every exchange answer successfully.
// setFirstCallBehavior installs behaviour that applies to this member's FIRST call only.
//
// It exists so a test can park the fan without also parking the concurrent single attempts: a
// global park makes an exact call-count assertion depend on how quickly the whole burst reaches
// selection, which is exactly the timing dependence such a test must not have.
func (f *fakeTransport) setFirstCallBehavior(behavior func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)) {
	f.access.Lock()
	f.firstCallBehavior = behavior
	f.access.Unlock()
}

func (f *fakeTransport) succeed() {
	f.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		return successResponse(message), nil
	})
}

// fail makes every exchange report a transport error.
func (f *fakeTransport) fail() {
	f.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		return nil, errFake
	})
}

func (f *fakeTransport) setOnEnter(onEnter func()) {
	f.access.Lock()
	f.onEnter = onEnter
	f.access.Unlock()
}

func (f *fakeTransport) callCount() int64 { return f.calls.Load() }

func (f *fakeTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	call := f.calls.Add(1)
	f.access.Lock()
	onEnter := f.onEnter
	behavior := f.behavior
	if call == 1 && f.firstCallBehavior != nil {
		behavior = f.firstCallBehavior
	}
	f.access.Unlock()
	if onEnter != nil {
		onEnter()
	}
	if behavior == nil {
		return successResponse(message), nil
	}
	return behavior(ctx, message)
}

func (f *fakeTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(f.Exchange(ctx, message))
	}()
}

func successResponse(message *mDNS.Msg) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(message)
	return response
}

func nxdomainResponse(message *mDNS.Msg) *mDNS.Msg {
	response := successResponse(message)
	response.Rcode = mDNS.RcodeNameError
	return response
}

func servfailResponse(message *mDNS.Msg) *mDNS.Msg {
	response := successResponse(message)
	response.Rcode = mDNS.RcodeServerFailure
	return response
}

func queryMessage() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.test.", mDNS.TypeA)
	return message
}

// testTimeout is a hard deadline for every context a test hands to the group.
// There are no unbounded waits anywhere in these tests.
const testTimeout = 10 * time.Second

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// waitFor polls a condition under a hard deadline. It is the barrier used to
// observe an asynchronous effect (a dispatched call, a released flag) without
// sleeping for a guessed duration.
func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for: ", description)
}

// groupHarness builds a group whose members are fakes, wired directly so the
// selection and record tests do not need a transport manager. The manager path
// is covered separately in manager_test.go.
type groupHarness struct {
	t         *testing.T
	transport *Transport
	fakes     []*fakeTransport
	byTag     map[string]*fakeTransport
}

func newGroupHarness(t *testing.T, options option.GroupDNSServerOptions) *groupHarness {
	t.Helper()
	rawTransport, err := NewTransport(
		context.Background(),
		log.NewNOPFactory().NewLogger("group-test"),
		"group",
		options,
	)
	require.NoError(t, err)
	transport := rawTransport.(*Transport)
	harness := &groupHarness{
		t:         t,
		transport: transport,
		byTag:     make(map[string]*fakeTransport),
	}
	for _, serverTag := range options.Servers {
		fake := newFakeTransport(serverTag)
		harness.fakes = append(harness.fakes, fake)
		harness.byTag[serverTag] = fake
	}
	harness.wire()
	t.Cleanup(func() {
		_ = transport.Close()
	})
	return harness
}

func stableOptions(serverTags ...string) option.GroupDNSServerOptions {
	return option.GroupDNSServerOptions{
		Servers: badoption.Listable[string](serverTags),
		Mode:    ModeStable,
	}
}

func fastestOptions(serverTags ...string) option.GroupDNSServerOptions {
	return option.GroupDNSServerOptions{
		Servers: badoption.Listable[string](serverTags),
		Mode:    ModeFastest,
	}
}

func parallelOptions(serverTags ...string) option.GroupDNSServerOptions {
	return option.GroupDNSServerOptions{
		Servers: badoption.Listable[string](serverTags),
		Mode:    ModeParallel,
	}
}

// wire installs the fakes as members and opens a transport lifetime, replacing
// whatever a previous cycle installed. It models Start without a manager.
func (h *groupHarness) wire() {
	h.t.Helper()
	members := make([]*member, 0, len(h.fakes))
	for _, fake := range h.fakes {
		members = append(members, &member{tag: fake.tag, transport: fake})
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	h.transport.access.Lock()
	if h.transport.cancelRun != nil {
		h.transport.cancelRun()
	}
	h.transport.members = members
	h.transport.runCtx = runCtx
	h.transport.cancelRun = cancelRun
	h.transport.closed = false
	h.transport.election = electionToken{}
	h.transport.gen++
	h.transport.access.Unlock()
}

func (h *groupHarness) allSucceed() {
	for _, fake := range h.fakes {
		fake.succeed()
	}
}

func (h *groupHarness) exchange(ctx context.Context) (*mDNS.Msg, error) {
	return h.transport.Exchange(ctx, queryMessage())
}

// awaitTotalCalls waits for every participant of a fan to have dispatched its
// call, then asserts the total is exactly the expected count.
//
// A fan returns on its first valid answer and the losing probes are cancelled,
// so a loser may not have been scheduled yet when Exchange returns. Waiting is
// therefore about observing the dispatched call, not about tolerating extra
// ones: the equality assertion is what proves the fan's size.
func (h *groupHarness) awaitTotalCalls(t *testing.T, expected int64, description string) {
	t.Helper()
	waitFor(t, description, func() bool {
		return h.totalCalls() >= expected
	})
	require.Equal(t, expected, h.totalCalls(), description)
}

func (h *groupHarness) totalCalls() int64 {
	var total int64
	for _, fake := range h.fakes {
		total += fake.callCount()
	}
	return total
}

func (h *groupHarness) calls(tag string) int64 {
	return h.byTag[tag].callCount()
}

// calledTags returns the tags that have been called at least once, so a test can
// say which single member the group chose without depending on ordering.
func (h *groupHarness) calledTags() []string {
	var tags []string
	for _, fake := range h.fakes {
		if fake.callCount() > 0 {
			tags = append(tags, fake.tag)
		}
	}
	return tags
}

func (h *groupHarness) generation() int {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.gen
}

func (h *groupHarness) current() string {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.current
}

func (h *groupHarness) setCurrent(tag string) {
	h.transport.access.Lock()
	h.transport.current = tag
	h.transport.access.Unlock()
}

func (h *groupHarness) liveErrors(tag string) int {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return len(h.transport.liveErrorsLocked(tag, time.Now()))
}

func (h *groupHarness) liveWins(tag string) int {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return len(h.transport.liveWinsLocked(tag, time.Now()))
}

func (h *groupHarness) errorCount(tag string) int {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	record := h.transport.records[tag]
	if record == nil {
		return 0
	}
	return len(record.errors)
}

func (h *groupHarness) markDirty(tag string) {
	h.transport.noteError(tag, h.generation())
}

func (h *groupHarness) recordCount() int {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return len(h.transport.records)
}

// electionInFlight reports whether ANY election token is set, including one left
// over from a generation Reset has already amnestied. It is the raw "a collector
// still owns a token" predicate, so it stays true until the old collector has
// unwound; whether that token still blocks selection is a different question,
// answered by electionOwned.
func (h *groupHarness) electionInFlight() bool {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.election.held()
}

// electionOwned reports whether the CURRENT generation owns the election. This
// is the predicate selection actually uses, so it is false for a stale token
// even while electionInFlight is still true.
func (h *groupHarness) electionOwned() bool {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.electionHeldLocked()
}

func (h *groupHarness) electionToken() electionToken {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.election
}

// electionCount is the number of elections the transport has ever minted. It is
// bumped synchronously under access when a query takes the single-flight lock,
// so a test can assert "exactly one fan" without depending on when the fan's
// participant goroutines happen to be scheduled.
func (h *groupHarness) electionCount() uint64 {
	h.transport.access.Lock()
	defer h.transport.access.Unlock()
	return h.transport.electionSeq
}

// setSurvivalRecords installs records with explicit ages so the least-dirty
// choice is deterministic without sleeping.
func (h *groupHarness) setSurvivalRecords(ages map[string]time.Duration) {
	now := time.Now()
	h.transport.access.Lock()
	h.transport.records = make(map[string]*memberRecord, len(ages))
	for tag, age := range ages {
		h.transport.records[tag] = &memberRecord{errors: []time.Time{now.Add(-age)}}
	}
	h.transport.access.Unlock()
}
