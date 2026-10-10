package outbound

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// START-02: re-entrancy, repeated start, and construction concurrency.
//
// # What these fixtures are for
//
// The dry run added a start-time decision in front of the start, so the states it can leave behind
// are the states that matter: a refused start that is retried, a legal start that is repeated, and
// a tag that two constructors race for. Each one is asserted on the manager's own observable state
// rather than on a log line, because "no state was left behind" is a claim about the object graph.

// TestRepeatedStartAfterADryRunFailureLeavesNoState pins that a refused start is a clean refusal.
//
// The dry run runs after the Initialize stage has already installed the default-outbound fallback,
// so a retry that appended it again would grow the outbound list on every attempt - and a retry
// that reported a different defect would mean the first attempt had left something behind.
func TestRepeatedStartAfterADryRunFailureLeavesNoState(t *testing.T) {
	healthy := &dryRunLeaf{tag: "healthy", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	udpOnly := &dryRunLeaf{tag: "udp-only", networks: []string{N.NetworkUDP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"healthy", "udp-only"},
		networks: []string{N.NetworkTCP, N.NetworkUDP},
		selected: "healthy",
	}
	fallback := &dryRunLeaf{tag: "fallback", networks: []string{N.NetworkTCP, N.NetworkUDP}}

	outbounds := []adapter.Outbound{healthy, udpOnly, selector}
	lookup := make(map[string]adapter.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		lookup[outbound.Tag()] = outbound
	}
	selector.lookup = lookup

	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{}}, "")
	for _, outbound := range outbounds {
		installOutbound(t, manager, outbound)
	}
	manager.Initialize(func() (adapter.Outbound, error) { return fallback, nil })
	manager.EnablePhysicalPathValidation(physicalpath.Declarations{}, func(string) string { return "" }, false)

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	for attempt := 0; attempt < 3; attempt++ {
		require.NoError(t, manager.Start(adapter.StartStateInitialize, scope),
			"the Initialize stage is repeatable: it installs the fallback only when there is none")
		require.Len(t, manager.Outbounds(), len(outbounds)+1,
			"the fallback must be installed exactly once however many times Start is attempted")
		err := manager.Start(adapter.StartStateStart, scope)
		require.Error(t, err, "the refusal must be stable across attempts")
		require.Contains(t, err.Error(), "udp-only")
		require.Contains(t, err.Error(), "cannot serve the tcp flow")
	}
}

// TestRepeatedStartOfALegalGraphIsIdempotent is the control: repeating a start that SUCCEEDS must
// not change the graph either, and must not consume a rotation.
func TestRepeatedStartOfALegalGraphIsIdempotent(t *testing.T) {
	first := &dryRunLeaf{tag: "first", networks: []string{N.NetworkTCP}}
	second := &dryRunLeaf{tag: "second", networks: []string{N.NetworkTCP}}
	selector := &countingDryRunGroup{dryRunGroup: dryRunGroup{
		tag:      "sel",
		members:  []string{"first", "second"},
		networks: []string{N.NetworkTCP},
		selected: "first",
	}}

	outbounds := []adapter.Outbound{first, second, selector}
	lookup := make(map[string]adapter.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		lookup[outbound.Tag()] = outbound
	}
	selector.lookup = lookup

	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{}}, "")
	for _, outbound := range outbounds {
		installOutbound(t, manager, outbound)
	}
	manager.EnablePhysicalPathValidation(physicalpath.Declarations{}, func(string) string { return "" }, false)
	manager.EnablePhysicalPathDelivery(map[string][]string{"sel": {N.NetworkTCP}})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	for attempt := 0; attempt < 3; attempt++ {
		require.NoError(t, manager.Start(adapter.StartStateStart, scope))
		require.Len(t, manager.Outbounds(), len(outbounds))
	}
	require.Equal(t, uint64(0), selector.committed.Load(),
		"no attempt may consume a rotation")
	require.Equal(t, int64(0), selector.previewed.Load(),
		"and none may take a selection preview")
}

// TestCreateIsSafeUnderConcurrentDuplicateTags answers START-02's concurrency item directly.
//
// The duplicate check runs BEFORE construction and again under the lock, because a constructor runs
// outside it: two goroutines can both observe the tag as free. The loser must release the object it
// built - a discarded outbound holds whatever its constructor claimed - and exactly one must end up
// installed.
func TestCreateIsSafeUnderConcurrentDuplicateTags(t *testing.T) {
	const racers = 8
	registry := &recordingStubRegistry{}
	manager := NewManager(registry, nil, "")
	logger := log.NewNOPFactory().NewLogger("test")

	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
		results   = make([]error, racers)
	)
	for index := 0; index < racers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			results[index] = manager.Create(context.Background(), nil, logger, "dup", "stub", &optionStub{})
		}(index)
	}
	close(start)
	waitGroup.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
			continue
		}
		require.Contains(t, err.Error(), "already exists")
	}
	require.Equal(t, 1, succeeded, "exactly one constructor may win the tag")

	installed := 0
	var winner adapter.Outbound
	for _, outbound := range manager.Outbounds() {
		if outbound.Tag() == "dup" {
			installed++
			winner = outbound
		}
	}
	require.Equal(t, 1, installed, "exactly one object may be installed under the tag")

	created := registry.objects()
	require.NotEmpty(t, created)
	require.LessOrEqual(t, len(created), racers)
	// Most racers lose at the cheap pre-construction check, so how many constructors ran is
	// timing-dependent; what must hold either way is that the losers are released.
	orphaned := 0
	for _, outbound := range created {
		if adapter.Outbound(outbound) == winner {
			require.Equal(t, int32(0), outbound.closed.Load(),
				"the winner must not be closed")
			continue
		}
		if outbound.closed.Load() == 0 {
			orphaned++
		}
	}
	require.Equal(t, 0, orphaned,
		"every losing object must be closed rather than orphaned: it is installed nowhere, so "+
			"nothing else in the lifecycle can ever release what its constructor claimed")
}

// TestCreateClosesTheLoserWhoseConstructionWasAlreadyInFlight is the deterministic form of the
// race above.
//
// The pre-construction check cannot cover it: both constructors run outside the lock, so both can
// observe the tag as free. The gate holds both inside the constructor until each has entered, which
// is the only state in which the second check - the one under the lock - is what decides.
func TestCreateClosesTheLoserWhoseConstructionWasAlreadyInFlight(t *testing.T) {
	registry := &gatedStubRegistry{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	manager := NewManager(registry, nil, "")
	logger := log.NewNOPFactory().NewLogger("test")

	results := make([]error, 2)
	var waitGroup sync.WaitGroup
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			results[index] = manager.Create(context.Background(), nil, logger, "dup", "stub", &optionStub{})
		}(index)
	}
	// Both must be INSIDE the constructor before either is allowed to finish it.
	<-registry.entered
	<-registry.entered
	close(registry.release)
	waitGroup.Wait()

	require.Equal(t, 2, len(registry.objects()),
		"the fixture must exercise the under-lock check: both constructors have to run")
	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
			continue
		}
		require.Contains(t, err.Error(), "already exists")
	}
	require.Equal(t, 1, succeeded)

	installed := 0
	var winner adapter.Outbound
	for _, outbound := range manager.Outbounds() {
		if outbound.Tag() == "dup" {
			installed++
			winner = outbound
		}
	}
	require.Equal(t, 1, installed)
	for _, outbound := range registry.objects() {
		if adapter.Outbound(outbound) == winner {
			require.Equal(t, int32(0), outbound.closed.Load())
			continue
		}
		require.Equal(t, int32(1), outbound.closed.Load(),
			"the object built by the loser must be closed by the loser: it is never installed, so "+
				"no later teardown can reach it")
	}
}

// gatedStubRegistry holds every constructor until the test has as many in flight as it wants.
type gatedStubRegistry struct {
	access  sync.Mutex
	created []*stubOutbound
	entered chan struct{}
	release chan struct{}
}

func (r *gatedStubRegistry) CreateOptions(outboundType string) (any, bool) {
	return &optionStub{}, true
}

func (r *gatedStubRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	outbound := &stubOutbound{tag: tag}
	r.access.Lock()
	r.created = append(r.created, outbound)
	r.access.Unlock()
	r.entered <- struct{}{}
	<-r.release
	return outbound, nil
}

func (r *gatedStubRegistry) OptionTypes() []string { return []string{"stub"} }

func (r *gatedStubRegistry) objects() []*stubOutbound {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]*stubOutbound(nil), r.created...)
}

// recordingStubRegistry keeps the objects it constructed, so a test can observe what happened to
// the ones that lost the race and were therefore never installed.
type recordingStubRegistry struct {
	access  sync.Mutex
	created []*stubOutbound
}

func (r *recordingStubRegistry) CreateOptions(outboundType string) (any, bool) {
	return &optionStub{}, true
}

func (r *recordingStubRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	outbound := &stubOutbound{tag: tag}
	r.access.Lock()
	r.created = append(r.created, outbound)
	r.access.Unlock()
	return outbound, nil
}

func (r *recordingStubRegistry) OptionTypes() []string { return []string{"stub"} }

func (r *recordingStubRegistry) objects() []*stubOutbound {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]*stubOutbound(nil), r.created...)
}
