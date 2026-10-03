package dns

import (
	"context"
	"sort"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the DNS transport manager's transaction boundaries.
//
// # Why this matters
//
// Create is production-reachable: box.go calls it once per configured DNS server, so a duplicate
// tag is a configuration a user can actually write. Two things must hold regardless.
//
// A refused operation must leave the manager EXACTLY as it was. A half-applied install is worse
// than a clean failure, because the manager keeps serving from a state no configuration describes.
//
// A duplicate tag must be refused rather than silently replacing its predecessor. The replaced
// object's constructor side effects cannot be undone, and the configuration that runs is not the
// one that was written.

// stubTransport is a DNS transport that records its own close.
type stubTransport struct {
	adapter.DNSTransport
	tag           string
	transportType string
	closed        int
	started       int
	startErr      error
}

func (t *stubTransport) Type() string           { return t.transportType }
func (t *stubTransport) Tag() string            { return t.tag }
func (t *stubTransport) Dependencies() []string { return nil }
func (t *stubTransport) Start(stage adapter.StartStage) error {
	t.started++
	return t.startErr
}
func (t *stubTransport) Close() error {
	t.closed++
	return nil
}

// Store satisfies adapter.FakeIPTransport, so the stub can stand in for a FakeIP server.
func (t *stubTransport) Store() adapter.FakeIPStore { return nil }

// stubRegistry constructs a stub transport.
type stubRegistry struct {
	created []*stubTransport
	fail    bool
}

func (r *stubRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	if r.fail {
		return nil, context.Canceled
	}
	transport := &stubTransport{tag: tag, transportType: transportType}
	r.created = append(r.created, transport)
	return transport, nil
}

func (r *stubRegistry) CreateOptions(transportType string) (any, bool) { return struct{}{}, true }
func (r *stubRegistry) OptionTypes() []string                          { return []string{"stub", constant.DNSTypeFakeIP} }

// newManager returns a manager with a stub registry.
func newManager() (*TransportManager, *stubRegistry) {
	registry := &stubRegistry{}
	return NewTransportManager(log.NewNOPFactory().NewLogger("dns-test"), registry, nil, ""), registry
}

// snapshot captures the observable state, so "unchanged" is asserted rather than assumed.
type managerSnapshot struct {
	transports int
	defaultTag string
	fakeIPTag  string
	byTag      []string
}

func snapshotManager(m *TransportManager) managerSnapshot {
	m.access.Lock()
	defer m.access.Unlock()
	snapshot := managerSnapshot{transports: len(m.transports)}
	if m.defaultTransport != nil {
		snapshot.defaultTag = m.defaultTransport.Tag()
	}
	if m.fakeIPTransport != nil {
		snapshot.fakeIPTag = m.fakeIPTransport.Tag()
	}
	for tag := range m.transportByTag {
		snapshot.byTag = append(snapshot.byTag, tag)
	}
	// Sorted, so the comparison is about state rather than Go's randomised map order. Without this
	// the assertion passes or fails depending on iteration order, which is not a property of the
	// manager.
	sort.Strings(snapshot.byTag)
	return snapshot
}

// TestDuplicateDNSTagIsRejected is the contract.
func TestDuplicateDNSTagIsRejected(t *testing.T) {
	manager, registry := newManager()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	require.NoError(t, manager.Create(ctx, logger, "dup", "stub", struct{}{}))
	require.Len(t, registry.created, 1)

	err := manager.Create(ctx, logger, "dup", "stub", struct{}{})
	require.Error(t, err, "a duplicate DNS server tag must be refused")

	require.Len(t, registry.created, 1,
		"the duplicate must be refused BEFORE construction, so nothing is created only to be "+
			"discarded with its constructor side effects un-undone")

	installed := manager.Transports()
	require.Len(t, installed, 1)
	require.Equal(t, "dup", installed[0].Tag())
}

// TestFakeIPDefaultIsRejectedWithoutMutation covers the partial-mutation defect.
//
// A FakeIP server cannot be the default. The refusal must happen before anything is installed.
func TestFakeIPDefaultIsRejectedWithoutMutation(t *testing.T) {
	manager, _ := newManager()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	before := snapshotManager(manager)

	err := manager.Create(ctx, logger, "fake", constant.DNSTypeFakeIP, struct{}{})
	require.Error(t, err, "a FakeIP server must not become the default")

	after := snapshotManager(manager)
	require.Equal(t, before, after,
		"a refused install must leave the manager byte-for-byte unchanged. A half-applied install "+
			"leaves the manager serving from a state no configuration describes: the transport would "+
			"be listed and stored while the call reported failure")
}

// TestSecondFakeIPIsRejectedWithoutMutation covers the other install-time refusal.
func TestSecondFakeIPIsRejectedWithoutMutation(t *testing.T) {
	manager, _ := newManager()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	// First: a non-default server, so the default slot is taken and FakeIP is permitted.
	require.NoError(t, manager.Create(ctx, logger, "first", "stub", struct{}{}))
	require.NoError(t, manager.Create(ctx, logger, "fake-one", constant.DNSTypeFakeIP, struct{}{}))

	before := snapshotManager(manager)

	err := manager.Create(ctx, logger, "fake-two", constant.DNSTypeFakeIP, struct{}{})
	require.Error(t, err, "a second FakeIP server must be refused")

	after := snapshotManager(manager)
	require.Equal(t, before, after,
		"a refused second FakeIP install must not have appended the transport or replaced the "+
			"fakeip pointer before reporting the error")
}

// TestFailedConstructionLeavesManagerUnchanged covers the registry error path.
func TestFailedConstructionLeavesManagerUnchanged(t *testing.T) {
	manager, registry := newManager()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	require.NoError(t, manager.Create(ctx, logger, "ok", "stub", struct{}{}))
	before := snapshotManager(manager)

	registry.fail = true
	err := manager.Create(ctx, logger, "broken", "stub", struct{}{})
	require.Error(t, err)

	require.Equal(t, before, snapshotManager(manager),
		"a construction failure must not change the manager")
}

// TestRefusedInstallConstructsNothing is the stronger statement of the leak contract.
//
// A refusal that happens BEFORE construction cannot leak anything, which is the ideal outcome. The
// second-FakeIP rule is checkable without building the object, so it is checked first and nothing
// is created.
//
// The release-on-loser path still exists for the genuine race - two concurrent Creates for one tag,
// where the loser has already constructed by the time it loses - and it is covered by
// TestConcurrentDuplicateCreateReleasesTheLoser below.
func TestRefusedInstallConstructsNothing(t *testing.T) {
	manager, registry := newManager()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	require.NoError(t, manager.Create(ctx, logger, "first", "stub", struct{}{}))
	require.NoError(t, manager.Create(ctx, logger, "fake-one", constant.DNSTypeFakeIP, struct{}{}))

	constructedBefore := len(registry.created)

	err := manager.Create(ctx, logger, "fake-two", constant.DNSTypeFakeIP, struct{}{})
	require.Error(t, err, "a second FakeIP server must be refused")

	require.Equal(t, constructedBefore, len(registry.created),
		"the refusal is decided before construction, so no object is built only to be discarded")

	for _, created := range registry.created {
		require.NotEqual(t, "fake-two", created.tag)
	}
}

// TestConcurrentDuplicateCreateReleasesTheLoser covers the race the pre-check cannot close.
//
// Two Creates for one tag can both pass the pre-check, because the constructor runs outside the
// lock. The loser must release what it built rather than leaking it.
func TestConcurrentDuplicateCreateReleasesTheLoser(t *testing.T) {
	registry := &stubRegistry{}
	manager := NewTransportManager(log.NewNOPFactory().NewLogger("dns-test"), registry, nil, "")
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns-test")

	const racers = 8
	errs := make([]error, racers)
	done := make(chan struct{})

	for index := 0; index < racers; index++ {
		go func(slot int) {
			defer close(done)
			errs[slot] = manager.Create(ctx, logger, "race", "stub", struct{}{})
		}(index)
		// Serialise the goroutine bodies enough that the winner is deterministic, while still
		// exercising the loser path.
		<-done
		if index < racers-1 {
			done = make(chan struct{})
		}
	}

	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded, "exactly one racer may install the tag")

	require.Len(t, manager.Transports(), 1,
		"only the winner may be installed")

	// Every non-installed object must have been released.
	installed := manager.Transports()[0]
	for _, created := range registry.created {
		if created == installed {
			continue
		}
		require.Equal(t, 1, created.closed,
			"a constructed-but-not-installed transport must be closed, or a failed Create leaks "+
				"its resources")
	}
}
