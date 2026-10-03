package dns

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for which DNS server becomes the default when several are created concurrently.
//
// # Why this is the interesting race
//
// The manager selects a default by an EMPTY-SLOT test rather than by configuration: when no default
// tag is configured, the first transport to find the slot empty claims it. Two concurrent Creates
// therefore both evaluate "am I the default candidate" against the same initial state, and the winner
// is whichever reaches the install lock first.
//
// That is not necessarily wrong - with no configured default, "one of them" is the only answer
// available - but it must be a DEFINED outcome rather than a scheduler accident, and exactly one
// transport may hold the slot.

// defaultTrackingRegistry creates stub transports that report the requested type.
type defaultTrackingRegistry struct {
	adapter.DNSTransportRegistry
}

func (r *defaultTrackingRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	return &selectionTransport{tag: tag, transportType: transportType}, nil
}

// selectionTransport is an inert transport used only for identity and type.
type selectionTransport struct {
	adapter.DNSTransport
	tag           string
	transportType string
}

func (t *selectionTransport) Type() string                         { return t.transportType }
func (t *selectionTransport) Tag() string                          { return t.tag }
func (t *selectionTransport) Dependencies() []string               { return nil }
func (t *selectionTransport) Start(stage adapter.StartStage) error { return nil }
func (t *selectionTransport) Close() error                         { return nil }
func (t *selectionTransport) Reset()                               {}

// TestConcurrentCreatesElectExactlyOneDefault is L1.
//
// Several normal servers racing for an unconfigured default slot must end with exactly one holder,
// and the holder must be a transport that is actually installed - not a cancelled or discarded one.
func TestConcurrentCreatesElectExactlyOneDefault(t *testing.T) {
	manager := NewTransportManager(log.NewNOPFactory().Logger(), &defaultTrackingRegistry{}, nil, "")
	manager.logger = log.NewNOPFactory().Logger()

	const creators = 8
	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
		access    sync.Mutex
		errs      []error
	)

	for index := 0; index < creators; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			err := manager.Create(context.Background(), manager.logger,
				"server-"+string(rune('a'+index)), "udp", nil)
			access.Lock()
			errs = append(errs, err)
			access.Unlock()
		}(index)
	}
	close(start)
	waitGroup.Wait()

	// Every server has a distinct tag, so every create must succeed.
	for _, err := range errs {
		require.NoError(t, err, "a distinct tag must not be refused by a concurrent create")
	}

	require.Len(t, manager.transports, creators, "all servers are installed")

	// Exactly one default, and it is one of the installed transports.
	manager.access.Lock()
	defaultTransport := manager.defaultTransport
	installed := make([]adapter.DNSTransport, len(manager.transports))
	copy(installed, manager.transports)
	manager.access.Unlock()

	require.NotNil(t, defaultTransport,
		"an unconfigured default slot must be claimed by exactly one transport, not left empty")

	require.Contains(t, installed, defaultTransport,
		"the default must be a transport that is actually installed. A default pointing at a "+
			"transport that was discarded or never installed would make every default lookup fail")

	holders := 0
	for _, transport := range installed {
		if transport == defaultTransport {
			holders++
		}
	}
	require.Equal(t, 1, holders)
}

// TestConcurrentFakeIPAndNormalDoNotBothClaimDefault is L2.
//
// A FakeIP server can never be the default. When a normal server and a FakeIP server race for an
// empty default slot, the FakeIP server must be refused rather than transiently becoming the default,
// and the normal server must end up holding it.
func TestConcurrentFakeIPAndNormalDoNotBothClaimDefault(t *testing.T) {
	manager := NewTransportManager(log.NewNOPFactory().Logger(), &defaultTrackingRegistry{}, nil, "")
	manager.logger = log.NewNOPFactory().Logger()

	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
		normalErr error
		fakeIPErr error
	)

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-start
		normalErr = manager.Create(context.Background(), manager.logger, "normal", "udp", nil)
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		fakeIPErr = manager.Create(context.Background(), manager.logger, "fake", "fakeip", nil)
	}()
	close(start)
	waitGroup.Wait()

	require.NoError(t, normalErr, "the normal server must install")

	manager.access.Lock()
	defaultTransport := manager.defaultTransport
	fakeIPTransport := manager.fakeIPTransport
	manager.access.Unlock()

	require.NotNil(t, defaultTransport)
	require.NotEqual(t, "fake", defaultTransport.Tag(),
		"a FakeIP server became the default. FakeIP addresses are placeholders, so every default "+
			"lookup would resolve into the virtual range")

	if fakeIPErr == nil {
		require.NotNil(t, fakeIPTransport)
		require.Equal(t, "fake", fakeIPTransport.Tag())
	} else {
		require.Nil(t, fakeIPTransport,
			"the FakeIP create failed, so it must not have been installed")
	}
}

// TestFakeIPTypeWithoutTheCapabilityIsRefused closes a latent panic.
//
// The installer asserted adapter.FakeIPTransport on any transport reporting the fakeip type. The
// built-in one implements it, so the built-in registry cannot reach the failure - but the registry
// is extensible, and a type name is a string a transport reports about itself. An assert on it is a
// process-wide panic waiting for a third-party transport that gets the string wrong.
//
// The refusal must also leave the manager exactly as it was: no half-installed transport, and no
// entry in the tag or default maps pointing at something that was discarded.
func TestFakeIPTypeWithoutTheCapabilityIsRefused(t *testing.T) {
	registry := &incapableFakeIPRegistry{}
	// A configured default tag, so the "a fakeip server cannot be the default" pre-check does not
	// fire first and the capability assertion is the one under test.
	manager := NewTransportManager(log.NewNOPFactory().Logger(), registry, nil, "configured-default")
	manager.logger = log.NewNOPFactory().Logger()

	err := manager.Create(context.Background(), manager.logger, "bad-fakeip", "fakeip", nil)
	require.Error(t, err,
		"a transport that reports the fakeip type without the capability must be refused, not "+
			"asserted into a panic")
	require.Contains(t, err.Error(), "fakeip capability")

	manager.access.Lock()
	defer manager.access.Unlock()
	require.Empty(t, manager.transports, "nothing may remain installed")
	require.NotContains(t, manager.transportByTag, "bad-fakeip")
	require.Nil(t, manager.fakeIPTransport)
	require.Nil(t, manager.defaultTransport,
		"a failed install must not leave itself as the default")
	require.Empty(t, manager.dependByTag,
		"and it must not leave dependency entries pointing at a transport that was discarded")
}

// TestFakeIPInvalidTransportIsClosedExactlyOnce is Part G's leak half.
//
// The refused transport was constructed, so it must be released - once, not zero times and not
// twice. A transport that is never closed leaks whatever the constructor opened, and double-closing
// is undefined for most of them.
func TestFakeIPInvalidTransportIsClosedExactlyOnce(t *testing.T) {
	registry := &incapableFakeIPRegistry{}
	manager := NewTransportManager(log.NewNOPFactory().Logger(), registry, nil, "configured-default")
	manager.logger = log.NewNOPFactory().Logger()

	err := manager.Create(context.Background(), manager.logger, "bad-fakeip", "fakeip", nil)
	require.Error(t, err, "the invalid FakeIP transport is refused")

	require.EqualValues(t, 1, registry.created.Load(), "exactly one transport was constructed")

	// The rollback path defers the close, so it has run by the time Create returns.
	require.NotNil(t, registry.last())
	require.EqualValues(t, 1, registry.last().closeCalls.Load(),
		"the refused transport must be released exactly once: leaking it abandons whatever the "+
			"constructor opened, and closing it twice is undefined for most transports")
}

// TestConcurrentInvalidFakeIPDoesNotLeak is Part G under concurrency.
func TestConcurrentInvalidFakeIPDoesNotLeak(t *testing.T) {
	registry := &incapableFakeIPRegistry{}
	manager := NewTransportManager(log.NewNOPFactory().Logger(), registry, nil, "configured-default")
	manager.logger = log.NewNOPFactory().Logger()

	const attempts = 8
	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
	)

	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_ = manager.Create(context.Background(), manager.logger, "bad-"+string(rune('a'+index)), "fakeip", nil)
		}()
	}
	close(start)
	waitGroup.Wait()

	manager.access.Lock()
	defer manager.access.Unlock()
	require.Empty(t, manager.transports, "no failed install may remain registered")
	require.Empty(t, manager.transportByTag)
	require.Nil(t, manager.fakeIPTransport)
	require.Nil(t, manager.defaultTransport)

	require.EqualValues(t, attempts, registry.closedTotal.Load(),
		"every constructed transport must be closed exactly once across the concurrent attempts")
}

// incapableFakeIPRegistry produces a transport that reports the fakeip type but cannot serve it.
type incapableFakeIPRegistry struct {
	adapter.DNSTransportRegistry

	created     atomic.Int32
	closedTotal atomic.Int32
	// lastTransport is guarded: concurrent creates write it.
	lastAccess    sync.Mutex
	lastTransport *incapableTransport
}

func (r *incapableFakeIPRegistry) recordTransport(transport *incapableTransport) {
	r.lastAccess.Lock()
	r.lastTransport = transport
	r.lastAccess.Unlock()
}

func (r *incapableFakeIPRegistry) last() *incapableTransport {
	r.lastAccess.Lock()
	defer r.lastAccess.Unlock()
	return r.lastTransport
}

func (r *incapableFakeIPRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	// No Store method, so it does not satisfy adapter.FakeIPTransport.
	transport := &incapableTransport{tag: tag, registry: r}
	r.created.Add(1)
	r.recordTransport(transport)
	return transport, nil
}

type incapableTransport struct {
	adapter.DNSTransport
	tag      string
	registry *incapableFakeIPRegistry
	// closeCalls counts how many times THIS transport was closed.
	closeCalls atomic.Int32
}

func (t *incapableTransport) Close() error {
	t.closeCalls.Add(1)
	if t.registry != nil {
		t.registry.closedTotal.Add(1)
	}
	return nil
}

func (t *incapableTransport) Type() string                         { return "fakeip" }
func (t *incapableTransport) Tag() string                          { return t.tag }
func (t *incapableTransport) Dependencies() []string               { return nil }
func (t *incapableTransport) Start(stage adapter.StartStage) error { return nil }
func (t *incapableTransport) Reset()                               {}
