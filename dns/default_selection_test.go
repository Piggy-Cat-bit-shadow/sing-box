package dns

import (
	"context"
	"sync"
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
}

// incapableFakeIPRegistry produces a transport that reports the fakeip type but cannot serve it.
type incapableFakeIPRegistry struct {
	adapter.DNSTransportRegistry
}

func (r *incapableFakeIPRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	// No Store method, so it does not satisfy adapter.FakeIPTransport.
	return &incapableTransport{tag: tag}, nil
}

type incapableTransport struct {
	adapter.DNSTransport
	tag string
}

func (t *incapableTransport) Type() string                         { return "fakeip" }
func (t *incapableTransport) Tag() string                          { return t.tag }
func (t *incapableTransport) Dependencies() []string               { return nil }
func (t *incapableTransport) Start(stage adapter.StartStage) error { return nil }
func (t *incapableTransport) Close() error                         { return nil }
func (t *incapableTransport) Reset()                               {}
