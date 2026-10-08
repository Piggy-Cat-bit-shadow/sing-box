package dns

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the DNS transport manager's half of the cross-kind cycle validation.
//
// The graph walk itself is tested in adapter/outbound (its natural home: it needs both namespaces
// and the outbound Adapter's resolver edge). What is pinned here is the WIRING, because the whole
// reason the defect existed is that two managers each assumed the other one checked:
//
//	the validation must run BEFORE any transport is started;
//	it must see every transport that is about to be started;
//	its error must reach box.Start() unchanged;
//	and it must be optional, so a manager built without a DNS-aware outbound manager behaves exactly
//	as it did before the check existed.

// fakeCrossKindValidator is an outbound manager with the validation capability.
type fakeCrossKindValidator struct {
	adapter.OutboundManager
	calls      int
	transports []adapter.DNSTransport
	err        error
}

func (v *fakeCrossKindValidator) ValidateCrossKindCycles(transports []adapter.DNSTransport) error {
	v.calls++
	v.transports = transports
	return v.err
}

// cycleStubTransport is a stub transport with a detour, so the validator's input carries the edge
// the real TransportAdapter would report.
type cycleStubTransport struct {
	*stubTransport
	references []string
}

func (t *cycleStubTransport) References() []string { return t.references }

// installCycleTransport puts a transport into the manager the way box.go's Create calls do.
func installCycleTransport(manager *TransportManager, transport *cycleStubTransport) {
	manager.access.Lock()
	manager.transports = append(manager.transports, transport)
	manager.transportByTag[transport.Tag()] = transport
	manager.access.Unlock()
}

func cycleStub(tag string) *cycleStubTransport {
	return &cycleStubTransport{
		stubTransport: &stubTransport{tag: tag, transportType: "stub"},
		references:    []string{"proxy"},
	}
}

// TestCrossKindCycleValidationRunsBeforeAnyTransportStarts is the ordering assertion, and it is the
// one that matters: a check that ran after startTransports would report the cycle only after the
// transports it is about were already live, and for a transport that establishes during Start that
// is too late.
func TestCrossKindCycleValidationRunsBeforeAnyTransportStarts(t *testing.T) {
	validator := &fakeCrossKindValidator{err: errCycleForTest}
	manager := NewTransportManager(nil, validator, "")
	transport := cycleStub("remote")
	installCycleTransport(manager, transport)

	err := manager.Start(adapter.StartStateStart, adapter.NewScope(t.Context(), log.NewNOPFactory().Logger()))

	require.ErrorIs(t, err, errCycleForTest)
	require.Equal(t, 1, validator.calls, "the validation must run exactly once")
	require.Zero(t, transport.started, "no transport may start before the cross-kind graph is validated")
}

// TestCrossKindCycleValidationSeesEveryTransportOfTheStartSet checks the input, not just the call:
// a validator handed an empty or partial list would clear a cycle for the wrong reason.
func TestCrossKindCycleValidationSeesEveryTransportOfTheStartSet(t *testing.T) {
	validator := &fakeCrossKindValidator{}
	manager := NewTransportManager(nil, validator, "")
	remote := cycleStub("remote")
	bootstrap := cycleStub("bootstrap")
	installCycleTransport(manager, remote)
	installCycleTransport(manager, bootstrap)

	err := manager.Start(adapter.StartStateStart, adapter.NewScope(t.Context(), log.NewNOPFactory().Logger()))

	require.NoError(t, err)
	require.Equal(t, 1, validator.calls)
	tags := make([]string, 0, len(validator.transports))
	for _, transport := range validator.transports {
		tags = append(tags, transport.Tag())
	}
	require.ElementsMatch(t, []string{"remote", "bootstrap"}, tags)
	require.Equal(t, 1, remote.started, "a validated acyclic set must start normally")
	require.Equal(t, 1, bootstrap.started)
}

// TestCrossKindCycleValidationIsOptional is the compatibility contract.
//
// The capability is asked for directly rather than added to adapter.OutboundManager, so a manager
// built with an implementation that has no opinion - a test double, a third-party manager - must
// start exactly as before.
func TestCrossKindCycleValidationIsOptional(t *testing.T) {
	manager := NewTransportManager(nil, nil, "")
	transport := cycleStub("remote")
	installCycleTransport(manager, transport)

	err := manager.Start(adapter.StartStateStart, adapter.NewScope(t.Context(), log.NewNOPFactory().Logger()))

	require.NoError(t, err)
	require.Equal(t, 1, transport.started)
}

// errCycleForTest stands in for the graph walk's error, so the wiring is tested without depending
// on a particular cycle's spelling.
var errCycleForTest = errorString("circular dependency between DNS server and outbound")

type errorString string

func (e errorString) Error() string { return string(e) }
