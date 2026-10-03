package outbound

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Tests for duplicate outbound tags.
//
// # Why a duplicate is a lifecycle problem, not a style preference
//
// A tag that already exists is SILENTLY REPLACED and the replaced object is discarded, so its
// constructor side effects are never undone. The bridge outbound shows the consequence concretely:
// it claims a process-global slot at construction, and once the object holding it is unreachable
// nothing can ever release it.
//
// The configuration the user wrote is also not the configuration that runs: whichever entry loads
// last wins with no diagnostic.

// stubRegistry constructs a stub outbound for any type.
type stubRegistry struct {
	constructed atomic.Int32
}

func (r *stubRegistry) CreateOptions(outboundType string) (any, bool) {
	return &optionStub{}, true
}

func (r *stubRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	r.constructed.Add(1)
	return &stubOutbound{tag: tag}, nil
}

func (r *stubRegistry) OptionTypes() []string { return []string{"stub"} }

type optionStub struct{}

// stubOutbound is an outbound that records its own close.
type stubOutbound struct {
	adapter.Outbound
	tag    string
	closed atomic.Int32
}

func (o *stubOutbound) Type() string           { return "stub" }
func (o *stubOutbound) Tag() string            { return o.tag }
func (o *stubOutbound) Network() []string      { return []string{"tcp"} }
func (o *stubOutbound) Dependencies() []string { return nil }
func (o *stubOutbound) Close() error {
	o.closed.Add(1)
	return nil
}

// installOutbound puts an outbound into the manager the way startup does.
func installOutbound(t *testing.T, manager *Manager, outbound adapter.Outbound) {
	t.Helper()
	manager.access.Lock()
	manager.outbounds = append(manager.outbounds, outbound)
	manager.outboundByTag[outbound.Tag()] = outbound
	manager.access.Unlock()
}

// TestDuplicateTagIsRejected is the contract.
//
// A duplicate must be refused so the configuration the user wrote is what runs, and so no
// constructed object is silently orphaned.
func TestDuplicateTagIsRejected(t *testing.T) {
	existing := &stubOutbound{tag: "dup"}
	registry := &stubRegistry{}
	manager := NewManager(registry, nil, "")
	installOutbound(t, manager, existing)

	err := manager.Create(context.Background(), nil, log.NewNOPFactory().NewLogger("test"),
		"dup", "stub", &optionStub{})

	require.Error(t, err, "a duplicate outbound tag must be refused")

	// The original is intact and still installed.
	installed, loaded := manager.Outbound("dup")
	require.True(t, loaded)
	require.Same(t, existing, installed,
		"the original must still be installed: silently replacing it discards an object whose "+
			"constructor side effects can never be undone")
	require.Equal(t, int32(0), existing.closed.Load(),
		"and it must not have been closed as part of a replacement")

	// The duplicate must not have been constructed at all, so nothing is leaked.
	require.Equal(t, int32(0), registry.constructed.Load(),
		"a duplicate tag must be refused BEFORE the object is constructed, so no constructor side "+
			"effect - a global slot, a socket, a goroutine - is created only to be orphaned")
}

// TestDuplicateTagDoesNotLeakTheReplacedObject is the resource statement.
func TestDuplicateTagDoesNotLeakTheReplacedObject(t *testing.T) {
	existing := &stubOutbound{tag: "dup"}
	registry := &stubRegistry{}
	manager := NewManager(registry, nil, "")
	installOutbound(t, manager, existing)

	_ = manager.Create(context.Background(), nil, log.NewNOPFactory().NewLogger("test"),
		"dup", "stub", &optionStub{})

	outbounds := manager.Outbounds()
	count := 0
	for _, outbound := range outbounds {
		if outbound.Tag() == "dup" {
			count++
		}
	}
	require.Equal(t, 1, count,
		"exactly one outbound may be installed under a tag; a second would leave one of them "+
			"unreachable by Close and its construction side effects permanently leaked")
}

var _ = badoption.Listable[string]{}
