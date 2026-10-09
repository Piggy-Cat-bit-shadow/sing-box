package rule

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The store-before-purge window: MEASURED, and then explained
// ---------------------------------------------------------------------------
//
// `experimental/clashmode/manager.go` SetMode does this, in this order:
//
//	m.mode.Store(newMode)          // the new policy is now VISIBLE to routing
//	m.updateAccess.Unlock()
//	... hooks ...
//	m.dnsRouter.ClearCache()       // the answers the old policy's server produced are dropped
//
// So there IS an interval in which a `clash_mode` rule matches the NEW mode while the previous policy's
// cached answers are still live. This file MEASURES that interval rather than arguing about it.
//
// # What was implemented, measured, and REVERTED
//
// Moving `ClearCache()` inside the critical section was written, and it does NOT close the window:
// `Mode()` is lock-free by design, so a reader is not blocked by the writer holding the mutex. The
// measurement below records the window as it is; the production file is byte-identical to what is
// already pushed, because holding a control lock across cache work would have bought nothing.
//
// Whether the window can serve a WRONG answer is a different question, answered by the DNS cache key
// rather than by this ordering - see docs/fork/v016-path-mtu-audit.md.

// windowDNSRouter is a DNSRouter that records the mode observed when its cache is invalidated, and can
// hold the invalidation open so a reader is interleaved by construction instead of by luck.
type windowDNSRouter struct {
	modeAtInvalidation atomic.Value // string
	invalidations      atomic.Int64
	observer           func() string
	entered            func()
}

func (r *windowDNSRouter) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (r *windowDNSRouter) Close() error                                               { return nil }

func (r *windowDNSRouter) Exchange(context.Context, *mDNS.Msg, adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, nil
}

func (r *windowDNSRouter) ExchangeAsync(context.Context, *mDNS.Msg, adapter.DNSQueryOptions, func(*mDNS.Msg, error)) {
}

func (r *windowDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, nil
}

func (r *windowDNSRouter) ClearCache() {
	if r.entered != nil {
		r.entered()
	}
	if r.observer != nil {
		r.modeAtInvalidation.Store(r.observer())
	}
	r.invalidations.Add(1)
}

func (r *windowDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (r *windowDNSRouter) ResetNetwork()                                  {}

func newWindowHarness(t *testing.T) (*clashmode.Manager, *windowDNSRouter, *ClashModeItem) {
	t.Helper()
	dnsRouter := &windowDNSRouter{}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
	manager := clashmode.NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
	dnsRouter.observer = manager.Mode

	// The production rule item, wired exactly as the router wires it.
	service.MustRegisterPtr(ctx, manager)
	item := NewClashModeItem(ctx, "Global")
	require.NoError(t, item.Start())
	return manager, dnsRouter, item
}

// TestTheWindowExistsAndIsMeasurable is the measurement. It makes no claim about harm.
//
// It holds the invalidation open and asks the production rule item what it matches in that interval.
// The recorded result is that it matches the NEW mode: that is the window. Stating it as an assertion
// means a future reordering that changes it becomes visible instead of silent.
func TestTheWindowExistsAndIsMeasurable(t *testing.T) {
	manager, dnsRouter, itemNew := newWindowHarness(t)
	require.Equal(t, "Rule", manager.Mode())
	metadata := &adapter.InboundContext{}

	inInvalidation := make(chan struct{})
	releaseInvalidation := make(chan struct{})
	dnsRouter.entered = func() {
		close(inInvalidation)
		<-releaseInvalidation
	}

	switched := make(chan struct{})
	go func() {
		defer close(switched)
		manager.SetMode("Global")
	}()

	select {
	case <-inInvalidation:
	case <-time.After(10 * time.Second):
		t.Fatal("the switch never reached the cache invalidation")
	}

	// What would a `clash_mode=Global` rule decide right now, while the previous policy's cached
	// answers are still live?
	answer := make(chan bool, 1)
	go func() { answer <- itemNew.Match(metadata) }()

	observed := false
	gotAnswer := false
	select {
	case observed = <-answer:
		gotAnswer = true
	case <-time.After(2 * time.Second):
		// A reader that blocked would be a different design; it is not this one.
	}

	close(releaseInvalidation)
	select {
	case <-switched:
	case <-time.After(10 * time.Second):
		t.Fatal("SetMode never returned")
	}
	require.Equal(t, "Global", manager.Mode())

	require.True(t, gotAnswer,
		"the routing read is lock-free by design and must not block on the control plane")
	require.True(t, observed,
		"MEASURED: `clash_mode=Global` matches while the previous policy's cached answers are still "+
			"being invalidated. The store-before-purge window is real and is recorded here rather than "+
			"denied; whether it can serve a WRONG answer is a separate question, answered by the DNS "+
			"cache key in the audit document")
}

// TestTheInvalidationObservesTheNewMode records the ordering itself, so both steps are visible side by
// side in one place.
func TestTheInvalidationObservesTheNewMode(t *testing.T) {
	manager, dnsRouter, _ := newWindowHarness(t)

	require.Equal(t, "Rule", manager.Mode())
	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode())
	require.EqualValues(t, 1, dnsRouter.invalidations.Load(),
		"the switch must reach the cache invalidation at all")

	observed, _ := dnsRouter.modeAtInvalidation.Load().(string)
	require.Equal(t, "Global", observed,
		"the invalidation runs AFTER the mode is published, which is the window: for the duration of "+
			"the purge, routing is on the new policy while the old policy's answers are still served")
}

// TestRepeatedSwitchesInvalidateOncePerRealChange keeps the existing contract intact.
func TestRepeatedSwitchesInvalidateOncePerRealChange(t *testing.T) {
	manager, dnsRouter, _ := newWindowHarness(t)

	manager.SetMode("Global")
	manager.SetMode("Global")
	require.EqualValues(t, 1, dnsRouter.invalidations.Load(),
		"a redundant switch must not drop a warm cache")

	manager.SetMode("Direct")
	require.EqualValues(t, 2, dnsRouter.invalidations.Load())

	manager.SetMode("NoSuchMode")
	require.EqualValues(t, 2, dnsRouter.invalidations.Load())
	require.Equal(t, "Direct", manager.Mode())
}
