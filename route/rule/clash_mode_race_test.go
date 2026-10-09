package rule

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The race this file pins
// ---------------------------------------------------------------------------
//
// WRITE: `experimental/clashmode/manager.go` SetMode assigns `m.mode = newMode` (line 88) with no lock.
// The Manager's only mutex, `updateAccess`, guards `updateHooks` and nothing else. `Start` assigns the
// field too (line 56) when a persisted mode is restored. `PATCH /configs`
// (`experimental/clashapi/configs.go:63`) and the daemon's service API
// (`daemon/started_service.go:750`) both reach SetMode from outside the process.
//
// READ: `Manager.Mode` (line 63) returns the field directly, and its caller here -
// `ClashModeItem.Match` (route/rule/rule_item_clash_mode.go:36) - runs for EVERY connection that
// reaches a `clash_mode` rule. `route/reference.go:215` reads it while building rule references.
//
// So a controller switching mode and a live connection being routed touch the same string header with
// nothing between them. These tests build that interleaving out of the PRODUCTION Manager and the
// PRODUCTION ClashModeItem, so the race they report is the product's, not a copy's.

// ---------------------------------------------------------------------------
// Doubles - collaborators only, never the object under test
// ---------------------------------------------------------------------------

// countingDNSRouter is a DNSRouter that counts ClearCache and answers nothing.
//
// It exists so a mode change can be observed reaching its cache invalidation without standing up a
// resolver: the race is inside Manager, and a real router would only add noise.
type countingDNSRouter struct {
	flushes atomic.Int64
}

func (r *countingDNSRouter) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (r *countingDNSRouter) Close() error                                               { return nil }

func (r *countingDNSRouter) Exchange(context.Context, *mDNS.Msg, adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, nil
}

func (r *countingDNSRouter) ExchangeAsync(context.Context, *mDNS.Msg, adapter.DNSQueryOptions, func(*mDNS.Msg, error)) {
}

func (r *countingDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, nil
}

func (r *countingDNSRouter) ClearCache() { r.flushes.Add(1) }

func (r *countingDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (r *countingDNSRouter) ResetNetwork()                                  {}

// newClashModeManager builds a real Manager plus the DNS router it will invalidate.
func newClashModeManager(t *testing.T) (*clashmode.Manager, *countingDNSRouter) {
	t.Helper()
	dnsRouter := &countingDNSRouter{}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
	manager := clashmode.NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Global", "Direct"})
	return manager, dnsRouter
}

// newClashModeRule builds a started ClashModeItem backed by the given manager.
//
// The rule reaches the manager through the context - `ClashModeItem.Start` does
// `service.PtrFromContext[clashmode.Manager]` - so a rule built here is wired exactly as the router
// wires it, and `Match` is the production code path.
func newClashModeRule(t *testing.T, mode string, manager *clashmode.Manager) *ClashModeItem {
	t.Helper()
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), &countingDNSRouter{})
	// Registered exactly as box.go:412 does it - `service.MustRegisterPtr(ctx, clashMode)` - because the
	// rule resolves it with `service.PtrFromContext[clashmode.Manager]`. Registering the value instead
	// would copy the Manager's mutex and the lookup would not find it at all.
	service.MustRegisterPtr(ctx, manager)
	item := NewClashModeItem(ctx, mode)
	require.NoError(t, item.Start())
	require.NotNil(t, item.clashMode, "the rule must have reached the manager through the context")
	require.Same(t, manager, item.clashMode, "the rule must hold the same manager the controller writes")
	return item
}

// ---------------------------------------------------------------------------
// The race
// ---------------------------------------------------------------------------

// TestClashModeReadsAreRaceFreeWhileTheControllerSwitches reports a data race on the unfixed tree.
//
// Run under -race before the fix:
//
//	WARNING: DATA RACE
//	Write at 0x... by goroutine N:
//	  github.com/sagernet/sing-box/experimental/clashmode.(*Manager).SetMode()
//	      experimental/clashmode/manager.go:88
//	Previous read at 0x... by goroutine M:
//	  github.com/sagernet/sing-box/experimental/clashmode.(*Manager).Mode()
//	      experimental/clashmode/manager.go:63
//	  github.com/sagernet/sing-box/route/rule.(*ClashModeItem).Match()
//	      route/rule/rule_item_clash_mode.go:36
//
// The readers call both entry points on purpose: Mode() is the API read side (GET /configs,
// route/reference.go) and Match() is the routing hot path. Both are real callers; neither is a
// contrived accessor.
func TestClashModeReadsAreRaceFreeWhileTheControllerSwitches(t *testing.T) {
	manager, dnsRouter := newClashModeManager(t)
	itemRule := newClashModeRule(t, "Rule", manager)
	itemGlobal := newClashModeRule(t, "Global", manager)
	itemDirect := newClashModeRule(t, "Direct", manager)

	metadata := &adapter.InboundContext{}
	stop := make(chan struct{})
	var waitGroup sync.WaitGroup

	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = manager.Mode()
				_ = itemRule.Match(metadata)
				_ = itemGlobal.Match(metadata)
				_ = itemDirect.Match(metadata)
			}
		}()
	}

	// The controller side: every switch writes a DIFFERENT value, so the writer cannot be optimised
	// into a no-op and the same memory is written repeatedly.
	modes := []string{"Global", "Direct", "Rule"}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			manager.SetMode(modes[index%len(modes)])
		}
	}()

	time.Sleep(500 * time.Millisecond)
	close(stop)
	waitGroup.Wait()

	// The concurrent run must have reached the real SetMode body, not only its early return.
	require.Positive(t, dnsRouter.flushes.Load(),
		"no mode switch reached ClearCache, so the concurrent run never exercised SetMode")
}

// TestClashModeRuleMatchIsRaceFreeWithItsOwnSwitches is the narrower interleaving: the READ that the
// router performs on every connection, against the WRITE the controller performs, with no API read in
// between. It exists so a failure points at the routing path specifically.
func TestClashModeRuleMatchIsRaceFreeWithItsOwnSwitches(t *testing.T) {
	manager, _ := newClashModeManager(t)
	item := newClashModeRule(t, "Global", manager)
	metadata := &adapter.InboundContext{}

	stop := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = item.Match(metadata)
			}
		}()
	}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			manager.SetMode("Global")
			manager.SetMode("Rule")
		}
	}()

	time.Sleep(500 * time.Millisecond)
	close(stop)
	waitGroup.Wait()
}

// ---------------------------------------------------------------------------
// The contract that must not change
// ---------------------------------------------------------------------------

// TestClashModeRuleMatchesOnlyItsOwnMode pins the routing semantics: a `clash_mode=X` rule matches when
// the manager's mode equals X and not otherwise.
func TestClashModeRuleMatchesOnlyItsOwnMode(t *testing.T) {
	manager, _ := newClashModeManager(t)
	itemRule := newClashModeRule(t, "Rule", manager)
	itemGlobal := newClashModeRule(t, "Global", manager)

	metadata := &adapter.InboundContext{}

	require.True(t, itemRule.Match(metadata), "mode is Rule, so clash_mode=Rule must match")
	require.False(t, itemGlobal.Match(metadata), "mode is Rule, so clash_mode=Global must not match")

	manager.SetMode("Global")
	require.False(t, itemRule.Match(metadata))
	require.True(t, itemGlobal.Match(metadata),
		"after the switch the Global rule must match: the mode change has to become visible to routing")

	manager.SetMode("Direct")
	require.False(t, itemRule.Match(metadata))
	require.False(t, itemGlobal.Match(metadata))
}

// TestClashModeMatchIsCaseInsensitive keeps the EqualFold the rule item already relied on, now that the
// stored value is normalised to the configured spelling.
func TestClashModeMatchIsCaseInsensitive(t *testing.T) {
	manager, _ := newClashModeManager(t)
	item := newClashModeRule(t, "gLoBaL", manager)
	manager.SetMode("Global")
	require.True(t, item.Match(&adapter.InboundContext{}))
}

// TestClashModeRuleWithoutAManagerDoesNotMatch keeps the existing nil-guard: a rule whose manager was
// never wired must not claim a match.
func TestClashModeRuleWithoutAManagerDoesNotMatch(t *testing.T) {
	item := NewClashModeItem(context.Background(), "Rule")
	require.False(t, item.Match(&adapter.InboundContext{}))
}

// TestSetModeIsIdempotentAndReachesTheCache pins the switch contract: one invalidation per real change,
// none for a redundant write.
func TestSetModeIsIdempotentAndReachesTheCache(t *testing.T) {
	manager, dnsRouter := newClashModeManager(t)

	require.Equal(t, "Rule", manager.Mode())
	manager.SetMode("Global")
	require.Equal(t, "Global", manager.Mode())
	require.EqualValues(t, 1, dnsRouter.flushes.Load())

	manager.SetMode("Global")
	require.EqualValues(t, 1, dnsRouter.flushes.Load(),
		"a redundant switch must not drop a warm DNS cache")
}

// TestSetModeNormalisesCaseAndRejectsUnknownModes keeps the acceptance rule intact.
func TestSetModeNormalisesCaseAndRejectsUnknownModes(t *testing.T) {
	manager, _ := newClashModeManager(t)

	manager.SetMode("gLoBaL")
	require.Equal(t, "Global", manager.Mode(), "the stored mode must be the configured spelling")

	manager.SetMode("NoSuchMode")
	require.Equal(t, "Global", manager.Mode(), "an unknown mode must not be adopted")
}

// TestConcurrentSwitchesLeaveARequestedMode proves the switch has a coherent linearization point even
// when two controllers write at once: the field must end on a value that was actually requested.
func TestConcurrentSwitchesLeaveARequestedMode(t *testing.T) {
	manager, _ := newClashModeManager(t)

	var waitGroup sync.WaitGroup
	for range 8 {
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			manager.SetMode("Global")
		}()
		go func() {
			defer waitGroup.Done()
			manager.SetMode("Direct")
		}()
	}
	waitGroup.Wait()

	require.Contains(t, []string{"Global", "Direct"}, manager.Mode(),
		"the mode must hold a value that was actually requested")
}

// TestUpdateHooksFireProvesTheNotificationPathIsUnchanged keeps the control plane's observable contract.
func TestUpdateHooksFireProvesTheNotificationPathIsUnchanged(t *testing.T) {
	manager, _ := newClashModeManager(t)

	clashModeSubscriber := observable.NewSubscriber[struct{}](1)
	defer func() { _ = clashModeSubscriber.Close() }()
	subscription, done := clashModeSubscriber.Subscription()
	manager.AddUpdateHook(clashModeSubscriber)

	manager.SetMode("Global")
	select {
	case <-subscription:
	case <-time.After(time.Second):
		t.Fatal("the update hook was never notified of the mode change")
	}
	select {
	case <-done:
		t.Fatal("the subscriber was closed by the emit path")
	default:
	}
}
