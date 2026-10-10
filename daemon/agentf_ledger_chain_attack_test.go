package daemon

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Agent F, round 3: the ledger's REACHABILITY through the chain a Box is actually built from.
//
// # Why this exists
//
// The cross-Box FakeIP refusal reads `service.PtrFromContext[adapter.FakeIPIssuanceLedger](r.ctx)`
// (route/route.go:1121). If the router is ever built from a context that does not carry the ledger,
// that refusal becomes a silent no-op - no error, no log, no failing test - and a historic placeholder
// can reach a peer again.
//
// `daemon/started_service_registration_test.go:67` pins ONE hop of that chain:
//
//	boxCtx := service.ExtendContext(started.ctx)
//
// But `newInstance` (daemon/instance.go:85-133) performs SIX hops before `box.New`, and the clone is
// the second of them:
//
//	:87  ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
//	:88  ctx = service.ExtendContext(ctx)
//	:89  service.MustRegister[deprecated.Manager](ctx, new(deprecatedManager))
//	:90  ctx, cancel := context.WithCancel(ctx)
//	:121 ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
//	:126 ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(...))
//	:132 boxInstance, err := box.New(box.Options{Context: ctx, ...})
//
// The repository has already been bitten by exactly this class once: the OOM recorder lookup at
// started_service.go:120-126 became nil because a context hop took a SNAPSHOT of the registry instead
// of carrying it. A test of one hop cannot see a break in another, so this walks the real chain and
// names the first hop that drops the ledger.
func TestAgentFLedgerSurvivesEveryHopANewInstancePerforms(t *testing.T) {
	base := service.ContextWithDefaultRegistry(context.Background())
	started := NewStartedService(ServiceOptions{Context: base})
	require.NotNil(t, started)

	ledger := service.PtrFromContext[adapter.FakeIPIssuanceLedger](started.ctx)
	require.NotNil(t, ledger, "the constructor must publish the ledger on its own context")

	check := func(hop string, ctx context.Context) context.Context {
		t.Helper()
		require.Same(t, ledger, service.PtrFromContext[adapter.FakeIPIssuanceLedger](ctx),
			"the hop %q dropped the FakeIP issuance ledger. Everything built from here records nothing "+
				"and refuses nothing on this basis, silently - which is the whole cross-Box protection", hop)
		return ctx
	}

	// --- newInstance, hop for hop, in the order it performs them. ---
	selectedLocale := locale.FromContext(started.ctx)
	require.NotNil(t, selectedLocale,
		"locale.FromContext returned nil; newInstance dereferences it unconditionally at :87")
	ctx, _ := locale.ContextWithLocale(started.ctx, selectedLocale.Locale)
	ctx = check("locale.ContextWithLocale", ctx)

	ctx = check("service.ExtendContext", service.ExtendContext(ctx))

	service.MustRegister[deprecated.Manager](ctx, new(deprecatedManager))
	ctx = check("service.MustRegister[deprecated.Manager]", ctx)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = check("context.WithCancel", ctx)

	ctx = check("service.ContextWithPtr", service.ContextWithPtr(ctx, urltest.NewHistoryStorage()))
	ctx = check("urltest.ContextWithCoordinator",
		urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(C.URLTestConcurrencyLimit)))

	// The final context is the one `box.New` receives and the one `route.NewRouter` copies into
	// `Router.ctx` (box.go:541 -> route/router.go:80-82), which is the context the refusal reads.
	t.Logf("MEASURED: the ledger survives all six hops of newInstance; the router built from this "+
		"context reads the same ledger %p", ledger)
}

// TestAgentFLedgerReachabilityIsNotAchievedByABlanketRegistration is the discriminating control for
// the walk above.
//
// A `check` that could never fail would make the test above decoration. The library hop that is known
// to SNAPSHOT a registry is `service.ExtendContext` on a context it has not seen before, so this pins
// that the two contexts are distinguishable at all: a component registered on a COPY that does not
// carry the registry must NOT be visible from the service context.
func TestAgentFLedgerIsNotVisibleFromAnUnrelatedContext(t *testing.T) {
	base := service.ContextWithDefaultRegistry(context.Background())
	started := NewStartedService(ServiceOptions{Context: base})
	ledger := service.PtrFromContext[adapter.FakeIPIssuanceLedger](started.ctx)
	require.NotNil(t, ledger)

	// A context with a registry of its own, sharing no ancestry with the service context.
	unrelated := service.ContextWithDefaultRegistry(context.Background())
	require.Nil(t, service.PtrFromContext[adapter.FakeIPIssuanceLedger](unrelated),
		"a lookup must be able to return nil, or every assertion in this file is vacuous: if the "+
			"ledger were visible from any context, 'the ledger survived the hop' would prove nothing")
}
