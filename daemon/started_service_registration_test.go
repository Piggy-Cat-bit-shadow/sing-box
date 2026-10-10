package daemon

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

// TestStartedServiceSeesAServiceRegisteredAfterItWasConstructed pins the ORDERING property the
// service context has to keep, and it exists because a fix for an unrelated bug broke it.
//
// # The defect it pins
//
// `NewStartedService` derives `s.ctx` and registers the FakeIP issuance ledger into it. The obvious
// way to do that is `service.ExtendContext(options.Context)`, which is a shallow registry CLONE - and
// a clone is a SNAPSHOT. `newInstance` extends `s.ctx` at the moment a Box is built, so anything the
// caller registers into its own context AFTER this constructor returns would be invisible to every
// Box for the rest of the session.
//
// That is exactly the composition `experimental/libbox/command_server.go` uses:
//
//	:55  ctx := baseContext(platformInterface)
//	:57  service.MustRegister[*powerreport.Manager](ctx, powerManager)      // before the constructor
//	:63  service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
//	:71  server.StartedService = daemon.NewStartedService(...Context: ctx...)
//	:87  service.MustRegister[*oomkiller.Recorder](ctx, oomRecorder)        // AFTER it
//
// and the daemon reads that recorder back out of its own context on the reload path:
//
//	oomRecorder := service.FromContext[*oomkiller.Recorder](s.ctx)
//	if oomRecorder != nil { oomRecorder.BeginReload(); defer oomRecorder.EndReload() }
//
// With an eager clone the lookup returns nil, the `if` is skipped, and the OOM killer's reload
// accounting stops running - silently, with no error and no failing test anywhere. The recorder is a
// REAL production type here rather than a stand-in, so this test is about the composition the product
// actually performs.
func TestStartedServiceSeesAServiceRegisteredAfterItWasConstructed(t *testing.T) {
	// The caller's context, with a registry, exactly as `baseContext` supplies it.
	ctx := service.ContextWithDefaultRegistry(context.Background())

	started := NewStartedService(ServiceOptions{Context: ctx})
	require.NotNil(t, started)

	// Registered AFTER construction, which is where the libbox command server registers it.
	recorder := oomkiller.NewRecorder(oomkiller.RecorderOptions{BasePath: t.TempDir()})
	service.MustRegister[*oomkiller.Recorder](ctx, recorder)

	require.Same(t, recorder, service.FromContext[*oomkiller.Recorder](started.ctx),
		"a service the caller registered after NewStartedService returned is not visible through the "+
			"service's own context, so the daemon cannot find it on the reload path. The service context "+
			"must be the caller's context (or one carrying the SAME registry), never a snapshot taken "+
			"at construction time")

	// And the ledger this constructor EXISTS to publish must be on that same context, so the two
	// requirements are shown to hold together rather than at each other's expense.
	ledger := service.PtrFromContext[adapter.FakeIPIssuanceLedger](started.ctx)
	require.NotNil(t, ledger,
		"the FakeIP issuance ledger must be registered on the context every Box of this service is "+
			"built from; without it a Box has no cross-Box issuance memory and a historic placeholder "+
			"can still reach a peer")

	// A Box's context is what `newInstance` builds: an ExtendContext clone of the service context.
	boxCtx := service.ExtendContext(started.ctx)
	require.Same(t, ledger, service.PtrFromContext[adapter.FakeIPIssuanceLedger](boxCtx),
		"the ledger must survive the clone a Box is built from; this is the whole mechanism")
	require.Same(t, recorder, service.FromContext[*oomkiller.Recorder](boxCtx),
		"and everything else registered on the service context must survive it too, which is the "+
			"property an eager clone destroyed")
}

// TestStartedServiceWithoutARegistryStillBuilds is the boundary half.
//
// `ContextWithDefaultRegistry` has to create a registry when the caller supplied a bare context, or
// the constructor would panic in `MustRegisterPtr`. That path is legitimate - a caller may hand over a
// plain `context.Background()` - and it must produce a working service, not a crash.
func TestStartedServiceWithoutARegistryStillBuilds(t *testing.T) {
	started := NewStartedService(ServiceOptions{Context: context.Background()})
	require.NotNil(t, started)
	require.NotNil(t, service.PtrFromContext[adapter.FakeIPIssuanceLedger](started.ctx),
		"a context with no registry must still end up with the ledger, or the boundary case silently "+
			"disables the protection instead of failing loudly")
}
