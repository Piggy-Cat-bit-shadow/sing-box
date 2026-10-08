package group

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Lifecycle tests: Close must stop work rather than merely mark the transport,
// and a restart loop must not leave goroutines behind.

func TestCloseIsIdempotentAndCancelsInFlight(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a"))
	entered := make(chan struct{}, 1)
	harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})

	done := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		done <- err
	}()
	<-entered

	require.NoError(t, harness.transport.Close())
	select {
	case err := <-done:
		require.Error(t, err, "Close must cancel an exchange that is still in flight")
	case <-time.After(testTimeout):
		t.Fatal("Close did not cancel the in-flight exchange")
	}
	require.NoError(t, harness.transport.Close(), "Close must be safe to call repeatedly")
}

func TestStartCloseCycleDoesNotAccumulateGoroutines(t *testing.T) {
	manager, registry, ctx, logger := newManagerHarness(t)
	require.NoError(t, manager.Create(ctx, logger, "member", "test", struct{}{}))
	require.NoError(t, manager.Create(ctx, logger, "cycled", C.DNSTypeGroup, option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"member"},
	}))
	rawGroup, loaded := manager.Transport("cycled")
	require.True(t, loaded)
	groupTransport := rawGroup.(*Transport)
	member := registry.members["member"]

	baseline := runtime.NumGoroutine()
	for cycle := 0; cycle < 30; cycle++ {
		// A fresh scope models one box lifetime: Start opens it and Close (run
		// by the scope, then called again explicitly) tears it down.
		scope := adapter.NewScope(ctx, logger)
		require.NoError(t, groupTransport.Start(adapter.StartStateInitialize, scope))
		require.NoError(t, groupTransport.Start(adapter.StartStateStart, scope))

		entered := make(chan struct{}, 1)
		member.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})

		done := make(chan error, 1)
		go func() {
			_, err := groupTransport.Exchange(context.Background(), queryMessage())
			done <- err
		}()
		<-entered
		require.NoError(t, scope.Close(), "the scope must run the transport's Close")
		require.NoError(t, groupTransport.Close(), "the explicit second Close must be harmless")
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Fatal("cycle ", cycle, ": Close did not cancel the in-flight exchange")
		}
	}

	waitFor(t, "goroutines to settle after 30 start/close cycles", func() bool {
		return runtime.NumGoroutine() <= baseline+4
	})
}
