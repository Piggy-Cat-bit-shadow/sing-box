package socks

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Tests for how the SOCKS outbound turns configuration into a preconnect pool and a
// copy-tuning preference.
//
// The variants are asserted through NewOutbound rather than by inspecting fields, so a
// configuration that `sing-box check` accepts is the same one these tests exercise.

func newTestOutbound(t *testing.T, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
	t.Helper()
	return NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "residential-socks", options)
}

// TestDefaultConfigurationIsUnchanged is the central guarantee: an operator who writes
// no new fields gets exactly the previous behaviour, and in particular no pool.
func TestDefaultConfigurationIsUnchanged(t *testing.T) {
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "5",
	})
	require.NoError(t, err)
	closer, isCloser := instance.(io.Closer)
	require.True(t, isCloser, "the framework closes outbounds through io.Closer")
	defer closer.Close()

	socksOutbound, isSocks := instance.(*Outbound)
	require.True(t, isSocks)
	require.Nil(t, socksOutbound.client.PreconnectPoolForTest(),
		"no configuration must mean no pool")
	require.False(t, socksOutbound.EarlyConnectionBufferGrowth(),
		"no configuration must mean no copy tuning")
}

// TestPreconnectEnabledAppliesConservativeDefaults covers the bare
// `"tcp_preconnect": {"enabled": true}` form: the operator should get a small bounded
// pool, not zero and not unbounded.
func TestPreconnectEnabledAppliesConservativeDefaults(t *testing.T) {
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "5",
		TCPPreconnect: &option.SOCKSOutboundPreconnectOptions{Enabled: true},
	})
	require.NoError(t, err)
	closer, isCloser := instance.(io.Closer)
	require.True(t, isCloser, "the framework closes outbounds through io.Closer")
	defer closer.Close()

	socksOutbound := instance.(*Outbound)
	pool := socksOutbound.client.PreconnectPoolForTest()
	require.NotNil(t, pool, "enabling the pool must create one")
	require.Equal(t, 2, pool.MinIdleForTest())
	require.Equal(t, 4, pool.MaxIdleForTest())
	require.Equal(t, 20*time.Second, pool.IdleTimeoutForTest())
}

// TestPreconnectRejectedForSOCKS4 is requirement: a configuration the pool cannot
// honour must fail rather than silently do nothing, so an operator cannot believe a
// pool is running when it is not.
func TestPreconnectRejectedForSOCKS4(t *testing.T) {
	_, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "4",
		TCPPreconnect: &option.SOCKSOutboundPreconnectOptions{Enabled: true},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires version 5")
}

// TestPreconnectDisabledIsNotCreated pins that `enabled: false` is the same as absent.
func TestPreconnectDisabledIsNotCreated(t *testing.T) {
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "5",
		TCPPreconnect: &option.SOCKSOutboundPreconnectOptions{Enabled: false, MinIdle: 2, MaxIdle: 4},
	})
	require.NoError(t, err)
	closer, isCloser := instance.(io.Closer)
	require.True(t, isCloser, "the framework closes outbounds through io.Closer")
	defer closer.Close()

	require.Nil(t, instance.(*Outbound).client.PreconnectPoolForTest(),
		"enabled:false must not create a pool even when other fields are present")
}

// TestInvalidPoolParametersAreRejected covers each configuration error that should be
// reported at `check` time.
func TestInvalidPoolParametersAreRejected(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options option.SOCKSOutboundPreconnectOptions
		wantErr string
	}{
		{
			name:    "min_idle above max_idle",
			options: option.SOCKSOutboundPreconnectOptions{Enabled: true, MinIdle: 8, MaxIdle: 2},
			wantErr: "must not exceed",
		},
		{
			name:    "negative min_idle",
			options: option.SOCKSOutboundPreconnectOptions{Enabled: true, MinIdle: -1, MaxIdle: 4},
			wantErr: "min_idle",
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			_, err := newTestOutbound(t, option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
				Version:       "5",
				TCPPreconnect: &testCase.options,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.wantErr)
		})
	}
}

// TestCopyTuningIsOptIn pins the second feature's default and its effect.
func TestCopyTuningIsOptIn(t *testing.T) {
	base := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "5",
	}

	off, err := newTestOutbound(t, base)
	require.NoError(t, err)
	defer off.(io.Closer).Close()
	require.False(t, off.(*Outbound).EarlyConnectionBufferGrowth(),
		"copy tuning must be off unless requested")

	withTuning := base
	withTuning.TCPTuning = &option.SOCKSOutboundTuningOptions{EarlyBufferGrowth: true}
	on, err := newTestOutbound(t, withTuning)
	require.NoError(t, err)
	defer on.(io.Closer).Close()
	require.True(t, on.(*Outbound).EarlyConnectionBufferGrowth())
}

// TestOutboundImplementsConnectionCopyTuner asserts the capability is actually
// satisfied, which is what the route layer type-asserts. A compile-time check lives in
// the source; this makes the requirement visible as a test failure too.
func TestOutboundImplementsConnectionCopyTuner(t *testing.T) {
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "5",
	})
	require.NoError(t, err)
	closer, isCloser := instance.(io.Closer)
	require.True(t, isCloser, "the framework closes outbounds through io.Closer")
	defer closer.Close()

	_, isTuner := instance.(adapter.ConnectionCopyTuner)
	require.True(t, isTuner,
		"the SOCKS outbound must implement adapter.ConnectionCopyTuner for the route "+
			"layer to honour tcp_tuning")
}

// TestPoolStartsOnlyWhenUsed pins the lifecycle requirement that constructing an
// outbound does not start a background goroutine: a pool that dialled during
// NewOutbound would connect to the proxy before sing-box had even started.
func TestPoolStartsOnlyWhenUsed(t *testing.T) {
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1},
		Version:       "5",
		TCPPreconnect: &option.SOCKSOutboundPreconnectOptions{
			Enabled: true, MinIdle: 2, MaxIdle: 4,
			IdleTimeout: badoption.Duration(time.Second),
		},
	})
	require.NoError(t, err)
	closer, isCloser := instance.(io.Closer)
	require.True(t, isCloser, "the framework closes outbounds through io.Closer")
	defer closer.Close()

	pool := instance.(*Outbound).client.PreconnectPoolForTest()
	require.NotNil(t, pool)
	require.False(t, pool.StartedForTest(),
		"constructing the outbound must not start the refill loop")

	// Close on a pool that never started must not hang.
	require.NoError(t, instance.(io.Closer).Close())
}
