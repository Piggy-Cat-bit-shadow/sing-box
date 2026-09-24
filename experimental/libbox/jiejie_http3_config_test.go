//go:build with_quic

package libbox

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// These tests exercise the SAME configuration entry point the Apple client uses
// (Libbox.CheckConfig), rather than the option structs directly. The Apple
// XCFramework is generated from ./experimental/libbox, so a config that this
// path accepts is a config SFI can actually load.
//
// The two options under test are the Jiejie HTTP/3 additions:
//
//	http3_connection_pool  - N independent QUIC transports per client
//	http3_fallback         - the HTTP/3 -> earlier-version backoff schedule
//
// Both live on the HTTP outbound's QUIC options, so the fixture below is a real
// HTTP (MASQUE) client config with version 3.

const jiejieAppleH3ClientConfig = `{
	"log": {
		"level": "warn"
	},
	"outbounds": [{
		"type": "http",
		"tag": "masque-out",
		"server": "192.0.2.1",
		"server_port": 443,
		"version": 3,
		"username": "example",
		"password": "example",
		"http3_connection_pool": {
			"size": 2,
			"strategy": "round_robin"
		},
		"http3_fallback": {
			"initial_backoff": "5s",
			"max_backoff": "5m",
			"multiplier": 2,
			"reset_on_success": true
		},
		"tls": {
			"enabled": true,
			"server_name": "example.org"
		}
	}]
}`

// TestCheckConfigAcceptsJiejieHTTP3Options is the Libbox-level proof that the
// Apple core accepts the Jiejie HTTP/3 options. It goes through CheckConfig, so
// it covers registry construction and box.New, not just JSON decoding.
func TestCheckConfigAcceptsJiejieHTTP3Options(t *testing.T) {
	t.Parallel()
	require.NoError(t, CheckConfig(jiejieAppleH3ClientConfig))
}

// TestCheckConfigParsesJiejieHTTP3OptionValues additionally asserts the values
// survive into the parsed options, so a config that merely fails to reject the
// keys cannot pass this test.
func TestCheckConfigParsesJiejieHTTP3OptionValues(t *testing.T) {
	t.Parallel()

	ctx := baseContext(nil)
	options, err := parseConfig(ctx, jiejieAppleH3ClientConfig)
	require.NoError(t, err)
	require.Len(t, options.Outbounds, 1)

	outbound, isHTTP := options.Outbounds[0].Options.(*option.HTTPOutboundOptions)
	require.True(t, isHTTP, "expected the fixture outbound to decode as an HTTP outbound")

	require.NotNil(t, outbound.HTTP3Options.HTTP3ConnectionPool,
		"http3_connection_pool must survive decoding")
	require.Equal(t, 2, outbound.HTTP3Options.HTTP3ConnectionPool.Size)
	require.Equal(t, option.HTTP3PoolStrategyRoundRobin, outbound.HTTP3Options.HTTP3ConnectionPool.Strategy)

	require.NotNil(t, outbound.HTTP3Options.HTTP3Fallback,
		"http3_fallback must survive decoding")
	require.Equal(t, badoption.Duration(5*time.Second), outbound.HTTP3Options.HTTP3Fallback.InitialBackoff)
	require.Equal(t, badoption.Duration(5*time.Minute), outbound.HTTP3Options.HTTP3Fallback.MaxBackoff)
	require.Equal(t, 2.0, outbound.HTTP3Options.HTTP3Fallback.Multiplier)
	require.NotNil(t, outbound.HTTP3Options.HTTP3Fallback.ResetOnSuccess)
	require.True(t, *outbound.HTTP3Options.HTTP3Fallback.ResetOnSuccess)
}

// TestCheckConfigRejectsInvalidHTTP3PoolSize proves the Apple core also
// VALIDATES the option, so this is not a permissive parser that would accept
// anything. Size above the supported maximum must be rejected at config time.
func TestCheckConfigRejectsInvalidHTTP3PoolSize(t *testing.T) {
	t.Parallel()

	invalid := `{
		"outbounds": [{
			"type": "http",
			"server": "192.0.2.1",
			"server_port": 443,
			"version": 3,
			"username": "example",
			"password": "example",
			"http3_connection_pool": {
				"size": 99
			},
			"tls": {
				"enabled": true,
				"server_name": "example.org"
			}
		}]
	}`
	require.Error(t, CheckConfig(invalid))
}

// TestCheckConfigRejectsUnknownHTTP3PoolStrategy is the second negative case,
// covering the strategy enum rather than the numeric bound.
func TestCheckConfigRejectsUnknownHTTP3PoolStrategy(t *testing.T) {
	t.Parallel()

	invalid := `{
		"outbounds": [{
			"type": "http",
			"server": "192.0.2.1",
			"server_port": 443,
			"version": 3,
			"username": "example",
			"password": "example",
			"http3_connection_pool": {
				"size": 2,
				"strategy": "least_connections"
			},
			"tls": {
				"enabled": true,
				"server_name": "example.org"
			}
		}]
	}`
	require.Error(t, CheckConfig(invalid))
}
