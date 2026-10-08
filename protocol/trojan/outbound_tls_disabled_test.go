package trojan

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A trojan node without TLS must be plain TCP, not a process-wide crash.
//
// # The failure this pins
//
// tls.NewClientWithOptions returns (nil, nil) for `"tls": {"enabled": false}` - that is its
// contract, and callers rely on a nil config meaning "no TLS". The outbound then built a TLS
// dialer around that nil config anyway, so the first successful TCP connect called
// ClientHandshake with a nil config and killed the whole process with a SIGSEGV. It fires on
// the URL test as readily as on live traffic.
//
// A trojan node with a TLS block and TLS disabled is a legal configuration from public
// subscriptions, so the process must dial it as plain TCP.
func TestNewOutboundTLSDisabledHasNoTLSDialer(t *testing.T) {
	t.Parallel()

	created, err := NewOutbound(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("trojan"),
		"plain-trojan",
		option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: 41393,
			},
			Password: "password",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: false},
			},
		},
	)
	require.NoError(t, err)
	outbound, isOutbound := created.(*Outbound)
	require.True(t, isOutbound)
	require.Nil(t, outbound.tlsConfig, "a disabled TLS block must not produce a config")
	require.Nil(t, outbound.tlsDialer, "a nil TLS config must never be wrapped in a dialer")
}

// The guard must not disable TLS for nodes that do have it.
func TestNewOutboundTLSEnabledHasTLSDialer(t *testing.T) {
	t.Parallel()

	created, err := NewOutbound(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("trojan"),
		"tls-trojan",
		option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: 41393,
			},
			Password: "password",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true},
			},
		},
	)
	require.NoError(t, err)
	outbound, isOutbound := created.(*Outbound)
	require.True(t, isOutbound)
	require.NotNil(t, outbound.tlsConfig)
	require.NotNil(t, outbound.tlsDialer)
}
