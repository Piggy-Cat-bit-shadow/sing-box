package tuic

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A typo in udp_relay_mode must be a configuration error, not a silent mode change.
//
// # The failure this pins
//
// The switch over UDPRelayMode had no default branch, so any value that was not exactly
// "native" or "quic" fell through to the zero value and meant native. A user who wrote "qiuc"
// got a relay in the wrong mode with no diagnostic at all, while a typo in the neighbouring
// congestion_control does produce an error. The `enum:` tag on the option is documentation
// only: it is read by the schema generator, never by the configuration loader.
func TestUnknownUDPRelayModeIsRejected(t *testing.T) {
	t.Parallel()

	_, err := newTestOutbound(t, option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "a3482e88-686a-4a58-9376-8adb0e7f38a9",
		Password:      "password",
		UDPRelayMode:  "qiuc",
	})
	require.ErrorContains(t, err, "unknown udp_relay_mode")
}

func TestKnownUDPRelayModesAreAccepted(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"", "native", "quic"} {
		mode := mode
		t.Run("mode="+mode, func(t *testing.T) {
			t.Parallel()
			_, err := newTestOutbound(t, option.TUICOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
				UUID:          "a3482e88-686a-4a58-9376-8adb0e7f38a9",
				Password:      "password",
				UDPRelayMode:  mode,
			})
			require.NoError(t, err)
		})
	}
}

// The udp_over_stream conflict is checked before the mode, so a typo does not hide it.
func TestUDPOverStreamConflictWinsOverATypo(t *testing.T) {
	t.Parallel()

	_, err := newTestOutbound(t, option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "a3482e88-686a-4a58-9376-8adb0e7f38a9",
		Password:      "password",
		UDPOverStream: true,
		UDPRelayMode:  "qiuc",
	})
	require.ErrorContains(t, err, "udp_over_stream is conflict with udp_relay_mode")
}

func newTestOutbound(t *testing.T, options option.TUICOutboundOptions) (any, error) {
	t.Helper()
	options.TLS = &option.OutboundTLSOptions{Enabled: true, Insecure: true}
	return NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("tuic"), "test", options)
}
