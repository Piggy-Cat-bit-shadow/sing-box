//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// An over-long REALITY short_id is a configuration error, not a process crash.
//
// # The failure this pins
//
// A short_id longer than 16 hex characters used to panic the whole process:
// hex.Decode writes len(src)/2 bytes into the [8]byte destination without checking its
// capacity, so the write ran off the end of the array INSIDE decode. The upstream
// "decodedLen > 8" test that follows the decode is unreachable for that input, because
// control never returns from hex.Decode. short_id reaches the core from a subscription,
// so this is untrusted input turning into a crash at configuration load.
//
// Sixteen hex characters is the largest value that fits in eight decoded bytes.
func TestRealityShortIDTooLongIsRejected(t *testing.T) {
	t.Parallel()

	clientPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(clientPrivateKey.PublicKey().Bytes())

	serverPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateKey := base64.RawURLEncoding.EncodeToString(serverPrivateKey.Bytes())

	testCases := []struct {
		name    string
		shortID string
		wantErr string
	}{
		{name: "empty", shortID: "", wantErr: ""},
		{name: "one byte", shortID: "0123abcd", wantErr: ""},
		{name: "full eight bytes", shortID: "0123456789abcdef", wantErr: ""},
		// Seventeen hex is an odd length, so upstream rejected it at the decoder with
		// "decode short_id". It is now caught by the length guard first, which is the same
		// decision the decoder made, reported as the same class of configuration error as the
		// longer values.
		{name: "seventeen hex", shortID: "0123456789abcdef0", wantErr: "invalid short_id"},
		{name: "eighteen hex", shortID: "0123456789abcdef01", wantErr: "invalid short_id"},
		{name: "far too long", shortID: "0123456789abcdef0123456789abcdef", wantErr: "invalid short_id"},
		{name: "not hex", shortID: "zz", wantErr: "decode short_id"},
	}

	for _, testCase := range testCases {
		t.Run("client/"+testCase.name, func(t *testing.T) {
			_, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), "www.example.com", option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "www.example.com",
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: "chrome",
				},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: publicKey,
					ShortID:   testCase.shortID,
				},
			})
			if testCase.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, testCase.wantErr)
		})

		t.Run("server/"+testCase.name, func(t *testing.T) {
			_, err := NewRealityServer(context.Background(), log.NewNOPFactory().NewLogger("tls"), option.InboundTLSOptions{
				Enabled:    true,
				ServerName: "www.example.com",
				Reality: &option.InboundRealityOptions{
					Enabled:    true,
					PrivateKey: privateKey,
					// An IP literal keeps the handshake dialer off the DNS transport manager,
					// which a bare test context does not provide.
					Handshake: option.InboundRealityHandshakeOptions{
						ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
					},
					ShortID: badoption.Listable[string]{testCase.shortID},
				},
			})
			if testCase.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, testCase.wantErr)
		})
	}
}
