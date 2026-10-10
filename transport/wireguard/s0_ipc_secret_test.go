package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// S0: the WireGuard IPC configuration must never reach an error
// ---------------------------------------------------------------------------
//
// # The defect
//
// `Endpoint.Start` handed the ENTIRE IPC configuration to the error it returned:
//
//	err = wgDevice.IpcSet(ipcConf.String())
//	if err != nil {
//		wgDevice.Close()
//		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
//	}
//
// That string begins `private_key=<hex>` and carries every peer's `preshared_key=<hex>`, so a failed
// `IpcSet` put the device's identity key and every PSK into an error the caller logs, wraps, or hands
// to an SDK. A configuration failure is routine - a malformed peer, a key the kernel rejects, a port
// conflict - and none of them should cost the user their keys.
//
// # Why sentinels rather than realistic keys
//
// A test asserting "the message does not contain the key" against a random key depends on that key
// being distinctive. These fixtures use structurally valid 32-byte keys carrying an unmistakable
// ASCII marker, so both the hex form (which is what an IPC line contains) and the base64 form are
// exact substrings that cannot appear by accident.

// s0SentinelKey builds 32 bytes whose HEX rendering embeds an unmistakable ASCII marker, encoded the
// way the option field wants it.
func s0SentinelKey(marker string) string {
	raw := make([]byte, 32)
	copy(raw, []byte("S0SENTINEL-"+marker))
	for index := len("S0SENTINEL-" + marker); index < len(raw); index++ {
		raw[index] = 0x0F
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// s0HexOf is the form the IPC configuration carries, and therefore the form a leak would show.
func s0HexOf(base64Key string) string {
	raw, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

// s0Endpoint builds a configuration that is VALID everywhere except the peer's allowed IPs, so the
// only thing that can fail is the IPC parse of those entries.
//
// # Why the failure is a real IpcSet failure and not an injected one
//
// Everything up to `IpcSet` must succeed, or the error under inspection would come from a different
// place and the test would prove nothing about the leak site. That is why the dialer is the real
// default dialer - the same one the package's own listen-port fixture uses, which takes the
// `dialer.UDPListener` path and therefore reaches `IpcSet` - and why the address and keys are valid.
func s0Endpoint(t *testing.T, privateKey string, preSharedKey string, allowedIPs []netip.Prefix) (*Endpoint, error) {
	t.Helper()
	ctx := pause.WithDefaultManager(context.Background())
	outboundDialer, err := dialer.NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)
	return NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Dialer:     outboundDialer,
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: privateKey,
		Peers: []PeerOptions{{
			Endpoint:     M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:    testListenPeerPublicKey,
			PreSharedKey: preSharedKey,
			AllowedIPs:   allowedIPs,
		}},
	})
}

// TestAFailedIpcSetDoesNotLeakThePrivateKey is the S0 detector.
func TestAFailedIpcSetDoesNotLeakThePrivateKey(t *testing.T) {
	t.Parallel()

	privateKey := s0SentinelKey("PRIVATE")
	preSharedKey := s0SentinelKey("PSK")
	privateKeyHex := s0HexOf(privateKey)
	preSharedKeyHex := s0HexOf(preSharedKey)

	// `0.0.0.0/33` is not a prefix: the IPC parser rejects it, so `IpcSet` fails on a REAL parse
	// error while everything before it succeeded.
	endpoint, err := s0Endpoint(t, privateKey, preSharedKey, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")})
	if err != nil {
		t.Skipf("construction rejected the fixture before IpcSet (%v); a SKIP, not a pass", err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })

	// Corrupt the peer's allowed IP after construction so the IPC line is unparsable at IpcSet time.
	// This is the ONE field the test manipulates, and it manipulates it through the same struct the
	// production path reads.
	endpoint.peers[0].allowedIPs = []netip.Prefix{{}}

	// Initialize installs the tun device that Start reads. The package's own fixtures call it the
	// same way; without it Start panics on a nil device BEFORE reaching IpcSet, which would make this
	// test assert about a different failure than the one it is named for.
	require.NoError(t, endpoint.Initialize(nil))

	startErr := endpoint.Start(false)
	if startErr == nil {
		t.Skip("IpcSet accepted the fixture on this platform, so the failure path this test targets " +
			"was not reached; a SKIP, not a pass")
	}
	message := startErr.Error()

	// --- the leak assertions -----------------------------------------------------------------
	require.NotContains(t, message, privateKeyHex,
		"the device's PRIVATE KEY must never appear in an error: errors reach logs, SDK wrappers and "+
			"crash reports, and a routine configuration failure must not cost the user their identity "+
			"key")
	require.NotContains(t, message, privateKey,
		"nor in its base64 form")
	require.NotContains(t, message, "private_key",
		"nor may the IPC field name appear, since that is what makes the value recognisable to a "+
			"secret scanner and to a reader")
	require.NotContains(t, message, preSharedKeyHex,
		"and no peer's PRESHARED KEY may appear: a PSK compromise is worse than a failed start")
	require.NotContains(t, message, preSharedKey,
		"nor its base64 form")
	require.NotContains(t, message, "preshared_key",
		"nor the IPC field name for it")

	// --- and the error must still be USEFUL --------------------------------------------------
	require.Contains(t, strings.ToLower(message), "wireguard",
		"the message must still name the subsystem, or the fix would have traded a leak for an "+
			"unactionable error. Got: %s", message)
}

// TestNoWireGuardErrorCarriesAKeyLikeString sweeps the failure paths reachable without a real peer,
// so a SECOND leak site added later is caught by the same assertions.
func TestNoWireGuardErrorCarriesAKeyLikeString(t *testing.T) {
	t.Parallel()

	privateKey := s0SentinelKey("SWEEPPRIVATE")
	preSharedKey := s0SentinelKey("SWEEPPSK")
	privateKeyHex := s0HexOf(privateKey)
	preSharedKeyHex := s0HexOf(preSharedKey)

	cases := []struct {
		name  string
		build func() error
	}{
		{
			name: "allowed ip the ipc parser rejects",
			build: func() error {
				endpoint, err := s0Endpoint(t, privateKey, preSharedKey,
					[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")})
				if err != nil {
					return err
				}
				defer endpoint.Close()
				endpoint.peers[0].allowedIPs = []netip.Prefix{{}}
				if initErr := endpoint.Initialize(nil); initErr != nil {
					return initErr
				}
				return endpoint.Start(false)
			},
		},
		{
			name: "private key that is not decodable",
			build: func() error {
				_, err := s0Endpoint(t, "not-a-valid-key-at-all", preSharedKey,
					[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
				return err
			},
		},
		{
			name: "preshared key that is not decodable",
			build: func() error {
				_, err := s0Endpoint(t, privateKey, "also-not-a-valid-key",
					[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
				return err
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.build()
			if err == nil {
				t.Skipf("%s: accepted on this platform, so there is no error to inspect; a SKIP, "+
					"not a pass", testCase.name)
			}
			message := err.Error()
			require.NotContains(t, message, privateKeyHex, "%s: no private key hex in an error", testCase.name)
			require.NotContains(t, message, preSharedKeyHex, "%s: no preshared key hex in an error", testCase.name)
			require.NotContains(t, message, privateKey, "%s: no private key in base64", testCase.name)
			require.NotContains(t, message, preSharedKey, "%s: no preshared key in base64", testCase.name)
			require.NotContains(t, message, "private_key", "%s: no private_key field text", testCase.name)
			require.NotContains(t, message, "preshared_key", "%s: no preshared_key field text", testCase.name)
		})
	}
}
