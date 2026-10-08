//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// The REALITY key_share policy.
//
// # The two failure directions, and why neither can be the default
//
// A post-quantum hybrid key share (X25519MLKEM768) makes the ClientHello about 1.7 KB, and on some
// fingerprints it leaves as two TCP segments. Paths exist that silently drop a greeting arriving
// that way; the symptom is a timeout, which is indistinguishable from a wrong public key.
//
// In the other direction, Xray >= v26.9.8 derives the REALITY auth key from the hybrid share and
// rejects a client that does not send one. So a build that unconditionally STRIPS the hybrid share
// - which is what this fork did, inheriting upstream's filter - cannot talk to a current Xray
// server, and the failure is again indistinguishable from a wrong key.
//
// The policy therefore has three values and the default is "whatever the fingerprint carries",
// because that is the only value that is not a claim about the network.

func newRealityTestKeyPair(t *testing.T) (publicKey string, privateKey string) {
	t.Helper()
	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(serverPrivate.Bytes())
}

func newRealityClientForTest(t *testing.T, fingerprint string, keyShare string) *RealityClientConfig {
	t.Helper()
	publicKey, _ := newRealityTestKeyPair(t)
	created, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), "www.example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fingerprint,
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   "0123abcd",
			KeyShare:  keyShare,
		},
	})
	require.NoError(t, err)
	client, isReality := created.(*RealityClientConfig)
	require.True(t, isReality, "the constructed config must be the REALITY client")
	return client
}

// buildHello builds the greeting the client would actually send, without any I/O.
func buildHello(t *testing.T, client *RealityClientConfig) (*utls.UConn, []byte) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	uConfig := client.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConn := utls.UClient(clientConn, uConfig, client.uClient.id)
	require.NoError(t, prepareClientHello(uConn, client.keyShare, client.uClient.id))
	return uConn, uConn.HandshakeState.Hello.Raw
}

// R1: the default must not change the greeting for any fingerprint. This is the guard whose
// absence broke compatibility with current Xray: an unconditional filter is invisible to every
// test that does not look at the wire.
func TestRealityKeyShareDefaultKeepsTheFingerprintsGreeting(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range []string{"chrome", "firefox", "safari", "edge", "ios", "android", "360", "qq"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			client := newRealityClientForTest(t, fingerprint, C.RealityKeyShareDefault)
			uConn, _ := buildHello(t, client)

			// An unfiltered uTLS conn is the reference: the default policy must be a no-op, so
			// comparing against it is comparing against "whatever the fingerprint carries" rather
			// than against a hand-written expectation that would rot with every uTLS update.
			referenceConn, _ := net.Pipe()
			defer referenceConn.Close()
			referenceConfig := client.uClient.config.Clone()
			referenceConfig.InsecureSkipVerify = true
			reference := utls.UClient(referenceConn, referenceConfig, client.uClient.id)
			require.NoError(t, reference.BuildHandshakeState())

			require.Equal(t,
				clientHelloCarriesHybridShare(reference),
				clientHelloCarriesHybridShare(uConn),
				"the default policy must leave the fingerprint's own key_share decision alone")
		})
	}
}

// The classical policy removes the hybrid share from BOTH extensions, leaves exactly one X25519
// share, and shortens the greeting enough that the ML-KEM key cannot physically be in it.
func TestRealityKeyShareClassicalRemovesTheHybridShare(t *testing.T) {
	t.Parallel()
	client := newRealityClientForTest(t, "chrome", C.RealityKeyShareClassical)
	uConn, raw := buildHello(t, client)

	require.False(t, clientHelloCarriesHybridShare(uConn),
		"classical must remove X25519MLKEM768 from key_share")

	var (
		hasHybridCurve bool
		x25519Shares   int
	)
	for _, extension := range uConn.Extensions {
		if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
			for _, curveID := range curves.Curves {
				if curveID == utls.X25519MLKEM768 {
					hasHybridCurve = true
				}
			}
		}
		if shares, isShares := extension.(*utls.KeyShareExtension); isShares {
			for _, share := range shares.KeyShares {
				if share.Group == utls.X25519 {
					x25519Shares++
				}
			}
		}
	}
	require.False(t, hasHybridCurve, "classical must remove X25519MLKEM768 from supported_groups")
	require.Equal(t, 1, x25519Shares, "classical must leave exactly one X25519 share")

	// Not a fingerprint comparison: the threshold is the size of an ML-KEM-768 encapsulation key
	// (1184 bytes), so a greeting below it cannot contain one whatever the preset does.
	require.Less(t, len(raw), 1184,
		"a classical greeting must be too short to carry an ML-KEM-768 key")
}

// The hybrid policy is a REQUIREMENT, not a request: a fingerprint that cannot produce a hybrid
// share is an error naming the fingerprint, never a silent downgrade.
func TestRealityKeyShareHybridRequiresTheShare(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range []string{"chrome", "chrome_pq", "firefox", "safari", "edge", "ios", "android", "360", "qq"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			client := newRealityClientForTest(t, fingerprint, C.RealityKeyShareHybrid)

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			uConfig := client.uClient.config.Clone()
			uConfig.InsecureSkipVerify = true
			uConn := utls.UClient(clientConn, uConfig, client.uClient.id)

			err := prepareClientHello(uConn, client.keyShare, client.uClient.id)
			if clientHelloCarriesHybridShare(uConn) {
				require.NoError(t, err,
					"a fingerprint that carries the hybrid share must accept the hybrid policy")
				require.True(t, clientHelloCarriesHybridShare(uConn))
				return
			}
			require.Error(t, err,
				"a fingerprint that cannot carry a hybrid share must be rejected, not silently downgraded")
			require.Contains(t, err.Error(), "X25519MLKEM768")
			require.Contains(t, err.Error(), `key_share "hybrid"`)
			require.Contains(t, err.Error(), client.uClient.id.Client,
				"the error must name the fingerprint, or it does not tell the user what to change")
		})
	}
}

// R4: an unknown value is rejected at construction, so a typo cannot silently become the default.
func TestRealityKeyShareUnknownValueIsRejected(t *testing.T) {
	t.Parallel()
	publicKey, _ := newRealityTestKeyPair(t)
	for _, value := range []string{"classic", "HYBRID", "none", "default", "true"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), "www.example.com", option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "www.example.com",
				UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: publicKey,
					KeyShare:  value,
				},
			})
			require.ErrorContains(t, err, "unknown reality key_share")
			require.ErrorContains(t, err, `expected "hybrid" or "classical"`)
		})
	}
}

// The policy survives Clone, which is what every dial actually uses.
func TestRealityKeyShareSurvivesClone(t *testing.T) {
	t.Parallel()
	for _, policy := range []string{C.RealityKeyShareDefault, C.RealityKeyShareClassical, C.RealityKeyShareHybrid} {
		t.Run(policy, func(t *testing.T) {
			t.Parallel()
			client := newRealityClientForTest(t, "chrome", policy)
			cloned, isReality := client.Clone().(*RealityClientConfig)
			require.True(t, isReality)
			require.Equal(t, policy, cloned.keyShare,
				"a clone that dropped the policy would silently revert every dial to the default")
			require.Equal(t, client.shortID, cloned.shortID)
			require.Equal(t, client.publicKey, cloned.publicKey)
		})
	}
}

// A hybrid greeting is long enough that an ML-KEM-768 key fits, and the auth key is derived from
// the hybrid share's X25519 half. Both are the reason Xray >= v26.9.8 accepts the default policy
// and rejects the classical one.
func TestRealityHybridGreetingCarriesAnMLKEMKey(t *testing.T) {
	t.Parallel()
	client := newRealityClientForTest(t, "chrome", C.RealityKeyShareDefault)
	uConn, raw := buildHello(t, client)

	if !clientHelloCarriesHybridShare(uConn) {
		t.Skip("this uTLS build's chrome fingerprint does not carry a hybrid share")
	}
	require.GreaterOrEqual(t, len(raw), 1216,
		"a hybrid greeting must be large enough to contain an ML-KEM-768 encapsulation key")

	keys := uConn.HandshakeState.State13.KeyShareKeys
	require.NotNil(t, keys)

	// The REALITY auth key must be derivable from a key the server can also derive it from.
	//
	// uTLS records the FIRST non-GREASE key share's X25519 private key. A preset that sends both a
	// hybrid share and a following bare X25519 share (Chrome does: GREASE, X25519MLKEM768, X25519)
	// therefore populates BOTH fields: MlkemEcdhe for the hybrid's X25519 half and Ecdhe for the
	// bare share. Whichever the server reads, one of the two is the right one, and "Ecdhe, else
	// MlkemEcdhe" covers both - which is precisely why the auth-key fallback is what makes a hybrid
	// greeting work at all. A build that reads only Ecdhe cannot cover a preset that omits the bare
	// share, which is why it had to delete the hybrid share instead.
	require.True(t, keys.Ecdhe != nil || keys.MlkemEcdhe != nil,
		"a X25519 private key must be available to derive the REALITY auth key from")

	// And the fallback really is reachable: when Ecdhe is nil the hybrid half is used.
	if keys.Ecdhe == nil {
		require.NotNil(t, keys.MlkemEcdhe,
			"with no bare X25519 share, the hybrid share's X25519 half is the only source of the auth key")
	}
}

// short_id validation is unchanged by the key_share work: the Phase-1 guard must still be the
// first thing that sees an over-long value, and it must still be reached before the decoder.
func TestRealityKeyShareDoesNotWeakenShortIDGuard(t *testing.T) {
	t.Parallel()
	publicKey, _ := newRealityTestKeyPair(t)
	_, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), "www.example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   "0123456789abcdef0123",
			KeyShare:  C.RealityKeyShareHybrid,
		},
	})
	require.ErrorContains(t, err, "invalid short_id")
}

// The REALITY handshake must declare the client version the server compares as a number.
//
// # Why a silently wrong constant is worth a test
//
// Xray packs session_id[0..2] big-endian and requires >= its own minimum. Upstream sing-box wrote
// 1.8.1 - its own epoch, not a protocol version - and Xray v26.7.11 raised the default minimum to
// 26.3.27. Every client that kept sending 1.8.1 was rejected, and a rejected REALITY handshake is
// answered with the camouflage site, so the client reports "reality verification failed" - the same
// message a wrong public_key produces. There is no way for a user to tell the two apart, and no way
// for a test to notice unless it looks at the bytes.
func TestRealityDeclaresTheCurrentMinimumClientVersion(t *testing.T) {
	t.Parallel()
	client := newRealityClientForTest(t, "chrome", C.RealityKeyShareDefault)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// The plaintext construction, because the greeting is sealed (and these bytes overwritten with
	// ciphertext) before it leaves.
	sessionID := client.buildSessionID(time.Unix(1750000000, 0))
	require.Len(t, sessionID, 32)
	require.EqualValues(t, 26, sessionID[0])
	require.EqualValues(t, 3, sessionID[1])
	require.EqualValues(t, 27, sessionID[2])
	require.EqualValues(t, 0, sessionID[3],
		"the fourth byte is the top of the timestamp and must stay zero or the version field reads as a different number")
	require.Equal(t, []byte{0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0}, sessionID[8:16],
		"the short_id must still land where the server looks for it")
}

// The first-flight transforms must reach the REALITY handshake.
//
// # The bug this pins
//
// REALITY builds its own uTLS connection, so it never went through UTLSClientConfig.Client - which is
// where `fragment`, `record_fragment` and the automatic record-fragment default for a detoured dial
// were applied. Both options were accepted by the config parser on a REALITY node and then silently
// did nothing, on exactly the path where the post-quantum hybrid greeting (about 1.7 KB, two TCP
// segments) makes fragmentation matter most.
func TestRealityAppliesFirstFlightTransforms(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name           string
		fragment       bool
		recordFragment bool
		wrapped        bool
	}{
		{name: "neither", wrapped: false},
		{name: "fragment", fragment: true, wrapped: true},
		{name: "record_fragment", recordFragment: true, wrapped: true},
		{name: "both", fragment: true, recordFragment: true, wrapped: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			publicKey, _ := newRealityTestKeyPair(t)
			created, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), "www.example.com", option.OutboundTLSOptions{
				Enabled:        true,
				ServerName:     "www.example.com",
				Fragment:       testCase.fragment,
				RecordFragment: testCase.recordFragment,
				UTLS:           &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: publicKey,
					ShortID:   "0123abcd",
				},
			})
			require.NoError(t, err)
			client, isReality := created.(*RealityClientConfig)
			require.True(t, isReality)

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			// The same config constructor ClientHandshake uses, minus the server check: this test
			// never completes a handshake, and the point of going through the constructor is that a
			// config built any other way is not the config a real dial uses.
			uConn, err := client.newClientUConn(clientConn, client.realityUConfig(nil))
			require.NoError(t, err)

			_, isFragmentConn := uConn.NetConn().(*tf.Conn)
			require.Equal(t, testCase.wrapped, isFragmentConn,
				"the REALITY handshake must get the same first-flight transforms as the plain uTLS path")
		})
	}
}
