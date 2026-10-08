//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// The REALITY greeting's authentication, asserted against the SERVER's acceptance path rather than
// against this package's idea of it.
//
// # Why the existing REALITY tests could not see either of the bugs this file pins
//
// Every other test here builds a greeting and asserts something about its own construction: that
// the hybrid share survives, that a short_id is rejected, that the version bytes are packed. None
// of them replays what the server does with the bytes, and both of the regressions below are
// invisible to a test that only looks at the client's intent:
//
//  1. The AEAD's additional data was the greeting carrying the PLAINTEXT session_id, while the
//     server rebuilds that additional data by ZEROING session_id inside the ClientHello it received
//     before it opens the seal. The key agreed, the nonce agreed, the short_id was right, the
//     greeting parsed - and the tag check still failed. The server then answered with the
//     camouflage site and the client reported "reality verification failed", which is exactly what
//     a wrong public_key produces. Nothing in the client distinguishes the two.
//
//  2. The certificate check (realityVerifier) was dropped from the connection's config by a second
//     clone of the stored config inside newClientUConn. The handshake therefore completed with
//     InsecureSkipVerify and no callback, so a connection the server had ACCEPTED still ended in
//     "reality verification failed", with verifier.verified left false.
//
// Both are one-line regressions with no local symptom, so the tests look at the wire and at a
// completed handshake, and both need a server to check against. The server is
// `utls.RealityServer`, which is the same REALITY implementation this repository's inbound uses
// (common/tls/reality_server.go calls exactly it), so these are also the fork's own server's rules.

// realityTestShortID is the short id the tests hand to both halves. It is the 16-hex-character form
// both implementations document, and it round-trips through hex.Decode to 8 bytes.
const realityTestShortID = "0123456789abcdef"

// realityTestServerName is the SNI the tests use. It has to be the name the server was configured
// to expect, because the server rejects a greeting whose SNI is not in its ServerNames before it
// even looks at the seal.
const realityTestServerName = "interop.local"

// newRealityClientWithServerKey builds a REALITY client plus the raw X25519 private key of the
// server it will talk to.
//
// The pair is minted here rather than taken from newRealityTestKeyPair because the server half is
// what the test replays with, and a helper that returned only the client would force the test to
// re-derive it - which is the same "the client checks itself" shape this file exists to avoid.
func newRealityClientWithServerKey(t *testing.T, keyShare string) (*RealityClientConfig, []byte) {
	t.Helper()
	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	created, err := NewRealityClient(context.Background(), log.NewNOPFactory().NewLogger("tls"), realityTestServerName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: realityTestServerName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
			ShortID:   realityTestShortID,
			KeyShare:  keyShare,
		},
	})
	require.NoError(t, err)
	client, isReality := created.(*RealityClientConfig)
	require.True(t, isReality, "the constructed config must be the REALITY client")
	return client, serverPrivate.Bytes()
}

// greetOnAPipe runs the client's first flight over an in-memory connection and returns the exact
// ClientHello handshake message a server would receive.
//
// A pipe rather than inspection of HandshakeState.Hello.Raw, because the point is the bytes that
// leave the client: a greeting that is correct in the struct but re-marshalled on the way out is
// precisely the class of bug this file is about. The handshake is abandoned after the first flight
// - there is no server on the other end - so the goroutine's error is deliberately dropped.
func greetOnAPipe(t *testing.T, client *RealityClientConfig) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	go func() {
		_, _ = client.ClientHandshake(context.Background(), clientConn)
	}()
	record, err := readTLSRecord(serverConn)
	require.NoError(t, err, "read the client's first flight")
	require.EqualValues(t, 22, record[0], "the first flight must be a handshake record")
	messageLength := int(record[3])<<8 | int(record[4])
	require.GreaterOrEqual(t, len(record), 5+messageLength, "the handshake message must be complete")
	return record[5 : 5+messageLength]
}

// readTLSRecord reads one complete TLS record, header included. net.Pipe preserves write boundaries
// today, but a record that arrives in two writes must not turn into a silent truncation.
func readTLSRecord(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[3])<<8 | int(header[4])
	if length == 0 {
		return header, nil
	}
	record := make([]byte, 5+length)
	copy(record, header)
	if _, err := io.ReadFull(conn, record[5:]); err != nil {
		return nil, err
	}
	return record, nil
}

// realityClientHello is the subset of a ClientHello the REALITY acceptance path reads.
type realityClientHello struct {
	random     []byte
	sessionID  []byte
	serverName string
	shares     []realityKeyShare
}

type realityKeyShare struct {
	group uint16
	data  []byte
}

// parseRealityClientHello is a transcription of the fields the server's parser reads, written
// against the wire format in RFC 8446 rather than against uTLS's own structs, so that a uTLS field
// rename cannot make the test agree with a broken greeting.
func parseRealityClientHello(message []byte) (realityClientHello, error) {
	var parsed realityClientHello
	if len(message) < 40 || message[0] != 1 {
		return parsed, E.New("not a ClientHello handshake message")
	}
	parsed.random = message[6:38]
	sessionIDLength := int(message[38])
	if 39+sessionIDLength > len(message) {
		return parsed, E.New("session_id runs past the message")
	}
	parsed.sessionID = message[39 : 39+sessionIDLength]
	cursor := 39 + sessionIDLength
	if cursor+2 > len(message) {
		return parsed, E.New("truncated before the cipher suites")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(message[cursor:]))
	cursor += 2 + cipherSuitesLength
	if cursor+1 > len(message) {
		return parsed, E.New("truncated before the compression methods")
	}
	compressionLength := int(message[cursor])
	cursor += 1 + compressionLength
	if cursor+2 > len(message) {
		return parsed, E.New("truncated before the extensions")
	}
	extensionsLength := int(binary.BigEndian.Uint16(message[cursor:]))
	cursor += 2
	end := cursor + extensionsLength
	for cursor+4 <= end && cursor+4 <= len(message) {
		extensionType := binary.BigEndian.Uint16(message[cursor:])
		extensionLength := int(binary.BigEndian.Uint16(message[cursor+2:]))
		cursor += 4
		if cursor+extensionLength > len(message) {
			return parsed, E.New("extension runs past the message")
		}
		data := message[cursor : cursor+extensionLength]
		cursor += extensionLength
		switch extensionType {
		case 0: // server_name
			if len(data) >= 5 {
				nameLength := int(binary.BigEndian.Uint16(data[3:]))
				if 5+nameLength <= len(data) {
					parsed.serverName = string(data[5 : 5+nameLength])
				}
			}
		case 51: // key_share
			if len(data) < 2 {
				continue
			}
			sharesLength := int(binary.BigEndian.Uint16(data))
			position := 2
			for position+4 <= sharesLength+2 && position+4 <= len(data) {
				group := binary.BigEndian.Uint16(data[position:])
				shareLength := int(binary.BigEndian.Uint16(data[position+2:]))
				position += 4
				if position+shareLength > len(data) {
					break
				}
				parsed.shares = append(parsed.shares, realityKeyShare{
					group: group,
					data:  data[position : position+shareLength],
				})
				position += shareLength
			}
		}
	}
	return parsed, nil
}

// referencePeerPublicKey picks the peer key the way the server does: the first bare X25519 share,
// and only when there is none, the X25519 half of an X25519MLKEM768 share.
//
// The ORDER is the whole point of the function. A Chrome greeting carries both shares, and the two
// halves of the client derive the auth key from different private keys for each; a client that
// picks the hybrid half while the server picks the bare share produces two different auth keys and
// a handshake that fails for a reason neither side can name.
func (c realityClientHello) referencePeerPublicKey() []byte {
	for _, share := range c.shares {
		if share.group == 0x001d && len(share.data) == 32 {
			return share.data
		}
	}
	for _, share := range c.shares {
		if share.group == 0x11ec && len(share.data) == 1184+32 {
			return share.data[1184:]
		}
	}
	return nil
}

// referenceServerAuth is the acceptance path a REALITY server runs, in the server's own order:
// X25519 against the chosen share, HKDF-SHA256 salted with the first 20 bytes of the random, then
// AES-256-GCM open of the sealed session_id with the received greeting - its session_id ZEROED - as
// the additional data.
//
// It returns the decrypted session_id, or the error the tag check produced. `metacubex/utls`
// reality.go and Xray's reality.go are the source; the zeroing line there is
// `copy(hs.clientHello.sessionId, plainText)`, which works because the parsed session_id aliases
// raw[39:].
func referenceServerAuth(hello []byte, parsed realityClientHello, serverPrivateKey []byte) ([]byte, error) {
	peerPublicKey := parsed.referencePeerPublicKey()
	if peerPublicKey == nil {
		return nil, E.New("the greeting carries no key share the server can use")
	}
	authKey, err := curve25519.X25519(serverPrivateKey, peerPublicKey)
	if err != nil {
		return nil, E.Cause(err, "derive the REALITY auth key")
	}
	if _, err = hkdf.New(sha256.New, authKey, parsed.random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, E.Cause(err, "run the REALITY HKDF")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	additionalData := append([]byte(nil), hello...)
	clear(additionalData[39 : 39+len(parsed.sessionID)])
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, parsed.random[20:], parsed.sessionID, additionalData)
	if err != nil {
		return nil, E.Cause(err, "open the sealed session_id")
	}
	return plaintext, nil
}

// TestRealityGreetingIsAcceptedByTheReferenceServersCheck is the regression guard for the seal's
// additional data, across every key_share policy.
//
// A failure here means a real Xray server answers the greeting with its camouflage site: the client
// sees a valid TLS connection to the wrong peer, reports "reality verification failed", and gives
// no hint that the key, the short_id and the SNI were all correct.
func TestRealityGreetingIsAcceptedByTheReferenceServersCheck(t *testing.T) {
	t.Parallel()
	shortID, err := hex.DecodeString(realityTestShortID)
	require.NoError(t, err)
	for _, keyShare := range []string{
		C.RealityKeyShareDefault,
		C.RealityKeyShareClassical,
		C.RealityKeyShareHybrid,
	} {
		keyShare := keyShare
		t.Run(keyShare, func(t *testing.T) {
			t.Parallel()
			client, serverPrivateKey := newRealityClientWithServerKey(t, keyShare)
			// ONE greeting, parsed and then replayed: a second call would produce a different
			// random and a different key share, and the replay would compare two unrelated flights.
			greeting := greetOnAPipe(t, client)
			parsed, err := parseRealityClientHello(greeting)
			require.NoError(t, err)
			require.Equal(t, realityTestServerName, parsed.serverName,
				"the SERVER rejects an unknown SNI before it looks at the seal")

			plaintext, err := referenceServerAuth(greeting, parsed, serverPrivateKey)
			require.NoError(t, err,
				"the reference server's own acceptance path must authenticate the greeting")
			require.Len(t, plaintext, 16)
			require.Equal(t, []byte{
				realityMinClientVersionMajor,
				realityMinClientVersionMinor,
				realityMinClientVersionPatch,
				0,
			}, plaintext[:4], "the server compares these as a big-endian integer against its minimum")
			require.Equal(t, shortID, plaintext[8:16], "the short_id must land where the server reads it")
		})
	}
}

// startCamouflageTLSServer starts the TLS server a REALITY server forwards an unauthenticated
// ClientHello to and returns its address.
//
// REALITY cannot authenticate on its own: the server relays the ClientHello to its `dest` and
// rebuilds its own flight from what comes back, so a `dest` that does not speak TLS 1.3 leaves the
// handshake with nothing to reuse. X25519 only, because the greeting under test is the classical
// one and the server reuses the target's key share.
func startCamouflageTLSServer(t *testing.T, serverName string) string {
	t.Helper()
	certificate, err := GenerateKeyPair(nil, nil, time.Now, serverName)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})
	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{*certificate},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				tlsConn := tls.Server(conn, serverConfig)
				// The REALITY server consumes the target's flight and never forwards the client's
				// Finished, so this handshake is expected to end in a read error. Draining it keeps
				// the flight it already wrote available to the REALITY server.
				_ = tlsConn.HandshakeContext(context.Background())
				_, _ = io.Copy(io.Discard, tlsConn)
				_ = tlsConn.Close()
			}()
		}
	}()
	return listener.Addr().String()
}

// TestRealityHandshakeVerifiesTheServerAgainstARealRealityServer is the end-to-end guard: this
// package's client against `utls.RealityServer`, the exact implementation
// common/tls/reality_server.go hands every REALITY inbound to.
//
// It is the only test here that completes a handshake, and it fails for either of the two
// regressions this file is about: a wrong seal leaves the server relaying the connection to the
// camouflage site, and a dropped verifier leaves verifier.verified false. Both surface as
// "reality verification failed", which is why the assertion is "the handshake completed at all".
func TestRealityHandshakeVerifiesTheServerAgainstARealRealityServer(t *testing.T) {
	t.Parallel()
	client, serverPrivateKey := newRealityClientWithServerKey(t, C.RealityKeyShareClassical)
	var shortID [8]byte
	decoded, err := hex.Decode(shortID[:], []byte(realityTestShortID))
	require.NoError(t, err)
	require.EqualValues(t, 8, decoded)

	camouflageAddress := startCamouflageTLSServer(t, realityTestServerName)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	serverConfig := &utls.RealityConfig{
		Type: "tcp",
		Dest: camouflageAddress,
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
		ServerNames: map[string]bool{realityTestServerName: true},
		PrivateKey:  serverPrivateKey,
		ShortIds:    map[[8]byte]bool{shortID: true},
		Config: utls.Config{
			Time: time.Now,
		},
	}
	go func() {
		_, _ = utls.RealityServer(context.Background(), serverConn, serverConfig)
	}()

	handshakeContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.ClientHandshake(handshakeContext, clientConn)
	require.NoError(t, err,
		"a handshake the server accepted must not end in \"reality verification failed\"")
	require.NotNil(t, conn)
}

// TestRealityUConfigCarriesTheServerVerifier is the cheap structural half of the guard above.
//
// The end-to-end test proves the wiring works today; this one names the thing that was dropped, so
// a future refactor that reintroduces a second clone fails with the reason instead of with a
// handshake timeout against the camouflage destination.
func TestRealityUConfigCarriesTheServerVerifier(t *testing.T) {
	t.Parallel()
	client, _ := newRealityClientWithServerKey(t, C.RealityKeyShareDefault)
	called := false
	verify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		called = true
		return nil
	}
	uConfig := client.realityUConfig(verify)
	require.NotNil(t, uConfig.VerifyPeerCertificate,
		"the connection's config must carry REALITY's own server check")
	require.True(t, uConfig.InsecureSkipVerify,
		"REALITY authenticates the server with the seal, not with a CA chain")
	require.True(t, uConfig.SessionTicketsDisabled)
	require.NoError(t, uConfig.VerifyPeerCertificate(nil, nil))
	require.True(t, called, "the callback must be the caller's, not a copy of some default")
}
