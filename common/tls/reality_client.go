//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	ctx       context.Context
	uClient   *UTLSClientConfig
	publicKey []byte
	shortID   [8]byte
	// keyShare is the ClientHello key_share policy (constant.RealityKeyShare*). It is a property of
	// the greeting's CONTENT; the fingerprint still decides its shape.
	keyShare string
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}

	// Validated before anything is built, so a typo cannot silently become the default. A caller
	// that asked for a policy the core cannot honour must be told, not quietly served something
	// else: "reality verification failed" at the server is indistinguishable from a wrong key.
	switch options.Reality.KeyShare {
	case C.RealityKeyShareDefault, C.RealityKeyShareClassical, C.RealityKeyShareHybrid:
	default:
		return nil, E.New("unknown reality key_share: ", options.Reality.KeyShare,
			` (expected "hybrid" or "classical")`)
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	// The length is checked BEFORE the decode, not after it.
	//
	// hex.Decode writes len(src)/2 bytes into dst without checking dst's capacity, so a short_id
	// longer than 16 hex characters runs off the end of the [8]byte INSIDE hex.Decode and panics
	// with "index out of range", taking the whole process down while the configuration is only
	// being loaded. The post-decode "decodedLen > 8" test below cannot catch it: control never
	// gets there. A short_id comes from a subscription, so it is untrusted input.
	if len(options.Reality.ShortID) > 16 {
		return nil, E.New("invalid short_id")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}

	var config Config = &RealityClientConfig{
		ctx:       ctx,
		uClient:   uClient.(*UTLSClientConfig),
		publicKey: publicKey,
		shortID:   shortID,
		keyShare:  options.Reality.KeyShare,
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

// newClientUConn builds the ClientHello the REALITY handshake will send: it applies the
// first-flight transforms, builds uTLS, and applies the key_share policy.
//
// It is split out of ClientHandshake because it is the part that decides WHAT goes on the wire, and
// it does no I/O - so it is the part a test can inspect. ClientHandshake is then only "send it and
// check the answer".
func (e *RealityClientConfig) newClientUConn(conn net.Conn) (*utls.UConn, error) {
	// The same first-flight transforms the plain uTLS path applies. REALITY has its own handshake,
	// so without this the configured fragmentation - and the automatic record-fragment default for a
	// detoured dial - were accepted and then silently ignored on exactly the path where the
	// oversized hybrid greeting makes them matter most.
	wrapped, err := e.uClient.wrapClientConn(conn)
	if err != nil {
		return nil, err
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConn := utls.UClient(wrapped, uConfig, e.uClient.id)
	if err = prepareClientHello(uConn, e.keyShare, e.uClient.id); err != nil {
		return nil, err
	}
	return uConn, nil
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.ServerName(),
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn, err := e.newClientUConn(conn)
	if err != nil {
		return nil, err
	}
	verifier.UConn = uConn
	authKey, err := e.prepareFirstFlight(uConn, uConfig)
	if err != nil {
		return nil, err
	}
	verifier.authKey = authKey

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

// prepareFirstFlight completes the REALITY greeting: ALPN, the sealed session_id and the auth key.
//
// It is separate from ClientHandshake so that every decision about what goes on the wire can be
// asserted without a server, which is the only way a silent compatibility break in this area is
// detectable at all.
func (e *RealityClientConfig) prepareFirstFlight(uConn *utls.UConn, uConfig *utls.Config) ([]byte, error) {
	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = e.buildSessionID(nowTime)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	// The X25519 private key of whichever key share uTLS put FIRST, because that is the one the
	// REALITY server reads.
	//
	// uTLS records a classical first share in Ecdhe and a hybrid (X25519MLKEM768) first share in
	// MlkemEcdhe - the X25519 half of the hybrid, whose public half travels inside the hybrid share
	// the server parses. Only the first non-GREASE share is recorded at all, so "Ecdhe, else
	// MlkemEcdhe" is exactly "the share the server will use", with no second guess available.
	// A build that reads only Ecdhe therefore has to delete the hybrid share to work at all, which
	// is the state this fork was in and which breaks REALITY against Xray >= v26.9.8.
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
	}
	return authKey, nil
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	// Named fields rather than positional: a positional literal silently drops a field added to the
	// struct, and the clones are what every dial actually uses.
	return &RealityClientConfig{
		ctx:       e.ctx,
		uClient:   e.uClient.Clone().(*UTLSClientConfig),
		publicKey: e.publicKey,
		shortID:   e.shortID,
		keyShare:  e.keyShare,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}

// prepareClientHello applies the REALITY key_share policy to the uTLS ClientHello and marshals it.
//
// # Why the policy exists at all
//
// A post-quantum hybrid key share (X25519MLKEM768) makes the ClientHello roughly 1.7 KB and,
// depending on the fingerprint, it leaves as two TCP segments. Some paths silently drop a greeting
// that arrives that way, and the failure is a timeout, not an error - the same symptom as a wrong
// public key. The policy lets a single node ask for the classical greeting without pretending to be
// a different browser.
//
// # Why the default does not strip
//
// Stripping is a CONTENT change with a compatibility cost in the other direction: Xray >= v26.9.8
// derives the REALITY auth key from the hybrid share and rejects a client that does not send one.
// So neither behaviour can be the unconditional default; "whatever the fingerprint carries" is the
// only default that is not a claim about the network, and the fingerprint is the thing the user
// actually chose.
//
// uTLS applies a preset exactly once (`clientHelloBuildStatus == BuildByUtls`); the second
// BuildHandshakeState below only re-marshals the greeting from the filtered extensions, which is
// why the filter must run between the two calls.
func prepareClientHello(uConn *utls.UConn, keySharePolicy string, fingerprint utls.ClientHelloID) error {
	err := uConn.BuildHandshakeState()
	if err != nil {
		return err
	}
	switch keySharePolicy {
	case C.RealityKeyShareClassical:
		for _, extension := range uConn.Extensions {
			if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
				curves.Curves = common.Filter(curves.Curves, func(curveID utls.CurveID) bool {
					return curveID != utls.X25519MLKEM768
				})
			}
			if shares, isShares := extension.(*utls.KeyShareExtension); isShares {
				shares.KeyShares = common.Filter(shares.KeyShares, func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768
				})
			}
		}
		return uConn.BuildHandshakeState()
	case C.RealityKeyShareHybrid:
		// Checked as a WIRE fact - is the share in the greeting the server will receive - rather
		// than against a table of fingerprint names. A table would go stale with every uTLS update
		// and, worse, would be a claim about a preset rather than about what was built.
		err = uConn.BuildHandshakeState()
		if err != nil {
			return err
		}
		if !clientHelloCarriesHybridShare(uConn) {
			return E.New(`reality key_share "hybrid": fingerprint `, fingerprint.Client,
				` carries no X25519MLKEM768 key share`)
		}
		return nil
	default:
		// The default keeps the greeting the preset built, for the reason in the doc comment.
		return nil
	}
}

// clientHelloCarriesHybridShare reports whether the built ClientHello's key_share extension
// contains X25519MLKEM768.
func clientHelloCarriesHybridShare(uConn *utls.UConn) bool {
	for _, extension := range uConn.Extensions {
		shares, isShares := extension.(*utls.KeyShareExtension)
		if !isShares {
			continue
		}
		return common.Any(shares.KeyShares, func(share utls.KeyShare) bool {
			return share.Group == utls.X25519MLKEM768
		})
	}
	return false
}

// buildSessionID returns the PLAINTEXT session_id the REALITY greeting carries before it is sealed.
//
// # Layout (from the Xray server's parser)
//
//	[0:3]  the client version, compared as a big-endian integer against the server's minimum
//	[3]    zero
//	[4:8]  the low four bytes of the unix time
//	[8:16] the short_id
//	[16:]  zero, then replaced by the AEAD tag when the greeting is sealed
//
// # Why the version is a real protocol value and not our own epoch
//
// Upstream sing-box wrote 1.8.1 here - its own release epoch. Xray v26.7.11 raised its default
// minimum to 26.3.27 and compares with >=, so every client still declaring 1.8.1 was rejected. The
// rejection is SILENT: a failed REALITY verification is answered with the camouflage site, so the
// client reports "reality verification failed", which is exactly what a wrong public_key produces.
// There is no diagnostic path from the symptom back to this constant, which is why it has a test.
//
// Xray >= v26.9.8 does not check the field at all - the default was commented out in the same change
// that made the hybrid key share mandatory - so this is required for v26.7.11 through v26.9.x and
// harmless afterwards. It is not a claim about our build: the server reads it as a number.
func (e *RealityClientConfig) buildSessionID(now time.Time) []byte {
	sessionID := make([]byte, 32)
	binary.BigEndian.PutUint64(sessionID, uint64(now.Unix()))
	sessionID[0] = realityMinClientVersionMajor
	sessionID[1] = realityMinClientVersionMinor
	sessionID[2] = realityMinClientVersionPatch
	binary.BigEndian.PutUint32(sessionID[4:], uint32(time.Now().Unix()))
	copy(sessionID[8:], e.shortID[:])
	return sessionID
}

// The minimum REALITY client version, as Xray packs and compares it. See buildSessionID.
const (
	realityMinClientVersionMajor = 26
	realityMinClientVersionMinor = 3
	realityMinClientVersionPatch = 27
)
