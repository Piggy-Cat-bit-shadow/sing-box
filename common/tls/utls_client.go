//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

type UTLSClientConfig struct {
	ctx                   context.Context
	config                *utls.Config
	serverName            string
	disableSNI            bool
	verifyServerName      bool
	handshakeTimeout      time.Duration
	id                    utls.ClientHelloID
	fragment              bool
	fragmentFallbackDelay time.Duration
	recordFragment        bool
	spoof                 string
	spoofMethod           tlsspoof.Method
}

func (c *UTLSClientConfig) ServerName() string {
	return c.serverName
}

func (c *UTLSClientConfig) SetServerName(serverName string) {
	c.serverName = serverName
	if c.disableSNI {
		c.config.ServerName = ""
		if c.verifyServerName {
			c.config.InsecureServerNameToVerify = serverName
		} else {
			c.config.InsecureServerNameToVerify = ""
		}
		return
	}
	c.config.ServerName = serverName
}

func (c *UTLSClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *UTLSClientConfig) SetNextProtos(nextProto []string) {
	if len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	c.config.NextProtos = nextProto
}

func (c *UTLSClientConfig) HandshakeTimeout() time.Duration {
	return c.handshakeTimeout
}

func (c *UTLSClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.handshakeTimeout = timeout
}

func (c *UTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

// wrapClientConn applies the first-flight transforms - ClientHello fragmentation and TLS spoofing -
// to a connection before uTLS is built on top of it.
//
// # Why this is a shared helper rather than four lines inside Client
//
// REALITY has its own handshake (it has to build the greeting, rewrite session_id and re-marshal),
// so it never went through Client and therefore never got this wrapper. The consequence was a silent
// no-op: `fragment` and `record_fragment` were accepted by the config parser on a REALITY node and
// did nothing, and the automatic record-fragment default for a detoured dial never reached the
// handshake - in the case where an unsplit ClientHello is the whole problem. Both paths must apply
// the same transforms, and a second copy of them is how they drift apart again.
func (c *UTLSClientConfig) wrapClientConn(conn net.Conn) (net.Conn, error) {
	if c.fragment || c.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.fragment, c.recordFragment, c.fragmentFallbackDelay)
	}
	return applyTLSSpoof(conn, c.spoof, c.spoofMethod)
}

func (c *UTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	conn, err := c.wrapClientConn(conn)
	if err != nil {
		return nil, err
	}
	return &utlsALPNWrapper{utlsConnWrapper{utls.UClient(conn, c.config.Clone(), c.id)}, c.config.NextProtos}, nil
}

func (c *UTLSClientConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.config.SessionIDGenerator = generator
}

func (c *UTLSClientConfig) Clone() Config {
	cloned := &UTLSClientConfig{
		ctx:                   c.ctx,
		config:                c.config.Clone(),
		serverName:            c.serverName,
		disableSNI:            c.disableSNI,
		verifyServerName:      c.verifyServerName,
		handshakeTimeout:      c.handshakeTimeout,
		id:                    c.id,
		fragment:              c.fragment,
		fragmentFallbackDelay: c.fragmentFallbackDelay,
		recordFragment:        c.recordFragment,
		spoof:                 c.spoof,
		spoofMethod:           c.spoofMethod,
	}
	cloned.SetServerName(cloned.serverName)
	return cloned
}

func (c *UTLSClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *UTLSClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
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

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

func (c *utlsConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *utlsConnWrapper) WriterReplaceable() bool {
	return true
}

type utlsALPNWrapper struct {
	utlsConnWrapper
	nextProtocols []string
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) error {
	if len(c.nextProtocols) > 0 {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
		for _, extension := range c.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = c.nextProtocols
				err = c.BuildHandshakeState()
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

func NewUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newUTLSClient(ctx, logger, serverAddress, options, false)
}

func newUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure && !allowEmptyServerName {
		return nil, errMissingServerName
	}

	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("disable_sni is unsupported in reality")
		}
	}
	if len(options.CertificateSHA256) > 0 || len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_sha256 or certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return VerifyPinnedCertificate(options.CertificateSHA256, options.CertificatePublicKeySHA256, rawCerts)
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", string(certificate))
		}
		tlsConfig.RootCAs = certPool
	}
	var clientCertificate []byte
	if len(options.ClientCertificate) > 0 {
		clientCertificate = []byte(strings.Join(options.ClientCertificate, "\n"))
	} else if options.ClientCertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.ClientCertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read client certificate")
		}
		clientCertificate = content
	}
	var clientKey []byte
	if len(options.ClientKey) > 0 {
		clientKey = []byte(strings.Join(options.ClientKey, "\n"))
	} else if options.ClientKeyPath != "" {
		content, err := filemanager.ReadFile(ctx, options.ClientKeyPath)
		if err != nil {
			return nil, E.Cause(err, "read client key")
		}
		clientKey = content
	}
	if len(clientCertificate) > 0 && len(clientKey) > 0 {
		keyPair, err := utls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			return nil, E.Cause(err, "parse client x509 key pair")
		}
		tlsConfig.Certificates = []utls.Certificate{keyPair}
	} else if len(clientCertificate) > 0 || len(clientKey) > 0 {
		return nil, E.New("client certificate and client key must be provided together")
	}
	var handshakeTimeout time.Duration
	if options.HandshakeTimeout > 0 {
		handshakeTimeout = options.HandshakeTimeout.Build()
	} else {
		handshakeTimeout = C.TCPTimeout
	}
	spoof, spoofMethod, err := parseTLSSpoofOptions(serverName, options)
	if err != nil {
		return nil, err
	}
	id, err := uTLSClientHelloID(options.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	var config Config = &UTLSClientConfig{
		ctx:                   ctx,
		config:                &tlsConfig,
		serverName:            serverName,
		disableSNI:            options.DisableSNI,
		verifyServerName:      options.DisableSNI && !options.Insecure,
		handshakeTimeout:      handshakeTimeout,
		id:                    id,
		fragment:              options.Fragment,
		fragmentFallbackDelay: time.Duration(options.FragmentFallbackDelay),
		recordFragment:        options.RecordFragment,
		spoof:                 spoof,
		spoofMethod:           spoofMethod,
	}
	config.SetServerName(serverName)
	if options.ECH != nil && options.ECH.Enabled {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("Reality is conflict with ECH")
		}
		config, err = parseECHClientConfig(ctx, config.(ECHCapableConfig), options)
		if err != nil {
			return nil, err
		}
	}
	if (options.KernelRx || options.KernelTx) && !common.PtrValueOrDefault(options.Reality).Enabled {
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

var (
	randomFingerprint     utls.ClientHelloID
	randomizedFingerprint utls.ClientHelloID

	// modernFingerprints is the pool `utls.fingerprint: random` draws from. It is
	// a package variable rather than a local of init because the REALITY
	// fingerprint register asserts what that draw can land on: the pool contains
	// four presets that cannot present the post-quantum hybrid key share, so a
	// `random` REALITY client is only able to complete a handshake against a
	// current reference when the draw happened to be Chrome.
	modernFingerprints []utls.ClientHelloID

	// uTLSFingerprints is the table of names `utls.fingerprint` accepts.
	//
	// It is a table rather than a switch so that it can be ENUMERATED. The
	// REALITY fingerprint register
	// (reality_fingerprint_register_test.go) walks this map and fails for any
	// name whose preset it has not classified, which is the property a
	// hand-written list in the test cannot have: a name added here would
	// otherwise be exercised by real users and by nothing else.
	//
	// It is built in init because two of its values are resolved there.
	uTLSFingerprints map[string]utls.ClientHelloID
)

func init() {
	modernFingerprints = []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights

	uTLSFingerprints = map[string]utls.ClientHelloID{
		// The psk and pq spellings are aliases of Chrome, and they are
		// deliberately NOT reordered or renamed here: they are part of the
		// configuration vocabulary users already have.
		"chrome_psk":                 utls.HelloChrome_Auto,
		"chrome_psk_shuffle":         utls.HelloChrome_Auto,
		"chrome_padding_psk_shuffle": utls.HelloChrome_Auto,
		"chrome_pq":                  utls.HelloChrome_Auto,
		"chrome_pq_psk":              utls.HelloChrome_Auto,
		"chrome":                     utls.HelloChrome_Auto,
		"":                           utls.HelloChrome_Auto,
		"firefox":                    utls.HelloFirefox_Auto,
		"edge":                       utls.HelloEdge_Auto,
		"safari":                     utls.HelloSafari_Auto,
		"360":                        utls.Hello360_Auto,
		"qq":                         utls.HelloQQ_Auto,
		"ios":                        utls.HelloIOS_Auto,
		"android":                    utls.HelloAndroid_11_OkHttp,
		"random":                     randomFingerprint,
		"randomized":                 randomizedFingerprint,
	}
}

func uTLSClientHelloID(name string) (utls.ClientHelloID, error) {
	id, isKnown := uTLSFingerprints[name]
	if !isKnown {
		return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
	}
	return id, nil
}
