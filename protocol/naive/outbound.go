//go:build with_naive_outbound

package naive

import (
	"context"
	"encoding/pem"
	"net"
	"strings"

	"github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/all"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NaiveOutboundOptions](registry, C.TypeNaive, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    logger.ContextLogger
	client    *cronet.NaiveClient
	uotClient *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.TLS.DisableSNI {
		return nil, E.New("disable_sni is not supported on naive outbound")
	}
	if options.TLS.Insecure {
		return nil, E.New("insecure is not supported on naive outbound")
	}
	if len(options.TLS.ALPN) > 0 {
		return nil, E.New("alpn is not supported on naive outbound")
	}
	if options.TLS.MinVersion != "" {
		return nil, E.New("min_version is not supported on naive outbound")
	}
	if options.TLS.MaxVersion != "" {
		return nil, E.New("max_version is not supported on naive outbound")
	}
	if len(options.TLS.CipherSuites) > 0 {
		return nil, E.New("cipher_suites is not supported on naive outbound")
	}
	if len(options.TLS.CurvePreferences) > 0 {
		return nil, E.New("curve_preferences is not supported on naive outbound")
	}
	if len(options.TLS.ClientCertificate) > 0 || options.TLS.ClientCertificatePath != "" {
		return nil, E.New("client_certificate is not supported on naive outbound")
	}
	if len(options.TLS.ClientKey) > 0 || options.TLS.ClientKeyPath != "" {
		return nil, E.New("client_key is not supported on naive outbound")
	}
	if options.TLS.Fragment || options.TLS.RecordFragment {
		return nil, E.New("fragment is not supported on naive outbound")
	}
	if options.TLS.KernelTx || options.TLS.KernelRx {
		return nil, E.New("kernel TLS is not supported on naive outbound")
	}
	if options.TLS.UTLS != nil && options.TLS.UTLS.Enabled {
		return nil, E.New("uTLS is not supported on naive outbound")
	}
	if options.TLS.Reality != nil && options.TLS.Reality.Enabled {
		return nil, E.New("reality is not supported on naive outbound")
	}

	// Reject a reserved-header collision at configuration time. cronet-go also
	// refuses it in NewNaiveClient, but failing here means the operator sees a
	// configuration error naming the offending header instead of a runtime failure
	// that depends on the native library loading first.
	if err := validateReservedExtraHeaders(options.ExtraHeaders.Build()); err != nil {
		return nil, err
	}

	serverAddress := options.ServerOptions.Build()

	var serverName string
	if options.TLS.ServerName != "" {
		serverName = options.TLS.ServerName
	} else {
		serverName = serverAddress.AddrString()
	}

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}

	var trustedRootCertificates string
	if len(options.TLS.Certificate) > 0 {
		trustedRootCertificates = strings.Join(options.TLS.Certificate, "\n")
	} else if options.TLS.CertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.TLS.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		trustedRootCertificates = string(content)
	}

	extraHeaders := make(map[string]string)
	for key, values := range options.ExtraHeaders.Build() {
		if len(values) > 0 {
			extraHeaders[key] = values[0]
		}
	}

	// Chromium's DNS goes through this bridge rather than the system resolver, so a Naive
	// connection cannot leak a query past sing-box's DNS policy.
	//
	// # There is no second lookup on the socket path
	//
	// The obvious worry is a double resolution: Chromium resolves the server name here, and then
	// the custom socket factory dials it again. That does not happen, and the socket callback's
	// contract is what settles it -- cronet-go documents the address it receives as an
	// "IP address string (e.g. \"1.2.3.4\" or \"::1\")" for BOTH the TCP and UDP factories. Chromium
	// resolves once through this bridge and hands the dialer an address, not a name.
	//
	// So the resolution happens exactly once, through the policy below, and the dial layer receives
	// the result. The two layers are not two authorities.
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	var dnsResolver cronet.DNSResolverFunc
	if dnsRouter != nil {
		dnsResolver = func(dnsContext context.Context, request *mDNS.Msg) *mDNS.Msg {
			response, err := dnsRouter.Exchange(dnsContext, request, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if err != nil {
				logger.Error("DNS exchange failed: ", err)
				return dns.FixedResponseStatus(request, mDNS.RcodeServerFailure)
			}
			return response
		}
	}

	var echEnabled bool
	var echConfigList []byte
	var echQueryServerName string
	if options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		echEnabled = true
		echQueryServerName = options.TLS.ECH.QueryServerName
		var echConfig []byte
		if len(options.TLS.ECH.Config) > 0 {
			echConfig = []byte(strings.Join(options.TLS.ECH.Config, "\n"))
		} else if options.TLS.ECH.ConfigPath != "" {
			content, err := filemanager.ReadFile(ctx, options.TLS.ECH.ConfigPath)
			if err != nil {
				return nil, E.Cause(err, "read ECH config")
			}
			echConfig = content
		}
		if len(echConfig) > 0 {
			block, rest := pem.Decode(echConfig)
			if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
				return nil, E.New("invalid ECH configs pem")
			}
			echConfigList = block.Bytes
		}
	}
	var quicCongestionControl cronet.QUICCongestionControl
	switch options.QUICCongestionControl {
	case "":
		quicCongestionControl = cronet.QUICCongestionControlDefault
	case "bbr":
		quicCongestionControl = cronet.QUICCongestionControlBBR
	case "bbr2":
		quicCongestionControl = cronet.QUICCongestionControlBBRv2
	case "cubic":
		quicCongestionControl = cronet.QUICCongestionControlCubic
	case "reno":
		quicCongestionControl = cronet.QUICCongestionControlReno
	default:
		return nil, E.New("unknown quic congestion control: ", options.QUICCongestionControl)
	}
	// InsecureConcurrencySingleEngine is passed through only when the operator asked
	// for it. cronet-go ORs this with `runtime.GOOS == "ios"`, so leaving it false
	// keeps the platform behaviour exactly as upstream: N engines on macOS, one
	// engine on iOS. Setting it true is what makes the single-engine + isolation-key
	// shape selectable on macOS for the A/B described in
	// docs/ENGINEERING-NOTES.md.
	clientOptions := buildCronetNaiveClientOptions(cronetNaiveClientParams{
		ctx:                     ctx,
		logger:                  logger,
		serverAddress:           serverAddress,
		serverName:              serverName,
		options:                 options,
		extraHeaders:            extraHeaders,
		trustedRootCertificates: trustedRootCertificates,
		dialer:                  outboundDialer,
		dnsResolver:             dnsResolver,
		echEnabled:              echEnabled,
		echConfigList:           echConfigList,
		echQueryServerName:      echQueryServerName,
		quicCongestionControl:   quicCongestionControl,
	})
	client, err := cronet.NewNaiveClient(clientOptions)
	if err != nil {
		return nil, err
	}
	var uotClient *uot.Client
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		uotClient = &uot.Client{
			Dialer:  &naiveDialer{client},
			Version: uotOptions.Version,
		}
	}
	var networks []string
	if uotClient != nil {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeNaive, tag, networks, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		client:    client,
		uotClient: uotClient,
	}, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.client.Start()
	if err != nil {
		return err
	}
	scope.Add(h.client.Close)
	h.logger.Info("NaiveProxy started, version: ", h.client.Engine().Version())
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialEarly(ctx, destination)
	case N.NetworkUDP:
		if h.uotClient == nil {
			return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
		}
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient == nil {
		return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
	}
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.CloseAllConnections()
}

func (h *Outbound) Client() *cronet.NaiveClient {
	return h.client
}

type naiveDialer struct {
	*cronet.NaiveClient
}

func (d *naiveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.NaiveClient.DialEarly(ctx, destination)
}

// cronetNaiveClientParams carries everything buildCronetNaiveClientOptions needs.
//
// The fields are unexported and the struct is internal: it exists to make the
// configuration -> Cronet mapping a pure function that a test can call, not to
// become part of any interface.
type cronetNaiveClientParams struct {
	ctx                     context.Context
	logger                  logger.ContextLogger
	serverAddress           M.Socksaddr
	serverName              string
	options                 option.NaiveOutboundOptions
	extraHeaders            map[string]string
	trustedRootCertificates string
	dialer                  N.Dialer
	dnsResolver             cronet.DNSResolverFunc
	echEnabled              bool
	echConfigList           []byte
	echQueryServerName      string
	quicCongestionControl   cronet.QUICCongestionControl
}

// buildCronetNaiveClientOptions maps a validated sing-box configuration onto
// cronet.NaiveClientOptions.
//
// It is a pure function with no side effects, which is what makes the plumbing
// testable: previously this mapping lived inline in NewOutbound, so a test could
// only assert that the option struct held a bool - it could not show that the value
// reached the Cronet constructor at all. The mapping is deliberately kept
// mechanical (no validation, no defaults beyond the switch statements already
// performed by the caller) so that reading it is enough to see every field.
func buildCronetNaiveClientOptions(params cronetNaiveClientParams) cronet.NaiveClientOptions {
	return cronet.NaiveClientOptions{
		Context:       params.ctx,
		Logger:        params.logger,
		ServerAddress: params.serverAddress,
		ServerName:    params.serverName,
		Username:      params.options.Username,
		Password:      params.options.Password,
		// InsecureConcurrency sets how many isolated sessions/pools to use;
		// TestForceSingleEngine sets how many Cronet engines back them. They are
		// independent: cronet-go decides with
		//   singleEngine: TestForceSingleEngine || runtime.GOOS == "ios"
		//   engineCount := 1; if concurrency > 1 && !singleEngine { engineCount = concurrency }
		// so leaving the switch false preserves the upstream macOS layout of N
		// engines.
		InsecureConcurrency:      params.options.InsecureConcurrency,
		TestForceSingleEngine:    params.options.InsecureConcurrencySingleEngine,
		ExtraHeaders:             params.extraHeaders,
		ReceiveWindow:            params.options.ReceiveWindow.Value(),
		TrustedRootCertificates:  params.trustedRootCertificates,
		Dialer:                   params.dialer,
		DNSResolver:              params.dnsResolver,
		ECHEnabled:               params.echEnabled,
		ECHConfigList:            params.echConfigList,
		ECHQueryServerName:       params.echQueryServerName,
		QUIC:                     params.options.QUIC,
		QUICCongestionControl:    params.quicCongestionControl,
		QUICSessionReceiveWindow: params.options.QUICSessionReceiveWindow.Value(),
	}
}

// validateReservedExtraHeaders rejects extra_headers entries that would override a
// Naive control header.
//
// The check delegates to cronet.IsReservedNaiveHeader so the reserved set has
// exactly one definition, shared with the code that builds the CONNECT request.
// Duplicating the list here would let the two drift, which is how the original
// override bug would come back.
func validateReservedExtraHeaders(extraHeaders map[string][]string) error {
	for key := range extraHeaders {
		if cronet.IsReservedNaiveHeader(key) {
			return E.New("extra_headers must not override the reserved Naive control header ",
				key, "; it would change protocol behaviour instead of adding a request header")
		}
	}
	return nil
}
