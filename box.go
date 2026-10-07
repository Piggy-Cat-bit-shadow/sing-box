package box

import (
	"context"
	"io"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/netns"
	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing-box/common/taskmonitor"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.SimpleLifecycle = (*Box)(nil)

// applyPauseEvent is the whole bridge between the platform's lifecycle and the power governor.
//
// It is a named function rather than an inline closure so the mapping can be tested without building
// a Box: this is the only place the two vocabularies meet, and a mis-mapped event here would show up
// as a device that never sleeps rather than as anything resembling a failure.
func applyPauseEvent(governor *power.Governor, event int) {
	if governor == nil {
		return
	}
	switch event {
	case pause.EventDevicePaused:
		governor.DevicePaused()
	case pause.EventDeviceWake:
		governor.DeviceWake()
	case pause.EventNetworkPause:
		governor.NetworkPaused()
	case pause.EventNetworkWake:
		governor.NetworkWake()
	}
}

type Box struct {
	ctx context.Context
	// ownedURLTestHistory is the storage this Box created, and therefore must close. It is nil when
	// the caller supplied one, so a Box never closes state it does not own.
	ownedURLTestHistory *urltest.HistoryStorage
	createdAt           time.Time
	powerGovernor       *power.Governor
	pauseManager        pause.Manager
	pauseCallback       *list.Element[pause.Callback]
	debugOptions        option.DebugOptions
	logFactory          log.Factory
	logger              log.ContextLogger
	network             *route.NetworkManager
	endpoint            *endpoint.Manager
	inbound             *inbound.Manager
	outbound            *outbound.Manager
	service             *boxService.Manager
	certificateProvider *boxCertificate.Manager
	dnsTransport        *dns.TransportManager
	dnsRouter           *dns.Router
	connection          *route.ConnectionManager
	router              *route.Router
	referenceManager    *route.ReferenceManager
	httpClientService   adapter.LifecycleService
	internalService     []adapter.LifecycleService
	ntpService          *ntp.Service
	scope               *adapter.Scope
}

type Options struct {
	option.Options
	Context                    context.Context
	PlatformLogWriter          log.PlatformWriter
	NetworkNamespaceHolderArgs []string
}

func Context(
	ctx context.Context,
	inboundRegistry adapter.InboundRegistry,
	outboundRegistry adapter.OutboundRegistry,
	endpointRegistry adapter.EndpointRegistry,
	dnsTransportRegistry adapter.DNSTransportRegistry,
	serviceRegistry adapter.ServiceRegistry,
	certificateProviderRegistry adapter.CertificateProviderRegistry,
) context.Context {
	if service.FromContext[option.InboundOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.InboundRegistry](ctx) == nil {
		ctx = service.ContextWith[option.InboundOptionsRegistry](ctx, inboundRegistry)
		ctx = service.ContextWith[adapter.InboundRegistry](ctx, inboundRegistry)
	}
	if service.FromContext[option.OutboundOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.OutboundRegistry](ctx) == nil {
		ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outboundRegistry)
		ctx = service.ContextWith[adapter.OutboundRegistry](ctx, outboundRegistry)
	}
	if service.FromContext[option.EndpointOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.EndpointRegistry](ctx) == nil {
		ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, endpointRegistry)
		ctx = service.ContextWith[adapter.EndpointRegistry](ctx, endpointRegistry)
	}
	if service.FromContext[adapter.DNSTransportRegistry](ctx) == nil {
		ctx = service.ContextWith[option.DNSTransportOptionsRegistry](ctx, dnsTransportRegistry)
		ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, dnsTransportRegistry)
	}
	if service.FromContext[adapter.ServiceRegistry](ctx) == nil {
		ctx = service.ContextWith[option.ServiceOptionsRegistry](ctx, serviceRegistry)
		ctx = service.ContextWith[adapter.ServiceRegistry](ctx, serviceRegistry)
	}
	if service.FromContext[adapter.CertificateProviderRegistry](ctx) == nil {
		ctx = service.ContextWith[option.CertificateProviderOptionsRegistry](ctx, certificateProviderRegistry)
		ctx = service.ContextWith[adapter.CertificateProviderRegistry](ctx, certificateProviderRegistry)
	}
	return ctx
}

// ensureURLTestServices supplies the URL-test services a Box needs, if the caller has not.
//
// # The two decisions are INDEPENDENT
//
// They were previously nested: the coordinator was created only inside the branch that created a
// missing HistoryStorage. That coupling failed in both directions.
//
//   - HistoryStorage provided, coordinator missing - the common case for a caller that builds its
//     own Box context - skipped the coordinator entirely, so every measurement in that Box ran
//     unbounded: several groups, each with ten concurrent probes, with no ceiling.
//   - Coordinator provided, HistoryStorage missing - the caller's carefully sized limiter was
//     replaced by a default one, silently discarding the configuration.
//
// Each service is now supplied only if absent, and neither is ever overwritten. A caller that has
// already chosen a limit keeps it; one that has not gets the Box default.
// It returns the storage it CREATED, or nil when the caller already supplied one.
//
// # Why ownership has to be reported
//
// Putting a storage on the context does not make it part of the Box lifecycle. When the Box created
// it, only the Box knows it exists and only the Box can close it - and the daemon does exactly that
// for the instance it creates. A standalone Box that created one and never closed it left the
// storage live after Close: the closed flag stayed false, the maps were retained, and a late writer
// was still accepted.
//
// The caller's storage is deliberately not reported, so a Box never closes something it does not
// own.
func ensureURLTestServices(ctx context.Context) (context.Context, *urltest.HistoryStorage) {
	var ownedHistory *urltest.HistoryStorage
	if service.PtrFromContext[urltest.HistoryStorage](ctx) == nil {
		ownedHistory = urltest.NewHistoryStorage()
		ctx = service.ContextWithPtr(ctx, ownedHistory)
	}
	if urltest.CoordinatorFromContext(ctx) == nil {
		ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(C.URLTestConcurrencyLimit))
	}
	return ctx, ownedHistory
}

func New(options Options) (*Box, error) {
	createdAt := time.Now()
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = service.ContextWithDefaultRegistry(ctx)

	endpointRegistry := service.FromContext[adapter.EndpointRegistry](ctx)
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	dnsTransportRegistry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	serviceRegistry := service.FromContext[adapter.ServiceRegistry](ctx)
	certificateProviderRegistry := service.FromContext[adapter.CertificateProviderRegistry](ctx)

	if endpointRegistry == nil {
		return nil, E.New("missing endpoint registry in context")
	}
	if inboundRegistry == nil {
		return nil, E.New("missing inbound registry in context")
	}
	if outboundRegistry == nil {
		return nil, E.New("missing outbound registry in context")
	}
	if dnsTransportRegistry == nil {
		return nil, E.New("missing DNS transport registry in context")
	}
	if serviceRegistry == nil {
		return nil, E.New("missing service registry in context")
	}
	if certificateProviderRegistry == nil {
		return nil, E.New("missing certificate provider registry in context")
	}

	ctx = pause.WithDefaultManager(ctx)
	// The power governor is the single authority for how much background work is allowed while the
	// device is asleep. It is registered as a service so a subsystem asks it rather than deriving a
	// sleep policy of its own, and it is driven from the platform's own lifecycle rather than from a
	// timer: see common/power.
	powerGovernor := power.NewGovernor(power.DefaultPolicy())
	service.MustRegister[*power.Governor](ctx, powerGovernor)
	pauseManager := service.FromContext[pause.Manager](ctx)
	pauseCallback := pauseManager.RegisterCallback(func(event int) {
		applyPauseEvent(powerGovernor, event)
	})
	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	debugOptions := common.PtrValueOrDefault(experimentalOptions.Debug)
	err := checkDebugOptions(debugOptions)
	if err != nil {
		return nil, err
	}
	var needCacheFile bool
	var needV2RayAPI bool
	var needClashAPI bool
	if experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled || options.PlatformLogWriter != nil {
		needCacheFile = true
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		needV2RayAPI = true
	}
	if experimentalOptions.ClashAPI != nil {
		needClashAPI = true
	}
	needAPIService := common.Any(options.Services, func(it option.Service) bool {
		return it.Type == C.TypeAPI
	})
	ctx, ownedURLTestHistory := ensureURLTestServices(ctx)
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	var defaultLogWriter io.Writer
	if platformInterface != nil {
		defaultLogWriter = io.Discard
	}
	logFactory, err := log.New(log.Options{
		Context: ctx,
		Options: common.PtrValueOrDefault(options.Log),
		// Either control plane needs an observable log factory: the Native API's
		// SubscribeLog consumes it, and the Clash API's external_controller is what
		// serves /logs. Neither may be dropped for the other - a build with both
		// gets one factory serving both.
		Observable: needAPIService ||
			(needClashAPI && experimentalOptions.ClashAPI.ExternalController != ""),
		DefaultWriter:  defaultLogWriter,
		BaseTime:       createdAt,
		PlatformWriter: options.PlatformLogWriter,
	})
	if err != nil {
		return nil, E.Cause(err, "create log factory")
	}
	service.MustRegister[log.Factory](ctx, logFactory)

	// Let URLTest report the two phases of a measurement. This is diagnostics only and runs
	// once per measurement, never on a packet path.

	var internalServices []adapter.LifecycleService
	routeOptions := common.PtrValueOrDefault(options.Route)
	certificateOptions := common.PtrValueOrDefault(options.Certificate)
	if C.IsAndroid || certificateOptions.Store != "" && certificateOptions.Store != C.CertificateStoreSystem ||
		len(certificateOptions.Certificate) > 0 ||
		len(certificateOptions.CertificatePath) > 0 ||
		len(certificateOptions.CertificateDirectoryPath) > 0 {
		certificateStore, err := certificate.NewStore(ctx, logFactory.NewLogger("certificate"), certificateOptions)
		if err != nil {
			return nil, err
		}
		service.MustRegister[adapter.CertificateStore](ctx, certificateStore)
		internalServices = append(internalServices, certificateStore)
	}
	netnsManager, err := netns.NewManager(logFactory.NewLogger("netns"), options.NetworkNamespaces, options.NetworkNamespaceHolderArgs)
	if err != nil {
		return nil, err
	}
	service.MustRegister[adapter.NetworkNamespaceManager](ctx, netnsManager)
	internalServices = append(internalServices, netnsManager)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	endpointManager := endpoint.NewManager(endpointRegistry)
	inboundManager := inbound.NewManager(inboundRegistry, endpointManager)
	outboundManager := outbound.NewManager(outboundRegistry, endpointManager, routeOptions.Final)
	dnsTransportManager := dns.NewTransportManager(dnsTransportRegistry, outboundManager, dnsOptions.Final)
	serviceManager := boxService.NewManager(serviceRegistry)
	certificateProviderManager := boxCertificate.NewManager(certificateProviderRegistry)
	service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
	service.MustRegister[adapter.InboundManager](ctx, inboundManager)
	service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportManager)
	service.MustRegister[adapter.ServiceManager](ctx, serviceManager)
	service.MustRegister[adapter.CertificateProviderManager](ctx, certificateProviderManager)
	dnsRouter, err := dns.NewRouter(ctx, logFactory, dnsOptions)
	if err != nil {
		return nil, E.Cause(err, "initialize DNS router")
	}
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, dnsRouter)
	connectionManager := route.NewConnectionManager(logFactory.NewLogger("connection"))
	// The fork's upload scheduler. Absent - the overwhelmingly common case - leaves it inert, so a
	// configuration that does not mention it behaves exactly as it did before the field existed.
	if trafficScheduler := routeOptions.TrafficScheduler; trafficScheduler != nil {
		connectionManager.SetUploadRate(trafficScheduler.UploadRate.Build())
	}
	service.MustRegister[adapter.ConnectionManager](ctx, connectionManager)
	networkManager, err := route.NewNetworkManager(ctx, logFactory.NewLogger("network"), routeOptions, dnsOptions)
	if err != nil {
		return nil, E.Cause(err, "initialize network manager")
	}
	service.MustRegister[adapter.NetworkManager](ctx, networkManager)
	// Must register after ConnectionManager: the Apple HTTP engine's proxy bridge reads it from the context when Manager.Start resolves the default client.
	httpClientManager := httpclient.NewManager(ctx, logFactory.NewLogger("httpclient"), options.HTTPClients, routeOptions.DefaultHTTPClient)
	service.MustRegister[adapter.HTTPClientManager](ctx, httpClientManager)
	httpClientService := adapter.LifecycleService(httpClientManager)
	router := route.NewRouter(ctx, logFactory, routeOptions, dnsOptions)
	service.MustRegister[adapter.Router](ctx, router)
	err = router.Initialize(routeOptions.Rules, routeOptions.RuleSet)
	if err != nil {
		return nil, E.Cause(err, "initialize router")
	}
	// ONE shared traffic manager and ONE shared mode manager, created if any consumer
	// needs them: the Clash API (traffic + mode endpoints), the Native API
	// (SubscribeConnections, SetClashMode) or the platform log writer. Creating a
	// second pair for the second control plane would mean two managers observing
	// different state.
	if needClashAPI || needAPIService || options.PlatformLogWriter != nil {
		trafficManager := trafficcontrol.NewManager()
		service.MustRegisterPtr(ctx, trafficManager)
		router.AppendTracker(trafficManager)
		internalServices = append(internalServices, trafficManager)
		// The routing mode is shared state: the Clash API serves it, and the Native
		// API's SetClashMode drives it. When the Clash API is configured its
		// default_mode seeds the manager; otherwise the mode list is derived from the
		// route rules (CalculateModeList) and no default is imposed.
		var clashDefaultMode string
		if needClashAPI {
			clashDefaultMode = experimentalOptions.ClashAPI.DefaultMode
		}
		clashMode := clashmode.NewManager(ctx, logFactory.NewLogger("clash-mode"), clashDefaultMode, clashmode.CalculateModeList(options.Options))
		service.MustRegisterPtr(ctx, clashMode)
		internalServices = append(internalServices, clashMode)
	}
	referenceManager := route.NewReferenceManager(ctx, logFactory.NewLogger("reference"), options.Options)
	internalServices = append(internalServices, referenceManager)
	ntpOptions := common.PtrValueOrDefault(options.NTP)
	var timeService *tls.TimeServiceWrapper
	if ntpOptions.Enabled {
		timeService = new(tls.TimeServiceWrapper)
		service.MustRegister[ntp.TimeService](ctx, timeService)
	}
	for i, transportOptions := range dnsOptions.Servers {
		var tag string
		if transportOptions.Tag != "" {
			tag = transportOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = dnsTransportManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("dns/", transportOptions.Type, "[", tag, "]")),
			tag,
			transportOptions.Type,
			transportOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize DNS server[", i, "]")
		}
	}
	err = dnsRouter.Initialize(dnsOptions.Rules)
	if err != nil {
		return nil, E.Cause(err, "initialize dns router")
	}
	for i, endpointOptions := range options.Endpoints {
		var tag string
		if endpointOptions.Tag != "" {
			tag = endpointOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		endpointCtx := ctx
		if tag != "" {
			// TODO: remove this
			endpointCtx = adapter.WithContext(endpointCtx, &adapter.InboundContext{
				Outbound: tag,
			})
		}
		err = endpointManager.Create(
			endpointCtx,
			router,
			logFactory.NewLogger(F.ToString("endpoint/", endpointOptions.Type, "[", tag, "]")),
			tag,
			endpointOptions.Type,
			endpointOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize endpoint[", i, "]")
		}
	}
	for i, inboundOptions := range options.Inbounds {
		var tag string
		if inboundOptions.Tag != "" {
			tag = inboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = inboundManager.Create(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("inbound/", inboundOptions.Type, "[", tag, "]")),
			tag,
			inboundOptions.Type,
			inboundOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize inbound[", i, "]")
		}
	}
	for i, serviceOptions := range options.Services {
		var tag string
		if serviceOptions.Tag != "" {
			tag = serviceOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = serviceManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("service/", serviceOptions.Type, "[", tag, "]")),
			tag,
			serviceOptions.Type,
			serviceOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize service[", i, "]")
		}
	}
	for i, outboundOptions := range options.Outbounds {
		var tag string
		if outboundOptions.Tag != "" {
			tag = outboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		// Refuse a tag already used by an ENDPOINT.
		//
		// Endpoints and outbounds are separate namespaces, but a lookup resolves an outbound first
		// and only falls back to an endpoint when no outbound matches, and the API lists both
		// collections. A tag used in both therefore creates two objects, shows the tag twice to a
		// client, and makes the endpoint permanently unreachable and unmeasurable - the
		// configuration appears to have an endpoint that silently does not exist.
		//
		// Endpoints are created before outbounds above, so the collision is detectable here.
		if _, endpointCollision := endpointManager.Get(tag); endpointCollision {
			return nil, E.New("outbound ", tag, " conflicts with an endpoint of the same tag")
		}
		outboundCtx := ctx
		if tag != "" {
			// TODO: remove this
			outboundCtx = adapter.WithContext(outboundCtx, &adapter.InboundContext{
				Outbound: tag,
			})
		}
		err = outboundManager.Create(
			outboundCtx,
			router,
			logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
			tag,
			outboundOptions.Type,
			outboundOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize outbound[", i, "]")
		}
	}

	// Collect the explicit traffic classes before any flow is routed.
	//
	// The class is declared on the outbound envelope, where every outbound type shares it, so it is
	// gathered here into a tag-keyed map rather than pushed into each outbound object. See
	// route.TrafficClassPolicies for why the object itself must not carry it.
	//
	// Only outbounds that explicitly state a class appear. A configuration that never uses the
	// field produces an empty map, and classification then rests entirely on tag matching - which
	// is the mode a stock configuration runs in.
	trafficClassPolicies := make(route.TrafficClassPolicies)
	for i, outboundOptions := range options.Outbounds {
		if outboundOptions.TrafficClass == nil {
			continue
		}
		tag := outboundOptions.Tag
		if tag == "" {
			// Mirrors the fallback used when the outbound was created above, so a tagless entry
			// resolves to the same name the router will see.
			tag = F.ToString(i)
		}
		trafficClassPolicies[tag] = *outboundOptions.TrafficClass
	}
	router.SetTrafficClassPolicies(trafficClassPolicies)
	for i, certificateProviderOptions := range options.CertificateProviders {
		var tag string
		if certificateProviderOptions.Tag != "" {
			tag = certificateProviderOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = certificateProviderManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("certificate-provider/", certificateProviderOptions.Type, "[", tag, "]")),
			tag,
			certificateProviderOptions.Type,
			certificateProviderOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize certificate provider[", i, "]")
		}
	}
	outboundManager.Initialize(func() (adapter.Outbound, error) {
		return direct.NewOutbound(
			ctx,
			router,
			logFactory.NewLogger("outbound/direct"),
			"direct",
			option.DirectOutboundOptions{},
		)
	})
	dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
		return dnsTransportRegistry.CreateDNSTransport(
			ctx,
			logFactory.NewLogger("dns/local"),
			"local",
			C.DNSTypeLocal,
			&option.LocalDNSServerOptions{},
		)
	})
	httpClientManager.Initialize(func() (*httpclient.ManagedTransport, error) {
		deprecated.Report(ctx, deprecated.OptionImplicitDefaultHTTPClient)
		var httpClientOptions option.HTTPClientOptions
		httpClientOptions.DefaultOutbound = true
		return httpclient.NewTransport(ctx, logFactory.NewLogger("httpclient"), "", httpClientOptions)
	})
	if platformInterface != nil {
		err = platformInterface.Initialize(networkManager)
		if err != nil {
			return nil, E.Cause(err, "initialize platform interface")
		}
	}
	if needCacheFile {
		cacheFile := cachefile.New(ctx, logFactory.NewLogger("cache-file"), common.PtrValueOrDefault(experimentalOptions.CacheFile))
		service.MustRegister[adapter.CacheFile](ctx, cacheFile)
		internalServices = append(internalServices, cacheFile)
	}
	if needClashAPI {
		clashServer, err := experimental.NewClashServer(ctx, logFactory.(log.ObservableFactory), common.PtrValueOrDefault(experimentalOptions.ClashAPI))
		if err != nil {
			return nil, E.Cause(err, "create clash-server")
		}
		internalServices = append(internalServices, clashServer)
	}
	if needV2RayAPI {
		v2rayServer, err := experimental.NewV2RayServer(logFactory.NewLogger("v2ray-api"), common.PtrValueOrDefault(experimentalOptions.V2RayAPI))
		if err != nil {
			return nil, E.Cause(err, "create v2ray-server")
		}
		if v2rayServer.StatsService() != nil {
			router.AppendTracker(v2rayServer.StatsService())
			internalServices = append(internalServices, v2rayServer)
			service.MustRegister[adapter.V2RayServer](ctx, v2rayServer)
		}
	}
	var ntpService *ntp.Service
	if ntpOptions.Enabled {
		if ntpOptions.WriteToSystem {
			err = adapter.CheckSecurityFeature(ctx, "NTP `write_to_system`")
			if err != nil {
				return nil, err
			}
		}
		ntpDialer, err := dialer.New(ctx, ntpOptions.DialerOptions, ntpOptions.ServerIsDomain())
		if err != nil {
			return nil, E.Cause(err, "create NTP service")
		}
		ntpService = ntp.NewService(ntp.Options{
			Context:       ctx,
			Dialer:        ntpDialer,
			Logger:        logFactory.NewLogger("ntp"),
			Server:        ntpOptions.ServerOptions.Build(),
			Interval:      time.Duration(ntpOptions.Interval),
			WriteToSystem: ntpOptions.WriteToSystem,
		})
		timeService.TimeService = ntpService
	}
	box := &Box{
		ctx:                 ctx,
		ownedURLTestHistory: ownedURLTestHistory,
		network:             networkManager,
		endpoint:            endpointManager,
		inbound:             inboundManager,
		outbound:            outboundManager,
		dnsTransport:        dnsTransportManager,
		service:             serviceManager,
		certificateProvider: certificateProviderManager,
		dnsRouter:           dnsRouter,
		connection:          connectionManager,
		router:              router,
		referenceManager:    referenceManager,
		httpClientService:   httpClientService,
		createdAt:           createdAt,
		powerGovernor:       powerGovernor,
		pauseManager:        pauseManager,
		pauseCallback:       pauseCallback,
		debugOptions:        debugOptions,
		logFactory:          logFactory,
		logger:              logFactory.Logger(),
		internalService:     internalServices,
		ntpService:          ntpService,
		scope:               adapter.NewScope(ctx, logFactory.Logger()),
	}

	// Releasing reusable connections is deferred to DEEP_IDLE rather than done the moment the screen
	// goes off, and that timing is the whole point.
	//
	// The Apple client used to call CloseIdleConnections() from pause(), which is the shape the brief
	// names as a trap: it looks like a saving, and it turns every unlock into a pile of DNS, TLS and
	// QUIC handshakes at exactly the moment the user wants a request answered. What the pool is worth
	// depends on how long the device stays asleep - a screen that goes off for a minute should cost
	// nothing, and a phone left in a pocket for an afternoon should not hold sockets it will not use.
	// DEEP_IDLE is precisely that distinction: the device has been paused, and no real traffic has
	// moved, for Policy.DeepIdleAfter.
	//
	// Business connections are untouched at every state. The governor closes nothing itself; it
	// reports, and this is the one place that reacts by releasing only what exists to be reused.
	powerGovernor.AddObserver(func(state power.State) {
		if state != power.StateDeepIdle {
			return
		}
		box.CloseIdleConnections()
	})

	return box, nil
}

func (s *Box) PreStart() error {
	err := s.preStart()
	if err != nil {
		s.Close()
		return err
	}
	s.logger.Info("sing-box pre-started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) Start() error {
	err := s.start()
	if err != nil {
		s.Close()
		return err
	}
	s.logger.Info("sing-box started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

type boxComponent struct {
	name      string
	lifecycle adapter.Lifecycle
}

func (s *Box) startComponents(stage adapter.StartStage, components ...boxComponent) error {
	for _, component := range components {
		err := s.scope.Start(component.name, component.lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Box) startInternalServices(stage adapter.StartStage) error {
	for _, lifecycleService := range s.internalService {
		err := s.scope.Start(lifecycleService.Name(), lifecycleService, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Box) preStart() error {
	monitor := taskmonitor.New(s.logger, C.StartTimeout)
	monitor.Start("start logger")
	err := s.logFactory.Start()
	monitor.Finish()
	if err != nil {
		return E.Cause(err, "start logger")
	}
	s.scope.Add(s.logFactory.Close)
	// Close the URL-test storage THIS Box created, and only that one.
	//
	// Putting it on the context does not make it part of the lifecycle: without a cleanup a
	// standalone Box left the storage live after Close, with its closed flag unset, its maps
	// retained and late writers still accepted - so a measurement that finished after teardown
	// could write into a Box that no longer existed. A storage the CALLER supplied is not touched,
	// because the Box does not own it and the daemon closes its own.
	if s.ownedURLTestHistory != nil {
		ownedURLTestHistory := s.ownedURLTestHistory
		s.scope.Add(func() error {
			s.ownedURLTestHistory = nil
			return ownedURLTestHistory.Close()
		})
	}
	applyDebugOptions(s.debugOptions)
	debugHTTPServer, err := startDebugHTTPServer(s.debugOptions)
	if err != nil {
		return err
	}
	if debugHTTPServer != nil {
		s.scope.Add(debugHTTPServer.Close)
	}
	err = s.startInternalServices(adapter.StartStateInitialize) // cache-file clash-api v2ray-api
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateInitialize,
		boxComponent{s.httpClientService.Name(), s.httpClientService},
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"outbound", s.outbound},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateStart,
		boxComponent{"outbound", s.outbound},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"network", s.network},
		boxComponent{"connection", s.connection},
		boxComponent{s.httpClientService.Name(), s.httpClientService},
		boxComponent{"router", s.router},
		boxComponent{"dns-router", s.dnsRouter},
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *Box) start() error {
	err := s.preStart()
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStateStart)
	if err != nil {
		return err
	}
	if s.ntpService != nil {
		done := adapter.LogElapsed(s.logger, "start ntp service")
		err = s.ntpService.Start()
		done()
		if err != nil {
			return E.Cause(err, "start ntp service")
		}
		s.scope.Add(s.ntpService.Close)
	}
	err = s.startComponents(adapter.StartStateStart,
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStatePostStart,
		boxComponent{"outbound", s.outbound},
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStatePostStart)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateStarted,
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"outbound", s.outbound},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStateStarted)
	if err != nil {
		return err
	}
	return nil
}

func (s *Box) Close() error {
	// The governor is closed first and its callback unregistered, so no lifecycle event can arrive
	// while the scope is tearing down components that would have asked it what to do.
	if s.pauseManager != nil && s.pauseCallback != nil {
		s.pauseManager.UnregisterCallback(s.pauseCallback)
		s.pauseCallback = nil
	}
	if s.powerGovernor != nil {
		s.powerGovernor.Close()
		s.powerGovernor = nil
	}
	// The scope owns teardown. Every component registered through scope.Start, and everything that
	// added itself through scope.Add, is closed here in reverse registration order - which is the
	// ordering the old hand-written close list was trying to express.
	return s.scope.Close()
}

func (s *Box) Network() adapter.NetworkManager {
	return s.network
}

func (s *Box) Router() adapter.Router {
	return s.router
}

func (s *Box) Inbound() adapter.InboundManager {
	return s.inbound
}

func (s *Box) Outbound() adapter.OutboundManager {
	return s.outbound
}

func (s *Box) Endpoint() adapter.EndpointManager {
	return s.endpoint
}

func (s *Box) CreatedAt() time.Time {
	return s.createdAt
}

func (s *Box) CloseIdleConnections() {
	s.referenceManager.CloseIdleConnections()
}

func (s *Box) LogFactory() log.Factory {
	return s.logFactory
}
