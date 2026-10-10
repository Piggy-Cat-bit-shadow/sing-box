package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ranges"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"go4.org/netipx"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TunInboundOptions](registry, C.TypeTun, NewInbound)
}

type Inbound struct {
	tag              string
	ctx              context.Context
	router           adapter.Router
	networkManager   adapter.NetworkManager
	logger           log.ContextLogger
	tunOptions       tun.Options
	udpTimeout       time.Duration
	udpMapping       tun.NATMapping
	udpFiltering     tun.NATFiltering
	udpNATMax        uint32
	dnsHijackAddress []netip.Addr
	dnsHijackByPort  bool
	// fakeIPStore is the configured FakeIP address space, or nil when no FakeIP transport exists.
	//
	// The route-set bypass below hands a destination to the platform's routing table, which is
	// correct for a real address and meaningless for a synthetic one. This is how JudgeFlow knows
	// the difference without asking the router, which the route sets exist to avoid.
	fakeIPStore                 adapter.FakeIPStore
	stack                       string
	tunIf                       tun.Tun
	tunStack                    tun.Stack
	platformInterface           adapter.PlatformInterface
	platformOptions             option.TunPlatformOptions
	autoRedirect                tun.AutoRedirect
	routeRuleSet                []adapter.RuleSet
	routeRuleSetCallback        []*list.Element[adapter.RuleSetUpdateCallback]
	routeExcludeRuleSet         []adapter.RuleSet
	routeExcludeRuleSetCallback []*list.Element[adapter.RuleSetUpdateCallback]
	routeAddressSetAccess       sync.RWMutex
	routeAddressSet             []*netipx.IPSet
	routeExcludeAddressSet      []*netipx.IPSet
	// routeRuleSetRefs records one entry per reference Start successfully took on a rule-set, in
	// acquisition order. It is guarded by routeAddressSetAccess.
	//
	// A rule-set counts its references by hand: IncRef keeps its parsed rules alive across an
	// update, and a rule-set only drops them once the count is back to zero. The entries are a
	// slice rather than a set on purpose - the same rule-set may be configured as both a route and
	// a route-exclude set, and each acquisition needs its own release.
	routeRuleSetRefs []adapter.RuleSet
	// autoRedirectOutputMark is the mark this inbound claimed from the network manager, and
	// autoRedirectOutputMarkClaimed records that it holds a claim. The claim is a resource of the
	// manager rather than of the tun stack, so it is handed back from Close: the one path that
	// discards an inbound without ever starting it is adapter/inbound.Manager.Create's duplicate-tag
	// loser, which closes what the constructor built, and a mark left behind there is applied to every
	// dial the surviving box makes.
	//
	// It is an ATOMIC bool rather than a plain one because Close is reachable concurrently - the
	// Scope's cleanup drain and the manager's duplicate-tag loser are two independent callers - and
	// the release must happen exactly once. `if claimed { claimed = false; release() }` is not that:
	// two concurrent Closes can both read true, both release, and the second release is the one that
	// can hand back a claim a NEW owner has since taken. CompareAndSwap makes the flag the
	// exactly-once token, so exactly one caller reaches the releaser and the loser does nothing.
	autoRedirectOutputMarkClaimed atomic.Bool
	autoRedirectOutputMark        uint32
	// testCloseObserver, when set, runs at the start of Close.
	//
	// It exists so a test can observe that a Close really happened to a particular inbound - the
	// duplicate-tag loser is closed by adapter/inbound/manager.go and nothing else announces it. Nil in
	// production.
	testCloseObserver func()
	// The two objects StartStatePostStart ACTIVATES are owned through a startupGate, because
	// Scope.Close does not wait for a Start that is already running: the Scope's release of them can
	// run while that activation is in flight, and NativeTun.Start programmes the platform routing
	// table with no closed check of its own.
	stackStartup     startupGate
	interfaceStartup startupGate
}

// autoRedirectMarkReleaser is the release half of the claim protocol, implemented by
// route.NetworkManager.
//
// It is asserted rather than declared in adapter.NetworkManager on purpose: the claim is held by the
// single implementation that owns the mark, and widening the interface would oblige every other
// implementation - the platform ones included - to carry a method for a resource they never take. An
// implementation that grants claims through RegisterAutoRedirectOutputMark has to provide this method
// as well; one that never grants a claim never needs it, and the assertion is silent.
type autoRedirectMarkReleaser interface {
	ReleaseAutoRedirectOutputMark(mark uint32)
}

// startupGate owns one resource whose activation in StartStatePostStart can run concurrently with
// the Scope's release of it.
//
// The two must not be allowed to interleave, and the Scope must not be made to wait for the Start:
// nothing bounds how long a component's Start may take, so Close waits only for the cleanup drain it
// already joined. The handoff therefore goes to whichever side is not already busy - the Scope's
// cleanup releases the resource directly, or, when an activation is in flight, the activation
// releases it as soon as the platform call returns. `once` is what makes that exactly-once even when
// both sides reach for it, which matters because closing an already closed interface fd is not
// something the platform layer has to tolerate.
type startupGate struct {
	access     sync.Mutex
	closing    bool
	activating bool
	once       *sync.Once
	release    func() error
	releaseErr error
}

// acquire arms the gate for one lifecycle: it records what that lifecycle releases and installs a
// fresh exactly-once guard. A start that failed and was rolled back can be retried on a new Scope
// with a new interface, and the previous lifecycle's guard would otherwise already be spent.
func (g *startupGate) acquire(release func() error) {
	g.access.Lock()
	defer g.access.Unlock()
	g.release = release
	g.once = new(sync.Once)
	g.releaseErr = nil
	g.closing = false
	g.activating = false
}

// activate starts the owned resource, or refuses when the Scope has already claimed the release.
func (g *startupGate) activate(start func() error) error {
	g.access.Lock()
	if g.closing {
		// Nothing is activated here: the resource has already been released, and a start that ran
		// anyway would add routes that no cleanup is left to remove.
		g.access.Unlock()
		return E.Cause(os.ErrClosed, "tun inbound is closed")
	}
	g.activating = true
	g.access.Unlock()
	err := start()
	g.access.Lock()
	g.activating = false
	releaseNow := g.closing
	g.access.Unlock()
	if !releaseNow {
		return err
	}
	// The Scope ran this resource's cleanup while the activation was in flight; it left the release
	// here rather than closing an object that was being started. The activation is reported as
	// failed: it ran, but the owner that would have kept it is gone.
	return E.Errors(
		E.Cause(os.ErrClosed, "tun inbound is closed while starting"),
		err,
		g.releaseOnce(),
	)
}

// bind records what this gate releases, if nothing has recorded it yet.
//
// StartStateStart binds each gate at the acquisition. Inbound.Close can be reached before that - the
// duplicate-tag loser in adapter/inbound/manager.go, or a caller that assembled the inbound around
// an already-started stack - and it must still release whatever the fields hold.
func (g *startupGate) bind(release func() error) {
	g.access.Lock()
	defer g.access.Unlock()
	if g.release == nil {
		g.release = release
	}
	if g.once == nil {
		g.once = new(sync.Once)
	}
}

// releaseByScope is the cleanup handed to the Scope, and the path Inbound.Close uses.
//
// It never waits for an in-flight activation: it records the decision and, if the activation owns
// the release, returns without releasing anything. The resource is then released by
// [startupGate.activate] the moment its platform call returns, so the exposure is bounded by that
// call alone.
func (g *startupGate) releaseByScope() error {
	g.access.Lock()
	g.closing = true
	if g.activating {
		g.access.Unlock()
		return nil
	}
	g.access.Unlock()
	return g.releaseOnce()
}

// releaseOnce performs the release at most once across every path that can reach it.
func (g *startupGate) releaseOnce() error {
	g.access.Lock()
	once := g.once
	release := g.release
	g.access.Unlock()
	if once == nil || release == nil {
		// Nothing was ever registered on this gate: Inbound.Close can be reached before Start.
		return nil
	}
	once.Do(func() { g.releaseErr = release() })
	g.access.Lock()
	defer g.access.Unlock()
	return g.releaseErr
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
	//nolint:staticcheck
	if len(options.Inet4Address) > 0 || len(options.Inet6Address) > 0 ||
		len(options.Inet4RouteAddress) > 0 || len(options.Inet6RouteAddress) > 0 ||
		len(options.Inet4RouteExcludeAddress) > 0 || len(options.Inet6RouteExcludeAddress) > 0 {
		return nil, E.New("legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0")
	}
	//nolint:staticcheck
	if options.GSO {
		return nil, E.New("GSO option in tun is deprecated in sing-box 1.11.0 and removed in sing-box 1.12.0")
	}
	//nolint:staticcheck
	if options.InboundOptions != (option.InboundOptions{}) {
		return nil, E.New("legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions")
	}
	if options.Stack != "" {
		deprecated.Report(ctx, deprecated.OptionTunStack)
	}

	address := options.Address
	inet4Address := common.Filter(address, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6Address := common.Filter(address, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	routeAddress := options.RouteAddress
	inet4RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	routeExcludeAddress := options.RouteExcludeAddress
	inet4RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	usePlatformInterface := platformInterface != nil && platformInterface.UsePlatformInterface()
	if options.NetNs != "" && !C.IsLinux {
		return nil, E.New("`netns` is only supported on Linux")
	}
	tunMTU := options.MTU
	if tunMTU == 0 {
		if platformInterface != nil && platformInterface.UnderNetworkExtension() {
			// In Network Extension, when MTU exceeds 4064 (4096-UTUN_IF_HEADROOM_SIZE), the performance of tun will drop significantly, which may be a system bug.
			tunMTU = 4064
		} else if C.IsAndroid {
			// Some Android devices report ENOBUFS when using MTU 65535
			tunMTU = 9000
		} else {
			tunMTU = 65535
		}
	}
	var enableGSO bool
	if C.IsLinux && !usePlatformInterface {
		switch options.Stack {
		case "", "go", "gvisor":
			enableGSO = tunMTU < 49152
		}
	}
	if options.MultiQueue {
		if !C.IsLinux || usePlatformInterface {
			return nil, E.New("`multi_queue` is only supported on Linux")
		}
		switch options.Stack {
		case "", "go":
		default:
			return nil, E.New("`multi_queue` is only supported by the `go` stack")
		}
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var err error
	includeUID := uidToRange(options.IncludeUID)
	if len(options.IncludeUIDRange) > 0 {
		includeUID, err = parseRange(includeUID, options.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(options.ExcludeUID)
	if len(options.ExcludeUIDRange) > 0 {
		excludeUID, err = parseRange(excludeUID, options.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	tableIndex := options.IPRoute2TableIndex
	if tableIndex == 0 {
		tableIndex = tun.DefaultIPRoute2TableIndex
	}
	ruleIndex := options.IPRoute2RuleIndex
	if ruleIndex == 0 {
		ruleIndex = tun.DefaultIPRoute2RuleIndex
	}
	autoRedirectFallbackRuleIndex := options.AutoRedirectFallbackRuleIndex
	if autoRedirectFallbackRuleIndex == 0 {
		autoRedirectFallbackRuleIndex = tun.DefaultIPRoute2AutoRedirectFallbackRuleIndex
	}
	nfQueue := options.AutoRedirectNFQueue
	if nfQueue == 0 {
		nfQueue = tun.DefaultAutoRedirectNFQueue
	}
	var includeMACAddress []net.HardwareAddr
	for i, macString := range options.IncludeMACAddress {
		mac, macErr := net.ParseMAC(macString)
		if macErr != nil {
			return nil, E.Cause(macErr, "parse include_mac_address[", i, "]")
		}
		includeMACAddress = append(includeMACAddress, mac)
	}
	var excludeMACAddress []net.HardwareAddr
	for i, macString := range options.ExcludeMACAddress {
		mac, macErr := net.ParseMAC(macString)
		if macErr != nil {
			return nil, E.Cause(macErr, "parse exclude_mac_address[", i, "]")
		}
		excludeMACAddress = append(excludeMACAddress, mac)
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	inbound := &Inbound{
		tag:            tag,
		ctx:            ctx,
		router:         router,
		networkManager: networkManager,
		logger:         logger,
		tunOptions: tun.Options{
			Name:                                  options.InterfaceName,
			NetNs:                                 options.NetNs,
			MTU:                                   tunMTU,
			GSO:                                   enableGSO,
			MultiQueue:                            options.MultiQueue,
			Inet4Address:                          inet4Address,
			Inet6Address:                          inet6Address,
			DNSMode:                               options.DNSMode,
			DNSAddress:                            options.DNSAddress,
			AutoRoute:                             options.AutoRoute,
			IPRoute2TableIndex:                    tableIndex,
			IPRoute2RuleIndex:                     ruleIndex,
			IPRoute2AutoRedirectFallbackRuleIndex: autoRedirectFallbackRuleIndex,
			AutoRedirectInputMark:                 uint32(options.AutoRedirectInputMark),
			AutoRedirectOutputMark:                uint32(options.AutoRedirectOutputMark),
			AutoRedirectResetMark:                 uint32(options.AutoRedirectResetMark),
			AutoRedirectTProxyMark:                uint32(options.AutoRedirectTProxyMark),
			AutoRedirectNFQueue:                   nfQueue,
			ExcludeMPTCP:                          options.ExcludeMPTCP,
			Inet4LoopbackAddress:                  common.Filter(options.LoopbackAddress, netip.Addr.Is4),
			Inet6LoopbackAddress:                  common.Filter(options.LoopbackAddress, netip.Addr.Is6),
			StrictRoute:                           options.StrictRoute,
			IncludeInterface:                      options.IncludeInterface,
			ExcludeInterface:                      options.ExcludeInterface,
			Inet4RouteAddress:                     inet4RouteAddress,
			Inet6RouteAddress:                     inet6RouteAddress,
			Inet4RouteExcludeAddress:              inet4RouteExcludeAddress,
			Inet6RouteExcludeAddress:              inet6RouteExcludeAddress,
			IncludeUID:                            includeUID,
			ExcludeUID:                            excludeUID,
			IncludeAndroidUser:                    options.IncludeAndroidUser,
			IncludePackage:                        options.IncludePackage,
			ExcludePackage:                        options.ExcludePackage,
			IncludeMACAddress:                     includeMACAddress,
			ExcludeMACAddress:                     excludeMACAddress,
			InterfaceMonitor:                      networkManager.InterfaceMonitor(),
			Logger:                                logger,
			EXP_MultiPendingPackets:               C.IsDarwin,
		},
		udpTimeout:        udpTimeout,
		udpMapping:        tun.NATMapping(options.UDPMapping),
		udpFiltering:      tun.NATFiltering(options.UDPFiltering),
		udpNATMax:         options.UDPNATMax,
		stack:             options.Stack,
		platformInterface: platformInterface,
		platformOptions:   common.PtrValueOrDefault(options.Platform),
	}
	for _, routeAddressSet := range options.RouteAddressSet {
		ruleSet, loaded := router.RuleSet(routeAddressSet)
		if !loaded {
			return nil, E.New("parse route_address_set: rule-set not found: ", routeAddressSet)
		}
		inbound.routeRuleSet = append(inbound.routeRuleSet, ruleSet)
	}
	for _, routeExcludeAddressSet := range options.RouteExcludeAddressSet {
		ruleSet, loaded := router.RuleSet(routeExcludeAddressSet)
		if !loaded {
			return nil, E.New("parse route_exclude_address_set: rule-set not found: ", routeExcludeAddressSet)
		}
		inbound.routeExcludeRuleSet = append(inbound.routeExcludeRuleSet, ruleSet)
	}
	if options.AutoRedirect {
		if !options.AutoRoute {
			return nil, E.New("`auto_route` is required by `auto_redirect`")
		}
		inbound.tunOptions.AutoRedirectMarkMode = true
		usePlatformAutoRedirect := platformInterface != nil && platformInterface.UsePlatformAutoRedirect()
		if usePlatformAutoRedirect {
			inbound.autoRedirect, err = newPlatformAutoRedirect(inbound)
		} else {
			disableNFTables, parseErr := strconv.ParseBool(os.Getenv("DISABLE_NFTABLES"))
			inbound.autoRedirect, err = tun.NewAutoRedirect(tun.AutoRedirectOptions{
				TunOptions:      &inbound.tunOptions,
				Context:         ctx,
				Handler:         (*autoRedirectHandler)(inbound),
				Logger:          logger,
				NetworkMonitor:  networkManager.NetworkMonitor(),
				InterfaceFinder: networkManager.InterfaceFinder(),
				TableName:       "sing-box",
				DisableNFTables: parseErr == nil && disableNFTables,
			})
		}
		if err != nil {
			return nil, E.Cause(err, "initialize auto-redirect")
		}
		inbound.dnsHijackByPort = inbound.tunOptions.DNSModeOrDefault() == tun.DNSModeHijack
		if !usePlatformAutoRedirect && options.NetNs == "" {
			mark := inbound.tunOptions.AutoRedirectOutputMarkOrDefault()
			err = networkManager.RegisterAutoRedirectOutputMark(mark)
			if err != nil {
				// The redirect was built before the claim was attempted, and this constructor is
				// returning an error: nobody will ever receive the *Inbound, so nobody will ever call
				// Close on it and nobody else can release what the redirect holds. Without this the
				// already-created redirect - its nftables/iptables rules, its network monitor and its
				// goroutines - outlives the failed construction with no owner at all.
				//
				// The field is cleared so the object being abandoned cannot be closed twice if a
				// caller ever did reach it.
				redirect := inbound.autoRedirect
				inbound.autoRedirect = nil
				return nil, E.Errors(err, common.Close(redirect))
			}
			inbound.autoRedirectOutputMark = mark
			inbound.autoRedirectOutputMarkClaimed.Store(true)
		}
	}
	return inbound, nil
}

func uidToRange(uidList badoption.Listable[uint32]) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (t *Inbound) Type() string {
	return C.TypeTun
}

func (t *Inbound) Tag() string {
	return t.tag
}

// isFlowCapable reports whether a registered component can hand a whole flow to the TUN, which is
// the capability the GSO / multi-pending-packets probe below is looking for.
func isFlowCapable(component any) bool {
	flowOutbound, isFlowOutbound := component.(adapter.FlowOutbound)
	return isFlowOutbound && flowOutbound.PreMatchFlow(N.NetworkTCP, netip.Addr{}) == adapter.PreMatchFlow
}

// setFlowCapability records, on the options the platform interface is built from, that a
// flow-capable component exists. The Linux and Darwin spellings are two names for the same probe.
func (t *Inbound) setFlowCapability() {
	if C.IsLinux {
		t.tunOptions.GSO = true
	} else {
		t.tunOptions.EXP_MultiPendingPackets = true
	}
}

func (t *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if t.tunOptions.DNSModeOrDefault() != tun.DNSModeDisabled && len(t.tunOptions.DNSAddress) == 0 {
			inet4DNSAddress, _ := t.tunOptions.Inet4DNSAddress()
			inet6DNSAddress, _ := t.tunOptions.Inet6DNSAddress()
			t.dnsHijackAddress = append(inet4DNSAddress, inet6DNSAddress...)
		}
		// Transports are constructed before any component starts, so this is the earliest point at
		// which the FakeIP range is known. It is resolved once rather than per flow: the range is
		// fixed for the transport's lifetime, and a per-flow lookup would put a manager call on the
		// path this whole file exists to keep cheap.
		if t.fakeIPStore == nil {
			transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
			if transportManager != nil {
				for _, transport := range transportManager.Transports() {
					if fakeIPTransport, isFakeIP := transport.(adapter.FakeIPTransport); isFakeIP {
						t.fakeIPStore = fakeIPTransport.Store()
						break
					}
				}
			}
		}
	case adapter.StartStateStart:
		if t.platformInterface == nil &&
			((C.IsLinux && !t.tunOptions.GSO) || (C.IsDarwin && !t.tunOptions.EXP_MultiPendingPackets)) {
			// A manager can legitimately be absent from this context, and that is not an error: the
			// probe below asks whether some component can hand a whole flow to the TUN, so a context
			// with no outbound or endpoint registry simply has nothing to ask. Dereferencing the nil
			// crashed Start outright - MEASURED on the race gate as
			//
			//	panic: runtime error: invalid memory address or nil pointer dereference
			//	github.com/sagernet/sing-box/protocol/tun.(*Inbound).Start
			//		protocol/tun/inbound.go:549
			//
			// from a scope that registered neither manager. The Initialize stage above already
			// guards its own manager lookup this way; this stage was the one that did not.
			outboundManager := service.FromContext[adapter.OutboundManager](t.ctx)
			if outboundManager != nil {
				for _, outbound := range outboundManager.Outbounds() {
					if isFlowCapable(outbound) {
						t.setFlowCapability()
						break
					}
				}
			}
			endpointManager := service.FromContext[adapter.EndpointManager](t.ctx)
			if endpointManager != nil {
				for _, endpoint := range endpointManager.Endpoints() {
					if isFlowCapable(endpoint) {
						t.setFlowCapability()
						break
					}
				}
			}
		}
		if C.IsAndroid && t.platformInterface == nil {
			t.tunOptions.BuildAndroidRules(t.networkManager.PackageManager())
		}
		if t.tunOptions.Name == "" {
			t.tunOptions.Name = tun.CalculateInterfaceName("")
		}
		t.tunOptions.BridgeInterface = t.networkManager.BridgeInterfaces()
		if t.tunOptions.NetNs != "" {
			manager := service.FromContext[adapter.NetworkNamespaceManager](t.ctx)
			if manager != nil {
				t.tunOptions.NetNs = manager.ResolvePath(t.tunOptions.NetNs)
			}
		}
		var (
			routeAddressSet        []*netipx.IPSet
			routeExcludeAddressSet []*netipx.IPSet
		)
		if t.autoRedirect != nil || t.platformInterface == nil || C.IsWindows {
			for _, routeRuleSet := range t.routeRuleSet {
				ipSets := routeRuleSet.ExtractIPSet()
				if len(ipSets) == 0 {
					t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeRuleSet.Name())
				}
				t.acquireRouteSetRef(routeRuleSet)
				routeAddressSet = append(routeAddressSet, ipSets...)
			}
			for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
				ipSets := routeExcludeRuleSet.ExtractIPSet()
				if len(ipSets) == 0 {
					t.logger.Warn("route_exclude_address_set: no destination IP CIDR rules found in rule-set: ", routeExcludeRuleSet.Name())
				}
				t.acquireRouteSetRef(routeExcludeRuleSet)
				routeExcludeAddressSet = append(routeExcludeAddressSet, ipSets...)
			}
			if t.autoRedirect != nil {
				t.routeAddressSetAccess.Lock()
				t.routeAddressSet = routeAddressSet
				t.routeExcludeAddressSet = routeExcludeAddressSet
				t.routeAddressSetAccess.Unlock()
				for _, routeRuleSet := range t.routeRuleSet {
					t.routeRuleSetCallback = append(t.routeRuleSetCallback, routeRuleSet.RegisterCallback(t.updateRouteAddressSet))
				}
				for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
					t.routeExcludeRuleSetCallback = append(t.routeExcludeRuleSetCallback, routeExcludeRuleSet.RegisterCallback(t.updateRouteAddressSet))
				}
			}
			// Hand the release to the Scope in the same breath as the acquisition.
			//
			// The product closes a Box by closing its Scope, and Scope.Close() runs the entries
			// handed to it through scope.Add - it never calls a component's Close() method. Storing
			// the elements here and releasing them from Close() left the Scope with no knowledge of
			// a resource Start had acquired, so on a real Box.Close() the callbacks were never
			// unregistered: every rule-set kept an observer pointed at a torn-down inbound for the
			// lifetime of the process.
			//
			// Registering here rather than at the end of the start sequence is deliberate. The
			// acquisition is what needs an owner, and every later step in Start and PostStart can
			// fail; an owner established at the acquisition covers all of those failures with the
			// Box's existing rollback (Box.Start closes the Scope when start() returns an error).
			//
			// It sits OUTSIDE the auto-redirect branch because Start takes the reference whether or
			// not an auto-redirect exists - a plain desktop TUN with route_address_set also reaches
			// this block - and a release registered only when callbacks were registered left those
			// references held for the lifetime of the process, so the rule-set could never drop its
			// rules. The references are the acquisition; the callbacks are a second, optional one.
			scope.Add(t.releaseRouteSetsCleanup)
		}
		var (
			tunInterface tun.Tun
			err          error
		)
		monitor := taskmonitor.New(t.logger, C.StartTimeout)
		tunOptions := t.tunOptions
		if t.autoRedirect == nil && !(runtime.GOOS == "android" && t.platformInterface != nil) {
			for _, ipSet := range routeAddressSet {
				for _, prefix := range ipSet.Prefixes() {
					if prefix.Addr().Is4() {
						tunOptions.Inet4RouteAddress = append(tunOptions.Inet4RouteAddress, prefix)
					} else {
						tunOptions.Inet6RouteAddress = append(tunOptions.Inet6RouteAddress, prefix)
					}
				}
			}
			for _, ipSet := range routeExcludeAddressSet {
				for _, prefix := range ipSet.Prefixes() {
					if prefix.Addr().Is4() {
						tunOptions.Inet4RouteExcludeAddress = append(tunOptions.Inet4RouteExcludeAddress, prefix)
					} else {
						tunOptions.Inet6RouteExcludeAddress = append(tunOptions.Inet6RouteExcludeAddress, prefix)
					}
				}
			}
		}
		monitor.Start("open interface")
		if t.platformInterface != nil && t.platformInterface.UsePlatformInterface() {
			tunInterface, err = t.platformInterface.OpenInterface(&tunOptions, t.platformOptions)
		} else {
			tunInterface, err = tun.New(tunOptions)
		}
		monitor.Finish()
		t.tunOptions.Name = tunOptions.Name
		if err != nil {
			return E.Cause(err, "configure tun interface")
		}
		t.interfaceStartup.acquire(tunInterface.Close)
		scope.Add(t.interfaceStartup.releaseByScope)
		t.logger.Trace("creating stack")
		t.tunIf = tunInterface
		if t.platformInterface != nil {
			err = t.platformInterface.ProcessPlatformOptions(t.platformOptions)
			if err != nil {
				return E.Cause(err, "process platform options")
			}
		}
		var includeAllNetworks bool
		if t.platformInterface != nil && t.platformInterface.UnderNetworkExtension() {
			includeAllNetworks = t.platformInterface.NetworkExtensionIncludeAllNetworks()
		}
		var memoryPressure func() tun.MemoryPressure
		oomKiller := service.FromContext[*oomkiller.Service](t.ctx)
		if oomKiller != nil {
			memoryPressure = oomKiller.MemoryPressure
		}
		tunStack, err := tun.NewStack(t.stack, tun.StackOptions{
			Context:                t.ctx,
			Tun:                    tunInterface,
			TunOptions:             t.tunOptions,
			UDPTimeout:             t.udpTimeout,
			ICMPTimeout:            C.ICMPTimeout,
			UDPMapping:             t.udpMapping,
			UDPFiltering:           t.udpFiltering,
			UDPNATMax:              t.udpNATMax,
			Handler:                t,
			Logger:                 t.logger,
			ForwarderBindInterface: C.IsDarwin,
			InterfaceFinder:        t.networkManager.InterfaceFinder(),
			IncludeAllNetworks:     includeAllNetworks,
			MemoryPressure:         memoryPressure,
		})
		if err != nil {
			return err
		}
		t.stackStartup.acquire(tunStack.Close)
		scope.Add(t.stackStartup.releaseByScope)
		t.tunStack = tunStack
		t.logger.Info("started at ", t.tunOptions.Name)
	case adapter.StartStatePostStart:
		monitor := taskmonitor.New(t.logger, C.StartTimeout)
		monitor.Start("starting tun stack")
		err := t.stackStartup.activate(t.tunStack.Start)
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "starting tun stack")
		}
		monitor.Start("starting tun interface")
		err = t.interfaceStartup.activate(t.tunIf.Start)
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "starting TUN interface")
		}
		if t.autoRedirect != nil {
			// Closing the auto-redirect is the last cleanup registered and therefore the first to run,
			// and it releases the route-set callbacks before it tears anything down. Ordering the
			// release by position alone would put it last (the Scope runs cleanups in reverse
			// registration order) - after this Close - which is exactly the window the release exists
			// to close.
			scope.Add(t.closeAutoRedirect)
			monitor.Start("initialize auto-redirect")
			err = t.autoRedirect.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "auto-redirect")
			}
		}
	}
	return nil
}

func (t *Inbound) updateRouteAddressSet(it adapter.RuleSet) {
	routeAddressSet := common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	routeExcludeAddressSet := common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
	t.routeAddressSetAccess.Lock()
	t.routeAddressSet = routeAddressSet
	t.routeExcludeAddressSet = routeExcludeAddressSet
	t.routeAddressSetAccess.Unlock()
	err := t.autoRedirect.UpdateRouteAddressSet()
	if err != nil {
		t.logger.Error("update route address set: ", err)
	}
}

//nolint:unused
func (t *Inbound) routeAddressSetPrefixes() (include []netip.Prefix, exclude []netip.Prefix) {
	t.routeAddressSetAccess.RLock()
	defer t.routeAddressSetAccess.RUnlock()
	include = common.FlatMap(t.routeAddressSet, (*netipx.IPSet).Prefixes)
	if len(t.routeAddressSet) > 0 && len(include) == 0 {
		include = []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 32), netip.PrefixFrom(netip.IPv6Unspecified(), 128)}
	}
	exclude = common.FlatMap(t.routeExcludeAddressSet, (*netipx.IPSet).Prefixes)
	return
}

func (t *Inbound) InterfaceUpdated(ctx context.Context) {
	tunStack := t.tunStack
	if tunStack != nil {
		tunStack.ResetNetwork()
	}
}

func (t *Inbound) Close() error {
	if t.testCloseObserver != nil {
		t.testCloseObserver()
	}
	// Release the route-set callbacks and references BEFORE tearing anything down.
	//
	// Start registers t.updateRouteAddressSet on every route and exclude rule-set and stores the
	// returned elements, but nothing used to release them. The callback closes over this *Inbound,
	// so a rule-set kept a reference to a closed inbound and would call into it on the next
	// update - reading fields the Close below has already invalidated. The stored element slice
	// made the omission look handled: the bookkeeping existed, only the release was missing.
	//
	// Releasing first also means the rule-set can never fire between the teardown and the release.
	t.releaseRouteSets()

	// The two activated objects go through their startupGate: this path can also be reached while
	// StartStatePostStart is activating them (the duplicate-tag loser in adapter/inbound/manager.go
	// closes an inbound whose start is in flight), and the gate is what keeps the release
	// exactly-once and stops a late activation from re-arming what this is releasing. A caller that
	// assembled the inbound around an already-started stack binds the gates here instead of in Start.
	if t.tunIf != nil {
		t.interfaceStartup.bind(t.tunIf.Close)
	}
	if t.tunStack != nil {
		t.stackStartup.bind(t.tunStack.Close)
	}
	closeErr := E.Errors(
		t.stackStartup.releaseByScope(),
		t.interfaceStartup.releaseByScope(),
		common.Close(t.autoRedirect),
	)
	// Hand the auto-redirect output mark back LAST, after the redirect that needed it is stopped.
	//
	// The claim is taken by the constructor and the object carrying it can be discarded before it is
	// ever started: Manager.Create closes the inbound it built when a concurrent Create installed the
	// same tag first. Without this the manager keeps a mark for a redirect that no longer exists and
	// stamps it on every later dial, including the dials of the box that won the tag.
	//
	// The claim flag is consumed with a CompareAndSwap, so exactly one Close can reach the releaser
	// even when two of them run at once - the Scope's drain and the duplicate-tag loser are
	// independent callers - and a second Close cannot hand the same claim back twice and clear a mark
	// that has since been taken by a new owner.
	if t.autoRedirectOutputMarkClaimed.CompareAndSwap(true, false) {
		if releaser, isReleaser := t.networkManager.(autoRedirectMarkReleaser); isReleaser {
			releaser.ReleaseAutoRedirectOutputMark(t.autoRedirectOutputMark)
		}
	}
	return closeErr
}

// acquireRouteSetRef takes one reference on ruleSet and records it for release.
//
// Taking the reference and recording it under the same lock is what keeps the pair exact: a Scope
// that is already closing runs releaseRouteSetsCleanup on this goroutine the moment it is handed
// over, so a drain that observed the reference before it was recorded would release a reference
// that was never taken, and one that missed it would leak. Holding routeAddressSetAccess across
// both makes the two orders impossible to interleave.
func (t *Inbound) acquireRouteSetRef(ruleSet adapter.RuleSet) {
	t.routeAddressSetAccess.Lock()
	defer t.routeAddressSetAccess.Unlock()
	ruleSet.IncRef()
	t.routeRuleSetRefs = append(t.routeRuleSetRefs, ruleSet)
}

// releaseRouteSetRefs releases exactly the references Start acquired and clears the record.
//
// Clearing is what makes this idempotent and what makes the pairing exact: the slice holds one
// entry per successful IncRef - including the same rule-set twice when it is configured as both a
// route and a route-exclude set - so a second call finds an empty slice and cannot drive a
// rule-set's counter negative, which is a panic in every real implementation.
func (t *Inbound) releaseRouteSetRefs() {
	// Take the references under the lock, then release them OUTSIDE it, for the same reason the
	// callbacks are released outside it: DecRef may take the rule-set's own lock.
	t.routeAddressSetAccess.Lock()
	refs := t.routeRuleSetRefs
	t.routeRuleSetRefs = nil
	t.routeAddressSetAccess.Unlock()

	for _, ruleSet := range refs {
		ruleSet.DecRef()
	}
}

// releaseRouteSets releases everything Start acquired from the route rule-sets: the registered
// callbacks first, then the references.
//
// # Why the order matters
//
// A callback that is still registered can be delivered the moment its rule-set updates, and it
// reads the rule-sets' rules through ExtractIPSet. Releasing the reference first would let a
// concurrent update drop those rules while a callback that is still wired into this inbound is
// reading them. Unregistering first means no new delivery can start, and the reference is only
// dropped once nothing is wired to read through it.
//
// Both halves are individually idempotent, so an explicit Inbound.Close(), the Scope's cleanup and
// closeAutoRedirect's release can all run in any order without releasing anything twice.
func (t *Inbound) releaseRouteSets() {
	t.releaseRouteSetCallbacks()
	t.releaseRouteSetRefs()
}

// releaseRouteSetsCleanup is the Scope-cleanup form of releaseRouteSets.
//
// Start hands this to the Scope at the acquisition, so the Scope - not a later Inbound.Close() that
// the product never calls - is the owner. The release itself stays the single idempotent
// implementation, so the Scope path and an explicit Close() cannot release the same element or the
// same reference twice.
func (t *Inbound) releaseRouteSetsCleanup() error {
	t.releaseRouteSets()
	return nil
}

// closeAutoRedirect stops new route-set notifications before it releases the auto-redirect those
// notifications would be delivered to.
//
// The two are one cleanup because the order between them is load-bearing and cannot be expressed by
// where they sit in the Scope's list. Scope.Close() runs cleanups in reverse registration order, so
// a release registered when the callbacks were acquired runs LAST - after the auto-redirect is
// already closed, which is precisely the state updateRouteAddressSet must never observe. Releasing
// first means a notification that races the teardown finds no observer left, and the window between
// "auto-redirect closed" and "callbacks released" does not exist.
func (t *Inbound) closeAutoRedirect() error {
	t.releaseRouteSets()
	if t.autoRedirect == nil {
		return nil
	}
	return t.autoRedirect.Close()
}

// releaseRouteSetCallbacks unregisters everything Start registered and clears the stored elements.
//
// Clearing them is what makes Close idempotent: a second call finds nothing to release and cannot
// hand the same element to UnregisterCallback twice, which would corrupt the rule-set's list.
func (t *Inbound) releaseRouteSetCallbacks() {
	// Take the elements under the lock, then release them OUTSIDE it.
	//
	// UnregisterCallback takes the rule-set's own lock. Holding this inbound's lock across that
	// call would order the two locks for no benefit, and a rule-set that ever grew a reason to
	// read back from the inbound would deadlock.
	t.routeAddressSetAccess.Lock()
	routeCallbacks := t.routeRuleSetCallback
	excludeCallbacks := t.routeExcludeRuleSetCallback
	t.routeRuleSetCallback = nil
	t.routeExcludeRuleSetCallback = nil
	t.routeAddressSetAccess.Unlock()

	for index, ruleSet := range t.routeRuleSet {
		if index < len(routeCallbacks) && routeCallbacks[index] != nil {
			ruleSet.UnregisterCallback(routeCallbacks[index])
		}
	}
	for index, ruleSet := range t.routeExcludeRuleSet {
		if index < len(excludeCallbacks) && excludeCallbacks[index] != nil {
			ruleSet.UnregisterCallback(excludeCallbacks[index])
		}
	}
}

// JudgeFlow decides what happens to a new flow at the TUN boundary.
//
// # The complete order, and what each step is allowed to decide
//
//  1. canonicalise a v4-mapped destination (::ffff:a.b.c.d -> a.b.c.d)
//  2. configured DNS hijack address      UDP -> ActionHijackDNS, TCP -> ActionAccept
//  3. dnsHijackByPort && port 53         UDP -> ActionHijackDNS, TCP -> ActionAccept
//  4. FakeIP placeholder guard           makes step 5 inapplicable
//  5. route_address_set miss / route_exclude_address_set hit
//     -> ActionBypass, and the Router is never consulted
//  6. otherwise                          adapter.JudgeFlow -> Router.PreMatch, and therefore
//     reverse mapping, domain/process/protocol policy and the
//     router-level Direct Fast Path eligibility
//
// # L0 is an authoritative IP-only pre-router policy, and that is a product decision
//
// Step 5 terminates evaluation. A matching L0 policy decides the flow on the DESTINATION ADDRESS
// alone, which means domain, process, protocol and reverse-mapped-domain policy deliberately do not
// participate in it - and the Router's call count is zero, not "one, then ignored". That is not an
// oversight to be repaired by routing literal-IP flows through the router for safety: the route sets
// ARE the platform routing table's configuration, so a flow they cover is one the platform carries
// whether or not sing-box has an opinion about its domain, and a verdict produced by consulting the
// router first is one this layer could not then honour.
//
// The consequence for whoever writes the configuration, stated plainly: putting an address in
// route_address_set (or route_exclude_address_set) OUTRANKS every domain, process and protocol rule
// that would otherwise have described a flow to that address. An address rule and a domain rule are
// two independent ways to write the same policy, and DNS state is what makes them describe the same
// flow; when they disagree, the address wins.
//
// # The three verdicts that are easy to confuse
//
//	ActionAccept      for a configured TCP DNS destination. The flow is NOT bypassed: it stays in
//	                  sing-box and the existing stream DNS path takes it. Reading this as "hand DNS
//	                  to the platform" is the mistake this distinction exists to prevent.
//	ActionBypass      the platform carries the flow and sing-box does not see it again.
//	L0 bypass vs      a different thing entirely: the router's Direct Fast Path is a per-flow
//	router-level   decision made from full metadata (sniffed domain, FakeIP state, trackers,
//	                  resolved candidates, destination rewrite, group membership), which is why it
//	                  can refuse a flow L0 would have carried.
//
// # What takes precedence over L0
//
// Configured DNS hijack (step 2, and step 3 when the by-port rule is on) and FakeIP protection
// (step 4). Those two are checked FIRST, so a query to a configured DNS server is never bypassed
// just because its address is outside a route set, and a FakeIP placeholder is never handed to a
// platform that has no route for it. Everything else - including whether port 53 is special at all -
// follows the configuration: with `dns_hijack` by-port disabled and no configured hijack address,
// UDP/53 is ordinary traffic and the route sets decide it.
//
// # Evidence
//
// Steps 2, 3, 4 and 5 were each reverse-broken in a disposable tree and every mutation turned the
// named tests red (see docs/fork/v016-overnight-implementation-report.md):
//
//	move steps 2-3 below step 5        -> TestDNSHijackBeatsRouteExcludeAddressSet and 6 others RED
//	remove the step 4 guard            -> TestFakeIPIsNotBypassedByRouteAddressSet and 2 others RED
//	let a step 5 hit continue to step 6 -> TestL0HitReport, TestL0CannotExpressAnythingButAddresses,
//	                                      TestL0AuthoritativeIPPolicyWinsBeforeReverseMapping RED
//	make step 6 unconditional          -> the same three plus
//	                                      TestL0DoesNotDiscardProcessOrProtocolRulesOnTheNonL0Branch RED
//
// # Cost
//
// Steps 1-3 are a slice scan and a port/network comparison, and a non-DNS flow pays only those. Step
// 4 is two prefix comparisons, skipped entirely when no FakeIP transport is configured. Step 5 is two
// radix lookups. Nothing here allocates, takes a lock beyond an RWMutex read of the route sets, or
// performs a DNS lookup: a flow that reaches step 5 and returns never touches the router, the reverse
// mapping, the process searcher or any timer.
func (t *Inbound) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	// The destination is canonicalised BEFORE any policy comparison, and that order is part of the
	// contract rather than tidiness.
	//
	// A v4-mapped address (::ffff:a.b.c.d) is an IPv4 address written in sixteen bytes: a dual-stack
	// application reaches 10.0.0.53 exactly as ::ffff:10.0.0.53, and sing-tun's parser carries the
	// sixteen-byte form through unchanged. Every comparison below is written against the four-byte
	// form, and each of them fails open on the mapped one:
	//
	//	netip.Addr equality      a configured DNS address is not recognised, so the query is not
	//	                         hijacked and DNS policy - including Fake-IP - is skipped entirely
	//	netip.Prefix.Contains    a FakeIP range does not contain its own address, so the L0 guard
	//	                         does not fire and the placeholder is handed to the platform
	//	netipx.IPSet.Contains    a route set does not contain its own address either, so an address
	//	                         the include set was supposed to match is bypassed, and one an
	//	                         exclude set was supposed to bypass is routed
	//
	// Failing open is the dangerous direction in all four cases, and they share one cause, so the
	// fix belongs here rather than in each comparison.
	destination = canonicalAddrPort(destination)

	// A configured DNS address is hijacked on every port.
	if slices.Contains(t.dnsHijackAddress, destination.Addr()) {
		if network == uint8(header.UDPProtocolNumber) {
			return tun.FlowVerdict{Action: tun.ActionHijackDNS}
		}
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	// The by-port rule, which must also precede the bypasses below.
	//
	// UDP is hijacked here; TCP is ACCEPTED so the existing stream DNS path takes over. TCP is
	// deliberately not hijacked at the flow level - changing that would alter the stream DNS
	// architecture - but it must be accepted rather than bypassed, because a bypassed TCP/53
	// leaves sing-box entirely.
	if t.dnsHijackByPort && destination.Port() == 53 &&
		(network == uint8(header.TCPProtocolNumber) || network == uint8(header.UDPProtocolNumber)) {
		if network == uint8(header.UDPProtocolNumber) {
			return tun.FlowVerdict{Action: tun.ActionHijackDNS}
		}
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}

	t.routeAddressSetAccess.RLock()
	routeAddressSet := t.routeAddressSet
	routeExcludeAddressSet := t.routeExcludeAddressSet
	t.routeAddressSetAccess.RUnlock()
	destinationAddress := destination.Addr()

	// The route sets decide what the PLATFORM's routing table is trusted to carry, and a FakeIP
	// address is not something the platform knows anything about: it is a placeholder this process
	// minted, it has no route, and the domain it stands for is only recovered by the router.
	//
	// This check is here rather than in the router because the route sets bypass the router
	// entirely. With route_address_set configured, every destination OUTSIDE the set is bypassed -
	// including a FakeIP address that the DNS layer just handed to an application - so without this
	// guard the placeholder is silently black-holed instead of being unmapped. The same applies to
	// an exclude set that happens to cover the FakeIP range, which is not far-fetched: 198.18.0.0/15
	// sits inside several broadly-written sets.
	//
	// It is two prefix comparisons on a path that already does radix lookups, runs once per flow
	// rather than per packet, and is skipped entirely when no FakeIP transport is configured.
	routeSetsApply := t.fakeIPStore == nil || !t.fakeIPStore.Contains(destinationAddress)
	if routeSetsApply {
		if len(routeAddressSet) > 0 && !slices.ContainsFunc(routeAddressSet, func(it *netipx.IPSet) bool {
			return it.Contains(destinationAddress)
		}) {
			return tun.FlowVerdict{Action: tun.ActionBypass}
		}
		if slices.ContainsFunc(routeExcludeAddressSet, func(it *netipx.IPSet) bool {
			return it.Contains(destinationAddress)
		}) {
			return tun.FlowVerdict{Action: tun.ActionBypass}
		}
	}
	return adapter.JudgeFlow(t.router, adapter.InboundContext{Inbound: t.tag, InboundType: C.TypeTun}, network, source, destination, firstPacket)
}

// canonicalAddrPort rewrites a v4-mapped IPv6 address to its four-byte form.
//
// A no-op for every other address. It exists so the reason above is written once: an address that
// arrives in sixteen bytes and is compared against four-byte policy is the shape of every bug in this
// family.
func canonicalAddrPort(destination netip.AddrPort) netip.AddrPort {
	address := destination.Addr()
	if !address.Is4In6() {
		return destination
	}
	return netip.AddrPortFrom(address.Unmap(), destination.Port())
}

// canonicalSocksaddr is canonicalAddrPort for the userspace entry points.
func canonicalSocksaddr(destination M.Socksaddr) M.Socksaddr {
	address := destination.Addr
	if !address.Is4In6() {
		return destination
	}
	return M.Socksaddr{
		Addr: address.Unmap(),
		Port: destination.Port,
	}
}

func (t *Inbound) isDNSHijackDestination(destination M.Socksaddr) bool {
	destination = canonicalSocksaddr(destination)
	return slices.Contains(t.dnsHijackAddress, destination.Addr) || t.dnsHijackByPort && destination.Port == 53
}

func (t *Inbound) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(t.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	t.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	t.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (t *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	// The router sees the canonical form for the same reason JudgeFlow does: rule matching compares
	// addresses against CIDR sets, and a sixteen-byte spelling of a four-byte address fails every one
	// of those comparisons - so the connection would be routed by whichever rules match nothing.
	destination = canonicalSocksaddr(destination)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	if t.isDNSHijackDestination(destination) {
		metadata.Protocol = C.ProtocolDNS
	}
	if metadata.Protocol == C.ProtocolDNS {
		t.logger.InfoContext(ctx, "inbound DNS connection from ", metadata.Source)
	} else {
		t.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
		t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (t *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	destination = canonicalSocksaddr(destination)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	if t.isDNSHijackDestination(destination) {
		metadata.Protocol = C.ProtocolDNS
	}
	if metadata.Protocol == C.ProtocolDNS {
		t.logger.InfoContext(ctx, "inbound DNS packet connection from ", metadata.Source)
	} else {
		t.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
		t.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	t.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

type autoRedirectHandler Inbound

func (t *autoRedirectHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return (*Inbound)(t).JudgeFlow(network, source, destination, firstPacket)
}

func (t *autoRedirectHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	destination = canonicalSocksaddr(destination)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	if (*Inbound)(t).isDNSHijackDestination(destination) {
		metadata.Protocol = C.ProtocolDNS
	}
	if metadata.Protocol == C.ProtocolDNS {
		t.logger.InfoContext(ctx, "inbound redirect DNS connection from ", metadata.Source)
	} else {
		t.logger.InfoContext(ctx, "inbound redirect connection from ", metadata.Source)
		t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

var _ tun.AutoRedirectHandler = (*autoRedirectHandler)(nil)
