package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/winpowrprof"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/exp/slices"
)

var _ adapter.NetworkManager = (*NetworkManager)(nil)

type NetworkManager struct {
	ctx                     context.Context
	logger                  logger.ContextLogger
	router                  adapter.Router
	interfaceFinder         *control.DefaultInterfaceFinder
	networkInterfaces       common.TypedValue[[]adapter.NetworkInterface]
	autoDetectInterface     bool
	defaultOptions          adapter.NetworkOptions
	autoRedirectOutputMark  uint32
	bridgeInterfaceAccess   sync.Mutex
	bridgeInterfaces        []string
	networkMonitor          tun.NetworkUpdateMonitor
	interfaceMonitor        tun.DefaultInterfaceMonitor
	packageManager          tun.PackageManager
	powerListener           winpowrprof.EventListener
	pauseManager            pause.Manager
	platformInterface       adapter.PlatformInterface
	connectionManager       adapter.ConnectionManager
	endpoint                adapter.EndpointManager
	inbound                 adapter.InboundManager
	outbound                adapter.OutboundManager
	needWIFIState           bool
	wifiMonitor             settings.WIFIMonitor
	wifiState               adapter.WIFIState
	networkEnvironment      uint64
	stateAccess             sync.RWMutex
	environmentUpdateAccess sync.Mutex
	startedCtx              context.Context
	interfaceUpdateAccess   sync.Mutex
	interfaceUpdateCancel   context.CancelFunc
	networkResetPending     bool
	resetRunAccess          sync.Mutex
	// networkResetGeneration increases every time a network reset BEGINS - it is advanced as the
	// reset's first statement, so an operation in flight when the reset starts is already stale.
	// Read it as a reset epoch, not as a count of finished resets.
	//
	// It is the epoch a pre-reset network operation is compared against: an operation that began
	// before a reset must not hand a connection to a caller after it, because that connection
	// belongs to the network that has been left.
	networkResetGeneration atomic.Uint64
	powerUpdateAccess      sync.Mutex
	powerUpdateCancel      context.CancelFunc
}

func NewNetworkManager(ctx context.Context, logger logger.ContextLogger, options option.RouteOptions, dnsOptions option.DNSOptions) (*NetworkManager, error) {
	defaultDomainResolver := common.PtrValueOrDefault(options.DefaultDomainResolver)
	if options.AutoDetectInterface && !(C.IsLinux || C.IsDarwin || C.IsWindows) {
		return nil, E.New("`auto_detect_interface` is only supported on Linux, Windows and macOS")
	} else if options.OverrideAndroidVPN && !C.IsAndroid {
		return nil, E.New("`override_android_vpn` is only supported on Android")
	} else if options.DefaultInterface != "" && !(C.IsLinux || C.IsDarwin || C.IsWindows) {
		return nil, E.New("`default_interface` is only supported on Linux, Windows and macOS")
	} else if options.DefaultMark != 0 && !C.IsLinux {
		return nil, E.New("`default_mark` is only supported on linux")
	}
	nm := &NetworkManager{
		ctx:                 ctx,
		logger:              logger,
		interfaceFinder:     control.NewDefaultInterfaceFinder(),
		autoDetectInterface: options.AutoDetectInterface,
		defaultOptions: adapter.NetworkOptions{
			BindInterface:  options.DefaultInterface,
			RoutingMark:    uint32(options.DefaultMark),
			DomainResolver: defaultDomainResolver.Server,
			DomainResolveOptions: adapter.DNSQueryOptions{
				Strategy:               C.DomainStrategy(defaultDomainResolver.Strategy),
				Timeout:                time.Duration(defaultDomainResolver.Timeout),
				DisableCache:           defaultDomainResolver.DisableCache,
				DisableOptimisticCache: defaultDomainResolver.DisableOptimisticCache,
				RewriteTTL:             defaultDomainResolver.RewriteTTL,
				ClientSubnet:           defaultDomainResolver.ClientSubnet.Build(netip.Prefix{}),
			},
			NetworkStrategy:     (*C.NetworkStrategy)(options.DefaultNetworkStrategy),
			NetworkType:         common.Map(options.DefaultNetworkType, option.InterfaceType.Build),
			FallbackNetworkType: common.Map(options.DefaultFallbackNetworkType, option.InterfaceType.Build),
			FallbackDelay:       time.Duration(options.DefaultFallbackDelay),
		},
		pauseManager:      service.FromContext[pause.Manager](ctx),
		platformInterface: service.FromContext[adapter.PlatformInterface](ctx),
		connectionManager: service.FromContext[adapter.ConnectionManager](ctx),
		endpoint:          service.FromContext[adapter.EndpointManager](ctx),
		inbound:           service.FromContext[adapter.InboundManager](ctx),
		outbound:          service.FromContext[adapter.OutboundManager](ctx),
		needWIFIState:     hasRule(options.Rules, isWIFIRule) || hasDNSRule(dnsOptions.Rules, isWIFIDNSRule),
	}
	if options.DefaultNetworkStrategy != nil {
		if options.DefaultInterface != "" {
			return nil, E.New("`default_network_strategy` is conflict with `default_interface`")
		}
		if !options.AutoDetectInterface {
			return nil, E.New("`auto_detect_interface` is required by `default_network_strategy`")
		}
	}
	usePlatformDefaultInterfaceMonitor := nm.platformInterface != nil && nm.platformInterface.UsePlatformDefaultInterfaceMonitor()
	enforceInterfaceMonitor := options.AutoDetectInterface
	if !usePlatformDefaultInterfaceMonitor {
		networkMonitor, err := tun.NewNetworkUpdateMonitor(logger)
		if !((err != nil && !enforceInterfaceMonitor) || errors.Is(err, os.ErrInvalid)) {
			if err != nil {
				return nil, E.Cause(err, "create network monitor")
			}
			nm.networkMonitor = networkMonitor
			networkMonitor.RegisterCallback(nm.postUpdateNetworkEnvironment)
			interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(nm.networkMonitor, logger, tun.DefaultInterfaceMonitorOptions{
				InterfaceFinder:       nm.interfaceFinder,
				OverrideAndroidVPN:    options.OverrideAndroidVPN,
				UnderNetworkExtension: nm.platformInterface != nil && nm.platformInterface.UnderNetworkExtension(),
			})
			if err != nil {
				return nil, E.New("auto_detect_interface unsupported on current platform")
			}
			nm.interfaceMonitor = interfaceMonitor
		}
	} else {
		nm.interfaceMonitor = nm.platformInterface.CreateDefaultInterfaceMonitor(logger)
	}
	return nm, nil
}

func (r *NetworkManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	switch stage {
	case adapter.StartStateInitialize:
		r.router = service.FromContext[adapter.Router](r.ctx)
		// Nothing to cancel for the environment boundary: it is established synchronously by the
		// event that causes it, so there is no pending timer that could fire after teardown.
		if r.networkMonitor != nil {
			monitor.Start("initialize network monitor")
			err := r.networkMonitor.Start()
			monitor.Finish()
			if err != nil {
				return err
			}
			scope.Add(r.networkMonitor.Close)
		}
		if r.interfaceMonitor != nil {
			monitor.Start("initialize interface monitor")
			err := r.interfaceMonitor.Start()
			monitor.Finish()
			if err != nil {
				return err
			}
			scope.Add(r.interfaceMonitor.Close)
			interfaceUpdateElement := r.interfaceMonitor.RegisterCallback(r.notifyInterfaceUpdate)
			scope.Add(func() error {
				r.interfaceMonitor.UnregisterCallback(interfaceUpdateElement)
				return nil
			})
		}
	case adapter.StartStateStart:
		if C.IsAndroid && r.platformInterface == nil {
			monitor.Start("initialize package manager")
			packageManager, err := tun.NewPackageManager(tun.PackageManagerOptions{
				Callback: r,
				Logger:   r.logger,
			})
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "create package manager")
			}
			monitor.Start("start package manager")
			err = packageManager.Start()
			monitor.Finish()
			if err != nil {
				r.logger.Warn("initialize package manager: ", err)
			} else {
				r.packageManager = packageManager
				scope.Add(packageManager.Close)
			}
		}
	case adapter.StartStatePostStart:
		if r.needWIFIState && !(r.platformInterface != nil && r.platformInterface.UsePlatformWIFIMonitor()) {
			wifiMonitor, err := settings.NewWIFIMonitor(r.onWIFIStateChanged)
			if err != nil {
				if err != os.ErrInvalid {
					r.logger.Warn(E.Cause(err, "create WIFI monitor"))
				}
			} else {
				r.wifiMonitor = wifiMonitor
				scope.Add(wifiMonitor.Close)
				err = r.wifiMonitor.Start()
				if err != nil {
					r.logger.Warn(E.Cause(err, "start WIFI monitor"))
				}
			}
		}
		scope.Add(func() error {
			r.resetRunAccess.Lock()
			defer r.resetRunAccess.Unlock()
			return nil
		})
		r.interfaceUpdateAccess.Lock()
		r.startedCtx = scope.Context()
		if r.interfaceMonitor != nil {
			r.dispatchInterfaceUpdateLocked()
		}
		r.interfaceUpdateAccess.Unlock()
		if runtime.GOOS == "windows" {
			powerListener, err := winpowrprof.NewEventListener(r.notifyWindowsPowerEvent)
			if err == nil {
				r.powerListener = powerListener
			} else {
				r.logger.Warn("initialize power listener: ", err)
			}
		}
		if r.powerListener != nil {
			monitor.Start("start power listener")
			err := r.powerListener.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "start power listener")
			}
			scope.Add(r.powerListener.Close)
		}
	}
	return nil
}

func (r *NetworkManager) Initialize(ruleSets []adapter.RuleSet) {
	for _, ruleSet := range ruleSets {
		metadata := ruleSet.Metadata()
		if metadata.ContainsWIFIRule {
			r.needWIFIState = true
			break
		}
	}
}

func (r *NetworkManager) InterfaceFinder() control.InterfaceFinder {
	return r.interfaceFinder
}

func (r *NetworkManager) UpdateInterfaces() error {
	defer r.postUpdateNetworkEnvironment()
	if r.platformInterface == nil || !r.platformInterface.UsePlatformNetworkInterfaces() {
		return r.interfaceFinder.Update()
	} else {
		interfaces, err := r.platformInterface.NetworkInterfaces()
		if err != nil {
			return err
		}
		if C.IsDarwin {
			err = r.interfaceFinder.Update()
			if err != nil {
				return err
			}
			// NEInterface only provides name,index and type
			interfaces = common.Map(interfaces, func(it adapter.NetworkInterface) adapter.NetworkInterface {
				iif, _ := r.interfaceFinder.ByIndex(it.Index)
				if iif != nil {
					it.Interface = *iif
				}
				return it
			})
		} else {
			r.interfaceFinder.UpdateInterfaces(common.Map(interfaces, func(it adapter.NetworkInterface) control.Interface { return it.Interface }))
		}
		oldInterfaces := r.networkInterfaces.Load()
		newInterfaces := common.Filter(interfaces, func(it adapter.NetworkInterface) bool {
			return it.Flags&net.FlagUp != 0
		})
		r.networkInterfaces.Store(newInterfaces)
		if len(newInterfaces) > 0 && !slices.EqualFunc(oldInterfaces, newInterfaces, func(oldInterface adapter.NetworkInterface, newInterface adapter.NetworkInterface) bool {
			return oldInterface.Interface.Index == newInterface.Interface.Index &&
				oldInterface.Interface.Name == newInterface.Interface.Name &&
				oldInterface.Interface.Flags == newInterface.Interface.Flags &&
				oldInterface.Type == newInterface.Type &&
				oldInterface.Expensive == newInterface.Expensive &&
				oldInterface.Constrained == newInterface.Constrained
		}) {
			r.logger.Info("updated available networks: ", strings.Join(common.Map(newInterfaces, func(it adapter.NetworkInterface) string {
				var options []string
				options = append(options, F.ToString(it.Type))
				if it.Expensive {
					options = append(options, "expensive")
				}
				if it.Constrained {
					options = append(options, "constrained")
				}
				return F.ToString(it.Name, " (", strings.Join(options, ", "), ")")
			}), ", "))
		}
		return nil
	}
}

func (r *NetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface {
	iif := r.interfaceMonitor.DefaultInterface()
	if iif == nil {
		return nil
	}
	for _, it := range r.networkInterfaces.Load() {
		if it.Interface.Index == iif.Index {
			return &it
		}
	}
	return &adapter.NetworkInterface{Interface: *iif}
}

func (r *NetworkManager) NetworkInterfaces() []adapter.NetworkInterface {
	return r.networkInterfaces.Load()
}

func (r *NetworkManager) AutoDetectInterface() bool {
	return r.autoDetectInterface
}

func (r *NetworkManager) AutoDetectInterfaceFunc() control.Func {
	if r.platformInterface != nil && r.platformInterface.UsePlatformAutoDetectInterfaceControl() {
		return func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return r.platformInterface.AutoDetectInterfaceControl(int(fd))
			})
		}
	} else {
		if r.interfaceMonitor == nil {
			return nil
		}
		return control.BindToInterfaceFunc(r.interfaceFinder, func(network string, address string) (interfaceName string, interfaceIndex int, err error) {
			remoteAddr := M.ParseSocksaddr(address).Addr
			if remoteAddr.IsValid() {
				iif, err := r.interfaceFinder.ByAddr(remoteAddr)
				if err == nil {
					return iif.Name, iif.Index, nil
				}
			}
			defaultInterface := r.interfaceMonitor.DefaultInterface()
			if defaultInterface == nil {
				return "", -1, tun.ErrNoRoute
			}
			return defaultInterface.Name, defaultInterface.Index, nil
		})
	}
}

func (r *NetworkManager) ProtectFunc() control.Func {
	if r.platformInterface != nil && r.platformInterface.UsePlatformAutoDetectInterfaceControl() {
		return func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return r.platformInterface.AutoDetectInterfaceControl(int(fd))
			})
		}
	}
	return nil
}

func (r *NetworkManager) DefaultOptions() adapter.NetworkOptions {
	return r.defaultOptions
}

func (r *NetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error {
	if r.autoRedirectOutputMark > 0 {
		return E.New("only one auto-redirect can be configured")
	}
	r.autoRedirectOutputMark = mark
	return nil
}

func (r *NetworkManager) AutoRedirectOutputMark() uint32 {
	return r.autoRedirectOutputMark
}

func (r *NetworkManager) RegisterBridgeInterface(interfaceName string) {
	r.bridgeInterfaceAccess.Lock()
	defer r.bridgeInterfaceAccess.Unlock()
	if !slices.Contains(r.bridgeInterfaces, interfaceName) {
		r.bridgeInterfaces = append(r.bridgeInterfaces, interfaceName)
	}
}

func (r *NetworkManager) BridgeInterfaces() []string {
	r.bridgeInterfaceAccess.Lock()
	defer r.bridgeInterfaceAccess.Unlock()
	return slices.Clone(r.bridgeInterfaces)
}

func (r *NetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if r.autoRedirectOutputMark == 0 {
			return nil
		}
		return control.RoutingMark(r.autoRedirectOutputMark)(network, address, conn)
	}
}

func (r *NetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor {
	return r.networkMonitor
}

func (r *NetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return r.interfaceMonitor
}

func (r *NetworkManager) PackageManager() tun.PackageManager {
	return r.packageManager
}

func (r *NetworkManager) NeedWIFIState() bool {
	return r.needWIFIState
}

func (r *NetworkManager) WIFIState() adapter.WIFIState {
	r.stateAccess.RLock()
	defer r.stateAccess.RUnlock()
	return r.wifiState
}

// publishWIFIState stores the new Wi-Fi state and reports whether it actually changed.
//
// It deliberately does NOT establish the environment boundary. A Wi-Fi change moves the environment
// fingerprint, so a boundary is owed - but the boundary is a reset, and one of this function's callers
// (updateInterface) already holds resetRunAccess while another (the monitor callback) does not.
// Splitting "publish" from "establish the boundary" is what lets each caller use the form its lock
// context allows, instead of one of them having to guess.
func (r *NetworkManager) publishWIFIState(state adapter.WIFIState) bool {
	state.BSSID = adapter.NormalizeWIFIBSSID(state.BSSID)
	r.stateAccess.Lock()
	defer r.stateAccess.Unlock()
	if state == r.wifiState {
		return false
	}
	r.wifiState = state
	return true
}

// onWIFIStateChanged is the entry for callers that do NOT hold resetRunAccess - the Wi-Fi monitor
// callback. It establishes the boundary itself, through the exported self-locking reset.
func (r *NetworkManager) onWIFIStateChanged(state adapter.WIFIState) {
	if !r.publishWIFIState(state) {
		return
	}
	r.logWIFIState(state)
	r.postUpdateNetworkEnvironment()
}

// logWIFIState reports the change at the same level the previous implementation used.
func (r *NetworkManager) logWIFIState(state adapter.WIFIState) {
	if state.SSID != "" {
		r.logger.Info("WIFI state changed: SSID=", state.SSID, ", BSSID=", state.BSSID)
	} else {
		r.logger.Info("WIFI disconnected")
	}
}

// UpdateWIFIState is the entry for callers that do NOT hold resetRunAccess.
func (r *NetworkManager) UpdateWIFIState(ctx context.Context) {
	state, loaded := r.readWIFIState(ctx)
	if !loaded {
		return
	}
	r.onWIFIStateChanged(state)
}

// updateWIFIStateLocked is the entry for a caller that DOES hold resetRunAccess.
//
// It publishes the state without taking a boundary: the caller is responsible for establishing one,
// because it holds the reset lock and must not ask for it again. Reading the state and publishing it
// are both done here so the caller's ordering is unchanged.
func (r *NetworkManager) updateWIFIStateLocked(ctx context.Context) {
	state, loaded := r.readWIFIState(ctx)
	if !loaded {
		return
	}
	if !r.publishWIFIState(state) {
		return
	}
	r.logWIFIState(state)
	// No boundary here. updateInterface recomputes the environment after this call and establishes a
	// single boundary covering both the Wi-Fi move and any pending interface reset.
}

// readWIFIState reads the current Wi-Fi state from whichever monitor is configured.
func (r *NetworkManager) readWIFIState(ctx context.Context) (adapter.WIFIState, bool) {
	if r.wifiMonitor != nil {
		return r.wifiMonitor.ReadWIFIState(ctx), true
	}
	if r.platformInterface != nil && r.platformInterface.UsePlatformWIFIMonitor() {
		return r.platformInterface.ReadWIFIState(ctx), true
	}
	return adapter.WIFIState{}, false
}

// ResetNetwork runs a network reset, serialised against every other one.
//
// # Why it takes the lock itself
//
// The interface-driven path and the power paths already hold resetRunAccess when they call the inner
// function, because they need it for a wider critical section that also decides WHETHER to reset.
// The control plane does not: experimental/clashapi and the libbox command server call ResetNetwork
// directly, with no lock at all.
//
// Two resets running concurrently interleave CloseAll, the InterfaceUpdated callbacks and the DNS
// reset. The generation then advances more than once while the transports and callbacks are reset in
// an order belonging to neither run, so a transport can be reset after the generation it was pinned
// to - and a caller observes a state that no single reset produced.
func (r *NetworkManager) ResetNetwork(ctx context.Context) {
	r.resetRunAccess.Lock()
	defer r.resetRunAccess.Unlock()
	// Claimed here because this entry point IS the transition: it has no earlier moment at which a
	// caller could observe a half-published state.
	r.beginTransition()
	r.resetNetworkLocked(ctx)
}

// beginTransition claims the epoch for a transition that is about to perform a reset.
//
// # Why the epoch is claimed separately from the reset body
//
// The epoch is the ownership token every other subsystem compares against: the DNS generation
// barrier rejects a response whose captured epoch has moved, and the dialer refuses to hand a
// connection to a caller whose epoch is stale. Both read the SAME counter this advances.
//
// Advancing it only inside resetNetworkLocked, which runs after resetRunAccess is acquired, left a
// window in which the transition was already half-published: recomputeNetworkEnvironment had
// written the new fingerprint, so NetworkEnvironment() reported the new network, while the epoch
// still reported the old one and every DNS transport pin still named the old network. An operation
// completing inside that window is compared against the OLD epoch, is judged current, and its
// answer is cached under the old namespace although the connection that carried it now reaches the
// new network. Holding the lock for a long time - a slow CloseAll, a contended mutex - only makes
// the window wider; it does not make it safe.
//
// Claiming the epoch BEFORE waiting turns the publish and the epoch into one observation: there is
// no instant at which a reader can see the new fingerprint with the old ownership. The reset body
// then runs without advancing the epoch a second time, so one logical transition still costs
// exactly one epoch.
func (r *NetworkManager) beginTransition() {
	r.networkResetGeneration.Add(1)
}

// NetworkResetGeneration reports the current reset epoch: it increases every time a network
// reset BEGINS, advanced as the reset's first statement rather than on completion.
//
// Read by the dialer to decide whether a connection it just produced still belongs to the network it
// was dialled for. See adapter.NetworkResetCounter.
func (r *NetworkManager) NetworkResetGeneration() uint64 {
	return r.networkResetGeneration.Load()
}

// interfaceUpdateDecisionHook, when set, runs between updateInterface's context check and its
// consumption of networkResetPending.
//
// Those two steps are the window a superseding notification can slip into, and the window is one
// instruction wide. A test that wants to prove the ordering cannot widen it by racing, so it parks
// the update here instead. It is nil in production, where the check is a single predictable branch.
var interfaceUpdateDecisionHook func()

// resetNetworkLocked performs the reset. Callers must hold resetRunAccess.
//
// The epoch must already have been claimed, by beginTransition or by one of the entry points that
// claims it as part of taking the lock. It is NOT advanced here: a transition claims its epoch
// before it waits for the lock, so that the epoch moves with the published environment rather than
// a lock acquisition later.
func (r *NetworkManager) resetNetworkLocked(ctx context.Context) {
	if r.connectionManager != nil {
		r.connectionManager.CloseAll()
	}

	for _, endpoint := range r.endpoint.Endpoints() {
		listener, isListener := endpoint.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated(ctx)
		}
	}

	for _, inbound := range r.inbound.Inbounds() {
		listener, isListener := inbound.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated(ctx)
		}
	}

	for _, outbound := range r.outbound.Outbounds() {
		listener, isListener := outbound.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated(ctx)
		}
	}

	r.router.ResetNetwork()
}

func (r *NetworkManager) ReleaseMemory(ctx context.Context) {
	r.ResetNetwork(ctx)
	for _, outbound := range r.outbound.Outbounds() {
		keeper, isKeeper := outbound.(adapter.IdleConnectionKeeper)
		if isKeeper {
			keeper.CloseIdleConnections()
		}
	}
}

func (r *NetworkManager) notifyInterfaceUpdate(_ *control.Interface, _ int) {
	r.interfaceUpdateAccess.Lock()
	defer r.interfaceUpdateAccess.Unlock()
	r.networkResetPending = true
	if r.startedCtx != nil {
		r.dispatchInterfaceUpdateLocked()
	}
}

func (r *NetworkManager) dispatchInterfaceUpdateLocked() {
	defaultInterface := r.interfaceMonitor.DefaultInterface()
	if defaultInterface == nil {
		r.pauseManager.NetworkPause()
		r.logger.Error("missing default interface")
		return
	}
	r.pauseManager.NetworkWake()
	if r.interfaceUpdateCancel != nil {
		r.interfaceUpdateCancel()
	}
	updateContext, updateCancel := context.WithCancel(r.startedCtx)
	r.interfaceUpdateCancel = updateCancel
	go r.updateInterface(updateContext, defaultInterface)
}

func (r *NetworkManager) updateInterface(ctx context.Context, defaultInterface *control.Interface) {
	r.resetRunAccess.Lock()
	defer r.resetRunAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	var options []string
	options = append(options, F.ToString("index ", defaultInterface.Index))
	if C.IsAndroid && r.platformInterface == nil {
		var vpnStatus string
		if r.interfaceMonitor.AndroidVPNEnabled() {
			vpnStatus = "enabled"
		} else {
			vpnStatus = "disabled"
		}
		options = append(options, "vpn "+vpnStatus)
	} else if r.platformInterface != nil && r.platformInterface.UsePlatformNetworkInterfaces() {
		networkInterface := common.Find(r.networkInterfaces.Load(), func(it adapter.NetworkInterface) bool {
			return it.Interface.Index == defaultInterface.Index
		})
		if networkInterface.Name == "" {
			// race
			return
		}
		options = append(options, F.ToString("type ", networkInterface.Type))
		if networkInterface.Expensive {
			options = append(options, "expensive")
		}
		if networkInterface.Constrained {
			options = append(options, "constrained")
		}
	}
	r.logger.Info("updated default interface ", defaultInterface.Name, ", ", strings.Join(options, ", "))
	// The Wi-Fi state is read through the monitor. A CHANGE in it moves the environment fingerprint,
	// but this function must NOT let that take its own boundary: updateInterface already holds
	// resetRunAccess, and the boundary is a reset. Establishing it from inside here would ask for the
	// lock this goroutine is holding - a self-deadlock, since sync.Mutex is not reentrant - and it
	// would also reset before this function has decided about the pending interface reset.
	//
	// So the state is published without a boundary, and the single decision below takes one reset
	// covering both reasons.
	r.updateWIFIStateLocked(ctx)
	if ctx.Err() != nil {
		return
	}
	// One decision, one reset.
	//
	// Two independent reasons can call for a reset here, and they describe the SAME physical
	// transition: an interface change sets networkResetPending AND usually moves the environment
	// fingerprint with it. Deciding them separately reset the network twice for one event, tearing
	// down pooled connections a second time with no second event behind it.
	//
	// The recompute runs first because it is what answers "did the environment move", and it must
	// NOT take the reset itself - the boundary is taken once, below, under this function's lock.
	//
	// The locked form throughout: this function holds resetRunAccess (taken above), and the boundary
	// resets the network. Calling the exported, self-locking entry from here would self-deadlock,
	// because sync.Mutex is not reentrant.
	environmentChanged := r.recomputeNetworkEnvironment()

	// Consume the pending flag only if THIS update is the one that will act on it.
	//
	// A newer interface notification cancels this update's context and arms the flag for itself. If a
	// cancelled update cleared the flag anyway, that newer transition would be dropped: its own update
	// would find nothing pending and skip the reset it exists to perform.
	// ONE ownership decision.
	//
	// Everything that decides whether this update still owns its event happens under
	// interfaceUpdateAccess, and it happens as a single step:
	//
	//	- whether this update is still current, and
	//	- whether networkResetPending belongs to it.
	//
	// Checking the context OUTSIDE the lock and consuming the flag INSIDE it made those two facts
	// separately readable, and a superseding notification - which arms the flag and cancels this
	// update's context under that same lock - could land between them. The check passed, the flag it
	// then consumed belonged to the newer event, and that event's own update found nothing to do.
	// The interface change was silently dropped.
	//
	// The two must therefore be observed together: the lock that the notifier takes is the lock in
	// which "am I still current" is answered. A context cancelled before this critical section is
	// seen as cancelled here; one cancelled after it has already lost, because this update has
	// claimed its epoch and committed to the transition.
	ownedByThisUpdate := false
	superseded := false
	r.interfaceUpdateAccess.Lock()
	if ctx.Err() != nil {
		superseded = true
	} else {
		if interfaceUpdateDecisionHook != nil {
			interfaceUpdateDecisionHook()
		}
		// Re-check inside the lock: the hook above explicitly widens the window, and a notification
		// that arrived while it ran must still win.
		if ctx.Err() != nil {
			superseded = true
		} else if r.networkResetPending {
			r.networkResetPending = false
			ownedByThisUpdate = true
		}
	}
	r.interfaceUpdateAccess.Unlock()

	// The environment half is governed by the same decision. A superseded update does not run a
	// reset for a state it no longer owns: the notification that superseded it will establish that
	// boundary itself, and running it here as well would be a second reset for one transition - with
	// the epoch already claimed by the newer event.
	if superseded && !ownedByThisUpdate {
		// The flag may still have been armed by the superseding notification, which is exactly what
		// must survive for its own update to consume.
		return
	}

	if environmentChanged || ownedByThisUpdate {
		// One transition, one epoch: the two reasons above describe the same physical event, so
		// claiming the epoch once here costs exactly one advance whichever of them fired.
		r.beginTransition()
		r.resetNetworkLocked(ctx)
	}
}

func (r *NetworkManager) notifyWindowsPowerEvent(event int) {
	switch event {
	case winpowrprof.EVENT_SUSPEND:
		r.pauseManager.DevicePause()
		r.cancelPowerUpdate()
		r.ResetNetwork(r.startedCtx)
	case winpowrprof.EVENT_RESUME:
		if !r.pauseManager.IsDevicePaused() {
			return
		}
		fallthrough
	case winpowrprof.EVENT_RESUME_AUTOMATIC:
		r.pauseManager.DeviceWake()
		updateContext, updateCancel := context.WithCancel(r.startedCtx)
		r.powerUpdateAccess.Lock()
		previousCancel := r.powerUpdateCancel
		r.powerUpdateCancel = updateCancel
		r.powerUpdateAccess.Unlock()
		if previousCancel != nil {
			previousCancel()
		}
		go func() {
			r.resetRunAccess.Lock()
			defer r.resetRunAccess.Unlock()
			if updateContext.Err() != nil {
				return
			}
			r.beginTransition()
			r.resetNetworkLocked(updateContext)
		}()
	}
}

func (r *NetworkManager) cancelPowerUpdate() {
	r.powerUpdateAccess.Lock()
	previousCancel := r.powerUpdateCancel
	r.powerUpdateCancel = nil
	r.powerUpdateAccess.Unlock()
	if previousCancel != nil {
		previousCancel()
	}
}

func (r *NetworkManager) OnPackagesUpdated(packages int, sharedUsers int) {
	r.logger.Info("updated packages list: ", packages, " packages, ", sharedUsers, " shared users")
}
