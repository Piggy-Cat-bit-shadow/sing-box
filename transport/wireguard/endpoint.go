package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/netipx"
)

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	returnDevice   *returnDeviceWrapper
	device         atomic.Pointer[device.Device]
	allowedIPs     *device.AllowedIPs
	egressPool     *tun.UDPEgressPool
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
	// deviceWakeCallback is the DeviceWake half of the recovery nudge. It is separate from
	// pauseCallback because the two events mean different things; see onDeviceWake.
	deviceWakeCallback *list.Element[pause.Callback]
	stateAccess        sync.Mutex
	suspended          atomic.Bool
	networkPaused      bool
	// closing is set by Close under stateAccess. Start checks it in the same critical section, so
	// a Close that lands while the device is still being built cannot leave a live device behind
	// a closed tun, and cannot resurrect a nil device pointer after teardown.
	closing bool
	// recovery is the runtime-lifecycle state: which peers are stale, and the worker that acts on
	// it. See recovery.go and docs/fork/runtime-lifecycle-phase1.5.md.
	recovery recoveryState
	// registration is this endpoint's handle on the runtime coordinator, used to coalesce and
	// bound rebinds. It is inert (not nil) when no coordinator is installed.
	registration       *runtimecoord.Registration
	removeRegistration func()
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsDomain() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		if len(publicKeyBytes) != device.NoisePublicKeySize {
			return nil, E.New("invalid public key for peer ", peerIndex, ", required ", device.NoisePublicKeySize, " bytes, got ", len(publicKeyBytes))
		}
		peer.publicKey = device.NoisePublicKey(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		if len(rawPeer.Reserved) > 0 {
			if len(rawPeer.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(peer.reserved))
			}
			copy(peer.reserved[:], rawPeer.Reserved[:])
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
	}, nil
}

func (e *Endpoint) Initialize(memoryPressure func() tun.MemoryPressure) error {
	e.initRecovery()
	// Registered for the endpoint's lifetime: the registration is what bounds recovery to one
	// rebind per window and makes a network change cancel a rebind that belonged to the old one.
	// The coordinator is optional, so an endpoint built without a core still works.
	if coordinator := service.FromContext[*runtimecoord.Coordinator](e.options.Context); coordinator != nil {
		e.registration, e.removeRegistration = coordinator.Register(e.RuntimeResourceLabel())
	} else {
		e.registration, e.removeRegistration = (*runtimecoord.Coordinator)(nil).Register(e.RuntimeResourceLabel())
	}
	options := e.options
	deviceOptions := DeviceOptions{
		Context:         options.Context,
		Logger:          options.Logger,
		System:          options.System,
		Handler:         options.Handler,
		UDPTimeout:      options.UDPTimeout,
		ICMPTimeout:     options.ICMPTimeout,
		UDPMapping:      options.UDPMapping,
		UDPFiltering:    options.UDPFiltering,
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: options.InterfaceFinder,
		MemoryPressure:  memoryPressure,
		CreateDialer:    options.CreateDialer,
		Name:            options.Name,
		MTU:             options.MTU,
		Address:         options.Address,
		AllowedAddress:  e.allowedAddress,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return E.Cause(err, "create WireGuard device")
	}
	e.tunDevice = tunDevice
	e.returnDevice = &returnDeviceWrapper{Device: tunDevice}
	return nil
}

func (e *Endpoint) Start(postStart bool) error {
	hasDomainPeer := common.Any(e.peers, func(peer peerConfig) bool {
		return peer.destination.IsDomain()
	})
	if postStart != hasDomainPeer {
		return nil
	}
	// Box.Close is legal at any point of Box.Start - the daemon deliberately lets a stop arrive
	// while a start is still running. The expensive part of the build runs OUTSIDE stateAccess so
	// a concurrent Close is not held up by it, and the publish step at the end re-checks the
	// closing flag under the lock: a start that lost the race closes what it built instead of
	// publishing a live device on top of a torn-down endpoint.
	//
	// Holding the lock across the whole build was the first shape of this fix, and it is wrong:
	// wgDevice.IpcSet brings the device up, which runs the pause/network callbacks, and those
	// take the same lock - a self-deadlock.
	var bind conn.Bind
	udpListener, isUDPListener := common.Cast[dialer.UDPListener](e.options.Dialer)
	if isUDPListener {
		listenerControl, egressEnabled := udpListener.UDPListenerControl()
		// Only the bind gets the family-tolerant view. The egress pool keeps the raw control,
		// where a per-member failure is already tolerated by the pool itself.
		standardBind := conn.NewStdNetBind(familyTolerantListenerControl(listenerControl)).(*conn.StdNetBind)
		if e.options.ListenPort == 0 && len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			standardBind.SetSinglePeerMode()
		}
		if egressEnabled {
			egressPoolOptions := e.options.EgressPoolOptions
			egressPoolOptions.Control = listenerControl
			e.egressPool = tun.NewUDPEgressPool(egressPoolOptions)
			standardBind.SetEgressProvider(e.egressPool)
		}
		powerManager := service.FromContext[*powerreport.Manager](e.options.Context)
		if powerManager != nil {
			recorder := powerManager.Recorder()
			if recorder != nil {
				attribution := &powerreport.Attribution{Endpoint: e.options.Tag}
				counter := recorder.TrafficCounter(powerreport.TrafficEndpoint, e.options.Tag)
				standardBind.SetIOActivityFuncs(func(size int) {
					counter.CountIn(int64(size))
					recorder.Touch(powerreport.DirectionInbound, size, attribution)
				}, func(size int) {
					counter.CountOut(int64(size))
					recorder.Touch(powerreport.DirectionOutbound, size, attribution)
				})
			}
		}
		bind = standardBind
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		if len(e.peers) == 1 {
			reserved = e.peers[0].reserved
			if e.peers[0].endpoint.IsValid() {
				isConnect = true
				connectAddr = e.peers[0].endpoint
			}
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr, reserved)
	}
	if isUDPListener || len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.endpoint.IsValid() && peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.options.Context, e.returnDevice, bind, logger, e.options.Workers)
	domainPeers := make(map[device.NoisePublicKey]*peerConfig)
	for peerIndex, peer := range e.peers {
		if peer.destination.IsDomain() {
			domainPeers[peer.publicKey] = &e.peers[peerIndex]
		}
	}
	if len(domainPeers) > 0 {
		wgDevice.SetEndpointResolverFunc(func(publicKey device.NoisePublicKey) ([]conn.Endpoint, error) {
			peer, found := domainPeers[publicKey]
			if !found {
				return nil, nil
			}
			addresses, lookupErr := e.options.ResolvePeer(peer.destination.Fqdn)
			if lookupErr != nil {
				return nil, lookupErr
			}
			endpoints := make([]conn.Endpoint, 0, len(addresses))
			for _, address := range addresses {
				destination := netip.AddrPortFrom(address, peer.destination.Port)
				if peer.reserved != ([3]uint8{}) {
					bind.SetReservedForEndpoint(destination, peer.reserved)
				}
				endpoint, parseErr := bind.ParseEndpoint(destination.String())
				if parseErr != nil {
					return nil, parseErr
				}
				endpoints = append(endpoints, endpoint)
			}
			return endpoints, nil
		})
	}
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	for _, peer := range e.peers {
		ipcConf.WriteString(peer.GenerateIpcLines())
	}
	err = wgDevice.IpcSet(ipcConf.String())
	if err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
	}
	wgPeers := make([]*device.Peer, 0, len(e.peers))
	for _, peer := range e.peers {
		wgPeer, loaded := wgDevice.LookupActivePeer(peer.publicKey)
		if loaded {
			wgPeers = append(wgPeers, wgPeer)
		}
	}
	e.stateAccess.Lock()
	if e.closing {
		// Close ran while this device was being built. Nothing was published, so nothing owns the
		// device: close it here rather than leaving it running against a torn-down endpoint.
		e.stateAccess.Unlock()
		wgDevice.Close()
		return os.ErrClosed
	}
	e.tunDevice.SetDevice(wgDevice, wgPeers)
	e.device.Store(wgDevice)
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		// Registered under the lock so a Close that is already waiting sees the callbacks and
		// unregisters them, instead of leaving them live on a closed endpoint.
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
		e.deviceWakeCallback = e.pause.RegisterCallback(e.onDeviceWake)
	}
	e.allowedIPs = wgDevice.AllowedIPs()
	e.stateAccess.Unlock()

	// Observe session transitions. Set AFTER the initial IpcSet, so the configuration's own
	// handshake start is already accounted for, and before any traffic can drive a retry.
	//
	// The callback contract is strict (see sessionStateChanged): cheap, serialized per peer, and it
	// must not call back into Device. It records state and nudges the recovery worker; nothing else.
	wgDevice.SetSessionStateFunc(e.sessionStateChanged)
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	if err := e.resumeForCaller(ctx); err != nil {
		return nil, err
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

// resumeForCaller wakes a suspended endpoint only for a caller that is allowed to.
//
// # Why a background probe may not wake it
//
// A suspended endpoint has been released deliberately - nothing references it, or the device is
// paused - so its device is down. A periodic health check that woke it would spin up a tunnel
// engine for a measurement, which is the opposite of what the idle policy is for, and it would also
// mean the device never stays idle. The probe therefore fails, with a sentinel the health layer
// recognises, and the endpoint's existing health evidence is left alone: "not measured" is not
// "unhealthy".
//
// Real device traffic never reaches here. A flow the device asked for is handed to the endpoint's
// own tun path, which is where demand wakes it.
func (e *Endpoint) resumeForCaller(ctx context.Context) error {
	if !e.suspended.Load() {
		return nil
	}
	if adapter.IsBackgroundProbe(ctx) {
		return adapter.ErrResourceSuspended
	}
	e.resume()
	return nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	if err := e.resumeForCaller(ctx); err != nil {
		return nil, err
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) SetIdle(idle bool) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	if idle {
		if e.suspended.Load() {
			return
		}
		e.suspended.Store(true)
		wgDevice.Down()
	} else {
		e.resumeLocked(wgDevice)
	}
}

func (e *Endpoint) resume() {
	if !e.suspended.Load() {
		return
	}
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	e.resumeLocked(wgDevice)
}

func (e *Endpoint) resumeLocked(wgDevice *device.Device) {
	if !e.suspended.Load() {
		return
	}
	e.suspended.Store(false)
	if !e.networkPaused {
		wgDevice.Up()
	}
}

func (e *Endpoint) Close() error {
	// The closing flag is set under the lock Start takes to publish a device. A start that is
	// still building sees it at that point and closes what it built instead of publishing it, so
	// a Close landing mid-start cannot leave a live device behind a closed tun.
	// Stop recovery first: a rebind must not be able to reopen a socket on an endpoint that is
	// going away. The flag is set under the lock the worker reads, and the worker also observes the
	// context, so this cannot leave a rebind in flight.
	e.closeRecovery()
	if e.removeRegistration != nil {
		e.removeRegistration()
		e.removeRegistration = nil
	}
	e.stateAccess.Lock()
	e.closing = true
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
		e.pauseCallback = nil
	}
	if e.deviceWakeCallback != nil {
		e.pause.UnregisterCallback(e.deviceWakeCallback)
		e.deviceWakeCallback = nil
	}
	wgDevice := e.device.Swap(nil)
	if wgDevice != nil {
		wgDevice.Down()
		wgDevice.Close()
	}
	e.stateAccess.Unlock()

	if e.egressPool != nil {
		e.egressPool.Close()
		e.egressPool = nil
	}
	if wgDevice != nil {
		return nil
	}
	return common.Close(e.tunDevice)
}

func (e *Endpoint) Lookup(address netip.Addr) *device.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.LookupFromPacket(netip.Addr{}, address, nil)
}

func (e *Endpoint) BindUpdate() error {
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return nil
	}
	return wgDevice.BindUpdate()
}

func (e *Endpoint) onPauseUpdated(event int) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	switch event {
	case pause.EventNetworkPause:
		e.networkPaused = true
		wgDevice.Down()
	case pause.EventNetworkWake:
		e.networkPaused = false
		if !e.suspended.Load() {
			wgDevice.Up()
		}
	}
}

// onDeviceWake is the consumer's nudge (trigger 3 of the recovery contract).
//
// # Why this is a separate callback from onPauseUpdated
//
// They are different events with different meanings. EventNetworkWake says the routing environment
// came back; EventDeviceWake says the DEVICE woke - the foreground/background transition the Apple
// and Android clients drive through PauseManager.DeviceWake. A tunnel that slept through a device
// wake is precisely the field case LX 041 was written for: the handshake is still retrying into a
// flow the sleep destroyed, and the user is looking at the screen.
//
// The nudge applies the same stale predicate as the other triggers, so a healthy session costs
// nothing, and it skips a suspended endpoint, so it cannot spin up a tunnel the idle policy
// released.
func (e *Endpoint) onDeviceWake(event int) {
	switch event {
	case pause.EventDeviceWake:
		go e.rebindOnWake()
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKey       device.NoisePublicKey
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
	reserved        [3]uint8
}

func (c peerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + hex.EncodeToString(c.publicKey[:]))
	if c.endpoint.IsValid() {
		ipcLines.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive > 0 {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + F.ToString(c.keepalive))
	}
	return ipcLines.String()
}
