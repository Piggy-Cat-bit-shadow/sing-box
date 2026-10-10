package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
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
	if err = validateTunnelMTU(options.MTU, options.Address, options.MTUBoundedBy, options.MTUBoundedRequired); err != nil {
		return nil, err
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
	// An endpoint with no dialer has no way to reach the network at all, and the bind it would build
	// from it (ClientBind, since a nil dialer cannot provide the listener capability) would fail
	// later, from wireguard-go's own goroutines. Refusing here reports it as the configuration error
	// it is, before a tun stack and a device have been built for a tunnel that cannot carry a packet.
	if e.options.Dialer == nil {
		return E.New("missing dialer for wireguard endpoint")
	}
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
		// The IPC configuration is NOT included, and that is the point.
		//
		// # What was leaking
		//
		// This returned `E.Cause(err, "setup wireguard: \n", ipcConf.String())`, and that string
		// begins `private_key=<hex>` and carries every peer's `preshared_key=<hex>`. A failed IpcSet
		// is a ROUTINE event - a malformed allowed_ip, a key the kernel rejects, a port conflict -
		// and each one put the device's identity key and every PSK into an error that the caller
		// logs, wraps, or hands to an SDK. An operator pasting that error into a bug report, or a
		// crash reporter shipping it, would disclose the keys themselves.
		//
		// # Why the fix is not a redaction pass
		//
		// Filtering the text would mean deciding, at the point of the error, which substrings are
		// secret - and that decision is exactly the kind that goes stale: a new IPC field, a new key
		// format, a peer option that carries a token. The configuration is therefore not passed at
		// all. What is kept is everything an operator needs to locate the failure: the subsystem,
		// the underlying parser error (which names the offending FIELD, not its value), and the peer
		// count, so a multi-peer configuration can be narrowed down.
		//
		// The underlying error is NOT swallowed: it is the cause, so `errors.Is`/`errors.As` and the
		// full text still work.
		return E.Cause(err, "setup wireguard: configure device with ",
			strconv.Itoa(len(e.peers)), " peer(s); the configuration itself is deliberately omitted from "+
				"this error because it contains private key material")
	}
	if err = e.bindListenPort(wgDevice); err != nil {
		wgDevice.Close()
		return err
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

// MinimumIPv6TunnelMTU is the smallest inner IP MTU over which IPv6 can be carried, from RFC 8200
// section 5: every link on an IPv6 path must carry 1280 bytes, and a tunnel interface is a link.
//
// It is exported because protocol/wireguard has to name it too: a nested endpoint's MTU can be bounded
// by a detour's capacity, and the remedy it reports is the detour MTU that would prove this much
// capacity. One definition, read from both places, is the point.
const MinimumIPv6TunnelMTU = 1280

// minimumIPv6TunnelMTU is the in-package reading of the exported constant above, kept so the validation
// below and its tests read as they did before the export.
const minimumIPv6TunnelMTU = MinimumIPv6TunnelMTU

// validateTunnelMTU refuses a tunnel whose MTU cannot carry the addresses it is configured with.
//
// # The two cases that must NOT be conflated
//
// An MTU below 1280 is not universally illegal - it is illegal FOR IPv6, and it is a legal special
// case for an IPv4-only tunnel, where a small MTU is a legitimate way to fit a narrow path. A blanket
// floor would reject those configurations, which is why this refuses exactly one combination: an IPv6
// address configured on a tunnel whose MTU cannot carry IPv6.
//
// # What the refusal replaces
//
// Today such a configuration is accepted, and then fails per flow: sing-tun's dispatcher refuses an
// IPv6 flow whose port reports an MTU below header.IPv6MinimumMTU
// (flow_dispatch.go:502-505, `if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU <
// header.IPv6MinimumMTU { return nil, createFlowUnsupported }`), so the operator sees a flow that is
// "unsupported" rather than an MTU that is too small, and IPv4 through the same endpoint keeps
// working - which makes the real cause very hard to see. The address the operator configured is
// unreachable by construction, so the honest place to say so is construction.
//
// # Why the address list, and not the MTU alone
//
// `Address` is the tunnel's own address set, and it is what the endpoint hands to the device and
// judges flows against. An IPv6 prefix there means this endpoint is expected to carry IPv6; no IPv6
// prefix means it is an IPv4-only tunnel, whatever the MTU, and it is left exactly as it was.
func validateTunnelMTU(
	mtu uint32,
	addresses []netip.Prefix,
	// boundedBy names the `detour` whose proven capacity produced the MTU, and is empty when the value
	// is the operator's own. It changes the ADVICE, never the decision: both cases are refused, because
	// an IPv6 address is unreachable on a tunnel below 1280 whichever way the number was arrived at.
	boundedBy string,
	// boundedRequired is the `mtu` the detour would need in order to prove a capacity large enough for
	// this tunnel to carry IPv6, and is meaningful only when boundedBy is set. It is handed in rather
	// than re-derived here: the header lengths and the detour's own encapsulation are common/dialer's
	// arithmetic, and a second derivation in this package would be a second thing to keep in step.
	boundedRequired uint32,
) error {
	if mtu >= minimumIPv6TunnelMTU {
		return nil
	}
	for _, prefix := range addresses {
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			continue
		}
		if boundedBy != "" {
			// The one remediation the operator cannot perform is the one the generic message leads
			// with, so it must not be offered here at all: `mtu` is derived from `detour`, and a larger
			// configured value is clamped straight back to this same number. The reachable levers are
			// named instead, and the detour's own number is given as a value rather than as a
			// description of one, because it is the thing the operator has to go and change.
			//
			// MEASURED: a detour with a 1210-byte inner MTU produces a 1130-byte nested MTU, and the
			// detour would need 1210 + (1280 - 1130) = 1360 bytes of its own for this tunnel to carry
			// the address.
			return E.New("`mtu` ", mtu, " cannot carry the IPv6 address ", prefix.Addr(),
				": an IPv6 path requires at least ", minimumIPv6TunnelMTU,
				" bytes (RFC 8200 section 5), so the configured address is unreachable. ",
				"This MTU was not configured: it is the capacity detour `", boundedBy,
				"` proves for a tunnel nested inside it, so raising `mtu` cannot help - any larger value ",
				"is clamped back to ", mtu, ". Raise the detour's own `mtu` to at least ",
				boundedRequired, " bytes, or remove the IPv6 address to run an IPv4-only tunnel at ",
				"this MTU")
		}
		return E.New("`mtu` ", mtu, " cannot carry the IPv6 address ", prefix.Addr(),
			": an IPv6 path requires at least ", minimumIPv6TunnelMTU,
			" bytes (RFC 8200 section 5), so the configured address is unreachable. ",
			"Raise `mtu` to at least ", minimumIPv6TunnelMTU,
			", or remove the IPv6 address to run an IPv4-only tunnel at this MTU")
	}
	return nil
}

// bindListenPort brings the device up and makes a configured `listen_port` a fact of the running
// endpoint rather than a line of text in the IPC configuration.
//
// # The two failures this closes
//
// wireguard-go opens the bind from the UP transition, not from IpcSet: `BindUpdate` closes the
// existing sockets and then returns immediately when the device is not up, and the transition that
// actually opens them is driven by the tun device's event channel - an ASYNCHRONOUS goroutine
// (`device.RoutineTUNEventReader`). So `listen_port=N` reached `device.net.port` and the bind was
// opened later, off whichever goroutine happened to observe the event. Two things followed:
//
//  1. Start returned before the socket existed. The port was still free after a successful Start, so
//     the endpoint was published as ready while nothing could receive on it, and anything that
//     checked the port - a monitoring probe, a second instance starting on the same port - got the
//     answer "free" from an endpoint that was about to take it.
//  2. A bind failure was SWALLOWED. When the port was already held by another process, `IpcSet`
//     succeeded (its own BindUpdate was a no-op on a device that was not up yet), Start returned nil,
//     and the failure surfaced only later as a logged "Unable to update bind" while the device fell
//     back to down. The endpoint then had no socket at all and no error to the operator:
//     `listen_port` was configured, silently not honoured, and the tunnel was dead.
//
// # The order, and why it is this order
//
//  1. Up() - the bind is opened HERE, synchronously, and its error is returned. This is the only
//     state in which wireguard-go opens sockets, so a port that cannot be bound fails Start.
//  2. With a pinned port, read back the port the device reports and, when it is not the configured
//     one, re-apply the pin. The device's asynchronous up transition can interleave with the
//     `listen_port` line of IpcSet, and `netc.port` is assigned from the bind's own return value, so
//     a concurrent open with port 0 could replace the pinned port with an ephemeral one - silently,
//     with no error anywhere. Re-applying the pin is deterministic precisely because it runs after
//     the device is up; it happens only when the port is wrong, so the normal path opens one bind.
//  3. Verify. A dialer that cannot own a listening socket at all - ClientBind, which is the bind for a
//     detour and has no local port of its own - reports actualPort 0 instead of failing. That is a
//     capability boundary rather than a transient error, so it is reported as one: the operator asked
//     for a listening port and this endpoint cannot provide one.
//
// It deliberately does not substitute another dialer to make the bind succeed. The dialer carries the
// operator's detour, bind_interface and routing mark, and opening a listening socket on a path the
// operator did not choose would be a worse failure than refusing to start.
func (e *Endpoint) bindListenPort(wgDevice *device.Device) error {
	err := wgDevice.Up()
	if err != nil {
		return E.Cause(err, "bring up wireguard device")
	}
	actualPort := e.currentListenPort(wgDevice)
	if e.options.ListenPort == 0 {
		// Dynamic allocation: there is nothing to verify. The port the kernel chose is still worth
		// reporting, because it is the one fact about this endpoint an operator cannot otherwise see.
		if actualPort != 0 {
			e.options.Logger.Info("wireguard[", e.options.Tag, "] listening on port ", actualPort)
		}
		return nil
	}
	if actualPort != e.options.ListenPort {
		err = wgDevice.IpcSet("listen_port=" + F.ToString(e.options.ListenPort) + "\n")
		if err != nil {
			return E.Cause(err, "bind listen_port ", e.options.ListenPort)
		}
		actualPort = e.currentListenPort(wgDevice)
		if actualPort != e.options.ListenPort {
			return E.New("listen_port ", e.options.ListenPort,
				" is not bound: this endpoint's dialer cannot own a listening socket (the device reports port ",
				actualPort, ")")
		}
	}
	e.options.Logger.Info("wireguard[", e.options.Tag, "] listening on port ", actualPort)
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
