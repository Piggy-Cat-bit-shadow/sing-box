package adapter

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type NetworkManager interface {
	Lifecycle
	Initialize(ruleSets []RuleSet)
	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	DefaultNetworkInterface() *NetworkInterface
	NetworkInterfaces() []NetworkInterface
	NetworkEnvironment() uint64
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	ProtectFunc() control.Func
	DefaultOptions() NetworkOptions
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	AutoRedirectOutputMarkFunc() control.Func
	RegisterBridgeInterface(interfaceName string)
	BridgeInterfaces() []string
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	NeedWIFIState() bool
	WIFIState() WIFIState
	UpdateWIFIState(ctx context.Context)
	ResetNetwork(ctx context.Context)
	ReleaseMemory(ctx context.Context)
}

// NetworkResetCounter is implemented by a network manager that can report how many network resets
// have run.
//
// # Why this is a counter and not a timestamp
//
// A pre-reset network operation - a dial, a listen - can succeed after the network has changed. The
// only way to tell whether the connection it produced still belongs to the current network is to
// compare the epoch it STARTED in against the epoch that is current when ownership is handed over.
// A timestamp cannot do that: two resets in quick succession, or a reset that happens to fall in the
// same clock tick, would be indistinguishable.
//
// # Why it is optional
//
// It is a capability rather than a method on NetworkManager. Every implementation and every test mock
// would otherwise have to grow a counter it does not care about, and a manager that cannot report an
// epoch is one where the ownership check simply does not apply - which is the correct degradation,
// not a compile error.
type NetworkResetCounter interface {
	// NetworkResetGeneration returns a value that increases every time a network reset BEGINS.
	//
	// It is advanced as the reset's first statement, not on completion, so that a network operation
	// running while a reset starts is already stale rather than being compared against the epoch it
	// was started under. It is therefore a reset epoch, not a count of finished resets.
	NetworkResetGeneration() uint64
}

// NetworkTransitionState reports whether the network is in the middle of a transition.
//
// # Why an epoch alone is not enough
//
// A monotonic epoch distinguishes "before" from "after". It cannot describe the state in between,
// and that state is not the same as either. While a transition is pending - the new environment is
// published, the ownership epoch has advanced, but the reset body has not yet run - the DNS
// generation has not moved and the transport pins still name the old network. An operation started
// there captures the NEW epoch, so an epoch comparison says it is current, while everything it can
// observe about the network still belongs to the old one. Handing it over is how the new network's
// answer ends up filed under the old network's namespace.
//
// The three states an operation must be able to tell apart are therefore:
//
//	stable A        the last transition committed; operations proceed normally
//	transitioning   a transition is pending; operations must not be accepted as stable results
//	stable B        the transition committed; operations proceed normally
//
// # Why it is a separate capability
//
// Like NetworkResetCounter, this is optional: a manager that cannot report it is one where the
// distinction does not arise, and every test mock would otherwise have to grow state it has no use
// for. A manager implementing only NetworkResetCounter keeps its previous behaviour exactly.
type NetworkTransitionState interface {
	// NetworkTransitionStable reports whether the network is currently in a settled state.
	//
	// It returns false from the moment a transition claims ownership until the reset body has
	// completed, and true otherwise.
	NetworkTransitionStable() bool
}

// NetworkTransitionSnapshotter reports the transition epoch and the settled state as ONE observation.
//
// # Why reading them separately is not equivalent
//
// A consumer needs both: the epoch to reject an operation that began before a transition, and the
// settled state to reject one that began during. Reading them as two calls lets the pair tear:
//
//	startedStable = true      <- read first
//	                          <- a transition begins here
//	capturedEpoch = R2        <- reads the NEW epoch
//
// The consumer then records "started settled, epoch R2", which is the state of an operation begun
// AFTER the transition - so an operation that actually began during the DURING window is recorded as
// a valid stable one, and the commit that follows accepts it. That is the unsafe direction.
//
// The manager can produce both values inside its own ownership critical section, so the pair is
// always a state the network really passed through. A manager that does not implement this keeps the
// two-call behaviour, which is no worse than before.
type NetworkTransitionSnapshotter interface {
	// NetworkTransitionSnapshot returns the current transition epoch and whether the network is
	// settled, as a single consistent observation.
	NetworkTransitionSnapshot() (epoch uint64, stable bool)
}

type NetworkOptions struct {
	BindInterface        string
	RoutingMark          uint32
	DomainResolver       string
	DomainResolveOptions DNSQueryOptions
	NetworkStrategy      *C.NetworkStrategy
	NetworkType          []C.InterfaceType
	FallbackNetworkType  []C.InterfaceType
	FallbackDelay        time.Duration
}

type InterfaceUpdateListener interface {
	InterfaceUpdated(ctx context.Context)
}

type WIFIState struct {
	SSID  string
	BSSID string
}

func NormalizeWIFIBSSID(bssid string) string {
	bssid = strings.TrimSpace(bssid)
	if bssid == "" {
		return ""
	}
	parsed, err := net.ParseMAC(bssid)
	if err == nil && len(parsed) == 6 {
		return parsed.String()
	}
	if len(bssid) == 12 {
		decoded, err := hex.DecodeString(bssid)
		if err == nil {
			return net.HardwareAddr(decoded).String()
		}
	}
	return bssid
}

type NetworkInterface struct {
	control.Interface
	Type             C.InterfaceType
	DNSServers       []string
	DNSSearchDomains []string
	Gateways         []netip.Addr
	Expensive        bool
	Constrained      bool
}
