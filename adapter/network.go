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
