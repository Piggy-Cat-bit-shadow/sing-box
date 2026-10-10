package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	System       bool
	Handler      tun.Handler
	UDPTimeout   time.Duration
	ICMPTimeout  time.Duration
	UDPMapping   tun.NATMapping
	UDPFiltering tun.NATFiltering
	UDPNATMax    uint32

	InterfaceFinder   control.InterfaceFinder
	EgressPoolOptions tun.UDPEgressPoolOptions
	Dialer            N.Dialer
	CreateDialer      func(interfaceName string) N.Dialer
	Tag               string
	Name              string
	MTU               uint32
	// MTUBoundedBy names the `detour` whose proven capacity set MTU, and is empty when MTU is the
	// operator's own value.
	//
	// # Why the transport layer has to be told this
	//
	// It is not a second source of truth for the number: MTU stays the only value used. It exists
	// because the two cases need DIFFERENT remedies when the MTU cannot carry a configured IPv6
	// address. An MTU the operator chose is theirs to raise, and validateTunnelMTU says so. An MTU a
	// lower tunnel's capacity produced cannot be raised at all - a larger configured value is clamped
	// straight back down to that capacity, which is the whole point of the clamp - so the operator is
	// left holding a refusal that names a number they cannot change, and nothing names the detour that
	// produced it. MEASURED: a detour with a 1210-byte inner MTU yields a nested MTU of
	// 1210 - 48 - 32 = 1130, and every configured value from 0 to 1500 is clamped back to 1130.
	MTUBoundedBy string
	// MTUBoundedRequired is the detour's own `mtu` that would make MTU enough to carry an IPv6 address,
	// and is meaningful only when MTUBoundedBy is set.
	//
	// It is the shortest form of the remedy: the detour must prove a capacity of at least
	// minimumIPv6TunnelMTU for a nested tunnel, and the capacity it proves is its own MTU minus the
	// headers and its own encapsulation - a difference this layer is told, not one it re-derives. It is
	// only meaningful for the IPv6 case, which is the only case this refusal is about.
	MTUBoundedRequired uint32
	Address            []netip.Prefix
	PrivateKey         string
	ListenPort         uint16
	ResolvePeer        func(domain string) ([]netip.Addr, error)
	Peers              []PeerOptions
	Workers            int
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
	Reserved                    []uint8
}
