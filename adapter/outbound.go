package adapter

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Network() []string
	Dependencies() []string
	N.Dialer
}

type OutboundWithPreferredRoutes interface {
	Outbound
	PreferredDomain(metadata *InboundContext, domain string) bool
	PreferredAddress(metadata *InboundContext, address netip.Addr) bool
}

type OutboundWithMultiplex interface {
	Outbound
	MultiplexEnabled() bool
}

// ConnectionCopyTuner is an OPTIONAL capability an outbound may implement to tune
// how the route layer copies bytes for connections through it.
//
// It exists for a CHAINED hop: when the final outbound is itself a proxy, the
// connection carries an extra segment, and waiting for the framework's default byte
// threshold before growing the copy buffer delays the point at which the larger
// buffer starts paying off.
//
// It is deliberately a capability rather than a check on a tag or a username. A tag
// is configuration, so keying on one would make behaviour depend on what an operator
// happened to name an outbound; keying on the capability means only an outbound that
// explicitly opted in is affected, and every other outbound - including every other
// SOCKS outbound - keeps the default.
//
// Implementations report the setting the operator chose. Returning false means "use
// the framework default", never "use zero".
type ConnectionCopyTuner interface {
	Outbound
	EarlyConnectionBufferGrowth() bool
}

type FlowOutbound interface {
	Outbound
	tun.Port
	PreMatchFlow(network string, destination netip.Addr) PreMatchAction
}

type OutboundRegistry interface {
	option.OutboundOptionsRegistry
	CreateOutbound(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) (Outbound, error)
}

type OutboundManager interface {
	Lifecycle
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	Default() Outbound
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}

type IdleConnectionKeeper interface {
	SetKeepIdleConnections(keep bool)
	CloseIdleConnections()
}

type Referrer interface {
	References() []string
}
