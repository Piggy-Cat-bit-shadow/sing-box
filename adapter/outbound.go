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

// CopyBufferGrowthTuner is an OPTIONAL capability a WRITER may implement to request
// that the copy feeding it grows its buffer early.
//
// # Why this lives on the writer rather than on the connection
//
// The route layer copies in two directions, and each direction calls
// bufio.CopyWithIncreateBuffer(destination, source, increaseBufferAfter, ...). The
// reason to grow early is a property of the DESTINATION writer: a writer with a large
// MTU or a padding geometry only benefits from a bigger buffer when the buffer matches
// that geometry.
//
// The threshold used to be derived from the connection's inbound type and then applied
// to BOTH directions. For Native Naive that was wrong in one of them: the padded writer
// is on the download side (target -> client), so Naive's own tuning correctly applied
// there. On the upload side (client -> target) the destination is an ordinary TCP or
// SOCKS writer with no such geometry, yet it received the Naive threshold too and grew
// early with nothing to gain.
//
// Implementing this interface lets a writer opt IN for exactly the copy that feeds it.
// A writer that does not implement it - every ordinary net.Conn, every SOCKS conn -
// keeps bufio.DefaultIncreaseBufferAfter, which is upstream behaviour.
//
// Returning false means "use the framework default", never "use zero".
type CopyBufferGrowthTuner interface {
	EarlyCopyBufferGrowth() bool
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
