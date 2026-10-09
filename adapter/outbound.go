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

// BypassableOutbound reports whether this outbound may be skipped entirely for a connection to a
// literal destination, letting the platform's own direct path carry the traffic.
//
// # What it answers, and what it does not
//
// It answers ONE question: "is this outbound, for THIS network and THIS literal destination,
// equivalent to connecting directly?" The destination is part of the answer because a dial option
// only disqualifies a flow if the userspace path would actually apply it to that flow - a domain
// resolver is not a reason to refuse a literal destination, and tcp_fast_open is not a reason to
// refuse a UDP flow.
//
// It knows nothing about the request it is serving, and it must not guess: an outbound cannot see
// FakeIP state, sniffed domains, destination rewrites, trackers or how it was selected.
//
// Whether a particular connection may take the fast path is therefore decided by the router,
// which does have that context. The split matters because the dangerous mistakes are all
// request-level, not outbound-level - an outbound that tried to decide alone would have to
// assume, and assuming is how a FakeIP address reaches the real network.
//
// # Who implements it
//
// Only an outbound whose behaviour is provably identical to a plain OS connect for the
// destination in question. A proxy, a group, an endpoint with its own socket handling, or a
// direct outbound configured with bind addresses, routing marks, TFO/MPTCP, network strategy or
// any other dial semantic must NOT implement it: bypassing those would silently discard
// configuration the user asked for.
type BypassableOutbound interface {
	Outbound
	// CanBypass reports whether a connection over this network to this literal destination may
	// bypass the userspace data path.
	//
	// A false result is always safe and always available. Implementations must return false
	// whenever they cannot prove equivalence.
	CanBypass(network string, destination netip.Addr) bool
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
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}

type IdleConnectionKeeper interface {
	SetKeepIdleConnections(keep bool)
	CloseIdleConnections()
}

// ReuseSuspect is implemented by a reusable pool that can refuse NEW work on the resources it holds
// now while the work already on them finishes.
//
// # Why this is not a method on IdleConnectionKeeper
//
// The two answer different questions, and the difference is real rather than a matter of taste, so a
// pool is allowed to implement either without the other:
//
//   - CloseIdleConnections is the TRIM action: drop what nobody is using. It must not be able to
//     make the next demand dial a different connection, or a memory pass becomes a reconnect
//     trigger, which is the shape the lifecycle model forbids.
//   - RetireSuspect is the REUSE BOUNDARY action. A resource that predates the last sleep is no
//     longer trusted, so new work must not be multiplexed onto it - and work already on it must not
//     be disturbed either, because the boundary exists to stop new stalls, not to break running
//     transfers.
//
// For an ordinary HTTP pool the two coincide, and its CloseIdleConnections is already the boundary
// action. The case that separates them is a MULTIPLEXED session with a stream still open on it. The
// pool cannot close that session - the stream would lose its transport - and it must not keep handing
// it new streams, because an open stream is not proof that the path survived the sleep: a stream can
// be open and silent across one (a paused response body, a UDP-over-TCP session between packets), so
// the session is unverified whatever its stream count says. Draining is the only action that is
// neither of those two wrong things. See transport/v2rayxhttp for the implementation.
//
// A pool that does not implement this is not thereby broken: the reference manager's boundary walk
// falls back to CloseIdleConnections for it, which is what every pool did before this interface
// existed.
type ReuseSuspect interface {
	// RetireSuspect refuses new work on every resource the pool holds at the call, and closes the
	// ones that are carrying nothing. A resource still carrying work keeps it and is torn down when
	// that work finishes. It must not dial and must not terminate work in progress.
	RetireSuspect()
}

type Referrer interface {
	References() []string
}
