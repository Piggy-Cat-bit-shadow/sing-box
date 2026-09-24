package route

import (
	"context"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// packetDestinationGuard enforces the route policy against the destination of
// EVERY datagram, not just the destination the packet session was created with.
//
// Why this exists: a UDP-over-TCP (UoT) session is authorised once, from the
// address in its request header. In the non-connect forms of UoT v1 and v2 that
// header address is only a session identifier - each datagram then carries its
// own destination. A session approved for one address could therefore send
// datagrams to a completely different one, including loopback and private
// addresses, without ever being re-checked. The same is true of any packet
// protocol that multiplexes more than one destination over a single session.
//
// The guard re-evaluates the router's own rules for each datagram's destination
// and drops anything the policy rejects, so the address actually used is always
// one the rules approved. It never rewrites a destination, never inspects
// payloads and adds no state beyond a small memo, so an allowed datagram costs
// one map lookup after the first.
type packetDestinationGuard struct {
	N.PacketConn

	router   *Router
	ctx      context.Context
	metadata adapter.InboundContext

	// sessionDestination is the destination the session was authorised with. A
	// datagram to exactly this destination (the common connect-style case) is
	// already covered by the decision made at session setup and needs no
	// second lookup.
	sessionDestination M.Socksaddr

	allowed   map[string]struct{}
	rejected  map[string]struct{}
	onReject  func(M.Socksaddr)
	rejectErr error
}

func newPacketDestinationGuard(
	ctx context.Context, router *Router, conn N.PacketConn,
	metadata adapter.InboundContext, onReject func(M.Socksaddr),
) *packetDestinationGuard {
	return &packetDestinationGuard{
		PacketConn:         conn,
		router:             router,
		ctx:                ctx,
		metadata:           metadata,
		sessionDestination: metadata.Destination,
		allowed:            make(map[string]struct{}),
		rejected:           make(map[string]struct{}),
		onReject:           onReject,
	}
}

// cacheKey identifies a destination for memoisation. The port is included
// because rules may match on it, and the address is normalised so that a
// host:port written in different-but-equivalent forms shares one entry.
func cacheKey(destination M.Socksaddr) string {
	if destination.IsDomain() {
		return "d:" + destination.Fqdn + ":" + strconv.Itoa(int(destination.Port))
	}
	address := destination.Addr
	// Unmap so an IPv4-mapped IPv6 address cannot get a distinct decision from
	// the plain IPv4 address it denotes.
	if address.Is4In6() {
		address = address.Unmap()
	}
	return "i:" + address.String() + ":" + strconv.Itoa(int(destination.Port))
}

func (g *packetDestinationGuard) permits(destination M.Socksaddr) bool {
	if !destination.IsValid() {
		// Without a usable destination there is nothing to authorise, so the
		// packet is refused rather than passed on unchecked.
		g.rejectErr = E.New("packet destination is not valid")
		return false
	}

	// The session-level decision already covers this exact destination.
	if destination == g.sessionDestination {
		return true
	}

	key := cacheKey(destination)
	if _, loaded := g.allowed[key]; loaded {
		return true
	}
	if _, loaded := g.rejected[key]; loaded {
		g.rejectErr = E.New("destination rejected by route rule: ", destination)
		return false
	}

	childMetadata := g.metadata
	childMetadata.Destination = destination
	childMetadata.DestinationAddresses = nil
	childMetadata.Domain = ""
	childMetadata.Protocol = ""
	childMetadata.RouteRule = ""
	childMetadata.RouteOutbound = ""
	childMetadata.OutboundChain = nil

	permitted, err := g.router.checkPacketDestination(g.ctx, &childMetadata)
	if err != nil {
		g.rejected[key] = struct{}{}
		g.rejectErr = err
		return false
	}
	if !permitted {
		g.rejected[key] = struct{}{}
		g.rejectErr = E.New("destination rejected by route rule: ", destination)
		return false
	}
	g.allowed[key] = struct{}{}
	return true
}

// ReadPacket decodes the next datagram and enforces the policy against ITS
// destination before the datagram is handed on.
//
// The read side is the correct enforcement point and the write side is not.
// A rejected datagram is consumed and skipped here, so no later stage of the
// copy machinery can deliver it, including the batch-writer fast paths that do
// not necessarily funnel through WritePacket.
func (g *packetDestinationGuard) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		destination, err := g.PacketConn.ReadPacket(buffer)
		if err != nil {
			return destination, err
		}
		if g.permits(destination) {
			return destination, nil
		}
		// The datagram is dropped: reset the buffer so the next read starts
		// clean, report it, and continue with the following datagram.
		buffer.Reset()
		if g.onReject != nil {
			g.onReject(destination)
		}
	}
}

// WritePacket forwards replies. It is deliberately NOT the enforcement point:
// it is kept so the guard remains a complete PacketConn, but the decision has
// already been made on the read side by the time a reply is written.
func (g *packetDestinationGuard) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return g.PacketConn.WritePacket(buffer, destination)
}

// Upstream exposes the wrapped connection so callers that need the concrete
// transport (for example to install a NAT mapping) can still reach it.
func (g *packetDestinationGuard) Upstream() any {
	return g.PacketConn
}

// checkPacketDestination reports whether the route policy accepts a datagram
// sent to this destination.
//
// It reuses the router's existing matching machinery so a guarded datagram sees
// exactly the same rules - in the same order, with the same resolve action -
// as the session it belongs to. Only rules that decide the fate of a single
// destination are consulted; a resolve action is honoured so that domain
// destinations are checked by their resolved addresses.
func (r *Router) checkPacketDestination(ctx context.Context, metadata *adapter.InboundContext) (bool, error) {
	if metadata.Destination.IsDomain() {
		// A domain destination is judged by the addresses it resolves to, the
		// same way the session-level path judges it. Resolving here (rather
		// than trusting a stale session decision) is what keeps the checked
		// address and the dialled address the same.
		addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), metadata.Destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return false, E.Cause(err, "resolve datagram destination ", metadata.Destination.Fqdn)
		}
		if len(addresses) == 0 {
			return false, E.New("no address resolved for datagram destination ", metadata.Destination.Fqdn)
		}
		metadata.DestinationAddresses = addresses
	}

	for _, rule := range r.rules {
		if !rule.Match(metadata) {
			continue
		}
		switch action := rule.Action().(type) {
		case *R.RuleActionReject:
			// Any reject is final here, matching how the packet session path
			// treats it.
			return false, nil
		case *R.RuleActionRoute:
			return true, nil
		case *R.RuleActionBypass:
			if action.Outbound != "" {
				return true, nil
			}
			continue
		case *R.RuleActionHijackDNS:
			// DNS hijacking is a session-level behaviour; a datagram does not
			// become a DNS query by being routed.
			continue
		}
	}
	// No rule decided: the default outbound applies, which is a permit.
	return true, nil
}

var _ N.PacketConn = (*packetDestinationGuard)(nil)
