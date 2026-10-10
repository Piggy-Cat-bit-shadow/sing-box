package dialer

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// DestinationOwnership is the shared answer to "may this destination domain be handed to the peer".
//
// # Why it lives here rather than in each protocol
//
// Two outbound protocols can put a destination domain on the wire as a NAME: SOCKS5 (ATYP=DOMAIN) and
// HTTP CONNECT (a hostname authority). They are implemented in different packages with different
// request builders, but the DECISION is the same one, made from the same option, and it has to give
// the same answer on every wire path of both. A second copy of the rule is how one protocol ends up
// enforcing ownership on its stream path and not on its packet path - which is exactly the defect that
// existed in protocol/socks, where the stream path resolved locally and the UoT branch returned before
// the resolution ran at all.
//
// The type holds only what the decision needs: the declaration, the router to ask, and the resolver
// policy. It deliberately does not own the dialer, the client, or any retry state - those stay with the
// protocol, which is the only layer that knows its own wire format.
type DestinationOwnership struct {
	// Declared reports whether the operator declared this outbound a downstream physical hop. When it
	// is false every method here is a no-op and the previous behaviour is preserved exactly.
	Declared bool
	// Router resolves the destination. It is required when Declared is true, because a declaration
	// with nothing to resolve through must fail closed rather than forward the name.
	Router adapter.DNSRouter
	// QueryOptions is the TARGET resolver policy, derived from the outbound's own DialerOptions.
	//
	// It is deliberately the target policy and not the node policy: a node address and a destination
	// address are different questions, and the operator configures them separately.
	QueryOptions adapter.DNSQueryOptions
}

// Lookup resolves a destination domain, or reports that ownership does not apply.
//
// The three answers, and why "no answer" is not one of them:
//
//   - not declared: (nil, false, nil). The destination travels unchanged. This is every ordinary
//     single-hop proxy, where the peer's own resolver is the better one because it sits in the
//     destination's region.
//   - declared, the destination is already an address: (nil, false, nil). There is nothing to own, and
//     a reverse lookup would be inventing a name.
//   - declared, the destination is a domain: the addresses are returned, or an ERROR is returned.
//
// A failed lookup does NOT fall through to sending the domain. Falling through would hand the name to
// the peer after the configuration said not to, which is the silent remote resolution this option
// exists to forbid; failing closed is the only answer that keeps the contract readable from the
// failure. An empty answer is the same case as a failure, for the same reason.
func (o DestinationOwnership) Lookup(ctx context.Context, destination M.Socksaddr) ([]netip.Addr, bool, error) {
	if !o.Declared || !destination.IsDomain() {
		return nil, false, nil
	}
	if o.Router == nil {
		return nil, false, E.New("destination DNS ownership is enabled for this outbound but no DNS ",
			"router is available to resolve ", destination.Fqdn)
	}
	addresses, err := o.Router.Lookup(ctx, destination.Fqdn, o.QueryOptions)
	if err != nil {
		return nil, false, E.Cause(err, "resolve destination ", destination.Fqdn,
			" locally, as destination DNS ownership requires; the name is deliberately NOT sent to ",
			"the peer")
	}
	if len(addresses) == 0 {
		return nil, false, E.New("no address for destination ", destination.Fqdn,
			"; destination DNS ownership forbids forwarding the unresolved name to the peer")
	}
	return addresses, true, nil
}

// NewDestinationOwnership builds the decision from an outbound's options and its resolved target
// policy.
//
// targetQueryOptions is passed in rather than derived here so this helper cannot become a second
// derivation of the resolver policy: the caller already derives it once at construction, and the
// helper only decides what to do with it.
func NewDestinationOwnership(ctx context.Context, options option.DialerOptions, router adapter.DNSRouter, targetQueryOptions adapter.DNSQueryOptions) DestinationOwnership {
	return DestinationOwnership{
		Declared:     options.DestinationDNSOwnership,
		Router:       router,
		QueryOptions: targetQueryOptions,
	}
}
