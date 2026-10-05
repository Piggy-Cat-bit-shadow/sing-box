# Release change surface

What this release actually changes, so that review and debugging can be aimed rather than spread
evenly over the tree. It is derived from the commits, not from intent.

## Load balance group

| area | change |
|---|---|
| adapter interfaces | **new optional capability** `FlowAwareOutboundGroup.SelectForFlow`; `OutboundGroup` itself unchanged, so no existing group or caller moved |
| outbound registry | new type `loadbalance` registered in `include/registry.go` |
| option registry | `option.LoadBalanceOutboundOptions`, and `docs/schema.json` regenerated from it |
| router | `resolveOutbound` gained a commit flag; the TCP and UDP call sites commit, the pre-match preview does not |
| PreMatch | a preview that consumes nothing; the branch whose verdict owns the port now performs its own committing resolution |
| OutboundChain | written by the existing code path; the chain's leaf is the member that was dialed, which is asserted end to end |
| tracker | unchanged; it consumes the chain the resolver produced |
| group lifecycle | start resolves members, close releases the measurement engine it composes |
| health | **reuses** the urltest measurement store and scope; no second health system |
| control API | Clash API omits `now` for a flow-aware group, the native API leaves `selected` empty |
| config | one new outbound type; existing configurations are unaffected |
| data plane | **not** wrapped: the group returns a member's own connection and is out of the path after one selection |

## This round

| area | change |
|---|---|
| `route/splice.go`, `route/conn.go`, `route/splice_diagnostics.go` | per-connection TCP splice outcome, recorded once on every path; one atomic add per connection, no per-byte work |
| `route/route.go` | the action-to-route-options decision moved into one function that both passes call, fixing a pre-match/full-match divergence for `bypass` without an outbound |
| `protocol/tun` | tests only: the v4-mapped ingress boundary pinned in the negative direction (NAT64 and IPv4-compatible are not unmapped) |
| Apple client (submodule) | presentation only: secondary destinations, the desktop detail column, the native log surface; no kernel, tunnel, libbox, profile or signing change |

## Deliberately not changed

Traffic class and traffic scheduler behaviour, the direct fast path's eligibility rules, the DNS and
FakeIP policy order, `ActionBypass` semantics, the pinned sing-tun, and the profile serialization
format. The load balance group is a control-plane selector; where it appears in a chain, the leaf
still owns the connection.
