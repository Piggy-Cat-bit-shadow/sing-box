package route

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

var defaultPacketSniffers = []sniff.PacketSniffer{
	sniff.DomainNameQuery,
	sniff.QUICClientHello,
	sniff.STUNMessage,
	sniff.UTP,
	sniff.UDPTracker,
	sniff.DTLSRecord,
	sniff.NTP,
}

// Deprecated: use RouteConnectionEx instead.
func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan any)
	err := r.routeConnection(ctx, conn, metadata, N.OnceClose(func(it error) {
		close(done)
	}))
	if err != nil {
		return err
	}
	select {
	case <-done:
	case <-r.ctx.Done():
	}
	return nil
}

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := r.routeConnection(ctx, conn, metadata, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
}

func (r *Router) routeConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	//nolint:staticcheck
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour, loaded := r.inbound.Get(metadata.InboundDetour)
		if !loaded {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.TCPInjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not TCP injectable: ", metadata.InboundDetour)
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		injectable.NewConnection(ctx, conn, metadata, onClose)
		return nil
	}
	metadata.Network = N.NetworkTCP
	switch metadata.Destination.Fqdn {
	case mux.Destination.Fqdn:
		return E.New("global multiplex is deprecated since sing-box v1.7.0, enable multiplex in Inbound fields instead.")
	case vmess.MuxDestination.Fqdn:
		return E.New("global multiplex (v2ray legacy) not supported since sing-box v1.7.0.")
	case uot.MagicAddress:
		return E.New("global UoT not supported since sing-box v1.7.0.")
	case uot.LegacyMagicAddress:
		return E.New("global UoT (legacy) not supported since sing-box v1.7.0.")
	}
	if metadata.InboundType == C.TypeTun && metadata.Protocol == C.ProtocolDNS {
		N.CloseOnHandshakeFailure(conn, onClose, r.hijackDNSStream(ctx, conn, metadata))
		return nil
	}
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	selectedRule, _, buffers, _, err := r.matchRule(ctx, &metadata, conn, nil)
	if err != nil {
		return err
	}
	var selectedOutbound adapter.Outbound
	if selectedRule != nil {
		switch action := selectedRule.Action().(type) {
		case *R.RuleActionRoute:
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				buf.ReleaseMulti(buffers)
				return E.New("outbound not found: ", action.Outbound)
			}
		case *R.RuleActionBypass:
			if action.Outbound == "" {
				break
			}
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				buf.ReleaseMulti(buffers)
				return E.New("outbound not found: ", action.Outbound)
			}
		case *R.RuleActionReject:
			buf.ReleaseMulti(buffers)
			if action.Method == C.RuleActionRejectMethodReply {
				return E.New("reject method `reply` is not supported for TCP connections")
			}
			return action.Error(ctx)
		case *R.RuleActionHijackDNS:
			for _, buffer := range buffers {
				conn = bufio.NewCachedConn(conn, buffer)
			}
			N.CloseOnHandshakeFailure(conn, onClose, r.hijackDNSStream(ctx, conn, metadata))
			return nil
		}
	}
	if selectedRule == nil {
		selectedOutbound = r.outbound.Default()
	}
	chain, err := resolveOutbound(selectedOutbound, &metadata, N.NetworkTCP, true)
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	for _, buffer := range buffers {
		conn = bufio.NewCachedConn(conn, buffer)
	}
	if selectedRule != nil {
		metadata.RouteRule = selectedRule.String()
	}
	metadata.RouteOutbound = selectedOutbound.Tag()
	// Resolve the class BEFORE the chain is published.
	//
	// Ordering is the contract: trackers and the connection manager are handed this metadata
	// immediately below, so the class has to be final by then. Resolving afterwards would leave
	// every consumer of OutboundChain looking at an unclassified flow.
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		conn = tracker.RoutedConnection(ctx, conn, metadata, selectedRule, selectedOutbound)
	}
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	onClose = registerInterrupt(chain, conn, onClose)
	outbound := chain[len(chain)-1]
	if outboundHandler, isHandler := outbound.(adapter.ConnectionHandler); isHandler {
		outboundHandler.NewConnection(ctx, conn, metadata, onClose)
	} else {
		r.connection.NewConnection(ctx, outbound, conn, metadata, onClose)
	}
	return nil
}

// resolveOutbound walks the matched outbound down to the leaf that will carry the flow.
//
// # commit
//
// A group whose choice depends on the flow - a load balancing group - has to know whether
// the caller will own the connection this chain is for. The pre-match preview runs this
// same walk for a verdict that may be discarded when the connection is created, and a
// balancing group that consumed its rotation or wrote an affinity pin for a preview would
// spend a slot on nothing: the two walks for one flow would disagree, and one of them would
// be wrong about which member carried it.
//
// Callers that own the connection pass true; the speculative preview passes false. Groups
// without the flow-aware capability ignore the question entirely, so an existing
// configuration routes through exactly the code it did before.
func resolveOutbound(outbound adapter.Outbound, metadata *adapter.InboundContext, network string, commit bool) ([]adapter.Outbound, error) {
	chain := []adapter.Outbound{outbound}
	for {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		if flowAware, isFlowAware := group.(adapter.FlowAwareOutboundGroup); isFlowAware {
			outbound = flowAware.SelectForFlow(metadata, network, commit)
		} else {
			outbound = group.Selected(network)
		}
		if outbound == nil {
			return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", group.Tag())
		}
		chain = append(chain, outbound)
	}
	if !common.Contains(outbound.Network(), network) {
		return nil, E.New(strings.ToUpper(network), " is not supported by outbound: ", outbound.Tag())
	}
	return chain, nil
}

func registerInterrupt(chain []adapter.Outbound, closer io.Closer, onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	var removers []func()
	for _, outbound := range chain {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		removers = append(removers, group.AttachConnection(closer))
	}
	if len(removers) == 0 {
		return onClose
	}
	return N.AppendClose(onClose, func(it error) {
		for _, remove := range removers {
			remove()
		}
	})
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan any)
	err := r.routePacketConnection(ctx, conn, metadata, N.OnceClose(func(it error) {
		close(done)
	}))
	if err != nil {
		conn.Close()
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
	select {
	case <-done:
	case <-r.ctx.Done():
	}
	return nil
}

func (r *Router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := r.routePacketConnection(ctx, conn, metadata, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) || R.IsRejected(err) {
			r.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			r.logger.ErrorContext(ctx, err)
		}
	}
}

func (r *Router) routePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	// A packet connection that declares a FIXED destination takes the connected-UDP path.
	//
	// # Why this is the FIRST thing done, before anything can return early
	//
	// The capability belongs to the ORIGINAL inbound connection, and two things downstream would
	// otherwise hide it:
	//
	//   - the InboundDetour early return below, which hands the connection to another inbound
	//     before the later read was ever reached, so a detoured fixed-destination tunnel arrived
	//     with UDPConnect unset;
	//   - every wrapper the routing path applies afterwards (cache, destination guard, tracker,
	//     FakeIP NAT), none of which forward the type assertion. A read placed after them would
	//     silently stop working.
	//
	// Converting the capability into metadata here means the rest of the chain carries plain
	// state and no consumer has to know the interface exists.
	//
	// # What authorises this
	//
	// The declaration alone. It is NOT inferred from "the session seems to have one
	// destination": an ordinary SOCKS UDP session also has a destination on its first datagram,
	// and treating that as fixed would pin the session to one address.
	//
	// The per-datagram guard is what keeps a UoT session that carries a destination on EVERY
	// datagram out of the connected path: connecting it would pin the session to whichever
	// address the first datagram happened to use and break the rest. It has to be checked here
	// too, not only at the later site, because the detour return would skip that check.
	if !metadata.UoTDatagramDestinations {
		adapter.ApplyUDPConnect(&metadata, conn)
	}

	//nolint:staticcheck
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour, loaded := r.inbound.Get(metadata.InboundDetour)
		if !loaded {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.UDPInjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not UDP injectable: ", metadata.InboundDetour)
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		injectable.NewPacketConnection(ctx, conn, metadata, onClose)
		return nil
	}
	// TODO: move to UoT
	metadata.Network = N.NetworkUDP

	// Currently we don't have deadline usages for UDP connections
	/*if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewPacketConn(bufio.NewNetPacketConn(conn))
	}*/
	if metadata.InboundType == C.TypeTun && metadata.Protocol == C.ProtocolDNS {
		return r.hijackDNSPacket(ctx, conn, nil, metadata, onClose)
	}
	selectedRule, _, _, packetBuffers, err := r.matchRule(ctx, &metadata, nil, conn)
	if err != nil {
		return err
	}
	var selectedOutbound adapter.Outbound
	var selectReturn bool
	if selectedRule != nil {
		switch action := selectedRule.Action().(type) {
		case *R.RuleActionRoute:
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				N.ReleaseMultiPacketBuffer(packetBuffers)
				return E.New("outbound not found: ", action.Outbound)
			}
		case *R.RuleActionBypass:
			if action.Outbound == "" {
				break
			}
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				N.ReleaseMultiPacketBuffer(packetBuffers)
				return E.New("outbound not found: ", action.Outbound)
			}
		case *R.RuleActionReject:
			N.ReleaseMultiPacketBuffer(packetBuffers)
			if action.Method == C.RuleActionRejectMethodReply {
				return E.New("reject method `reply` is not supported for UDP connections")
			}
			return action.Error(ctx)
		case *R.RuleActionHijackDNS:
			return r.hijackDNSPacket(ctx, conn, packetBuffers, metadata, onClose)
		}
	}
	if selectedRule == nil || selectReturn {
		selectedOutbound = r.outbound.Default()
	}
	chain, err := resolveOutbound(selectedOutbound, &metadata, N.NetworkUDP, true)
	if err != nil {
		N.ReleaseMultiPacketBuffer(packetBuffers)
		return err
	}
	for _, buffer := range slices.Backward(packetBuffers) {
		conn = bufio.NewCachedPacketConn(conn, buffer.Buffer, buffer.Destination)
		N.PutPacketBuffer(buffer)
	}
	// A packet session is authorised once, from its session destination. Some
	// transports (notably the non-connect forms of UoT v1 and v2) then carry a
	// DIFFERENT destination on every datagram, so the session decision does not
	// cover them. Guard those per-datagram destinations with the same rules, so
	// a session approved for one address cannot be used to reach another -
	// which would otherwise expose loopback and internal services.
	if metadata.UoTDatagramDestinations {
		conn = newPacketDestinationGuard(ctx, r, conn, metadata, func(destination M.Socksaddr) {
			r.logger.DebugContext(ctx, "drop datagram to ", destination, ": rejected by route rule")
		})
	}
	if selectedRule != nil {
		metadata.RouteRule = selectedRule.String()
	}
	metadata.RouteOutbound = selectedOutbound.Tag()
	// Resolve the class BEFORE the chain is published.
	//
	// Ordering is the contract: trackers and the connection manager are handed this metadata
	// immediately below, so the class has to be final by then. Resolving afterwards would leave
	// every consumer of OutboundChain looking at an unclassified flow.
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	metadata.OutboundChain = chain
	for _, tracker := range r.trackers {
		conn = tracker.RoutedPacketConnection(ctx, conn, metadata, selectedRule, selectedOutbound)
	}
	if metadata.FakeIP {
		conn = newFakeIPNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	}
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	onClose = registerInterrupt(chain, conn, onClose)
	outbound := chain[len(chain)-1]
	if outboundHandler, isHandler := outbound.(adapter.PacketConnectionHandler); isHandler {
		outboundHandler.NewPacketConnection(ctx, conn, metadata, onClose)
	} else {
		r.connection.NewPacketConnection(ctx, outbound, conn, metadata, onClose)
	}
	return nil
}

func (r *Router) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	ctx := log.ContextWithNewID(r.ctx)
	metadata.PreMatch = true
	continueResult := adapter.PreMatchResult{Action: adapter.PreMatchContinue}
	packetDestination := metadata.Destination
	err := r.prepareMatchMetadata(ctx, &metadata)
	if err != nil {
		return continueResult
	}
	for currentRuleIndex, currentRule := range r.rules {
		metadata.ResetRuleCache()
		if !currentRule.Match(&metadata) {
			continue
		}
		ruleDescription := currentRule.String()
		if ruleDescription != "" {
			r.logger.DebugContext(ctx, "pre-match[", currentRuleIndex, "] ", currentRule, " => ", currentRule.Action())
		} else {
			r.logger.DebugContext(ctx, "pre-match[", currentRuleIndex, "] => ", currentRule.Action())
		}
		switch action := currentRule.Action().(type) {
		case *R.RuleActionSniff:
			if metadata.Network == N.NetworkICMP {
				continue
			}
			if metadata.Network != N.NetworkUDP || len(firstPacket) == 0 {
				return continueResult
			}
			if sniff.Skip(&metadata) || metadata.Protocol != "" {
				continue
			}
			if len(action.PacketSniffers) == 0 && len(action.StreamSniffers) > 0 {
				continue
			}
			if slices.Equal(metadata.SnifferNames, action.SnifferNames) && metadata.SniffError != nil {
				continue
			}
			packetSniffers := action.PacketSniffers
			if len(packetSniffers) == 0 {
				packetSniffers = defaultPacketSniffers
			}
			sniffErr := sniff.PeekPacket(ctx, &metadata, firstPacket, packetSniffers...)
			metadata.SnifferNames = action.SnifferNames
			metadata.SniffError = sniffErr
			if sniffErr != nil {
				if errors.Is(sniffErr, sniff.ErrNeedMoreData) {
					return continueResult
				}
				continue
			}
			//goland:noinspection GoDeprecation
			if action.OverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
			if metadata.Domain != "" && metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain, ", client: ", metadata.Client)
			} else if metadata.Domain != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain)
			} else if metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", client: ", metadata.Client)
			} else {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol)
			}
		case *R.RuleActionRouteOptions:
			applyActionRouteOptions(&metadata, action)
		case *R.RuleActionRoute:
			// Applied before the flow decision, so the metadata canFastBypass inspects matches
			// what the slow path would have seen.
			applyActionRouteOptions(&metadata, action)
			return r.preMatchFlow(ctx, &metadata, packetDestination, currentRule, action.Outbound)
		case *R.RuleActionBypass:
			// A bypass without an outbound contributes nothing, which is what keeps the verdict
			// below reachable: its own options can no longer rewrite the destination out from
			// under it.
			applyActionRouteOptions(&metadata, action)
			if action.Outbound == "" {
				if metadata.Destination.IsDomain() || metadata.Destination != packetDestination {
					return continueResult
				}
				return adapter.PreMatchResult{Action: adapter.PreMatchBypass}
			}
			if metadata.Destination.IsDomain() || metadata.Destination != packetDestination {
				return r.preMatchFlow(ctx, &metadata, packetDestination, currentRule, action.Outbound)
			}
			result := r.preMatchFlow(ctx, &metadata, packetDestination, currentRule, action.Outbound)
			if result.Action != adapter.PreMatchFlow {
				return adapter.PreMatchResult{Action: adapter.PreMatchBypass}
			}
			result.Action = adapter.PreMatchBypass
			return result
		case *R.RuleActionReject:
			rejectErr := action.Error(r.ctx)
			if rejectErr == nil && metadata.Network == N.NetworkICMP {
				return continueResult
			}
			if errors.Is(rejectErr, R.ErrDrop) {
				return adapter.PreMatchResult{Action: adapter.PreMatchDrop}
			}
			return adapter.PreMatchResult{Action: adapter.PreMatchReject}
		case *R.RuleActionHijackDNS:
			if metadata.Network != N.NetworkUDP {
				return continueResult
			}
			return adapter.PreMatchResult{Action: adapter.PreMatchHijackDNS}
		case *R.RuleActionResolve:
			resolveErr := r.actionResolve(adapter.WithContext(ctx, &metadata), &metadata, action)
			if resolveErr != nil {
				r.logger.DebugContext(ctx, "pre-match[", currentRuleIndex, "] ", currentRule, " => ", action, ": ", resolveErr)
				return adapter.PreMatchResult{Action: adapter.PreMatchReject}
			}
		default:
			return continueResult
		}
	}
	return r.preMatchFlow(ctx, &metadata, packetDestination, nil, "")
}

// applyRouteOptionsMetadata applies a route action's options to the connection metadata.
//
// # Why this is one function
//
// The pre-match path and the full match path both have to apply these options, and they used to do
// it separately: pre-match applied address, port and UDP timeout, while the full path applied
// eleven fields. The difference was invisible until the Direct Fast Path started making decisions
// in pre-match, and then it became a correctness bug - the fast path judged a connection eligible
// before options such as tls_fragment, udp_connect or a network strategy had been recorded, so a
// connection the user had explicitly configured took the native path and those options were
// silently discarded.
//
// One implementation means the two paths cannot drift again: a field added here is added for both,
// and a field that pre-match needs in order to decide correctly cannot be forgotten.
//
// It must be called BEFORE any verdict is produced, because its whole purpose is to make the
// metadata the fast path inspects identical to the metadata the slow path would have seen.
// routeOptionsForAction returns the route options an action contributes to the connection
// metadata, or nil when the action contributes none.
//
// It exists because two passes decide which actions change how a connection is handled - the
// pre-match decision and the full match path - and a connection judged in pre-match is only
// equivalent to the full path if both saw the same options. They were decided in two places and
// disagreed about exactly one case:
//
//	bypass() with no outbound
//
// The full match path applied nothing, and the pre-match pass applied the action's options. The
// pre-match behaviour was the wrong one: a bypass action without an outbound routes nothing, so
// there is no route for its options to configure, and the packet destination guard already treats
// that same action as "not a decision" and keeps looking. Applying its options anyway rewrote the
// destination before the bypass verdict was computed, the verdict's own "is this still the packet's
// destination" test then failed, and the rule silently stopped bypassing while the full path
// applied nothing at all - a flow the two passes genuinely disagreed about, with no error and no
// log.
func routeOptionsForAction(action adapter.RuleAction) *R.RuleActionRouteOptions {
	switch action := action.(type) {
	case *R.RuleActionRoute:
		return &action.RuleActionRouteOptions
	case *R.RuleActionRouteOptions:
		return action
	case *R.RuleActionBypass:
		if action.Outbound == "" {
			return nil
		}
		return &action.RuleActionRouteOptions
	default:
		return nil
	}
}

// applyActionRouteOptions applies whatever route options the action contributes, and reports
// whether it contributed any.
//
// Both passes call this and nothing else applies an action's options, so the question "which
// actions change how a connection is handled" has one answer. The field-level work stays in
// applyRouteOptionsMetadata; this is only the decision of whether to do it.
func applyActionRouteOptions(metadata *adapter.InboundContext, action adapter.RuleAction) bool {
	routeOptions := routeOptionsForAction(action)
	if routeOptions == nil {
		return false
	}
	applyRouteOptionsMetadata(metadata, routeOptions)
	return true
}

func applyRouteOptionsMetadata(metadata *adapter.InboundContext, routeOptions *R.RuleActionRouteOptions) {
	// The original destination is captured before any rewrite, and only the first time: it records
	// what the application asked for, which later rules must not overwrite.
	if (routeOptions.OverrideAddress.IsValid() || routeOptions.OverridePort > 0) && !metadata.RouteOriginalDestination.IsValid() {
		metadata.RouteOriginalDestination = metadata.Destination
	}
	if routeOptions.OverrideAddress.IsValid() {
		// A resolved address list belongs to the pre-rewrite destination.
		metadata.DestinationAddresses = nil
	}
	if routeOptions.OverrideAddress.IsValid() {
		metadata.Destination = M.Socksaddr{
			Addr: routeOptions.OverrideAddress.Addr,
			Port: metadata.Destination.Port,
			Fqdn: routeOptions.OverrideAddress.Fqdn,
		}
	}
	if routeOptions.OverridePort > 0 {
		metadata.Destination = M.Socksaddr{
			Addr: metadata.Destination.Addr,
			Port: routeOptions.OverridePort,
			Fqdn: metadata.Destination.Fqdn,
		}
	}
	if routeOptions.UDPTimeout > 0 {
		metadata.UDPTimeout = routeOptions.UDPTimeout
	}
	if routeOptions.NetworkStrategy != nil {
		metadata.NetworkStrategy = routeOptions.NetworkStrategy
	}
	if len(routeOptions.NetworkType) > 0 {
		metadata.NetworkType = routeOptions.NetworkType
	}
	if len(routeOptions.FallbackNetworkType) > 0 {
		metadata.FallbackNetworkType = routeOptions.FallbackNetworkType
	}
	if routeOptions.FallbackDelay != 0 {
		metadata.FallbackDelay = routeOptions.FallbackDelay
	}
	if routeOptions.UDPDisableDomainUnmapping {
		metadata.UDPDisableDomainUnmapping = true
	}
	if routeOptions.UDPConnect {
		metadata.UDPConnect = true
	}
	if routeOptions.TLSFragment {
		metadata.TLSFragment = true
		metadata.TLSFragmentFallbackDelay = routeOptions.TLSFragmentFallbackDelay
	}
	if routeOptions.TLSRecordFragment {
		metadata.TLSRecordFragment = true
	}
	if routeOptions.TLSSpoof != "" {
		metadata.TLSSpoof = routeOptions.TLSSpoof
		metadata.TLSSpoofMethod = routeOptions.TLSSpoofMethod
	}
}

// canFastBypass reports whether this connection may skip the userspace data path entirely, and if
// not, which condition refused it.
//
// # Allow-list, not deny-list
//
// Everything not explicitly proven safe is refused. The conditions below are the complete set of
// reasons a plain direct connection is equivalent to an OS connect; anything the router cannot see
// through - a sniffed domain, a rewritten destination, a tracker that must observe the flow -
// disqualifies the connection. A refusal costs one predicate call and falls through to exactly the
// behaviour that existed before, so being conservative is free.
//
// # The one condition that is about the FLOW rather than the configuration
//
// The last check delegates to the outbound, and the outbound answers for the flow it was handed.
// That distinction is the whole point of the owner's profile: a dial option only disqualifies a
// flow if the userspace path would actually apply it to that flow. Comparing configurations
// instead refused every flow through an outbound that carried a domain_resolver, including the
// literal-IP flows that never reach a resolver.
//
// # Ordering
//
// Cheapest and most selective first: type and string comparisons, then slice lengths, then the
// interface assertion, and the outbound's own check last because it is the only part that
// touches other state. This runs on every pre-match for every rule that routes to an outbound,
// so the common miss must not do real work.
//
// # Why the arguments
//
// packetDestination is the destination the TUN flow was created for, before any rule could
// rewrite it. Comparing against metadata.Destination is how an override, a FakeIP rewrite or a
// sniff override_destination is detected - the fast path may only carry a connection to the
// address the platform already put on the wire.
func (r *Router) canFastBypass(metadata *adapter.InboundContext, packetDestination M.Socksaddr, chain []adapter.Outbound, outbound adapter.Outbound) BypassVerdict {
	// v1 targets TUN only. ActionBypass is the platform handing the flow back to the OS's own
	// routing; other inbounds have no equivalent, so they keep their existing path.
	if metadata.InboundType != C.TypeTun {
		return BypassRefusedInboundType
	}

	// Only the two protocols the optimisation was reasoned about. ICMP keeps its existing flow
	// handling, and an unknown network is not this function's business.
	if metadata.Network != N.NetworkTCP && metadata.Network != N.NetworkUDP {
		return BypassRefusedNetwork
	}

	// A domain destination still needs resolution, so it cannot be bypassed.
	if metadata.Destination.IsDomain() {
		return BypassRefusedDomainDestination
	}

	// FakeIP addresses are placeholders belonging to the virtual range. Handing one to the OS
	// routing table would send it somewhere meaningless, and the mapping back to the real
	// destination is exactly the work the userspace path exists to do.
	if metadata.FakeIP {
		return BypassRefusedFakeIP
	}

	// A recovered or sniffed domain means this connection may use dual-stack recovery, which
	// lives in the dialer and would be skipped entirely. Preserving that behaviour is worth more
	// than the bypass.
	if metadata.Domain != "" {
		return BypassRefusedSniffedDomain
	}

	// A populated candidate list means resolve, recovery or candidate planning already took
	// part in this connection.
	if len(metadata.DestinationAddresses) > 0 {
		return BypassRefusedResolvedCandidates
	}

	// The destination must be exactly what the flow was created for. Any difference means a
	// rule rewrote it - override_address, override_port, a FakeIP rewrite, or a sniff that
	// replaced the target - and the rewritten destination is the one the userspace path must
	// dial.
	if metadata.Destination != packetDestination {
		return BypassRefusedDestinationRewritten
	}
	if metadata.RouteOriginalDestination.IsValid() {
		return BypassRefusedRouteOriginalDestination
	}

	// A UoT session carrying per-datagram destinations is not a fixed target; treating it as one
	// would pin the session to whichever address arrived first.
	if metadata.UoTDatagramDestinations {
		return BypassRefusedUoTDatagramDestinations
	}

	// Connected UDP has its own socket and NAT semantics that this optimisation does not
	// reproduce. Left on the existing path deliberately.
	if metadata.UDPConnect {
		return BypassRefusedUDPConnect
	}

	// Domain unmapping is performed by the userspace NAT path (splice and conn decide
	// unidirectional NAT from it). A native bypass never reaches that code, so the option would
	// be silently ignored for a connection that is not already an IP destination.
	if metadata.UDPDisableDomainUnmapping {
		return BypassRefusedUDPDomainUnmapping
	}

	// A custom UDP timeout is applied by the userspace UDP path. The native bypass has its own
	// lifetime semantics, so the two are not interchangeable.
	if metadata.UDPTimeout > 0 {
		return BypassRefusedCustomUDPTimeout
	}

	// Network selection, interface pinning and fallback are dialer behaviour that a bypass does
	// not perform.
	if metadata.NetworkStrategy != nil ||
		len(metadata.NetworkType) > 0 ||
		len(metadata.FallbackNetworkType) > 0 ||
		metadata.FallbackDelay > 0 {
		return BypassRefusedNetworkOptions
	}

	// TLS fragmentation and spoofing rewrite the handshake in the userspace path. Bypassing
	// would silently disable them.
	if metadata.TLSFragment || metadata.TLSRecordFragment || metadata.TLSSpoof != "" {
		return BypassRefusedTLSOptions
	}

	// A tracker observes connections; a bypassed flow would simply never appear in traffic
	// statistics or the connections API. Silently losing accounting is not an acceptable
	// optimisation, so the presence of any tracker disables the fast path for now.
	if len(r.trackers) > 0 {
		return BypassRefusedTracker
	}

	// Process metadata must have been OBTAINED, not merely absent.
	//
	// The rules above are consulted in PreMatch, which walks the whole rule set. A process rule
	// evaluated against a nil ProcessInfo does not match, so a transient lookup failure is
	// indistinguishable from "no process rule applies" - and the default direct outbound would
	// then take an irreversible bypass chosen by missing data rather than by the configuration.
	if !r.processMetadataIsProven(metadata) {
		return BypassRefusedProcessMetadataUnproven
	}

	// Only a connection that resolves to exactly one outbound, with nothing in front of it. A
	// group introduces selection, lifecycle and accounting semantics of its own, and bypassing
	// it would skip all of them even when the selected outbound happens to be direct.
	if len(chain) != 1 {
		return BypassRefusedOutboundChain
	}

	// Finally, the outbound itself must declare that it would do nothing special for this flow.
	// This is the one condition the router cannot evaluate, so it is delegated rather than
	// assumed - and it is delegated with the flow, not with the configuration: a dial option the
	// flow never reaches is not a reason to refuse.
	bypassable, isBypassable := outbound.(adapter.BypassableOutbound)
	if !isBypassable {
		return BypassRefusedOutboundNotBypassable
	}
	if !bypassable.CanBypass(metadata.Network, metadata.Destination.Addr) {
		return BypassRefusedOutboundSemantics
	}
	return BypassAllowed
}

// preMatchFlow resolves the outbound for a matched rule and decides how the flow proceeds.
func (r *Router) preMatchFlow(ctx context.Context, metadata *adapter.InboundContext, packetDestination M.Socksaddr, matchedRule adapter.Rule, outboundTag string) adapter.PreMatchResult {
	continueResult := adapter.PreMatchResult{Action: adapter.PreMatchContinue}
	var outbound adapter.Outbound
	if outboundTag == "" {
		outbound = r.outbound.Default()
	} else {
		var loaded bool
		outbound, loaded = r.outbound.Outbound(outboundTag)
		if !loaded {
			return continueResult
		}
	}
	// A preview, not a commitment: this chain decides whether the pre-match verdict can
	// bypass, and for a direct flow the verdict is discarded when the connection is
	// created and the full route resolves again. Passing false is what keeps that second
	// walk from being a second selection of the same flow.
	chain, err := resolveOutbound(outbound, metadata, metadata.Network, false)
	if err != nil {
		return continueResult
	}
	outbound = chain[len(chain)-1]

	// Direct Fast Path: a plain direct outbound with nothing special about this connection takes
	// the platform's own path instead of a userspace one.
	//
	// This sits AFTER the rule loop has decided the outbound, so rule ordering is untouched: a
	// reject, a proxy or an explicit bypass earlier in the chain has already returned, and this
	// only ever applies to a connection that a normal match settled on direct.
	//
	// It sits BEFORE the FlowOutbound branch because the whole point is to avoid creating a
	// userspace flow; discovering the flow could not be created and then backing out would
	// already have paid the cost this exists to avoid.
	//
	// On any doubt canFastBypass returns false and nothing about the previous behaviour changes.
	if r.canFastBypass(metadata, packetDestination, chain, outbound).BypassAllowed() {
		// The message is built only when it will be emitted.
		//
		// The arguments to a debug call are evaluated before the logger decides the level is off, and
		// this one is not free: AddrString allocates and the variadic slice allocates, which measured
		// at five allocations and about 95 ns per eligible flow - more than the eligibility decision
		// itself, on exactly the flows the fast path is supposed to make cheaper.
		if r.debugLogging() {
			r.logger.DebugContext(ctx, "pre-match: bypass verdict for ", metadata.Network,
				" connection from ", metadata.Source.AddrString(), " to ", metadata.Destination,
				" (honoured only where the caller can carry it natively)")
		}
		return adapter.PreMatchResult{Action: adapter.PreMatchBypass, Outbound: outbound}
	}

	flowOutbound, isFlowOutbound := outbound.(adapter.FlowOutbound)
	if !isFlowOutbound {
		return continueResult
	}
	flowAction := flowOutbound.PreMatchFlow(metadata.Network, metadata.Destination.Addr)
	if flowAction != adapter.PreMatchFlow {
		return adapter.PreMatchResult{Action: flowAction, Outbound: outbound}
	}

	// This verdict COMMITS the flow, so the choice is committed here.
	//
	// A flow port receives this result and builds the connection from it; the flow does not
	// return to this function, and for a flow-capable port it does not reach the route path
	// again either. The walk above therefore decided only that the flow CAN be given a port,
	// and this walk decides which member owns it - the only one allowed to consume a
	// balancing decision. Without it, a balancing group whose members can own a port would
	// answer every such flow with the same previewed member, because nothing ever committed.
	//
	// A committed member that cannot own a port sends the flow back to the route path, which
	// resolves once more with the same commit flag. That costs that flow one extra balancing
	// decision, and it can only happen for a group mixing port-capable and port-less members;
	// the alternative - never committing here - would leave every port-capable flow on one
	// member for the life of the group, which is the silent failure this feature exists to
	// avoid.
	committedChain, committedErr := resolveOutbound(outbound, metadata, metadata.Network, true)
	if committedErr != nil {
		return continueResult
	}
	committedOutbound := committedChain[len(committedChain)-1]
	if committedOutbound != outbound {
		committedFlowOutbound, isCommittedFlowOutbound := committedOutbound.(adapter.FlowOutbound)
		if !isCommittedFlowOutbound || committedFlowOutbound.PreMatchFlow(metadata.Network, metadata.Destination.Addr) != adapter.PreMatchFlow {
			return continueResult
		}
		outbound = committedOutbound
		flowOutbound = committedFlowOutbound
		chain = committedChain
	}
	result := adapter.PreMatchResult{Action: adapter.PreMatchFlow, Outbound: outbound}
	if metadata.Network == N.NetworkUDP {
		if metadata.UDPTimeout > 0 {
			result.UDPTimeout = metadata.UDPTimeout
		} else {
			protocol := metadata.Protocol
			if protocol == "" {
				protocol = C.PortProtocols[metadata.Destination.Port]
			}
			if protocol != "" {
				result.UDPTimeout = C.ProtocolTimeouts[protocol]
			}
		}
	}
	if metadata.Destination.IsDomain() {
		if !metadata.FakeIP {
			return continueResult
		}
		var newDestination netip.Addr
		for _, address := range metadata.DestinationAddresses {
			if address.Is4() == packetDestination.IsIPv4() {
				newDestination = address
				break
			}
		}
		if !newDestination.IsValid() {
			if len(metadata.DestinationAddresses) == 0 {
				r.logger.WarnContext(ctx, "pre-match: reject ", metadata.Network, " connection from ", metadata.Source.AddrString(), " to fake destination ", metadata.Destination.Fqdn, ": a resolve action is required before routing to outbound/", outbound.Type(), "[", outbound.Tag(), "]")
			} else {
				r.logger.DebugContext(ctx, "pre-match: reject ", metadata.Network, " connection from ", metadata.Source.AddrString(), " to fake destination ", metadata.Destination.Fqdn, ": no resolved address for this address family")
			}
			return adapter.PreMatchResult{Action: adapter.PreMatchReject}
		}
		flowAction = flowOutbound.PreMatchFlow(metadata.Network, newDestination)
		if flowAction != adapter.PreMatchFlow {
			return adapter.PreMatchResult{Action: flowAction, Outbound: outbound}
		}
		result.Destination = netip.AddrPortFrom(newDestination, metadata.Destination.Port)
	} else if metadata.Destination != packetDestination {
		result.Destination = metadata.Destination.AddrPort()
	}
	metadata.TrafficClass = resolveTrafficClass(chain, r.trafficClassPolicies)
	metadata.OutboundChain = chain
	metadataCopy := *metadata
	result.NewTracker = func() tun.FlowTracker {
		r.logger.InfoContext(ctx, "pre-match: forward ", metadataCopy.Network, " connection from ", metadataCopy.Source.AddrString(), " to ", metadataCopy.Destination.AddrString(), " via outbound/", outbound.Type(), "[", outbound.Tag(), "]")
		flowTrackers := make([]tun.FlowTracker, 0, len(r.trackers)+2)
		flowTrackers = append(flowTrackers, newFlowLogger(ctx, r.logger, metadataCopy, outbound))
		flowInterrupter := newFlowInterrupter(chain)
		if flowInterrupter != nil {
			flowTrackers = append(flowTrackers, flowInterrupter)
		}
		for _, tracker := range r.trackers {
			flowTracker := tracker.RoutedFlow(ctx, metadataCopy, matchedRule, outbound)
			if flowTracker != nil {
				flowTrackers = append(flowTrackers, flowTracker)
			}
		}
		if len(flowTrackers) == 1 {
			return flowTrackers[0]
		}
		return multiFlowTracker(flowTrackers)
	}
	return result
}

func (r *Router) prepareMatchMetadata(ctx context.Context, metadata *adapter.InboundContext) error {
	r.searchProcessInfo(ctx, metadata)
	if r.neighborResolver != nil && metadata.SourceMACAddress == nil && metadata.Source.Addr.IsValid() {
		mac, macFound := r.neighborResolver.LookupMAC(metadata.Source.Addr)
		if macFound {
			metadata.SourceMACAddress = mac
		}
		hostname, hostnameFound := r.neighborResolver.LookupHostname(metadata.Source.Addr)
		if hostnameFound {
			metadata.SourceHostname = hostname
			if macFound {
				r.logger.InfoContext(ctx, "found neighbor: ", mac, ", hostname: ", hostname)
			} else {
				r.logger.InfoContext(ctx, "found neighbor hostname: ", hostname)
			}
		} else if macFound {
			r.logger.InfoContext(ctx, "found neighbor: ", mac)
		}
	}
	if metadata.Destination.Addr.IsValid() && r.dnsTransport.FakeIP() != nil && r.dnsTransport.FakeIP().Store().Contains(metadata.Destination.Addr) {
		domain, loaded := r.dnsTransport.FakeIP().Store().Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("missing fakeip record, try enable `experimental.cache_file`")
		}
		if domain != "" {
			metadata.OriginDestination = metadata.Destination
			metadata.Destination = M.Socksaddr{
				Fqdn: domain,
				Port: metadata.Destination.Port,
			}
			metadata.FakeIP = true
			r.logger.DebugContext(ctx, "found fakeip domain: ", domain)
		}
	} else if metadata.Domain == "" {
		domain, loaded := r.dns.LookupReverseMapping(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
			r.logger.DebugContext(ctx, "found reserve mapped domain: ", metadata.Domain)
		}
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	return nil
}

func (r *Router) matchRule(
	ctx context.Context, metadata *adapter.InboundContext,
	inputConn net.Conn, inputPacketConn N.PacketConn,
) (
	selectedRule adapter.Rule, selectedRuleIndex int,
	buffers []*buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error,
) {
	fatalErr = r.prepareMatchMetadata(ctx, metadata)
	if fatalErr != nil {
		return
	}

match:
	for currentRuleIndex, currentRule := range r.rules {
		metadata.ResetRuleCache()
		if !currentRule.Match(metadata) {
			continue
		}
		ruleDescription := currentRule.String()
		if ruleDescription != "" {
			r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] ", currentRule, " => ", currentRule.Action())
		} else {
			r.logger.DebugContext(ctx, "match[", currentRuleIndex, "] => ", currentRule.Action())
		}
		if applyActionRouteOptions(metadata, currentRule.Action()) {
			// TODO: add nat
		}
		switch action := currentRule.Action().(type) {
		case *R.RuleActionSniff:
			newBuffer, newPacketBuffers, newErr := r.actionSniff(ctx, metadata, action, inputConn, inputPacketConn, buffers, packetBuffers)
			if newBuffer != nil {
				buffers = append(buffers, newBuffer)
			} else if len(newPacketBuffers) > 0 {
				packetBuffers = append(packetBuffers, newPacketBuffers...)
			}
			if newErr != nil {
				fatalErr = newErr
				return
			}
		case *R.RuleActionResolve:
			fatalErr = r.actionResolve(ctx, metadata, action)
			if fatalErr != nil {
				return
			}
		}
		actionType := currentRule.Action().Type()
		if actionType == C.RuleActionTypeRoute ||
			actionType == C.RuleActionTypeReject ||
			actionType == C.RuleActionTypeHijackDNS {
			selectedRule = currentRule
			selectedRuleIndex = currentRuleIndex
			break match
		}
		if actionType == C.RuleActionTypeBypass {
			bypassAction := currentRule.Action().(*R.RuleActionBypass)
			if bypassAction.Outbound == "" {
				continue match
			}
			selectedRule = currentRule
			selectedRuleIndex = currentRuleIndex
			break match
		}
	}
	return
}

func (r *Router) actionSniff(
	ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionSniff,
	inputConn net.Conn, inputPacketConn N.PacketConn, inputBuffers []*buf.Buffer, inputPacketBuffers []*N.PacketBuffer,
) (buffer *buf.Buffer, packetBuffers []*N.PacketBuffer, fatalErr error) {
	if sniff.Skip(metadata) {
		r.logger.DebugContext(ctx, "sniff skipped due to port considered as server-first")
		return
	} else if metadata.Protocol != "" {
		r.logger.DebugContext(ctx, "duplicate sniff skipped")
		return
	}
	if inputConn != nil {
		if len(action.StreamSniffers) == 0 && len(action.PacketSniffers) > 0 {
			return
		} else if slices.Equal(metadata.SnifferNames, action.SnifferNames) && metadata.SniffError != nil && !errors.Is(metadata.SniffError, sniff.ErrNeedMoreData) {
			r.logger.DebugContext(ctx, "packet sniff skipped due to previous error: ", metadata.SniffError)
			return
		}
		var streamSniffers []sniff.StreamSniffer
		if len(action.StreamSniffers) > 0 {
			streamSniffers = action.StreamSniffers
		} else {
			streamSniffers = []sniff.StreamSniffer{
				sniff.TLSClientHello,
				sniff.HTTPHost,
				sniff.StreamDomainNameQuery,
				sniff.BitTorrent,
				sniff.SSH,
				sniff.RDP,
			}
		}
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(
			ctx,
			metadata,
			inputConn,
			inputBuffers,
			sniffBuffer,
			action.Timeout,
			streamSniffers...,
		)
		metadata.SnifferNames = action.SnifferNames
		metadata.SniffError = err
		if err == nil {
			//goland:noinspection GoDeprecation
			if action.OverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
			if metadata.Domain != "" && metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol, ", domain: ", metadata.Domain, ", client: ", metadata.Client)
			} else if metadata.Domain != "" {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol, ", domain: ", metadata.Domain)
			} else {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol)
			}
		}
		if !sniffBuffer.IsEmpty() {
			buffer = sniffBuffer
		} else {
			sniffBuffer.Release()
		}
	} else if inputPacketConn != nil {
		if len(action.PacketSniffers) == 0 && len(action.StreamSniffers) > 0 {
			return
		} else if slices.Equal(metadata.SnifferNames, action.SnifferNames) && metadata.SniffError != nil && !errors.Is(metadata.SniffError, sniff.ErrNeedMoreData) {
			r.logger.DebugContext(ctx, "packet sniff skipped due to previous error: ", metadata.SniffError)
			return
		}
		quicMoreData := func() bool {
			return slices.Equal(metadata.SnifferNames, action.SnifferNames) && errors.Is(metadata.SniffError, sniff.ErrNeedMoreData)
		}
		var packetSniffers []sniff.PacketSniffer
		if len(action.PacketSniffers) > 0 {
			packetSniffers = action.PacketSniffers
		} else {
			packetSniffers = defaultPacketSniffers
		}
		var err error
		for _, packetBuffer := range inputPacketBuffers {
			if quicMoreData() {
				err = sniff.PeekPacket(
					ctx,
					metadata,
					packetBuffer.Buffer.Bytes(),
					sniff.QUICClientHello,
				)
			} else {
				err = sniff.PeekPacket(
					ctx, metadata,
					packetBuffer.Buffer.Bytes(),
					packetSniffers...,
				)
			}
			metadata.SnifferNames = action.SnifferNames
			metadata.SniffError = err
			if errors.Is(err, sniff.ErrNeedMoreData) {
				// TODO: replace with generic message when there are more multi-packet protocols
				r.logger.DebugContext(ctx, "attempt to sniff fragmented QUIC client hello")
				continue
			}
			goto finally
		}
		for {
			var (
				sniffBuffer = buf.NewPacket()
				destination M.Socksaddr
				done        = make(chan struct{})
			)
			go func() {
				sniffTimeout := C.ReadPayloadTimeout
				if action.Timeout > 0 {
					sniffTimeout = action.Timeout
				}
				inputPacketConn.SetReadDeadline(time.Now().Add(sniffTimeout))
				destination, err = inputPacketConn.ReadPacket(sniffBuffer)
				inputPacketConn.SetReadDeadline(time.Time{})
				close(done)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				inputPacketConn.Close()
				fatalErr = ctx.Err()
				return
			}
			if err != nil {
				sniffBuffer.Release()
				if !E.IsTimeout(err) {
					fatalErr = err
					return
				}
			} else {
				if quicMoreData() {
					err = sniff.PeekPacket(
						ctx,
						metadata,
						sniffBuffer.Bytes(),
						sniff.QUICClientHello,
					)
				} else {
					err = sniff.PeekPacket(
						ctx, metadata,
						sniffBuffer.Bytes(),
						packetSniffers...,
					)
				}
				packetBuffer := N.NewPacketBuffer()
				*packetBuffer = N.PacketBuffer{
					Buffer:      sniffBuffer,
					Destination: destination,
				}
				packetBuffers = append(packetBuffers, packetBuffer)
				metadata.SnifferNames = action.SnifferNames
				metadata.SniffError = err
				if errors.Is(err, sniff.ErrNeedMoreData) {
					// TODO: replace with generic message when there are more multi-packet protocols
					r.logger.DebugContext(ctx, "attempt to sniff fragmented QUIC client hello")
					continue
				}
			}
			goto finally
		}
	finally:
		if err == nil {
			//goland:noinspection GoDeprecation
			if action.OverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
			if metadata.Domain != "" && metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain, ", client: ", metadata.Client)
			} else if metadata.Domain != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.Domain)
			} else if metadata.Client != "" {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", client: ", metadata.Client)
			} else {
				r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol)
			}
		}
	}
	return
}

// actionResolve resolves a name into dial candidates.
//
// # Why a literal destination with a sniffed domain also resolves
//
// The action used to resolve only when Destination was itself a domain. In a TUN
// deployment the application has usually already resolved the name and connects to an
// address, so Destination is a literal and the action did nothing - even though sniffing
// had recovered the domain into metadata.Domain. The result was a connection with exactly
// one candidate: whichever family the application happened to pick. With a broken IPv6 path
// and a healthy IPv4 one, there was no alternative to fall back to, so Happy Eyeballs had
// nothing to race.
//
// # Destination is NOT rewritten
//
// Resolving a sniffed domain produces dial CANDIDATES. The routing decision has already
// been made, and rules such as geoip, ip_cidr, ip_version and private-IP checks are
// specified in terms of the address the client actually connected to. Replacing
// metadata.Destination with a resolved address would silently change which rules match.
// Destination therefore keeps meaning "what the client asked for" and
// DestinationAddresses means "where we may dial instead".
func (r *Router) actionResolve(ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionResolve) error {
	lookupName := resolveLookupName(metadata)
	if lookupName == "" {
		return nil
	}

	var transport adapter.DNSTransport
	if action.Server != "" {
		var loaded bool
		transport, loaded = r.dnsTransport.Transport(action.Server)
		if !loaded {
			return E.New("DNS server not found: ", action.Server)
		}
	}
	addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), lookupName, adapter.DNSQueryOptions{
		Transport:              transport,
		Strategy:               action.Strategy,
		DisableCache:           action.DisableCache,
		DisableOptimisticCache: action.DisableOptimisticCache,
		RewriteTTL:             action.RewriteTTL,
		Timeout:                action.Timeout,
		ClientSubnet:           action.ClientSubnet,
	})
	if err != nil {
		return err
	}
	// Plan with the EFFECTIVE strategy, not the raw one.
	//
	// The lookup above honours AsIS by applying the router's configured default, and returns
	// addresses ordered accordingly. The planner has its own rule for AsIS - "keep the
	// application's own family first, because a recovery is a fallback rather than an override" -
	// and it cannot tell "the caller expressed no preference" from "the literal value AsIS
	// arrived". Handing it the raw value therefore discarded the preference the resolver had just
	// applied: a router configured for prefer_ipv6 with an IPv4 original produced an IPv4-first
	// plan.
	//
	// A router that cannot report its strategy (a third-party implementation of the optional
	// interface) keeps the previous behaviour, which is the safe default: the original's family
	// leads.
	strategy := action.Strategy
	if strategy == C.DomainStrategyAsIS {
		if resolver, isResolver := r.dns.(adapter.DNSStrategyResolver); isResolver {
			strategy = resolver.ResolveStrategy(adapter.DNSQueryOptions{
				Transport: transport,
				Strategy:  action.Strategy,
			})
		}
	}
	metadata.DestinationAddresses = mergeOriginalDestination(metadata.Destination, addresses, strategy)
	r.logger.DebugContext(ctx, "resolved [", strings.Join(F.MapToString(metadata.DestinationAddresses), " "), "]")
	return nil
}

// resolveLookupName reports which name to resolve, or empty when there is nothing to do.
//
// A domain destination is resolved directly. An IP destination is resolved through the
// sniffed domain when one was recovered, because that is the name the client actually
// wanted and it is the only source of the other address family.
func resolveLookupName(metadata *adapter.InboundContext) string {
	if metadata.Destination.IsDomain() {
		return metadata.Destination.Fqdn
	}
	if !metadata.Destination.IsIP() {
		return ""
	}
	// A protocol sentinel is not an application domain and must never be resolved.
	//
	// # How one gets here
	//
	// common/uot.Router recognises the UoT magic address, reads the session header, and then rewrites
	// the metadata: Domain keeps the magic address to record the flow's provenance, and Destination
	// becomes the real target. That target is usually a literal IP, which is the shape that makes
	// this function fall back to metadata.Domain - so without this check the resolver is asked for
	// "sp.v2.udp-over-tcp.arpa".
	//
	// The lookup cannot succeed: it is not a real name, so the query runs to its timeout and the flow
	// is abandoned before the per-datagram target policy it exists to exercise is ever consulted.
	//
	// # Why only the sentinels are excluded
	//
	// An IP destination WITH a genuine sniffed domain is a deliberate shape - 4ca74d69f added the
	// recovery so dual-stack planning can work against the real name - and excluding everything would
	// revert that fix. Only a value that is a protocol marker rather than a name learned from the
	// traffic is filtered, which is why the comparison is against the canonical constants and not
	// against a string pattern.
	switch metadata.Domain {
	case uot.MagicAddress, uot.LegacyMagicAddress:
		return ""
	}
	return validSniffedDomain(metadata.Domain)
}

// validSniffedDomain returns the domain to resolve, or empty when the sniffed value is not
// usable.
//
// The check is deliberately strict. A sniffed domain is attacker-influenced input - it is
// derived from bytes the remote peer chose - and it is about to be sent to a resolver. A
// value that is empty, over-long, contains a NUL or a space, or carries an IP literal is
// rejected rather than resolved.
func validSniffedDomain(domain string) string {
	switch {
	case domain == "":
		return ""
	case len(domain) > 253:
		return ""
	case strings.ContainsAny(domain, "\x00 \t\r\n/"):
		return ""
	}
	// A sniffed "domain" that is actually an address literal must not be resolved.
	if _, err := netip.ParseAddr(domain); err == nil {
		return ""
	}
	// A single trailing dot is the FQDN form; anything else must contain a dot to be a
	// plausible domain rather than a bare hostname fragment from a partial parse.
	trimmed := strings.TrimSuffix(domain, ".")
	if trimmed == "" || !strings.Contains(trimmed, ".") {
		return ""
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, char := range label {
			isAlnum := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
			if !isAlnum && char != '-' && char != '_' {
				return ""
			}
		}
	}
	return trimmed
}

// mergeOriginalDestination combines resolved candidates with the address the client chose,
// using the shared planner so the order published on the metadata is the order the dialer
// will use.
//
// The original is kept because the resolved set may not contain it: a CDN answering
// differently per query, a split-horizon resolver, or a cached mapping. Dropping it would
// discard a destination the client is demonstrably able to reach. It is appended within its
// own family rather than promoted, so the configured family preference survives - a recovery
// must not quietly overrule the strategy.
func mergeOriginalDestination(original M.Socksaddr, resolved []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	if !original.IsIP() {
		return resolved
	}
	return dialer.MergeOriginalDestination(original.Addr, resolved, strategy)
}
