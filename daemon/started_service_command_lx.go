//go:build with_lx_command

package daemon

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/protocol/group"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The unary command surface that JiejieBox / singbox-launcher drives its proxy UI
// with. See started_service_command_lx_stub.go for the build-tag twin and
// daemon/started_service.proto for why the RPCs are declared unconditionally while
// these handlers are gated.
//
// Ported from SagerNet/sing-box 94c41b50 (SPEC 014/015/019) and then ADAPTED to
// this fork's architecture. Two adaptations matter and are called out at the sites
// below: this fork's group.RealTag takes (detour, network) rather than
// (outboundManager, detour), and this fork has no adapter.IdleStateReporter, so the
// WG/AWG endpoint-state field is deliberately left unfilled rather than ported with
// a subsystem that does not exist here.

// GetGroups returns a pull snapshot of the group list.
//
// This is the RPC whose absence produced, on a real machine:
//
//	cannot read the proxies of group "🌍 国外流量": daemon GetGroups:
//	rpc error: code = Unimplemented desc = unknown method GetGroups
//
// It deliberately does NOT build a second group enumeration. readGroups() is the
// single source that also feeds SubscribeGroups, so the stream and the unary call
// cannot disagree about the same instance — which is what the parity test asserts.
//
// A unary call is needed at all because SubscribeGroups only PUSHES: a client that
// has just paired, or that missed a broadcast during a reconnect, has no way to ask
// for the current state, and would otherwise show an empty proxy list while the
// tunnel is demonstrably up.
//
// Error model: FailedPrecondition when the service is not started, matching
// GetOutbounds and the other snapshots. An empty group list is a SUCCESS with an
// empty list, not NotFound — "this config defines no groups" is a valid answer, and
// reporting it as an error would make the UI show a failure for a working core.
func (s *StartedService) GetGroups(ctx context.Context, empty *emptypb.Empty) (*Groups, error) {
	s.serviceAccess.RLock()
	if s.serviceStatus.Status != ServiceStatus_STARTED {
		s.serviceAccess.RUnlock()
		return nil, status.Error(codes.FailedPrecondition, "service is not started")
	}
	groups := s.readGroups()
	s.serviceAccess.RUnlock()
	return groups, nil
}

// GetOutbounds returns a pull snapshot of the flat outbound and endpoint list.
//
// It exists alongside GetGroups because the two answer different questions:
// SubscribeGroups/GetGroups cover only the nodes INSIDE a group, whereas standalone
// outbounds that belong to no group appear only here.
//
// The builder is shared with SubscribeOutbounds rather than duplicated, via
// readOutbounds(). The reference chose to duplicate it to avoid touching upstream
// code; this fork has already diverged from upstream substantially, so sharing is
// both cheaper and safer here — a duplicate would be free to drift, and the parity
// test would only catch that after the fact.
func (s *StartedService) GetOutbounds(ctx context.Context, empty *emptypb.Empty) (*OutboundList, error) {
	s.serviceAccess.RLock()
	if s.serviceStatus.Status != ServiceStatus_STARTED {
		s.serviceAccess.RUnlock()
		return nil, status.Error(codes.FailedPrecondition, "service is not started")
	}
	list := s.readOutbounds()
	s.serviceAccess.RUnlock()
	return list, nil
}

// URLTestOutbound measures a single node and returns its latency synchronously.
//
// Unlike URLTest above — which kicks off a whole group and writes the result to the
// history asynchronously, so the caller never learns the value — this returns the
// delay in the reply, which is what a per-node latency badge needs.
//
// CANCELLATION. The test is parented to the gRPC per-call ctx, NOT to
// boxService.ctx. gRPC cancels this ctx automatically when the caller cancels or
// the connection drops, so:
//
//   - the user closing the proxy page aborts the in-flight dial;
//   - a new round of testing supersedes the old one instead of racing it;
//   - a broken daemon connection does not leave a dial running against a client
//     that has gone away.
//
// Parenting to boxService.ctx would make the test outlive its caller: cancellation
// could not reach the dial, and the only remaining lever would be tearing down the
// whole connection. A caller-supplied Timeout is layered ON TOP of the call ctx as a
// child deadline, never as a replacement — so a request that specifies no timeout is
// still bounded by the caller's own cancellation.
func (s *StartedService) URLTestOutbound(ctx context.Context, request *URLTestOutboundRequest) (*URLTestOutboundResponse, error) {
	s.serviceAccess.RLock()
	if s.serviceStatus.Status != ServiceStatus_STARTED {
		s.serviceAccess.RUnlock()
		return nil, status.Error(codes.FailedPrecondition, "service is not started")
	}
	boxService := s.instance
	s.serviceAccess.RUnlock()

	// The lock is released BEFORE the network operation. Holding serviceAccess across
	// urltest.URLTest would let one latency test — bounded only by the caller's
	// timeout, potentially tens of seconds — block StartOrReloadService, CloseService
	// and every other reader. Only the instance POINTER is taken under the lock; the
	// test itself runs outside it.
	//
	// The pointer stays valid for the duration because a reload does not free the old
	// instance underneath an in-flight call: the dialers it holds are reference-
	// counted through boxService.ctx, and the test ctx is derived from the gRPC call,
	// so a reload during a test causes the test to fail fast rather than use freed
	// state. The lifecycle tests in started_service_command_lx_test.go exercise
	// exactly this window.
	tag := request.OutboundTag

	// Resolve in BOTH managers: outbound first, then endpoint. An adapter.Endpoint
	// embeds adapter.Outbound, so either resolution yields an N.Dialer for
	// urltest.URLTest and an adapter.Outbound for history keying. An endpoint that is
	// also an outbound would otherwise be invisible to a per-node test.
	//
	// The endpoint manager is reached through the service context, as the rest of
	// this file does, rather than through a struct field.
	var detour N.Dialer
	var realTagSource adapter.Outbound
	if outbound, isLoaded := boxService.outboundManager.Outbound(tag); isLoaded {
		detour = outbound
		realTagSource = outbound
	} else if endpointManager := service.FromContext[adapter.EndpointManager](boxService.ctx); endpointManager != nil {
		if endpoint, isLoaded := endpointManager.Get(tag); isLoaded {
			detour = endpoint
			realTagSource = endpoint
		}
	}
	if detour == nil {
		// Variant B: an unknown tag is an APPLICATION outcome, reported in the
		// payload, so the client has exactly one failure channel to handle.
		return &URLTestOutboundResponse{Error: "outbound or endpoint not found: " + tag}, nil
	}

	testCtx := ctx
	if request.Timeout > 0 {
		var cancel context.CancelFunc
		testCtx, cancel = context.WithTimeout(ctx, time.Duration(request.Timeout)*time.Millisecond)
		defer cancel()
	}

	// An empty link means "use the default"; urltest.URLTest substitutes
	// https://www.gstatic.com/generate_204 itself (common/urltest/urltest.go:102).
	// Resolving it here would create a SECOND definition of that default, free to
	// drift from the one the group path uses.
	delay, err := urltest.URLTest(testCtx, request.Link, detour)

	// The history key must be the one readGroups/readOutbounds already use, or the
	// value written here would never be the value displayed: GetGroups would keep
	// reporting the previous delay while this RPC returned a fresh one. This fork's
	// RealTag takes (detour, network) — the reference's takes
	// (outboundManager, detour) — so the call is adapted rather than copied.
	realTag := group.RealTag(realTagSource, N.NetworkTCP)
	if realTag == "" {
		// RealTag returns "" when a group resolves to no selection. Falling back to
		// the requested tag keeps the history entry addressable instead of writing to
		// the empty key, which every later lookup would also hit.
		realTag = tag
	}
	historyStorage := boxService.urlTestHistoryStorage
	if err != nil {
		// A failed test must REMOVE the stale figure. Leaving it would show the last
		// good latency for a node that has just failed, which is worse than showing
		// nothing: the UI would report a dead node as healthy.
		historyStorage.DeleteURLTestHistory(realTag)
		return &URLTestOutboundResponse{Error: err.Error()}, nil
	}
	historyStorage.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: delay,
	})
	return &URLTestOutboundResponse{Delay: uint32(delay)}, nil
}

// --- declared for descriptor compatibility; deliberately NOT implemented here ---
//
// These back subsystems this fork does not have. They are answered Unimplemented
// even in a with_lx_command build, and NOT copied from the reference, because a
// faithful port would need the corresponding adapter interface:
//
//   GetChains / SetChainPositionEnabled / GetChainCloneConfig
//       an outbound-chain (multi-hop) manager. This fork has no adapter.ChainManager
//       and no chain clone state, so there is nothing to report and nothing to
//       toggle. Faking a chain list would make the UI offer a feature that does
//       not route anything.
//
//   GetRules
//       a rule provider. The reference reads the running route rules through an
//       adapter this fork does not expose. The rules still work; only the
//       introspection endpoint is absent.
//
//   GetPool / GetDNSGroups / SubscribeDNSQueries
//       urltest rotation pools and DNS server groups (SPEC 019 v2 / 035). Both are
//       lx-only subsystems absent here, including the DnsGroupPath/attempt tracing
//       the DNS event stream depends on.
//
//   GetRunningConfig
//       serializing the live config. Valuable, but the reference implementation is
//       entangled with chain state and would need a careful, separate review; it is
//       reported NOT PORTED rather than half-written.
//
//   GetURLViaOutbound
//       a diagnostic HTTP probe with body limits. Genuinely useful and a good
//       candidate for a follow-up, but out of scope for restoring the proxy list,
//       and it must not be rushed: it returns an arbitrary remote body into the
//       process.
//
//   SetEndpointEnabled
//       endpoint enable/disable, which needs the endpoint lifecycle state
//       (never_built / building / up / asleep / torn_down) that this fork's
//       adapter.Endpoint does not expose.
//
// Answering Unimplemented keeps the launcher's capability probe honest: it reports
// these as absent capabilities and never renders a control that cannot work.

func (s *StartedService) GetRules(ctx context.Context, empty *emptypb.Empty) (*RuleList, error) {
	return nil, unimplemented("GetRules")
}

func (s *StartedService) GetPool(ctx context.Context, request *GetPoolRequest) (*PoolList, error) {
	return nil, unimplemented("GetPool")
}

func (s *StartedService) GetDNSGroups(ctx context.Context, empty *emptypb.Empty) (*DnsGroupList, error) {
	return nil, unimplemented("GetDNSGroups")
}

func (s *StartedService) GetRunningConfig(ctx context.Context, empty *emptypb.Empty) (*RunningConfig, error) {
	return nil, unimplemented("GetRunningConfig")
}

func (s *StartedService) GetURLViaOutbound(ctx context.Context, request *GetURLViaOutboundRequest) (*GetURLViaOutboundResponse, error) {
	return nil, unimplemented("GetURLViaOutbound")
}

func (s *StartedService) GetChains(ctx context.Context, empty *emptypb.Empty) (*ChainList, error) {
	return nil, unimplemented("GetChains")
}

func (s *StartedService) SetChainPositionEnabled(ctx context.Context, request *SetChainPositionEnabledRequest) (*SetChainPositionEnabledResponse, error) {
	return nil, unimplemented("SetChainPositionEnabled")
}

func (s *StartedService) GetChainCloneConfig(ctx context.Context, request *GetChainCloneConfigRequest) (*RunningConfig, error) {
	return nil, unimplemented("GetChainCloneConfig")
}

func (s *StartedService) SetEndpointEnabled(ctx context.Context, request *SetEndpointEnabledRequest) (*SetEndpointEnabledResponse, error) {
	return nil, unimplemented("SetEndpointEnabled")
}

func (s *StartedService) SubscribeDNSQueries(request *SubscribeDNSQueriesRequest, server grpc.ServerStreamingServer[DnsQueryEvent]) error {
	return unimplemented("SubscribeDNSQueries")
}
