//go:build !with_lx_command

package daemon

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Build-tag twin of started_service_command_lx.go.
//
// The RPCs are still REGISTERED — the .proto seam is compiled into every build, so
// the descriptor and the generated client are identical everywhere — but they answer
// codes.Unimplemented without with_lx_command. A tag-less sing-box is therefore
// behaviourally equivalent to upstream while still advertising the same method set.
//
// The code matters as much as the message. singbox-launcher's capability probe
// (core/daemon_rpc_compat.go) reads Unimplemented as "this daemon build does not
// include the method" and any OTHER status — InvalidArgument, FailedPrecondition,
// NotFound — as "the method exists and rejected this particular request". Returning
// a plain errors.New, or codes.Unknown, would be classified as the latter and the
// launcher would offer a control the daemon cannot honour. Unimplemented is the
// only correct answer here.
//
// The message names the tag to rebuild with, because "unknown method GetGroups" —
// what an ABSENT method produces — tells a user nothing about what to do next.

// --- implemented for real under with_lx_command ---

func (s *StartedService) GetGroups(ctx context.Context, empty *emptypb.Empty) (*Groups, error) {
	return nil, unimplemented("GetGroups")
}

func (s *StartedService) GetOutbounds(ctx context.Context, empty *emptypb.Empty) (*OutboundList, error) {
	return nil, unimplemented("GetOutbounds")
}

func (s *StartedService) URLTestOutbound(ctx context.Context, request *URLTestOutboundRequest) (*URLTestOutboundResponse, error) {
	return nil, unimplemented("URLTestOutbound")
}

// --- declared for descriptor compatibility; no implementation in this fork ---
//
// These back subsystems this fork does not have (outbound chains, a rules
// provider, DNS server groups, endpoint enable/disable). They are declared so the
// served descriptor matches the launcher's and answered Unimplemented so the
// launcher can tell "not in this build" from "unknown method". Porting a real
// implementation requires the corresponding adapter interface; a control the core
// silently ignores would be worse for the user than an honest refusal.

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
