//go:build !with_lx_command

package daemon

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (s *StartedService) GetGroups(ctx context.Context, empty *emptypb.Empty) (*Groups, error) {
	return nil, status.Error(codes.Unimplemented, "GetGroups is not included in this build, rebuild with -tags with_lx_command")
}

func (s *StartedService) GetOutbounds(ctx context.Context, empty *emptypb.Empty) (*OutboundList, error) {
	return nil, status.Error(codes.Unimplemented, "GetOutbounds is not included in this build, rebuild with -tags with_lx_command")
}

func (s *StartedService) URLTestOutbound(ctx context.Context, request *URLTestOutboundRequest) (*URLTestOutboundResponse, error) {
	return nil, status.Error(codes.Unimplemented, "URLTestOutbound is not included in this build, rebuild with -tags with_lx_command")
}
