package daemon

import (
	"context"
	"runtime/debug"

	"github.com/sagernet/sing-box/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A gRPC handler runs in its own goroutine, so a panic there takes the whole
// daemon down -- and with it the Native API the dashboard depends on, leaving no
// way to see why. These interceptors log the panic with its stack and answer
// codes.Internal instead, so one bad request cannot take the control plane down
// and the failure is visible in the log stream.
//
// They are generic control-plane infrastructure, not feature-specific: every
// build that serves the Native API installs them, and daemon/server.go chains
// them ahead of the auth interceptors.

func unaryRecoverInterceptor(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recoveredPanic(info.FullMethod, r)
		}
	}()
	return handler(ctx, request)
}

func streamRecoverInterceptor(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recoveredPanic(info.FullMethod, r)
		}
	}()
	return handler(server, stream)
}

func recoveredPanic(method string, r any) error {
	log.Error("daemon: panic serving ", method, ": ", r, "\n", string(debug.Stack()))
	return status.Errorf(codes.Internal, "internal panic: %v", r)
}
