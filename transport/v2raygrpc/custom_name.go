package v2raygrpc

import (
	"context"

	"google.golang.org/grpc"
)

type GunService interface {
	Context() context.Context
	Send(*Hunk) error
	Recv() (*Hunk, error)
}

// grpcTunStreamName is the stream the gun service exposes, and the last segment of a gun stream's
// HTTP/2 path.
const grpcTunStreamName = "Tun"

// streamPath is the `:path` of a gun stream: the service name and the stream name concatenated
// between slashes, VERBATIM.
//
// That is the reference's rule, and it is not a simplification of one. Xray builds the same string
// by concatenation - `c.cc.NewStream(ctx, desc, "/"+name+"/"+tun)` - and grpc-go writes the method
// string into the `:path` pseudo-header unchanged. The server side is grpc-go too: it splits the
// RAW path at its LAST slash and looks the leading part up as a literal service name. So a `/` in
// the configured service name is another path segment and a `%2F` in it is still the three
// characters `%`, `2`, `F`; nothing anywhere decodes or re-escapes the name.
//
// The escaping therefore has to stay out of the path construction in BOTH gRPC transports, and
// transport/v2raygrpclite's client - which reaches the same string through net/http's URL type -
// is asserted against this function's output by custom_service_name_test.go there.
func streamPath(serviceName string, streamName string) string {
	return "/" + serviceName + "/" + streamName
}

func ServerDesc(name string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*GunServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    grpcTunStreamName,
				Handler:       _GunService_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func (c *gunServiceClient) TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[0], streamPath(name, grpcTunStreamName), opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Hunk, Hunk]{ClientStream: stream}
	return x, nil
}

var _ GunServiceCustomNameClient = (*gunServiceClient)(nil)

type GunServiceCustomNameClient interface {
	TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error)
	Tun(ctx context.Context, opts ...grpc.CallOption) (GunService_TunClient, error)
}

func RegisterGunServiceCustomNameServer(s *grpc.Server, srv GunServiceServer, name string) {
	desc := ServerDesc(name)
	s.RegisterService(&desc, srv)
}
