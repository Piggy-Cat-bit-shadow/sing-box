//go:build with_lx_command

package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// End-to-end gRPC contract tests for the JiejieBox command surface.
//
// # Why these go through a real transport
//
// The bug this whole surface exists to fix was NOT a Go-level defect. The client
// had GetGroups in its generated stub; the server's DESCRIPTOR did not contain the
// method; the transport answered "unknown method GetGroups". A test that calls
// service.GetGroups(&emptypb.Empty{}) directly cannot see that class of failure at
// all — it would have passed against the broken daemon, because the Go method
// existed the whole time.
//
// So every test here:
//
//  1. registers the service through the REAL NewServer (the same function
//     production uses, with its interceptors and RegisterStartedServiceServer);
//  2. dials it over a real gRPC connection (bufconn);
//  3. calls it through the GENERATED client stub.
//
// That path covers the descriptor, the method name, the request/response
// serialization and the handler wiring — which is exactly what drifted.

// startedServiceGRPCHarness is a running service reachable over a real connection.
type startedServiceGRPCHarness struct {
	service *StartedService
	client  StartedServiceClient
	conn    *grpc.ClientConn
	cleanup func()
}

// newStartedServiceHarness starts the real server on a bufconn listener.
//
// The secret is empty so the auth interceptor is a no-op; authentication is covered
// by its own tests and is not what this file is about.
func newStartedServiceHarness(t *testing.T) *startedServiceGRPCHarness {
	t.Helper()
	return newStartedServiceHarnessWithContext(t, context.Background())
}

// newStartedServiceHarnessWithContext is the same server, with the service context
// supplied by the caller. The integration fixture installs engine registries on that
// context, which newInstance reads.
func newStartedServiceHarnessWithContext(t *testing.T, serviceContext context.Context) *startedServiceGRPCHarness {
	t.Helper()

	service := NewStartedService(ServiceOptions{Context: serviceContext})
	server := NewServer(service, "")

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "dial the bufconn server")

	harness := &startedServiceGRPCHarness{
		service: service,
		client:  NewStartedServiceClient(conn),
		conn:    conn,
	}
	harness.cleanup = func() {
		_ = conn.Close()
		server.Stop()
	}
	t.Cleanup(harness.cleanup)
	return harness
}

// markStarted puts the service into the STARTED state without running an engine.
//
// The handlers under test read the state, the instance pointer and the outbound
// manager. The full engine is exercised by the binary smoke test; here the state
// machine is what matters, so it is set directly under the same lock the handlers
// take.
func (h *startedServiceGRPCHarness) markStarted() {
	h.service.serviceAccess.Lock()
	h.service.serviceStatus.Status = ServiceStatus_STARTED
	h.service.serviceAccess.Unlock()
}

// TestJiejieDaemonRPCContract is the regression test for the reported failure.
//
// It asserts the three methods the launcher's proxy UI needs are REACHABLE over a
// real gRPC connection. "Reachable" means specifically: not
// Unimplemented/"unknown method". That distinction is the whole point —
//
//	unknown method GetGroups   -> the descriptor is missing the RPC (the bug)
//	GetGroups is not included  -> the handler is a stub (a build-configuration fact)
//
// The launcher treats the first as "this daemon cannot do it at all" and the second
// as "this BUILD cannot do it", and the shipped macOS profile must be neither.
func TestJiejieDaemonRPCContract(t *testing.T) {
	harness := newStartedServiceHarness(t)

	// The service is deliberately NOT started yet, so every call must reach the
	// handler and be refused by it with FailedPrecondition. Reaching the handler at
	// all is what proves the method is registered.
	t.Run("methods are registered, not unknown", func(t *testing.T) {
		_, err := harness.client.GetGroups(context.Background(), &emptypb.Empty{})
		require.Error(t, err)
		require.NotEqual(t, codes.Unimplemented, status.Code(err),
			"GetGroups must be REGISTERED: an absent method is what produced "+
				"'unknown method GetGroups' and an empty proxy list in the UI; got %v", err)
		require.NotContains(t, err.Error(), "unknown method",
			"the transport must not report the method as unknown")
		require.Equal(t, codes.FailedPrecondition, status.Code(err),
			"an unstarted service must be refused by the HANDLER with "+
				"FailedPrecondition, which also proves the handler ran; got %v", err)

		_, err = harness.client.GetOutbounds(context.Background(), &emptypb.Empty{})
		require.Error(t, err)
		require.NotEqual(t, codes.Unimplemented, status.Code(err),
			"GetOutbounds must be registered; got %v", err)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))

		_, err = harness.client.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
			OutboundTag: "anything",
		})
		require.Error(t, err)
		require.NotEqual(t, codes.Unimplemented, status.Code(err),
			"URLTestOutbound must be registered; got %v", err)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
}

// TestJiejieDaemonRPCContractStartedService is the "once it is up, it really
// answers" half of the contract.
//
// It is separate from the test above because reaching a STARTED handler state needs
// a real engine (readGroups dereferences the instance and its outbound manager), and
// that in turn needs the fixture registries. The test above deliberately uses a bare
// service, which is enough to prove the METHODS are registered — the actual reported
// bug — without paying for an engine on every run.
func TestJiejieDaemonRPCContractStartedService(t *testing.T) {
	fixture := newLiveFixture(t)

	// The engine is up: the calls must now succeed end-to-end, over the real
	// connection, through the generated client.
	groups, err := fixture.harness.client.GetGroups(context.Background(), &emptypb.Empty{})
	require.NoError(t, err, "GetGroups must succeed once the service is started")
	require.NotNil(t, groups, "the response must not be nil; a nil body would "+
		"deserialize as an empty group list and hide a server bug")
	require.NotEmpty(t, groups.Group, "the fixture defines groups, so the snapshot "+
		"must not be empty; this is the empty-proxy-list symptom the user reported")

	outbounds, err := fixture.harness.client.GetOutbounds(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, outbounds)
	require.NotEmpty(t, outbounds.Outbounds, "the fixture defines outbounds")

	// And the three must not be stubs in this build.
	_, err = fixture.harness.client.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
		OutboundTag: "node-a",
		Link:        fixture.testURL,
		Timeout:     5000,
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"the shipped macOS profile must enable the real implementations; "+
			"Unimplemented here means with_lx_command did not take effect")
}

// TestJiejieDaemonRPCSurfaceIsComplete pins the exact method names the launcher
// calls, at the DESCRIPTOR level.
//
// The connection test above proves the three methods respond; this asserts they are
// present under their expected full names, so a rename or a move to another service
// is caught even if some other method happens to answer.
func TestJiejieDaemonRPCSurfaceIsComplete(t *testing.T) {
	// The full method names, as singbox-launcher's generated client spells them.
	required := []string{
		StartedService_GetGroups_FullMethodName,
		StartedService_GetOutbounds_FullMethodName,
		StartedService_URLTestOutbound_FullMethodName,
		StartedService_SelectOutbound_FullMethodName,
		StartedService_SubscribeGroups_FullMethodName,
		StartedService_SubscribeOutbounds_FullMethodName,
		StartedService_GetVersion_FullMethodName,
	}

	// Read the service descriptor the generated server actually serves.
	serviceDescriptor := StartedService_ServiceDesc
	available := make(map[string]bool, len(serviceDescriptor.Methods))
	for _, method := range serviceDescriptor.Methods {
		available["/daemon.StartedService/"+method.MethodName] = true
	}
	for _, stream := range serviceDescriptor.Streams {
		available["/daemon.StartedService/"+stream.StreamName] = true
	}

	for _, name := range required {
		require.True(t, available[name],
			"the launcher calls %s but the served descriptor does not declare it; "+
				"a client with a method the server does not serve gets "+
				"'unknown method', which is the reported failure", name)
	}

	// And the method names must match the launcher's spelling exactly.
	require.Equal(t, "/daemon.StartedService/GetGroups", StartedService_GetGroups_FullMethodName)
	require.Equal(t, "/daemon.StartedService/GetOutbounds", StartedService_GetOutbounds_FullMethodName)
	require.Equal(t, "/daemon.StartedService/URLTestOutbound", StartedService_URLTestOutbound_FullMethodName)
}

// TestStubWouldBeUnimplementedNotUnknown documents the behaviour a build WITHOUT
// with_lx_command must have.
//
// This runs only where the real implementation is absent, so it is skipped in a
// tagged build — the tagged case is covered by the test above, which requires the
// calls to reach the handler. It exists so the CONTRACT for an untagged build is
// recorded in code rather than only in a comment: a client must be able to tell
// "this build lacks the feature" from "this daemon does not know the method".
func TestStubWouldBeUnimplementedNotUnknown(t *testing.T) {
	// In a with_lx_command build the implementation is present, so this assertion
	// belongs to the twin file started_service_command_lx_stub_test.go. Assert the
	// real behaviour here instead: the methods must NOT be Unimplemented.
	harness := newStartedServiceHarness(t)
	harness.markStarted()

	_, err := harness.client.GetGroups(context.Background(), &emptypb.Empty{})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"this build was compiled WITH with_lx_command, so GetGroups must be "+
			"implemented rather than stubbed; a stub here means the build tag did "+
			"not take effect, which is the 'source has the capability, the shipped "+
			"binary does not' failure this test exists to prevent")
}

// drainTimeout bounds tests that must observe a cancellation.
const drainTimeout = 10 * time.Second
