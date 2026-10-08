package v2raygrpclite

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raygrpc"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// The custom service name, over both gRPC transports.
//
// # Why the paths are asserted instead of the option
//
// The service name is not a name, it is a PATH: the stream's `:path` is
// `"/" + serviceName + "/Tun"` on both sides, so a `/` inside it is another segment and a `%2F`
// inside it is still three literal characters. The reference builds that string by concatenation
// and never escapes it (transport/v2raygrpc's streamPath, and Xray's own encoding.TunCustomName),
// and the reference SERVER dispatches on the raw path, splitting it at its last slash. A transport
// that escapes the name produces a path the reference server does not have, and the same
// configuration then reaches a different place depending on which transport is in use.
//
// So the assertions here are about the string that would be written into the `:path` pseudo-header,
// for the four shapes a service name can take, plus one end-to-end check against a grpc-go server -
// which is the same server implementation the reference uses, and therefore the same dispatch rule.

// serviceNameCases covers the four shapes the escaping rules can disagree about.
var serviceNameCases = []struct {
	name     string
	service  string
	expected string
}{
	{name: "plain", service: "GunService", expected: "/GunService/Tun"},
	{name: "multi-segment", service: "pkg.Service/v1", expected: "/pkg.Service/v1/Tun"},
	{name: "slash", service: "a/b", expected: "/a/b/Tun"},
	{name: "pre-escaped", service: "a%2Fb", expected: "/a%2Fb/Tun"},
}

// TestCustomServiceNamePathMatchesTheReference pins the effective path of this transport's client.
//
// The expected strings are transcribed from the reference's own construction - a literal
// concatenation - rather than computed with the code under test, so a change of escaping policy
// fails here instead of agreeing with itself.
func TestCustomServiceNamePathMatchesTheReference(t *testing.T) {
	for _, testCase := range serviceNameCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			path, rawPath := serviceURLPath(testCase.service)
			requestURL := &url.URL{
				Scheme:  "https",
				Host:    "127.0.0.1:443",
				Path:    path,
				RawPath: rawPath,
			}
			require.Equal(t, testCase.expected, requestURL.EscapedPath(),
				"the path net/http puts in the :path pseudo-header")
			require.Equal(t, testCase.expected, requestURL.RequestURI(),
				"the request target the transport actually writes")
			require.Equal(t, servicePath(testCase.service), testCase.expected)
		})
	}
}

// recordingGunService answers a gun stream by announcing which service name was reached. A stream
// that arrives under the wrong path never reaches any of these handlers at all: the grpc-go server
// looks the leading part of the RAW path up as a literal service name and fails the RPC with
// "unknown service" when it is not registered.
type recordingGunService struct {
	v2raygrpc.UnimplementedGunServiceServer
	name     string
	accepted chan<- string
}

func (s *recordingGunService) Tun(stream grpc.BidiStreamingServer[v2raygrpc.Hunk, v2raygrpc.Hunk]) error {
	select {
	case s.accepted <- s.name:
	default:
	}
	if err := stream.Send(&v2raygrpc.Hunk{Data: []byte("gun")}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// TestBothGRPCTransportsReachTheSameServiceName is the cross-transport half: one config, both
// transports, one server, and the SAME service name must be the one that answers.
//
// The server is grpc-go's, which is what Xray runs; registering a `/`-containing name and reaching
// it is therefore the reference's dispatch rule in action, not this repository's opinion of it.
func TestBothGRPCTransportsReachTheSameServiceName(t *testing.T) {
	accepted := make(chan string, 1)
	grpcServer := grpc.NewServer()
	for _, testCase := range serviceNameCases {
		v2raygrpc.RegisterGunServiceCustomNameServer(grpcServer,
			&recordingGunService{name: testCase.service, accepted: accepted}, testCase.service)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	serverAddress := M.SocksaddrFromNet(listener.Addr())

	waitForService := func(t *testing.T, service string) {
		t.Helper()
		select {
		case reached := <-accepted:
			require.Equal(t, service, reached,
				"the server reached a different service than the one the config named")
		case <-time.After(10 * time.Second):
			t.Fatalf("no service was reached for %q; the stream went somewhere else", service)
		}
	}

	for _, testCase := range serviceNameCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			liteClient := NewClient(ctx, N.SystemDialer, serverAddress,
				option.V2RayGRPCOptions{ServiceName: testCase.service}, nil)
			liteConn, err := liteClient.DialContext(ctx)
			require.NoError(t, err)
			// The lite transport establishes the stream lazily: the request is only written when
			// the first byte is. Writing is what makes the server see the path.
			_, err = liteConn.Write([]byte("lite"))
			require.NoError(t, err)
			waitForService(t, testCase.service)
			_ = liteConn.Close()

			fullClient, err := v2raygrpc.NewClient(ctx, N.SystemDialer, serverAddress,
				option.V2RayGRPCOptions{ServiceName: testCase.service}, nil)
			require.NoError(t, err)
			fullConn, err := fullClient.DialContext(ctx)
			require.NoError(t, err,
				"the full gRPC transport must reach the same service the lite transport reached")
			waitForService(t, testCase.service)
			_ = fullConn.Close()
			_ = fullClient.Close()
		})
	}
}

// TestDefaultServiceNameIsUnchanged is the positive control for the escaping work: the documented
// default service name has no escapable character, so both transports and the reference agree on
// `/GunService/Tun` and nothing about the change is visible to a deployment that never set one.
func TestDefaultServiceNameIsUnchanged(t *testing.T) {
	path, rawPath := serviceURLPath("GunService")
	require.Equal(t, "/GunService/Tun", path)
	require.Equal(t, "/GunService/Tun", rawPath)
}

// closingConnectionHandler accepts a stream and closes it immediately. ServeHTTP blocks until the
// handler reports the connection closed, so a test that only wants to know whether the path was
// accepted needs a handler that gets out of the way.
type closingConnectionHandler struct{}

func (h *closingConnectionHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	onClose(nil)
}

// TestServerAcceptsTheReferencePath is the server half of the same rule.
//
// The server compares the RAW path it received against the literal service name. Comparing the
// DECODED path - which is what net/http puts in URL.Path - cannot work for a name that is itself an
// escape, because a request to `/a%2Fb/Tun` decodes to `/a/b/Tun` and would never equal its own
// literal; and it accepts `/a%2Fb/Tun` for the service name `a/b`, a path the reference server
// would answer with "unknown service". Both halves are asserted here through ServeHTTP, with the
// request URL parsed the way net/http parses a request target so Path and RawPath are what a real
// connection would carry.
func TestServerAcceptsTheReferencePath(t *testing.T) {
	for _, testCase := range serviceNameCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			server, err := NewServer(context.Background(), log.NewNOPFactory().NewLogger("grpc"),
				option.V2RayGRPCOptions{ServiceName: testCase.service}, nil, &closingConnectionHandler{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = server.Close()
			})

			accepted := serveGRPCPath(t, server, testCase.expected)
			require.Equal(t, http.StatusOK, accepted,
				"the server must accept the path the reference sends for service name %q", testCase.service)

			// The lite client's OLD path: every escapable character of the name percent-encoded.
			// For a plain name it is the same string and there is nothing to reject.
			escapedPath := "/" + url.PathEscape(testCase.service) + "/Tun"
			if escapedPath == testCase.expected {
				return
			}
			rejected := serveGRPCPath(t, server, escapedPath)
			require.Equal(t, http.StatusNotFound, rejected,
				"the escaped path %q is a different service name and must not be accepted", escapedPath)
		})
	}
}

// serveGRPCPath hands one request target to the server the way Go's HTTP/2 server would and
// returns the status it answered with.
func serveGRPCPath(t *testing.T, server *Server, requestTarget string) int {
	t.Helper()
	requestURL, err := url.ParseRequestURI(requestTarget)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "https://interop.invalid/", nil)
	request.URL = requestURL
	request.Header.Set("Content-Type", "application/grpc")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder.Code
}
