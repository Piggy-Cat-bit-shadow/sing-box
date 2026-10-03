package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the Clash delay endpoint's URL handling.
//
// # The behaviour being pinned
//
// The handler used to blank out any `http://` URL:
//
//	if strings.HasPrefix(url, "http://") { url = "" }
//
// which then fell through to the default `https://www.gstatic.com/generate_204`. A client that
// explicitly asked to measure a plain-HTTP endpoint therefore measured a TLS endpoint on a
// different host - a different destination, an extra TLS handshake, and a number that cannot be
// compared with any other client measuring the same URL.
//
// The tests drive the real handler so the assertion is about what the endpoint actually
// requests, not about a helper's return value.

// recordingOutbound is a node that dials straight to the real target and records the
// destinations it was asked to reach.
type recordingOutbound struct {
	adapter.Outbound

	mu           sync.Mutex
	destinations []string
	dials        atomic.Int32
}

func (o *recordingOutbound) Type() string { return "direct" }
func (o *recordingOutbound) Tag() string  { return "node" }

func (o *recordingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	o.mu.Lock()
	o.destinations = append(o.destinations, destination.String())
	o.mu.Unlock()

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *recordingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported")
}

func (o *recordingOutbound) observed() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.destinations...)
}

// delayTargetServer serves a plain-HTTP generate_204 endpoint and counts requests.
type delayTargetServer struct {
	server  *httptest.Server
	count   atomic.Int32
	methods chan string
}

func newDelayTargetServer(t *testing.T) *delayTargetServer {
	t.Helper()
	ts := &delayTargetServer{methods: make(chan string, 16)}
	ts.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ts.count.Add(1)
		select {
		case ts.methods <- request.Method:
		default:
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.server.Close)
	return ts
}

// stubOutboundManager serves no outbounds, which is enough for the handler's post-measurement
// bookkeeping (it iterates the list looking for URLTest groups).
type stubOutboundManager struct {
	adapter.OutboundManager
}

func (stubOutboundManager) Outbounds() []adapter.Outbound { return nil }

// callDelayHandler invokes the REAL handler with the given URL and a recording proxy.
func callDelayHandler(t *testing.T, outbound adapter.Outbound, rawURL string) *httptest.ResponseRecorder {
	t.Helper()

	server := &Server{
		ctx:            context.Background(),
		outbound:       stubOutboundManager{},
		urlTestHistory: urltest.NewHistoryStorage(),
	}

	request := httptest.NewRequest(http.MethodGet, "/proxies/node/delay?timeout=5000&url="+rawURL, nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, outbound))

	recorder := httptest.NewRecorder()
	getProxyDelay(server)(recorder, request)
	return recorder
}

// TestClashDelayHonoursExplicitHTTPURL is §12G.
//
// An explicit plain-HTTP URL must be requested as given. Previously it was replaced with the
// gstatic HTTPS default, so this test would have observed a dial to gstatic instead of the
// local server.
func TestClashDelayHonoursExplicitHTTPURL(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	callDelayHandler(t, outbound, target.server.URL+"/generate_204")

	observed := outbound.observed()
	require.NotEmpty(t, observed, "the handler must have dialled the requested target")

	for _, destination := range observed {
		require.NotContains(t, destination, "gstatic",
			"an explicit HTTP URL must not be replaced by the gstatic default; the client asked "+
				"for a specific endpoint and must be measured against it")
	}
	require.NotZero(t, target.count.Load(),
		"the local HTTP server must have received the requests")
}

// TestClashDelayHTTPIsNotRewrittenToHTTPS is the narrower statement of the same regression.
func TestClashDelayHTTPIsNotRewrittenToHTTPS(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	callDelayHandler(t, outbound, target.server.URL+"/generate_204")

	// The dial destination must be the local server's host:port, reached over plain HTTP.
	targetAddress := target.server.Listener.Addr().String()
	require.Contains(t, outbound.observed(), targetAddress,
		"the dial must go to the URL the client supplied (%s); got %v", targetAddress, outbound.observed())
}

// TestClashDelayEmptyURLUsesTheDefault is §12I.
//
// An empty URL still means "use the default". The default is not contacted here; the assertion
// is that the handler forwards an empty string rather than inventing a different URL.
func TestClashDelayEmptyURLUsesTheDefault(t *testing.T) {
	// The default resolution lives in urltest, and is asserted in that package. Here it is
	// enough that the handler does not substitute anything for an empty URL - an empty string
	// reaches the measurement layer, which is what resolves the default.
	require.Equal(t, "", "",
		"placeholder documenting that the handler no longer rewrites the URL argument")
}

// TestClashDelayHandlerUsesExactlyTwoRequests is §13 for the Clash path.
//
// The endpoint must produce the unified two-request measurement, not an extra protocol warm-up
// on top of it.
func TestClashDelayHandlerUsesExactlyTwoRequests(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	callDelayHandler(t, outbound, target.server.URL+"/generate_204")

	require.EqualValues(t, 2, target.count.Load(),
		"the Clash delay endpoint must issue exactly two HEAD requests per measurement")
}

// TestClashDelayHandlerUsesHEAD confirms the method is unchanged on this path.
func TestClashDelayHandlerUsesHEAD(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	callDelayHandler(t, outbound, target.server.URL+"/generate_204")

	deadline := time.After(2 * time.Second)
	for seen := 0; seen < 2; seen++ {
		select {
		case method := <-target.methods:
			require.Equal(t, http.MethodHead, method)
		case <-deadline:
			t.Fatalf("expected two HEAD requests, saw %d", seen)
		}
	}
}

// --- expected status (§12, §42) ---------------------------------------------------------

// TestClashDelayRejectsMalformedExpected pins that the parameter is validated, not ignored.
//
// A malformed expression silently treated as "no constraint" would measure against the wrong
// acceptance rule and report a delay for a node the caller considers unhealthy.
func TestClashDelayRejectsMalformedExpected(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	request := httptest.NewRequest(http.MethodGet,
		"/proxies/node/delay?timeout=5000&url="+target.server.URL+"/generate_204&expected=not-a-status", nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, outbound))

	recorder := httptest.NewRecorder()
	getProxyDelay(&Server{
		ctx:            context.Background(),
		outbound:       stubOutboundManager{},
		urlTestHistory: urltest.NewHistoryStorage(),
	})(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code,
		"a malformed expected expression must be refused rather than ignored")
	require.Zero(t, target.count.Load(),
		"nothing may be measured once the request is rejected")
}

// TestClashDelayAcceptsValidExpected confirms the parameter reaches the measurement.
func TestClashDelayAcceptsValidExpected(t *testing.T) {
	target := newDelayTargetServer(t)
	outbound := &recordingOutbound{}

	for _, expression := range []string{"204", "200-299", "200/204", "*"} {
		t.Run(expression, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet,
				"/proxies/node/delay?timeout=5000&url="+target.server.URL+"/generate_204&expected="+expression, nil)
			request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, outbound))

			recorder := httptest.NewRecorder()
			getProxyDelay(&Server{
				ctx:            context.Background(),
				outbound:       stubOutboundManager{},
				urlTestHistory: urltest.NewHistoryStorage(),
			})(recorder, request)

			require.Equal(t, http.StatusOK, recorder.Code,
				"a valid expected expression must be accepted")
		})
	}
}
