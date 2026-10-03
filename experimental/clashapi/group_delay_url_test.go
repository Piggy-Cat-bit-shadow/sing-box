package clashapi

import (
	"context"
	"github.com/sagernet/sing/service"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the Clash GROUP delay endpoint.
//
// # Why this file exists separately
//
// /proxies/{name}/delay and /group/{name}/delay are two endpoints that perform the same job for
// two shapes of target, and they had drifted: the proxy path was brought onto the shared measurement
// contracts while the group path kept the older behaviour. A client that measured a group therefore
// got different semantics from the same query parameters it used for a node - a different target, a
// different acceptance rule, and a measurement that wrote selection evidence instead of a diagnostic.
//
// These tests drive the REAL handler, so the assertions are about what the endpoint actually does
// rather than about a helper's return value.

// fakeGroupMember is a node that dials the real target and records it.
type fakeGroupMember struct {
	adapter.Outbound
	tag string

	destinations atomic.Int32
	lastTarget   atomic.Value
}

func (o *fakeGroupMember) Type() string      { return "direct" }
func (o *fakeGroupMember) Tag() string       { return o.tag }
func (o *fakeGroupMember) Network() []string { return []string{"tcp", "udp"} }

func (o *fakeGroupMember) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.destinations.Add(1)
	o.lastTarget.Store(destination.String())
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *fakeGroupMember) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not used")
}

// plainGroup is a selector-like group: it has members and a selection, but no configured health
// target of its own, which is what makes it a "generic group" rather than a URLTest group.
type plainGroup struct {
	adapter.Outbound
	tag     string
	members []adapter.Outbound
	// selected, when set, is what Selected returns.
	selected adapter.Outbound
}

func (g *plainGroup) Type() string      { return "selector" }
func (g *plainGroup) Tag() string       { return g.tag }
func (g *plainGroup) Network() []string { return []string{"tcp", "udp"} }
func (g *plainGroup) All() []string {
	tags := make([]string, 0, len(g.members))
	for _, member := range g.members {
		tags = append(tags, member.Tag())
	}
	return tags
}
func (g *plainGroup) Selected(network string) adapter.Outbound { return g.selected }
func (g *plainGroup) AttachConnection(closer io.Closer) func() { return func() {} }
func (g *plainGroup) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return g.selected.DialContext(ctx, network, destination)
}
func (g *plainGroup) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return g.selected.ListenPacket(ctx, destination)
}

// groupOutboundManager resolves the group's members by tag.
type groupOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
	all   []adapter.Outbound
}

func (m *groupOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

func (m *groupOutboundManager) Outbounds() []adapter.Outbound { return m.all }

// callGroupDelayHandler invokes the REAL group delay handler.
func callGroupDelayHandler(t *testing.T, server *Server, group adapter.Outbound, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/group/x/delay?"+rawQuery, nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, group))
	recorder := httptest.NewRecorder()
	getGroupDelay(server)(recorder, request)
	return recorder
}

// TestGroupDelayHonoursExplicitHTTPURL is §5.
//
// An explicit plain-HTTP URL must be measured as given. The group path blanked it, so it measured
// the gstatic HTTPS default instead - a different destination, an extra TLS handshake, and a number
// that cannot be compared with another client's measurement of the same URL.
func TestGroupDelayHonoursExplicitHTTPURL(t *testing.T) {
	target := newDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	recorder := callGroupDelayHandler(t, server, group,
		"timeout=5000&url="+target.server.URL+"/generate_204")

	require.Equal(t, http.StatusOK, recorder.Code,
		"the measurement must be accepted, not silently redirected to another host")
	require.Contains(t, member.lastTarget.Load().(string), "127.0.0.1",
		"an explicit HTTP URL must be dialled as given; blanking it sends the probe to the gstatic "+
			"HTTPS default and measures a destination the client never asked for")
	require.NotZero(t, target.count.Load(), "the local target must have received the probe")
}

// TestGroupDelayRejectsNonPositiveTimeout is §6.
//
// A non-positive timeout makes the context already expired, which produced an instant, meaningless
// "measurement" that looked like a failed probe rather than a bad request.
func TestGroupDelayRejectsNonPositiveTimeout(t *testing.T) {
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}
	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	for _, timeout := range []string{"0", "-1", "-5000", "abc", ""} {
		t.Run(timeout, func(t *testing.T) {
			recorder := callGroupDelayHandler(t, server, group, "timeout="+timeout)
			require.Equal(t, http.StatusBadRequest, recorder.Code,
				"timeout %q must be refused as a bad request", timeout)
		})
	}
}

// TestGroupDelayRejectsMalformedExpected is §7.
//
// A malformed acceptance rule is the caller's error. Ignoring it would measure against a different
// rule than the one requested and report the result as if it were the requested one.
func TestGroupDelayRejectsMalformedExpected(t *testing.T) {
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}
	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	for _, expected := range []string{"abc", "200-abc", "70000"} {
		t.Run(expected, func(t *testing.T) {
			recorder := callGroupDelayHandler(t, server, group, "timeout=5000&expected="+expected)
			require.Equal(t, http.StatusBadRequest, recorder.Code,
				"expected %q must be refused rather than silently ignored", expected)
			require.Zero(t, member.destinations.Load(),
				"and nothing may be dialled for a request that was refused")
		})
	}
}

// TestGroupDelayExpectedReachesMeasurement is §7, the positive half.
//
// A valid acceptance rule must actually reach the measurement: a status outside it is a failure.
func TestGroupDelayExpectedReachesMeasurement(t *testing.T) {
	// The target answers 204.
	target := newDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}
	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	accepting := callGroupDelayHandler(t, server, group,
		"timeout=5000&url="+target.server.URL+"/generate_204&expected=204")
	require.Equal(t, http.StatusOK, accepting.Code, "204 must satisfy expected=204")

	// The same target, measured against a rule it cannot satisfy.
	before := member.destinations.Load()
	rejecting := callGroupDelayHandler(t, server, group,
		"timeout=5000&url="+target.server.URL+"/generate_204&expected=200")
	require.NotEqual(t, http.StatusOK, rejecting.Code,
		"the target answers 204, so expected=200 must not report success; if the rule is ignored the "+
			"endpoint reports a measurement against a rule the caller never asked for")
	require.Greater(t, member.destinations.Load(), before,
		"the rule is applied to a measurement that actually ran")
}

// TestGenericGroupDelayIsDisplayOnly is §8.
//
// A manual diagnostic must not write health evidence. The legacy wrapper defaulted to writing it,
// which meant a user's diagnostic silently became selection input: measuring a group could change
// which member carries traffic.
func TestGenericGroupDelayIsDisplayOnly(t *testing.T) {
	target := newDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	storage := urltest.NewHistoryStorage()
	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: storage,
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	before := storage.HealthEntryCount()

	recorder := callGroupDelayHandler(t, server, group,
		"timeout=5000&url="+target.server.URL+"/generate_204")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Greater(t, member.destinations.Load(), int32(0), "the members were measured")

	require.Equal(t, before, storage.HealthEntryCount(),
		"a manual group diagnostic wrote health evidence. That makes a diagnostic into selection "+
			"input: measuring a group would change which member carries traffic, on the strength of "+
			"a URL the group was never configured to check")

	// The display layer is where a manual result belongs, and it was written.
	require.Greater(t, storage.DisplayEntryCount(), 0,
		"the result is still shown, which is the point of a diagnostic")
}

// TestGenericGroupDelayDoesNotGrowHealthScopes is §9.
//
// A user can test an arbitrary URL as often as they like. That must not grow the health map, whose
// size should be decided by the configuration's URLTest groups.
func TestGenericGroupDelayDoesNotGrowHealthScopes(t *testing.T) {
	target := newDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	storage := urltest.NewHistoryStorage()
	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: storage,
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	before := storage.HealthEntryCount()

	const probes = 50
	for index := 0; index < probes; index++ {
		recorder := callGroupDelayHandler(t, server, group,
			"timeout=5000&url="+target.server.URL+"/generate_204?probe="+strconv.Itoa(index))
		require.Equal(t, http.StatusOK, recorder.Code)
	}

	require.Equal(t, before, storage.HealthEntryCount(),
		"%d manual probes against %d different URLs must leave the health map unchanged; otherwise "+
			"a user grows selection state without bound by running diagnostics", probes, probes)
}

// TestGenericGroupDelayUsesBoxCoordinator is §12.
//
// The request context carries no Box services, so using it as the base made a manual group
// measurement bypass the per-Box concurrency limit entirely.
func TestGenericGroupDelayUsesBoxCoordinator(t *testing.T) {
	target := newDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	coordinator := urltest.NewCoordinator(1)
	serverCtx := urltest.ContextWithCoordinator(context.Background(), coordinator)

	server := &Server{
		ctx:            serverCtx,
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	// Hold the Box's only slot, so the measurement cannot proceed.
	releaseSlot, err := coordinator.Acquire(serverCtx)
	require.NoError(t, err)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- callGroupDelayHandler(t, server, group,
			"timeout=3000&url="+target.server.URL+"/generate_204")
	}()

	// The measurement must be waiting for the slot rather than running.
	select {
	case recorder := <-done:
		t.Fatalf("the group measurement completed while the Box's only slot was held (status %d). "+
			"It did not see the Coordinator, so a manual group measurement bypasses the per-Box "+
			"concurrency limit - exactly the budget the coordinator exists to enforce",
			recorder.Code)
	case <-time.After(200 * time.Millisecond):
		// Still queued, which is the correct behaviour.
	}

	releaseSlot()

	select {
	case recorder := <-done:
		require.Equal(t, http.StatusOK, recorder.Code,
			"once admitted the measurement must succeed")
	case <-time.After(10 * time.Second):
		t.Fatal("the measurement never completed after the slot was released")
	}
}

// TestGenericGroupDelayInheritsServerContext covers the RootCA half of §12.
//
// The target's certificate is trusted ONLY by the root pool in the server's context, so the
// measurement succeeds if and only if that context reached it.
func TestGenericGroupDelayInheritsServerContext(t *testing.T) {
	target := newTLSDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	server := &Server{
		ctx:            service.ContextWith[adapter.CertificateStore](context.Background(), target.store),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	recorder := callGroupDelayHandler(t, server, group,
		"timeout=5000&url="+target.server.URL+"/generate_204")

	require.Equal(t, http.StatusOK, recorder.Code,
		"an HTTPS probe must trust the root the Box context carries. Starting from the request "+
			"context discards it, so a private-root endpoint fails here while the identical "+
			"node-level measurement succeeds")
	require.NotZero(t, target.count.Load())
}

// TestGenericGroupDelayIsCancelledWithTheRequest covers the cancellation half of §12.
func TestGenericGroupDelayIsCancelledWithTheRequest(t *testing.T) {
	target := newHangingDelayTargetServer(t)
	member := &fakeGroupMember{tag: "a"}
	group := &plainGroup{tag: "grp", members: []adapter.Outbound{member}, selected: member}

	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet,
		"/group/x/delay?timeout=30000&url="+target.server.URL+"/generate_204", nil)
	request = request.WithContext(context.WithValue(requestCtx, CtxKeyProxy, group))

	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		getGroupDelay(server)(recorder, request)
	}()

	time.Sleep(100 * time.Millisecond)
	cancelRequest()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return after the request context was cancelled; the " +
			"measurement is running on a context that does not observe the client")
	}
}

// urlTestGroupStub is a group that reports itself as a URLTest group.
//
// It exists so the handler's branch for a group that owns its own measurement scope can be exercised
// without building a real URLTest group.
type urlTestGroupStub struct {
	plainGroup
	calls atomic.Int32
}

func (g *urlTestGroupStub) URLTest(ctx context.Context) (map[string]uint16, error) {
	g.calls.Add(1)
	return map[string]uint16{"a": 42}, nil
}

func (g *urlTestGroupStub) PerformUpdateCheck() {}

// TestURLTestGroupDelayRefusesAnOverride is §13/§14.
//
// A URLTest group owns a configured target and a measurement scope this endpoint cannot reconstruct.
// Supplying `url` or `expected` cannot be honoured for it, so the request is refused rather than
// answered with a measurement of a target the client did not name.
//
// # The contract this follows, checked rather than assumed
//
// Mihomo's /group/{name}/delay passes both parameters into the group, but its URLTest group ignores
// the URL it is handed and substitutes its own configured target:
//
//	func (u *URLTest) URLTest(ctx, url string, expectedStatus ...) {
//	    return u.GroupBase.URLTest(ctx, u.testUrl, expectedStatus)
//	}
//
// So the parameters reach the group and are then discarded. Reproducing that would mean answering
// 200 for a measurement of a different target than the caller asked for, which is the silent ignore
// this endpoint must not do.
func TestURLTestGroupDelayRefusesAnOverride(t *testing.T) {
	member := &fakeGroupMember{tag: "a"}
	group := &urlTestGroupStub{plainGroup: plainGroup{tag: "urltest", members: []adapter.Outbound{member}, selected: member}}

	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	for _, override := range []string{"url=http://example.com/generate_204", "expected=204", "url=http://example.com/x&expected=200-299"} {
		t.Run(override, func(t *testing.T) {
			before := group.calls.Load()
			recorder := callGroupDelayHandler(t, server, group, "timeout=5000&"+override)

			require.Equal(t, http.StatusBadRequest, recorder.Code,
				"an override this group cannot honour must be refused, not silently replaced by a "+
					"measurement of its own configured target")
			require.Equal(t, before, group.calls.Load(),
				"and the group must not have been measured for the refused request")
		})
	}
}

// TestURLTestGroupDelayWithoutOverrideMeasures is the corresponding positive case.
func TestURLTestGroupDelayWithoutOverrideMeasures(t *testing.T) {
	member := &fakeGroupMember{tag: "a"}
	group := &urlTestGroupStub{plainGroup: plainGroup{tag: "urltest", members: []adapter.Outbound{member}, selected: member}}

	server := &Server{
		ctx:            context.Background(),
		outbound:       &groupOutboundManager{byTag: map[string]adapter.Outbound{"a": member}, all: []adapter.Outbound{member}},
		urlTestHistory: urltest.NewHistoryStorage(),
		logger:         log.NewNOPFactory().NewLogger("clashapi-test"),
	}

	recorder := callGroupDelayHandler(t, server, group, "timeout=5000")
	require.Equal(t, http.StatusOK, recorder.Code,
		"a URLTest group measured against its own configured target is the supported request")
	require.Equal(t, int32(1), group.calls.Load())
	require.Contains(t, recorder.Body.String(), "42",
		"and the group's own result is what is returned")
}
