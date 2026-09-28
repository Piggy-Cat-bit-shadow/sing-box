//go:build with_lx_command

package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Integration tests for the JiejieBox command surface against a REAL running
// instance.
//
// The contract tests in started_service_command_lx_grpc_test.go prove the methods
// are reachable; these prove they return the RIGHT ANSWER, which requires a real
// engine: a real outbound manager, real groups and a real urlTestHistoryStorage.
//
// Everything here is OFFLINE. The single outbound is `direct` and the URL test
// target is a local httptest server, so the suite needs no internet, no VPS and no
// credentials, and cannot flake on a remote host being down. That matters because
// these tests must run in CI on every change.

// testFixtureConfig builds a config with a direct outbound and a selector over two
// more direct outbounds.
//
// The tag names are chosen to match how a real JiejieBox profile looks, so the
// group/selection assertions read like the UI interaction they stand for.
func testFixtureConfig(testURL, cachePath string) string {
	return fmt.Sprintf(`{
  "log": {"level": "error", "disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "direct", "tag": "node-a"},
    {"type": "direct", "tag": "node-b"},
    {
      "type": "selector",
      "tag": "🤖 AI",
      "outbounds": ["node-a", "node-b"],
      "default": "node-a"
    },
    {
      "type": "selector",
      "tag": "single-node-group",
      "outbounds": ["direct"],
      "default": "direct"
    }
  ],
  "route": {
    "final": "direct",
    "rules": [
      {"action": "route", "outbound": "direct", "domain": ["example.com"]}
    ]
  },
  "experimental": {
    "cache_file": {"enabled": true, "path": %q}
  }
}`, cachePath)
}

// registerTestRegistries installs the minimum registries the fixture config needs:
// the direct outbound, the selector group, and a local DNS transport.
//
// box.Context installs them on the context; newInstance reads them from there.
func registerTestRegistries() {
	outboundRegistry := outbound.NewRegistry()
	direct.RegisterOutbound(outboundRegistry)
	group.RegisterSelector(outboundRegistry)
	group.RegisterURLTest(outboundRegistry)

	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)

	// newInstance derives its context from s.ctx (the ServiceOptions context), so
	// the registries must be installed THERE. newInstance then calls
	// service.ExtendContext on it, which is why the registries survive the call.
	boxContext = box.Context(context.Background(),
		inbound.NewRegistry(),
		outboundRegistry,
		endpoint.NewRegistry(),
		dnsRegistry,
		service.NewRegistry(),
		certificate.NewRegistry(),
	)
}

// boxContext carries the test registries into newInstance, which derives its
// context from the service context.
var boxContext context.Context

// liveFixture starts a real instance and returns a client talking to it.
type liveFixture struct {
	harness *startedServiceGRPCHarness
	server  *httptest.Server
	testURL string
}

func newLiveFixture(t *testing.T) *liveFixture {
	t.Helper()

	// A local HTTP target for the URL test. urltest.URLTest only cares that the
	// request completes, so any 2xx works.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	// httptest binds to 127.0.0.1; the URL test must therefore reach loopback. The
	// default fixture routes loopback through the direct outbound implicitly because
	// `direct` dials the system resolver and the system route.
	//
	// The registries are built HERE rather than through package include, because
	// include under the jiejie_client_macos tag reaches service/api, which imports
	// THIS package — an import cycle a test cannot have. Registering only what the
	// fixture needs also keeps the test honest: it proves the RPCs work against a
	// real engine without pulling in the whole product registry.
	registerTestRegistries()
	// The harness picks up boxContext as the service context, so newInstance finds
	// the registries registered above.
	harness := newStartedServiceHarnessWithContext(t, boxContext)

	// The cache file defaults to the RELATIVE path "cache.db"
	// (experimental/cachefile/cache.go:88), so two instances started from the same
	// process would contend for one file and the second would fail with
	// "initialize cache-file: timeout". A per-test path keeps the tests independent
	// of each other and of the developer's working directory.
	cachePath := filepath.Join(t.TempDir(), "cache.db")

	require.NoError(t, harness.service.StartOrReloadService(
		context.Background(), testFixtureConfig(server.URL, cachePath), nil,
	), "the fixture config must start; a failure here means the fixture itself is "+
		"wrong, not that the RPC under test failed")

	return &liveFixture{harness: harness, server: server, testURL: server.URL}
}

// getGroups fetches the group snapshot through the real client stub.
func (f *liveFixture) getGroups(t *testing.T) *Groups {
	t.Helper()
	groups, err := f.harness.client.GetGroups(context.Background(), &emptypb.Empty{})
	require.NoError(t, err, "GetGroups must succeed against a started instance")
	return groups
}

// findGroup returns the group with the given tag, failing if it is absent.
func findGroup(t *testing.T, groups *Groups, tag string) *Group {
	t.Helper()
	for _, group := range groups.Group {
		if group.Tag == tag {
			return group
		}
	}
	tags := make([]string, 0, len(groups.Group))
	for _, group := range groups.Group {
		tags = append(tags, group.Tag)
	}
	require.Failf(t, "group not found",
		"GetGroups did not report group %q; it reported %v. A group defined in the "+
			"config and missing from GetGroups is exactly the 'proxy list is empty' "+
			"failure the user sees.", tag, tags)
	return nil
}

func findItem(t *testing.T, group *Group, tag string) *GroupItem {
	t.Helper()
	for _, item := range group.Items {
		if item.Tag == tag {
			return item
		}
	}
	require.Failf(t, "item not found", "group %q does not list node %q", group.Tag, tag)
	return nil
}

// TestGetGroupsReturnsConfiguredGroups is the primary acceptance test.
//
// It asserts the group the user is missing ("🤖 AI") is present, marked selectable,
// carrying its members, and reporting a current selection — the four things the
// proxy picker needs to render an actionable list.
func TestGetGroupsReturnsConfiguredGroups(t *testing.T) {
	fixture := newLiveFixture(t)
	groups := fixture.getGroups(t)

	ai := findGroup(t, groups, "🤖 AI")
	require.True(t, ai.Selectable, "a selector must report selectable=true, or the "+
		"UI renders it as a read-only group and offers no way to switch nodes")
	require.Equal(t, "selector", ai.Type)
	require.Equal(t, "node-a", ai.Selected,
		"the default selection from the config must be reported")
	require.Len(t, ai.Items, 2, "both configured members must be listed")
	findItem(t, ai, "node-a")
	findItem(t, ai, "node-b")
}

// TestGetGroupsKeepsSingleNodeAndEmptyGroups pins the fix for the len<2 drop.
//
// Upstream's readGroups skipped groups with fewer than two items, which hides a
// single-node selector completely. A user with such a group sees a proxy list that
// silently omits it, with no error explaining the absence — indistinguishable from
// "the daemon has no group support at all", which is the bug being fixed.
func TestGetGroupsKeepsSingleNodeAndEmptyGroups(t *testing.T) {
	fixture := newLiveFixture(t)
	groups := fixture.getGroups(t)

	single := findGroup(t, groups, "single-node-group")
	require.Len(t, single.Items, 1,
		"a single-node selector must still be reported; dropping it is the "+
			"len<2 regression this asserts against")
	require.Equal(t, "direct", single.Selected)
}

// TestSelectOutboundRoundTripsThroughGetGroups is the §12 regression test.
//
// It does not re-test SelectOutbound's own behaviour (which already worked); it
// asserts the two RPCs agree, because a selection the UI makes must be visible in
// the very next snapshot. Without this, a switch could appear to succeed and then
// silently revert on refresh.
func TestSelectOutboundRoundTripsThroughGetGroups(t *testing.T) {
	fixture := newLiveFixture(t)

	before := findGroup(t, fixture.getGroups(t), "🤖 AI")
	require.Equal(t, "node-a", before.Selected, "precondition: default is node-a")

	_, err := fixture.harness.client.SelectOutbound(context.Background(), &SelectOutboundRequest{
		GroupTag:    "🤖 AI",
		OutboundTag: "node-b",
	})
	require.NoError(t, err, "SelectOutbound must accept a member of the selector")

	after := findGroup(t, fixture.getGroups(t), "🤖 AI")
	require.Equal(t, "node-b", after.Selected,
		"GetGroups must reflect the new selection immediately; a stale 'node-a' "+
			"means the switch is not observable and the UI would show the old node")

	// And the change must hold across a second read, ruling out a one-shot cache.
	again := findGroup(t, fixture.getGroups(t), "🤖 AI")
	require.Equal(t, "node-b", again.Selected, "the selection must be stable")
}

// TestURLTestOutboundWritesHistoryVisibleInGetGroups closes the loop the §9
// requirement describes: a delay measured by URLTestOutbound must be the delay
// GetGroups reports for that node.
//
// This is the assertion that catches a history-key mismatch. Writing the history
// under one key and reading it under another produces a per-node delay that is
// returned correctly to the caller and then never appears in the list — a bug that
// is invisible to a test of URLTestOutbound alone.
func TestURLTestOutboundWritesHistoryVisibleInGetGroups(t *testing.T) {
	fixture := newLiveFixture(t)

	response, err := fixture.harness.client.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
		OutboundTag: "node-a",
		Link:        fixture.testURL,
		Timeout:     5000,
	})
	require.NoError(t, err, "an application outcome is reported in the payload, so "+
		"the gRPC call itself must not fail")
	require.Empty(t, response.Error,
		"the local test server is reachable through direct, so the test must succeed "+
			"with an empty error; delay is only meaningful then")
	require.LessOrEqual(t, response.Delay, uint32(5000),
		"a delay at or above the timeout means the deadline fired rather than the "+
			"request completing")

	item := findItem(t, findGroup(t, fixture.getGroups(t), "🤖 AI"), "node-a")
	require.NotZero(t, item.UrlTestTime,
		"GetGroups must show the URL-test time the test just wrote; a zero means the "+
			"history key used by URLTestOutbound does not match the one readGroups "+
			"reads, so the measured delay would never reach the UI")
	// The DELAY must match the payload exactly, but it is not asserted to be
	// non-zero: urltest reports whole milliseconds (common/urltest/urltest.go:153),
	// and a loopback round trip is routinely sub-millisecond, so 0 is a legitimate
	// successful measurement here. Asserting non-zero would make this test flaky on
	// a fast machine while proving nothing about the code under test.
	//
	// This is exactly the distinction the proto documents: delay is valid iff
	// error == "", and 0 ms with an empty error is success, not failure.
	require.Equal(t, response.Delay, uint32(item.UrlTestDelay),
		"GetGroups must report the SAME delay URLTestOutbound just measured; a "+
			"mismatch means the two disagree about the history key, so a node would "+
			"show one latency in the list and another when tested on its own")
}

// TestURLTestOutboundReportsUnknownTagInPayload pins the Variant B error model.
//
// The client must have ONE failure channel. An unknown tag is an application
// outcome, so it belongs in response.error with a nil gRPC error; if it instead
// arrived as a transport status, every caller would need two branches.
func TestURLTestOutboundReportsUnknownTagInPayload(t *testing.T) {
	fixture := newLiveFixture(t)

	response, err := fixture.harness.client.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
		OutboundTag: "does-not-exist",
		Link:        fixture.testURL,
	})
	require.NoError(t, err,
		"Variant B: an unknown outbound is an APPLICATION error carried in the "+
			"payload, never a transport-level gRPC error")
	require.NotNil(t, response)
	require.NotEmpty(t, response.Error, "the payload must explain the failure")
	require.Contains(t, response.Error, "does-not-exist",
		"the message must name the tag, or the user cannot tell which node failed")
}

// TestURLTestOutboundHonoursCallerCancellation is the §8 requirement.
//
// The test must be parented to the gRPC call ctx. Parenting it to the service ctx
// instead makes it outlive the caller: cancelling the request would not abort the
// dial, and the only remaining lever would be tearing down the whole connection.
//
// The assertion is deliberately about the DEADLINE, not about a specific error
// string: what must hold is that a cancelled call returns promptly rather than
// running to completion.
func TestURLTestOutboundHonoursCallerCancellation(t *testing.T) {
	fixture := newLiveFixture(t)

	// The ctx is ALREADY CANCELLED before the call is made, so the outcome does not
	// depend on beating a deadline against a fast loopback server. An earlier
	// version used a 1ms timeout and was flaky: the local round trip sometimes
	// finished first, which is a property of the test machine, not of the code.
	//
	// Cancelling up front is also the stronger assertion. It proves the handler
	// consults the CALL ctx at all: an implementation using context.Background()
	// would ignore an already-dead ctx entirely and return a successful measurement.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := fixture.harness.client.URLTestOutbound(ctx, &URLTestOutboundRequest{
		OutboundTag: "node-a",
		Link:        fixture.testURL,
		// No request timeout: the CALL ctx is the only bound, which is exactly the
		// path that a context.Background() implementation would ignore.
	})
	elapsed := time.Since(start)

	require.Error(t, err,
		"a cancelled call ctx must fail the RPC; a successful response here means "+
			"the handler ignored the gRPC ctx and ran the test against the service "+
			"context, which is exactly the bug this asserts against")
	require.Equal(t, codes.Canceled, status.Code(err),
		"the call must fail because the CALLER cancelled, not for some unrelated "+
			"reason; got %v", err)
	require.Less(t, elapsed, drainTimeout,
		"the call must return promptly after cancellation rather than running the "+
			"full test")
}

// TestGetGroupsAndSubscribeGroupsAgree is the §21 parity requirement.
//
// SubscribeGroups and GetGroups must describe the same instance identically. They
// already shared readGroups(), so this test pins that relationship: if someone later
// forks the builder for one of them, the two views drift and the UI shows different
// data depending on whether it is being pushed or pulling.
func TestGetGroupsAndSubscribeGroupsAgree(t *testing.T) {
	fixture := newLiveFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	stream, err := fixture.harness.client.SubscribeGroups(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	pushed, err := stream.Recv()
	require.NoError(t, err, "SubscribeGroups must emit an initial snapshot")

	pulled := fixture.getGroups(t)

	// Compare normalized snapshots: the stream's first frame is taken slightly
	// earlier, so only the fields that describe identity and state are compared.
	require.Equal(t, len(pushed.Group), len(pulled.Group),
		"the stream and the unary call must report the same number of groups")
	for _, pushedGroup := range pushed.Group {
		pulledGroup := findGroup(t, pulled, pushedGroup.Tag)
		require.Equal(t, pushedGroup.Type, pulledGroup.Type)
		require.Equal(t, pushedGroup.Selectable, pulledGroup.Selectable)
		require.Equal(t, pushedGroup.Selected, pulledGroup.Selected)
		require.Equal(t, len(pushedGroup.Items), len(pulledGroup.Items))
	}
}

// TestGetOutboundsAndSubscribeOutboundsAgree is the §22 parity requirement, the
// outbound-side twin of the test above.
func TestGetOutboundsAndSubscribeOutboundsAgree(t *testing.T) {
	fixture := newLiveFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	stream, err := fixture.harness.client.SubscribeOutbounds(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	pushed, err := stream.Recv()
	require.NoError(t, err, "SubscribeOutbounds must emit an initial snapshot")

	pulled, err := fixture.harness.client.GetOutbounds(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	require.Equal(t, len(pushed.Outbounds), len(pulled.Outbounds),
		"the stream and the unary call must report the same number of outbounds")
	require.NotEmpty(t, pulled.Outbounds, "the fixture defines outbounds")

	pushedTags := make([]string, 0, len(pushed.Outbounds))
	for _, item := range pushed.Outbounds {
		pushedTags = append(pushedTags, item.Tag)
	}
	pulledTags := make([]string, 0, len(pulled.Outbounds))
	for _, item := range pulled.Outbounds {
		pulledTags = append(pulledTags, item.Tag)
	}
	require.ElementsMatch(t, pushedTags, pulledTags,
		"both views must list the same outbounds; the fixture has standalone "+
			"outbounds that belong to no group, which is why GetOutbounds exists "+
			"alongside GetGroups")
}

// TestGetOutboundsReportsTypeAndHistory asserts the fields the UI actually renders.
func TestGetOutboundsReportsTypeAndHistory(t *testing.T) {
	fixture := newLiveFixture(t)

	_, err := fixture.harness.client.URLTestOutbound(context.Background(), &URLTestOutboundRequest{
		OutboundTag: "node-b",
		Link:        fixture.testURL,
		Timeout:     5000,
	})
	require.NoError(t, err)

	list, err := fixture.harness.client.GetOutbounds(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)

	var node *GroupItem
	for _, item := range list.Outbounds {
		if item.Tag == "node-b" {
			node = item
			break
		}
	}
	require.NotNil(t, node, "GetOutbounds must list a standalone node outbound")
	require.Equal(t, "direct", node.Type, "the UI needs the type to pick an icon")
	require.NotZero(t, node.UrlTestTime,
		"GetOutbounds and URLTestOutbound must share the history key too; without a "+
			"timestamp the per-node latency never reaches this view")
}

// ensure a loopback dial actually reaches the local server, so a failure above is
// attributable. This also documents the offline nature of the fixture.
func TestFixtureLoopbackIsReachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	require.NoError(t, err, "the local test server must be reachable")
	defer response.Body.Close()

	// Guard against the fixture silently depending on the outside world: the URL
	// must be loopback.
	host, _, err := net.SplitHostPort(response.Request.URL.Host)
	require.NoError(t, err)
	require.True(t, net.ParseIP(host).IsLoopback(),
		"the fixture must use a loopback URL so the suite needs no internet")
}
