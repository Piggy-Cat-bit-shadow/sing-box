package e2e

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

// routeMetadataConfig exercises the metadata a route decision publishes, rather than the fact that
// a connection succeeded.
//
// The rules are chosen so that each of the fields under test has exactly one source:
//
//	auth_user      a rule that can only match because the inbound authenticated the user
//	group chains   a selector and a loadbalance group, so OutboundChain has more than one element
//	traffic class  one group whose TAG is recognised automatically and one outbound whose
//	               configuration states a class explicitly
//	bypass         a rule with the bypass action, judged through the router's own PreMatch
//	client         a rule on the sniffed client, which in this product is QUIC/SSH-only
const routeMetadataConfig = `{
  "log": {"level": "%s"},
  "dns": {
    "servers": [{"tag": "dns-local", "type": "udp", "server": "127.0.0.1", "server_port": %d}],
    "final": "dns-local",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "mixed", "tag": "auth-in", "listen": "127.0.0.1", "listen_port": %d,
      "users": [{"username": "alice", "password": "alice-pass"}, {"username": "bob", "password": "bob-pass"}]
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct", "domain_resolver": "dns-local"},
    {"type": "socks", "tag": "remote", "server": "127.0.0.1", "server_port": %d, "version": "5"},
    {"type": "socks", "tag": "remote-b", "server": "127.0.0.1", "server_port": %d, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["remote", "remote-b"], "default": "remote"},
    {"type": "selector", "tag": "🤖 AI", "outbounds": ["remote"], "default": "remote"},
    {"type": "loadbalance", "tag": "lb", "outbounds": ["remote", "remote-b"], "strategy": "round_robin"},
    {"type": "direct", "tag": "bulk-out", "traffic_class": "bulk"}
  ],
  "route": {
    "rules": [
      {"ip_cidr": ["10.9.9.20/32"], "action": "bypass"},
      {"action": "sniff"},
      {"domain": ["client.test"], "client": ["curl"], "action": "route", "outbound": "remote"},
      {"domain": ["client.test"], "action": "route", "outbound": "direct"},
      {"domain": ["lb.test"], "action": "route", "outbound": "lb"},
      {"domain": ["ai.test"], "action": "route", "outbound": "🤖 AI"},
      {"domain": ["bulk.test"], "action": "route", "outbound": "bulk-out"},
      {"auth_user": ["alice"], "action": "route", "outbound": "sel"},
      {"auth_user": ["bob"], "action": "route", "outbound": "direct"}
    ],
    "final": "direct"
  }
}`

// TestRouteSelectionMetadata drives real clients and asserts the router's own view of each flow.
func TestRouteSelectionMetadata(t *testing.T) {
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sinkA := startSocksSink(t, "127.0.0.1:0")
	sinkB := startSocksSink(t, "127.0.0.1:0")
	for _, sink := range []*socksSink{sinkA, sinkB} {
		sink.backendOverride = map[string]string{
			"alice.test:" + fmt.Sprint(echoPort): echo.listener.Addr().String(),
			"lb.test:" + fmt.Sprint(echoPort):    echo.listener.Addr().String(),
			"ai.test:" + fmt.Sprint(echoPort):    echo.listener.Addr().String(),
			"bob.test:" + fmt.Sprint(echoPort):   echo.listener.Addr().String(),
		}
	}
	proxyPort := freePort(t)
	dnsLocal := startDNSResponder(t, "dns-local", map[string]netip.Addr{
		"client.test": netip.MustParseAddr("127.0.0.1"),
		"bob.test":    netip.MustParseAddr("127.0.0.1"),
		"bulk.test":   netip.MustParseAddr("127.0.0.1"),
	})
	config := fmt.Sprintf(routeMetadataConfig, chainLogLevel, dnsLocal.port(), proxyPort,
		uint16(sinkA.listener.Addr().(*net.TCPAddr).Port), uint16(sinkB.listener.Addr().(*net.TCPAddr).Port))
	running := startChain(t, config)
	proxyAddress := fmt.Sprintf("127.0.0.1:%d", proxyPort)

	// -------------------------------------------------------------------
	// A rule that can only match because the inbound authenticated a user,
	// and a group chain that has to be published in full.
	// -------------------------------------------------------------------
	t.Run("authenticated_user_selects_group", func(t *testing.T) {
		conn := dialSocks5UserPass(t, proxyAddress, "alice", "alice-pass", "alice.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "alice-through-group")
		flows := running.tracker.waitForFlows(t, 1, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "alice", flow.User, "the authenticated identity must reach the rule engine")
		require.Equal(t, "sel", flow.RouteOutbound)
		require.Equal(t, []string{"sel", "remote"}, flow.OutboundChain,
			"the chain must name the group AND the leaf that carried the flow")
		require.Contains(t, flow.RouteRule, "alice")
		require.Equal(t, trafficclass.ClassDefault, flow.TrafficClass)
	})

	t.Run("second_user_takes_the_other_rule", func(t *testing.T) {
		before := len(sinkA.seen()) + len(sinkB.seen())
		conn := dialSocks5UserPass(t, proxyAddress, "bob", "bob-pass", "bob.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "bob-direct")
		require.Equal(t, before, len(sinkA.seen())+len(sinkB.seen()),
			"bob's rule routes to direct; nothing may reach a remote node")
		flows := running.tracker.waitForFlows(t, 2, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "bob", flow.User)
		require.Equal(t, "direct", flow.RouteOutbound)
		require.Equal(t, []string{"direct"}, flow.OutboundChain)
	})

	// -------------------------------------------------------------------
	// A wrong password must not become an unauthenticated flow.
	// -------------------------------------------------------------------
	t.Run("wrong_password_is_refused", func(t *testing.T) {
		before := len(sinkA.seen()) + len(sinkB.seen())
		acceptedBefore := echo.accepts.Load()
		dialSocks5UserPassExpectFailure(t, proxyAddress, "alice", "wrong", "alice.test", echoPort)
		require.Equal(t, before, len(sinkA.seen())+len(sinkB.seen()))
		require.Equal(t, acceptedBefore, echo.accepts.Load())
	})

	// -------------------------------------------------------------------
	// Load balancing: the chain names the group and the chosen member, and
	// the traffic really left through a member.
	// -------------------------------------------------------------------
	t.Run("loadbalance_group_chain", func(t *testing.T) {
		conn := dialSocks5UserPass(t, proxyAddress, "alice", "alice-pass", "lb.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "loadbalance")
		flows := running.tracker.waitForFlows(t, 3, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "lb", flow.RouteOutbound)
		require.Len(t, flow.OutboundChain, 2)
		require.Equal(t, "lb", flow.OutboundChain[0])
		require.Contains(t, []string{"remote", "remote-b"}, flow.OutboundChain[1])
		total := len(sinkA.seen()) + len(sinkB.seen())
		require.Greater(t, total, 0, "a load balanced flow must reach one of the members")
	})

	// -------------------------------------------------------------------
	// Traffic class: automatic from the group tag, and explicit from the
	// outbound's own configuration.
	// -------------------------------------------------------------------
	t.Run("traffic_class_automatic_from_tag", func(t *testing.T) {
		conn := dialSocks5UserPass(t, proxyAddress, "alice", "alice-pass", "ai.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "ai-class")
		flows := running.tracker.waitForFlows(t, 4, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "🤖 AI", flow.RouteOutbound)
		require.Equal(t, []string{"🤖 AI", "remote"}, flow.OutboundChain)
		require.Equal(t, trafficclass.ClassInteractive, flow.TrafficClass,
			"a group whose tag names the AI path must classify the flow as interactive")
	})

	t.Run("traffic_class_explicit_from_configuration", func(t *testing.T) {
		conn := dialSocks5UserPass(t, proxyAddress, "alice", "alice-pass", "bulk.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "bulk-class")
		flows := running.tracker.waitForFlows(t, 5, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "bulk-out", flow.RouteOutbound)
		require.Equal(t, trafficclass.ClassBulk, flow.TrafficClass,
			"the class stated in the configuration must win over automatic detection")
	})

	// -------------------------------------------------------------------
	// The client rule. It is measured rather than assumed: in this product
	// (and in upstream sing-box, whose common/sniff/http.go is identical)
	// only the QUIC and SSH sniffers populate metadata.Client, so no HTTP
	// User-Agent can ever satisfy it.
	// -------------------------------------------------------------------
	t.Run("client_rule_has_no_http_source", func(t *testing.T) {
		// Two rules name the same domain and only the first needs metadata.Client, so the rule that
		// matches IS the measurement. The flow is a real SOCKS5 CONNECT carrying a domain: there is
		// no HTTP path that could populate Client either, because the mixed inbound's HTTP parser
		// consumes the CONNECT request itself before the sniffer is ever asked.
		conn := dialSocks5UserPass(t, proxyAddress, "alice", "alice-pass", "client.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "client-rule")
		require.Contains(t, dnsLocal.asked(), "client.test/1",
			"the fallback rule routes to the direct outbound, which resolved the CONNECT domain")
		flows := running.tracker.waitForFlows(t, 6, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "client.test:"+fmt.Sprint(echoPort), flow.Destination)
		require.Empty(t, flow.Client,
			"measured: only the QUIC and SSH sniffers set metadata.Client, in this fork and upstream")
		require.NotContains(t, flow.RouteRule, "curl",
			"the client rule must not have matched; the fallback domain rule did")
		require.Equal(t, "direct", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// The bypass action, judged through the router's own PreMatch - the
	// same decision the TUN packet path makes for a flow.
	// -------------------------------------------------------------------
	t.Run("bypass_verdict_has_no_port", func(t *testing.T) {
		verdict := adapter.JudgeFlow(running.router(), adapter.InboundContext{
			Inbound:     "tun-in",
			InboundType: C.TypeTun,
		}, uint8(header.TCPProtocolNumber),
			netip.MustParseAddrPort("198.18.0.2:40000"), netip.MustParseAddrPort("10.9.9.20:443"), nil)
		require.Equal(t, tun.ActionBypass, verdict.Action,
			"a bypass rule must produce a bypass verdict, not a userspace flow")
		require.Nil(t, verdict.Port,
			"a bypass verdict must carry no Port: sing-tun rewrites ActionBypass+Port back into a flow")
	})

	t.Run("a_destination_no_rule_matches_is_accepted", func(t *testing.T) {
		verdict := adapter.JudgeFlow(running.router(), adapter.InboundContext{
			Inbound:     "tun-in",
			InboundType: C.TypeTun,
		}, uint8(header.TCPProtocolNumber),
			netip.MustParseAddrPort("198.18.0.2:40000"), netip.MustParseAddrPort("10.9.9.21:443"), nil)
		require.Equal(t, tun.ActionAccept, verdict.Action)
	})
}
