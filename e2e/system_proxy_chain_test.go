package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// systemProxyChainConfig is the configuration under test. It is a real configuration document, not
// a struct literal, so the whole decode path (registry lookup, option validation, defaulting) is
// part of what is exercised.
//
// Rule order is load-bearing and deliberately adversarial in three places:
//
//   - rules 0 and 1 name the same domain, so "first match wins" is measured rather than assumed;
//   - the sniff action is rule 2, ahead of every rule that reads sniffed metadata, because the
//     router continues matching AFTER the sniff rule;
//   - a CIDR rule that cannot match sits above the ones that can, so a rule that matches
//     everything by accident is visible.
const systemProxyChainConfig = `{
  "log": {"level": "%s"},
  "dns": {
    "servers": [
      {"tag": "dns-local", "type": "udp", "server": "127.0.0.1", "server_port": %d}
    ],
    "final": "dns-local",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "direct", "tag": "direct-resolved", "domain_resolver": "dns-local"},
    {"type": "socks", "tag": "remote", "server": "127.0.0.1", "server_port": %d, "version": "5"},
    {"type": "socks", "tag": "remote-resolved", "server": "127.0.0.1", "server_port": %d, "version": "5", "domain_resolver": "dns-local"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "rules": [
      {"domain": ["order-first.test"], "action": "route", "outbound": "remote"},
      {"domain": ["order-first.test"], "action": "route", "outbound": "direct"},
      {"action": "sniff"},
      {"domain": ["blocked.test"], "action": "reject"},
      {"domain": ["sniffed.test"], "action": "route", "outbound": "remote"},
      {"domain": ["forwarded.test"], "action": "route", "outbound": "remote"},
      {"domain": ["resolved.test"], "action": "route", "outbound": "direct-resolved"},
      {"domain": ["resolved-rule.test"], "action": "route", "outbound": "remote-resolved"},
      {"ip_cidr": ["192.0.2.0/24", "198.51.100.0/24"], "action": "route", "outbound": "block"},
      {"domain": ["resolve-then-rule.test"], "action": "resolve", "strategy": "ipv4_only"},
      {"ip_cidr": ["127.0.0.1/32"], "port": [%d], "action": "route", "outbound": "remote"},
      {"ip_cidr": ["::1/128"], "action": "route", "outbound": "remote"}
    ],
    "final": "direct"
  }
}`

// TestSystemProxyChain drives the whole app -> system proxy -> inbound -> route -> DNS -> outbound
// -> remote chain with real clients and real far ends.
//
// Every scenario asserts three separate things, because they fail independently:
//
//	transport  bytes really crossed, from the far end's own counter;
//	selection  the far end really is the one the configuration selected (the SOCKS sink records
//	           what it was asked for, so "direct" traffic reaching it is a detectable bug);
//	metadata   the router's own view of the flow - destination, domain, protocol, resolved
//	           addresses, matched rule, selected outbound, chain and traffic class.
func TestSystemProxyChain(t *testing.T) {
	echo4 := startEchoServer(t, "tcp", "127.0.0.1:0")
	echo4b := startEchoServer(t, "tcp", "127.0.0.1:0")
	echo6 := startEchoServer(t, "tcp", "[::1]:0")
	udpEcho := startUDPEchoServer(t, "udp", "127.0.0.1:0")
	tlsEcho, _, tlsPool := startTLSEchoServer(t, "tcp", "127.0.0.1:0")
	sink := startSocksSink(t, "127.0.0.1:0")
	dnsLocal := startDNSResponder(t, "dns-local", map[string]netip.Addr{
		"resolved.test":          netip.MustParseAddr("127.0.0.1"),
		"resolved-rule.test":     netip.MustParseAddr("127.0.0.1"),
		"resolve-then-rule.test": netip.MustParseAddr("127.0.0.1"),
		"order-first.test":       netip.MustParseAddr("127.0.0.1"),
	})

	proxyPort := freePort(t)
	sinkPort := uint16(sink.listener.Addr().(*net.TCPAddr).Port)
	config := fmt.Sprintf(systemProxyChainConfig,
		chainLogLevel,
		dnsLocal.port(),
		proxyPort,
		sinkPort,
		sinkPort,
		echo4b.listener.Addr().(*net.TCPAddr).Port,
	)
	running := startChain(t, config)
	proxyAddress := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	echo4Port := uint16(echo4.listener.Addr().(*net.TCPAddr).Port)
	echo4bPort := uint16(echo4b.listener.Addr().(*net.TCPAddr).Port)
	echo6Port := uint16(echo6.listener.Addr().(*net.TCPAddr).Port)
	udpEchoPort := uint16(udpEcho.conn.LocalAddr().(*net.UDPAddr).Port)
	tlsPort := uint16(tlsEcho.listener.Addr().(*net.TCPAddr).Port)
	sink.backendOverride = map[string]string{
		"forwarded.test:" + fmt.Sprint(echo4Port):     echo4.listener.Addr().String(),
		"resolved-rule.test:" + fmt.Sprint(echo4Port): echo4.listener.Addr().String(),
		"order-first.test:" + fmt.Sprint(echo4bPort):  echo4b.listener.Addr().String(),
	}

	// -------------------------------------------------------------------
	// SOCKS5 to a literal IPv4 destination, selected by the final outbound.
	// -------------------------------------------------------------------
	t.Run("socks5_ipv4_literal_direct", func(t *testing.T) {
		before := len(sink.seen())
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echo4Port)
		defer conn.Close()
		requireEcho(t, conn, "socks5-ipv4-direct")
		flows := running.tracker.waitForFlows(t, 1, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "tcp", flow.Network)
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(echo4Port), flow.Destination)
		require.Equal(t, "mixed-in", flow.Inbound)
		require.Equal(t, "mixed", flow.InboundType)
		require.Equal(t, "direct", flow.RouteOutbound)
		require.Equal(t, []string{"direct"}, flow.OutboundChain)
		require.Empty(t, flow.RouteRule, "final outbound has no matched rule")
		require.Greater(t, echo4.accepts.Load(), int64(0))
		require.Equal(t, before, len(sink.seen()), "direct traffic must not reach the remote outbound")
	})

	// -------------------------------------------------------------------
	// SOCKS5 with a DOMAIN destination: the domain has to reach the remote
	// node unresolved, because that is the point of a proxy.
	//
	// metadata.Domain stays empty on purpose: it is the SNIFFED domain, and
	// nothing sniffed this flow. The rule still matches, because the domain
	// conditions fall back to the FQDN destination - which this row proves by
	// the rule that matched.
	// -------------------------------------------------------------------
	t.Run("socks5_domain_forwarded_to_remote", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x03, "forwarded.test", echo4Port)
		defer conn.Close()
		requireEcho(t, conn, "socks5-domain-forwarded")
		request := sink.waitForHost(t, "forwarded.test", 10*time.Second)
		require.Equal(t, socksRequest{AddressType: 0x03, Host: "forwarded.test", Port: echo4Port}, request,
			"the remote node must receive the DOMAIN, not a locally resolved address")
		flows := running.tracker.waitForFlows(t, 2, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "forwarded.test:"+fmt.Sprint(echo4Port), flow.Destination)
		require.Empty(t, flow.Domain, "Domain is the sniffed domain; this flow was never sniffed")
		require.Equal(t, "remote", flow.RouteOutbound)
		require.Equal(t, []string{"remote"}, flow.OutboundChain)
		require.Contains(t, flow.RouteRule, "forwarded.test")
		require.Empty(t, flow.DestinationAddresses, "nothing resolved this destination")
	})

	// -------------------------------------------------------------------
	// Rule order: two rules name the same domain; the first must win.
	// -------------------------------------------------------------------
	t.Run("rule_order_first_match_wins", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x03, "order-first.test", echo4bPort)
		defer conn.Close()
		requireEcho(t, conn, "rule-order")
		sink.waitForHost(t, "order-first.test", 10*time.Second)
		flows := running.tracker.waitForFlows(t, 3, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "remote", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// A rule that must NOT match: if the 192.0.2.0/24 rule matched a
	// loopback destination the flow would be blackholed.
	// -------------------------------------------------------------------
	t.Run("cidr_rule_does_not_overmatch", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echo4Port)
		defer conn.Close()
		requireEcho(t, conn, "cidr-negative-control")
		flows := running.tracker.waitForFlows(t, 4, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "direct", flow.RouteOutbound)
		require.NotContains(t, flow.RouteRule, "192.0.2.0/24")
	})

	// -------------------------------------------------------------------
	// HTTP CONNECT with a literal IPv4 target.
	// -------------------------------------------------------------------
	t.Run("http_connect_ipv4", func(t *testing.T) {
		conn, head := dialHTTPConnect(t, proxyAddress, fmt.Sprintf("127.0.0.1:%d", echo4Port), "")
		defer conn.Close()
		require.Contains(t, head, "HTTP/1.1 200")
		requireEcho(t, conn, "http-connect-ipv4")
		flows := running.tracker.waitForFlows(t, 5, 10*time.Second)
		require.Equal(t, "direct", flows[len(flows)-1].RouteOutbound)
	})

	// -------------------------------------------------------------------
	// HTTP CONNECT to an IP, carrying TLS for a DIFFERENT name: the only
	// source of Domain and Protocol here is the sniffer, so this row fails
	// if sniffing does not run or does not feed the rules.
	// -------------------------------------------------------------------
	t.Run("http_connect_sniffed_tls_long_lived", func(t *testing.T) {
		conn, _ := dialHTTPConnect(t, proxyAddress, fmt.Sprintf("127.0.0.1:%d", tlsPort), "")
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: "sniffed.test", RootCAs: tlsPool})
		require.NoError(t, tlsConn.SetDeadline(time.Now().Add(30*time.Second)))
		require.NoError(t, tlsConn.HandshakeContext(context.Background()))
		// A long-lived connection: keep it busy for long enough that a proxy which half-closes,
		// idles out or loses ownership of the tunnel would be caught.
		deadline := time.Now().Add(3 * time.Second)
		round := 0
		for time.Now().Before(deadline) {
			payload := fmt.Sprintf("long-lived-%02d", round)
			_, err := tlsConn.Write([]byte(payload))
			require.NoError(t, err, "write %d on the long-lived TLS tunnel", round)
			reply := make([]byte, len(payload))
			_, err = io.ReadFull(tlsConn, reply)
			require.NoError(t, err, "read %d back on the long-lived TLS tunnel", round)
			require.Equal(t, payload, string(reply))
			round++
		}
		require.Greater(t, round, 100, "the long-lived loop should have run many rounds")
		// The SNI selects the outbound but does NOT rewrite the destination: the sniff action has
		// no override_destination, so the remote node is asked for the address the client named.
		// Both halves are asserted, because a proxy that silently re-resolved the sniffed name
		// would still pass a rule-match assertion.
		request := sink.waitForHostPort(t, "127.0.0.1", tlsPort, 10*time.Second)
		require.Equal(t, "127.0.0.1", request.Host,
			"the client named an IP; sniffing must not rewrite the destination")
		flows := running.tracker.waitForFlows(t, 6, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "tls", flow.Protocol, "the TLS sniffer must have run before the domain rules")
		require.Equal(t, "sniffed.test", flow.Domain)
		require.Equal(t, "remote", flow.RouteOutbound, "the sniffed SNI selected this outbound")
		require.Contains(t, flow.RouteRule, "sniffed.test")
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(tlsPort), flow.Destination)
	})

	// -------------------------------------------------------------------
	// SOCKS5 to a literal IPv6 destination.
	// -------------------------------------------------------------------
	t.Run("socks5_ipv6_literal", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x04, "::1", echo6Port)
		defer conn.Close()
		requireEcho(t, conn, "socks5-ipv6")
		request := sink.waitForHost(t, "::1", 10*time.Second)
		require.Equal(t, byte(0x04), request.AddressType, "the remote node must receive a real IPv6 address")
		require.Equal(t, "::1", request.Host)
		flows := running.tracker.waitForFlows(t, 7, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "[::1]:"+fmt.Sprint(echo6Port), flow.Destination)
		require.Equal(t, "remote", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// HTTP CONNECT to a literal IPv6 target.
	// -------------------------------------------------------------------
	t.Run("http_connect_ipv6", func(t *testing.T) {
		conn, head := dialHTTPConnect(t, proxyAddress, fmt.Sprintf("[::1]:%d", echo6Port), "")
		defer conn.Close()
		require.Contains(t, head, "HTTP/1.1 200")
		requireEcho(t, conn, "http-connect-ipv6")
		flows := running.tracker.waitForFlows(t, 8, 10*time.Second)
		require.Equal(t, "[::1]:"+fmt.Sprint(echo6Port), flows[len(flows)-1].Destination)
	})

	// -------------------------------------------------------------------
	// resolve action: the route decision has to consume the DNS answer.
	// -------------------------------------------------------------------
	t.Run("resolve_action_feeds_ip_rule", func(t *testing.T) {
		// resolve-then-rule.test resolves to 127.0.0.1, so the flow reaches echo4b through the
		// remote node, chosen by the CIDR+port rule that can only match after the resolve.
		conn := dialSocks5(t, proxyAddress, 0x03, "resolve-then-rule.test", echo4bPort)
		defer conn.Close()
		requireEcho(t, conn, "resolve-action")
		flows := running.tracker.waitForFlows(t, 9, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, []string{"127.0.0.1"}, flow.DestinationAddresses,
			"the resolve action must publish the resolved addresses on the flow")
		require.Equal(t, "remote", flow.RouteOutbound)
		require.Contains(t, flow.RouteRule, "127.0.0.1/32")
		require.Contains(t, dnsLocal.asked(), "resolve-then-rule.test/1")
	})

	// -------------------------------------------------------------------
	// A domain reaching a socks outbound that declares a resolver.
	//
	// This is the documented negative: for an outbound other than direct,
	// dial.domain_resolver affects the SERVER address, not the request
	// domain - so the socks5 outbound below must still forward the domain
	// even though it declares one.
	// -------------------------------------------------------------------
	t.Run("outbound_domain_resolver_scope", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x03, "resolved-rule.test", echo4Port)
		defer conn.Close()
		requireEcho(t, conn, "outbound-resolver-scope")
		request := sink.waitForHost(t, "resolved-rule.test", 10*time.Second)
		require.Equal(t, byte(0x03), request.AddressType,
			"a socks outbound's domain_resolver governs its SERVER address; the request domain is not resolved locally")
		require.Equal(t, "resolved-rule.test", request.Host)
		require.NotContains(t, dnsLocal.asked(), "resolved-rule.test/1",
			"the request domain of a socks5 outbound must not be queried through its domain_resolver")
		flows := running.tracker.waitForFlows(t, 10, 10*time.Second)
		require.Equal(t, "remote-resolved", flows[len(flows)-1].RouteOutbound)
	})

	// -------------------------------------------------------------------
	// The direct outbound, in contrast, DOES resolve the request domain
	// through its own resolver: the name below exists only in the test's
	// DNS server, so reaching the loopback echo server proves the DNS
	// answer was used.
	// -------------------------------------------------------------------
	t.Run("direct_outbound_resolves_request_domain", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x03, "resolved.test", echo4Port)
		defer conn.Close()
		requireEcho(t, conn, "direct-resolves-request-domain")
		require.Contains(t, dnsLocal.asked(), "resolved.test/1")
		flows := running.tracker.waitForFlows(t, 11, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "direct-resolved", flow.RouteOutbound)
		require.Equal(t, "resolved.test:"+fmt.Sprint(echo4Port), flow.Destination,
			"the destination stays the requested name; resolution happens inside the outbound")
	})

	// -------------------------------------------------------------------
	// reject: the client must be refused, and nothing may egress.
	// -------------------------------------------------------------------
	t.Run("reject_action_blocks", func(t *testing.T) {
		acceptedBefore := echo4.accepts.Load()
		sinkBefore := len(sink.seen())
		conn, replyCode := socks5Request(t, proxyAddress, 0x03, "blocked.test", echo4Port)
		if conn != nil {
			defer conn.Close()
		}
		// The reply code is recorded rather than asserted here: see TestRejectReplyCode for the
		// measurement and for why the observable contract asserted here is "nothing egresses".
		t.Logf("SOCKS5 reply code for a rejected destination: 0x%02x", replyCode)
		require.Equal(t, acceptedBefore, echo4.accepts.Load(), "a rejected destination must not be dialled")
		require.Equal(t, sinkBefore, len(sink.seen()), "a rejected destination must not reach the remote outbound")
	})

	// -------------------------------------------------------------------
	// The forward-proxy path: a plain HTTP request in absolute form, which
	// is what an application configured with an HTTP proxy actually sends
	// for http:// URLs. No CONNECT is involved, so this is a different
	// parser, a different reply shape and a different tunnel.
	// -------------------------------------------------------------------
	t.Run("http_forward_proxy_get", func(t *testing.T) {
		origin := startHTTPOrigin(t)
		proxyURL, err := url.Parse("http://" + proxyAddress)
		require.NoError(t, err)
		// A real http.Client with the proxy configured, which is exactly how an application uses
		// a system HTTP proxy for an http:// URL: absolute-form request line, no CONNECT.
		flowsBefore := running.tracker.count()
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   15 * time.Second,
		}
		response, err := client.Get("http://" + origin.address() + "/body")
		require.NoError(t, err, "a forward-proxy GET must complete")
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "forward-proxy-body", string(body), "the origin's body must reach the client")
		origin.waitForRequest(t, "GET /body", 10*time.Second)
		flows := running.tracker.waitForFlows(t, flowsBefore+1, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "tcp", flow.Network)
		require.Equal(t, origin.address(), flow.Destination,
			"an absolute-form request must be routed to the host it names")
		require.Equal(t, "direct", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// WebSocket-style upgrade through the same proxy: after the handshake
	// the connection must become a raw bidirectional tunnel, which is the
	// path a long-lived realtime connection takes.
	// -------------------------------------------------------------------
	t.Run("http_forward_proxy_websocket_upgrade", func(t *testing.T) {
		origin := startHTTPOrigin(t)
		flowsBefore := running.tracker.count()
		conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
		request := "GET http://" + origin.address() + "/ws HTTP/1.1\r\n" +
			"Host: " + origin.address() + "\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: websocket\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n\r\n"
		_, err = conn.Write([]byte(request))
		require.NoError(t, err)
		head, err := readHTTPHead(conn)
		require.NoError(t, err, "the upgrade response head (10s deadline)")
		require.Contains(t, head, "101", "the upgrade response must reach the client, got %q", head)
		for round := 0; round < 3; round++ {
			payload := fmt.Sprintf("ws-frame-%d", round)
			_, err = conn.Write([]byte(payload))
			require.NoError(t, err)
			reply := make([]byte, len(payload))
			_, err = io.ReadFull(conn, reply)
			require.NoError(t, err, "round %d of the upgraded tunnel", round)
			require.Equal(t, payload, string(reply))
		}
		require.Greater(t, origin.upgraded.Load(), int64(0))
		flows := running.tracker.waitForFlows(t, flowsBefore+1, 10*time.Second)
		require.Equal(t, origin.address(), flows[len(flows)-1].Destination)
	})

	// -------------------------------------------------------------------
	// UDP through the same inbound, via SOCKS5 UDP ASSOCIATE.
	// -------------------------------------------------------------------
	t.Run("socks5_udp_associate_direct", func(t *testing.T) {
		conn := dialSocks5UDP(t, proxyAddress, "127.0.0.1", udpEchoPort)
		defer conn.Close()
		requireEchoUDP(t, conn, "udp-associate-direct")
		require.Greater(t, udpEcho.packets.Load(), int64(0))
		flows := running.tracker.waitForFlows(t, 12, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "udp", flow.Network)
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(udpEchoPort), flow.Destination)
		require.Equal(t, "direct", flow.RouteOutbound)
	})

	// -------------------------------------------------------------------
	// Concurrent CONNECTs through one inbound: no cross-talk, and every
	// flow gets its own decision.
	// -------------------------------------------------------------------
	t.Run("concurrent_connects", func(t *testing.T) {
		const workers = 16
		before := running.tracker.count()
		var waitGroup sync.WaitGroup
		errs := make([]error, workers)
		for index := 0; index < workers; index++ {
			waitGroup.Add(1)
			go func(index int) {
				defer waitGroup.Done()
				conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
				if err != nil {
					errs[index] = err
					return
				}
				defer conn.Close()
				payload := fmt.Sprintf("concurrent-%02d", index)
				if _, err = conn.Write([]byte("CONNECT 127.0.0.1:" + fmt.Sprint(echo4Port) + " HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
					errs[index] = err
					return
				}
				if _, err = readHTTPHead(conn); err != nil {
					errs[index] = err
					return
				}
				if _, err = conn.Write([]byte(payload)); err != nil {
					errs[index] = err
					return
				}
				reply := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, reply); err != nil {
					errs[index] = err
					return
				}
				if string(reply) != payload {
					errs[index] = fmt.Errorf("payload mismatch: sent %q got %q", payload, reply)
				}
			}(index)
		}
		waitGroup.Wait()
		for index, err := range errs {
			require.NoError(t, err, "concurrent worker %d", index)
		}
		flows := running.tracker.waitForFlows(t, before+workers, 15*time.Second)
		for _, flow := range flows[before:] {
			require.Equal(t, "direct", flow.RouteOutbound)
			require.Equal(t, "127.0.0.1:"+fmt.Sprint(echo4Port), flow.Destination)
		}
	})

	// -------------------------------------------------------------------
	// The full chain must survive a second, independent pass with exactly
	// the same answers: a proxy that works once and not twice is a real
	// and common failure.
	// -------------------------------------------------------------------
	t.Run("repeat_after_all_of_the_above", func(t *testing.T) {
		for round := 0; round < 3; round++ {
			conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echo4Port)
			requireEcho(t, conn, fmt.Sprintf("repeat-%d", round))
			require.NoError(t, conn.Close())
		}
	})
}

// TestRejectReplyCode measures what a client is told when the policy rejects the destination.
//
// # This test does NOT certify the contract
//
// The contract a proxy owes its client is: a destination the policy rejects is reported as
// rejected. That contract is NOT met by either inbound, and this test pins the measured values so
// the defect is visible, cannot change silently, and has a place to land when it is fixed. A green
// run here means "the values below are still what the product does", not "the product is correct".
//
//	          SOCKS5 reply code        HTTP CONNECT status
//	no sniff  0x01 general failure     200 Connection established
//	sniff     0x00 SUCCESS             200 Connection established
//
// # Why the SOCKS5 row depends on the sniff rule
//
// The SOCKS5 success reply is written lazily by sing's LazyConn on the first read OR write of the
// connection (SagerNet/sing, protocol/socks/lazy.go). Nothing else reads the connection before the
// decision... except a `sniff` rule, which peeks the stream to learn the domain. So adding sniffing
// - which every real configuration does, because domain rules need it - commits the success reply
// before the router has decided anything, and a rejected flow is announced as established and then
// closed.
//
// # Why this is not fixed here
//
// Both mechanisms are inherited, not fork regressions:
//
//   - the lazy SOCKS reply is SagerNet/sing behaviour (verified against upstream main);
//   - the HTTP 200 is written before the route decision in transport/http/server_conn.go
//     serveConnect, and upstream sing's protocol/http/handshake.go does exactly the same.
//
// Changing either one is a product decision about diverging from upstream, owned by protocol/**.
func TestRejectReplyCode(t *testing.T) {
	for _, testCase := range []struct {
		name string
		// sniff enables the sniff rule, which is what commits the SOCKS5 success reply early.
		sniff bool
		// wantReplyCode is the measured value, not the correct one.
		wantReplyCode byte
	}{
		{name: "without_sniff_rule", sniff: false, wantReplyCode: 0x01},
		{name: "with_sniff_rule", sniff: true, wantReplyCode: 0x00},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			echo := startEchoServer(t, "tcp", "127.0.0.1:0")
			sniffRule := ""
			if testCase.sniff {
				sniffRule = `{"action": "sniff"},`
			}
			proxyPort := freePort(t)
			config := fmt.Sprintf(`{
  "log": {"level": "%s"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {
    "rules": [%s {"domain": ["blocked.test"], "action": "reject"}],
    "final": "direct"
  }
}`, chainLogLevel, proxyPort, sniffRule)
			startChain(t, config)
			echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)

			// The invariant that DOES hold, in every configuration: a rejected destination is never
			// dialled, and nothing leaves the box for it.
			acceptedBefore := echo.accepts.Load()
			conn, replyCode := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 0x03, "blocked.test", echoPort)
			if conn != nil {
				defer conn.Close()
			}
			require.Equal(t, acceptedBefore, echo.accepts.Load(), "a rejected destination must not be dialled")
			if testCase.wantReplyCode == 0x00 {
				require.Equal(t, byte(0x00), replyCode,
					"PINNED DEFECT: sniffing commits the SOCKS5 success reply, so a rejected destination "+
						"is announced as established. If this assertion now fails, the defect was fixed: "+
						"flip the expectation and delete this comment.")
			} else {
				require.Equal(t, testCase.wantReplyCode, replyCode,
					"without a sniff rule the SOCKS5 reply is the real failure code")
			}

			status, head, connectErr := httpConnectStatus(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), "blocked.test:443")
			require.Equal(t, acceptedBefore, echo.accepts.Load())
			// # What this pins, and what it may NOT report as "fixed"
			//
			// The defect is that the proxy announces "200 Connection established" BEFORE the route
			// decision and then refuses the flow. What the client observes depends on whether the
			// socket reset destroys the announced head before it is read: MEASURED, with the write
			// provably executed and 32 of the 40 head bytes already read as
			// `HTTP/1.1 200 Connection establis` when `wsarecv: An existing connection was forcibly
			// closed by the remote host` ended the read. An isolated microbenchmark of plain Go
			// (write-then-close, 5000 iterations each way) pins the operating system's rule: a clean
			// close after the write is observable every time, while an ABORTIVE close - which is what
			// refusing a handed-off CONNECT does here - discards the response, sometimes entirely.
			//
			// So the client may observe the head, part of it, or a reset with no bytes at all, and all
			// three are the SAME pinned defect. The assertion below therefore reads what arrived
			// instead of discarding it. A defect that HAS been fixed looks different in every case: the
			// client receives a status line that is not 200, which fails the assertion and is the
			// signal to flip this expectation.
			switch {
			case head != "":
				// A complete head, or as much of one as the reset left: either way the announcement
				// is what was observed, and the truncated case is logged with how much arrived.
				require.Contains(t, status, "200",
					"PINNED DEFECT: transport/http/server_conn.go writes 200 Connection established "+
						"before the route decision, so a rejected CONNECT is announced as established. "+
						"If this assertion now fails, the defect was fixed: flip the expectation.")
				if connectErr != nil {
					t.Logf("the rejected CONNECT was aborted after %d byte(s) of head: %q (%v)",
						len(head), head, connectErr)
				}
			default:
				// Not one byte arrived. The abort won the race, which is the same defect observed from
				// the other side - but a CONNECT that HANGS is a different problem and must not be
				// excused by this branch, so a deadline is still a failure.
				require.False(t, errors.Is(connectErr, os.ErrDeadlineExceeded),
					"the rejected CONNECT neither answered nor aborted: it hung until the read deadline")
				require.Error(t, connectErr,
					"the CONNECT produced no bytes and no error, which cannot describe a rejected request")
				t.Logf("the rejected CONNECT was aborted before any byte of the status line arrived: %v",
					connectErr)
			}
		})
	}
}

// httpConnectStatus issues a CONNECT and returns the status line, whatever it is, plus the raw head
// and the read error. dialHTTPConnect requires a 200, so this is the variant that can observe a
// refusal.
//
// # Why the partial head and the error both come back
//
// `readHTTPHead` reads ONE BYTE AT A TIME and returns what it has when the connection fails. This
// helper used to throw that away and answer ("", err.Error()), which made a connection that had
// already delivered 29 bytes of the status line indistinguishable from one that delivered nothing -
// and a caller asserting on the status line then reported "the defect may have been fixed" for a
// socket that was simply reset. The bytes read are the observation, so they are returned.
func httpConnectStatus(t *testing.T, proxyAddress string, target string) (string, string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	require.NoError(t, err)
	head, err := readHTTPHead(conn)
	if err != nil {
		return firstLine(head), head, err
	}
	return firstLine(head), head, nil
}

// firstLine is the status line of a head, complete or truncated.
func firstLine(head string) string {
	if head == "" {
		return ""
	}
	return strings.SplitN(head, "\r\n", 2)[0]
}
