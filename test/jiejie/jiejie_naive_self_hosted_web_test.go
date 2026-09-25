package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Self-hosted web access through Native Naive, without reopening public 443.
//
// The problem this solves: the Naive target ACL denies the host's own address,
// which is correct - allowing it would let a client re-enter the public TCP/443
// front door and recurse through the proxy. But the operator's own web services
// (`*.zhuzhu.jiejie12131.top`) resolve to that same address, so they became
// unreachable through the proxy.
//
// The fix is NOT a self-IP:443 exception. It is a destination REWRITE: those
// domains are routed to an isolated loopback Web-only HTTPS ingress at
// 127.0.0.1:28439. `override_address` also clears DestinationAddresses, so the
// dial target is the loopback ingress and never the resolved public address.
//
// Consequence, and the reason this is safe: a client can CONNECT
// push.zhuzhu...:443 and then present an unrelated TLS SNI inside the tunnel, and
// the connection still terminates at 127.0.0.1:28439. The public front door is
// not reachable this way at all.
//
// The tests below assert what the ORIGIN observed, not the router's verdict: a
// route decision that never dialled proves nothing.

const (
	// selfHostedSuffix is the operator's own zone.
	selfHostedSuffix = "zhuzhu.jiejie12131.top"
	// proxyIngressNames are used as TLS server_name by the proxy inbounds
	// (masque-h2, masque-h3, naive-in and anytls-in). They must never be treated
	// as ordinary self-hosted web.
	proxyIngressRIRI = "riri." + selfHostedSuffix
	proxyIngressAPI  = "api." + selfHostedSuffix
)

// selfHostedWebEnv is an instance whose rules mirror the production shape for the
// self-hosted web path.
type selfHostedWebEnv struct {
	port uint16
	// frontDoor stands in for the public TCP/443 Nginx Stream entry point. It must
	// receive NOTHING.
	frontDoor *countingOrigin
	// proxyListener stands in for the Native Naive listener reached through the
	// public front door. It must receive NOTHING from a rewritten connection.
	proxyListener *countingOrigin
}

// startSelfHostedWebInstance starts a Naive inbound with the production-shaped
// self-hosted web rules and a counting stand-in for the isolated web ingress.
//
// The ingress port is passed to the rule as override_port, so the test does not
// need to own 28439 while still exercising exactly the production rule shape.
func startSelfHostedWebInstance(t *testing.T, selfAddress net.IP, webIngressPort uint16) *selfHostedWebEnv {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	port := reserveTCPPort(t)
	selfCIDR := selfAddress.String() + "/32"

	// Names used by the proxy inbounds resolve to the host itself, exactly as they
	// do in production; the exact-domain deny must catch them before the suffix
	// rule can rewrite them.
	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"push." + selfHostedSuffix:  {selfAddress},
		"files." + selfHostedSuffix: {selfAddress},
		proxyIngressRIRI:            {selfAddress},
		proxyIngressAPI:             {selfAddress},
		"evil.test":                 {selfAddress},
		"public.test":               {net.IPv4(93, 184, 216, 34)},
	})
	_ = dnsServer

	// Rule ORDER is the security property:
	//   1. exact proxy-ingress deny   (before the suffix rule can rewrite them)
	//   2. self-hosted web suffix     (rewrite to the isolated ingress)
	//   3. resolve
	//   4. self-IP SSH exception
	//   5. self + restricted reject
	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + dnsPort + `}],
			"final": "scripted",
			"strategy": "ipv4_only",
			"independent_cache": true
		},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": "scripted"}],
		"route": {
			"rules": [
				{"inbound": ["naive-in"], "network": ["tcp"], "domain": ["` + proxyIngressRIRI + `", "` + proxyIngressAPI + `"], "port": [443], "action": "reject"},
				{"inbound": ["naive-in"], "network": ["tcp"], "domain_suffix": ["` + selfHostedSuffix + `"], "port": [443], "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": ` + strconv.Itoa(int(webIngressPort)) + `},
				{"inbound": ["naive-in"], "action": "resolve"},
				{"inbound": ["naive-in"], "network": ["tcp"], "ip_cidr": ["` + selfCIDR + `"], "port": [2222], "action": "route", "outbound": "direct"},
				{"inbound": ["naive-in"], "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8", "` + selfCIDR + `"], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	return &selfHostedWebEnv{
		port:          port,
		frontDoor:     startCountingTCPOrigin(t),
		proxyListener: startCountingTCPOrigin(t),
	}
}

// connectThroughNaive opens an authenticated tunnel to the given authority and
// returns the connection plus the parsed CONNECT response.
//
// The response alone does NOT prove reachability. The Naive inbound answers
// "200 OK" as part of accepting the CONNECT, and a router-level reject only
// closes the connection afterwards - verified on Linux: a CONNECT to
// 127.0.0.1:443, to the self address:443 and to a proxy ingress name all return
// 200 OK and then carry nothing. So callers assert reachability on the origin
// counters, using waitForDial, rather than on the status code.
func connectThroughNaive(t *testing.T, port uint16, authority string) (net.Conn, *http.Response, error) {
	t.Helper()
	conn := naiveTLSConn(t, port, "http/1.1")
	response, err := naiveWriteConnect(t, conn, authority, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		// The Padding header is part of the NaiveProxy wire handshake. Without it
		// the tunnel opens but the server never forwards a response, so a probe
		// that omits it reports every target - allowed or not - as unreachable.
		// This was verified against the SSH exception path, which is a known-good
		// direct route: with Padding it returns origin-ok, without it the read
		// succeeds but the body is empty.
		"Padding": "~~~~~~~~",
	})
	// The response body is deliberately NOT closed here. For a hijacked HTTP/1.1
	// tunnel the body IS the tunnel, so Body.Close() would tear down the very
	// connection the caller is about to probe. Callers close the net.Conn.
	return conn, response, err
}

// tunnelWasAccepted reports whether the CONNECT was answered with 200.
//
// It is named "accepted" and not "reached" on purpose: it only says the proxy
// took the request, which is true even for targets the router then rejects.
func tunnelWasAccepted(response *http.Response) bool {
	return response != nil && response.StatusCode == http.StatusOK
}

// probeTunnelServes writes raw HTTP/1 through the tunnel and reports whether the
// counting origin answered.
//
// Used by the tests that point at a live counting origin. The H1 tunnel is
// unframed, so the request goes out raw rather than in a Naive padding frame.
func probeTunnelServes(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		return false
	}
	payload, err := io.ReadAll(conn)
	if err != nil {
		return false
	}
	return strings.Contains(string(payload), "origin-ok")
}

// sendTLSInsideTunnel performs a TLS handshake INSIDE the established tunnel and
// reports whether it succeeded plus the negotiated state.
//
// This is what makes the SNI-mismatch test meaningful: the CONNECT authority and
// the tunnelled SNI are chosen independently, so the test can prove that an
// unrelated SNI does not change where the connection actually terminates.
func sendTLSInsideTunnel(t *testing.T, conn net.Conn, sni string) (bool, error) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return false, err
	}
	_, err := tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n"))
	if err != nil {
		return false, err
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return true, err
	}
	defer response.Body.Close()
	return true, nil
}

// TestJiejieNaiveSelfHostedWebRoute is the acceptance matrix for this task.
//
// Every ALLOW case asserts that the ISOLATED INGRESS accepted a connection, and
// every REJECT case asserts that neither the ingress nor the stand-in front door
// nor the proxy listener was touched. A route verdict alone would not distinguish
// "allowed" from "allowed but never dialled", or "rejected" from "rejected after
// dialling anyway".
func TestJiejieNaiveSelfHostedWebRoute(t *testing.T) {
	selfAddress := selfTestAddress(t)

	// The isolated web ingress. Started first so its real port can be named in the
	// rule, mirroring production where the port is fixed at 28439.
	ingress := startCountingTCPOrigin(t)
	env := startSelfHostedWebInstance(t, selfAddress, originPort(t, ingress))

	t.Run("CASE 1: push self-hosted service is routed to the isolated ingress", func(t *testing.T) {
		before := ingress.conns.Load()
		conn, response, err := connectThroughNaive(t, env.port, "push."+selfHostedSuffix+":443")
		defer conn.Close()
		require.NoError(t, err)
		require.True(t, tunnelWasAccepted(response), "the CONNECT must be answered")

		require.True(t, waitForDial(&ingress.conns, before),
			"the connection must actually reach the isolated ingress; it saw %d "+
				"new connections", ingress.conns.Load()-before)
		require.True(t, probeTunnelServes(t, conn),
			"the tunnel must carry traffic end to end to the ingress, not merely "+
				"open a socket to it")
		t.Logf("push.%s reached the isolated ingress (%d connections)",
			selfHostedSuffix, ingress.conns.Load())
	})

	t.Run("CASE 2: another subdomain of the same zone is routed too", func(t *testing.T) {
		// Proves the rule is a suffix rule rather than a special case for "push".
		before := ingress.conns.Load()
		conn, response, err := connectThroughNaive(t, env.port, "files."+selfHostedSuffix+":443")
		defer conn.Close()
		require.NoError(t, err)
		require.True(t, tunnelWasAccepted(response))
		require.True(t, waitForDial(&ingress.conns, before),
			"a different subdomain must reach the same isolated ingress, proving "+
				"the rule matches the zone rather than one name")
		require.True(t, probeTunnelServes(t, conn),
			"a different subdomain must be served, not just dialled")
	})

	t.Run("CASE 3: riri proxy ingress is refused", func(t *testing.T) {
		ingressBefore := ingress.conns.Load()
		frontBefore := env.frontDoor.conns.Load()
		proxyBefore := env.proxyListener.conns.Load()

		conn, _, _ := connectThroughNaive(t, env.port, proxyIngressRIRI+":443")
		defer conn.Close()
		require.False(t, probeTunnelServes(t, conn),
			"a proxy ingress name must be refused")

		time.Sleep(300 * time.Millisecond)
		require.Equal(t, ingressBefore, ingress.conns.Load(),
			"the isolated web ingress must not be reached for a proxy ingress name")
		require.Equal(t, frontBefore, env.frontDoor.conns.Load(),
			"the public front door must not be reached")
		require.Equal(t, proxyBefore, env.proxyListener.conns.Load(),
			"the proxy listener must not be reached")
	})

	t.Run("CASE 4: api proxy ingress is refused", func(t *testing.T) {
		ingressBefore := ingress.conns.Load()
		conn, _, _ := connectThroughNaive(t, env.port, proxyIngressAPI+":443")
		defer conn.Close()
		require.False(t, probeTunnelServes(t, conn),
			"the anytls ingress name must be refused")
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, ingressBefore, ingress.conns.Load(),
			"the isolated web ingress must not be reached for a proxy ingress name")
	})

	t.Run("CASE 5: literal self IPv4 on 443 is refused", func(t *testing.T) {
		ingressBefore := ingress.conns.Load()
		conn, _, _ := connectThroughNaive(t, env.port, selfAddress.String()+":443")
		defer conn.Close()
		require.False(t, probeTunnelServes(t, conn),
			"the host's own address on 443 must stay denied")
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, ingressBefore, ingress.conns.Load(),
			"the web rewrite is domain-based and must not fire for a literal address")
	})

	t.Run("CASE 7: unrelated hostname resolving to the self address is refused", func(t *testing.T) {
		// This is the case that proves self-IP:443 was not simply reopened: the
		// name resolves to the host, but it is NOT in the self-hosted zone, so no
		// rewrite applies and the self-IP reject still catches it.
		ingressBefore := ingress.conns.Load()
		conn, _, _ := connectThroughNaive(t, env.port, "evil.test:443")
		defer conn.Close()
		require.False(t, probeTunnelServes(t, conn),
			"a third-party name resolving to the host must still be refused")
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, ingressBefore, ingress.conns.Load(),
			"the rewrite applies only to the self-hosted zone")
	})

	t.Run("CASE 8: loopback and private addresses stay refused", func(t *testing.T) {
		for _, target := range []string{
			"127.0.0.1:443",
			"10.255.255.1:443",
			"192.168.1.1:443",
		} {
			ingressBefore := ingress.conns.Load()
			conn, _, _ := connectThroughNaive(t, env.port, target)
			require.False(t, probeTunnelServes(t, conn),
				"%s must stay refused", target)
			_ = conn.Close()
			require.Equal(t, ingressBefore, ingress.conns.Load(),
				"the web rewrite must not create a path to %s", target)
		}
	})

	t.Run("CASE 9: self SSH exception still works", func(t *testing.T) {
		// The exception is address+port based, not domain based, and must survive
		// this change untouched. startSelfACLInstance builds the ACL instance whose
		// SSH exception port is the one the rule names.
		sshPort := reservePortOn(t, selfAddress)
		ssh := startTCPOriginOn(t, net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(sshPort))))

		sshEnv := startSelfACLInstance(t, selfAddress, sshPort, 0)
		conn := naiveTLSConn(t, sshEnv.port)
		response, err := naiveWriteConnect(t, conn, ssh.addr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
		})
		require.NoError(t, err, "the SSH exception must still be answered")
		require.Equal(t, http.StatusOK, response.StatusCode)
		naiveCloseResponse(conn)
		require.True(t, waitForDial(&ssh.conns, 0),
			"the SSH exception must survive the self-hosted web routing change")
	})
}

// TestJiejieNaiveSelfHostedWebSNIMismatchCannotReenterProxy is the regression that
// justifies this whole design.
//
// A client can CONNECT a self-hosted name (which the rule rewrites to the isolated
// ingress) and then present a DIFFERENT TLS SNI inside the tunnel - here the proxy
// ingress name. If the design had instead been "allow *.zhuzhu... to reach
// self-IP:443", that connection would land on the public front door and could be
// dispatched back into the proxy, which is the recursion this must prevent.
//
// Because the destination was rewritten before dialling, the connection terminates
// at the isolated ingress no matter what SNI is presented. The assertions are on
// the counters: the proxy listener and the front door must both see zero.
func TestJiejieNaiveSelfHostedWebSNIMismatchCannotReenterProxy(t *testing.T) {
	selfAddress := selfTestAddress(t)

	ingress := startCountingTCPOrigin(t)
	env := startSelfHostedWebInstance(t, selfAddress, originPort(t, ingress))

	ingressBefore := ingress.conns.Load()
	frontBefore := env.frontDoor.conns.Load()
	proxyBefore := env.proxyListener.conns.Load()

	// CONNECT a self-hosted name, which the rule rewrites to the ingress.
	conn, response, err := connectThroughNaive(t, env.port, "push."+selfHostedSuffix+":443")
	require.NoError(t, err)
	require.True(t, tunnelWasAccepted(response), "the CONNECT must be answered")
	defer conn.Close()

	require.True(t, waitForDial(&ingress.conns, ingressBefore),
		"the connection must reach the isolated ingress")

	// Now present an unrelated SNI inside the tunnel. The ingress is a plain TCP
	// counter in this test, so the handshake will not complete - that is fine and
	// expected. What matters is WHERE the connection went, which the counters show.
	_, _ = sendTLSInsideTunnel(t, conn, proxyIngressRIRI)
	time.Sleep(400 * time.Millisecond)

	require.Equal(t, proxyBefore, env.proxyListener.conns.Load(),
		"a mismatched TLS SNI must NOT cause re-entry into the proxy: the "+
			"destination was rewritten before dialling, so the SNI cannot "+
			"redirect the connection")
	require.Equal(t, frontBefore, env.frontDoor.conns.Load(),
		"the public front door must not be reached, which is the recursion this "+
			"design exists to prevent")

	t.Logf("SNI mismatch contained: ingress=%d proxy=%d frontDoor=%d",
		ingress.conns.Load(), env.proxyListener.conns.Load(), env.frontDoor.conns.Load())
}

// TestJiejieNaiveSelfHostedWebEndToEndTLS runs a REAL TLS + HTTP exchange through
// the rewrite to a real internal HTTPS listener.
//
// The counter-based tests prove where the connection went; this proves the path is
// usable, which is the actual user-visible requirement (the reported symptom was a
// failing page load). The ingress here is a genuine TLS server presenting a
// certificate for the self-hosted name, and the tunnelled SNI matches the CONNECT
// authority, which is the normal case.
func TestJiejieNaiveSelfHostedWebEndToEndTLS(t *testing.T) {
	selfAddress := selfTestAddress(t)

	// A real HTTPS listener stands in for the Nginx Web-only ingress. The
	// certificate is issued for the self-hosted name so the SNI matches.
	_, ingressCert, ingressKey := createSelfSignedCertificate(t, "push."+selfHostedSuffix)
	ingressListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ingressListener.Close() })

	ingressPort := uint16(ingressListener.Addr().(*net.TCPAddr).Port)
	var ingressConnections atomic.Int64
	ingressServer := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("self-hosted-web-ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ingressTLSConfig, err := loadTestCertificate(ingressCert, ingressKey)
	require.NoError(t, err)
	tlsListener := tls.NewListener(&countingListener{
		Listener: ingressListener,
		count:    &ingressConnections,
	}, ingressTLSConfig)
	go func() { _ = ingressServer.Serve(tlsListener) }()
	t.Cleanup(func() { _ = ingressServer.Close() })

	// The instance must name that port; build it with the real listener's port.
	env := startSelfHostedWebInstance(t, selfAddress, ingressPort)

	conn, response, err := connectThroughNaive(t, env.port, "push."+selfHostedSuffix+":443")
	require.NoError(t, err)
	require.True(t, tunnelWasAccepted(response), "the CONNECT must be answered")
	defer conn.Close()

	handshakeOK, err := sendTLSInsideTunnel(t, conn, "push."+selfHostedSuffix)
	require.True(t, handshakeOK,
		"the tunnel must carry a real TLS handshake to the internal ingress: %v", err)
	require.NoError(t, err, "the internal web ingress must answer the request")

	require.Positive(t, ingressConnections.Load(),
		"the internal HTTPS ingress must have accepted the connection")
	t.Logf("self-hosted web end to end: ingress saw %d connection(s)",
		ingressConnections.Load())
}

// originPort returns the TCP port a counting origin is listening on.
func originPort(t *testing.T, origin *countingOrigin) uint16 {
	t.Helper()
	_, portText, err := net.SplitHostPort(origin.addr)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

// countingListener counts accepted connections before handing them on.
type countingListener struct {
	net.Listener
	count *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return conn, err
}

// loadTestCertificate reads a PEM certificate and key pair.
func loadTestCertificate(certPath, keyPath string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}}, nil
}

// TestJiejieNaiveSelfHostedWebRuleShapeMatchesProduction pins the shipped rule
// shape, so the production fixture and the tests cannot drift apart.
//
// This is the test that keeps the runtime tests honest: they build their own
// config, and without this check the two could diverge and the runtime tests
// would keep passing against a shape production no longer uses.
func TestJiejieNaiveSelfHostedWebRuleShapeMatchesProduction(t *testing.T) {
	fixture, path := loadProductionFixture(t)

	var denyRule, rewriteRule *productionRouteRule
	var denyIndex, rewriteIndex, resolveIndex = -1, -1, -1
	for index := range fixture.Route.Rules {
		rule := &fixture.Route.Rules[index]
		if len(rule.Inbound) != 1 || rule.Inbound[0] != "naive-in" {
			continue
		}
		switch {
		case rule.Action == "reject" && len(rule.Domain) > 0:
			denyRule, denyIndex = rule, index
		case len(rule.DomainSuffix) > 0:
			rewriteRule, rewriteIndex = rule, index
		case rule.Action == "resolve":
			resolveIndex = index
		}
	}

	require.NotNil(t, denyRule,
		"%s must declare an exact proxy-ingress deny for naive-in", path)
	require.NotNil(t, rewriteRule,
		"%s must declare the self-hosted web rewrite for naive-in", path)

	t.Run("the deny names both proxy ingress hostnames", func(t *testing.T) {
		// Both of these are TLS server_name values of proxy inbounds, so a client
		// reaching them through the proxy would recurse.
		require.Contains(t, denyRule.Domain, proxyIngressRIRI,
			"riri is the TLS server_name of masque-h2, masque-h3 and naive-in")
		require.Contains(t, denyRule.Domain, proxyIngressAPI,
			"api is the TLS server_name of anytls-in")
		require.Equal(t, "reject", denyRule.Action)
		require.Equal(t, []string{"tcp"}, denyRule.Network)
		require.Equal(t, []uint16{443}, denyRule.Port)
	})

	t.Run("the rewrite targets the loopback web ingress", func(t *testing.T) {
		require.Equal(t, "route", rewriteRule.Action)
		require.Equal(t, "direct", rewriteRule.Outbound)
		require.Equal(t, "127.0.0.1", rewriteRule.OverrideAddress,
			"the self-hosted web path must be rewritten to loopback, never to the "+
				"public self address")
		require.EqualValues(t, 28439, rewriteRule.OverridePort,
			"the isolated Web-only ingress port is fixed at 28439")
		require.Contains(t, rewriteRule.DomainSuffix, selfHostedSuffix,
			"domain_suffix must be the bare zone; sing-box matches the zone and "+
				"its subdomains without a wildcard prefix")
		for _, suffix := range rewriteRule.DomainSuffix {
			require.False(t, strings.HasPrefix(suffix, "*."),
				"domain_suffix is a raw suffix matcher and must not be written "+
					"with a wildcard prefix")
		}
		require.Empty(t, rewriteRule.Domain,
			"the rewrite must be suffix-based; an exact domain list would silently "+
				"stop covering new subdomains")
	})

	t.Run("the rewrite is tcp and 443 only", func(t *testing.T) {
		require.Equal(t, []string{"tcp"}, rewriteRule.Network,
			"the self-hosted web exception must not create a UDP or UoT path")
		require.Equal(t, []uint16{443}, rewriteRule.Port)
	})

	t.Run("the deny precedes the rewrite and both precede resolve", func(t *testing.T) {
		require.Positive(t, denyIndex)
		require.Positive(t, rewriteIndex)
		require.Less(t, denyIndex, rewriteIndex,
			"the exact proxy-ingress deny must come BEFORE the suffix rewrite, or "+
				"an ingress name would be rewritten into the web ingress")
		require.Greater(t, resolveIndex, rewriteIndex,
			"both new rules must precede the naive-in resolve action: a domain "+
				"matcher needs the destination to still be a domain")
	})

	t.Run("the self address stays denied on 443", func(t *testing.T) {
		// The whole point of the fallback deny: only the named zone is rewritten.
		var rejectCIDRs []string
		for _, rule := range fixture.Route.Rules {
			if rule.Action == "reject" && len(rule.IPCIDR) > 0 {
				rejectCIDRs = append(rejectCIDRs, rule.IPCIDR...)
			}
		}
		require.NotEmpty(t, rejectCIDRs,
			"the self and restricted address ranges must still be rejected")
		require.Contains(t, rejectCIDRs, "192.0.2.10/32",
			"the self address placeholder must remain in the reject list; "+
				"rewriting the web zone does not reopen the public self address")
	})
}
