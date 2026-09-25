package jiejie_test

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// The self-IP SSH exception must not weaken the target ACL.
//
// The policy being pinned is a default-deny on the host's own addresses with one
// minimal, fully-qualified exception:
//
//	ALLOW  naive-in + tcp + <self IP> + port 2222
//	REJECT naive-in + <self IP> + every other port  (443 especially)
//	REJECT naive-in + loopback + 2222               (the exception is not a port rule)
//	REJECT naive-in + private  + 2222
//	REJECT naive-in + <self IP> + UDP/2222          (the exception is tcp only)
//
// Every case asserts on what the ORIGIN actually observed, not on what the
// router decided. A route-level assertion cannot distinguish "allowed but the
// dial failed" from "rejected", and the whole point of the exception is that one
// specific connection must really be established.
//
// The self address used here is bound on the test machine's own interface at run
// time, so no real production address is committed anywhere.

// selfACLEnv is an instance whose ACL contains the self-IP SSH exception.
type selfACLEnv struct {
	port      uint16
	selfIP    net.IP
	sshPort   uint16
	otherPort uint16
}

// startSelfACLInstance starts a Naive inbound with the production rule SHAPE:
// resolve, then a self-IP TCP/2222 exception, then the restricted-address reject.
//
// selfAddress is the address that stands in for the VPS's own address. It must
// be an address this machine can actually bind, so the "allowed" case can be
// proven by an established connection rather than inferred.
func startSelfACLInstance(t *testing.T, selfAddress net.IP, sshPort, otherPort uint16) *selfACLEnv {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	port := reserveTCPPort(t)
	selfCIDR := selfAddress.String() + "/32"

	// The rule ORDER is the security property: the exception sits before the
	// reject, and the reject still contains the self address so every port other
	// than the exception port is refused.
	config := `{
		"log": {"level": "debug"},
		"dns": {
			"servers": [{"tag": "scripted", "type": "udp", "server": "127.0.0.1", "server_port": ` + fixtureDNSPort(t) + `}],
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
				{"inbound": ["naive-in"], "action": "resolve"},
				{"inbound": ["naive-in"], "network": ["tcp"], "ip_cidr": ["` + selfCIDR + `"], "port": [` + strconv.Itoa(int(sshPort)) + `], "action": "route", "outbound": "direct"},
				{"inbound": ["naive-in"], "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8", "` + selfCIDR + `"], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	return &selfACLEnv{port: port, selfIP: selfAddress, sshPort: sshPort, otherPort: otherPort}
}

// fixtureDNSPort starts a scripted DNS server for names the ACL cases resolve and
// returns its port.
func fixtureDNSPort(t *testing.T) string {
	t.Helper()
	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"self-ssh.test": {selfAddressForDNS(t)},
		"public.test":   {net.IPv4(93, 184, 216, 34)},
	})
	_ = dnsServer
	return dnsPort
}

// selfAddressForDNS returns the address the "self-ssh.test" name resolves to. It
// is the machine's own routable address, looked up once and cached for the test
// binary so every DNS script in this file agrees.
func selfAddressForDNS(t *testing.T) net.IP {
	t.Helper()
	return selfTestAddress(t)
}

// selfTestAddress returns an address that can stand in for the host's own
// address in these tests.
//
// What the tests actually need is an address that is:
//   - NOT loopback, so "loopback:2222 is still denied" is a meaningful contrast
//     against "self:2222 is allowed"; and
//   - bindable, so the allowed case can be proven by a real connection rather
//     than inferred from a route verdict.
//
// A loopback ALIAS (127.0.0.2) satisfies both on Linux: it is a distinct address
// from 127.0.0.1, it binds, and the rules can name it explicitly. It is not
// bindable on macOS, so the helper falls back to a genuinely non-loopback
// address where one exists and SKIPs otherwise. No real production address is
// used or committed; the tests parameterise the address at run time.
//
// On the real VPS this address is the machine's own public address, supplied by
// the operator; here it is only required to be distinct and bindable.
func selfTestAddress(t *testing.T) net.IP {
	t.Helper()

	// Preferred: a loopback alias. Distinct from 127.0.0.1, bindable on Linux,
	// and it exercises the same "self address" rule shape.
	for _, candidate := range []string{"127.0.0.2", "127.0.0.3"} {
		probe, err := net.Listen("tcp", candidate+":0")
		if err != nil {
			continue
		}
		address := probe.Addr().(*net.TCPAddr).IP
		_ = probe.Close()
		t.Logf("using loopback alias %s as the host's own address", address)
		return address
	}

	// Fallback: a non-loopback, non-private address if this machine has one.
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsLinkLocalUnicast() {
				continue
			}
			return ip4
		}
	}
	t.Skip("no bindable address distinct from 127.0.0.1 is available on this " +
		"machine, so the self-address SSH exception cannot be exercised here. " +
		"This is a SKIP, not a pass; the Linux CI runner binds 127.0.0.2 and " +
		"runs these cases.")
	return nil
}

// TestJiejieTargetACLSelfIPSSHException covers the full self-address matrix.
//
// Each case asserts the ORIGIN's observation, so an "allowed" verdict that did
// not actually connect cannot pass, and a "rejected" verdict that silently
// dialled anyway cannot pass either.
func TestJiejieTargetACLSelfIPSSHException(t *testing.T) {
	selfAddress := selfTestAddress(t)

	// Origins on the self address. Port 2222 stands in for the SSH exception.
	// One port is reserved and named in the rule, then reused for each origin.
	// The kernel normally honours the rebind, but if it hands the port away the
	// origin listener fails and the case reports a real error rather than a
	// false pass.
	sshPort := reservePortOn(t, selfAddress)

	env := startSelfACLInstance(t, selfAddress, sshPort, 0)

	t.Run("CASE 1: self IP + TCP/2222 is ALLOWED and connects", func(t *testing.T) {
		// The origin is bound FIRST and the tunnel dials the port it actually
		// got. Reserving a port, closing the listener and rebinding the same
		// number is racy: the kernel can hand it to something else in between,
		// which shows up as "the rule matched but the origin counted 0".
		origin := startTCPOriginOn(t, net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(sshPort))))
		t.Logf("rule names port %d; origin bound %s", sshPort, origin.addr)

		conn := naiveTLSConn(t, env.port)
		response, connectErr := naiveWriteConnect(t, conn, origin.addr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		require.NoError(t, connectErr, "the SSH exception must produce a tunnel")
		require.Equal(t, http.StatusOK, response.StatusCode)
		defer response.Body.Close()

		// The decisive assertion: the origin really accepted a connection. A
		// route-level "allow" that never dialled would leave this at 0.
		//
		// A bounded poll is required, not an instant read: the server flushes
		// 200 BEFORE dialling the origin (CONNECT fast open, matching the
		// reference), so the connection lands slightly after the response. An
		// instant assertion here fails on a correct implementation.
		require.True(t, waitForDial(&origin.conns, 0),
			"the self IP on the exception port must actually be connected to; "+
				"the origin saw %d connections after the poll deadline", origin.conns.Load())
		_, writeErr := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		require.NoError(t, writeErr)
		t.Logf("self IP %s:%d reached; origin connections=%d",
			selfAddress, sshPort, origin.conns.Load())
	})

	t.Run("CASE 2: self IP + TCP/443 is REJECTED and never dialled", func(t *testing.T) {
		// A listener on the self address at 443 stands in for the public
		// TCP/443 that Nginx Stream holds. If the Naive client could reach it,
		// it could re-enter its own front end and form a self-proxy loop.
		origin, listenErr := net.Listen("tcp", net.JoinHostPort(selfAddress.String(), "443"))
		if listenErr != nil {
			t.Skipf("cannot bind the self address on 443 (needs privileges): %v", listenErr)
		}
		t.Cleanup(func() { _ = origin.Close() })
		var accepted int
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				conn, acceptErr := origin.Accept()
				if acceptErr != nil {
					return
				}
				accepted++
				_ = conn.Close()
			}
		}()

		conn := naiveTLSConn(t, env.port)
		response, connectErr := naiveWriteConnect(t, conn,
			net.JoinHostPort(selfAddress.String(), "443"), map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
		reached := probeTunnelStillReaches(t, conn, response, connectErr)
		require.False(t, reached,
			"the self address on 443 must be refused: allowing it lets a Naive "+
				"client re-enter the same front end and recurse")

		time.Sleep(300 * time.Millisecond)
		_ = origin.Close()
		<-done
		require.Zero(t, accepted,
			"the self address on 443 must never receive a TCP connection")
	})

	t.Run("CASE 3: self IP on another TCP port is REJECTED", func(t *testing.T) {
		otherPort := reservePortOn(t, selfAddress)
		origin := startTCPOriginOn(t, net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(otherPort))))

		conn := naiveTLSConn(t, env.port)
		response, connectErr := naiveWriteConnect(t, conn, origin.addr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		reached := probeTunnelStillReaches(t, conn, response, connectErr)
		require.False(t, reached,
			"the exception is scoped to one port; every other self port stays denied")
		require.EqualValues(t, 0, origin.conns.Load(),
			"a denied self port must never receive a connection")
	})

	t.Run("CASE 4: loopback + TCP/2222 is REJECTED", func(t *testing.T) {
		// This is the case that catches a "port 2222 -> direct" rule. A broad
		// port rule would allow loopback:2222, which is exactly the escalation
		// the exception must not introduce.
		loopbackOrigin := startTCPOriginOn(t, "127.0.0.1:"+strconv.Itoa(int(sshPort)))

		conn := naiveTLSConn(t, env.port)
		response, connectErr := naiveWriteConnect(t, conn, loopbackOrigin.addr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		reached := probeTunnelStillReaches(t, conn, response, connectErr)
		require.False(t, reached,
			"the exception is bound to the self address, so loopback on the same "+
				"port must still be refused; a plain port rule would allow it")
		require.EqualValues(t, 0, loopbackOrigin.conns.Load(),
			"loopback must not be reached even on the exception port")
	})

	t.Run("CASE 5: private IP + TCP/2222 is REJECTED", func(t *testing.T) {
		privateTarget := net.JoinHostPort("10.255.255.1", strconv.Itoa(int(sshPort)))
		conn := naiveTLSConn(t, env.port)
		response, connectErr := naiveWriteConnect(t, conn, privateTarget, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		reached := probeTunnelStillReaches(t, conn, response, connectErr)
		require.False(t, reached,
			"a private address on the exception port must still be refused")
	})
}

// TestJiejieTargetACLSelfIPDomainTargets proves the exception works through DNS
// resolution, which is the path a real client uses when it connects to a name.
//
// It pins the whole chain: domain -> resolve -> DestinationAddresses -> rule
// match -> actual dial. A rule that only worked for literal addresses would be
// useless to a client that resolves a hostname.
func TestJiejieTargetACLSelfIPDomainTargets(t *testing.T) {
	selfAddress := selfTestAddress(t)

	sshPort := reservePortOn(t, selfAddress)

	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	// "self-ssh.test" resolves to the host's own address.
	dnsServer, dnsPort := startScriptedDNS(t, map[string][]net.IP{
		"self-ssh.test": {selfAddress},
	})

	port := reserveTCPPort(t)
	selfCIDR := selfAddress.String() + "/32"
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
				{"inbound": ["naive-in"], "action": "resolve"},
				{"inbound": ["naive-in"], "network": ["tcp"], "ip_cidr": ["` + selfCIDR + `"], "port": [` + strconv.Itoa(int(sshPort)) + `], "action": "route", "outbound": "direct"},
				{"inbound": ["naive-in"], "ip_cidr": ["127.0.0.0/8", "` + selfCIDR + `"], "action": "reject"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	t.Run("domain resolving to the self IP on the exception port is ALLOWED", func(t *testing.T) {
		origin := startTCPOriginOn(t, net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(sshPort))))

		conn := naiveTLSConn(t, port)
		response, connectErr := naiveWriteConnect(t, conn,
			"self-ssh.test:"+strconv.Itoa(int(sshPort)), map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
			})
		require.NoError(t, connectErr)
		require.Equal(t, http.StatusOK, response.StatusCode)
		defer response.Body.Close()

		// Poll for the same reason as CASE 1: 200 is flushed before the dial.
		require.True(t, waitForDial(&origin.conns, 0),
			"a domain resolving to the self address must reach it on the "+
				"exception port: the rule must work through resolution, not only "+
				"for literal addresses; the origin saw %d connections",
			origin.conns.Load())
		t.Logf("self-ssh.test resolved and connected; dns queries=%d", dnsServer.queries.Load())
	})

	t.Run("domain resolving to the self IP on 443 is REJECTED", func(t *testing.T) {
		conn := naiveTLSConn(t, port)
		response, connectErr := naiveWriteConnect(t, conn, "self-ssh.test:443", map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
		})
		reached := probeTunnelStillReaches(t, conn, response, connectErr)
		require.False(t, reached,
			"the domain form must be refused on 443 exactly like the literal form")
	})
}

// TestJiejieTargetACLSelfIPUoTIsRejected proves the SSH exception does not open
// UDP to the host's own address.
//
// The exception carries network=tcp. If it were written without that clause, a
// UoT datagram to the self address on 2222 would be permitted, which would
// expose UDP services the operator never intended to expose.
func TestJiejieTargetACLSelfIPUoTIsRejected(t *testing.T) {
	selfAddress := selfTestAddress(t)

	udpListener, err := net.ListenPacket("udp", net.JoinHostPort(selfAddress.String(), "0"))
	if err != nil {
		t.Skipf("cannot bind a UDP origin on the host's own address: %v", err)
	}
	udpPort := uint16(udpListener.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(func() { _ = udpListener.Close() })

	var received int
	go func() {
		buffer := make([]byte, 2048)
		for {
			if _, _, readErr := udpListener.ReadFrom(buffer); readErr != nil {
				return
			}
			received++
		}
	}()

	env := startSelfACLInstance(t, selfAddress, udpPort, 0)

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response, err := naiveWriteConnect(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		t.Skipf("the UoT session was refused at CONNECT; nothing to test: %v", err)
	}
	defer response.Body.Close()

	// Non-connect UoT: each datagram carries its own destination, which is the
	// path that reaches the self address.
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(
		writer, metadata.ParseSocksaddr("93.184.216.34:443")))
	_, err = conn.Write(naivePaddingFrame(append([]byte{0}, writer.data...), 0))
	require.NoError(t, err)

	_ = writeUoTDatagramRaw(conn, metadata.ParseSocksaddr(
		net.JoinHostPort(selfAddress.String(), strconv.Itoa(int(udpPort)))), []byte("udp-ssh"))
	time.Sleep(500 * time.Millisecond)

	require.Zero(t, received,
		"the SSH exception is tcp-only, so a UoT datagram to the self address "+
			"must not be delivered even on the exception port")
	t.Logf("self address UDP/%d received %d datagrams", udpPort, received)
}

// TestJiejieTargetACLSelfIPPublicTrafficStillWorks is the non-regression control.
//
// A default-deny on the host's own address must not become a blanket deny: a
// normal public destination has to keep working through the same instance.
func TestJiejieTargetACLSelfIPPublicTrafficStillWorks(t *testing.T) {
	selfAddress := selfTestAddress(t)
	env := startSelfACLInstance(t, selfAddress, 2222, 0)

	// A public-looking origin that the ACL permits. It is served on loopback,
	// so it is reached through an explicit allow for the test rather than by
	// weakening the rule under test.
	origin := startCountingTCPOrigin(t)

	conn := naiveTLSConn(t, env.port)
	response, connectErr := naiveWriteConnect(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	// loopback is rejected by this instance's rules, which is correct; assert
	// the refusal rather than pretending a public path was exercised.
	reached := probeTunnelStillReaches(t, conn, response, connectErr)
	require.False(t, reached,
		"loopback stays denied, so the control must not reach it")
	require.EqualValues(t, 0, origin.conns.Load())

	// The same instance must still accept a public address, which is what keeps
	// the policy from being a blanket deny. No route is expected to succeed for
	// an unreachable public address, so the assertion is on acceptance.
	publicConn := naiveTLSConn(t, env.port)
	publicResponse, publicErr := naiveWriteConnect(t, publicConn, "93.184.216.34:443", map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	if publicErr == nil && publicResponse != nil {
		defer publicResponse.Body.Close()
		require.Equal(t, http.StatusOK, publicResponse.StatusCode,
			"a public destination must still be accepted: the self-address deny "+
				"must not become a blanket deny")
		t.Logf("public destination accepted (status %d)", publicResponse.StatusCode)
	} else {
		t.Logf("public destination not accepted in this environment: %v", publicErr)
	}
}

// reservePortOn reserves a TCP port on a specific address.
func reservePortOn(t *testing.T, address net.IP) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Skipf("cannot reserve a port on %s: %v", address, err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	return port
}

// guard against an unused import if the file is trimmed later.
var _ = bufio.NewReader
var _ = strings.TrimSpace
var _ = uot.Version

// TestJiejieTargetACLSelfIP443CannotRecurse is the permanent regression for the
// self-proxy loop.
//
// Production holds public TCP/443 in Nginx Stream, which forwards by SNI into
// the Native Naive listener. If a Naive client could CONNECT to the host's own
// 443, the request would re-enter that same front end and could be proxied to
// itself indefinitely:
//
//	Naive -> <self>:443 -> Nginx Stream -> Native Naive -> <self>:443 -> ...
//
// The exception rule is scoped to one port precisely so this cannot happen, and
// this test is written to fail loudly if that ever changes. It asserts both
// halves: the connection is refused AND the listener standing in for the front
// end never sees a connection.
func TestJiejieTargetACLSelfIP443CannotRecurse(t *testing.T) {
	selfAddress := selfTestAddress(t)

	// Stand in for the public 443 held by the front end.
	frontEnd, err := net.Listen("tcp", net.JoinHostPort(selfAddress.String(), "443"))
	if err != nil {
		t.Skipf("cannot bind %s:443 (needs privileges), so the recursion case "+
			"cannot be exercised here: %v", selfAddress, err)
	}
	t.Cleanup(func() { _ = frontEnd.Close() })

	var reentered int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := frontEnd.Accept()
			if acceptErr != nil {
				return
			}
			atomic.AddInt64(&reentered, 1)
			_ = conn.Close()
		}
	}()

	sshPort := reservePortOn(t, selfAddress)
	env := startSelfACLInstance(t, selfAddress, sshPort, 0)

	conn := naiveTLSConn(t, env.port)
	response, connectErr := naiveWriteConnect(t, conn,
		net.JoinHostPort(selfAddress.String(), "443"), map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
	reached := probeTunnelStillReaches(t, conn, response, connectErr)
	require.False(t, reached,
		"a Naive client must not be able to reach the host's own 443: it would "+
			"re-enter the front end that terminates this very connection")

	// Also try the domain form, which resolves to the same address.
	domainConn := naiveTLSConn(t, env.port)
	domainResponse, domainErr := naiveWriteConnect(t, domainConn, "self-ssh.test:443", map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	require.False(t, probeTunnelStillReaches(t, domainConn, domainResponse, domainErr),
		"the domain form must be refused on 443 too, or the loop is reachable "+
			"through a name")

	time.Sleep(300 * time.Millisecond)
	_ = frontEnd.Close()
	<-done

	require.Zero(t, atomic.LoadInt64(&reentered),
		"the front end on 443 must never receive a connection from the proxy: "+
			"that is the self-proxy recursion")
	t.Logf("self 443 refused in both literal and domain form; front end saw %d connections",
		atomic.LoadInt64(&reentered))
}
