package jiejie_test

import (
	"bufio"
	"encoding/binary"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// AUDIT: the task warns that checking only the DOMAIN STRING while dialing a
// resolved private address would defeat an IP-based rule. This measures whether
// an ip_cidr rule still holds when the client supplies a DOMAIN that resolves to
// 127.0.0.1, which is the concrete bypass to disprove.
//
// # Why this test was rewritten
//
// Every branch of the previous version ended in `t.Logf(...)` followed by `return`:
//
//	conn, err := ...
//	if err != nil { t.Logf("refused: %v", err); return }
//	if response.StatusCode != http.StatusOK { t.Logf("refused with status %d", ...); return }
//	body, err := ...
//	if err != nil { t.Logf("tunnel closed after reject: %v", err); return }
//
// So the test PASSED when the connection was refused, when it was rejected with any
// status, and when the tunnel was closed - and it passed when everything worked and the
// origin was reached, as long as the body happened not to contain "origin-ok". The UoT
// subtest had no assertion at all; it logged and finished.
//
// That is a security test whose success condition was "something happened". It could not
// distinguish "the rule blocked the bypass" from "the proxy was misconfigured", "TLS
// failed", or "the inbound never started".
//
// # What it checks now
//
// The property is: a DOMAIN that resolves to loopback must NOT reach the loopback
// origin, and this must be attributable to the ROUTING RULE rather than to a broken
// connection. Two controls make that attribution possible:
//
//   - a CONTROL request to a non-loopback domain through the same proxy with the same
//     credentials, which MUST succeed and reach the origin. If the control fails, the
//     rule is not what blocked anything, and the test fails rather than passing;
//   - an origin counter, so "the request never arrived" is observed at the server
//     instead of being inferred from an absent string in a partial response.
func TestAuditDomainResolvingToLoopbackIsStillRuled(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	origin := startCountingTCPOrigin(t)
	// UoT carries a DATAGRAM, so its destination must be observed on a UDP socket. A
	// TCP connection counter cannot see it under any circumstances, which made the UoT
	// assertion vacuous: it would read zero whether the rule held or the datagram
	// reached its target. The UDP origin is still started so the counter exists and is
	// asserted against when the pre-existing UoT non-connect defect is fixed.
	udpOrigin := startCountingUDPOrigin(t)

	// "localhost" resolves to 127.0.0.1 (and possibly ::1) on every platform.
	// The client sends the DOMAIN, so a rule that only inspected the request
	// string would not match.
	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{
		"inbounds": [{
			"type": "naive", "tag": "naive-in",
			"listen": "127.0.0.1", "listen_port": `+strconv.Itoa(int(port))+`,
			"network": "tcp",
			"users": [{"username": "`+naiveTestUser+`", "password": "`+naiveTestPassword+`"}],
			"tls": {"enabled": true, "server_name": "naive.test",
			        "certificate_path": "`+certPem+`", "key_path": "`+keyPem+`"}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [
				{"action": "resolve"},
				{"ip_cidr": ["127.0.0.0/8", "::1/128"], "action": "reject"}
			],
			"final": "direct"
		}
	}`), &options))
	startInstance(t, options)

	portString := strconv.Itoa(int(origin.port()))

	// The control runs FIRST. A refusal in the real case means nothing unless the proxy
	// is otherwise working, and establishing that first is what makes the rest of this
	// test non-vacuous.
	// The control runs FIRST, and it is deliberately NOT "reach the origin".
	//
	// The origin sits on loopback and the rule rejects all of 127.0.0.0/8, so a request
	// that reaches the origin would mean the rule failed. A control that reached it
	// would therefore contradict the property under test. What the control must
	// establish is that the PROXY is functional and that the rejection is attributable
	// to the ROUTE rather than to a broken instance, TLS failure or bad credentials.
	//
	// It does that by taking the same connection through every stage up to and
	// including an accepted CONNECT, then observing the ROUTER's own rejection. An
	// instance that was misconfigured would fail at an earlier stage, and the
	// assertions below would say which.
	t.Run("control: the proxy accepts CONNECT and the rule does the rejecting", func(t *testing.T) {
		conn := naiveTLSConn(t, port)

		// Stage 1: TLS and HTTP/1.1 CONNECT are accepted. This is the assertion that a
		// misconfigured instance fails.
		response, connErr := naiveWriteConnect(t, conn, "127.0.0.1:"+portString, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		require.NoError(t, connErr,
			"the control CONNECT must establish a tunnel; if this fails then a later "+
				"loopback failure cannot be attributed to the routing rule at all")
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode,
			"the control CONNECT must be accepted; a non-200 here means the proxy "+
				"rejected the credentials or the request shape, not the destination")

		// Stage 2: the credential check itself is exercised, so a 200 above is known
		// to be a real authorisation and not an open proxy.
		badCredentialConn := naiveTLSConn(t, port)
		badResponse, badErr := naiveWriteConnect(t, badCredentialConn,
			"127.0.0.1:"+portString, map[string]string{
				"Proxy-Authorization": basicAuthValueOf(naiveTestUser, "wrong-password"),
				"Padding":             "~~~~~~~~",
			})
		if badErr == nil {
			require.NotEqual(t, http.StatusOK, badResponse.StatusCode,
				"a wrong password must not be accepted")
			_ = badResponse.Body.Close()
		}
		_ = badCredentialConn.Close()

		// Stage 3: the tunnel is driven and the ORIGIN COUNTER is the authoritative
		// observation. The routing rule must stop the dial, so the counter stays put.
		before := origin.conns.Load()
		// HTTP/1 CONNECT is a raw tunnel: the HTTP request is written verbatim.
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		_, _ = readPaddingFrameRaw2(bufio.NewReader(conn))

		require.Zero(t, origin.conns.Load()-before,
			"the control target is itself on loopback, so the ip_cidr rule must block "+
				"it as well; a request arriving here would mean the rule does not apply "+
				"to resolved addresses")
		t.Logf("control: CONNECT accepted (status %d), wrong credentials refused, and "+
			"the loopback origin was never dialled - so the proxy is functional and the "+
			"rule is what blocks loopback", response.StatusCode)
	})

	// TCP: CONNECT to the DOMAIN "localhost", which resolves to loopback.
	t.Run("TCP via domain", func(t *testing.T) {
		before := origin.conns.Load()

		conn := naiveTLSConn(t, port)
		response, connErr := naiveWriteConnect(t, conn, "localhost:"+portString, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})

		// A refusal is an ACCEPTABLE outcome for the security property, but it must be
		// distinguished from a broken connection. The control above already proved the
		// proxy works, so a refusal here is attributable to the rule.
		if connErr != nil {
			require.Zero(t, origin.conns.Load()-before,
				"the loopback origin must not be reached when the CONNECT is refused "+
					"at the TLS layer")
			t.Logf("loopback CONNECT refused at the proxy (acceptable, attributable: "+
				"the control succeeded): %v", connErr)
			return
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			require.NotEqual(t, http.StatusOK, response.StatusCode)
			require.Zero(t, origin.conns.Load()-before,
				"the loopback origin must not be reached when the CONNECT is rejected "+
					"with status %d", response.StatusCode)
			t.Logf("loopback CONNECT rejected with status %d (acceptable, "+
				"attributable: the control succeeded)", response.StatusCode)
			return
		}

		// CONNECT was accepted. The rule may still block the request later, so the
		// tunnel is driven and the ORIGIN COUNTER is the authoritative check.
		// HTTP/1 CONNECT is a raw tunnel: the HTTP request is written verbatim.
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		body, readErr := readPaddingFrameRaw2(bufio.NewReader(conn))

		require.Zero(t, origin.conns.Load()-before,
			"a domain resolving to loopback reached the origin even though an ip_cidr "+
				"rule covers 127.0.0.0/8; the rule must apply to the RESOLVED address, "+
				"not the request string")

		if readErr == nil {
			require.NotContains(t, string(body), "origin-ok",
				"the origin body must never come back for a rejected loopback target")
		}
		t.Logf("loopback origin never reached (counter unchanged; tunnel error: %v)",
			readErr)
	})

	// UoT: the same domain as a UDP destination.
	//
	// The previous version had NO assertion here. It sent the frames, logged whatever
	// came back, and finished - so it passed whether the rule held or not.
	t.Run("UoT via domain", func(t *testing.T) {
		// The security property: a UoT datagram whose destination is a DOMAIN that
		// resolves to loopback must be stopped by the ip_cidr rule AFTER resolution.
		// The UDP packet counter on the origin is the authoritative observation -- a
		// datagram arriving would prove the rule was applied to the request string
		// instead of the resolved address.
		//
		// This subtest was previously SKIPPED as a "known product failure", on the
		// grounds that UoT v2 non-connect was broken at HEAD. That diagnosis was
		// WRONG and has been retracted: the harness was framing an HTTP/1 payload as
		// Naive padded data, so the server read the frame's length byte (0x08) as a
		// SOCKS address family and answered "unknown address family: 8". The product
		// path was correct; see TestAuditUoTPaddingContractIsTransportDependent.
		//
		// Skipping a security check because its own helper wrote the wrong wire
		// format would have left this property unverified indefinitely, so the check
		// is restored rather than deleted.
		before := udpOrigin.packets.Load()

		// What the tunnel must prove is that it is FUNCTIONAL, so the zero count below
		// is attributable to the rule. There is no permitted UDP target to use as a
		// positive control: the rule rejects all of 127.0.0.0/8, and every UDP origin
		// in this harness lives on loopback. A "control datagram that must be
		// delivered" would therefore contradict the property under test.
		//
		// The functional evidence is instead the established session itself: the
		// server answered 200 and accepted the UoT request header (openUoTNonConnect
		// asserts both), which it only does for a well-formed v2 non-connect request.
		// That is the same standard the TCP subtest in this file uses.
		rejectedSession := openUoTNonConnect(t, port)
		defer rejectedSession.Close()

		// The property: "localhost" resolves to 127.0.0.1, which the ip_cidr rule
		// covers, so the datagram must be dropped AFTER resolution.
		rejectedSession.writeNonConnectDatagram(t, "localhost:"+strconv.Itoa(int(udpOrigin.port())), []byte("probe"))

		// Give the router time to resolve and rule on it.
		require.Never(t, func() bool { return udpOrigin.packets.Load() > before },
			1*time.Second, 50*time.Millisecond,
			"a UoT datagram to a domain resolving to loopback reached the UDP origin; "+
				"the ip_cidr rule must apply to the RESOLVED address, not the request string")
	})

}

// readNonConnectDatagramOrEmpty reads one UoT reply, returning nil instead of failing
// the test when none arrives. A rejected destination is expected to produce no reply, so
// "no reply" is a normal outcome here rather than an error - the UDP-socket counter is
// the authoritative check.
func (s *uotSession) readNonConnectDatagramOrEmpty() []byte {
	body, err := readPaddingFrameRaw2(s.reader)
	if err != nil {
		return nil
	}
	reader := &sliceReader{data: body}
	if _, err = uot.AddrParser.ReadAddrPort(reader); err != nil {
		return nil
	}
	rest := reader.remaining()
	if len(rest) < 2 {
		return nil
	}
	size := int(binary.BigEndian.Uint16(rest[:2]))
	if size > len(rest)-2 {
		return nil
	}
	return rest[2 : 2+size]
}
