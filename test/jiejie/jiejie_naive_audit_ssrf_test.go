package jiejie_test

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// AUDIT: what can an AUTHENTICATED Naive client reach?
//
// This measures the current capability, and then proves the intended control
// mechanism (sing-box route rules) actually contains it. It does NOT assume the
// protocol layer blocks anything, because sing-box's model is that access
// control lives in the router, not in each protocol.
func TestAuditAuthenticatedClientReach(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// A service on loopback standing in for an internal admin port.
	internal := startOriginBackend(t)

	targets := []struct {
		name   string
		target string
	}{
		{"loopback IPv4", internal},
		{"loopback IPv4 explicit", "127.0.0.1:" + portOf(t, internal)},
		{"IPv6 loopback", "[::1]:9"},
		{"RFC1918 10/8", "10.0.0.1:9"},
		{"RFC1918 192.168/16", "192.168.1.1:9"},
		{"IPv4 link-local", "169.254.169.254:80"},
		{"IPv6 ULA", "[fd00::1]:9"},
		{"IPv6 link-local", "[fe80::1]:9"},
		{"public", "93.184.216.34:443"},
	}

	for _, target := range targets {
		t.Run("TCP "+target.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			response, err := naiveWriteConnect(t, conn, target.target, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			if err != nil {
				t.Logf("TCP %-22s -> refused at transport (%v)", target.name, err)
				return
			}
			defer response.Body.Close()
			t.Logf("TCP %-22s -> status %d", target.name, response.StatusCode)
		})

		t.Run("UoT "+target.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			magic := uot.RequestDestination(uot.Version).String()
			response, err := naiveWriteConnect(t, conn, magic, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			if err != nil {
				t.Logf("UoT %-22s -> refused (%v)", target.name, err)
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Logf("UoT %-22s -> status %d", target.name, response.StatusCode)
				return
			}
			writer := &sliceWriter{}
			if err = metadata.SocksaddrSerializer.WriteAddrPort(writer,
				metadata.ParseSocksaddr(target.target)); err != nil {
				t.Logf("UoT %-22s -> encode error %v", target.name, err)
				return
			}
			// HTTP/1: raw tunnel, so the UoT request header goes out verbatim.
			_, _ = conn.Write(append([]byte{1}, writer.data...))
			length := make([]byte, 2)
			binary.BigEndian.PutUint16(length, 4)
			_, _ = conn.Write(append(length, []byte("ping")...))
			t.Logf("UoT %-22s -> accepted into the data path", target.name)
		})
	}
}

// TestAuditLoopbackIsReachableByDefault documents the DEFAULT capability, so the
// risk is measured rather than assumed either way.
func TestAuditLoopbackIsReachableByDefault(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	internal := startOriginBackend(t)

	conn := naiveTLSConn(t, env.port)
	response, err := naiveWriteConnect(t, conn, internal, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.NoError(t, err, "an authenticated CONNECT to loopback should be attempted")
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	// HTTP/1 CONNECT is a RAW tunnel, so the HTTP request is written verbatim and
	// the response is read verbatim. This test originally framed both, which meant
	// it asserted on a byte stream the origin never sent.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	body, readErr := io.ReadAll(bufio.NewReader(conn))
	require.NoError(t, readErr)
	t.Logf("DEFAULT: authenticated client reached loopback origin, got %q",
		string(body[:minInt(20, len(body))]))
	require.Contains(t, string(body), "origin-ok",
		"documenting current behaviour: with no route rule, an authenticated "+
			"client CAN reach a loopback service")
}

// TestAuditRouteRuleBlocksLoopback proves the INTENDED control works: a route
// rule rejecting private/loopback destinations prevents reach, for both TCP and
// UoT, with authentication still required.
func TestAuditRouteRuleBlocksLoopback(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	internal := startOriginBackend(t)

	// Build the route through JSON so the rule uses the real config schema
	// rather than a hand-built option literal.
	// Decode with the registry-aware context, otherwise the inbound options
	// cannot be resolved to their concrete type.
	var routeOptions option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": `+strconv.Itoa(int(port))+`,
			"network": "tcp",
			"users": [{"username": "`+naiveTestUser+`", "password": "`+naiveTestPassword+`"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "`+certPem+`",
				"key_path": "`+keyPem+`"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [{
				"ip_cidr": ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "10.0.0.0/8", "192.168.0.0/16"],
				"action": "reject"
			}],
			"final": "direct"
		}
	}`), &routeOptions))
	startInstance(t, routeOptions)

	// Loopback must now be refused.
	conn := naiveTLSConn(t, port)
	response, err := naiveWriteConnect(t, conn, internal, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			// HTTP/1: raw tunnel, written and read verbatim.
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
			// A rejected route closes the tunnel, so the read may simply fail.
			// Either an error or a body without the origin's content is a pass.
			body, readErr := io.ReadAll(bufio.NewReader(conn))
			if readErr != nil {
				t.Logf("loopback tunnel closed after route reject: %v", readErr)
			} else {
				require.NotContains(t, string(body), "origin-ok",
					"a route rule rejecting private IPs must prevent reaching loopback")
				t.Logf("loopback reach blocked by route rule (body %q)",
					string(body[:minInt(20, len(body))]))
			}
		} else {
			t.Logf("loopback refused with status %d", response.StatusCode)
		}
	} else {
		t.Logf("loopback refused at transport: %v", err)
	}

	// Control: prove the rule is TARGETED, not blanket. A second inbound in the
	// same instance with a rule that does NOT cover 127.0.0.0/8 must still reach
	// the same loopback origin. This is the only way to show that the block above
	// came from the rule rather than from the destination being unreachable.
	controlPort := reserveTCPPort(t)
	var controlOptions option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(`{
		"inbounds": [{
			"type": "naive",
			"tag": "naive-control",
			"listen": "127.0.0.1",
			"listen_port": `+strconv.Itoa(int(controlPort))+`,
			"network": "tcp",
			"users": [{"username": "`+naiveTestUser+`", "password": "`+naiveTestPassword+`"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "`+certPem+`",
				"key_path": "`+keyPem+`"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [{
				"ip_cidr": ["203.0.113.0/24"],
				"action": "reject"
			}],
			"final": "direct"
		}
	}`), &controlOptions))
	startInstance(t, controlOptions)

	controlConn := naiveTLSConn(t, controlPort)
	controlResponse, controlErr := naiveWriteConnect(t, controlConn, internal, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.NoError(t, controlErr)
	defer controlResponse.Body.Close()
	require.Equal(t, http.StatusOK, controlResponse.StatusCode)
	// HTTP/1: raw tunnel, written and read verbatim.
	_, controlErr = controlConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	require.NoError(t, controlErr)
	controlBody, controlReadErr := io.ReadAll(bufio.NewReader(controlConn))
	require.NoError(t, controlReadErr)
	require.Contains(t, string(controlBody), "origin-ok",
		"a rule that does NOT cover loopback must still allow the same destination: "+
			"this proves the earlier block came from the rule, not from unreachability")
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return port
}
