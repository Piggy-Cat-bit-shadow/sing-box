package jiejie_test

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// AUDIT: the task warns that checking only the DOMAIN STRING while dialing a
// resolved private address would defeat an IP-based rule. This measures whether
// an ip_cidr rule still holds when the client supplies a DOMAIN that resolves to
// 127.0.0.1, which is the concrete bypass to disprove.
func TestAuditDomainResolvingToLoopbackIsStillRuled(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	internal := startOriginBackend(t)

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

	_, portString, err := net.SplitHostPort(internal)
	require.NoError(t, err)

	// TCP: CONNECT to the DOMAIN "localhost".
	t.Run("TCP via domain", func(t *testing.T) {
		conn := naiveTLSConn(t, port)
		response, connErr := naiveWriteConnect(t, conn, "localhost:"+portString, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		if connErr != nil {
			t.Logf("refused: %v", connErr)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Logf("refused with status %d", response.StatusCode)
			return
		}
		_, _ = conn.Write(naivePaddingFrame(
			[]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"), 0))
		body, readErr := readPaddingFrameRaw2(bufio.NewReader(conn))
		if readErr != nil {
			t.Logf("tunnel closed after reject: %v", readErr)
			return
		}
		require.NotContains(t, string(body), "origin-ok",
			"a domain resolving to loopback must still be blocked by an ip_cidr "+
				"rule: the rule must apply to the RESOLVED address, not the string")
		t.Logf("domain resolving to loopback blocked (body %q)",
			string(body[:minInt(20, len(body))]))
	})

	// UoT: the same domain as a UDP destination.
	t.Run("UoT via domain", func(t *testing.T) {
		conn := naiveTLSConn(t, port)
		magic := uot.RequestDestination(uot.Version).String()
		response, connErr := naiveWriteConnect(t, conn, magic, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		if connErr != nil {
			t.Logf("refused: %v", connErr)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Logf("refused with status %d", response.StatusCode)
			return
		}
		writer := &sliceWriter{}
		require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer,
			metadata.ParseSocksaddr("localhost:"+portString)))
		_, _ = conn.Write(naivePaddingFrame(append([]byte{1}, writer.data...), 0))
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, 4)
		_, _ = conn.Write(naivePaddingFrame(append(length, []byte("ping")...), 0))

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		frame, readErr := readPaddingFrameRaw2(bufio.NewReader(conn))
		if readErr != nil {
			t.Logf("UoT domain tunnel closed after reject: %v", readErr)
			return
		}
		t.Logf("UoT domain reply: %q", string(frame))
	})
}
