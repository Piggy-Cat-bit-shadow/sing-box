package jiejie_test

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// AUDIT: CONNECT authority interpretation.
//
// The reference implementation (klzgrad/forwardproxy) derives the tunnel target
// from r.URL.Host and falls back to r.Host. It never reads the "-connect-authority"
// header, which is not part of the Naive protocol.
//
// This test pins the observable consequence: when a client sends a CONNECT whose
// real target is A but supplies "-connect-authority: B", the request must be
// treated as a request for A. Otherwise the routed destination disagrees with the
// requested one, which misleads routing rules and logs.
func TestAuditConnectAuthorityCannotOverrideTarget(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	// A distinct origin the client will try to redirect to.
	decoyTarget := startRecordingTCPTarget(t)

	conn := naiveTLSConn(t, env.port)
	// The REAL CONNECT target is the echo address; the header names another host.
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n"+
		"Proxy-Authorization: %s\r\nPadding: ~~~~~~~~\r\n"+
		"-connect-authority: %s\r\n\r\n",
		env.echoAddr, env.echoAddr, naiveBasicAuth(), decoyTarget.address)
	_, err := io.WriteString(conn, request)
	require.NoError(t, err)

	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Send data through the tunnel and see WHICH target received it.
	_, err = conn.Write(naivePaddingFrame([]byte("AUTHORITY-PROBE"), 0))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.ReadAll(conn)
	_ = conn.Close()

	time.Sleep(300 * time.Millisecond)

	// The connection must have gone to the REAL CONNECT target, not to the host
	// named by the non-standard header.
	require.Zero(t, decoyTarget.connections.Load(),
		"the -connect-authority header is not part of the Naive protocol and must "+
			"not redirect the tunnel: the reference implementation ignores it")
}
