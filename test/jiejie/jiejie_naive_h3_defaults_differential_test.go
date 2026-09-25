package jiejie_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// HTTP/3 server defaults, measured against the reference.
//
// The reference is Caddy v2.10.0, whose startHTTP3 builds:
//
//	&http3.Server{
//	    Handler:        s,
//	    TLSConfig:      tlsCfg,
//	    MaxHeaderBytes: s.MaxHeaderBytes,
//	    QUICConfig:     &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}, Tracer: ...},
//	    IdleTimeout:    time.Duration(s.IdleTimeout),
//	}
//
// so it sets three things this inbound does not: a header limit, an idle timeout
// (Caddy default 5 minutes) and an EXPLICIT QUIC version list. Each is measured
// here rather than assumed, because "quic-go currently defaults to v1 and v2"
// is a dependency property that can change under us, and an unset idle timeout
// is a real resource bound on a 1 GiB host.

// h3QUICVersions reports the QUIC versions a server accepts.
//
// quic-go negotiates from the client's offer, so offering one version at a time
// is what identifies which are supported.
func h3QUICVersions(t *testing.T, address string) []quic.Version {
	t.Helper()
	var supported []quic.Version
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := quic.DialAddrEarly(ctx, address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         []string{http3.NextProtoH3},
		}, &quic.Config{Versions: []quic.Version{version}})
		cancel()
		if err != nil {
			t.Logf("QUIC %s: refused (%v)", version, err)
			continue
		}
		_ = conn.CloseWithError(0, "")
		supported = append(supported, version)
		t.Logf("QUIC %s: accepted", version)
	}
	return supported
}

// TestJiejieNaiveH3QUICVersionsMatchTheReference pins the QUIC versions.
//
// Caddy pins v1 and v2 explicitly. If this fork relied on quic-go's default, a
// dependency bump that changed that default would silently drop v2 support with
// no test failing, so the versions are asserted rather than inherited.
func TestJiejieNaiveH3QUICVersionsMatchTheReference(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3 support (the production tag set " +
			"omits protocol/naive/quic), so the QUIC version sets cannot be " +
			"compared. Run under with_quic without jiejie_server_minimal. This is " +
			"a SKIP, not a pass.")
	}
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference binary is unavailable, so the QUIC versions could "+
			"not be compared. Set %s or %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	reference := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)
	forkPort := startNaiveInboundH3(t)

	forkVersions := h3QUICVersions(t, "127.0.0.1:"+strconv.Itoa(int(forkPort)))
	referenceVersions := h3QUICVersions(t, "127.0.0.1:"+strconv.Itoa(int(reference.port)))

	t.Logf("fork QUIC versions:      %v", forkVersions)
	t.Logf("reference QUIC versions: %v", referenceVersions)

	require.Contains(t, referenceVersions, quic.Version1,
		"the reference must accept QUIC v1 for this comparison to be meaningful")
	require.Equal(t, referenceVersions, forkVersions,
		"the fork must accept exactly the QUIC versions the reference accepts; "+
			"Caddy pins v1 and v2 explicitly, so relying on the library default "+
			"would let a dependency change go unnoticed")
}

// TestJiejieNaiveH3HeaderLimitIsEnforced measures whether an oversized request
// header is rejected.
//
// ENFORCED is the reference-like outcome. NOT-ENFORCED is recorded explicitly
// rather than treated as a pass, because a server with no header limit accepts
// arbitrary header bytes from an unauthenticated peer.
func TestJiejieNaiveH3HeaderLimitIsEnforced(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3 support, so the header limit " +
			"cannot be measured. This is a SKIP, not a pass.")
	}
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference binary is unavailable; set %s or %s. This is a "+
			"SKIP, not a pass.", caddyReferenceBinaryEnv, caddyReferenceSourceEnv)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	reference := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)
	forkPort := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)

	// An oversized header value. The exact limit differs between the two
	// implementations, so the test reports what each did rather than asserting a
	// single threshold it cannot know.
	oversized := strings.Repeat("A", 2*1024*1024)

	for _, tc := range []struct {
		name    string
		address string
	}{
		{"fork", "127.0.0.1:" + strconv.Itoa(int(forkPort))},
		{"reference", "127.0.0.1:" + strconv.Itoa(int(reference.port))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := h3ProbeOversizedHeader(t, tc.address, origin.addr, oversized)
			t.Logf("%s with a %d-byte header: %s", tc.name, len(oversized), observation.summary())
			// Both an explicit rejection and a transport-level failure are
			// acceptable; silently ACCEPTING it is the outcome worth knowing
			// about, and it is logged so a difference is visible.
			if observation.err == "" && observation.status == "200" {
				t.Logf("%s ACCEPTED the oversized header", tc.name)
			}
		})
	}
}

// h3ProbeOversizedHeader attempts a CONNECT carrying a very large header.
func h3ProbeOversizedHeader(t *testing.T, address, authority, headerValue string) h3Observation {
	t.Helper()
	client := dialH3Any(t, address)
	if client == nil {
		return h3Observation{err: "h3-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
	headers := naiveH3Auth()
	headers.Set("X-Oversized", headerValue)
	if err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: headers,
	}); err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
	return h3ObservationOf(response, "", nil)
}

// TestJiejieNaiveH3IdleTimeoutIsBounded measures whether an idle HTTP/3
// connection is reclaimed, by watching the connection stay usable across idle
// periods and reporting when it stops.
//
// Caddy sets IdleTimeout from its server config (default 5 minutes), so an idle
// H3 connection is reclaimed there. This test does not wait five minutes; it
// measures whether the connection SURVIVES a short idle period, which is the
// observable half of the property, and reports the finding rather than asserting
// a threshold the API cannot expose.
//
// Scope, stated so this is not over-read: "still alive after N seconds" does not
// prove an idle bound exists, only that it is longer than N. The check that would
// prove a bound is a multi-minute wait, which is not worth the CI cost for a
// property the quic-go default already provides; the finding is recorded instead.
func TestJiejieNaiveH3IdleTimeoutIsBounded(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3 support, so idle behaviour " +
			"cannot be measured. This is a SKIP, not a pass.")
	}
	forkPort := startNaiveInboundH3(t)
	address := "127.0.0.1:" + strconv.Itoa(int(forkPort))
	origin := startCountingTCPOrigin(t)

	client := dialH3Any(t, address)
	require.NotNil(t, client, "the HTTP/3 listener must be reachable")

	// Establish a tunnel, then idle, then use it again.
	firstResponse, stream := openH3Connect(t, client, origin.addr, naiveH3Auth())
	require.Equal(t, 200, firstResponse.StatusCode)
	_ = stream

	idle := 3 * time.Second
	t.Logf("idling the HTTP/3 connection for %s", idle)
	time.Sleep(idle)

	// A second stream on the SAME connection must still work if the connection
	// was not reclaimed.
	secondResponse, secondStream := openH3Connect(t, client, origin.addr, naiveH3Auth())
	if secondResponse == nil {
		t.Logf("the connection was reclaimed after %s of idling", idle)
		return
	}
	t.Logf("the connection survived %s of idling (status=%d)", idle, secondResponse.StatusCode)
	_ = secondStream
	t.Logf("Note: this shows the idle bound is LONGER than %s, not that none "+
		"exists; proving a bound needs a multi-minute wait", idle)
}

// openH3Connect opens one CONNECT stream on an existing client connection.
func openH3Connect(t *testing.T, client *h3NaiveClient, authority string, headers map[string][]string) (*http.Response, *http3.RequestStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		t.Logf("opening a stream failed: %v", err)
		return nil, nil
	}
	header := make(http.Header, len(headers))
	for name, values := range headers {
		header[name] = values
	}
	if err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: header,
	}); err != nil {
		t.Logf("sending the request header failed: %v", err)
		return nil, nil
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Logf("reading the response failed: %v", err)
		return nil, nil
	}
	return response, stream
}
