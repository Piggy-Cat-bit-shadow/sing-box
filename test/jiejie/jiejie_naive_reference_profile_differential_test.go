package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Bare vs official reference, compared as two distinct deployments.
//
// This is the differential that the single-profile harness could not express.
// The two reference deployments answer the SAME unauthenticated request in
// completely different ways, and each is correct for its own deployment:
//
//	bare      unauth CONNECT -> 407 + Proxy-Authenticate
//	official  unauth CONNECT -> served by the web backend (never challenged)
//
// Reporting either one as "the reference behaviour" would be wrong, and a report
// that mixed them would let a genuine divergence hide behind the other profile's
// result. So the profiles are compared separately and each observation records
// which one produced it.

// profileObservation is one interaction with one reference profile.
type profileObservation struct {
	profile referenceProfile
	// status is the HTTP status line code, or 0 when none was produced.
	status int
	// proxyAuthenticate is the challenge header, or "" when absent.
	proxyAuthenticate string
	// location is the redirect target when the reference passes the request on.
	location string
	// contentType is the response content type.
	contentType string
	// bodyContainsDecoy reports whether the web backend's document was served.
	bodyContainsDecoy bool
	// err classifies a transport failure instead of a response.
	err string
}

func (o profileObservation) summary() string {
	if o.err != "" {
		return "err=" + o.err
	}
	return fmt.Sprintf("status=%d challenge=%q location=%q type=%q decoy=%v",
		o.status, o.proxyAuthenticate, o.location, o.contentType, o.bodyContainsDecoy)
}

// probeProfileRequest opens a TLS connection to a reference profile, sends a raw
// request and records the response.
func probeProfileRequest(t *testing.T, instance *referenceInstance, request string) profileObservation {
	t.Helper()
	observation := profileObservation{profile: instance.profile}

	rawConn, err := net.DialTimeout("tcp",
		"127.0.0.1:"+strconv.Itoa(int(instance.port)), 10*time.Second)
	if err != nil {
		observation.err = "dial"
		return observation
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		NextProtos:         []string{"http/1.1"},
	})
	if err = tlsConn.Handshake(); err != nil {
		observation.err = "tls"
		return observation
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err = io.WriteString(tlsConn, request); err != nil {
		observation.err = "write"
		return observation
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		// A reference that passes the request to a handler with no route can
		// close without a response. That is a result, not a failure.
		observation.err = "no-response"
		return observation
	}
	defer response.Body.Close()

	observation.status = response.StatusCode
	observation.proxyAuthenticate = response.Header.Get("Proxy-Authenticate")
	observation.location = response.Header.Get("Location")
	observation.contentType = response.Header.Get("Content-Type")
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	observation.bodyContainsDecoy = strings.Contains(string(body), referenceDecoyMarker)
	return observation
}

// TestJiejieReferenceProfilesAreDistinct pins that the two profiles really do
// behave differently for the same unauthorised request.
//
// Without this, a configuration mistake that accidentally produced the same
// deployment twice would make every downstream comparison look like agreement.
func TestJiejieReferenceProfilesAreDistinct(t *testing.T) {
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so the "+
			"two reference profiles could not be compared. Set %s, or %s to a "+
			"klzgrad/forwardproxy@naive checkout at %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv, CaddyReferenceCommit)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")

	bare := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)
	official := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileOfficial)

	const unauthConnect = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"

	bareObservation := probeProfileRequest(t, bare, unauthConnect)
	officialObservation := probeProfileRequest(t, official, unauthConnect)

	require.Equal(t, referenceProfileBare, bareObservation.profile)
	require.Equal(t, referenceProfileOfficial, officialObservation.profile)

	t.Logf("bare     unauth CONNECT: %s", bareObservation.summary())
	t.Logf("official unauth CONNECT: %s", officialObservation.summary())

	t.Run("bare challenges with a 407", func(t *testing.T) {
		require.Equal(t, http.StatusProxyAuthRequired, bareObservation.status,
			"the bare profile has no probe resistance, so it must advertise the "+
				"proxy with a challenge")
		require.Equal(t, "Basic realm=\""+bareProxyRealm+"\"",
			bareObservation.proxyAuthenticate)
	})

	t.Run("official does not challenge", func(t *testing.T) {
		require.NotEqual(t, http.StatusProxyAuthRequired, officialObservation.status,
			"with probe_resistance configured the reference must not advertise a "+
				"proxy authentication surface; a challenge here means the profile "+
				"is not configured the way this test believes")
		require.Empty(t, officialObservation.proxyAuthenticate,
			"the official deployment must never emit Proxy-Authenticate for an "+
				"unauthenticated request")
	})

	t.Run("the two profiles differ", func(t *testing.T) {
		require.NotEqual(t, bareObservation.summary(), officialObservation.summary(),
			"if both profiles behave identically then one of them is misconfigured "+
				"and every comparison built on them is meaningless")
	})
}

// TestJiejieReferenceOfficialServesTheFrontingSite pins the other half of the
// official deployment: ordinary web traffic reaches the web backend.
func TestJiejieReferenceOfficialServesTheFrontingSite(t *testing.T) {
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable; set %s "+
			"or %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	official := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileOfficial)

	observation := probeProfileRequest(t, official,
		"GET / HTTP/1.1\r\nHost: whatever.test\r\nConnection: close\r\n\r\n")

	require.Empty(t, observation.err, "the fronting site must answer an ordinary GET")
	require.Equal(t, http.StatusOK, observation.status)
	require.True(t, observation.bodyContainsDecoy,
		"an ordinary GET must be served the fronting site, not a proxy response")
	require.Empty(t, observation.proxyAuthenticate,
		"the fronting site must never carry a proxy challenge")
}

// TestJiejieNativeNaiveMatchesTheBareProfileChallenge compares the fork against
// the bare reference on the surface that was previously divergent.
//
// This is the cross-implementation half: the same request is sent to the bare
// reference and to the Native Naive inbound with no masquerade, and the two
// answers must agree. The official profile is deliberately NOT used here, because
// its correct answer for this request is different by design.
func TestJiejieNativeNaiveMatchesTheBareProfileChallenge(t *testing.T) {
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable; set %s "+
			"or %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	bare := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)

	env := startNaiveInbound(t, false)
	const request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"

	referenceObservation := probeProfileRequest(t, bare, request)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	defer conn.Close()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err, "the fork must answer an unauthenticated CONNECT")
	defer response.Body.Close()

	t.Logf("reference (bare): %s", referenceObservation.summary())
	t.Logf("native naive    : status=%d challenge=%q", response.StatusCode,
		response.Header.Get("Proxy-Authenticate"))

	require.Equal(t, referenceObservation.status, response.StatusCode,
		"the fork must answer an unauthenticated CONNECT with the same status as "+
			"the bare reference")
	require.Equal(t, referenceObservation.proxyAuthenticate,
		response.Header.Get("Proxy-Authenticate"),
		"the challenge header must match the reference verbatim")
}
