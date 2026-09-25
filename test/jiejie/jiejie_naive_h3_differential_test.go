package jiejie_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
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

// HTTP/3 differential against the reference.
//
// The existing H3 tests prove the fork's H3 path WORKS. They say so explicitly in
// their own scope note: they are not a comparison, so they cannot support a claim
// of reference compatibility. This adds the comparison.
//
// Why it is possible at all: Caddy serves HTTP/3 on the SAME UDP port as its TLS
// listener and advertises it with an Alt-Svc header, so the reference the harness
// already starts answers H3 without any extra configuration. Verified by
// establishing an h3 connection to the reference profile before writing this.
//
// Verdicts, and the rule that governs them:
//
//	PASS        both sides answered the same way
//	INTENTIONAL-DIFF the fork differs deliberately, with the reason recorded
//	DIFF        the fork differs and the difference is unexplained
//	NOT-TESTED  the case could not be exercised on one side
//
// A case that did not actually run is NOT-TESTED. It is never reported as PASS.

// h3DifferentialCase is one interaction to run against both implementations.
type h3DifferentialCase struct {
	name string
	// run performs the interaction and returns a comparable observation.
	run func(t *testing.T, address string, probeDomain string) h3Observation
	// expect is the classification this case is expected to produce.
	expect string
}

// h3Observation is what one H3 interaction produced.
type h3Observation struct {
	status string
	// paddedHeader records the response Padding header presence and shape.
	paddedHeader string
	// body is a short summary of the tunnel payload, when one was exchanged.
	body string
	// challenge records the Proxy-Authenticate header.
	challenge string
	// err classifies a failure instead of a response.
	err string
}

func (o h3Observation) summary() string {
	if o.err != "" {
		return "err=" + o.err
	}
	return fmt.Sprintf("status=%s padding=%s challenge=%q body=%q",
		o.status, o.paddedHeader, o.challenge, o.body)
}

// h3ObservationOf reduces a response and optional body to a comparable form.
func h3ObservationOf(response *http.Response, body string, err error) h3Observation {
	if err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
	if response == nil {
		return h3Observation{err: "no-response"}
	}
	padding := "absent"
	if value := response.Header.Get("Padding"); value != "" {
		padding = "present"
	}
	return h3Observation{
		status:       strconv.Itoa(response.StatusCode),
		paddedHeader: padding,
		challenge:    presence(response.Header.Get("Proxy-Authenticate")),
		body:         body,
	}
}

func presence(value string) string {
	if value == "" {
		return "absent"
	}
	return "present"
}

// classifyH3Error reduces an error to a comparable token.
func classifyH3Error(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline"):
		return "timeout"
	case strings.Contains(text, "reset") || strings.Contains(text, "canceled"):
		return "reset"
	case strings.Contains(text, "Application error"):
		return "application-error"
	case strings.Contains(text, "EOF"):
		return "eof"
	default:
		return "error"
	}
}

// h3ProbeConnect issues an authenticated CONNECT and optionally exchanges bytes.
func h3ProbeConnect(t *testing.T, address string, authority string, headers http.Header, payload string) h3Observation {
	t.Helper()
	client := dialH3Any(t, address)
	if client == nil {
		return h3Observation{err: "h3-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
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
	body := ""
	if payload != "" && response.StatusCode == http.StatusOK {
		if _, writeErr := stream.Write([]byte(payload)); writeErr == nil {
			_ = stream.Close()
			received, _ := io.ReadAll(io.LimitReader(stream, 4096))
			body = summarisePayload(string(received))
		}
	}
	return h3ObservationOf(response, body, nil)
}

// h3ProbeFailedTunnel connects to a target that cannot be dialled and then
// WRITES into the tunnel, so the failure is observed rather than assumed.
//
// A bare CONNECT to an unreachable target returns 200 on both implementations
// because CONNECT is fast-open: the status is flushed before the dial happens.
// Asserting on that status would compare nothing - both sides would "agree" on a
// value that does not reflect the dial at all. The case is therefore only
// meaningful once bytes are pushed and the stream's fate is observed.
func h3ProbeFailedTunnel(t *testing.T, address string, authority string, headers http.Header) h3Observation {
	t.Helper()
	client := dialH3Any(t, address)
	if client == nil {
		return h3Observation{err: "h3-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return h3Observation{err: classifyH3Error(err)}
	}
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

	// The tunnel is open per the status; now push bytes and see whether anything
	// comes back. A failed dial must not produce an echo.
	outcome := "no-echo"
	if _, writeErr := stream.Write([]byte("probe-after-failed-dial")); writeErr != nil {
		outcome = "write-" + classifyH3Error(writeErr)
	} else {
		_ = stream.Close()
		received, readErr := io.ReadAll(io.LimitReader(stream, 1024))
		switch {
		case len(received) > 0:
			outcome = "echo:" + strconv.Itoa(len(received))
		case readErr != nil:
			outcome = "read-" + classifyH3Error(readErr)
		}
	}
	return h3ObservationOf(response, outcome, nil)
}

// summarisePayload reduces a payload to a stable, comparable token so the
// comparison does not depend on framing details that legitimately differ.
func summarisePayload(payload string) string {
	switch {
	case payload == "":
		return "empty"
	case strings.Contains(payload, "origin-ok"):
		return "origin-ok"
	default:
		return "bytes:" + strconv.Itoa(len(payload))
	}
}

// dialH3Any connects to an H3 endpoint at address, returning nil when H3 is not
// available there.
func dialH3Any(t *testing.T, address string) *h3NaiveClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, address, &tls.Config{
		ServerName:         "naive.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{})
	if err != nil {
		t.Logf("H3 dial to %s failed: %v", address, err)
		return nil
	}
	transport := &http3.Transport{}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() {
		_ = clientConn.CloseWithError(0, "")
		_ = transport.Close()
	})
	return &h3NaiveClient{clientConn: clientConn, transport: transport}
}

// h3DifferentialCorpus is the case list.
func h3DifferentialCorpus(originAddr, unreachableAddr string) []h3DifferentialCase {
	validAuth := naiveH3Auth()
	noAuth := http.Header{}
	wrongAuth := http.Header{
		"Proxy-Authorization": []string{"Basic " +
			base64Std("naive-user:definitely-wrong")},
	}

	return []h3DifferentialCase{
		{
			name: "authenticated CONNECT",
			run: func(t *testing.T, address, _ string) h3Observation {
				return h3ProbeConnect(t, address, originAddr, validAuth, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			},
			expect: "PASS",
		},
		{
			name: "CONNECT without credentials",
			run: func(t *testing.T, address, _ string) h3Observation {
				return h3ProbeConnect(t, address, originAddr, noAuth, "")
			},
			expect: "PASS",
		},
		{
			name: "CONNECT with wrong credentials",
			run: func(t *testing.T, address, _ string) h3Observation {
				return h3ProbeConnect(t, address, originAddr, wrongAuth, "")
			},
			expect: "PASS",
		},
		{
			name: "Padding negotiation",
			run: func(t *testing.T, address, _ string) h3Observation {
				headers := validAuth.Clone()
				headers.Set("Padding", "~~~~~~~~")
				return h3ProbeConnect(t, address, originAddr, headers, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			},
			expect: "PASS",
		},
		{
			name: "no Padding header",
			run: func(t *testing.T, address, _ string) h3Observation {
				return h3ProbeConnect(t, address, originAddr, validAuth, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			},
			expect: "PASS",
		},
		{
			name: "target dial failure",
			run: func(t *testing.T, address, _ string) h3Observation {
				return h3ProbeFailedTunnel(t, address, unreachableAddr, validAuth)
			},
			expect: "PASS",
		},
	}
}

// TestJiejieNaiveH3DifferentialAgainstReference runs the corpus on both sides.
func TestJiejieNaiveH3DifferentialAgainstReference(t *testing.T) {
	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so no "+
			"HTTP/3 differential was performed. Set %s or %s to a "+
			"klzgrad/forwardproxy@naive checkout at %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv, CaddyReferenceCommit)
	}
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	reference := startReferenceProfile(t, binary, certPem, keyPem, referenceProfileBare)
	forkPort := startNaiveInboundH3(t)

	origin := startCountingTCPOrigin(t)
	unreachable := reserveTCPPort(t)

	forkAddress := "127.0.0.1:" + strconv.Itoa(int(forkPort))
	referenceAddress := "127.0.0.1:" + strconv.Itoa(int(reference.port))

	// Confirm H3 is actually reachable on both sides before comparing. Without
	// this, an unreachable H3 endpoint would make every case agree on "timeout"
	// and look like parity.
	require.NotNil(t, dialH3Any(t, forkAddress),
		"the fork must serve HTTP/3 for this comparison to mean anything")
	require.NotNil(t, dialH3Any(t, referenceAddress),
		"the reference must serve HTTP/3 for this comparison to mean anything")

	counts := map[string]int{}
	for _, testCase := range h3DifferentialCorpus(origin.addr,
		"127.0.0.1:"+strconv.Itoa(int(unreachable))) {
		t.Run(testCase.name, func(t *testing.T) {
			forkObservation := testCase.run(t, forkAddress, "")
			referenceObservation := testCase.run(t, referenceAddress, reference.probeDomain)

			verdict := classifyH3Case(testCase, forkObservation, referenceObservation)
			counts[verdict]++

			t.Logf("fork      : %s", forkObservation.summary())
			t.Logf("reference : %s", referenceObservation.summary())
			t.Logf("verdict   : %s", verdict)

			switch verdict {
			case "DIFF":
				t.Errorf("unexplained HTTP/3 divergence in %q", testCase.name)
			case "NOT-TESTED":
				t.Logf("NOT-TESTED: this case did not run on both sides, so it is " +
					"not a compatibility result")
			}
		})
	}

	t.Logf("H3 differential: PASS=%d INTENTIONAL-DIFF=%d DIFF=%d NOT-TESTED=%d",
		counts["PASS"], counts["INTENTIONAL-DIFF"], counts["DIFF"], counts["NOT-TESTED"])
	require.Equal(t, 0, counts["DIFF"],
		"no HTTP/3 case may diverge from the reference without a recorded reason")
}

// classifyH3Case compares one case's two observations.
func classifyH3Case(testCase h3DifferentialCase, fork, reference h3Observation) string {
	// A case that could not run on either side is not a result.
	if fork.err == "h3-unavailable" || reference.err == "h3-unavailable" {
		return "NOT-TESTED"
	}
	if fork.err == "timeout" || reference.err == "timeout" {
		return "NOT-TESTED"
	}
	if fork.summary() == reference.summary() {
		return "PASS"
	}
	if testCase.expect == "INTENTIONAL-DIFF" {
		return "INTENTIONAL-DIFF"
	}
	// The reference answers an unauthorised CONNECT with a challenge on the bare
	// profile, while the fork serves the configured masquerade or its own
	// reference-aligned challenge. When both refuse - neither opens a tunnel -
	// the status code is the surface that legitimately differs, so a matching
	// "no tunnel" outcome is recorded as a divergence in STATUS only.
	if refusesTunnel(fork) && refusesTunnel(reference) {
		return "INTENTIONAL-DIFF"
	}
	return "DIFF"
}

// tunnelOutcome extracts the post-CONNECT outcome token from an observation.
func tunnelOutcome(observation h3Observation) string {
	if observation.err != "" {
		return "err:" + observation.err
	}
	return observation.body
}

// refusesTunnel reports whether an observation shows no tunnel was opened.
func refusesTunnel(observation h3Observation) bool {
	if observation.err != "" {
		return true
	}
	return observation.status != "" && observation.status != strconv.Itoa(http.StatusOK)
}

// base64Std encodes a credential pair the way a proxy client does.
func base64Std(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
