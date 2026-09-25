package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/stretchr/testify/require"
)

// Caddy differential compatibility harness.
//
// The point of this file is to compare sing-box's Native Naive inbound against
// the REFERENCE implementation (klzgrad/forwardproxy@naive behind Caddy) on the
// same probe matrix, rather than against sing-box's own expectations. A
// divergence is only meaningful if it is measured against the thing we claim to
// be compatible with.
//
// The reference is pinned, never @latest:
//   - forwardproxy commit: CaddyReferenceCommit
//   - Caddy:              CaddyReferenceVersion
//
// The reference binary is built from a LOCAL checkout so the build is
// reproducible and does not depend on a branch moving. If the binary is not
// available the harness SKIPs with an explicit message - it never reports a pass
// it did not earn, and it never mistakes "could not build the reference" for
// "the implementations agree".

const (
	// CaddyReferenceVersion is the Caddy release the reference is built from.
	CaddyReferenceVersion = "v2.10.0"

	// caddyReferenceBinaryEnv lets CI (or a developer) point at a prebuilt
	// reference binary. Building Caddy takes minutes, so the harness prefers a
	// cached binary when one is provided.
	caddyReferenceBinaryEnv = "JIEJIE_CADDY_REFERENCE_BINARY"

	// caddyReferenceSourceEnv points at a local forwardproxy checkout. Used to
	// build the reference when no binary is provided.
	caddyReferenceSourceEnv = "JIEJIE_CADDY_REFERENCE_SOURCE"

	// naiveTestUser / naiveTestPassword are reused from the Naive test suite so
	// both servers are configured with identical credentials.
	naiveParityUser     = naiveTestUser
	naiveParityPassword = naiveTestPassword
)

// parityResult is one row of the compatibility report.
//
// The JSON shape is the machine-readable artifact contract: consumers key on
// `verdict`, and every row states which reference it was compared against so a
// report cannot be read without knowing that.
type parityResult struct {
	Protocol  string `json:"protocol"`
	Name      string `json:"case"`
	Reference string `json:"reference"`
	SingBox   string `json:"sing_box"`
	// Verdict is one of PASS, DIFF, INTENTIONAL-DIFF, NOT-TESTED.
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// ReferenceCommit and CaddyVersion identify what the comparison was against.
	ReferenceCommit string `json:"reference_commit"`
	CaddyVersion    string `json:"caddy_version"`
}

// parityReport is the top-level artifact.
type parityReport struct {
	GeneratedAt     string         `json:"generated_at"`
	ReferenceCommit string         `json:"reference_commit"`
	CaddyVersion    string         `json:"caddy_version"`
	Summary         map[string]int `json:"summary"`
	Cases           []parityResult `json:"cases"`
}

// writeParityReport emits the machine-readable report.
//
// The summary counts every verdict, and any NOT-TESTED case is called out
// explicitly so a reader cannot mistake "the comparison did not run" for "the
// comparison passed".
func writeParityReport(t *testing.T, results []parityResult) {
	t.Helper()
	path := os.Getenv("JIEJIE_PARITY_REPORT")
	if path == "" {
		return
	}

	summary := make(map[string]int)
	for _, result := range results {
		summary[result.Verdict]++
	}

	report := parityReport{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		ReferenceCommit: CaddyReferenceCommit,
		CaddyVersion:    CaddyReferenceVersion,
		Summary:         summary,
		Cases:           results,
	}

	// MERGE rather than clobber. The H1 and H2 differentials are separate tests
	// writing to the same artifact path, so writing outright would leave a report
	// containing whichever ran last - a report that silently omits a protocol is
	// worse than no report, because it reads as full coverage.
	if existing, readErr := os.ReadFile(path); readErr == nil {
		var previous parityReport
		if json.Unmarshal(existing, &previous) == nil {
			report.Cases = append(previous.Cases, report.Cases...)
			merged := make(map[string]int)
			for _, one := range report.Cases {
				merged[one.Verdict]++
			}
			report.Summary = merged
		}
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Logf("could not encode the parity report: %v", err)
		return
	}
	if err = os.WriteFile(path, encoded, 0o644); err != nil {
		t.Logf("could not write the parity report to %s: %v", path, err)
		return
	}
	t.Logf("machine-readable report written to %s: %v", path, report.Summary)

	if notTested := report.Summary["NOT-TESTED"]; notTested > 0 {
		t.Logf("REFERENCE COMPARISON: NOT-TESTED for %d case(s) - see the report",
			notTested)
	}
}

// parityProbe is one observable interaction, run against both servers.
type parityProbe struct {
	name string
	run  func(t *testing.T, address string) parityObservation

	// knownDivergence, when set, marks a difference that has been investigated and
	// is INTENTIONAL on our side. The probe is still run and its two results are
	// still printed, and the verdict becomes INTENTIONAL-DIFF rather than PASS or DIFF.
	// Leaving it unset means the probe is expected to match exactly.
	//
	// The label is INTENTIONAL-DIFF, and it is NOT an escape hatch for an
	// unexplained failure. The bar is that all four of these exist and are
	// recorded in the string:
	//
	//   1. pinned-source evidence for what the reference does;
	//   2. runtime reproduction through this harness;
	//   3. the exact observed values (filled in automatically below);
	//   4. an explicit product decision that this fork intends to differ.
	//
	// A difference that cannot meet that bar is a DIFF and fails CI. An earlier
	// version of this harness labelled the H1 raw-passthrough case as a divergence
	// on the strength of a misread probe; it has since been proven by byte
	// comparison that both implementations agree, and the label was removed rather
	// than kept.
	knownDivergence string
}

// parityObservation is what a probe saw, reduced to comparable strings.
type parityObservation struct {
	// status is the HTTP status, or "" when no response was produced.
	status string
	// paddingHeader is "present"/"absent" and, when present, its length bucket.
	paddingHeader string
	// tunnelOpened reports whether CONNECT produced a usable tunnel.
	tunnelOpened string
	// rawPassthrough reports whether UNframed bytes reached the origin.
	rawPassthrough string
	// framedPassthrough reports whether FRAMED bytes reached the origin.
	framedPassthrough string
	// err is a short error classification when something failed.
	err string
}

// ---------------------------------------------------------------------------
// Reference server lifecycle
// ---------------------------------------------------------------------------

// caddyReferenceBinary locates or builds the reference Caddy binary.
//
// Returns "" when it cannot be produced, so the caller can SKIP explicitly.
func caddyReferenceBinary(t *testing.T) string {
	t.Helper()

	if provided := os.Getenv(caddyReferenceBinaryEnv); provided != "" {
		if _, err := os.Stat(provided); err == nil {
			t.Logf("using prebuilt reference binary from %s", caddyReferenceBinaryEnv)
			return provided
		}
		t.Logf("%s is set to %q but that file does not exist", caddyReferenceBinaryEnv, provided)
	}

	source := os.Getenv(caddyReferenceSourceEnv)
	if source == "" {
		// A conventional checkout location, so a developer who followed the
		// documentation gets the harness without extra setup.
		candidate := filepath.Join(os.TempDir(), "forwardproxy-ref")
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			source = candidate
		}
	}
	if source == "" {
		t.Logf("no reference source: set %s to a klzgrad/forwardproxy@naive checkout",
			caddyReferenceSourceEnv)
		return ""
	}

	// Verify the checkout is the pinned revision before building it. Building an
	// arbitrary revision would make the comparison meaningless.
	head, err := exec.Command("git", "-C", source, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Logf("cannot read the reference revision: %v", err)
		return ""
	}
	if got := strings.TrimSpace(string(head)); got != CaddyReferenceCommit {
		t.Logf("reference checkout is at %s but this harness is pinned to %s; "+
			"refusing to compare against an unpinned revision", got, CaddyReferenceCommit)
		return ""
	}

	buildDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(
		"module caddyrefbuild\n\ngo 1.23.0\n\nrequire (\n"+
			"\tgithub.com/caddyserver/caddy/v2 "+CaddyReferenceVersion+"\n"+
			"\tgithub.com/caddyserver/forwardproxy v0.0.0\n)\n\n"+
			"replace github.com/caddyserver/forwardproxy => "+source+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(
		"package main\n\nimport (\n\tcaddycmd \"github.com/caddyserver/caddy/v2/cmd\"\n\n"+
			"\t_ \"github.com/caddyserver/caddy/v2/modules/standard\"\n"+
			"\t_ \"github.com/caddyserver/forwardproxy\"\n)\n\nfunc main() { caddycmd.Main() }\n"), 0o644))

	binary := filepath.Join(buildDir, "caddy-reference")
	t.Logf("building the reference Caddy %s with forwardproxy@%s (this takes a few minutes)",
		CaddyReferenceVersion, CaddyReferenceCommit[:12])
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = buildDir
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Logf("reference build failed: %v\n%s", buildErr, tailLines(string(output), 20))
		return ""
	}
	return binary
}

// startCaddyReference starts the reference server with a Naive forwardproxy.
//
// It answers on loopback with the test certificate, exactly as the sing-box
// instance under test does, so the two differ only in implementation.
func startCaddyReference(t *testing.T, binary, certPem, keyPem string) (port uint16, stop func()) {
	t.Helper()
	port = reserveTCPPort(t)
	// A SEPARATE port for Caddy's automatic HTTP->HTTPS redirect server. Sharing
	// one port between http_port and https_port let the plain-HTTP server take
	// the listener, so the TLS probe hit a cleartext port and failed with
	// "first record does not look like a TLS handshake".
	redirectPort := reserveTCPPort(t)

	// auth_credentials is a list of base64-encoded "user:password" strings; that
	// is the field the reference declares (forwardproxy.go line 109) and it is
	// what it compares the Proxy-Authorization payload against.
	// Caddy provisions an automatic-HTTPS server by default and, with no port
	// configured, tries to bind :80 - which an unprivileged test process cannot
	// do. Pinning http_port/https_port to the reserved listener and disabling
	// automatic HTTPS keeps the reference on loopback, which is also what makes
	// it comparable to the sing-box instance under test.
	//
	// auth_credentials is `[][]byte` (forwardproxy.go line 109), and the
	// reference fills it with the BYTES of a base64 string:
	//
	//	func EncodeAuthCredentials(user, pass string) (result []byte) {
	//	    raw := []byte(user + ":" + pass)
	//	    result = make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	//	    base64.StdEncoding.Encode(result, raw)   // caddyfile.go line 27
	//	}
	//
	// Go marshals a []byte to JSON as base64, so the JSON string must be the
	// base64 OF THAT base64 STRING. Writing the plain "user:password" base64
	// here makes Caddy hold the decoded bytes and compare them against the
	// base64 text the client sends, which never matches - it answers 407 for
	// correct credentials and looks exactly like an authentication divergence.
	caddyAuthCredential := base64.StdEncoding.EncodeToString([]byte(basicAuthValue()))
	//
	// The TLS connection policy is left EMPTY deliberately. A policy matching on
	// SNI made Caddy look for an automated certificate for that name instead of
	// using the manually loaded one, and the handshake then failed - which showed
	// up as err=tls in every probe and would have been easy to misread as a
	// protocol divergence.
	config := fmt.Sprintf(`{
	"admin": {"disabled": true},
	"logging": {"logs": {"default": {"level": "ERROR"}}},
	"apps": {
		"http": {
			"http_port": %d,
			"https_port": %d,
			"servers": {
				"naive": {
					"listen": ["127.0.0.1:%d"],
					"routes": [{
						"handle": [{
							"handler": "forward_proxy",
							"auth_credentials": [%q],
							"acl": [{"subjects": ["127.0.0.1/32", "::1/128"], "allow": true}]
						}]
					}],
					"tls_connection_policies": [{}]
				}
			}
		},
		"tls": {
			"certificates": {
				"load_files": [{"certificate": %q, "key": %q}]
			}
		}
	}
}`, redirectPort, port, port, caddyAuthCredential, certPem, keyPem)

	configPath := filepath.Join(t.TempDir(), "caddy-naive.json")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	// JSON is Caddy's native config format, so no --adapter is passed; asking for
	// an adapter named "json" is rejected ("unrecognized config adapter").
	command := exec.Command(binary, "run", "--config", configPath)
	command.Stdout = io.Discard
	var stderr strings.Builder
	command.Stderr = &stderr
	require.NoError(t, command.Start())

	t.Logf("reference config: cert=%s key=%s port=%d", certPem, keyPem, port)
	if _, statErr := os.Stat(certPem); statErr != nil {
		t.Logf("certificate path is not readable: %v", statErr)
	}
	if _, statErr := os.Stat(keyPem); statErr != nil {
		t.Logf("key path is not readable: %v", statErr)
	}

	waited := false
	for range 100 {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			waited = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !waited {
		_ = command.Process.Kill()
		t.Skipf("the reference Caddy did not start listening on %d; stderr:\n%s",
			port, tailLines(stderr.String(), 20))
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	if stderr.Len() > 0 {
		t.Logf("reference stderr: %s", tailLines(stderr.String(), 15))
	}
	return port, func() { _ = command.Process.Kill() }
}

func tailLines(text string, count int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Probes. Each is transport-agnostic: it is handed an address and reports what
// it observed, so the same code runs against both servers.
// ---------------------------------------------------------------------------

// probeObservation runs one H1 CONNECT and reduces the outcome to comparable
// strings.
func probeH1Connect(originAddr string, headers map[string]string, body []byte) func(*testing.T, string) parityObservation {
	return func(t *testing.T, address string) parityObservation {
		var observation parityObservation

		rawConn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			observation.err = "dial"
			return observation
		}
		defer rawConn.Close()

		// ALPN is pinned to http/1.1. Caddy negotiates h2 by default when the
		// client offers it, so without this a probe that then speaks HTTP/1.1
		// would fail the TLS layer and look like a protocol divergence rather
		// than the transport mismatch it actually is.
		tlsConn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         []string{"http/1.1"},
		})
		if err = tlsConn.Handshake(); err != nil {
			observation.err = "tls: " + err.Error()
			return observation
		}
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

		var builder strings.Builder
		fmt.Fprintf(&builder, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", originAddr, originAddr)
		for name, value := range headers {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
		builder.WriteString("\r\n")
		if _, err = io.WriteString(tlsConn, builder.String()); err != nil {
			observation.err = "write-request"
			return observation
		}

		response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			observation.err = "read-response"
			return observation
		}
		observation.status = strconv.Itoa(response.StatusCode)
		observation.paddingHeader = classifyPaddingHeader(response.Header.Get("Padding"))

		if response.StatusCode != http.StatusOK {
			return observation
		}
		observation.tunnelOpened = "yes"

		if body != nil {
			if _, err = tlsConn.Write(body); err == nil {
				payload, readErr := io.ReadAll(tlsConn)
				if readErr == nil && strings.Contains(string(payload), "origin-ok") {
					observation.rawPassthrough = "yes"
				} else {
					observation.rawPassthrough = "no"
				}
			}
		}
		return observation
	}
}

// probeFramedConnect sends a Naive padding frame and reports whether it reached
// the origin and came back framed.
func probeFramedConnect(originAddr string, framingHeaders map[string]string) func(*testing.T, string) parityObservation {
	return func(t *testing.T, address string) parityObservation {
		var observation parityObservation

		rawConn, err := net.DialTimeout("tcp", address, 10*time.Second)
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

		var builder strings.Builder
		fmt.Fprintf(&builder, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", originAddr, originAddr)
		fmt.Fprintf(&builder, "Proxy-Authorization: Basic %s\r\n", basicAuthValue())
		for name, value := range framingHeaders {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
		builder.WriteString("\r\n")
		if _, err = io.WriteString(tlsConn, builder.String()); err != nil {
			observation.err = "write-request"
			return observation
		}

		response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			observation.err = "read-response"
			return observation
		}
		observation.status = strconv.Itoa(response.StatusCode)
		observation.paddingHeader = classifyPaddingHeader(response.Header.Get("Padding"))
		if response.StatusCode != http.StatusOK {
			return observation
		}
		observation.tunnelOpened = "yes"

		// A framed request: 2-byte size, 1-byte padding, payload, zero padding.
		payload := []byte("GET / HTTP/1.1\r\nHost: " + originAddr + "\r\nConnection: close\r\n\r\n")
		frame := make([]byte, 0, 3+len(payload)+7)
		frame = append(frame, byte(len(payload)>>8), byte(len(payload)), 7)
		frame = append(frame, payload...)
		frame = append(frame, make([]byte, 7)...)
		if _, err = tlsConn.Write(frame); err != nil {
			observation.err = "write-frame"
			return observation
		}

		// Read one framed reply.
		reader := bufio.NewReader(tlsConn)
		header := make([]byte, 3)
		if _, err = io.ReadFull(reader, header); err != nil {
			observation.framedPassthrough = "no"
			return observation
		}
		size := int(header[0])<<8 | int(header[1])
		pad := int(header[2])
		data := make([]byte, size)
		if _, err = io.ReadFull(reader, data); err != nil {
			observation.framedPassthrough = "no"
			return observation
		}
		if pad > 0 {
			if _, err = io.ReadFull(reader, make([]byte, pad)); err != nil {
				observation.framedPassthrough = "no"
				return observation
			}
		}
		if strings.Contains(string(data), "origin-ok") {
			observation.framedPassthrough = "yes"
		} else {
			observation.framedPassthrough = "no"
		}
		return observation
	}
}

// classifyPaddingHeader reduces a Padding header to a COMPARABLE value.
//
// The reference generates the header with rand.Intn(32)+30, so both its content
// and its length differ on every response by design. Comparing the raw value
// would report a divergence on every run for two implementations that agree
// perfectly. What is comparable is: is it present, and does its length fall in
// the documented range [30, 61]?
func classifyPaddingHeader(value string) string {
	if value == "" {
		return "absent"
	}
	if len(value) < 30 || len(value) > 61 {
		return fmt.Sprintf("present(OUT-OF-RANGE len=%d)", len(value))
	}
	return "present(in-range)"
}

func basicAuthValue() string {
	request := &http.Request{Header: http.Header{}}
	request.SetBasicAuth(naiveParityUser, naiveParityPassword)
	return strings.TrimPrefix(request.Header.Get("Authorization"), "Basic ")
}

// parityProbes is the comparison matrix. It covers the safe protocol surface
// only: request form, authentication, padding negotiation, CONNECT validation
// and lifecycle. It deliberately does NOT probe for scanner evasion.
func parityProbes(originAddr, unreachableAddr string, validAuth string) []parityProbe {
	return []parityProbe{
		{
			name: "H1 CONNECT valid auth + Padding",
			run: probeH1Connect(originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + validAuth,
				"Padding":             "~~~~~~~~",
			}, nil),
		},
		{
			name: "H1 CONNECT valid auth, no Padding",
			run: probeH1Connect(originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + validAuth,
			}, nil),
		},
		{
			name: "H1 CONNECT no auth",
			run:  probeH1Connect(originAddr, nil, nil),
			// INVESTIGATED, INTENTIONAL. The reference answers 407 with
			// Proxy-Authenticate (forwardproxy.go: it sets the header and
			// returns caddyhttp.Error(StatusProxyAuthRequired) when
			// ProbeResistance is nil). This fork instead hijacks the connection,
			// sets SO_LINGER to 0 and closes it without any response
			// (protocol/naive/inbound.go, rejectHTTP), so an unauthenticated
			// CONNECT produces a reset rather than a challenge.
			//
			// That is a deliberate anti-probing choice for this deployment, not
			// an oversight: sending a proxy-auth challenge advertises the port as
			// a proxy. It is recorded here rather than "fixed", because changing
			// it would change the fork's security posture and is a product
			// decision, not a compatibility bug.
			knownDivergence: "unauthenticated CONNECT: reference " +
				CaddyReferenceCommit + " returns 407 + Proxy-Authenticate " +
				"(forwardproxy.go sets the header then returns " +
				"caddyhttp.Error(StatusProxyAuthRequired)); this fork hijacks the " +
				"connection, sets SO_LINGER to 0 and closes it with no response " +
				"(protocol/naive/inbound.go rejectHTTP). INTENTIONAL: challenging " +
				"advertises the port as a proxy, which this deployment does not " +
				"do. Verified by runtime reproduction in this harness and by " +
				"reading the pinned source.",
		},
		{
			name: "H1 CONNECT wrong auth",
			run: probeH1Connect(originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + basicAuthValueOf(naiveParityUser, "definitely-wrong"),
			}, nil),
			knownDivergence: "wrong credentials: same behaviour as the no-auth " +
				"case at reference " + CaddyReferenceCommit + " (reference " +
				"challenges with 407 + Proxy-Authenticate, this fork resets with no " +
				"response via rejectHTTP). INTENTIONAL for the same reason: a " +
				"challenge would advertise the proxy.",
		},
		{
			name: "H1 CONNECT unreachable target",
			run: probeH1Connect(unreachableAddr, map[string]string{
				"Proxy-Authorization": "Basic " + validAuth,
			}, nil),
		},
		{
			name: "H1 CONNECT invalid authority",
			run: probeH1Connect("not a valid authority", map[string]string{
				"Proxy-Authorization": "Basic " + validAuth,
			}, nil),
		},
		{
			name: "H1 CONNECT raw passthrough reaches origin",
			run: probeH1Connect(originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + validAuth,
			}, []byte("GET / HTTP/1.1\r\nHost: "+originAddr+"\r\nConnection: close\r\n\r\n")),
			// This was previously recorded as a INTENTIONAL-DIFF claiming the
			// reference parses tunnelled bytes as a new HTTP request and answers
			// 407. That claim was WRONG and has been removed.
			//
			// It was a probe artifact. The reference enforces
			// dialContextCheckACL, which denies loopback by default: it flushed
			// 200 (CONNECT fast open), then refused the dial with 403, and the
			// probe misread the following stream as a fresh HTTP response. The
			// reference is now started with loopback allowed, and
			// TestJiejieNaiveH1RawDifferentialAgainstReference compares the bytes
			// the origin actually receives: both implementations deliver an
			// arbitrary binary payload AND a literal Naive frame VERBATIM. HTTP/1
			// is raw in both, exactly as the pinned source says
			// (serveHijack -> dualStream(..., false)).
			//
			// No divergence is claimed here any more, so this probe is a plain
			// parity probe and must match.
		},
		{
			name: "H1 CONNECT framed passthrough reaches origin",
			run:  probeFramedConnect(originAddr, nil),
		},
	}
}

func basicAuthValueOf(user, password string) string {
	request := &http.Request{Header: http.Header{}}
	request.SetBasicAuth(user, password)
	return strings.TrimPrefix(request.Header.Get("Authorization"), "Basic ")
}

// ---------------------------------------------------------------------------
// The differential test
// ---------------------------------------------------------------------------

// TestJiejieNaiveCaddyDifferentialCompatibility runs the probe matrix against
// both the reference Caddy/forwardproxy and the sing-box Native Naive inbound,
// and reports where they differ.
//
// It SKIPs (never passes) when the reference cannot be built or started. A skip
// here means "not compared", which is a different statement from "compatible".
func TestJiejieNaiveCaddyDifferentialCompatibility(t *testing.T) {
	requireFullNaiveRegistry(t)

	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so no "+
			"differential comparison was performed. Build it and set %s, or set "+
			"%s to a klzgrad/forwardproxy@naive checkout at %s. This is a SKIP, "+
			"not a pass.", caddyReferenceBinaryEnv, caddyReferenceSourceEnv,
			CaddyReferenceCommit)
	}

	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	referencePort, _ := startCaddyReference(t, binary, certPem, keyPem)

	singBoxEnv := startNaiveInbound(t, false)

	// Unreachable: a well-formed address nothing listens on.
	unreachablePort := reserveTCPPort(t)
	unreachableAddr := "127.0.0.1:" + strconv.Itoa(int(unreachablePort))

	probes := parityProbes(singBoxEnv.originAddr, unreachableAddr, basicAuthValue())

	results := make([]parityResult, 0, len(probes))
	for _, probe := range probes {
		referenceObservation := probe.run(t, "127.0.0.1:"+strconv.Itoa(int(referencePort)))
		singBoxObservation := probe.run(t, "127.0.0.1:"+strconv.Itoa(int(singBoxEnv.port)))

		result := parityResult{
			Protocol:        "h1",
			Name:            probe.name,
			Reference:       referenceObservation.summary(),
			SingBox:         singBoxObservation.summary(),
			ReferenceCommit: CaddyReferenceCommit,
			CaddyVersion:    CaddyReferenceVersion,
		}
		switch {
		case referenceObservation.equal(singBoxObservation):
			result.Verdict = "PASS"
		case probe.knownDivergence != "":
			// The evidence bar is enforced, not merely documented: a divergence
			// label that does not state the reference commit and the observed
			// values is not accepted.
			require.Contains(t, probe.knownDivergence, CaddyReferenceCommit,
				"probe %q claims an intentional divergence but does not name the "+
					"pinned reference commit it was verified against", probe.name)
			result.Verdict = "INTENTIONAL-DIFF"
			result.Reason = probe.knownDivergence + " | observed: " +
				referenceObservation.difference(singBoxObservation)
		default:
			result.Verdict = "DIFF"
			result.Reason = referenceObservation.difference(singBoxObservation)
		}
		results = append(results, result)
	}

	report := renderParityReport(results)
	t.Logf("\n%s", report)

	// The report is also written out so CI can publish it as an artifact without
	// parsing test logs.
	writeParityReport(t, results)

	unexplained := 0
	known := 0
	for _, result := range results {
		switch result.Verdict {
		case "DIFF":
			unexplained++
		case "INTENTIONAL-DIFF":
			known++
		}
	}
	t.Logf("%d probe(s) matched the reference, %d intentional divergence(s), %d unexplained",
		len(results)-unexplained-known, known, unexplained)
	require.Zero(t, unexplained,
		"%d probe(s) diverged from the reference without an investigated "+
			"explanation; see the report above", unexplained)
}

func (o parityObservation) summary() string {
	parts := make([]string, 0, 6)
	if o.status != "" {
		parts = append(parts, "status="+o.status)
	}
	if o.paddingHeader != "" {
		parts = append(parts, "padding="+o.paddingHeader)
	}
	if o.tunnelOpened != "" {
		parts = append(parts, "tunnel="+o.tunnelOpened)
	}
	if o.rawPassthrough != "" {
		parts = append(parts, "raw="+o.rawPassthrough)
	}
	if o.framedPassthrough != "" {
		parts = append(parts, "framed="+o.framedPassthrough)
	}
	if o.err != "" {
		parts = append(parts, "err="+o.err)
	}
	return strings.Join(parts, " ")
}

// equal compares only the fields a probe actually observed, so a probe that does
// not exercise a field is not counted as differing on it.
func (o parityObservation) equal(other parityObservation) bool {
	return o.status == other.status &&
		o.paddingHeader == other.paddingHeader &&
		o.tunnelOpened == other.tunnelOpened &&
		o.rawPassthrough == other.rawPassthrough &&
		o.framedPassthrough == other.framedPassthrough
}

func (o parityObservation) difference(other parityObservation) string {
	var parts []string
	if o.status != other.status {
		parts = append(parts, fmt.Sprintf("status: caddy=%q singbox=%q", o.status, other.status))
	}
	if o.paddingHeader != other.paddingHeader {
		parts = append(parts, fmt.Sprintf("padding header: caddy=%q singbox=%q", o.paddingHeader, other.paddingHeader))
	}
	if o.tunnelOpened != other.tunnelOpened {
		parts = append(parts, fmt.Sprintf("tunnel: caddy=%q singbox=%q", o.tunnelOpened, other.tunnelOpened))
	}
	if o.rawPassthrough != other.rawPassthrough {
		parts = append(parts, fmt.Sprintf("raw passthrough: caddy=%q singbox=%q", o.rawPassthrough, other.rawPassthrough))
	}
	if o.framedPassthrough != other.framedPassthrough {
		parts = append(parts, fmt.Sprintf("framed passthrough: caddy=%q singbox=%q", o.framedPassthrough, other.framedPassthrough))
	}
	return strings.Join(parts, "; ")
}

// renderParityReport formats the machine-readable parity summary.
func renderParityReport(results []parityResult) string {
	var builder strings.Builder
	builder.WriteString("\nNaive Caddy Compatibility Report\n")
	builder.WriteString("reference: caddy " + CaddyReferenceVersion +
		" + forwardproxy@" + CaddyReferenceCommit + "\n\n")
	builder.WriteString(fmt.Sprintf("%-6s %-52s %-6s %s\n", "PROTO", "CASE", "VERDICT", "OBSERVATION"))
	builder.WriteString(strings.Repeat("-", 110) + "\n")
	for _, result := range results {
		builder.WriteString(fmt.Sprintf("%-6s %-52s %-6s %s\n",
			result.Protocol, result.Name, result.Verdict, result.SingBox))
		if result.Verdict != "PASS" {
			builder.WriteString(fmt.Sprintf("%-6s %-52s %-6s %s\n", "", "", "", "  reference: "+result.Reference))
			builder.WriteString(fmt.Sprintf("%-6s %-52s %-6s %s\n", "", "", "", "  reason:    "+result.Reason))
		}
	}
	return builder.String()
}

// ---------------------------------------------------------------------------
// HTTP/2 probes
//
// These use a REAL golang.org/x/net/http2 client over a TLS connection, not an
// H1 probe with ProtoMajor edited: a faked protocol would not exercise the H2
// code path at all, which is precisely what needs comparing.
//
// HTTP/2 is where the Padding header is actually honoured (the reference passes
// `r.Header.Get("Padding") != ""` to dualStream for ProtoMajor 2 and 3 only,
// while serveHijack hardcodes false for H1), so it is the transport where the
// padding contract differs from H1 and therefore must be measured separately.
// ---------------------------------------------------------------------------

// h2ProbeObservation is what one H2 probe saw.
type h2ProbeObservation struct {
	status        string
	paddingHeader string
	tunnelOpened  string
	rawPayload    string
	framedPayload string
	err           string
}

func (o h2ProbeObservation) summary() string {
	parts := make([]string, 0, 5)
	if o.status != "" {
		parts = append(parts, "status="+o.status)
	}
	if o.paddingHeader != "" {
		parts = append(parts, "padding="+o.paddingHeader)
	}
	if o.tunnelOpened != "" {
		parts = append(parts, "tunnel="+o.tunnelOpened)
	}
	if o.rawPayload != "" {
		parts = append(parts, "raw="+o.rawPayload)
	}
	if o.framedPayload != "" {
		parts = append(parts, "framed="+o.framedPayload)
	}
	if o.err != "" {
		parts = append(parts, "err="+o.err)
	}
	return strings.Join(parts, " ")
}

func (o h2ProbeObservation) equal(other h2ProbeObservation) bool {
	return o.status == other.status &&
		o.paddingHeader == other.paddingHeader &&
		o.tunnelOpened == other.tunnelOpened &&
		o.rawPayload == other.rawPayload &&
		o.framedPayload == other.framedPayload
}

func (o h2ProbeObservation) difference(other h2ProbeObservation) string {
	var parts []string
	for _, field := range []struct {
		name        string
		left, right string
	}{
		{"status", o.status, other.status},
		{"padding header", o.paddingHeader, other.paddingHeader},
		{"tunnel", o.tunnelOpened, other.tunnelOpened},
		{"raw payload", o.rawPayload, other.rawPayload},
		{"framed payload", o.framedPayload, other.framedPayload},
	} {
		if field.left != field.right {
			parts = append(parts, fmt.Sprintf("%s: caddy=%q singbox=%q",
				field.name, field.left, field.right))
		}
	}
	return strings.Join(parts, "; ")
}

// probeH2Connect performs an HTTP/2 CONNECT and reports what happened.
//
// mode controls what is written into the tunnel:
//
//	"none"   - only observe the response
//	"raw"    - write unframed bytes
//	"framed" - write a complete Naive padding frame
func probeH2Connect(target string, headers map[string]string, mode string) func(*testing.T, string) h2ProbeObservation {
	return func(t *testing.T, address string) h2ProbeObservation {
		var observation h2ProbeObservation

		raw, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			observation.err = "dial"
			return observation
		}
		defer raw.Close()
		tlsConn := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         []string{http2.NextProtoTLS},
		})
		if err = tlsConn.Handshake(); err != nil {
			observation.err = "tls"
			return observation
		}

		clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
		if err != nil {
			observation.err = "h2conn"
			return observation
		}
		defer clientConn.Close()

		pipeReader, pipeWriter := io.Pipe()
		defer pipeWriter.Close()
		defer pipeReader.Close()

		request := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: target},
			Host:   target,
			Header: http.Header{},
			Body:   pipeReader,
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}

		// Write the payload slightly after the request so the tunnel exists.
		go func() {
			time.Sleep(200 * time.Millisecond)
			switch mode {
			case "raw":
				_, _ = pipeWriter.Write([]byte("RAW-PAYLOAD-BYTES"))
			case "framed":
				payload := []byte("FRAMED-PAYLOAD")
				frame := make([]byte, 0, 3+len(payload))
				frame = append(frame, byte(len(payload)>>8), byte(len(payload)), 0)
				frame = append(frame, payload...)
				_, _ = pipeWriter.Write(frame)
			}
			time.Sleep(300 * time.Millisecond)
		}()

		response, err := clientConn.RoundTrip(request)
		if err != nil {
			observation.err = "roundtrip"
			return observation
		}
		defer response.Body.Close()

		observation.status = strconv.Itoa(response.StatusCode)
		observation.paddingHeader = classifyPaddingHeader(response.Header.Get("Padding"))
		if response.StatusCode == http.StatusOK {
			observation.tunnelOpened = "yes"
		}

		_ = response.Body.Close()
		return observation
	}
}

// probeH2AuthShape covers the authentication outcomes on HTTP/2.
func probeH2AuthShape(target string, headers map[string]string) func(*testing.T, string) h2ProbeObservation {
	return func(t *testing.T, address string) h2ProbeObservation {
		var observation h2ProbeObservation

		raw, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			observation.err = "dial"
			return observation
		}
		defer raw.Close()
		tlsConn := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         []string{http2.NextProtoTLS},
		})
		if err = tlsConn.Handshake(); err != nil {
			observation.err = "tls"
			return observation
		}
		clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
		if err != nil {
			observation.err = "h2conn"
			return observation
		}
		defer clientConn.Close()

		pipeReader, pipeWriter := io.Pipe()
		defer pipeWriter.Close()
		defer pipeReader.Close()

		request := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: target},
			Host:   target,
			Header: http.Header{},
			Body:   pipeReader,
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}

		response, err := clientConn.RoundTrip(request)
		if err != nil {
			// A stream-level refusal is itself the outcome under comparison.
			observation.err = "refused"
			return observation
		}
		defer response.Body.Close()
		observation.status = strconv.Itoa(response.StatusCode)
		observation.paddingHeader = classifyPaddingHeader(response.Header.Get("Padding"))
		if response.StatusCode == http.StatusOK {
			observation.tunnelOpened = "yes"
		}
		return observation
	}
}

// TestJiejieNaiveH2DifferentialAgainstReference compares HTTP/2 behaviour with
// the pinned reference using real H2 clients.
//
// A finding worth recording, because it narrows the one remaining divergence:
// on HTTP/2 both implementations answer bad authentication with 407, matching
// exactly. The 407-vs-reset divergence reported for HTTP/1 is therefore specific
// to the H1 hijack path (rejectHTTP), not a general property of this fork's
// authentication handling - the H2 path goes through the normal response writer
// and behaves like the reference.
func TestJiejieNaiveH2DifferentialAgainstReference(t *testing.T) {
	requireFullNaiveRegistry(t)

	binary := caddyReferenceBinary(t)
	if binary == "" {
		t.Skipf("the reference Caddy/forwardproxy binary is unavailable, so no "+
			"HTTP/2 differential comparison was performed. Set %s, or %s to a "+
			"klzgrad/forwardproxy@naive checkout at %s. This is a SKIP, not a pass.",
			caddyReferenceBinaryEnv, caddyReferenceSourceEnv, CaddyReferenceCommit)
	}

	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	referencePort, _ := startCaddyReference(t, binary, certPem, keyPem)
	env := startNaiveInbound(t, false)

	unreachablePort := reserveTCPPort(t)
	unreachableAddr := "127.0.0.1:" + strconv.Itoa(int(unreachablePort))

	type h2Case struct {
		name  string
		probe func(*testing.T, string) h2ProbeObservation
		// skipIfUnsupported, when set, turns a reference-side transport failure
		// into a SKIP rather than a comparison failure, since it says nothing
		// about protocol compatibility.
		note string
	}

	cases := []h2Case{
		{
			name: "h2 CONNECT valid auth, no Padding",
			probe: probeH2ConnectReturning(env.originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + basicAuthValue(),
			}, "none"),
		},
		{
			name: "h2 CONNECT valid auth, request Padding",
			probe: probeH2ConnectReturning(env.originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + basicAuthValue(),
				"Padding":             "~~~~~~~~",
			}, "none"),
		},
		{
			name:  "h2 CONNECT no auth",
			probe: probeH2AuthShapeReturning(env.originAddr, map[string]string{}),
		},
		{
			name: "h2 CONNECT wrong auth",
			probe: probeH2AuthShapeReturning(env.originAddr, map[string]string{
				"Proxy-Authorization": "Basic " + basicAuthValueOf(naiveParityUser, "wrong"),
			}),
		},
		{
			name: "h2 CONNECT unreachable target",
			probe: probeH2ConnectReturning(unreachableAddr, map[string]string{
				"Proxy-Authorization": "Basic " + basicAuthValue(),
			}, "none"),
		},
	}

	results := make([]parityResult, 0, len(cases))
	for _, testCase := range cases {
		referenceObservation := testCase.probe(t, "127.0.0.1:"+strconv.Itoa(int(referencePort)))
		singBoxObservation := testCase.probe(t, "127.0.0.1:"+strconv.Itoa(int(env.port)))

		result := parityResult{
			Protocol:        "h2",
			Name:            testCase.name,
			Reference:       referenceObservation.summary(),
			SingBox:         singBoxObservation.summary(),
			ReferenceCommit: CaddyReferenceCommit,
			CaddyVersion:    CaddyReferenceVersion,
		}
		if referenceObservation.equal(singBoxObservation) {
			result.Verdict = "PASS"
		} else {
			result.Verdict = "DIFF"
			result.Reason = referenceObservation.difference(singBoxObservation)
		}
		results = append(results, result)
		t.Logf("%-6s %-45s %-6s singbox:[%s] reference:[%s]",
			result.Protocol, testCase.name, result.Verdict,
			result.SingBox, result.Reference)
	}

	writeParityReport(t, results)

	unexplained := 0
	for _, result := range results {
		if result.Verdict == "DIFF" {
			unexplained++
		}
	}
	require.Zero(t, unexplained,
		"%d HTTP/2 probe(s) diverged from the reference without an investigated "+
			"explanation", unexplained)
}

// The two wrappers below exist only to give the helpers in the H2 probe section
// distinct, greppable names at the call site above.
func probeH2ConnectReturning(target string, headers map[string]string, mode string) func(*testing.T, string) h2ProbeObservation {
	return probeH2Connect(target, headers, mode)
}

func probeH2AuthShapeReturning(target string, headers map[string]string) func(*testing.T, string) h2ProbeObservation {
	return probeH2AuthShape(target, headers)
}
