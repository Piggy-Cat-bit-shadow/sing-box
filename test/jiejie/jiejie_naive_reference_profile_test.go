package jiejie_test

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Reference profiles for the Caddy differential.
//
// The reference is not one thing. There are two deployments worth comparing
// against, and conflating them produces exactly the kind of unearned PASS that a
// differential exists to prevent:
//
//   - The BARE profile runs forward_proxy with nothing else. It is the control
//     for raw protocol behaviour: CONNECT, credentials, the 407 challenge, the
//     Padding header, framing, dial failure.
//
//   - The OFFICIAL profile runs forward_proxy with probe_resistance enabled
//     behind a real web handler, which is the deployment the project documents.
//     Its observable behaviour is completely different for anything
//     unauthenticated: instead of a 407 it serves the web backend or passes the
//     request through, because a challenge would advertise the port as a proxy.
//
// A probe that expects a 407 passes on the bare profile and fails on the
// official one. A probe that expects a web response does the reverse. So each
// observation records which profile produced it, and the report refuses to
// compare across profiles.
type referenceProfile int

const (
	// referenceProfileBare is forward_proxy with no probe resistance.
	referenceProfileBare referenceProfile = iota
	// referenceProfileOfficial is forward_proxy with probe_resistance plus a
	// real web handler behind it.
	referenceProfileOfficial
)

func (p referenceProfile) String() string {
	switch p {
	case referenceProfileBare:
		return "bare"
	case referenceProfileOfficial:
		return "official"
	default:
		return "unknown"
	}
}

// referenceInstance is one running reference server.
type referenceInstance struct {
	// profile records which deployment this is, so a mixed report is impossible.
	profile referenceProfile
	// port is the Naive proxy front door.
	port uint16
	// webPort is the web backend the official profile fronts. Zero for bare.
	webPort uint16
	// probeDomain is the secret hostname the official profile answers with its
	// hidden page. Empty for bare.
	probeDomain string
}

// referenceProbeDomain is the secret domain the official profile treats as the
// proxy. It is a TEST-NET-adjacent documentation name, never a real host: the
// reference only compares it as a string against the request host, so it never
// needs to resolve.
const referenceProbeDomain = "probe.invalid"

// startReferenceProfile starts the pinned reference in the requested profile.
//
// The bare profile delegates to startCaddyReference so its configuration is
// byte-for-byte the one the existing differential already validated against; this
// function adds the official deployment rather than replacing anything.
func startReferenceProfile(t *testing.T, binary, certPem, keyPem string, profile referenceProfile) *referenceInstance {
	t.Helper()
	switch profile {
	case referenceProfileBare:
		port, _ := startCaddyReference(t, binary, certPem, keyPem)
		return &referenceInstance{profile: referenceProfileBare, port: port}
	case referenceProfileOfficial:
		return startOfficialNaiveDeployment(t, binary, certPem, keyPem)
	default:
		t.Fatalf("unknown reference profile %d", profile)
		return nil
	}
}

// startOfficialNaiveDeployment starts the reference the way the project documents
// it: forward_proxy with probe_resistance, plus a real web handler that serves
// everything else.
//
// The configuration mirrors the Caddyfile shape from the upstream documentation,
// expressed as JSON because that is Caddy's native format:
//
//	example.com {
//	    route {
//	        forward_proxy {
//	            basic_auth user pass
//	            probe_resistance secret.localhost
//	        }
//	        file_server
//	    }
//	}
//
// `probe_resistance <domain>` is the field that changes the unauthenticated
// behaviour: with it set, an unauthorised CONNECT that does NOT name the secret
// domain is passed to the next handler instead of being challenged, and one that
// DOES name it receives a hidden page carrying the challenge.
func startOfficialNaiveDeployment(t *testing.T, binary, certPem, keyPem string) *referenceInstance {
	t.Helper()
	port := reserveTCPPort(t)
	redirectPort := reserveTCPPort(t)
	webPort := startReferenceWebBackend(t)

	// Same base64-of-base64 encoding the bare profile uses; see the long comment
	// in startCaddyReference for why the extra layer is required.
	caddyAuthCredential := base64.StdEncoding.EncodeToString([]byte(basicAuthValue()))

	// The web backend is reached through Caddy's reverse_proxy rather than
	// file_server so the test can count requests per path. A file_server would
	// only prove a file exists on disk.
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
							"probe_resistance": {"domain": %q},
							"acl": [{"subjects": ["127.0.0.1/32", "::1/128"], "allow": true}]
						}, {
							"handler": "reverse_proxy",
							"upstreams": [{"dial": "127.0.0.1:%d"}]
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
}`, redirectPort, port, port, caddyAuthCredential, referenceProbeDomain, webPort, certPem, keyPem)

	configPath := filepath.Join(t.TempDir(), "caddy-official.json")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	command := exec.Command(binary, "run", "--config", configPath)
	command.Stdout = discardWriter{}
	var stderr strings.Builder
	command.Stderr = &stderr
	require.NoError(t, command.Start())

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
		t.Skipf("the official reference deployment did not start on %d; stderr:\n%s",
			port, tailLines(stderr.String(), 20))
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	if stderr.Len() > 0 {
		t.Logf("reference stderr: %s", tailLines(stderr.String(), 15))
	}
	return &referenceInstance{
		profile:     referenceProfileOfficial,
		port:        port,
		webPort:     webPort,
		probeDomain: referenceProbeDomain,
	}
}

// discardWriter absorbs the reference's stdout without importing io into a file
// that otherwise does not need it.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// startReferenceWebBackend starts a counting web backend for the official
// profile and returns its port.
//
// It serves a tiny page with sub-resources, which is what the preamble E2E needs:
// a browser loading the decoy fetches the document and then its css/js/image, and
// every one of those requests must reach the backend rather than the proxy.
func startReferenceWebBackend(t *testing.T) uint16 {
	t.Helper()
	backend := newReferenceWebBackend()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server := newReferenceWebServer(backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	t.Logf("reference web backend on 127.0.0.1:%d", port)
	return port
}
