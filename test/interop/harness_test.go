package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/stretchr/testify/require"
)

// Test-side wiring for the stand.
//
// Everything in this file needs *testing.T, so it lives in a _test.go file. The
// reusable half of the harness (the generator, the process orchestration, the
// target, the box lifecycle and the gate) is in non-test files, which is what
// lets the `gen` command and the default validation tests share exactly the same
// generator the live tests use. A stand whose generator differs between the
// validation path and the live path would validate nothing.

// KeepArtifactsEnv makes the harness write its generated configs and both sides'
// logs into a directory that survives the test.
//
// It is off by default because t.TempDir is the right home for a passing run; it
// exists because the entire point of this stand is diagnosing a wire mismatch,
// and a mismatch is diagnosed by reading the two config files and the two logs
// side by side, not by reading a Go stack trace.
const KeepArtifactsEnv = "INTEROP_KEEP_ARTIFACTS"

// artifacts owns the directory a scenario's files are written into.
type artifacts struct {
	t    *testing.T
	dir  string
	kept bool
}

// newArtifacts prepares the artifact directory, keeping it only when asked.
func newArtifacts(t *testing.T, scenarioName string) *artifacts {
	t.Helper()
	created := &artifacts{t: t}
	if os.Getenv(KeepArtifactsEnv) == "1" {
		dir, err := os.MkdirTemp("", "sing-box-interop-"+sanitizeName(scenarioName)+"-")
		require.NoError(t, err, "create a kept artifact directory")
		created.dir = dir
		created.kept = true
		t.Logf("%s=1: interop artifacts will be kept at %s", KeepArtifactsEnv, dir)
	} else {
		created.dir = t.TempDir()
	}
	// Registered AFTER t.TempDir(), so this cleanup runs BEFORE the temporary
	// directory is removed (cleanups are LIFO). A dump registered earlier would
	// read an empty directory and report a misleading "no artifacts".
	t.Cleanup(created.reportOnFailure)
	return created
}

// reportOnFailure writes the artifact paths — and the tail of every captured log
// — into the test log when the test failed.
//
// The log tails go into the test output rather than being left on disk because a
// CI runner's artifact upload is a separate step that a maintainer may not have,
// while the test output is what they are already looking at. The paths are
// printed unconditionally on failure so the SAME information can be opened
// again after the run when the directory was kept.
func (a *artifacts) reportOnFailure() {
	if !a.t.Failed() && !a.kept {
		return
	}
	a.t.Logf("interop artifacts in %s", a.dir)
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		a.t.Logf("interop artifacts could not be listed: %v", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(a.dir, entry.Name())
		a.t.Logf("  artifact: %s", path)
		if !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			a.t.Logf("    (could not read: %v)", readErr)
			continue
		}
		a.t.Logf("    %s", indentLogTail(string(content), 40))
	}
}

// path joins a file name onto the artifact directory.
func (a *artifacts) path(name string) string {
	return filepath.Join(a.dir, name)
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, name)
}

func indentLogTail(content string, maxLines int) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	for index, line := range lines {
		lines[index] = "    | " + line
	}
	return strings.Join(lines, "\n")
}

// requireLiveInterop enforces the whole gate and returns the reference binary.
//
// The order matters: the build-tag/environment gate is checked first because it
// is the one a maintainer controls, then the build's capability, then the binary,
// so the FIRST thing reported is the first thing they would have to fix. Every
// failure here is a SKIP: none of these conditions is evidence about the
// protocol, and a test that failed on them would train a maintainer to ignore
// interop failures.
func requireLiveInterop(t *testing.T, scenario Scenario) string {
	t.Helper()
	if reason := LiveInteropSkipReason(); reason != "" {
		t.Skip(reason)
	}
	if reason := LiveInteropCapabilityReason(scenario); reason != "" {
		t.Skip(reason)
	}
	// A defect in this build's option layer is checked before the reference is
	// even located: the xhttp scenarios cannot construct their client from a
	// config file until option/v2ray_transport.go learns the transport, and a skip
	// that names that file is more useful than a failure inside box.New. See
	// optionlayer.go.
	if scenario.Transport == TransportXHTTP {
		if reason := XHTTPOptionLayerSkipReason(); reason != "" {
			t.Skip(reason)
		}
	}
	binary, err := LocateReferenceBinary()
	if err != nil {
		t.Skipf("reference interop cannot run: %v\nSet %s=/path/to/xray and re-run:\n  %s",
			err, ReferenceBinaryEnv, LiveInteropEnableCommand)
	}
	return binary
}

// stand is one live scenario: the two local servers, the reference process, the
// box client, and the generated pair tying them together.
type stand struct {
	scenario   Scenario
	binary     string
	artifacts  *artifacts
	target     *Target
	camouflage *Camouflage
	reference  *Reference
	client     *BoxClient
	pair       Pair
	serverName string
}

// newStand builds the local servers, mints the keys and writes the two config
// files. Nothing is started until start() is called, so a generation failure is
// reported before any process exists to clean up.
func newStand(t *testing.T, scenario Scenario, binary string, version string, encryption EncryptionKeyMaterial) *stand {
	t.Helper()
	created := &stand{
		scenario:   scenario,
		binary:     binary,
		artifacts:  newArtifacts(t, scenario.Name),
		serverName: "interop.local",
	}

	if scenario.EncryptionEnabled() && !encryption.LiveUsable() {
		// A live stand handed synthetic key material would start a reference that
		// cannot decrypt anything, and the resulting failure would read as a
		// protocol bug. The provider already refuses to fabricate a live pair; this
		// makes the refusal impossible to bypass by passing one in.
		t.Fatalf("scenario %s: a live run was handed %s key material; it must use a pair the reference owns",
			scenario.Name, encryption.Source)
	}

	target, err := StartTarget()
	require.NoError(t, err, "start the local echo/HTTP target")
	t.Cleanup(func() {
		_ = target.Close()
	})
	created.target = target

	// The camouflage server doubles as the certificate source for the plain-TLS
	// (H3) scenario. Starting it unconditionally keeps one code path for both
	// security modes; it costs one loopback listener.
	camouflage, err := StartCamouflage(created.artifacts.dir, created.serverName)
	require.NoError(t, err, "start the REALITY camouflage server")
	t.Cleanup(func() {
		_ = camouflage.Close()
	})
	created.camouflage = camouflage

	serverPort := reservePort(t, scenario.H3)
	clientPort := reserveTCPPort(t)

	realityPublicKey, realityPrivateKey, err := GenerateRealityKeyPair()
	require.NoError(t, err, "generate a REALITY key pair")

	userUUID, err := uuid.NewV4()
	require.NoError(t, err, "generate the VLESS uuid")

	pair, err := Input{
		Scenario:          scenario,
		ArtifactDir:       created.artifacts.dir,
		ServerAddress:     "127.0.0.1",
		ServerPort:        serverPort,
		ClientAddress:     "127.0.0.1",
		ClientPort:        clientPort,
		TargetAddress:     "127.0.0.1",
		TargetPort:        target.Port(),
		ServerName:        created.serverName,
		CamouflageAddress: camouflage.Address(),
		RealityPublicKey:  realityPublicKey,
		RealityPrivateKey: realityPrivateKey,
		ShortID:           GenerateShortID(),
		UUID:              userUUID.String(),
		Encryption:        encryption,
		TLSCertFile:       camouflage.CertificateFile(),
		TLSKeyFile:        camouflage.KeyFile(),
		ClientLogPath:     created.artifacts.path("box-client.log"),
		ServerLogPath:     created.artifacts.path("xray-server.log"),
	}.Generate()
	require.NoError(t, err, "generate the interop configuration pair")
	created.pair = pair

	created.client = NewBoxClient(pair.ClientConfig, pair.ClientConfigPath, "127.0.0.1", clientPort)
	t.Logf("scenario %s: reference v%s, client config %s, server config %s",
		scenario.Name, versionOrUnknown(version), pair.ClientConfigPath, pair.ServerConfigPath)
	return created
}

// start launches the reference, waits for it to accept, then launches the box and
// waits for an actual proxied request to succeed.
//
// Two waits rather than one, because they answer different questions: the
// reference wait catches "the generated Xray config was rejected", which is a
// harness bug with a precise log line, and the client wait catches "the tunnel
// does not work", which is the bug the stand exists to find. Collapsing them
// would make a bad config look like a protocol failure.
func (s *stand) start(t *testing.T) {
	t.Helper()
	reference, err := StartReference(s.binary, s.pair.ServerConfigPath, s.pair.ServerLogPath,
		s.pair.ServerPort, s.pair.ServerUDP)
	if err != nil {
		t.Fatalf("start the reference: %v", err)
	}
	s.reference = reference
	t.Cleanup(reference.Stop)

	referenceReady, cancelReference := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelReference()
	if err = reference.WaitReady(referenceReady); err != nil {
		s.fatalf(t, "the reference never became ready: %v", err)
	}

	if err = s.client.Start(); err != nil {
		s.fatalf(t, "start the box client: %v", err)
	}
	t.Cleanup(func() {
		_ = s.client.Stop()
	})

	clientReady, cancelClient := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelClient()
	if err = s.client.WaitReady(clientReady, s.target.URL(TargetHelloPath)); err != nil {
		s.fatalf(t, "the box client never became usable: %v", err)
	}
}

// fatalf reports a failure with everything needed to diagnose it: the reference's
// own log, the client's log path, and the artifact directory.
func (s *stand) fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	message := fmt.Sprintf(format, args...)
	if s.reference != nil {
		message += "\n--- reference log (" + s.reference.LogPath() + ") tail ---\n" +
			s.reference.LogTail(40)
		if exitErr, exited := s.reference.Exited(); exited {
			message += "\n--- reference exited: " + describeExit(exitErr)
		}
	}
	message += "\n--- artifacts: " + s.artifacts.dir
	t.Fatalf("%s", message)
}

// assertRoundTrip writes payload through the tunnel and requires the exact bytes
// back.
//
// Byte equality is the assertion, not "no error". A transport that negotiates
// perfectly and then re-frames, truncates or reorders the payload is precisely
// the class of bug a suite of mocks cannot see, and it is the class this stand
// exists to catch.
func (s *stand) assertRoundTrip(t *testing.T, ctx context.Context, payload []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.target.URL(TargetEchoPath),
		bytes.NewReader(payload))
	if err != nil {
		s.fatalf(t, "build the echo request: %v", err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := s.client.HTTPClient().Do(request)
	if err != nil {
		s.fatalf(t, "proxied round trip failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTargetBody+1))
	if err != nil {
		s.fatalf(t, "read the echoed body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		s.fatalf(t, "the target answered HTTP %d: %s", response.StatusCode, summarizeBody(body))
	}
	if !bytes.Equal(body, payload) {
		s.fatalf(t, "the proxied round trip corrupted the payload: sent %s, received %s",
			summarizeBody(payload), summarizeBody(body))
	}
}

// assertSlowRequestFails makes one request to the never-answering endpoint and
// requires it to end with the caller's own context error.
//
// The elapsed bound is what makes the assertion about the tunnel rather than
// about the target: a request that fails instantly has not exercised the
// cancellation path at all, and a request that ignores the context would show up
// as the caller hanging until the test's own timeout.
func (s *stand) assertSlowRequestFails(t *testing.T, ctx context.Context, expected error, minimum time.Duration) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.target.URL(TargetSlowPath),
		strings.NewReader("slow"))
	if err != nil {
		s.fatalf(t, "build the slow request: %v", err)
	}
	started := time.Now()
	response, err := s.client.HTTPClient().Do(request)
	elapsed := time.Since(started)
	if err == nil {
		_ = response.Body.Close()
		s.fatalf(t, "a request to the never-answering endpoint succeeded")
	}
	if !errors.Is(err, expected) {
		s.fatalf(t, "the slow request ended with %v, want %v", err, expected)
	}
	if elapsed < minimum {
		s.fatalf(t, "the slow request ended after %s, before the %s bound could apply; "+
			"it failed on the way in rather than on the caller's context", elapsed, minimum)
	}
}

// runSubtests is the behaviour matrix every scenario is put through.
//
// The five behaviours are the ones that separate a transport that works from one
// that works once: several sequential connections (a fresh TCP connection each
// time), several concurrent connections (a shared real connection), a cancel and
// a deadline (the caller's context reaching all the way through the tunnel), and
// a stop/start of the client (the reference's view of a session that was torn
// down underneath it).
func (s *stand) runSubtests(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for index := 0; index < 5; index++ {
			s.assertRoundTrip(t, ctx, deterministicPayload(256+index*137))
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		const connections = 8
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		payloads := make([][]byte, connections)
		for index := range payloads {
			payloads[index] = deterministicPayload(1024 + index*97)
		}
		var (
			waitGroup sync.WaitGroup
			failures  = make([]error, connections)
		)
		for index := 0; index < connections; index++ {
			waitGroup.Add(1)
			go func(index int) {
				defer waitGroup.Done()
				request, err := http.NewRequestWithContext(ctx, http.MethodPost,
					s.target.URL(TargetEchoPath), bytes.NewReader(payloads[index]))
				if err != nil {
					failures[index] = err
					return
				}
				response, err := s.client.HTTPClient().Do(request)
				if err != nil {
					failures[index] = err
					return
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, maxTargetBody+1))
				if err != nil {
					failures[index] = err
					return
				}
				if !bytes.Equal(body, payloads[index]) {
					failures[index] = fmt.Errorf("connection %d: sent %s, received %s",
						index, summarizeBody(payloads[index]), summarizeBody(body))
				}
			}(index)
		}
		waitGroup.Wait()
		for index, failure := range failures {
			if failure != nil {
				s.fatalf(t, "concurrent connection %d failed: %v", index, failure)
			}
		}
	})

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel()
		}()
		defer cancel()
		s.assertSlowRequestFails(t, ctx, context.Canceled, 250*time.Millisecond)
	})

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		s.assertSlowRequestFails(t, ctx, context.DeadlineExceeded, 600*time.Millisecond)
	})

	t.Run("restart", func(t *testing.T) {
		if err := s.client.Stop(); err != nil {
			s.fatalf(t, "stop the box client: %v", err)
		}
		if err := s.client.Start(); err != nil {
			s.fatalf(t, "restart the box client: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.client.WaitReady(ctx, s.target.URL(TargetHelloPath)); err != nil {
			s.fatalf(t, "the box client was not usable after a restart: %v", err)
		}
		s.assertRoundTrip(t, ctx, deterministicPayload(4096))
	})
}

func versionOrUnknown(version string) string {
	if version == "" {
		return "unknown"
	}
	return version
}

// reserveTCPPort asks the kernel for a free loopback TCP port.
func reserveTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve a TCP port")
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// reserveUDPPort asks the kernel for a free loopback UDP port.
func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err, "reserve a UDP port")
	defer listener.Close()
	return uint16(listener.LocalAddr().(*net.UDPAddr).Port)
}

// reservePort reserves the port the reference will bind: UDP for an H3 scenario
// (the QUIC listener) and TCP otherwise.
//
// The port is reserved by binding and closing, which leaves a window a competing
// process could take. That window is acceptable here and is the repo's existing
// convention (test/jiejie_helpers_test.go); the alternative — passing the
// listener to the reference — is not something an out-of-process binary can
// accept.
func reservePort(t *testing.T, udp bool) uint16 {
	t.Helper()
	if udp {
		return reserveUDPPort(t)
	}
	return reserveTCPPort(t)
}
