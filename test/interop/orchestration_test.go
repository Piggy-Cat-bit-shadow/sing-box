package interop

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Tests for the pieces of the harness that do not need a reference.
//
// These exist so the stand's own machinery is exercised everywhere, not only on
// a machine with Xray installed. A live run that fails is only diagnosable if the
// target, the camouflage server and the process orchestration are known-good
// independently: otherwise "the tunnel is broken" and "the echo endpoint never
// answered" produce the same result.

// TestLocalTargetIsAGenuineEchoEndpoint proves the destination used by every live
// round trip actually round-trips.
//
// Without this, a live failure could be the target's fault, and the whole stand
// would be measuring the wrong thing.
func TestLocalTargetIsAGenuineEchoEndpoint(t *testing.T) {
	t.Parallel()
	target, err := StartTarget()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = target.Close()
	})
	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("echo", func(t *testing.T) {
		payload := deterministicPayload(4096)
		request, err := http.NewRequest(http.MethodPost, target.URL(TargetEchoPath), bytes.NewReader(payload))
		require.NoError(t, err)
		response, err := client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.True(t, bytes.Equal(body, payload), "the echo endpoint must return the request body unchanged")
	})

	t.Run("source", func(t *testing.T) {
		response, err := client.Get(target.URL(TargetSourcePath) + "?size=1000")
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, deterministicPayload(1000), body)
	})

	t.Run("sink", func(t *testing.T) {
		response, err := client.Post(target.URL(TargetSinkPath), "application/octet-stream",
			bytes.NewReader(deterministicPayload(5000)))
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "5000", string(body))
	})

	t.Run("slow holds until the caller's deadline", func(t *testing.T) {
		// This is the property the cancel and deadline subtests depend on: /slow
		// must NOT answer on its own inside the test's window, or a deadline test
		// would pass because the server responded rather than because the caller's
		// context was honoured.
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL(TargetSlowPath),
			strings.NewReader("slow"))
		require.NoError(t, err)
		_, err = client.Do(request)
		require.Error(t, err)
		require.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)
	})
}

// TestCamouflageServerSpeaksTLSWithH2 proves the REALITY `dest` is usable.
//
// h2 is asserted explicitly because an XHTTP-over-REALITY client negotiates
// HTTP/2, and a camouflage endpoint that only offered HTTP/1.1 would make the
// stand's REALITY+XHTTP scenarios fail in a way that looks like a transport bug.
func TestCamouflageServerSpeaksTLSWithH2(t *testing.T) {
	t.Parallel()
	camouflage, err := StartCamouflage(t.TempDir(), "interop.local")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = camouflage.Close()
	})
	// The certificate is minted per run, so the chain cannot be verified; the
	// stand never relies on it and REALITY never looks at it.
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         camouflage.ServerName(),
		NextProtos:         []string{"h2", "http/1.1"},
	}}
	conn, err := dialer.DialContext(context.Background(), "tcp", camouflage.Address())
	require.NoError(t, err)
	defer conn.Close()
	tlsConn, isTLS := conn.(*tls.Conn)
	require.True(t, isTLS)
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))
	require.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol)

	// The certificate files are the ones the reference config points at, so they
	// must exist and be loadable as a pair.
	_, err = tls.LoadX509KeyPair(camouflage.CertificateFile(), camouflage.KeyFile())
	require.NoError(t, err)
}

// TestReferenceOrchestrationReportsAnExitedProcess exercises the readiness
// contract's exit branch with processes that die immediately.
//
// It stands in for the most common live failure that is NOT a protocol problem:
// the reference rejecting the generated configuration and exiting. The harness
// must report that as a readiness failure carrying the captured log, and it must
// do it promptly — if it waited for the deadline instead, every config typo would
// cost the full timeout and read as a hang.
//
// The stand-ins are tiny non-shell binaries rather than `/bin/sh` scripts on
// purpose. A shell costs roughly half a second to start on some hosts (it does on
// the macOS host this was written on, measured), and a test whose runtime is
// dominated by the stand-in's own startup would misreport the harness's exit
// detection as slow.
func TestReferenceOrchestrationReportsAnExitedProcess(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("the stand's process orchestration test uses Unix binaries")
	}

	t.Run("a clean exit is still not readiness", func(t *testing.T) {
		// `echo run -c <config>` writes the command line it was handed to stdout
		// and exits 0. Both halves matter: the log assertion proves the config path
		// really reaches the child and that its output is captured, and the exit
		// status proves a process that exits SUCCESSFULLY without binding a port is
		// not mistaken for a ready reference.
		echoBinary, err := exec.LookPath("echo")
		if err != nil {
			t.Skip("no `echo` on PATH")
		}
		reference, configPath, logPath := launchStandIn(t, echoBinary)

		started := time.Now()
		readyErr := reference.WaitReady(boundedContext(t))
		elapsed := time.Since(started)
		require.Error(t, readyErr, "a process that exited must not be reported as ready")
		require.Contains(t, readyErr.Error(), "exited before it accepted")
		require.Less(t, elapsed, 5*time.Second, "an exited process must be detected before the deadline")
		require.Contains(t, reference.LogTail(20), configPath,
			"the captured log must show the config path the reference was given")
		require.Contains(t, readyErr.Error(), "exit status 0")
		require.FileExists(t, logPath)
		exitErr, exited := reference.Exited()
		require.True(t, exited, "the process must be known to have exited")
		require.NoError(t, exitErr, "the stand-in exits cleanly")
		_, exited = reference.Exited()
		require.True(t, exited, "the exit must stay observable after a read")
	})

	t.Run("a failing exit reports its status", func(t *testing.T) {
		falseBinary, err := exec.LookPath("false")
		if err != nil {
			t.Skip("no `false` on PATH")
		}
		reference, _, _ := launchStandIn(t, falseBinary)
		readyErr := reference.WaitReady(boundedContext(t))
		require.Error(t, readyErr)
		require.Contains(t, readyErr.Error(), "exit status 1")
	})
}

// launchStandIn starts a process that will not listen and returns it with the
// paths it was configured with.
func launchStandIn(t *testing.T, binary string) (*Reference, string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server-scenario.json")
	logPath := filepath.Join(dir, "reference.log")
	reference, err := StartReference(binary, configPath, logPath, 1, false)
	require.NoError(t, err)
	t.Cleanup(reference.Stop)
	return reference, configPath, logPath
}

func boundedContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestLocateReferenceBinaryRejectsAMissingPath covers the environment half of the
// binary lookup: an XRAY_BINARY pointing at nothing must be an error, not a
// silent fall-through to whatever is on PATH.
func TestLocateReferenceBinaryRejectsAMissingPath(t *testing.T) {
	// Not parallel: it mutates the process environment.
	missing := filepath.Join(t.TempDir(), "no-such-xray")
	t.Setenv(ReferenceBinaryEnv, missing)
	_, err := LocateReferenceBinary()
	require.Error(t, err)
	require.Contains(t, err.Error(), missing)

	directory := t.TempDir()
	t.Setenv(ReferenceBinaryEnv, directory)
	_, err = LocateReferenceBinary()
	require.Error(t, err)
	require.Contains(t, err.Error(), "is a directory")
}
