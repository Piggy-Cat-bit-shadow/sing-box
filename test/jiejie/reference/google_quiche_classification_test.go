package reference_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Classification tests for the QUICHE client runner.
//
// # Why these do not need Google QUICHE
//
// The classification answers a question about the RUNNER, not about QUICHE: given a
// process that started, exited or was killed, does the harness report the right outcome?
// Fake executables answer that exactly, and they let every branch be covered - including
// the ones a real QUICHE binary rarely produces on demand, such as a deadline kill.
//
// Rebuilding QUICHE to test the branches would make the suite slow and would still not
// produce a timeout on request. The real binary is exercised by the interop tests
// themselves; these cover the classification those tests depend on.
//
// # The distinction being protected
//
// These outcomes are NOT interchangeable and the runner must not collapse them:
//
//	NOT-RUN            nothing executed, so nothing was demonstrated
//	EXECUTED-FAILED    it ran and disagreed - a real observed failure
//	INCONCLUSIVE       it ran and was killed at the deadline - no evidence either way
//
// The previous implementation inferred a timeout from "non-zero error AND empty output",
// which cannot tell a killed process apart from a process that ran and printed nothing,
// and which reads an implementation failure into a harness deadline.

// writeFakeQuiche writes a fake masque_client that behaves as described.
//
// The script is a real executable with a real exit status, so the runner sees exactly what
// it would see from QUICHE: a process, an exit code, and stdout/stderr.
func writeFakeQuiche(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "masque_client")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return path
}

// TestQuicheOutcomeClassification covers each outcome with a fake process.
func TestQuicheOutcomeClassification(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		script          string
		timeout         time.Duration
		wantOutcome     quicheOutcome
		wantStarted     bool
		wantTimedOut    bool
		wantExitCode    int
		wantOutputSubst string
	}{
		{
			name:            "exit 0 with output",
			script:          `echo "JIEJIE-QUICHE-LIVE-OK"; exit 0`,
			timeout:         10 * time.Second,
			wantOutcome:     executedSucceeded,
			wantStarted:     true,
			wantExitCode:    0,
			wantOutputSubst: "JIEJIE-QUICHE-LIVE-OK",
		},
		{
			name:            "exit 0 without output",
			script:          `exit 0`,
			timeout:         10 * time.Second,
			wantOutcome:     executedSucceeded,
			wantStarted:     true,
			wantExitCode:    0,
			wantOutputSubst: "",
		},
		{
			name:            "non-zero exit WITH output",
			script:          `echo "E masque_client.cc:143 Failed to connect. Error: QUIC_CONNECTION_CANCELLED" >&2; exit 1`,
			timeout:         10 * time.Second,
			wantOutcome:     executedFailed,
			wantStarted:     true,
			wantExitCode:    1,
			wantOutputSubst: "QUIC_CONNECTION_CANCELLED",
		},
		{
			name:            "non-zero exit WITHOUT output",
			script:          `exit 3`,
			timeout:         10 * time.Second,
			wantOutcome:     executedFailed,
			wantStarted:     true,
			wantExitCode:    3,
			wantOutputSubst: "",
		},
		{
			// The case the old implementation got wrong: a process that is still running
			// when the deadline passes must be reported as a TIMEOUT, not as a failure,
			// even though the command also returns an error.
			// `exec sleep` REPLACES the shell with sleep, so the process the runner
			// kills IS the one holding the output pipe. A plain `sleep 30` leaves the
			// shell as a child that keeps the pipe open, and CombinedOutput then waits
			// for the full 30s even though the deadline already fired - measured at
			// 30.2s before this was changed.
			name:         "deadline exceeded",
			script:       `exec sleep 30`,
			timeout:      1 * time.Second,
			wantOutcome:  inconclusiveTimeout,
			wantStarted:  true,
			wantTimedOut: true,
			// A process killed by a signal has no normal exit status.
			wantExitCode: -1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := writeFakeQuiche(t, testCase.script)
			client := &quicheClient{path: path}

			run := runQuicheClient(t, client, testCase.timeout, "--fake-flag")

			require.Equal(t, testCase.wantOutcome, run.classify(),
				"outcome must be %s; run described as %s", testCase.wantOutcome, run.describe())

			require.Equal(t, testCase.wantStarted, run.started,
				"started must reflect whether the process was actually launched")
			require.Equal(t, testCase.wantTimedOut, run.timedOut,
				"timedOut must be read from the deadline, not inferred from empty output")
			if testCase.wantStarted && !testCase.wantTimedOut {
				require.Equal(t, testCase.wantExitCode, run.exitCode,
					"exit code must be captured for a process that exited normally")
			}
			if testCase.wantTimedOut {
				require.Equal(t, -1, run.exitCode,
					"a process killed at the deadline has no normal exit status, and "+
						"reporting one would be inventing a result")
			}
			if testCase.wantOutputSubst != "" {
				require.Contains(t, run.output, testCase.wantOutputSubst)
			}
		})
	}
}

// TestQuicheTimeoutIsNotReportedAsFailure is the specific regression guard.
//
// A killed process reports an error, so a runner that only checked `err != nil` would
// classify a harness deadline as an implementation failure. That is the misreport this
// test prevents, and it is checked separately from the table above so the intent is
// explicit rather than one row among many.
func TestQuicheTimeoutIsNotReportedAsFailure(t *testing.T) {
	path := writeFakeQuiche(t, `exec sleep 30`)
	client := &quicheClient{path: path}

	run := runQuicheClient(t, client, 1*time.Second)

	require.Error(t, run.err,
		"precondition: a killed process does report an error, which is why the "+
			"classification cannot rely on the error alone")
	require.NotEqual(t, executedFailed, run.classify(),
		"a process killed at the deadline must NOT be classified as EXECUTED-FAILED: "+
			"that would blame an implementation for a harness deadline")
	require.Equal(t, inconclusiveTimeout, run.classify())
	require.True(t, run.timedOut,
		"the deadline must be recorded explicitly rather than inferred from output")
}

// TestQuicheStartFailureIsNotATimeout proves a launch failure is distinguished.
//
// A missing or non-executable binary produces an error with no process behind it. Reporting
// that as a timeout would send a reader looking for a network problem when the binary was
// simply absent.
func TestQuicheStartFailureIsNotATimeout(t *testing.T) {
	client := &quicheClient{path: filepath.Join(t.TempDir(), "definitely-not-here")}

	run := runQuicheClient(t, client, 5*time.Second)

	require.False(t, run.started,
		"a binary that could not be launched must not be reported as started")
	require.False(t, run.timedOut,
		"a launch failure is not a timeout")
	require.Equal(t, notRunStartFailed, run.classify())
	require.NotEqual(t, inconclusiveTimeout, run.classify())
	require.NotEqual(t, executedFailed, run.classify())
}

// TestQuicheClassifyOrdering pins the precedence directly, without a process.
//
// The ordering is the whole correctness argument: timeout beats exit code, and "never
// started" beats both. Testing it on the struct keeps that argument checkable even if the
// process-level fixtures change.
func TestQuicheClassifyOrdering(t *testing.T) {
	require.Equal(t, notRunStartFailed, quicheRun{started: false}.classify(),
		"not started wins over everything")
	require.Equal(t, notRunStartFailed,
		quicheRun{started: false, timedOut: true, err: os.ErrNotExist}.classify(),
		"not started wins even when a timeout was also recorded")

	require.Equal(t, inconclusiveTimeout,
		quicheRun{started: true, timedOut: true, err: os.ErrDeadlineExceeded}.classify(),
		"a timeout wins over the exit error, because a killed process reports one")

	require.Equal(t, executedFailed,
		quicheRun{started: true, err: os.ErrInvalid}.classify(),
		"a started process with an error is a real observed failure")

	require.Equal(t, executedSucceeded,
		quicheRun{started: true}.classify(),
		"a started process with no error succeeded")
}

// TestQuicheOutcomeStringsAreDistinct guards the summary vocabulary.
//
// The workflow and the documentation quote these strings, so a silent change to them would
// make a report describe an outcome that no longer exists in the code.
func TestQuicheOutcomeStringsAreDistinct(t *testing.T) {
	outcomes := []quicheOutcome{
		notRunBinaryMissing, notRunStartFailed, executedFailed,
		inconclusiveTimeout, executedSucceeded,
	}
	seen := make(map[quicheOutcome]bool, len(outcomes))
	for _, outcome := range outcomes {
		require.NotEmpty(t, string(outcome))
		require.False(t, seen[outcome],
			"outcome %q is used twice, so two different results would be indistinguishable",
			outcome)
		seen[outcome] = true
	}

	// The vocabulary must actually distinguish not-run / failed / inconclusive.
	require.NotEqual(t, notRunBinaryMissing, executedFailed,
		"not-run and executed-failed must not share a label")
	require.NotEqual(t, executedFailed, inconclusiveTimeout,
		"executed-failed and inconclusive must not share a label")
	require.Contains(t, string(inconclusiveTimeout), "INCONCLUSIVE")
	require.Contains(t, string(notRunBinaryMissing), "NOT-RUN")
	require.Contains(t, string(executedFailed), "FAILED")
}

// TestQuicheCommandRedactionStillApplies proves the classification change did not disturb
// the redaction, which is checked here because the runner was rewritten.
func TestQuicheCommandRedactionStillApplies(t *testing.T) {
	path := writeFakeQuiche(t, `exit 0`)
	client := &quicheClient{path: path}

	run := runQuicheClient(t, client, 10*time.Second,
		quicheProxyHeaders("Proxy-Authorization", basicProxyAuthorization()))

	require.Contains(t, run.command, "Proxy-Authorization:<redacted>",
		"the recorded command must keep the header name and hide the value")
	require.NotContains(t, run.command, basicProxyAuthorization(),
		"the recorded command must not contain the credential value")
	require.False(t, strings.Contains(run.command, "c2VrYWk6cGFzc3dvcmQ="),
		"the recorded command must not contain the base64 credential")
}
