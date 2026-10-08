package interop

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Orchestration for the reference binary.
//
// The reference is a real child process started from a generated configuration
// file. Two properties follow, and both are the point:
//
//  1. Nothing here stubs the reference. The stand cannot pass without a real
//     binary on the other end, which is exactly the property the fork's unit
//     tests lack.
//  2. The reference is observed the way it is deployed: configuration parsed
//     from JSON, listeners bound from that file, output captured to a file. A
//     test that set an internal field instead would be testing the harness.

// ReferenceBinaryEnv names the environment variable that points at the reference
// binary. It is documented rather than discovered silently, so a run without a
// binary reports "not run" instead of testing whatever `xray` happens to be
// first on PATH.
const ReferenceBinaryEnv = "XRAY_BINARY"

// ReferenceReadyMarker is the substring the reference prints once its listeners
// are bound. It is used as the readiness signal ONLY for a QUIC scenario, where
// a TCP connect cannot observe the listener: for everything else readiness is an
// accepted TCP connection, which is the thing the client actually needs.
const ReferenceReadyMarker = "started"

// referenceStopGrace is how long the reference is given to exit after SIGINT
// before it is killed. Xray drains in-flight connections on SIGINT; killing
// earlier would truncate exactly the log a failing test needs.
const referenceStopGrace = 5 * time.Second

// Reference is a running reference process.
type Reference struct {
	binary     string
	configPath string
	logPath    string
	port       uint16
	udp        bool

	command *exec.Cmd
	logFile *os.File

	waitOnce sync.Once
	waitCh   chan referenceExit

	stopOnce sync.Once
}

// LocateReferenceBinary resolves the reference binary.
//
// XRAY_BINARY wins over PATH. That order matters for a maintainer who has more
// than one Xray build installed — most obviously the classical/hybrid key_share
// split, which needs an OLD binary for one scenario and a NEW one for another —
// and who therefore cannot be served by "whatever is first on PATH".
func LocateReferenceBinary() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(ReferenceBinaryEnv)); configured != "" {
		if info, err := os.Stat(configured); err != nil {
			return "", E.Cause(err, ReferenceBinaryEnv, "=", configured)
		} else if info.IsDir() {
			return "", E.New(ReferenceBinaryEnv, "=", configured, " is a directory")
		}
		return configured, nil
	}
	located, err := exec.LookPath("xray")
	if err != nil {
		return "", E.Cause(ErrNoReferenceBinary,
			ReferenceBinaryEnv, " is not set and `xray` is not on PATH")
	}
	return located, nil
}

// ErrNoReferenceBinary reports that no reference binary could be found. The live
// harness turns this into a SKIP: a machine without a reference binary has not
// demonstrated anything, but it has not found a bug either.
var ErrNoReferenceBinary = E.New("no reference binary")

// StartReference launches the reference against an already-generated server
// config and arranges for its output to be captured.
//
// Readiness is NOT awaited here. The caller decides whether to wait on a TCP
// connect, a log marker, or an actual proxied request, because those are three
// different questions and only the last one is "the reference is usable".
func StartReference(binary string, configPath string, logPath string, port uint16, udp bool) (*Reference, error) {
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, E.Cause(err, "create reference log")
	}
	command := exec.Command(binary, "run", "-c", configPath)
	// One file for both streams: the reference interleaves its listener banner
	// (stdout) with its per-connection and error lines (stderr), and splitting
	// them would reorder exactly the sequence a wire-mismatch diagnosis needs.
	command.Stdout = logFile
	command.Stderr = logFile
	if err = command.Start(); err != nil {
		_ = logFile.Close()
		return nil, E.Cause(err, "start reference process ", binary)
	}
	reference := &Reference{
		binary:     binary,
		configPath: configPath,
		logPath:    logPath,
		port:       port,
		udp:        udp,
		command:    command,
		logFile:    logFile,
		waitCh:     make(chan referenceExit, 1),
	}
	go func() {
		reference.waitCh <- referenceExit{err: command.Wait()}
	}()
	return reference, nil
}

// WaitReady blocks until the reference is accepting connections on its listen
// port, the process exits, or the context expires.
//
// The two transports need two different signals and pretending otherwise would
// be a lie:
//
//   - TCP: an accepted connection. That is literally what the client will do
//     next, so it is the strongest signal available without speaking the
//     protocol.
//   - QUIC: the reference's own "started" line. A UDP listener cannot be probed
//     by "connecting" to it in any way a caller can trust, and sending a probe
//     datagram would inject a spurious session into the log. The definitive
//     readiness for QUIC is the first real proxied request, which the client
//     readiness probe performs.
func (r *Reference) WaitReady(ctx context.Context) error {
	if r.udp {
		return r.waitReadyLog(ctx)
	}
	return r.waitReadyTCP(ctx)
}

func (r *Reference) waitReadyTCP(ctx context.Context) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.port)))
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		// The exit is checked BEFORE the select, not only as a select case. With
		// both a tick and an exit ready, Go chooses uniformly, so a dead process
		// would be detected on average one dial late — and each dial costs the
		// full per-attempt timeout. Polling first makes the common "the reference
		// rejected its config" case immediate instead of a partial hang.
		if exit, exited := r.pollExit(); exited {
			return E.New("reference exited before it accepted a connection on ", address, ": ",
				describeExit(exit.err), r.deadlineDetail())
		}
		select {
		case <-ctx.Done():
			detail := ""
			if lastErr != nil {
				detail = " (last dial error: " + lastErr.Error() + ")"
			}
			return E.Cause(ctx.Err(), "reference did not accept a TCP connection on ", address,
				" within the deadline", detail, r.deadlineDetail())
		case exit := <-r.waitCh:
			r.waitCh <- exit
			return E.New("reference exited before it accepted a connection on ", address, ": ",
				describeExit(exit.err), r.deadlineDetail())
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
			lastErr = err
		}
	}
}

func (r *Reference) waitReadyLog(ctx context.Context) error {
	deadlineDetail := func() string { return r.deadlineDetail() }
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if exit, exited := r.pollExit(); exited {
			return E.New("reference exited before it reported readiness: ", describeExit(exit.err),
				deadlineDetail())
		}
		select {
		case <-ctx.Done():
			return E.Cause(ctx.Err(), "reference did not report readiness (`", ReferenceReadyMarker,
				"` in its log) within the deadline", deadlineDetail())
		case exit := <-r.waitCh:
			r.waitCh <- exit
			return E.New("reference exited before it reported readiness: ", describeExit(exit.err),
				deadlineDetail())
		case <-ticker.C:
			if strings.Contains(strings.ToLower(r.readLog()), ReferenceReadyMarker) {
				return nil
			}
		}
	}
}

// Stop terminates the reference, waiting for a clean exit and killing it only
// when the grace period expires.
//
// It is safe to call more than once, because the test harness registers it as a
// cleanup AND calls it explicitly on the failure path to get its log into the
// failure message; a second SIGINT to a recycled pid would be a genuinely bad
// outcome.
func (r *Reference) Stop() {
	r.stopOnce.Do(func() {
		if r.command.Process != nil {
			_ = r.command.Process.Signal(os.Interrupt)
		}
		select {
		case exit := <-r.waitCh:
			// Push the observed value back rather than a fresh zero one: the buffer
			// has a single slot, and replacing it would lose the exit status that
			// the failure message may still want to report.
			r.waitCh <- exit
		case <-time.After(referenceStopGrace):
			if r.command.Process != nil {
				_ = r.command.Process.Kill()
			}
			<-r.waitCh
		}
		if r.logFile != nil {
			_ = r.logFile.Close()
		}
	})
}

// LogPath is where the reference's stdout and stderr were captured.
func (r *Reference) LogPath() string {
	return r.logPath
}

// LogTail returns the last lines of the reference log, for embedding in a
// failure message. When an operator reads a failing live run, this is the only
// place the reference's view of the connection is recorded; a report that says
// "dial timeout" without it is not actionable.
func (r *Reference) LogTail(maxLines int) string {
	content := r.readLog()
	if content == "" {
		return "(the reference produced no output)"
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}

// referenceVersionCache memoizes `version` per binary path.
//
// The live suite has one test per scenario and they all need the version; running
// the subprocess ten times would add a visible, pointless cost to a suite that is
// already gated on a human having installed a reference.
var referenceVersionCache sync.Map

// ReferenceVersion asks a reference binary for its version, caching the answer.
func ReferenceVersion(binary string) string {
	if cached, loaded := referenceVersionCache.Load(binary); loaded {
		return cached.(string)
	}
	version := ""
	output, err := exec.Command(binary, "version").CombinedOutput()
	if err == nil {
		version = parseReferenceVersion(string(output))
	}
	referenceVersionCache.Store(binary, version)
	return version
}

// RealityKeyShareSupport reports whether a reference of the given version accepts
// the key_share policy, and the reason it does not when that is the case.
//
// An UNKNOWN version is treated as "supported": failing to parse a version is
// the harness's problem (or a reference build that changed its banner), and
// silently skipping a scenario because of it would hide a real regression. The
// skip is reserved for a version we positively identified as incompatible.
func RealityKeyShareSupport(version string, keyShare string) (bool, string) {
	if version == "" {
		return true, ""
	}
	switch keyShare {
	case RealityKeyShareClassical:
		if compareVersions(version, "26.9.8") >= 0 {
			return false, "REALITY key_share=classical is only accepted by a reference below v26.9.8 " +
				"(this reference is v" + version + "; v26.9.8 made the X25519MLKEM768 hybrid share mandatory)"
		}
	case RealityKeyShareHybrid:
		if compareVersions(version, "26.9.8") < 0 {
			return false, "REALITY key_share=hybrid requires a reference at or above v26.9.8 " +
				"(this reference is v" + version + ")"
		}
	}
	return true, ""
}

// Exited reports the process's exit status and whether it has exited at all.
//
// The two results are not redundant: a reference can exit with status 0, and a
// bare `error` would then be indistinguishable from "still running". That
// distinction is the whole reason readiness must not be inferred from the
// process having gone away quietly.
func (r *Reference) Exited() (error, bool) {
	exit, exited := r.pollExit()
	return exit.err, exited
}

// referenceExit is the buffered exit notification. It is a struct rather than a
// bare error so that a clean exit (nil error) still reads as "exited" at the
// receive site instead of looking like an empty channel.
type referenceExit struct {
	err error
}

// pollExit reports whether the process has exited, leaving the single buffered
// slot readable by the next caller.
//
// The channel has room for exactly one value and every reader pushes it back, so
// the exit status stays observable for the whole run without a second, mutable
// field that the waiter goroutine could be writing while a reader looks at it.
func (r *Reference) pollExit() (referenceExit, bool) {
	select {
	case exit := <-r.waitCh:
		r.waitCh <- exit
		return exit, true
	default:
		return referenceExit{}, false
	}
}

func (r *Reference) readLog() string {
	content, err := os.ReadFile(r.logPath)
	if err != nil {
		return ""
	}
	return string(content)
}

func (r *Reference) deadlineDetail() string {
	tail := r.LogTail(20)
	if tail == "" {
		return ""
	}
	return "\n--- reference log tail (" + filepath.Base(r.logPath) + ") ---\n" + tail
}

func describeExit(err error) string {
	if err == nil {
		return "exit status 0"
	}
	return err.Error()
}

// parseReferenceVersion extracts the version token from the reference's own
// `version` output, which reads `Xray 25.8.3 (go1.24.0 linux/amd64)`.
func parseReferenceVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i, field := range fields {
			if strings.EqualFold(field, "xray") && i+1 < len(fields) {
				token := strings.TrimSpace(fields[i+1])
				if token != "" && token[0] >= '0' && token[0] <= '9' {
					return token
				}
			}
		}
	}
	// Fall back to the first dotted-numeric token anywhere in the output, so a
	// future banner that drops the product name does not silently disable the
	// version gate.
	for _, field := range strings.Fields(output) {
		if isVersionToken(field) {
			return field
		}
	}
	return ""
}

func isVersionToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return false
	}
	for _, part := range parts[:3] {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

// compareVersions compares two dotted numeric versions.
//
// Only the first three components are considered, which is enough for the
// classical/hybrid split (v26.9.8) and avoids depending on a SemVer library for
// a comparison the stand makes exactly twice.
func compareVersions(left string, right string) int {
	leftParts := versionParts(left)
	rightParts := versionParts(right)
	for i := 0; i < 3; i++ {
		switch {
		case leftParts[i] < rightParts[i]:
			return -1
		case leftParts[i] > rightParts[i]:
			return 1
		}
	}
	return 0
}

func versionParts(version string) [3]int {
	var parts [3]int
	for i, field := range strings.Split(version, ".") {
		if i >= 3 {
			break
		}
		value, err := strconv.Atoi(strings.TrimFunc(field, func(r rune) bool {
			return r < '0' || r > '9'
		}))
		if err != nil {
			continue
		}
		parts[i] = value
	}
	return parts
}
