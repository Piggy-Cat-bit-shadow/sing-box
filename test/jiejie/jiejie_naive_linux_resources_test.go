package jiejie_test

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Resource budget measurement on Linux.
//
// The target is a ~1 GiB VPS, so "does this fit" is a real production question
// and a benchmark that only reports nanoseconds cannot answer it. These tests
// measure what the process actually holds while the Naive inbound is driven:
// RSS, goroutines, file descriptors and UDP sockets.
//
// What they are NOT: a proof about the production binary. This runs the test
// binary with the production tag set, not the shipped executable, and its
// allocator behaviour is not identical. The numbers are a budget check on the
// data path, and the test says so rather than implying it measured production.
//
// Reading /proc requires Linux, so on other platforms these tests SKIP - they do
// not silently pass.

// procStatusRSS returns the process's resident set size in KiB on Linux.
func procStatusRSS(t *testing.T) (int, bool) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		value, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

// openFileDescriptors counts entries in /proc/self/fd.
func openFileDescriptors(t *testing.T) (int, bool) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

// countUDPSockets counts this process's UDP sockets via /proc/net/udp{,6}.
//
// The inode column is matched against the process's own socket inodes so that
// sockets belonging to other processes (or the rest of the system) are not
// counted. Without that filter the number would be meaningless on a shared
// runner.
func countUDPSockets(t *testing.T) (int, bool) {
	t.Helper()
	owned := make(map[string]struct{})
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	for _, entry := range entries {
		target, readErr := os.Readlink("/proc/self/fd/" + entry.Name())
		if readErr != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		owned[inode] = struct{}{}
	}

	count := 0
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // skip the header row
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// Column 9 is the inode in the /proc/net/udp layout.
			if _, isOwned := owned[fields[9]]; isOwned {
				count++
			}
		}
	}
	return count, true
}

// linuxResourceSnapshot records one measurement.
type linuxResourceSnapshot struct {
	label       string
	rssKiB      int
	goroutines  int
	fds         int
	udpSockets  int
	heapAllocMB float64
}

func takeResourceSnapshot(t *testing.T, label string) linuxResourceSnapshot {
	t.Helper()
	snapshot := linuxResourceSnapshot{label: label, goroutines: runtime.NumGoroutine()}
	if rss, ok := procStatusRSS(t); ok {
		snapshot.rssKiB = rss
	}
	if fds, ok := openFileDescriptors(t); ok {
		snapshot.fds = fds
	}
	if sockets, ok := countUDPSockets(t); ok {
		snapshot.udpSockets = sockets
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	snapshot.heapAllocMB = float64(stats.HeapAlloc) / (1024 * 1024)
	return snapshot
}

func (s linuxResourceSnapshot) log(t *testing.T) {
	t.Helper()
	t.Logf("%-28s RSS=%6d KiB (%5.1f MiB)  heap=%6.1f MiB  goroutines=%4d  fds=%4d  udpSockets=%3d",
		s.label, s.rssKiB, float64(s.rssKiB)/1024, s.heapAllocMB,
		s.goroutines, s.fds, s.udpSockets)
}

// TestJiejieNaiveLinuxResourceBudget drives the Naive inbound through a realistic
// mixed workload and reports the resource cost of each phase.
//
// The workload is deliberately modest: a 1 GiB VPS runs this for real, and a test
// that itself needs gigabytes to measure would be measuring the wrong thing. What
// matters is the DELTA between idle and loaded, and whether the process returns
// toward its baseline afterwards - a leak shows up as a rising floor rather than
// as a large instantaneous number.
func TestJiejieNaiveLinuxResourceBudget(t *testing.T) {
	if _, ok := procStatusRSS(t); !ok {
		t.Skip("this test reads /proc and therefore requires Linux; NOT a pass")
	}
	env := startNaiveInboundForUoT(t)

	// Warm up so one-time allocations are not attributed to the workload.
	for range 20 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("warm"))
	}
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	idle := takeResourceSnapshot(t, "idle")
	idle.log(t)

	// Phase 1: short-lived session churn. This is the path the loss defect lived
	// on, so its resource cost matters.
	const churn = 500
	for range churn {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("churn"))
	}
	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	afterChurn := takeResourceSnapshot(t, "after 500 churn sessions")
	afterChurn.log(t)

	// Phase 2: concurrent TCP tunnels.
	const tunnels = 8
	tunnelConns := make([]interface{ Close() error }, 0, tunnels)
	for range tunnels {
		conn := naiveTLSConn(t, env.port)
		response := naiveWriteConnectOK(t, conn, env.echoAddr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		_ = response
		tunnelConns = append(tunnelConns, conn)
	}
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	loaded := takeResourceSnapshot(t, "8 concurrent TCP tunnels")
	loaded.log(t)

	// Phase 3: sustained UDP sessions on those tunnels.
	for round := range 20 {
		for _, conn := range tunnelConns {
			writer, ok := conn.(interface{ Write([]byte) (int, error) })
			if !ok {
				continue
			}
			_, _ = writer.Write(naivePaddingFrame([]byte("sustain-"+strconv.Itoa(round)), 0))
		}
	}
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	afterUDP := takeResourceSnapshot(t, "after sustained UDP")
	afterUDP.log(t)

	for _, conn := range tunnelConns {
		_ = conn.Close()
	}
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	settled := takeResourceSnapshot(t, "settled after close")
	settled.log(t)

	// The deltas are the meaningful numbers.
	t.Logf("delta idle->loaded:      RSS=%+d KiB goroutines=%+d fds=%+d udpSockets=%+d",
		loaded.rssKiB-idle.rssKiB, loaded.goroutines-idle.goroutines,
		loaded.fds-idle.fds, loaded.udpSockets-idle.udpSockets)
	t.Logf("delta idle->after churn: RSS=%+d KiB goroutines=%+d fds=%+d udpSockets=%+d",
		afterChurn.rssKiB-idle.rssKiB, afterChurn.goroutines-idle.goroutines,
		afterChurn.fds-idle.fds, afterChurn.udpSockets-idle.udpSockets)
	t.Logf("delta idle->settled:     RSS=%+d KiB goroutines=%+d fds=%+d udpSockets=%+d",
		settled.rssKiB-idle.rssKiB, settled.goroutines-idle.goroutines,
		settled.fds-idle.fds, settled.udpSockets-idle.udpSockets)

	// 500 churn sessions must not cost 500 sockets: each session is closed, so
	// the socket count must not track the session count.
	require.Less(t, afterChurn.udpSockets-idle.udpSockets, churn/10,
		"after %d closed sessions the UDP socket count must not have grown with "+
			"the session count; that would mean sessions are not releasing sockets",
		churn)

	// Goroutines must settle back near the idle level once the tunnels close.
	// A generous bound: the test framework itself runs goroutines that come and
	// go, so the assertion is about "not proportional to the workload", not
	// about an exact count.
	require.Less(t, settled.goroutines, idle.goroutines+64,
		"goroutines must settle after the workload; idle=%d settled=%d",
		idle.goroutines, settled.goroutines)

	// 1 GiB is the production budget. The test process legitimately holds more
	// than the server would (it also holds the test framework, the echo servers
	// and every retained trace), so this is a sanity ceiling rather than a
	// production memory figure - and it is reported as such.
	const testProcessCeilingKiB = 1024 * 1024
	require.Less(t, loaded.rssKiB, testProcessCeilingKiB,
		"the test process exceeded 1 GiB of RSS while driving %d tunnels; that is "+
			"a budget failure worth investigating before a 1 GiB VPS migration, "+
			"even though this is not the production binary", tunnels)
}

// TestJiejieNaiveLinuxSocketAndGoroutineReclaim is the leak-focused counterpart:
// it drives many sessions and requires the counts to come back down, rather than
// only reporting them.
func TestJiejieNaiveLinuxSocketAndGoroutineReclaim(t *testing.T) {
	if _, ok := procStatusRSS(t); !ok {
		t.Skip("requires Linux /proc; NOT a pass")
	}
	env := startNaiveInboundForUoT(t)

	for range 10 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("warm"))
	}
	time.Sleep(300 * time.Millisecond)
	before := takeResourceSnapshot(t, "before")
	before.log(t)

	const sessions = 1000
	failures := 0
	for range sessions {
		if err := shortLivedUoTSession(env.port, env.echoAddr, []byte("reclaim")); err != nil {
			failures++
		}
	}
	t.Logf("%d/%d sessions succeeded", sessions-failures, sessions)

	// Allow the runtime and the kernel to release resources.
	deadline := time.Now().Add(5 * time.Second)
	var after linuxResourceSnapshot
	for time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(300 * time.Millisecond)
		after = takeResourceSnapshot(t, "after 1000 sessions")
		if after.fds <= before.fds+16 && after.udpSockets <= before.udpSockets+16 {
			break
		}
	}
	after.log(t)

	t.Logf("delta over %d sessions: RSS=%+d KiB goroutines=%+d fds=%+d udpSockets=%+d",
		sessions, after.rssKiB-before.rssKiB, after.goroutines-before.goroutines,
		after.fds-before.fds, after.udpSockets-before.udpSockets)

	require.LessOrEqual(t, after.fds, before.fds+16,
		"file descriptors must not grow with the number of completed sessions "+
			"(before=%d after=%d over %d sessions)", before.fds, after.fds, sessions)
	require.LessOrEqual(t, after.udpSockets, before.udpSockets+16,
		"UDP sockets must not grow with the number of completed sessions "+
			"(before=%d after=%d over %d sessions)",
		before.udpSockets, after.udpSockets, sessions)
	require.Less(t, after.goroutines, before.goroutines+64,
		"goroutines must not grow with the number of completed sessions "+
			"(before=%d after=%d over %d sessions)",
		before.goroutines, after.goroutines, sessions)
}
