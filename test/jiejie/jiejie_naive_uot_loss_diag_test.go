package jiejie_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Diagnostic runs that locate the intermittent UoT datagram loss by RECORDING
// every hop, instead of inferring the location from the padding layer alone.
//
// Design notes that matter:
//
//   - Each session uses a UNIQUE Packet ID, so a reply can be attributed to the
//     datagram that caused it. The previous harness used a constant payload, so a
//     late reply to datagram N could be mistaken for the reply to N+1.
//   - HTTP/1.1 padded, HTTP/1.1 unpadded and HTTP/2 padded are measured
//     SEPARATELY. The earlier loss was observed only through the HTTP/1.1 helper,
//     so attributing it to the HTTP/2 wrapper was never justified.
//   - Every stage the task lists is recorded, including the outbound UDP write
//     and the echo's own write result, which the previous echo discarded.

// lossRunResult summarizes one measurement run.
type lossRunResult struct {
	transport   string
	sessions    int
	failures    int
	failureLogs []string
	trace       *Trace
}

func (r lossRunResult) report(t *testing.T) {
	t.Helper()
	t.Logf("=== %s: %d sessions, %d failures ===", r.transport, r.sessions, r.failures)
	for _, line := range r.failureLogs {
		t.Log(line)
	}
	if r.trace != nil {
		t.Logf("stage counts: uot.ReadPacket=%d router.UDPWrite=%d echo.ReadFromUDP=%d "+
			"echo.WriteToUDP=%d outbound.UDPRead=%d uot.WritePacket=%d client.Received=%d",
			r.trace.countStage(StageUoTReadPacket),
			r.trace.countStage(StageRouterUDPWrite),
			r.trace.countStage(StageEchoReadFromUDP),
			r.trace.countStage(StageEchoWriteToUDP),
			r.trace.countStage(StageOutboundUDPRead),
			r.trace.countStage(StageUoTWritePacket),
			r.trace.countStage(StageClientReceived))
	}
}

// runUoTLossMeasure performs N one-datagram sessions and records every hop.
func runUoTLossMeasure(t *testing.T, transport string, sessions int) lossRunResult {
	t.Helper()
	env := startNaiveInboundForUoT(t)
	trace := newTrace()
	echo := startInstrumentedEcho(t, trace)

	result := lossRunResult{transport: transport, sessions: sessions, trace: trace}
	const replyTimeout = 3 * time.Second

	for index := range sessions {
		packetID := uint32(index + 1)
		session, err := openTracedSession(t, env.port, echo.address, index, trace, transport)
		if err != nil {
			result.failures++
			result.failureLogs = append(result.failureLogs,
				fmt.Sprintf("session %d: open failed: %v", index, err))
			continue
		}

		if err = session.sendDatagram(t, packetID); err != nil {
			result.failures++
			result.failureLogs = append(result.failureLogs,
				fmt.Sprintf("session %d packet %d: send failed: %v", index, packetID, err))
			session.close()
			continue
		}

		if err = session.awaitReply(t, packetID, replyTimeout); err != nil {
			result.failures++
			result.failureLogs = append(result.failureLogs,
				fmt.Sprintf("session %d packet %d FAILED: %v\n%s",
					index, packetID, err, trace.summarizeFor(packetID)))
		}
		session.close()
	}
	return result
}

// TestDiagUoTLossByTransport measures the three transports separately.
//
// This is a DIAGNOSTIC: it reports the real failure counts and the event
// timeline for every failed Packet ID. It asserts only that the transports do not
// collapse entirely, so a partial loss does not turn the suite red while the
// investigation is open.
func TestDiagUoTLossByTransport(t *testing.T) {
	const perTransport = 200

	for _, transport := range []string{"http1-padded", "http1-unpadded", "http2-padded"} {
		t.Run(transport, func(t *testing.T) {
			result := runUoTLossMeasure(t, transport, perTransport)
			result.report(t)

			// A collapse would mean the harness itself is broken; that must fail.
			successes := result.sessions - result.failures
			if successes == 0 {
				t.Fatalf("%s: every session failed, which means the harness is "+
					"broken rather than a partial loss being measured", transport)
			}
		})
	}
}

// TestDiagUoTLossUnderChurn reproduces the ORIGINAL conditions: many sessions
// created back to back with concurrency, which is when the earlier ~1% loss was
// observed. Sequential single sessions did not reproduce it, so the load shape
// matters and must be measured rather than assumed away.
func TestDiagUoTLossUnderChurn(t *testing.T) {
	const (
		totalWorkers = 10
		perWorker    = 200 // 2000 sessions, above the required 1000
	)
	env := startNaiveInboundForUoT(t)
	trace := newTrace()
	echo := startInstrumentedEcho(t, trace)

	var (
		mu       sync.Mutex
		failures []string
		packetID uint32
		wg       sync.WaitGroup
	)
	nextID := func() uint32 {
		mu.Lock()
		defer mu.Unlock()
		packetID++
		return packetID
	}

	for range totalWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				id := nextID()
				session, err := openTracedSession(t, env.port, echo.address, int(id), trace, "http1-padded")
				if err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("packet %d: open failed: %v", id, err))
					mu.Unlock()
					continue
				}
				if err = session.sendDatagram(t, id); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("packet %d: send failed: %v", id, err))
					mu.Unlock()
					session.close()
					continue
				}
				if err = session.awaitReply(t, id, 3*time.Second); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("packet %d FAILED: %v\n%s",
						id, err, trace.summarizeFor(id)))
					mu.Unlock()
				}
				session.close()
			}
		}()
	}
	wg.Wait()

	total := totalWorkers * perWorker
	t.Logf("=== churn: %d sessions with %d concurrent workers, %d failures ===",
		total, totalWorkers, len(failures))
	for _, line := range failures {
		t.Log(line)
	}
	t.Logf("stage counts: echo.ReadFromUDP=%d echo.WriteToUDP=%d client.Received=%d",
		trace.countStage(StageEchoReadFromUDP),
		trace.countStage(StageEchoWriteToUDP),
		trace.countStage(StageClientReceived))

	// STRICT acceptance. The root cause is fixed and proven, so this now asserts
	// zero loss instead of reporting a tolerance. A single failure means the
	// regression is back.
	require.Empty(t, failures,
		"no datagram may be lost under churn: %d of %d sessions failed, which means "+
			"the hijack buffered-reader regression is back or a new cause was "+
			"introduced", len(failures), total)
}
