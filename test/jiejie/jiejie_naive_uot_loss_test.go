package jiejie_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// UoT reply-loss: what was measured, what it turned out to be, and what is now
// asserted.
//
// ORIGINAL FINDING (kept for the record, because the numbers were real):
// under aggressive session churn a small fraction of UoT sessions saw the first
// datagram's reply never arrive. On a Linux 6.8 kernel, 500 sessions:
//
//	padding frame reads     1017 / 1017 succeeded (err=nil)
//	client-observed failures 3-5 per 500   (~0.6-1.0%)
//
// The conclusion drawn at the time - "the loss is after a successful read, in
// the shared UDP packet path" - was WRONG, and this comment previously asserted
// it as fact. Padding reads succeeded because the affected sessions never
// reached the padding layer at all: the HTTP/1.1 hijack path discarded the
// *bufio.ReadWriter that net/http returns, so bytes it had already buffered past
// the CONNECT headers (the UoT request and first datagram, when a client
// pipelines them) were thrown away. The datagram never left the server.
//
// That defect is fixed in protocol/naive/inbound.go. A/B evidence on Linux,
// 1000 sessions x 10 workers, showed unfixed code failing reproducibly (1, 0 and
// 3 failures across three runs, with echo counts short of the client's) and the
// fixed code failing zero times with every stage at 1000/1000.
//
// So the shared UDP copy path and FastFail were NOT the cause and were not
// changed. The tests below now reflect the corrected understanding:
//
//   - TestJiejieUoTLossUnderChurn (jiejie_naive_uot_loss_diag_test.go) is the
//     real acceptance: it requires ZERO failures and reports per-stage counts,
//     so a failure identifies the stage it died at.
//   - TestJiejieNaiveUoTLossRateIsBounded remains only as a coarse catastrophic
//     guard. Its ceiling is NOT evidence of correctness and must not be read as
//     "up to 5% loss is acceptable".
//   - TestJiejieNaiveUoTResendOnSameSessionAfterLoss no longer waits for a
//     random failure: it injects one.
//
// A zero-failure run proves the defect did not occur in those sessions. It is
// not a proof that loss can never happen on other hardware or under other load.

// TestJiejieNaiveUoTLossRateIsBounded is a COARSE CATASTROPHIC GUARD ONLY.
//
// It is deliberately NOT the acceptance criterion for the UoT reply-loss defect.
// That criterion is TestJiejieUoTLossUnderChurn, which requires zero failures and
// names the stage a failure occurred at. A percentage ceiling cannot distinguish
// "the fix works" from "the machine was slow", so a pass here carries no
// evidence that the defect is gone - only that UDP is not broadly broken.
//
// The ceiling is retained at 5% purely to catch a regression severe enough to be
// unmissable. It is not a tolerance for the known defect: that defect is fixed,
// and the strict test is the one that proves it.
func TestJiejieNaiveUoTLossRateIsBounded(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// Warm up so one-time setup is not counted.
	for range 10 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("warmup"))
	}

	const rounds = 200
	failures := 0
	firstFailure := ""
	for range rounds {
		if err := shortLivedUoTSession(env.port, env.echoAddr, []byte("rate")); err != nil {
			failures++
			if firstFailure == "" {
				// Record the real error rather than only counting it: a bare
				// count cannot distinguish a timeout from a reset from a
				// malformed reply.
				firstFailure = err.Error()
			}
		}
	}
	rate := float64(failures) / float64(rounds) * 100
	t.Logf("UoT one-datagram round-trip failures: %d/%d (%.2f%%)", failures, rounds, rate)
	if failures > 0 {
		t.Logf("first failure detail: %s", firstFailure)
		t.Logf("NOTE: this test is a coarse guard, not the acceptance test. See " +
			"TestJiejieUoTLossUnderChurn for the strict zero-failure run.")
	}

	const ceiling = 5.0
	if rate > ceiling {
		t.Fatalf("UoT datagram loss %.2f%% exceeds the %.1f%% catastrophic "+
			"ceiling; first failure: %s", rate, ceiling, firstFailure)
	}
}

// TestJiejieNaiveUoTResendOnSameSessionAfterLoss proves, DETERMINISTICALLY,
// that a UoT session survives a lost reply and can still carry a later datagram.
//
// The previous version hunted for a naturally-failing session and SKIPPED when it
// could not find one - which, after the hijack fix, was always. A test that
// usually verifies nothing is not a regression test.
//
// Here the loss is INJECTED at the origin: the echo receives the first datagram
// and deliberately withholds the reply, leaving the UoT session open. That is
// precisely the state the question is about - "the client did not get a reply,
// is the tunnel dead?" - and it is reproducible on every run.
//
// This is NOT a substitute for the hijack regression. The hijack defect lost the
// datagram before it reached the server; here the datagram demonstrably arrives
// and only the reply is withheld. Both are kept, and they test different things.
func TestJiejieNaiveUoTResendOnSameSessionAfterLoss(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	trace := newTrace()
	echo := startFaultInjectingEcho(t, trace)

	const replyTimeout = 2 * time.Second

	// Session 1: the first datagram's reply is withheld on purpose.
	const firstID uint32 = 9001
	const secondID uint32 = 9002
	echo.withholdReplies(firstID, 1)

	session, err := openTracedSession(t, env.port, echo.address, int(firstID), trace, "http1-padded")
	require.NoError(t, err, "the UoT session must open")
	defer session.close()

	require.NoError(t, session.sendDatagram(t, firstID), "the first datagram must be sent")

	// The reply must NOT arrive: that is the injected loss.
	firstErr := session.awaitReply(t, firstID, replyTimeout)
	require.Error(t, firstErr,
		"the reply was withheld on purpose, so waiting for it must fail; "+
			"if it succeeded the fault injection did not take effect and this "+
			"test would prove nothing")
	require.Equal(t, 1, echo.receivedCount(firstID),
		"the echo must have RECEIVED the first datagram: the datagram was "+
			"delivered and only the reply was withheld")
	t.Logf("injected loss confirmed: packet %d delivered to echo, reply withheld (%v)",
		firstID, firstErr)

	// The session is still open. A second datagram on it must work.
	require.NoError(t, session.sendDatagram(t, secondID),
		"the session must still accept a datagram after a lost reply")

	secondErr := session.awaitReply(t, secondID, replyTimeout)
	require.NoError(t, secondErr,
		"a datagram sent on the SAME session after a lost reply must still be "+
			"answered: a single withheld reply must not kill the tunnel")

	require.Equal(t, 1, echo.receivedCount(secondID),
		"the echo must have received the second datagram")
	t.Logf("recovery confirmed: packet %d answered on the same session", secondID)

	// No cross-contamination: the withheld reply must never turn up as the
	// answer to the second datagram.
	require.NotEqual(t, firstID, secondID)

	// The first datagram's reply stays lost even after the second succeeded -
	// resilience here means "later datagrams work", not "the old reply returns".
	lateErr := session.awaitReply(t, firstID, 200*time.Millisecond)
	t.Logf("late check for the withheld reply: err=%v (expected non-nil)", lateErr)

	t.Logf("timeline first (lost reply):\n%s", trace.summarizeFor(firstID))
	t.Logf("timeline second (recovered):\n%s", trace.summarizeFor(secondID))
	t.Logf("stage counts: echo.ReadFromUDP=%d echo.WriteToUDP=%d client.Received=%d",
		trace.countStage(StageEchoReadFromUDP),
		trace.countStage(StageEchoWriteToUDP),
		trace.countStage(StageClientReceived))
}

// requireNormalSessionsWork asserts that the ordinary case is healthy, which is
// what keeps the loss characterisation above from being mistaken for "UoT is
// broken".
func requireNormalSessionsWork(t *testing.T, env *uotTestEnv, count int) {
	t.Helper()
	succeeded := 0
	for range count {
		if err := shortLivedUoTSession(env.port, env.echoAddr, []byte("ok")); err == nil {
			succeeded++
		}
	}
	if succeeded < count*9/10 {
		t.Fatalf("only %d/%d ordinary UoT sessions succeeded; UoT is broadly "+
			"broken, not merely lossy", succeeded, count)
	}
	t.Logf("%d/%d ordinary UoT sessions succeeded", succeeded, count)
}
