package v2rayxhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// SPEC 077 for packet-up.
//
// The acceptance rule is the same one dial_ctx_contract_test.go pins for the
// streamed modes:
//
//	before DialContext returns: the dial context bounds construction
//	after  DialContext returns: the dial context must no longer govern the conn
//
// packet-up differs from stream-one/stream-up in what "construction" can be. It
// has no upload pipe to adopt — every Write is its own bounded POST — and the
// download response may legitimately not arrive until the first uplink
// (dial_deadlock_test.go, SPEC 061), so there is no network RAISE the dial can
// wait for. What it does have is a synchronous construction: take a reusable
// pooled connection from XMUX, build the download request, build the
// packetConn, start the download RoundTrip goroutine. Before this file's fix
// that construction ignored the caller's context entirely (`_ = ctx`), so a
// caller that cancelled before the dial returned still received a conn.

// packetUpClient builds a packet-up client around a caller-supplied pool, so a
// test can control exactly when the pool opens its connection.
func packetUpClient(t *testing.T, manager *xmuxManager) *Client {
	t.Helper()
	meta, err := normalizeMeta(metaOptions{}, modePacketUp)
	if err != nil {
		t.Fatalf("normalizeMeta: %v", err)
	}
	return &Client{
		ctx:          context.Background(),
		serverAddr:   M.ParseSocksaddr("127.0.0.1:443"),
		xmux:         manager,
		scheme:       "http",
		host:         "example.com",
		path:         "/xhttp/",
		mode:         modePacketUp,
		headers:      make(http.Header),
		paddingRange: intRange{0, 0},
		meta:         meta,
	}
}

// TestPacketUpDialPreCancelledContextFailsDial is the case the brief names: an
// XMUX connection is already reusable, the caller cancels before the dial
// returns, and the download response has not arrived. DialContext must return
// the context error, not a conn, and the pooled slot must come back exactly
// once — hence the loop: a leak leaves openUsage above zero, a double release
// leaves it below.
//
// Red on the pre-fix base: getContext serves the reusable connection without
// consulting the context, dialPacketUp ignored ctx outright, and DialContext
// returned (conn, nil) to a caller that had already given up.
func TestPacketUpDialPreCancelledContextFailsDial(t *testing.T) {
	t.Parallel()

	client := packetUpClient(t, singleTransportXmux(&hangRoundTripper{}))
	// Warm the pool so the dial takes the already-reusable branch, where
	// getContext has nothing to wait on and therefore cannot observe the cancel
	// by itself.
	warm, _ := client.xmux.get()
	warm.addOpenUsage(1)
	warm.addOpenUsage(-1)

	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := expectDialFailure(t, dialUnderTest(ctx, client), "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext error = %v, want context.Canceled", err)
		}
	}
	if got := openUsageOf(client); got != 0 {
		t.Fatalf("openUsage = %d after three cancelled dials, want exactly 0 (slot leaked or double-released)", got)
	}
}

// TestPacketUpDialCancelDuringConstructionFailsDial makes the cancel land
// INSIDE DialContext — the literal "immediately after entering" case — without
// racing the scheduler: the pool's connection factory runs synchronously in
// getContext and cancels the dial context there. The guard in dialPacketUp
// still runs afterwards and must fail the dial.
func TestPacketUpDialCancelDuringConstructionFailsDial(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := newXmuxManager(xmuxConfig{}, func() xmuxConn {
		cancel()
		return &fixedXmuxConn{transport: &hangRoundTripper{}}
	})
	client := packetUpClient(t, manager)

	err := expectDialFailure(t, dialUnderTest(ctx, client), "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext error = %v, want context.Canceled", err)
	}
	if got := openUsageOf(client); got != 0 {
		t.Fatalf("openUsage = %d after a cancelled dial, want exactly 0 (slot leaked or double-released)", got)
	}
}

// TestPacketUpCancelAfterReturnKeepsConnAlive pins the other half of SPEC 077:
// once DialContext has returned, cancelling the dial context is routine
// lifecycle (net.Dialer callers do it in a defer, the DNS transport pool does it
// immediately), and it must not govern the conn. The server here withholds the
// download response until the first uplink, so the test also proves the conn
// survives the cancel while the download is still unraised — and that the first
// Write afterwards raises it.
func TestPacketUpCancelAfterReturnKeepsConnAlive(t *testing.T) {
	t.Parallel()

	server := newXrayLikeServer(t)
	client := h2cClient(t, server.addr, modePacketUp)

	ctx, cancel := context.WithCancel(context.Background())
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// The dial is over. The download response has not arrived and will not until
	// the first uplink leaves the pipe.
	cancel()

	if _, err := conn.Write([]byte("uplink")); err != nil {
		t.Fatalf("Write after the dial context was cancelled: %v", err)
	}
	deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		t.Fatal("packet-up conn does not support SetReadDeadline")
	}
	deadlineConn.SetReadDeadline(time.Now().Add(writeFreeBudget))
	downlink := make([]byte, len("downlink"))
	if _, err := io.ReadFull(conn, downlink); err != nil {
		t.Fatalf("Read after the dial context was cancelled: %v", err)
	}
	if string(downlink) != "downlink" {
		t.Fatalf("Read %q, want %q", downlink, "downlink")
	}
	// Still usable: a second POST after the cancel must drain too.
	if _, err := conn.Write([]byte("uplink again")); err != nil {
		t.Fatalf("second Write after the dial context was cancelled: %v", err)
	}
}
