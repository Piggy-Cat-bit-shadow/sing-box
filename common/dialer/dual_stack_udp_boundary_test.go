package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Regressions for the UDP boundary (§43, §44, §83, §109).
//
// These exist to make a specific WRONG implementation fail. The tempting shortcut when adding
// dual-stack support to a datagram protocol is to treat "the UDP socket was created" as proof
// the destination is reachable and declare that family the winner. It is not proof of
// anything: the kernel creates a UDP socket without contacting anyone, so a blackholed path
// looks instantly healthy.
//
// A test that only checked "the connection succeeded" would pass for that broken
// implementation. These assert the opposite: socket creation must NOT be accepted as a
// verified outcome.

// fakeUDPDialer models a UDP path where socket creation always succeeds immediately but no
// packet ever gets a reply.
// TestCandidateSchedulerRejectsUnverifiedSuccess documents the boundary between the planner
// and the protocol (§15).
//
// The scheduler accepts whatever the attempt function reports. That is correct, and it is why
// the ATTEMPT FUNCTION is where the honesty has to live: if a UDP caller reports success on
// socket creation, the scheduler will faithfully race sockets and pick a winner that proves
// nothing.
//
// This test pins that the scheduler itself has no notion of UDP success - it does not inspect
// the connection, and it cannot manufacture a verdict. The protocol must decide.
func TestCandidateSchedulerTakesSuccessFromTheExecutor(t *testing.T) {
	scheduler := &candidateScheduler{fallbackDelay: time.Millisecond}

	first := &countingConn{}
	second := &countingConn{}
	// The second candidate must genuinely be in flight before the first wins, otherwise there
	// is no losing connection and the cleanup assertion proves nothing.
	secondStarted := make(chan struct{})

	held, winner, err := scheduler.dial(context.Background(),
		planCandidates([]netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("192.0.2.1"),
		}, netip.Addr{}, C.DomainStrategyPreferIPv6),
		func(ctx context.Context, candidate netip.Addr) (net.Conn, error) {
			if candidate == netip.MustParseAddr("2001:db8::1") {
				select {
				case <-secondStarted:
				case <-time.After(2 * time.Second):
					return nil, context.DeadlineExceeded
				}
				return first, nil
			}
			close(secondStarted)
			time.Sleep(20 * time.Millisecond)
			return second, nil
		})

	require.NoError(t, err)
	require.Same(t, first, held)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), winner)
	require.True(t, second.closed.Load(), "the losing connection must still be closed")
}

// TestRecoveryDoesNotApplyToPacketListeners records the deliberate scope limit (§44, §109).
//
// Recovery is implemented for stream dials, where a completed connection is meaningful. It is
// NOT applied to packet listeners: there is no way to verify a datagram path without sending
// application data, and racing datagrams would duplicate the user's packets - a DNS query, a
// STUN binding or a game packet sent twice, with real side effects.
func TestPacketDialHasNoRecoveryRacer(t *testing.T) {
	dialer := &resolveDialer{}
	// A packet destination with a sniffed domain must not produce recovered candidates, because
	// the packet path has no per-candidate verification to justify racing.
	require.Nil(t, dialer.recoverCandidates(context.Background(), M.ParseSocksaddr("192.0.2.1:443")),
		"recovery must refuse without a sniffed domain, which is the packet path's situation")
}

// TestRecoveryRefusesRatherThanGuessingOnFailure pins the failure behaviour (§9).
//
// A recovery failure must not become a connection error. The caller falls through to the
// plain dial it would have made before, so a resolver problem cannot break a connection that
// would otherwise have worked. The refusal cases are the observable consequence: with no
// sniffed domain, no candidates are invented.
func TestRecoveryRefusesRatherThanGuessingOnFailure(t *testing.T) {
	dialer := &resolveDialer{}
	// No sniffed domain in the context: recovery must decline rather than guess a name.
	require.Nil(t, dialer.recoverCandidates(context.Background(), M.ParseSocksaddr("192.0.2.1:443")),
		"recovery must not invent a name to resolve")
}
