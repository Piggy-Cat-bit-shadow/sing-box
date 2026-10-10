package dialer

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// TestLiteralBothFailWhileOriginalPending is §29 under the timer arm.
//
// dialLiteralWithRecovery has two arms once recovery has produced candidates:
//
//   - resolve.go:641 - the original reported before the head-start timer, so the
//     recovered candidates are dialled on their own (dialRecoveredOrReport);
//   - resolve.go:648 - the head-start timer fired first, so the recovered candidates
//     race the still-pending original (raceWithPendingOriginal).
//
// TestLiteralBothFailReturnsPromptly only reliably reaches the first arm: its original
// dial takes the same 5ms as its recovered dial and its head start is 10ms, so the
// original has almost always reported by the time the timer could fire. Which arm runs
// is therefore a coin flip pinned by machine speed, and that is why the failure
// reproduces at roughly 1% under load instead of always.
//
// This test pins the arm deterministically: recovery answers instantly, the recovered
// candidate fails in 1ms, and the original is still dialling when the head start
// expires. Both attempts still fail within milliseconds, so the dial must report an
// error at once rather than at the caller's 30s deadline.
func TestLiteralBothFailWhileOriginalPending(t *testing.T) {
	original := netip.MustParseAddr("192.0.2.1")
	recovered := netip.MustParseAddr("192.0.2.2")

	inner := &lifecycleDialer{answers: map[netip.Addr]lifecycleAnswer{
		// Still in flight when the head-start timer fires.
		original: {delay: 200 * time.Millisecond, success: false},
		// Fails long before the original does.
		recovered: {delay: 1 * time.Millisecond, success: false},
	}}
	dialer := &resolveDialer{
		router:        &lifecycleRouter{addresses: []netip.Addr{recovered}},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 2 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(sniffedContext(t, context.Background()), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(original, 443))
	elapsed := time.Since(start)

	require.Error(t, err, "both attempts failed, so the dial must report an error")
	require.Less(t, elapsed, 5*time.Second,
		"both attempts failed within milliseconds but the dial took %v; it must not wait for the "+
			"caller's 30s deadline", elapsed)
}
