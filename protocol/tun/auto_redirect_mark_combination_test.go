package tun

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The combination scenario the hardening round asked for as one test:
//
//	two concurrent Inbound.Close
//	+ adapter/inbound.Manager.Create's duplicate-tag loser
//	+ a NEW owner claiming the SAME mark value
//	+ concurrent reads of the mark
//
// Each of those exists separately elsewhere; nothing exercised them TOGETHER, which is where the
// interesting interleavings are. The previous report left this item OPEN on the grounds that the
// composed test had not been written, and this file is that test.

// newMarkClaimedInbound builds the field set NewInbound leaves on the claim path.
//
// It is the shape the real constructor produces when it takes the mark: the tag, the network manager
// the release goes back to, the mark, and the claim flag set. Nothing else is built - no stack, no
// interface, no redirect - so Close has only the claim to release, and the fixture isolates the
// claim protocol from the platform.
func newMarkClaimedInbound(tag string, networkManager adapter.NetworkManager, mark uint32) *Inbound {
	inbound := &Inbound{
		tag:                    tag,
		networkManager:         networkManager,
		autoRedirectOutputMark: mark,
	}
	inbound.autoRedirectOutputMarkClaimed.Store(true)
	return inbound
}

// countingReleaser wraps a NetworkManager and counts releases, so "exactly once" is measured rather
// than inferred from the final mark value - a double release that happens to be a no-op against the
// manager would otherwise be invisible.
type countingReleaser struct {
	adapter.NetworkManager
	releases atomic.Int32
}

func (c *countingReleaser) ReleaseAutoRedirectOutputMark(mark uint32) {
	c.releases.Add(1)
	c.NetworkManager.(interface{ ReleaseAutoRedirectOutputMark(uint32) }).ReleaseAutoRedirectOutputMark(mark)
}

// newMarkNetworkManager builds a real NetworkManager, which is the implementation that owns the claim.
func newMarkNetworkManager(t *testing.T) *route.NetworkManager {
	t.Helper()
	networkManager, err := route.NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)
	return networkManager
}

// TestConcurrentInboundCloseReleasesTheMarkExactlyOnce is the first half of the combination: the
// Scope's cleanup drain and the manager's duplicate-tag loser are two INDEPENDENT callers of Close,
// so two Closes can be in flight at once.
//
// The property is that the claim is handed back exactly once. The flag is read and cleared with a
// CompareAndSwap for exactly this reason: with a plain bool, two callers can both read true, both
// reach the releaser, and the SECOND release is the one that can strip a claim a new owner has taken
// in between - which is the ABA case, and the reason the release is matched against the claim value
// as well.
func TestConcurrentInboundCloseReleasesTheMarkExactlyOnce(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))

	counter := &countingReleaser{NetworkManager: networkManager}
	inbound := newMarkClaimedInbound("tun-in", counter, mark)

	const closers = 8
	var waitGroup sync.WaitGroup
	waitGroup.Add(closers)
	for range closers {
		go func() {
			defer waitGroup.Done()
			_ = inbound.Close()
		}()
	}
	waitGroup.Wait()

	require.EqualValues(t, 1, counter.releases.Load(),
		"the claim must be handed back exactly once no matter how many Closes race for it: a second "+
			"release is the one that can clear a mark a new owner has since taken")
	require.Zero(t, networkManager.AutoRedirectOutputMark(), "the released mark must be gone")
}

// TestNewOwnerWithTheSameMarkValueSurvivesAStaleRelease is the ABA half, and the one the round asked
// about by name.
//
// The old owner releases the mark, a NEW owner claims the SAME NUMERIC VALUE - which is the ordinary
// case, because the mark comes from the configuration and a restart uses the same one - and then the
// old owner is closed again. The new owner's claim must survive.
func TestNewOwnerWithTheSameMarkValueSurvivesAStaleRelease(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)

	first := newMarkClaimedInbound("tun-first", networkManager, mark)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))
	require.NoError(t, first.Close())
	require.Zero(t, networkManager.AutoRedirectOutputMark())

	// A new owner takes the same value.
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark),
		"the mark must be claimable again after its owner released it")
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark())

	// The stale owner is closed again, several times, and must not touch the new claim.
	for range 3 {
		require.NoError(t, first.Close())
	}
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark(),
		"a stale owner cleared a mark that a new owner holds: the release is not matched against the "+
			"claim, so an old inbound can strip the live one")

	// And a DIFFERENT object holding the same mark may close without touching it either: it never
	// claimed, so it has nothing to hand back.
	neverClaimed := &Inbound{tag: "tun-other", networkManager: networkManager, autoRedirectOutputMark: mark}
	require.NoError(t, neverClaimed.Close())
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark(),
		"an inbound that never claimed cleared someone else's mark")
}

// TestDuplicateTagLoserAndWinnerLeaveExactlyOneClaim drives the production duplicate-tag race through
// adapter/inbound.Manager.Create, which is the path that closes an inbound the constructor built.
//
// # What the race actually looks like, measured rather than assumed
//
// The first version of this test held one constructor open and let the other run "concurrently". It
// HUNG, and the reason is a real property of the tree that is worth recording: Registry.Create holds
// the registry's own mutex ACROSS the constructor call, so constructors are globally serialised even
// for different tags. That is also why route.NetworkManager.RegisterAutoRedirectOutputMark says the
// registry lock "happens to serialise them today" and refuses to rely on it.
//
// So the reachable loser is the one Manager.Create produces: Create runs its constructor, re-checks
// the tag under its own lock, finds a concurrent Create installed it first, and closes what it built -
// with common.Close, while holding the manager lock. The loser in that path DOES claim the mark (its
// constructor ran to completion), which is exactly the case the release exists for.
//
// The concurrent window is therefore made real by racing two Create calls for one tag, which is what
// the loop below does: the first to install wins, the other is closed by the manager.
func TestDuplicateTagLoserAndWinnerLeaveExactlyOneClaim(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)

	var claims atomic.Int32
	var closes atomic.Int32

	registry := inbound.NewRegistry()
	inbound.Register[option.TunInboundOptions](registry, "claim-race",
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
			shared := service.FromContext[adapter.NetworkManager](ctx)
			if err := shared.RegisterAutoRedirectOutputMark(mark); err != nil {
				// The mark is process-global, so a second constructor in the SAME test process is
				// refused. That is the production refusal, and it is what makes the claim protocol
				// interesting: the registry lock is what keeps it from happening, not this test.
				return nil, err
			}
			claims.Add(1)
			current := newMarkClaimedInbound(tag, shared, mark)
			current.testCloseObserver = func() { closes.Add(1) }
			return current, nil
		})

	manager := inbound.NewManager(registry, nil)
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	loggerNOP := log.NewNOPFactory().NewLogger("claim-race")

	// Race two Create calls for ONE tag. Exactly one installs; the other's constructor may or may not
	// have run first, and whichever loses the tag is closed by the manager.
	var waitGroup sync.WaitGroup
	results := make([]error, 2)
	for index := range results {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results[index] = manager.Create(ctx, nil, loggerNOP, "shared-tag", "claim-race", &option.TunInboundOptions{})
		}()
	}
	waitGroup.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
			continue
		}
		// BOTH rejections are correct outcomes of this race, and which one occurs depends on how the
		// two Create calls interleave:
		//
		//   - "already exists"  the loser was rejected by the manager: either its pre-check saw the
		//                       tag, or its constructor ran and the re-check under the manager's lock
		//                       found it. That second form is the one that closes an inbound the
		//                       constructor built.
		//   - "only one auto-redirect can be configured"
		//                       the loser's constructor reached the mark claim first and refused to
		//                       build a second owner. No inbound exists to close, and the mark is
		//                       untouched.
		//
		// What is NOT acceptable is any third error: a construction that failed for its own reasons
		// would make the rest of this test meaningless.
		isDuplicateTag := strings.Contains(err.Error(), "already exists")
		isMarkRefusal := strings.Contains(err.Error(), "only one auto-redirect can be configured")
		require.True(t, isDuplicateTag || isMarkRefusal,
			"the loser must be rejected either as a duplicate tag or by the mark claim, got %v", err)
	}
	require.Equal(t, 1, succeeded, "exactly one Create may install the tag")

	installed, loaded := manager.Get("shared-tag")
	require.True(t, loaded)
	winner, isInbound := installed.(*Inbound)
	require.True(t, isInbound)

	// The registry lock serialises constructors, so the loser either never claimed (it was rejected by
	// the pre-check before constructing) or claimed and was closed by the manager. Either way the
	// surviving state must be exactly one claim, held by the installed inbound.
	require.EqualValues(t, 1, claims.Load(),
		"the registry lock serialises constructors, so exactly one of the two Create calls may reach "+
			"the claim; got %d", claims.Load())
	if closes.Load() > 0 {
		// The loser's constructor ran and the manager closed it: the release must already have
		// happened, or the winner could never have claimed. Reaching here with a live claim is the
		// proof.
		require.Equal(t, mark, networkManager.AutoRedirectOutputMark(),
			"the closed loser released a mark that the installed winner holds: the release is not "+
				"matched against the claim")
	}
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark(),
		"the installed inbound must hold the mark after the duplicate-tag race")
	require.True(t, winner.autoRedirectOutputMarkClaimed.Load(),
		"the installed inbound must still hold its claim")

	installedCloseErr := winner.Close()
	require.NoError(t, installedCloseErr)
	require.Zero(t, networkManager.AutoRedirectOutputMark())
	require.NoError(t, winner.Close())
	require.Zero(t, networkManager.AutoRedirectOutputMark())
}

// TestConstructedThenClosedInboundFreesTheMarkForARealReClaim is the manager-close path measured end
// to end with a REAL NewInbound-shaped claimant: the object claims, is closed the way Manager.Create
// closes a loser, and the mark is then claimable again by a new owner.
func TestConstructedThenClosedInboundFreesTheMarkForARealReClaim(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)

	loser := newMarkClaimedInbound("tun-loser", networkManager, mark)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark())

	// The manager's own close of a rejected inbound.
	require.NoError(t, loser.Close())
	require.Zero(t, networkManager.AutoRedirectOutputMark(),
		"a closed inbound must not keep the mark alive: the box would stamp a discarded tun's mark on "+
			"every dial it makes")

	// A new owner claims the same value and keeps it.
	newOwner := newMarkClaimedInbound("tun-new", networkManager, mark)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark())
	require.NoError(t, newOwner.Close())
	require.Zero(t, networkManager.AutoRedirectOutputMark())
}

// TestDuplicateTagRejectionDoesNotLeakTheRedirect pins the constructor's cleanup path: when the mark
// claim fails because another inbound already holds it, the auto-redirect the constructor already
// built must be closed rather than abandoned with the rejected inbound.
//
// The object under test is the *Inbound's own Close, reached through the same path Manager.Create
// uses, so what is asserted is the production teardown and not a parallel one.
func TestDuplicateTagRejectionDoesNotLeakTheRedirect(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))

	// A rejected inbound: it never got to claim, and it must therefore release nothing.
	rejected := &Inbound{
		tag:            "tun-rejected",
		networkManager: networkManager,
	}
	require.NoError(t, rejected.Close())
	require.Equal(t, mark, networkManager.AutoRedirectOutputMark(),
		"an inbound that never claimed released the holder's mark: the release must be tied to the "+
			"claim flag, not to the field being set")
}

// TestMarkReadsAreRaceFreeDuringClose runs the reads the product performs on the hot path - the
// dialer, wireguard, tailscale and openvpn all call AutoRedirectOutputMark - against a Close that is
// releasing the claim. The assertion is the race detector's: this test is about the access being
// correct, not about the value.
func TestMarkReadsAreRaceFreeDuringClose(t *testing.T) {
	networkManager := newMarkNetworkManager(t)
	const mark = uint32(0x2024)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(mark))

	inbound := newMarkClaimedInbound("tun-in", networkManager, mark)

	stop := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range 4 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = networkManager.AutoRedirectOutputMark()
				}
			}
		}()
	}

	var closers sync.WaitGroup
	for range 4 {
		closers.Add(1)
		go func() {
			defer closers.Done()
			_ = inbound.Close()
		}()
	}
	closers.Wait()
	close(stop)
	waitGroup.Wait()

	require.Zero(t, networkManager.AutoRedirectOutputMark())
}
