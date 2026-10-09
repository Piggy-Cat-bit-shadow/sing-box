package box

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// §7.2 of the architecture-closure prompt is about ORDER, not about outcomes, and the two orderings
// it names are load-bearing in opposite directions:
//
//	sleep:      the EDGE is recorded, THEN the level is paused
//	wake/unlock: the reuse verdict is published, THEN the level is released
//
// Both are already stated in box_lifecycle.go with their reasons, and both already have tests for
// their EFFECTS - one measurement per sleep however many facts report it, a boundary per sleep/resume
// pair, a display-on that does not release the level. Effects are not order. A bridge that paused the
// level first and measured afterwards produces exactly the same effects in a single-threaded test,
// because the two calls still both happen; what it changes is the WINDOW between them, and only a
// concurrent fact arriving inside that window can see it. So the two tests below observe the order
// itself rather than waiting for a race to expose it.
//
// # The sleep ordering, and why a probe is the honest way to observe it
//
// "The edge first" means: at the moment the level moves, a sleep is already on record. That is a
// statement about the state of the governor DURING the level call, so the observer has to be inside
// it. A probe that asks the governor whether a resume would produce a boundary - at that exact
// moment - answers it directly: if the edge had not been recorded, the sleep would be zero-length on
// record (or absent) and Resumed would return without publishing anything.
//
// # The wake ordering, and why the sequence is observable
//
// The pause manager's callback is where the level is recorded, and the production bridge applies the
// pause event from inside that same callback (see newAppleBridge). So a sequence recorder shared by
// the callback and the reuse observer sees the true order of the two publications, whichever order
// the bridge used.

// orderingSequence records publications in the order they happen. It is shared by the pause
// callback and the reuse observer, which is what makes the order observable.
type orderingSequence struct {
	access sync.Mutex
	events []string
}

func (s *orderingSequence) add(event string) {
	s.access.Lock()
	defer s.access.Unlock()
	s.events = append(s.events, event)
}

func (s *orderingSequence) snapshot() []string {
	s.access.Lock()
	defer s.access.Unlock()
	return append([]string(nil), s.events...)
}

// TestTheReuseVerdictIsPublishedBeforeTheLevelIsReleased pins the wake ordering.
//
// If it were reversed, the level would be released first, and the speculative work that release
// authorises - health checks, URLTests, provider refreshes - would be free to dial while the pool
// still held connections from before the sleep. That is the stale-first-request race the reuse epoch
// exists to close, and closing it by ORDER is what makes it a property rather than a timing.
func TestTheReuseVerdictIsPublishedBeforeTheLevelIsReleased(t *testing.T) {
	clock := newTestClock()
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)
	governor := power.NewGovernorWithClock(bridgePolicy(), clock.Now)
	t.Cleanup(governor.Close)

	sequence := &orderingSequence{}
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		sequence.add("reuse-verdict")
	})
	manager.RegisterCallback(func(event int) {
		switch event {
		case pause.EventDevicePaused:
			sequence.add("level-paused")
		case pause.EventDeviceWake:
			sequence.add("level-released")
		default:
			return
		}
		applyPauseEvent(governor, event)
	})

	bridge := lifecycle{governor: governor, device: manager}

	// A sleep long enough that the policy owes a boundary on the resume.
	bridge.slept()
	clock.Advance(30 * time.Second)
	require.NotEqual(t, power.ReuseKeep, power.DefaultPolicy().ReuseFreshness.Classify(30*time.Second, true),
		"this test is measuring the wrong band: a 30 second sleep must not be kept")
	bridge.lockState(false)

	require.Equal(t, []string{"level-paused", "reuse-verdict", "level-released"}, sequence.snapshot(),
		"the reuse verdict must be published before the level is released, or released work can dial a stale pool")
	require.Equal(t, uint64(1), governor.ReuseEpoch(),
		"the unlock did not reach the retire band, so the ordering above was not exercised")
}

// TestTheSleepEdgeIsRecordedBeforeTheLevelIsPaused pins the sleep ordering with the probe described
// in the file comment.
func TestTheSleepEdgeIsRecordedBeforeTheLevelIsPaused(t *testing.T) {
	clock := newTestClock()
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)
	governor := power.NewGovernorWithClock(bridgePolicy(), clock.Now)
	t.Cleanup(governor.Close)

	// probingAxis asks the governor, at the moment the level is paused, whether a resume would
	// produce a boundary. A boundary means a sleep was already on record with a non-zero length,
	// which is only true if the EDGE was recorded first.
	axis := &probingAxis{inner: manager, clock: clock, governor: governor}

	bridge := lifecycle{governor: governor, device: axis}
	bridge.slept()

	require.True(t, axis.probed, "the level was never paused, so this test measured nothing")
	require.True(t, axis.result.boundaryPublished,
		"the level was paused BEFORE the sleep edge was recorded: a resume arriving in that window "+
			"would find no sleep on record and publish no boundary, so the first flow after it would "+
			"be handed a socket the sleep killed")
}

// probingAxis is a deviceAxis that forwards to the real pause manager and, on the first pause, asks
// the governor whether a resume would be a boundary right now.
type probingAxis struct {
	inner    pause.Manager
	clock    *testClock
	governor *power.Governor
	result   struct{ boundaryPublished bool }
	probed   bool
}

func (a *probingAxis) DevicePause() {
	if !a.probed {
		a.probed = true
		// Move the clock past the retire band first: a zero-length sleep is ReuseKeep by policy and
		// would produce no boundary even with the edge correctly recorded, which would make this
		// probe unable to tell the two orderings apart.
		a.clock.Advance(30 * time.Second)
		before := a.governor.ReuseEpoch()
		a.governor.Resumed()
		a.result.boundaryPublished = a.governor.ReuseEpoch() > before
	}
	a.inner.DevicePause()
}

func (a *probingAxis) DeviceWake() {
	a.inner.DeviceWake()
}
