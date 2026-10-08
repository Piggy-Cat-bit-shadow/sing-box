package trafficcontrol

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// # Why this package needed a race regression
//
// Manager keeps two structures that together answer "what is this process's traffic": the live
// compatible.Map and the closed-connection list with its accumulated totals. A connection moves
// between them exactly once, in leave, and every reader - Total, ClosedConnections, Connections -
// walks one or both. That transition is the whole contract:
//
//   - a connection that has been removed from the live map but not yet added to the closed list is
//     invisible to a concurrent Total, so its traffic disappears from that reading;
//   - a connection visible in both is counted twice.
//
// closedConnectionsAccess is what makes the transition atomic, and the placement that matters is
// that LoadAndDelete is INSIDE it: with the delete outside, Total can hold the lock, miss the
// connection in both structures, and report a total that went backwards. Nothing in the package
// guarded that - there was no test file here at all - so the fix was one scheduling accident away
// from being reverted.
//
// The invariant is exact, not statistical: every tracker is joined before the observers start and
// no tracker's traffic ever changes afterwards, so Total MUST equal the full sum at every instant,
// no matter how many leaves, closes and trims are racing it. A total that is merely "sometimes
// low" is the bug, so equality is the assertion.
//
// The observers also read every field of every returned metadata, which is what the Clash API's
// connection list does. That is deliberate: it is the access pattern that turns a write to shared
// metadata (the ClosedAt assignment leave used to make on the live tracker) into a -race report.
//
// Snapshot safety is covered here rather than by a separate alias test: ClosedConnections copies
// through list.Array, and the observer below spans the returned slices while the mutators rotate
// and Clear the list, so an implementation that handed out live list storage would be reported by
// -race instead of merely going stale.

const (
	raceTrackerCount  = 512
	raceUploadEach    = 3
	raceDownloadEach  = 5
	raceFullUpload    = raceTrackerCount * raceUploadEach
	raceFullDownload  = raceTrackerCount * raceDownloadEach
	raceCloseAttempts = 4
)

// raceTestTracker is a Tracker whose traffic is fixed at construction, so a test can compute the
// exact total that every reading must equal.
type raceTestTracker struct {
	metadata TrackerMetadata
	manager  *Manager
	closes   atomic.Int64
}

func newRaceTestTracker(manager *Manager) *raceTestTracker {
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	tracker := &raceTestTracker{manager: manager}
	tracker.metadata = TrackerMetadata{
		ID:        id,
		CreatedAt: time.Now(),
		Upload:    new(atomic.Int64),
		Download:  new(atomic.Int64),
	}
	tracker.metadata.Upload.Store(raceUploadEach)
	tracker.metadata.Download.Store(raceDownloadEach)
	return tracker
}

func (t *raceTestTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *raceTestTracker) Close() error {
	t.closes.Add(1)
	t.manager.leave(t)
	return nil
}

func joinRaceTrackers(manager *Manager, count int) []*raceTestTracker {
	trackers := make([]*raceTestTracker, count)
	for index := range trackers {
		trackers[index] = newRaceTestTracker(manager)
		manager.join(trackers[index])
	}
	return trackers
}

// TestManagerConcurrentListOperationsConserveTraffic is the regression for the transition's
// atomicity. Everything except the two observers mutates the manager; the observers assert that the
// totals and the lists stay consistent throughout.
func TestManagerConcurrentListOperationsConserveTraffic(t *testing.T) {
	manager := NewManager()
	trackers := joinRaceTrackers(manager, raceTrackerCount)

	var stopped atomic.Bool
	var observers, mutators sync.WaitGroup

	observers.Add(3)
	// One observer owns the total, so the readings it compares are a well-ordered sequence. It
	// runs until every mutator has stopped, which is the whole racing window.
	go func() {
		defer observers.Done()
		for !stopped.Load() {
			upload, download := manager.Total()
			if upload != raceFullUpload || download != raceFullDownload {
				t.Errorf("traffic total (%d,%d) does not equal everything that was added (%d,%d): a "+
					"connection left the live map without appearing in the closed list, or was "+
					"counted in both", upload, download, int64(raceFullUpload), int64(raceFullDownload))
				return
			}
		}
	}()
	// The Clash API's access pattern: take both lists and read every field, while the list is
	// rotated underneath. An iterator that handed out live storage would be a -race report here.
	go func() {
		defer observers.Done()
		for !stopped.Load() {
			for _, metadata := range manager.Connections() {
				_, _ = metadata.Upload.Load(), metadata.Download.Load()
				_ = metadata.ClosedAt
				_ = metadata.CreatedAt
				_ = manager.Connection(metadata.ID)
			}
			for _, metadata := range manager.ClosedConnections() {
				_, _ = metadata.Upload.Load(), metadata.Download.Load()
				_ = metadata.ClosedAt
				_ = metadata.CreatedAt
			}
			_ = manager.ConnectionsLen()
		}
	}()
	// Trim concurrently. Clear must move the list's traffic into the accumulated totals rather
	// than dropping it, so it is part of the same conservation invariant.
	go func() {
		defer observers.Done()
		for !stopped.Load() {
			manager.Clear()
		}
	}()

	mutators.Add(2)
	go func() {
		defer mutators.Done()
		for index := 0; index < raceTrackerCount/2; index++ {
			manager.leave(trackers[index])
			// A second leave is the ordinary shape of a tracker closed twice; it must be a
			// no-op rather than a second closed-list entry.
			manager.leave(trackers[index])
		}
	}()
	go func() {
		defer mutators.Done()
		for range raceCloseAttempts {
			manager.CloseAllConnections()
		}
	}()
	mutators.Wait()
	stopped.Store(true)
	observers.Wait()

	upload, download := manager.Total()
	require.EqualValues(t, raceFullUpload, upload,
		"traffic added to a connection must survive its removal and every trim")
	require.EqualValues(t, raceFullDownload, download)
	for index, tracker := range trackers {
		require.LessOrEqual(t, tracker.closes.Load(), int64(1),
			"tracker %d was closed more than once by the manager", index)
	}
}

// TestManagerConcurrentLeaveIsIdempotent pins the other half of the transition: several goroutines
// may race to retire the same tracker, and exactly one of them may win. The losers must not add a
// second closed-list entry and must not add the traffic again.
func TestManagerConcurrentLeaveIsIdempotent(t *testing.T) {
	manager := NewManager()
	trackers := joinRaceTrackers(manager, raceTrackerCount)

	var waitGroup sync.WaitGroup
	for _, tracker := range trackers {
		waitGroup.Add(raceCloseAttempts)
		for range raceCloseAttempts / 2 {
			go func() {
				defer waitGroup.Done()
				manager.leave(tracker)
			}()
			go func() {
				defer waitGroup.Done()
				_ = tracker.Close()
			}()
		}
	}
	waitGroup.Wait()

	closed := manager.ClosedConnections()
	require.Len(t, closed, raceTrackerCount)
	seen := make(map[uuid.UUID]int, len(closed))
	for _, metadata := range closed {
		seen[metadata.ID]++
		require.NotZero(t, metadata.ClosedAt, "a closed connection must carry its close time")
	}
	for id, count := range seen {
		require.Equal(t, 1, count, "connection %s appears in the closed list %d times", id, count)
	}

	upload, download := manager.Total()
	require.EqualValues(t, raceFullUpload, upload)
	require.EqualValues(t, raceFullDownload, download)
}
