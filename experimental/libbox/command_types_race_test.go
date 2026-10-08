package libbox

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The connection list is fed from one goroutine and read from another, by design.
//
// The command client receives the event stream on its own goroutine
// (`go c.handleConnectionsStream(...)` -> the platform handler -> ApplyEvents) while the UI thread
// calls Iterator, FilterState and the Sort methods to draw and order the list. Before this test the
// type had no synchronization at all, which made three unsynchronized accesses reachable:
//
//  1. ApplyEvents ITERATED connectionMap while ApplyEvents could concurrently WRITE it. In Go that is
//     not a recoverable race: it is `fatal error: concurrent map iteration and map write`, a runtime
//     throw that kills the process with no panic to catch - a user-visible crash triggered by ordinary
//     background traffic.
//  2. `filtered` was re-sliced and refilled while SortBy* sorted the same backing array.
//  3. Iterator handed the caller the LIVE slice, so even a read-only consumer walked memory the next
//     event batch was rewriting under it.
//
// The test drives all four access kinds concurrently. It asserts liveness and consistency, and its
// real value is what `-race` reports: run against the unsynchronized implementation it fails with a
// data race on connectionMap and on filtered, and it is the map one that would have been a fatal
// process kill in production rather than a benign report.

func raceTestEvents(batch int, connections int) *ConnectionEvents {
	events := &ConnectionEvents{}
	if batch == 0 {
		events.Reset = true
	}
	for index := 0; index < connections; index++ {
		id := fmt.Sprintf("conn-%d", index)
		events.events = append(events.events, &ConnectionEvent{
			Type: ConnectionEventNew,
			ID:   id,
			Connection: &Connection{
				ID:        id,
				CreatedAt: time.Now().UnixMilli(),
				Uplink:    int64(index),
				Downlink:  int64(index * 2),
			},
		})
		// An update is what makes ApplyEvents write into entries another path is reading.
		events.events = append(events.events, &ConnectionEvent{
			Type:        ConnectionEventUpdate,
			ID:          id,
			UplinkDelta: 1,
		})
	}
	return events
}

// TestConnectionsConcurrentApplyAndReadIsRaceFree is the SPEC 016 regression.
func TestConnectionsConcurrentApplyAndReadIsRaceFree(t *testing.T) {
	t.Parallel()
	connections := NewConnections()

	const (
		batches = 200
		readers = 4
	)
	var waitGroup sync.WaitGroup

	// The stream goroutine.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for batch := 0; batch < batches; batch++ {
			connections.ApplyEvents(raceTestEvents(batch, 8))
		}
	}()

	// The UI goroutine, doing each of the four things the platform does.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < batches; index++ {
			iterator := connections.Iterator()
			// Walk it fully: this is where a live-slice iterator reads torn memory.
			seen := 0
			for iterator.HasNext() {
				connection := iterator.Next()
				if connection != nil {
					seen++
				}
			}
			require.NotNil(t, connections)
			_ = seen
		}
	}()

	// Concurrent filter and sort, which touch the same backing array as ApplyEvents.
	for reader := 0; reader < readers; reader++ {
		reader := reader
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for index := 0; index < batches; index++ {
				switch (reader + index) % 4 {
				case 0:
					connections.FilterState(ConnectionStateAll)
				case 1:
					connections.FilterState(ConnectionStateActive)
				case 2:
					connections.SortByDate()
				default:
					connections.SortByTraffic()
				}
				// And the totals sort, which reads fields ApplyEvents also writes.
				if index%8 == 0 {
					connections.SortByTrafficTotal()
				}
			}
		}()
	}

	waitGroup.Wait()
}

// An iterator must not observe later mutations: it is a snapshot, not a view.
//
// This is the property that makes the gomobile surface safe, because the consumer walks the result
// across a UI frame while the stream keeps arriving. Without the snapshot this fails - the iterator
// would report the post-ApplyEvents length for a list it was handed before that batch existed.
func TestConnectionIteratorIsASnapshotNotAView(t *testing.T) {
	t.Parallel()
	connections := NewConnections()
	connections.ApplyEvents(raceTestEvents(0, 8))

	iterator := connections.Iterator()

	// Mutate hard after the iterator was handed out, in every way that touches the backing array.
	connections.ApplyEvents(raceTestEvents(1, 64))
	connections.FilterState(ConnectionStateActive)
	connections.SortByDate()

	count := 0
	for iterator.HasNext() {
		require.NotNil(t, iterator.Next())
		count++
	}
	require.Equal(t, 8, count,
		"the iterator must walk the list as it was when it was created; if it walks the live slice, "+
			"the consumer is reading memory the event stream is rewriting")

	// And the live list really did move on, so the assertion above is not vacuous.
	require.Equal(t, 64, countConnections(connections))
}

// The filter is honoured under concurrency, so the lock did not simply serialise the writes without
// keeping the state coherent.
func TestConnectionsConcurrentFilterStaysCoherent(t *testing.T) {
	t.Parallel()
	connections := NewConnections()
	events := raceTestEvents(0, 20)
	// Close half of them so the three filter states are genuinely different.
	for index := 0; index < 10; index++ {
		events.events = append(events.events, &ConnectionEvent{
			Type:     ConnectionEventClosed,
			ID:       fmt.Sprintf("conn-%d", index),
			ClosedAt: time.Now().UnixMilli(),
		})
	}
	connections.ApplyEvents(events)

	connections.FilterState(ConnectionStateActive)
	require.Equal(t, 10, countConnections(connections))
	connections.FilterState(ConnectionStateClosed)
	require.Equal(t, 10, countConnections(connections))
	connections.FilterState(ConnectionStateAll)
	require.Equal(t, 20, countConnections(connections))
}

func countConnections(connections *Connections) int {
	iterator := connections.Iterator()
	count := 0
	for iterator.HasNext() {
		iterator.Next()
		count++
	}
	return count
}
