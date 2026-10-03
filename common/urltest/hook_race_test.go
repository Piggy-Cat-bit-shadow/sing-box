package urltest

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

// Concurrency tests for update-hook notification.
//
// # The race these pin
//
// notifyUpdated walked `s.updateHooks` with no lock, while AddUpdateHook appended to it and Close
// replaced it - both under the storage's own lock, which notifyUpdated did not take. The slice
// header and its backing array were therefore read and written concurrently.
//
// A Subscriber is a buffered channel with a non-blocking Emit, so a notification is a send rather
// than a callback. That shapes the contract: the hook list is copied under the lock, and the sends
// happen outside it. Copying is what removes the race; sending outside the lock is what keeps a
// storage read from deadlocking against the write that triggered the notification.

// newObserver returns a subscriber and a function reporting how many notifications it received.
func newObserver(buffer int) (*observable.Subscriber[struct{}], func() int) {
	subscriber := observable.NewSubscriber[struct{}](buffer)
	subscription, _ := subscriber.Subscription()
	return subscriber, func() int { return len(subscription) }
}

// TestUpdateHookConcurrentWithNotify is the barrier test (§39).
//
// A writer stores and deletes continuously, another adds hooks, and a third notifies explicitly.
// Run under -race this detects the unsynchronised slice access.
func TestUpdateHookConcurrentWithNotify(t *testing.T) {
	storage := NewHistoryStorage()
	scope, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	const iterations = 300

	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: uint16(index%100 + 1)})
			storage.DeleteHealthHistory("node-a", scope)
			storage.StoreDisplayHistory("node-a", scope, &adapter.URLTestHistory{Delay: 1})
		}
	}()

	// Mutates the slice notifyUpdated reads.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			subscriber, _ := newObserver(1)
			storage.AddUpdateHook(subscriber)
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			storage.NotifyUpdated()
		}
	}()

	close(start)
	waitGroup.Wait()
}

// TestUpdateHookConcurrentWithClose races notification against teardown.
func TestUpdateHookConcurrentWithClose(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		storage := NewHistoryStorage()
		scope, err := NewMeasurementScope("https://a.example/x", nil)
		require.NoError(t, err)

		subscriber, _ := newObserver(64)
		storage.AddUpdateHook(subscriber)

		var waitGroup sync.WaitGroup
		start := make(chan struct{})

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for index := 0; index < 50; index++ {
				storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: uint16(index + 1)})
			}
		}()

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			require.NoError(t, storage.Close())
		}()

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			storage.NotifyUpdated()
		}()

		close(start)
		waitGroup.Wait()
	}
}

// TestUpdateHookObservesEveryNotification checks the copy does not lose events.
func TestUpdateHookObservesEveryNotification(t *testing.T) {
	storage := NewHistoryStorage()
	scope, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	subscriber, observed := newObserver(64)
	storage.AddUpdateHook(subscriber)

	const notifications = 50
	for index := 0; index < notifications; index++ {
		storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: uint16(index + 1)})
	}

	require.Equal(t, notifications, observed(),
		"every store must notify the registered hook; copying the hook list must not drop events")
}

// TestNotificationsStopAfterClose is the terminal boundary (§11).
func TestNotificationsStopAfterClose(t *testing.T) {
	storage := NewHistoryStorage()
	scope, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	subscriber, observed := newObserver(64)
	storage.AddUpdateHook(subscriber)

	storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: 1})
	require.Equal(t, 1, observed())

	require.NoError(t, storage.Close())

	// Drain what was already emitted before Close, so the assertion is about what follows.
	subscription, _ := subscriber.Subscription()
	for len(subscription) > 0 {
		<-subscription
	}

	// Anything after Close must be silent.
	storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: 2})
	storage.StoreDisplayHistory("node-a", scope, &adapter.URLTestHistory{Delay: 2})
	storage.NotifyUpdated()

	require.Equal(t, 0, observed(),
		"a closed storage must not notify: the caller has torn down whatever consumes the events")

	// A hook added after Close is never registered.
	lateSubscriber, lateObserved := newObserver(8)
	storage.AddUpdateHook(lateSubscriber)
	storage.NotifyUpdated()
	require.Equal(t, 0, lateObserved(), "AddUpdateHook after Close must be a no-op")
}

// TestCloseIsSerialisedAgainstNotification checks Close does not return mid-notification.
//
// The storage serialises teardown against notification, so a caller that closes and then releases
// whatever the events feed cannot be notified afterwards.
func TestCloseIsSerialisedAgainstNotification(t *testing.T) {
	storage := NewHistoryStorage()
	scope, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	subscriber, observed := newObserver(4)
	storage.AddUpdateHook(subscriber)

	// Fill and drain repeatedly while Close runs concurrently; the invariant is that after Close
	// returns, no further event can appear.
	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < 200; index++ {
			storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: uint16(index%50 + 1)})
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		require.NoError(t, storage.Close())
	}()

	close(start)
	waitGroup.Wait()

	subscription, _ := subscriber.Subscription()
	for len(subscription) > 0 {
		<-subscription
	}

	storage.StoreHealthHistory("node-a", scope, &adapter.URLTestHistory{Delay: 7})
	storage.NotifyUpdated()
	time.Sleep(10 * time.Millisecond)

	require.Equal(t, 0, observed(),
		"no event may be produced after Close has returned")
}
