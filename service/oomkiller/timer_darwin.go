//go:build darwin && cgo

package oomkiller

// notifyPressure handles a memory-pressure event from the dispatch source.
//
// # Why the active check comes first
//
// This is called from a dispatch callback. The registry hands each service a snapshot of the
// registered services, so a callback can be in flight while the service is being closed - the
// snapshot was taken before the Close and the callback runs after it.
//
// The previous order was:
//
//	releaseMemory()          <- Flush cache, Store(Critical), badCleanup, FreeOSMemory
//	if t.timer == nil { return }
//
// so a callback that arrived after Close performed the whole destructive sequence and only
// then discovered the timer was stopped. The consequences are not merely wasted work:
//
//   - an OOM-killer service that has been shut down flushes caches and calls FreeOSMemory,
//     which is exactly the behaviour the user stopped;
//   - pressure is rewritten from None back to Critical, so a torn-down service re-arms a
//     pressure report that other components read;
//   - badCleanup() runs on a service nobody owns any more.
//
// # Why a bare `if t.timer != nil` is not enough
//
// Checking the timer outside the lock and then doing the work would be a time-of-check /
// time-of-use race: Close can stop the timer between the check and the work. The state is
// therefore read and the decision acted on under one hold of the lifecycle lock.
//
// # Ordering guarantee
//
// notifyPressure and stop() are mutually exclusive through t.access:
//
//   - If stop() wins the lock first, the timer is nil by the time notifyPressure runs, so it
//     returns without touching anything. Close does not wait.
//   - If notifyPressure wins first, it completes its work and releases the lock; stop() then
//     proceeds. Close waits for the in-flight callback, which is the correct behaviour: the
//     service was genuinely active when the pressure arrived.
//
// Either way a callback never performs destructive work on a stopped timer, and Close never
// races the work.
func (t *adaptiveTimer) notifyPressure() {
	t.access.Lock()

	// Read the active state and decide under the same lock, so Close cannot stop the timer
	// between the check and the work.
	if t.timer == nil {
		t.access.Unlock()
		return
	}

	// The service is genuinely active. Record the pressure intent while still holding the
	// lock, so the state Close observes is consistent.
	t.forceMinInterval = true
	t.pendingPressureBaseline = true
	t.access.Unlock()

	// The destructive cleanup runs OUTSIDE the lock so a long FreeOSMemory does not block
	// Close for its whole duration. The check above already established that this service was
	// active at the moment the pressure arrived; a Close that lands during the cleanup is
	// handled by the normal stop path, and the cleanup completing afterwards is correct
	// because it was legitimately started while the service was live.
	t.releaseMemory()

	t.poll()
}
