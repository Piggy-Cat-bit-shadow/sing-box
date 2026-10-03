//go:build darwin && cgo

package oomkiller

// notifyPressure handles a memory-pressure event from the dispatch source.
//
// # The two-part guarantee
//
// A callback must not do destructive work on a stopped timer, AND Close must not return while
// a callback that legitimately started can still write MemoryPressureCritical. Those are
// different requirements and the first does not imply the second:
//
//	active check   -> bounds WHEN the work may start
//	in-flight group -> bounds when it has FINISHED, so Close can wait for it
//
// The previous implementation had only the first. It released the lock before doing the work -
// correctly, so a slow FreeOSMemory does not stall Close - but nothing joined on that work, so
// this sequence was possible:
//
//	notifyPressure: active check passes, unlock
//	Close:          timer = nil, pressure.Store(None), Close RETURNS
//	notifyPressure: releaseMemory() -> Store(Critical), cache flush, badCleanup, FreeOSMemory
//
// A torn-down service was left reporting Critical with cleanup still running, which is exactly
// what the earlier ordering fix was supposed to prevent.
//
// # Ordering
//
// Add(1) happens under t.access, after the active check. stop() sets timer = nil under the same
// lock and only then waits. So a callback that started before stop() is always counted, and one
// that arrives after sees timer == nil and never Adds - there is no window in which Add can
// land after the wait has already concluded.
//
// Release-and-poll still run outside the lock: they are the slow part, and holding t.access
// across FreeOSMemory would stall every other reader of the timer state for its whole duration.
func (t *adaptiveTimer) notifyPressure() {
	t.access.Lock()

	// Read the active state and decide under the same lock, so Close cannot stop the timer
	// between the check and the work.
	if t.timer == nil {
		t.access.Unlock()
		return
	}

	// Join the in-flight group WHILE STILL HOLDING the lock.
	//
	// This is the ordering that makes the barrier sound. stop() sets timer = nil under this
	// same lock before it waits, so a callback either:
	//
	//   - Added here before stop() took the lock, in which case stop()'s Wait observes it; or
	//   - arrives after timer became nil, fails the check above, and never Adds.
	//
	// Adding after unlocking would leave a window where stop() could see a zero count and
	// return while this callback was already committed to running - the exact race the barrier
	// exists to close.
	t.pressureCallbacks.Add(1)

	// Record the pressure intent while still holding the lock, so the state Close observes is
	// consistent.
	t.forceMinInterval = true
	t.pendingPressureBaseline = true
	t.access.Unlock()

	// Every path below must decrement, including a panic in the cleanup, or stop() would wait
	// forever.
	defer t.pressureCallbacks.Done()

	// The destructive cleanup runs OUTSIDE the lock so a long FreeOSMemory does not block
	// Close for its whole duration. stop() does not return until this has finished.
	t.releaseMemory()

	t.poll()
}
