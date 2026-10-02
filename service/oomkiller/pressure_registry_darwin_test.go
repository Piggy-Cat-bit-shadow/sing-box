//go:build darwin && cgo

package oomkiller

import (
	"sync"
	"testing"
)

// Tests for the memory-pressure monitor lifecycle (§6).
//
// # What can and cannot be tested here
//
// The dispatch source itself needs a live Darwin runtime: creating one, cancelling it and
// observing that no further events arrive cannot be asserted from Go. What CAN be tested -
// and what actually decides whether the source is leaked or left running - is the
// registry's start/stop policy. That is where the reload races live, so it is where the
// tests are, and the C half is left to the Apple build and a real device.
//
// The monitor is injected here, so these tests observe the exact decisions the production
// code makes without dispatching anything.

// recordingMonitor counts start and stop calls.
type recordingMonitor struct {
	access sync.Mutex
	starts int
	stops  int
}

func (m *recordingMonitor) Start() {
	m.access.Lock()
	defer m.access.Unlock()
	m.starts++
}

func (m *recordingMonitor) Stop() {
	m.access.Lock()
	defer m.access.Unlock()
	m.stops++
}

func (m *recordingMonitor) counts() (int, int) {
	m.access.Lock()
	defer m.access.Unlock()
	return m.starts, m.stops
}

func newTestRegistry() (*pressureRegistry, *recordingMonitor) {
	monitor := &recordingMonitor{}
	return &pressureRegistry{monitor: monitor}, monitor
}

// start mirrors Service.Start's use of the registry: add, then start if it says so.
func (r *pressureRegistry) start(service *Service) {
	if r.add(service) {
		r.monitor.Start()
	}
}

// close mirrors Service.Close's use of the registry: remove, then stop if it says so.
func (r *pressureRegistry) close(service *Service) {
	if r.remove(service) {
		r.monitor.Stop()
	}
}

func TestPressureRegistryStartsForFirstAndStopsForLast(t *testing.T) {
	registry, monitor := newTestRegistry()
	first := &Service{}
	second := &Service{}

	registry.start(first)
	registry.start(second)
	if starts, _ := monitor.counts(); starts != 1 {
		t.Errorf("monitor started %d times, want 1: the second service must not start another", starts)
	}

	registry.close(first)
	if _, stops := monitor.counts(); stops != 0 {
		t.Error("removing a service while another remains must not stop the monitor")
	}
	registry.close(second)
	if _, stops := monitor.counts(); stops != 1 {
		t.Errorf("monitor stopped %d times, want 1", stops)
	}
}

func TestPressureRegistryToleratesDoubleClose(t *testing.T) {
	// Close can be called twice. The second call must not look like the last service
	// leaving, or it would tear down a monitor that other services still need.
	registry, monitor := newTestRegistry()
	first := &Service{}
	second := &Service{}
	registry.start(first)
	registry.start(second)

	registry.close(first)
	if _, stops := monitor.counts(); stops != 0 {
		t.Error("removing the first of two must not stop the monitor")
	}
	// A repeated close of the same service.
	if stop := registry.remove(first); stop {
		t.Error("removing an already-removed service must not be treated as the last one")
	}
	if registry.count() != 1 {
		t.Errorf("registry holds %d services, want 1", registry.count())
	}
	registry.close(second)
	if _, stops := monitor.counts(); stops != 1 {
		t.Errorf("monitor stopped %d times, want exactly 1", stops)
	}
}

func TestPressureRegistryCloseWithoutStart(t *testing.T) {
	// Closing a service that never registered must not stop a monitor belonging to others.
	registry, monitor := newTestRegistry()
	active := &Service{}
	registry.add(active)

	never := &Service{}
	if stop := registry.remove(never); stop {
		t.Error("removing a service that was never added must not stop the monitor")
	}
	if registry.count() != 1 {
		t.Error("the active service must still be registered")
	}
	if _, stops := monitor.counts(); stops != 0 {
		t.Errorf("monitor stopped %d times, want 0", stops)
	}
}

func TestPressureRegistryStartCloseStartCycle(t *testing.T) {
	// Repeated start -> close -> start must not accumulate registry entries or leave the
	// monitor running after everything has stopped.
	registry, monitor := newTestRegistry()
	for cycle := 0; cycle < 5; cycle++ {
		service := &Service{}
		registry.start(service)
		if starts, _ := monitor.counts(); starts != cycle+1 {
			t.Fatalf("cycle %d: monitor started %d times, want %d", cycle, starts, cycle+1)
		}
		registry.close(service)
		if _, stops := monitor.counts(); stops != cycle+1 {
			t.Fatalf("cycle %d: monitor stopped %d times, want %d", cycle, stops, cycle+1)
		}
	}
	if registry.count() != 0 {
		t.Errorf("registry holds %d services after all cycles, want 0", registry.count())
	}
	starts, stops := monitor.counts()
	if starts != 5 || stops != 5 {
		t.Errorf("monitor started %d and stopped %d times, want 5 and 5", starts, stops)
	}
}

func TestPressureRegistrySnapshotIsIndependent(t *testing.T) {
	// The callback iterates a snapshot without holding the lock. Mutating the registry
	// afterwards must not change what a callback already took.
	registry, _ := newTestRegistry()
	first := &Service{}
	registry.add(first)

	snapshot := registry.snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot has %d entries, want 1", len(snapshot))
	}
	registry.remove(first)
	if len(snapshot) != 1 {
		t.Error("a snapshot must not be affected by later registry changes")
	}
	if registry.count() != 0 {
		t.Error("the registry itself must reflect the removal")
	}
}

func TestPressureRegistryConcurrentStartStop(t *testing.T) {
	// Concurrent start and close must not double-start the monitor or leave it running.
	// Run under -race to catch unsynchronised access.
	registry, monitor := newTestRegistry()
	const workers = 16
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer waitGroup.Done()
			service := &Service{}
			registry.start(service)
			registry.close(service)
		}()
	}
	waitGroup.Wait()

	if registry.count() != 0 {
		t.Errorf("registry holds %d services, want 0", registry.count())
	}
	starts, stops := monitor.counts()
	// Every start must be matched by a stop, and the monitor must never be left running.
	if starts != stops {
		t.Errorf("monitor started %d times but stopped %d; it was left running", starts, stops)
	}
}
