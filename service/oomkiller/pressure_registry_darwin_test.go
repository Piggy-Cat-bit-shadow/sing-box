//go:build darwin && cgo

package oomkiller

import (
	"sync"
	"testing"
	"time"
)

// Tests for the memory-pressure monitor lifecycle.
//
// # What can and cannot be tested here
//
// The dispatch source itself needs a live Darwin runtime: creating one, cancelling it and
// observing that no further events arrive cannot be asserted from Go. What CAN be tested - and
// what actually decides whether the source is leaked or left running - is the registry's
// start/stop policy. That is where the reload races live, so it is where the tests are. The C
// half is covered by the ownership reasoning in service_darwin.go and by the Apple build.
//
// The monitor is injected, so these tests observe the exact decisions production makes without
// dispatching anything.

// recordingMonitor counts transitions, tracks the running state, and can be made to block
// inside Start so a transition still in progress can be interleaved with a Close.
type recordingMonitor struct {
	access  sync.Mutex
	starts  int
	stops   int
	running bool

	// startEntered is closed the first time Start is entered, so a test can wait until the
	// transition is genuinely in progress.
	startEntered chan struct{}
	startOnce    sync.Once
	// startRelease, when non-nil, blocks Start until it is closed.
	startRelease chan struct{}
}

func newRecordingMonitor() *recordingMonitor {
	return &recordingMonitor{startEntered: make(chan struct{})}
}

func (m *recordingMonitor) Start() {
	m.startOnce.Do(func() { close(m.startEntered) })
	if m.startRelease != nil {
		<-m.startRelease
	}
	m.access.Lock()
	m.starts++
	m.running = true
	m.access.Unlock()
}

func (m *recordingMonitor) Stop() {
	m.access.Lock()
	m.stops++
	m.running = false
	m.access.Unlock()
}

func (m *recordingMonitor) counts() (int, int) {
	m.access.Lock()
	defer m.access.Unlock()
	return m.starts, m.stops
}

// isRunning reports the CURRENT state.
//
// Counting starts and stops is not enough to detect the bug: "stopped then started" and
// "started then stopped" both yield one of each, but only the first leaves a monitor running
// with an empty registry.
func (m *recordingMonitor) isRunning() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.running
}

func newTestRegistry() (*pressureRegistry, *recordingMonitor) {
	monitor := newRecordingMonitor()
	return &pressureRegistry{monitor: monitor}, monitor
}

func TestPressureRegistryStartsForFirstAndStopsForLast(t *testing.T) {
	registry, monitor := newTestRegistry()
	first := &Service{}
	second := &Service{}

	registry.add(first)
	if starts, _ := monitor.counts(); starts != 1 {
		t.Fatalf("the first registration must start the monitor, got %d starts", starts)
	}
	if !monitor.isRunning() {
		t.Fatal("the monitor must be running after the first registration")
	}

	registry.add(second)
	if starts, _ := monitor.counts(); starts != 1 {
		t.Fatalf("a second registration must not restart the monitor, got %d starts", starts)
	}

	registry.remove(first)
	if _, stops := monitor.counts(); stops != 0 {
		t.Fatalf("the monitor must keep running while a service remains, got %d stops", stops)
	}

	registry.remove(second)
	starts, stops := monitor.counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("expected exactly one start and one stop, got %d/%d", starts, stops)
	}
	if registry.count() != 0 {
		t.Fatalf("the registry should be empty, got %d", registry.count())
	}
	if monitor.isRunning() {
		t.Fatal("the monitor must be stopped once the last service has gone")
	}
}

func TestPressureRegistryToleratesDoubleCloseAndLateClose(t *testing.T) {
	registry, monitor := newTestRegistry()
	service := &Service{}

	registry.add(service)
	registry.remove(service)
	registry.remove(service) // Close can legitimately be called twice.

	starts, stops := monitor.counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("a double Close must not add transitions, got %d/%d", starts, stops)
	}

	// A Close that was never paired with a Start must not stop a monitor belonging to others.
	registry.add(&Service{})
	registry.remove(&Service{})
	if starts, stops := monitor.counts(); starts != 2 || stops != 1 {
		t.Fatalf("an unpaired Close must not add transitions, got %d/%d", starts, stops)
	}
	if !monitor.isRunning() {
		t.Fatal("the remaining service must still have a running monitor")
	}
}

// TestPressureRegistrySerializesStartAndStop is the §4 regression.
//
// # The failure it reproduces
//
// The registry used to return a bool and let the caller perform the transition after
// unlocking, which allows:
//
//	add:    lock, append, first, unlock ...... (not yet started)
//	remove:      lock, remove, last, unlock, Stop()
//	                                          Start()
//
// The final state is an EMPTY registry with a RUNNING monitor. Stop ran before Start, so
// Start's "already running?" check saw nothing and created a source that nothing will ever
// stop. The registry and the monitor then disagree permanently, and the source keeps
// delivering pressure events for services that are gone.
//
// Asserting starts == stops would NOT catch this - the broken version also ends with one of
// each. What catches it is the final state: registry empty AND monitor stopped.
func TestPressureRegistrySerializesStartAndStop(t *testing.T) {
	monitor := newRecordingMonitor()
	monitor.startRelease = make(chan struct{})
	registry := &pressureRegistry{monitor: monitor}

	service := &Service{}

	// add() calls Start() while holding the lifecycle lock, so this goroutine is still inside
	// the registry when it blocks.
	addDone := make(chan struct{})
	go func() {
		defer close(addDone)
		registry.add(service)
	}()

	select {
	case <-monitor.startEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Start was never entered")
	}

	// Close concurrently, while Start has not completed.
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		registry.remove(service)
	}()

	// With correct serialization the Close is blocked on the registry lock and must not have
	// stopped anything yet.
	select {
	case <-closeDone:
		t.Fatal("remove completed while add held the lifecycle lock; transitions are not serialized")
	case <-time.After(100 * time.Millisecond):
	}

	close(monitor.startRelease)
	select {
	case <-addDone:
	case <-time.After(2 * time.Second):
		t.Fatal("add did not complete")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("remove did not complete after Start was released")
	}

	if registry.count() != 0 {
		t.Fatalf("the registry must be empty at the end, got %d services", registry.count())
	}
	starts, stops := monitor.counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("expected exactly one start and one stop, got %d/%d", starts, stops)
	}
	if monitor.isRunning() {
		t.Fatal("the monitor must end STOPPED: a running monitor with an empty registry is the leak")
	}
}

// TestPressureRegistryRepeatedCyclesLeaveItStopped is the repeated start/stop acceptance check.
//
// Every cycle must return the monitor to a stopped state with an empty registry. A leak here
// would be one dispatch source per cycle in production, because Stop is what releases it.
func TestPressureRegistryRepeatedCyclesLeaveItStopped(t *testing.T) {
	registry, monitor := newTestRegistry()

	for cycle := 0; cycle < 100; cycle++ {
		service := &Service{}
		registry.add(service)
		registry.remove(service)
	}

	if registry.count() != 0 {
		t.Fatalf("the registry must be empty, got %d", registry.count())
	}
	starts, stops := monitor.counts()
	if starts != 100 || stops != 100 {
		t.Fatalf("every cycle must produce one start and one stop, got %d/%d", starts, stops)
	}
	if monitor.isRunning() {
		t.Fatal("the monitor must end stopped after the final cycle")
	}
}

// TestPressureRegistryConcurrentCyclesStayBalanced drives adds and removes from many
// goroutines, which is the shape of a real tunnel reloading while several services start.
func TestPressureRegistryConcurrentCyclesStayBalanced(t *testing.T) {
	registry, monitor := newTestRegistry()

	// startRelease is left nil so Start returns immediately; this test is about the lock
	// ordering under contention, not about a blocked transition.
	const workers = 8
	const cycles = 50

	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			service := &Service{}
			for cycle := 0; cycle < cycles; cycle++ {
				registry.add(service)
				registry.remove(service)
			}
		}()
	}
	waitGroup.Wait()

	if registry.count() != 0 {
		t.Fatalf("the registry must be empty, got %d", registry.count())
	}
	if monitor.isRunning() {
		t.Fatal("the monitor must end stopped once every service has gone")
	}
	starts, stops := monitor.counts()
	if starts != stops {
		t.Fatalf("every start must be matched by a stop, got %d/%d", starts, stops)
	}
}
