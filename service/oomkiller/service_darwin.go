//go:build darwin && cgo

package oomkiller

/*
#include <dispatch/dispatch.h>

// One monitor per process, owned entirely by this file.
//
// # Ownership of the dispatch source
//
// This preamble is plain C, not Objective-C: the file has no .m and nothing here is compiled
// with ARC. Under plain C, OS_OBJECT_USE_OBJC is 0, so dispatch objects are NOT automatically
// reference counted and dispatch_retain/dispatch_release are ordinary function calls.
//
// dispatch_source_create() returns a +1 reference that the caller owns. Cancelling a source
// stops further deliveries but does NOT consume that reference, so a create/cancel pair with no
// release leaks the source - and repeated start/stop cycles leak one each time.
//
// An earlier version of this file claimed the event handler's block captured `source` and that
// the capture kept it alive, so no release was needed. That was wrong twice over: the handler
// body is `^{ goMemoryPressureCallback(); }`, which does not mention `source` at all, so there
// was never a capture to retain anything; and a capture would not have balanced the create
// anyway, because the +1 from create is the caller's to release regardless of what the handler
// references.
//
// The lifecycle is therefore: create holds +1, stop removes the global reference FIRST, then
// cancels, then releases the caller's +1. A handler already queued when cancel runs still
// executes safely - it touches only Go state, never `source`, which is what makes the release
// safe here.

static dispatch_source_t memoryPressureSource;

extern void goMemoryPressureCallback(void);

static void startMemoryPressureMonitor() {
	if (memoryPressureSource != NULL) {
		// Already running. Creating a second source would leak the first and leave it
		// delivering events nobody owns.
		return;
	}

	dispatch_source_t source = dispatch_source_create(
		DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,
		0,
		DISPATCH_MEMORYPRESSURE_CRITICAL,
		dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0)
	);
	if (source == NULL) {
		return;
	}

	// The handler deliberately does NOT reference `source`. It needs no data from it - the Go
	// callback takes no argument - and not capturing it removes any question of the block
	// keeping a cancelled source alive or reading a newer source's state.
	dispatch_source_set_event_handler(source, ^{
		goMemoryPressureCallback();
	});

	// Publish before activating, so a handler that runs immediately finds the global set.
	memoryPressureSource = source;
	dispatch_activate(source);
}

static void stopMemoryPressureMonitor() {
	dispatch_source_t source = memoryPressureSource;
	if (source == NULL) {
		return;
	}

	// Detach from the global FIRST so a concurrent start cannot observe a cancelled source as
	// the live one and skip creating its own.
	memoryPressureSource = NULL;

	// Cancel stops further deliveries. It does NOT release.
	dispatch_source_cancel(source);

	// Balance the +1 from dispatch_source_create. Without this every start/stop cycle leaks a
	// dispatch source - a real leak in a service started and stopped as the tunnel comes up
	// and down.
	//
	// This is safe even if a handler was already queued: the handler does not touch `source`,
	// and libdispatch keeps the object alive until any in-flight handler returns.
	dispatch_release(source);
}
*/
import "C"

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/byteformats"
)

// pressureRegistry owns the set of NetworkExtension services sharing the process-wide
// memory-pressure monitor, and decides when the monitor starts and stops.
//
// # Why the bookkeeping is a separate type
//
// The rules it encodes - start the monitor for the FIRST service, stop it for the LAST,
// tolerate a service being closed twice, tolerate a close that was never started - are
// exactly the conditions that decide whether the dispatch source is left running or
// leaked. They are ordinary Go state and can be tested on any platform, which matters
// because the C half can only be exercised by a real Darwin build.
//
// # Why the transition happens inside the lock
//
// An earlier version returned a bool - "you are first" / "you are last" - and let the caller
// call Start or Stop after unlocking. That leaves a window:
//
//	add:    lock, append, see first, unlock ................ call Start()
//	remove:      lock, remove, see last, unlock, call Stop()      call Start()
//
// The interleaving marked above ends with an EMPTY registry and a RUNNING monitor: Stop ran
// before Start, so Start's "already running?" check saw nothing and created a source that
// nothing will ever stop. The registry and the monitor disagree permanently, and the source
// keeps delivering pressure events for services that are gone.
//
// Holding one lock across both the state change and the transition removes the window. The
// monitor's own Start/Stop must not call back into this registry, or the lock would deadlock;
// see pressureMonitor.
type pressureRegistry struct {
	access   sync.Mutex
	services []*Service
	monitor  pressureMonitor
}

// pressureMonitor is the process-wide monitor, abstracted so the registry's decisions can
// be tested without dispatching.
//
// # Start and Stop must not re-enter the registry
//
// The registry calls these while holding its lifecycle lock. An implementation that called
// back into the registry - to notify, log through it, or read its service list - would
// deadlock. dispatchPressureMonitor calls straight into C, and the dispatch callback path
// reaches the registry only through a snapshot taken before dispatch, never from inside
// Start or Stop.
type pressureMonitor interface {
	Start()
	Stop()
}

type dispatchPressureMonitor struct{}

func (dispatchPressureMonitor) Start() { C.startMemoryPressureMonitor() }
func (dispatchPressureMonitor) Stop()  { C.stopMemoryPressureMonitor() }

var globalPressureRegistry = &pressureRegistry{monitor: dispatchPressureMonitor{}}

// add registers a service and starts the monitor if this is the first one.
//
// Registration and the start transition are one serialized operation, so the registry cannot
// report an empty set while a monitor it started is still running.
func (r *pressureRegistry) add(service *Service) {
	r.access.Lock()
	defer r.access.Unlock()
	r.services = append(r.services, service)
	if len(r.services) == 1 && r.monitor != nil {
		r.monitor.Start()
	}
}

// remove unregisters a service and stops the monitor if this was the last one.
//
// Removing a service that is not present is not an error - Close can legitimately be called
// twice - and it must not be mistaken for the last one leaving, or a second Close on an
// already-removed service would tear down a monitor other services still need.
func (r *pressureRegistry) remove(service *Service) {
	r.access.Lock()
	defer r.access.Unlock()
	for i, existing := range r.services {
		if existing == service {
			r.services = append(r.services[:i], r.services[i+1:]...)
			if len(r.services) == 0 && r.monitor != nil {
				r.monitor.Stop()
			}
			return
		}
	}
}

// snapshot returns the currently registered services.
func (r *pressureRegistry) snapshot() []*Service {
	r.access.Lock()
	defer r.access.Unlock()
	services := make([]*Service, len(r.services))
	copy(services, r.services)
	return services
}

func (r *pressureRegistry) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.services)
}

func (s *Service) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := s.startTimer()
	if err != nil {
		return err
	}
	if s.timerConfig.policyMode == policyModeNetworkExtension {
		// Registration and the start transition are one serialized operation. Splitting them
		// let a concurrent Close stop a monitor this Start had not started yet, leaving an
		// empty registry and a running source.
		globalPressureRegistry.add(s)
	}
	return nil
}

func (s *Service) Close() error {
	s.stopTimer()
	if s.timerConfig.policyMode == policyModeNetworkExtension {
		globalPressureRegistry.remove(s)
	}
	return nil
}

//export goMemoryPressureCallback
func goMemoryPressureCallback() {
	// The status argument is gone because it was never used. Reading it was the only
	// reason the handler touched the shared source pointer, and removing that dependency
	// is what makes a late callback safe.
	services := globalPressureRegistry.snapshot()
	if len(services) == 0 {
		return
	}
	sample := readMemorySample(policyModeNetworkExtension)
	for _, s := range services {
		s.logger.Warn("memory pressure: critical, usage: ", byteformats.FormatMemoryBytes(sample.usage))
		if s.recorder != nil {
			s.recorder.recordPressure(sample)
		}
		s.adaptiveTimer.notifyPressure()
		if s.recorder != nil {
			s.recorder.snapshot(SnapshotReasonPressure, sample, false, false)
		}
	}
}
