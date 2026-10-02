//go:build darwin && cgo

package oomkiller

/*
#include <dispatch/dispatch.h>

// One monitor per process, owned entirely by this file.
//
// # Why the source is no longer read through a global
//
// The event handler used to read its own source back out of the mutable global
// memoryPressureSource:
//
//     unsigned long status = dispatch_source_get_data(memoryPressureSource);
//
// The handler is delivered on a dispatch queue, so it can be queued and then run after
// stopMemoryPressureMonitor() has already set that global to NULL - a null dereference on
// a background queue, in the process whose job is to survive memory pressure. The value
// was not even used: the Go callback ignored its argument.
//
// The handler now captures the source it was installed on, which is a strong reference
// that outlives cancellation, so a late callback reads its own source and nothing else.
// That also removes the cross-talk case where a callback belonging to a cancelled source
// read the NEW source's data.
static dispatch_source_t memoryPressureSource;

extern void goMemoryPressureCallback(void);

static void startMemoryPressureMonitor() {
	if (memoryPressureSource != NULL) {
		// Already running. Starting again would leak the previous source and leave it
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

	// The block captures `source` by value. Under ARC-free C blocks, dispatch objects are
	// reference counted by libdispatch, and a block capture retains; that is what keeps
	// this valid if the handler runs after cancellation.
	dispatch_source_set_event_handler(source, ^{
		goMemoryPressureCallback();
	});
	memoryPressureSource = source;
	dispatch_activate(source);
}

static void stopMemoryPressureMonitor() {
	dispatch_source_t source = memoryPressureSource;
	if (source == NULL) {
		return;
	}
	// Clear the global FIRST so a concurrent start cannot observe a cancelled source as
	// the live one and skip creating its own.
	memoryPressureSource = NULL;

	// Cancel stops further deliveries. The block's own capture keeps `source` alive until
	// any already-queued invocation has run, so this needs no explicit release: under
	// libdispatch's reference counting the capture is the reference that matters, and
	// calling dispatch_release here would risk releasing a source a queued handler still
	// holds.
	dispatch_source_cancel(source);
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
type pressureRegistry struct {
	access   sync.Mutex
	services []*Service
	monitor  pressureMonitor
}

// pressureMonitor is the process-wide monitor, abstracted so the registry's decisions can
// be tested without dispatching.
type pressureMonitor interface {
	Start()
	Stop()
}

type dispatchPressureMonitor struct{}

func (dispatchPressureMonitor) Start() { C.startMemoryPressureMonitor() }
func (dispatchPressureMonitor) Stop()  { C.stopMemoryPressureMonitor() }

var globalPressureRegistry = &pressureRegistry{monitor: dispatchPressureMonitor{}}

// add registers a service and reports whether the monitor should be started.
//
// The decision is made while holding the lock, so two services starting concurrently
// cannot both believe they are first and create two monitors.
func (r *pressureRegistry) add(service *Service) (startMonitor bool) {
	r.access.Lock()
	defer r.access.Unlock()
	r.services = append(r.services, service)
	return len(r.services) == 1
}

// remove unregisters a service and reports whether the monitor should be stopped.
//
// It reports true only when the LAST service leaves. Removing a service that is not
// present is not an error - Close can legitimately be called twice - and it must not be
// mistaken for the last one leaving, or a second Close on an already-removed service
// would tear down a monitor other services still need.
func (r *pressureRegistry) remove(service *Service) (stopMonitor bool) {
	r.access.Lock()
	defer r.access.Unlock()
	for i, existing := range r.services {
		if existing == service {
			r.services = append(r.services[:i], r.services[i+1:]...)
			return len(r.services) == 0
		}
	}
	return false
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
		if globalPressureRegistry.add(s) {
			globalPressureRegistry.monitor.Start()
		}
	}
	return nil
}

func (s *Service) Close() error {
	s.stopTimer()
	if s.timerConfig.policyMode == policyModeNetworkExtension {
		if globalPressureRegistry.remove(s) {
			globalPressureRegistry.monitor.Stop()
		}
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
