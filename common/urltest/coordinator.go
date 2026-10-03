package urltest

import (
	"context"

	"github.com/sagernet/sing/service"
)

// Coordinator bounds how many measurements one Box may have in flight.
//
// # Why a Box-wide bound is needed
//
// Each URLTest batch already limits itself to ten concurrent probes, but that limit is per batch.
// A configuration with several URLTest groups - or a group plus Clash delay probes plus a manual
// refresh - can therefore run several times ten measurements at once. On a phone running inside a
// NetworkExtension with roughly 50 MiB of budget, each measurement holding a socket, a TLS session
// and buffers, that is the difference between a check that fits and one that is killed.
//
// # Why it is per Box and not a package global
//
// A process can hold more than one Box at a time: the running one, a temporary Box built to validate
// a new configuration, and test instances. A global limiter would make those compete, so validating
// a configuration could stall the live one, and a leaked temporary Box would permanently consume
// slots. The limit belongs to whichever Box is doing the measuring, so it is carried on that Box's
// context.
type Coordinator struct {
	slots chan struct{}
}

// NewCoordinator returns a coordinator allowing limit concurrent measurements.
//
// A non-positive limit disables coordination rather than blocking every measurement, because a
// limit of zero is more likely to be a misconfiguration than a request to measure nothing.
func NewCoordinator(limit int) *Coordinator {
	if limit <= 0 {
		return &Coordinator{}
	}
	return &Coordinator{slots: make(chan struct{}, limit)}
}

// Acquire reserves one measurement slot, or fails if ctx is done first.
//
// The returned function must be called exactly once; it is what returns the slot. Waiting honours
// cancellation, so a measurement that cannot start before its own deadline does not hold a
// goroutine or a slot while it waits to find that out.
func (c *Coordinator) Acquire(ctx context.Context) (func(), error) {
	if c == nil || c.slots == nil {
		return func() {}, nil
	}
	select {
	case c.slots <- struct{}{}:
		// The release closure holds a plain bool, NOT an atomic.
		//
		// That is correct because the closure is called by the goroutine that acquired it - Measure
		// defers it immediately, and it is the only caller. An atomic would suggest a cross-goroutine
		// release is supported, which it is not: if one were ever introduced, the guard would need to
		// become atomic AND the slot ownership would need rethinking, because freeing a slot from
		// another goroutine says nothing about which measurement finished.
		//
		// The guard exists so a double call cannot free a slot twice, which would hand it to a second
		// measurement while the first still believed it owned it.
		var released bool
		return func() {
			if released {
				return
			}
			released = true
			<-c.slots
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// InFlight reports how many slots are currently held. It exists for tests and diagnostics.
func (c *Coordinator) InFlight() int {
	if c == nil || c.slots == nil {
		return 0
	}
	return len(c.slots)
}

// Limit reports the configured bound, or zero when coordination is disabled.
func (c *Coordinator) Limit() int {
	if c == nil || c.slots == nil {
		return 0
	}
	return cap(c.slots)
}

// ContextWithCoordinator attaches a coordinator to a Box context.
//
// It is stored by pointer under its own type, so it needs no lifecycle and takes no part in service
// startup. It owns no goroutines and has nothing to close: its whole state is a buffered channel of
// outstanding slots.
func ContextWithCoordinator(ctx context.Context, coordinator *Coordinator) context.Context {
	return service.ContextWithPtr(ctx, coordinator)
}

// CoordinatorFromContext returns the Box's measurement coordinator, or nil when there is none.
//
// A nil result means "unbounded", which is the correct behaviour for an isolated unit test or a
// library caller that never built a Box. It deliberately does NOT fall back to a package-level
// limiter: that would reintroduce the cross-Box coupling the per-Box design exists to avoid.
func CoordinatorFromContext(ctx context.Context) *Coordinator {
	return service.PtrFromContext[Coordinator](ctx)
}
