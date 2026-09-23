//go:build with_quic

package httpclient

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func newScheduleTransport(schedule option.HTTP3FallbackSchedule) *http3FallbackTransport {
	return &http3FallbackTransport{
		schedule: schedule,
		broken:   make(map[string]http3BrokenEntry),
	}
}

// jiejieSchedule is the recommended server-edition schedule.
func jiejieSchedule() option.HTTP3FallbackSchedule {
	return option.HTTP3FallbackSchedule{
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Multiplier:     2,
		ResetOnSuccess: true,
	}
}

func TestHTTP3ScheduleUpstreamDefaults(t *testing.T) {
	// An absent http3_fallback object must reproduce upstream semantics.
	var options *option.HTTP3FallbackOptions
	schedule := options.Build()
	if schedule.InitialBackoff != 5*time.Minute {
		t.Fatalf("upstream initial backoff must stay 5m, got %v", schedule.InitialBackoff)
	}
	if schedule.MaxBackoff != 48*time.Hour {
		t.Fatalf("upstream max backoff must stay 48h, got %v", schedule.MaxBackoff)
	}
	if schedule.Multiplier != 2 {
		t.Fatalf("upstream multiplier must stay 2, got %v", schedule.Multiplier)
	}
	if !schedule.ResetOnSuccess {
		t.Fatal("upstream resets the backoff after a successful HTTP/3 round trip")
	}
}

func TestHTTP3ScheduleFirstFailure(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 5*time.Second {
		t.Fatalf("first failure must use initial_backoff 5s, got %v", got)
	}
}

func TestHTTP3ScheduleExponentialGrowth(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	expected := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		5 * time.Minute, // 320s clamped to the 5m cap
		5 * time.Minute,
	}
	for index, want := range expected {
		transport.markH3Broken("a.example:443")
		if got := transport.broken["a.example:443"].backoff; got != want {
			t.Fatalf("mark #%d: got %v, want %v", index+1, got, want)
		}
	}
}

func TestHTTP3ScheduleMaximumCap(t *testing.T) {
	schedule := jiejieSchedule()
	if got := schedule.Next(10 * time.Minute); got != 5*time.Minute {
		t.Fatalf("backoff must clamp to max_backoff, got %v", got)
	}
	// A very large current value must not overflow into a negative duration.
	if got := schedule.Next(time.Duration(1) << 62); got != 5*time.Minute {
		t.Fatalf("overflow must clamp to max_backoff, got %v", got)
	}
}

func TestHTTP3ScheduleExpiry(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.broken["a.example:443"] = http3BrokenEntry{
		backoff: 5 * time.Second,
		until:   time.Now().Add(-time.Millisecond),
	}
	if transport.h3Broken("a.example:443") {
		t.Fatal("an expired entry must not report broken")
	}
	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("an expired entry must be evicted on read")
	}
}

func TestHTTP3ScheduleActiveEntry(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.markH3Broken("a.example:443")
	if !transport.h3Broken("a.example:443") {
		t.Fatal("a freshly marked authority must report broken")
	}
}

func TestHTTP3ScheduleResetOnSuccess(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.markH3Broken("a.example:443")
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 10*time.Second {
		t.Fatalf("precondition: expected 10s, got %v", got)
	}
	transport.clearH3Broken("a.example:443")
	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("a successful HTTP/3 round trip must clear the broken entry")
	}
	// The escalation must restart from initial_backoff, not resume at 20s.
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 5*time.Second {
		t.Fatalf("after reset the schedule must restart at 5s, got %v", got)
	}
}

func TestHTTP3ScheduleResetDisabledKeepsCounter(t *testing.T) {
	schedule := jiejieSchedule()
	schedule.ResetOnSuccess = false
	transport := newScheduleTransport(schedule)
	transport.markH3Broken("a.example:443")
	transport.clearH3Broken("a.example:443")
	if _, found := transport.broken["a.example:443"]; !found {
		t.Fatal("reset_on_success=false must preserve the escalation counter")
	}
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 10*time.Second {
		t.Fatalf("escalation must continue at 10s, got %v", got)
	}
}

func TestHTTP3ScheduleAuthorityIsolation(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	for range 3 {
		transport.markH3Broken("a.example:443")
	}
	if got := transport.broken["a.example:443"].backoff; got != 20*time.Second {
		t.Fatalf("a.example should be at 20s, got %v", got)
	}
	transport.markH3Broken("b.example:443")
	if got := transport.broken["b.example:443"].backoff; got != 5*time.Second {
		t.Fatalf("b.example must start its own schedule at 5s, got %v", got)
	}
	transport.clearH3Broken("a.example:443")
	if !transport.h3Broken("b.example:443") {
		t.Fatal("clearing a.example must not affect b.example")
	}
}

func TestHTTP3ScheduleEmptyAuthorityNoOp(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.markH3Broken("")
	transport.clearH3Broken("")
	if len(transport.broken) != 0 {
		t.Fatalf("empty authority must be a no-op, got %d entries", len(transport.broken))
	}
	if transport.h3Broken("") {
		t.Fatal("empty authority must never report broken")
	}
}

func TestHTTP3ScheduleConcurrentAccess(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	const (
		workers    = 16
		iterations = 200
	)
	var waitGroup sync.WaitGroup
	for worker := range workers {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			authority := "a.example:443"
			if worker%2 == 1 {
				authority = "b.example:443"
			}
			for range iterations {
				transport.markH3Broken(authority)
				transport.h3Broken(authority)
				if worker%4 == 0 {
					transport.clearH3Broken(authority)
				}
			}
		}(worker)
	}
	waitGroup.Wait()

	// The map must contain only the two authorities that were actually used,
	// and every surviving entry must respect the configured cap.
	if len(transport.broken) > 2 {
		t.Fatalf("unexpected entry count: %d", len(transport.broken))
	}
	for authority, entry := range transport.broken {
		if entry.backoff > 5*time.Minute {
			t.Fatalf("%s: backoff %v exceeds the 5m cap", authority, entry.backoff)
		}
		if entry.backoff < 5*time.Second {
			t.Fatalf("%s: backoff %v below initial_backoff", authority, entry.backoff)
		}
	}
}

func TestHTTP3SchedulePartialOptionKeepsUpstreamForUnsetFields(t *testing.T) {
	reset := true
	schedule := (&option.HTTP3FallbackOptions{
		InitialBackoff: badoption.Duration(5 * time.Second),
		ResetOnSuccess: &reset,
	}).Build()
	if schedule.InitialBackoff != 5*time.Second {
		t.Fatalf("explicit initial_backoff must be honoured, got %v", schedule.InitialBackoff)
	}
	if schedule.MaxBackoff != 48*time.Hour {
		t.Fatalf("unset max_backoff must fall back to the upstream 48h, got %v", schedule.MaxBackoff)
	}
	if schedule.Multiplier != 2 {
		t.Fatalf("unset multiplier must fall back to 2, got %v", schedule.Multiplier)
	}
}

func TestHTTP3ScheduleResetOnSuccessAbsentDefaultsTrue(t *testing.T) {
	schedule := (&option.HTTP3FallbackOptions{InitialBackoff: badoption.Duration(time.Second)}).Build()
	if !schedule.ResetOnSuccess {
		t.Fatal("an absent reset_on_success must default to true")
	}
	disabled := false
	schedule = (&option.HTTP3FallbackOptions{ResetOnSuccess: &disabled}).Build()
	if schedule.ResetOnSuccess {
		t.Fatal("an explicit reset_on_success=false must be honoured")
	}
}

func TestHTTP3ScheduleMaxBelowInitialIsClamped(t *testing.T) {
	reset := true
	schedule := (&option.HTTP3FallbackOptions{
		InitialBackoff: badoption.Duration(60 * time.Second),
		MaxBackoff:     badoption.Duration(5 * time.Second),
		ResetOnSuccess: &reset,
	}).Build()
	if schedule.MaxBackoff != 60*time.Second {
		t.Fatalf("max_backoff below initial_backoff must be clamped up, got %v", schedule.MaxBackoff)
	}
}
