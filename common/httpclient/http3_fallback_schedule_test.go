//go:build with_quic

package httpclient

import (
	"strconv"
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
	// The entry is deliberately retained after expiry so the escalation history
	// survives; it is reclaimed later by bounded cleanup, not by the read path.
	// See TestHTTP3ScheduleEscalationSurvivesExpiry.
	if _, found := transport.broken["a.example:443"]; !found {
		t.Fatal("an expired entry must be retained so its escalation is not lost")
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

// TestHTTP3ScheduleEscalationSurvivesExpiry is the P0 regression for the generic
// transport.
//
// h3Broken() used to delete the entry when the window expired, which discarded
// the escalation counter as well. A serial
// failure -> wait for expiry -> retry -> failure sequence therefore restarted at
// initial_backoff instead of continuing to grow, so a flapping server never
// escalated. The window and the escalation are now separate: expiry only ends the
// window.
func TestHTTP3ScheduleEscalationSurvivesExpiry(t *testing.T) {
	schedule := option.HTTP3FallbackSchedule{
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Multiplier:     2,
		ResetOnSuccess: true,
	}
	transport := newScheduleTransport(schedule)

	// Failure 1 -> 5s.
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 5*time.Second {
		t.Fatalf("first failure must be 5s, got %v", got)
	}

	// Let the window expire by rewinding the recorded deadline rather than
	// sleeping, so the test is deterministic and instant.
	expireEntry(transport, "a.example:443")
	if transport.h3Broken("a.example:443") {
		t.Fatal("an expired window must not block HTTP/3")
	}

	// Failure 2 after expiry -> 10s, not 5s again.
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 10*time.Second {
		t.Fatalf("a failure after expiry must escalate to 10s, got %v", got)
	}

	expireEntry(transport, "a.example:443")
	transport.markH3Broken("a.example:443")
	if got := transport.broken["a.example:443"].backoff; got != 20*time.Second {
		t.Fatalf("the escalation must continue to 20s, got %v", got)
	}
}

// TestHTTP3ScheduleExpiredEntryIsReclaimedWithoutLosingEscalation covers the
// cleanup half: expired entries must eventually be reclaimed so the map cannot
// grow without bound, but reclamation must not be the thing that resets a live
// escalation.
func TestHTTP3ScheduleExpiredEntryIsReclaimedWithoutLosingEscalation(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())

	// Fill the map to its cap with entries that are long expired AND untouched
	// beyond the retention window, which is what makes them reclaimable.
	old := time.Now().Add(-2 * time.Hour)
	transport.brokenAccess.Lock()
	for index := range maxTrackedAuthorities {
		authority := "bulk-" + strconv.Itoa(index) + ".example:443"
		transport.broken[authority] = http3BrokenEntry{
			backoff: 5 * time.Second,
			until:   old,
			seen:    old,
		}
	}
	transport.brokenAccess.Unlock()

	if count := len(transport.broken); count != maxTrackedAuthorities {
		t.Fatalf("precondition: expected a full map, got %d", count)
	}

	// A new authority must be admitted, which requires reclamation to run.
	transport.markH3Broken("fresh.example:443")

	transport.brokenAccess.Lock()
	remaining := len(transport.broken)
	_, freshPresent := transport.broken["fresh.example:443"]
	transport.brokenAccess.Unlock()

	if !freshPresent {
		t.Fatal("a new authority must be admitted once stale entries are reclaimed")
	}
	if remaining > maxTrackedAuthorities {
		t.Fatalf("the map must stay bounded, got %d entries", remaining)
	}
}

// TestHTTP3ScheduleRecentlyExpiredEntryKeepsEscalation proves cleanup is
// conservative: an entry that just expired must not be reclaimed, because its
// escalation may still be needed.
func TestHTTP3ScheduleRecentlyExpiredEntryKeepsEscalation(t *testing.T) {
	transport := newScheduleTransport(jiejieSchedule())
	transport.markH3Broken("keep.example:443")
	transport.markH3Broken("keep.example:443")

	// Expire the window but keep `seen` recent.
	transport.brokenAccess.Lock()
	entry := transport.broken["keep.example:443"]
	entry.until = time.Now().Add(-time.Second)
	entry.seen = time.Now()
	transport.broken["keep.example:443"] = entry
	transport.brokenAccess.Unlock()

	if transport.h3Broken("keep.example:443") {
		t.Fatal("the window is expired, so HTTP/3 must be available again")
	}
	// The entry escalated 5s -> 10s, so the next failure is 20s.
	transport.markH3Broken("keep.example:443")
	if got := transport.broken["keep.example:443"].backoff; got != 20*time.Second {
		t.Fatalf("a recently expired entry must keep escalating (10s -> 20s), got %v", got)
	}
}

// expireEntry rewinds an entry's deadline into the past so expiry can be tested
// without sleeping for a production-length backoff.
func expireEntry(transport *http3FallbackTransport, authority string) {
	transport.brokenAccess.Lock()
	defer transport.brokenAccess.Unlock()
	entry, found := transport.broken[authority]
	if !found {
		return
	}
	entry.until = time.Now().Add(-time.Second)
	transport.broken[authority] = entry
}
