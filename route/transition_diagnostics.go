package route

import (
	"fmt"
	"sync/atomic"
)

// Transition and drain diagnostics.
//
// # What this is for
//
// The network lifecycle work claims that a path change no longer terminates the streams the device
// is running. That claim is only worth anything if a real-device run can show the difference, and
// until this existed there was nothing to read: a transition either killed everything (before) or
// did not (after), and neither left a trace that outlived the log line announcing it.
//
// # What these numbers do and do not say
//
// They answer "of the transitions this tunnel saw, how many connections were left running and how
// many were reclaimed, at the transition and later by the sweep". They cannot say whether a drained
// connection went on to succeed - a connection that drains and then fails on its own looks exactly
// like one that drained and finished. That distinction belongs to the stream, not to the manager,
// and inventing a counter for it here would be a number a report could not defend.
//
// # Cost
//
// One atomic add per transition and one per reclaim PASS, never per byte, per connection read or
// per write. A transition is a rare event and a reclaim pass is rarer still, so this adds nothing
// measurable to the forwarding path it exists to describe.

type transitionDiagnostics struct {
	// transitions counts network transitions that ran a reset body.
	transitions atomic.Uint64
	// oldGenerationSeen counts the connections a transition's scan found belonging to the path it
	// was leaving. Drained and reclaimedAtTransition partition it, so the three should add up.
	oldGenerationSeen atomic.Uint64
	// drained counts connections that were alive when a transition ran and were deliberately left
	// running. This is the number the whole change is about.
	drained atomic.Uint64
	// reclaimedAtTransition counts connections that were already provably idle and went during the
	// transition itself.
	reclaimedAtTransition atomic.Uint64
	// reclaimedBySweep counts connections that were still working at the transition and were
	// reclaimed later, once they fell silent. Together with the field above it is every connection a
	// transition ever closed, and the split is what shows the drain doing its job.
	reclaimedBySweep atomic.Uint64
	// sweeps counts sweep passes that reclaimed something, so a reader can tell "the sweep finished"
	// from "the sweep never ran".
	sweeps atomic.Uint64
}

func (d *transitionDiagnostics) recordTransition(drained, reclaimed, seen int) {
	d.transitions.Add(1)
	if seen > 0 {
		d.oldGenerationSeen.Add(uint64(seen))
	}
	if drained > 0 {
		d.drained.Add(uint64(drained))
	}
	if reclaimed > 0 {
		d.reclaimedAtTransition.Add(uint64(reclaimed))
	}
}

func (d *transitionDiagnostics) recordSweep(reclaimed int) {
	if reclaimed <= 0 {
		return
	}
	d.sweeps.Add(1)
	d.reclaimedBySweep.Add(uint64(reclaimed))
}

// TransitionSnapshot is an immutable view of the transition and drain diagnostics.
type TransitionSnapshot struct {
	// Transitions is the number of transitions that ran a reset body.
	Transitions uint64
	// OldGenerationSeen is the number of connections those transitions found on the path they were
	// leaving. Drained + ReclaimedAtTransition partition it.
	OldGenerationSeen uint64
	// Drained is the number of connections left running by those transitions.
	Drained uint64
	// ReclaimedAtTransition is the number already idle when the transition ran.
	ReclaimedAtTransition uint64
	// ReclaimedBySweep is the number that fell silent afterwards and were reclaimed later.
	ReclaimedBySweep uint64
	// Sweeps is the number of sweep passes that reclaimed at least one connection.
	Sweeps uint64
}

// Reclaimed is every connection a transition closed, however long it took.
func (s TransitionSnapshot) Reclaimed() uint64 {
	return s.ReclaimedAtTransition + s.ReclaimedBySweep
}

// DrainRatio is the share of transition-affected connections that were allowed to continue, or 0
// with no transitions. It is the one number that says whether the drain is doing anything: a
// transition that reclaims everything is the old behaviour wearing a new name.
func (s TransitionSnapshot) DrainRatio() float64 {
	total := s.Drained + s.ReclaimedAtTransition
	if total == 0 {
		return 0
	}
	return float64(s.Drained) / float64(total)
}

// TransitionSummary is one line, written once per tunnel lifetime, in the same shape as the splice
// summaries. A real-device run needs no instrumentation: start the tunnel, change networks a few
// times, stop it, read one line.
func (s TransitionSnapshot) TransitionSummary() string {
	return fmt.Sprintf(
		"network transitions: %d, old-generation seen %d, drained %d, reclaimed %d at the transition and %d by sweep (%d sweep(s), drain ratio %.2f)",
		s.Transitions, s.OldGenerationSeen, s.Drained, s.ReclaimedAtTransition, s.ReclaimedBySweep, s.Sweeps, s.DrainRatio())
}

// TransitionDiagnostics returns the current transition and drain diagnostics.
//
// Reading it is a handful of atomic loads and has no effect on forwarding.
func (m *ConnectionManager) TransitionDiagnostics() TransitionSnapshot {
	return TransitionSnapshot{
		Transitions:           m.transitions.transitions.Load(),
		OldGenerationSeen:     m.transitions.oldGenerationSeen.Load(),
		Drained:               m.transitions.drained.Load(),
		ReclaimedAtTransition: m.transitions.reclaimedAtTransition.Load(),
		ReclaimedBySweep:      m.transitions.reclaimedBySweep.Load(),
		Sweeps:                m.transitions.sweeps.Load(),
	}
}
