package route

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Phase 2B.0: the scheduler gate must not hide traffic counters.
//
// # The hazard
//
// The gate must be non-replaceable, or the copy engine unwraps straight past it and the scheduler
// never runs (commit 940660d5a). But N.UnwrapCountWriter stops at exactly that shape:
//
//	if counter, isCounter := writer.(WriteCounter); isCounter { ...unwrap... }
//	if u, ok := writer.(WriterWithUpstream); !ok || !u.WriterReplaceable() {
//	    return writer, countFunc        // <-- stops here
//	}
//
// So a non-replaceable gate placed OUTSIDE the counters terminates the walk before the counters are
// discovered. Data still flows, which is what makes it dangerous: Clash/API accounting, byte
// counters and tracker-visible bytes would silently read zero while everything appears to work.
//
// # The fix
//
// Extract the counters from the real destination FIRST, gate only the counter-stripped base, and
// expose the extracted funcs through a WriteCounter whose UnwrapWriter returns the GATE - never the
// pre-gate writer. One unwrap pass then yields destination=gate, counters=funcs: the counters are
// visible, the gate stays in the write path, nothing is double counted, and the recursion terminates
// because the returned writer is the non-replaceable gate, not the adapter.

type countingSink struct {
	received int64
	counted  atomic.Int64
}

func (s *countingSink) Write(p []byte) (int, error) {
	s.received += int64(len(p))
	return len(p), nil
}

func (s *countingSink) WriteBuffer(buffer *buf.Buffer) error {
	s.received += int64(buffer.Len())
	buffer.Release()
	return nil
}

func (s *countingSink) countFunc() N.CountFunc {
	return func(n int64) { s.counted.Add(n) }
}

type countWriter struct {
	upstream N.ExtendedWriter
	count    N.CountFunc
}

func (w *countWriter) Write(p []byte) (int, error) { return w.upstream.Write(p) }

func (w *countWriter) WriteBuffer(buffer *buf.Buffer) error {
	return w.upstream.WriteBuffer(buffer)
}

func (w *countWriter) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return w.upstream, []N.CountFunc{w.count}
}

type nonReplaceableGate struct {
	upstream N.ExtendedWriter
	writes   atomic.Int64
}

func (g *nonReplaceableGate) Write(p []byte) (int, error) {
	g.writes.Add(1)
	return g.upstream.Write(p)
}

// WriteBuffer forwards ownership: the upstream ExtendedWriter releases the buffer.
func (g *nonReplaceableGate) WriteBuffer(buffer *buf.Buffer) error {
	g.writes.Add(1)
	return g.upstream.WriteBuffer(buffer)
}

func (g *nonReplaceableGate) WriterReplaceable() bool { return false }

func (g *nonReplaceableGate) UpstreamWriter() io.Writer { return g.upstream }

type counterPreservingAdapter struct {
	gate  *nonReplaceableGate
	funcs []N.CountFunc
}

func (a *counterPreservingAdapter) Write(p []byte) (int, error) { return a.gate.Write(p) }

func (a *counterPreservingAdapter) WriteBuffer(buffer *buf.Buffer) error {
	return a.gate.WriteBuffer(buffer)
}

func (a *counterPreservingAdapter) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return a.gate, a.funcs
}

var (
	_ N.WriteCounter       = (*countWriter)(nil)
	_ N.WriteCounter       = (*counterPreservingAdapter)(nil)
	_ N.ExtendedWriter     = (*countingSink)(nil)
	_ N.ExtendedWriter     = (*countWriter)(nil)
	_ N.ExtendedWriter     = (*nonReplaceableGate)(nil)
	_ N.WriterWithUpstream = (*nonReplaceableGate)(nil)
)

func newCountingDestination(t *testing.T) (*countingSink, *countWriter) {
	t.Helper()
	sink := &countingSink{}
	return sink, &countWriter{upstream: sink, count: sink.countFunc()}
}

// TestSchedulerGateOutsideCountersHidesThem is the FAILING case this phase exists to prevent.
func TestSchedulerGateOutsideCountersHidesThem(t *testing.T) {
	sink, counted := newCountingDestination(t)
	gate := &nonReplaceableGate{upstream: counted}

	destination, counters := N.UnwrapCountWriter(gate, nil)

	require.Empty(t, counters,
		"a non-replaceable gate outside the counters terminates the unwrap, so the counters "+
			"behind it are never discovered - this is the accounting loss the gate must avoid")
	require.Same(t, gate, destination,
		"and the walk stops at the gate, which is what keeps the scheduler in the path")

	written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.EqualValues(t, len("payload"), sink.received, "bytes did arrive")
	require.Zero(t, sink.counted.Load(),
		"but the accounting stayed at zero: data flows while the counters silently read nothing")
}

// TestCounterPreservingAdapterKeepsCountersAndGate is the fix.
func TestCounterPreservingAdapterKeepsCountersAndGate(t *testing.T) {
	sink, counted := newCountingDestination(t)

	base, funcs := N.UnwrapCountWriter(counted, nil)
	require.NotEmpty(t, funcs, "precondition: the real destination exposes counters")

	gate := &nonReplaceableGate{upstream: base.(N.ExtendedWriter)}
	adapter := &counterPreservingAdapter{gate: gate, funcs: funcs}

	destination, counters := N.UnwrapCountWriter(adapter, nil)

	require.Same(t, gate, destination,
		"the engine must still write THROUGH the gate, or the scheduler would be bypassed")
	require.Len(t, counters, len(funcs), "and the counters must be visible to the engine")

	const payload = "payload"
	written, err := bufio.CopyWithIncreateBuffer(adapter, strings.NewReader(payload), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len(payload), written)
	require.EqualValues(t, len(payload), sink.received, "bytes arrived")
	require.EqualValues(t, len(payload), sink.counted.Load(),
		"counted exactly once: not skipped, not doubled")
	require.Positive(t, gate.writes.Load(),
		"the gate observed the write, so the scheduler is in the path rather than bypassed")
}

// TestAdapterDoesNotUnwrapItselfAway guards the failure mode where the fix reintroduces the bypass.
func TestAdapterDoesNotUnwrapItselfAway(t *testing.T) {
	_, counted := newCountingDestination(t)
	base, funcs := N.UnwrapCountWriter(counted, nil)
	gate := &nonReplaceableGate{upstream: base.(N.ExtendedWriter)}
	adapter := &counterPreservingAdapter{gate: gate, funcs: funcs}

	destination, _ := N.UnwrapCountWriter(adapter, nil)

	require.NotSame(t, counted, destination,
		"the unwrap must not reach the pre-gate counter wrapper, or the gate is bypassed")
	require.Same(t, gate, destination)
	require.False(t, destination.(N.WriterWithUpstream).WriterReplaceable(),
		"and the gate must remain non-replaceable so a second unwrap cannot pass it either")
}
