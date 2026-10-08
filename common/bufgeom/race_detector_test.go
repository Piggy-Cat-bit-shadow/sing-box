//go:build race

package bufgeom

// raceDetectorEnabled reports whether this test binary was built with -race.
//
// # Why allocation measurements cannot be asserted under the race detector
//
// The race detector instruments every allocation with its own shadow memory and bookkeeping, so the
// bytes the runtime reports are not the program's. Measured here, a pooled buf.Get/Put cycle - which
// cannot allocate a payload at all, because it is a sync.Pool hand-off - reported 8251 bytes per
// acquire under -race against 1.7 bytes without it. That is instrument memory, and asserting a byte
// ceiling against it would fail for a reason that has nothing to do with buffers.
//
// Loosening the ceiling to accommodate the instrument would be worse: the ceiling exists to sit far
// below the smallest shipped buffer size, and a ceiling large enough for the race detector's shadow
// could not distinguish a pooled buffer from a reallocated 8 KiB one. So the byte ceiling is
// asserted only in non-race builds, while the STRUCTURAL half of the contract
// (TestGeometryBuffersAreExactlyPoolable, which drives the real allocator and requires Put to
// accept the buffer back) runs under both.
//
// This is a build-tag split rather than a runtime check because Go exposes no supported way to ask
// the race detector whether it is active, and inventing one would be less reliable than the tag the
// toolchain itself sets.
const raceDetectorEnabled = true
