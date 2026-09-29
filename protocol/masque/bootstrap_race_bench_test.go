package masque

import (
	"net/netip"
	"strconv"
	"testing"
)

// Benchmark for the bootstrap racer's candidate ORDERING helper.
//
// # Why there is no benchmark of the racer itself
//
// The racer's own orchestration cannot be measured honestly without a real QUIC connection.
// awaitHandshake calls quicConn.HandshakeComplete() and quicConn.Context(), so a stub connector
// cannot stand in for the connection it returns -- a fake *quic.Conn is a nil dereference, which is
// what an earlier attempt at this benchmark discovered the hard way.
//
// Building a real one would measure quic-go's handshake, not this package's orchestration, and the
// orchestration runs ONCE per connection rather than per packet. So it is not a hot path, and the
// useful thing to pin is the helper that runs once per connection and is a pure function over the
// candidate list.
//
// interleaveCandidates is worth a number because it is trivially measurable and a change that made
// it quadratic would otherwise surface only as a mysterious connection-establishment delay.

// benchRacerCandidates builds a dual-stack candidate list of the requested size, alternating
// families so the interleaving is exercised rather than a single run.
func benchRacerCandidates(count int) []netip.Addr {
	candidates := make([]netip.Addr, 0, count)
	for index := range count {
		if index%2 == 0 {
			candidates = append(candidates, netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}))
		} else {
			candidates = append(candidates, netip.AddrFrom16(
				[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(index + 1)}))
		}
	}
	return candidates
}

// BenchmarkInterleaveCandidates measures the ordering helper, which runs once per connection.
//
// It is included because it is a pure function over the candidate list and its cost is trivial to
// measure, so a change that made it quadratic would be visible immediately rather than showing up
// as a mysterious connection-establishment delay.
func BenchmarkInterleaveCandidates(b *testing.B) {
	for _, count := range []int{2, 4, 16, 64} {
		b.Run("candidates"+strconv.Itoa(count), func(b *testing.B) {
			candidates := benchRacerCandidates(count)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = interleaveCandidates(candidates, true)
			}
		})
	}
}
