package sniff_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/stretchr/testify/require"
)

// FuzzPeekPacket drives the production packet plan with arbitrary datagrams.
//
// The four properties the sniffers owe their callers are all checked by not being violated: no
// panic, no out-of-bounds read, no unbounded loop (a datagram is scanned once, and the run
// deadline catches a parser that forgets that), and no allocation proportional to anything but the
// input. The seeds are the shapes the collision corpus cares about, because a fuzzer that starts
// from noise rarely reaches a valid WireGuard header or a STUN cookie on its own.
func FuzzPeekPacket(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},
		{0x00, 0x00},
		make([]byte, 12),
		make([]byte, 20),
		make([]byte, 48),
		make([]byte, 64),
		bytesOfValue(0xFF, 64),
		buildDNSQuery(),
		buildSTUNMessage(0),
		buildSTUNMessage(64),
		buildNTPRequest(),
		buildUDPTrackerConnect(),
		wireGuardMessage(1, 148),
		wireGuardMessage(2, 92),
		wireGuardMessage(3, 64),
		wireGuardMessage(4, 32),
		quicInitial,
		quicInitial[:5],
		quicInitial[:21],
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 1<<16 {
			t.Skip()
		}
		metadata := adapter.InboundContext{}
		err := sniff.PeekPacket(context.Background(), &metadata, packet, sniff.DefaultPacketSniffers...)
		if err == nil {
			require.NotEmpty(t, metadata.Protocol)
		}
	})
}

// FuzzPacketSnifferParsers runs each datagram parser on its own, so a failure points at the parser
// rather than at the plan, and so the parsers that the plan stops before ever reaching are covered
// too.
func FuzzPacketSnifferParsers(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x00},
		make([]byte, 12),
		make([]byte, 20),
		make([]byte, 64),
		bytesOfValue(0xFF, 64),
		buildDNSQuery(),
		buildSTUNMessage(0),
		buildNTPRequest(),
		buildUDPTrackerConnect(),
		wireGuardMessage(1, 148),
		quicInitial,
	} {
		f.Add(seed)
	}
	parsers := map[string]sniff.PacketSniffer{
		"dns":        sniff.DomainNameQuery,
		"quic":       sniff.QUICClientHello,
		"stun":       sniff.STUNMessage,
		"wireguard":  sniff.WireGuard,
		"utp":        sniff.UTP,
		"udptracker": sniff.UDPTracker,
		"dtls":       sniff.DTLSRecord,
		"ntp":        sniff.NTP,
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 1<<16 {
			t.Skip()
		}
		for name, parser := range parsers {
			metadata := adapter.InboundContext{}
			err := parser(context.Background(), &metadata, packet)
			if err == nil {
				require.NotEmpty(t, metadata.Protocol, name)
			}
		}
	})
}

// FuzzStreamSnifferPrefixes runs each stream parser over arbitrary bytes. It is a prefix fuzzer in
// the sense that matters here: the parsers all read from the front and are expected to fail fast on
// a wrong first byte, so the interesting inputs are the ones that get past the first check.
func FuzzStreamSnifferPrefixes(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x16},
		{0x16, 0x03, 0x01, 0x00, 0x00},
		[]byte("GET / HTTP/1.1\r\nHost: fuzz.example.com\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		mustHex("001e740701000001000000000000012a06676f6f676c6503636f6d0000010001"),
		{19},
		{19, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't'},
		{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0},
		bytesOfValue(0xFF, 64),
	} {
		f.Add(seed)
	}
	parsers := map[string]sniff.StreamSniffer{
		"tls":        sniff.TLSClientHello,
		"http":       sniff.HTTPHost,
		"dns":        sniff.StreamDomainNameQuery,
		"bittorrent": sniff.BitTorrent,
		"ssh":        sniff.SSH,
		"rdp":        sniff.RDP,
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<16 {
			t.Skip()
		}
		for _, parser := range parsers {
			metadata := adapter.InboundContext{}
			_ = parser(context.Background(), &metadata, bytes.NewReader(payload))
		}
	})
}

// TestSniffDoesNotAllocateForItsInputSize is the "no giant allocation from a tiny input" guard,
// measured with the benchmark harness rather than with runtime.MemStats, because the number that
// matters is bytes per call and MemStats cannot separate that from the harness's own work.
//
// The bound is loose on purpose. A one byte datagram is rejected by all eight parsers out of the
// default plan and pays for the aggregate that records why, which is a couple of kilobytes; what
// this catches is an allocation that scales with a length field read out of the input instead of
// with the input itself.
func TestSniffDoesNotAllocateForItsInputSize(t *testing.T) {
	t.Parallel()
	tinyPacket := []byte{0x00}
	packetResult := testing.Benchmark(func(b *testing.B) {
		metadata := adapter.InboundContext{}
		for i := 0; i < b.N; i++ {
			_ = sniff.PeekPacket(context.Background(), &metadata, tinyPacket, sniff.DefaultPacketSniffers...)
		}
	})
	require.Less(t, packetResult.AllocedBytesPerOp(), int64(16<<10),
		"a one byte datagram allocated %d bytes per call", packetResult.AllocedBytesPerOp())

	// A stream DNS length prefix is a sixteen bit field, so the reader the parser builds for the
	// body it was promised is bounded by 64KiB and taken from the buffer pool. It must not be
	// treated as an unbounded allocation, and it must not exceed that bound either.
	hugeLength := mustHex("ffff")
	streamResult := testing.Benchmark(func(b *testing.B) {
		metadata := adapter.InboundContext{}
		for i := 0; i < b.N; i++ {
			_ = sniff.StreamDomainNameQuery(context.Background(), &metadata, bytes.NewReader(hugeLength))
		}
	})
	require.Less(t, streamResult.AllocedBytesPerOp(), int64(1<<17),
		"a two byte stream with a 65535 byte length prefix allocated %d bytes per call", streamResult.AllocedBytesPerOp())
}
