package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
)

// These benchmarks run the plans the router runs, taken from the package that defines them, so a
// change to a plan shows up here as a different measurement rather than as a benchmark of a list
// nobody uses.

// benchmarkPeekStream drives PeekStream over an in-memory connection.
//
// cachedCount splits the payload the way a flow with earlier cached buffers is shaped: the first
// cachedCount segments arrive as already-cached *buf.Buffer values, the last comes from the
// connection. chunkCount then splits that last segment into the reads the connection hands back,
// which is what forces the retry loop to run.
func benchmarkPeekStream(b *testing.B, payload []byte, chunkCount int, cachedCount int, wantError bool) {
	b.Helper()
	var cached []*buf.Buffer
	if cachedCount > 0 {
		segments := splitChunks(payload, cachedCount+1)
		for _, segment := range segments[:cachedCount] {
			cached = append(cached, buf.As(segment))
		}
		payload = segments[cachedCount]
	}
	var chunks [][]byte
	if chunkCount <= 1 {
		chunks = [][]byte{payload}
	} else {
		chunks = splitChunks(payload, chunkCount)
	}
	conn := &scriptedConn{chunks: chunks}
	metadata := adapter.InboundContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetSniffResult(&metadata)
		conn.reset()
		sniffBuffer := buf.NewPacket()
		err := sniff.PeekStream(
			context.Background(),
			&metadata,
			conn,
			cached,
			sniffBuffer,
			0,
			sniff.DefaultStreamSniffers...,
		)
		if wantError {
			if err == nil {
				b.Fatal("expected every sniffer to reject the payload")
			}
		} else if err != nil {
			b.Fatal("sniff failed: ", err)
		}
		sniffBuffer.Release()
	}
}

func BenchmarkPeekStreamTLS(b *testing.B) {
	benchmarkPeekStream(b, captureClientHello(b, &tls.Config{ServerName: "www.example.com"}), 1, 0, false)
}

func BenchmarkPeekStreamHTTP(b *testing.B) {
	benchmarkPeekStream(b, []byte("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n"), 1, 0, false)
}

func BenchmarkPeekStreamDNS(b *testing.B) {
	benchmarkPeekStream(b, mustHex("001e740701000001000000000000012a06676f6f676c6503636f6d0000010001"), 1, 0, false)
}

func BenchmarkPeekStreamUnknown(b *testing.B) {
	benchmarkPeekStream(b, bytes.Repeat([]byte{0x00}, 64), 1, 0, true)
}

func BenchmarkPeekStreamTLSFragmented(b *testing.B) {
	benchmarkPeekStream(b, captureClientHello(b, &tls.Config{ServerName: "www.example.com"}), 8, 0, false)
}

func BenchmarkPeekStreamWithCachedBuffers(b *testing.B) {
	benchmarkPeekStream(b, captureClientHello(b, &tls.Config{ServerName: "www.example.com"}), 1, 2, false)
}

// benchmarkPeekPacket runs one plan over one datagram. An empty wantProtocol means the benchmark
// expects every sniffer to reject the packet, which is the all-fail path.
func benchmarkPeekPacket(b *testing.B, packet []byte, sniffers []sniff.PacketSniffer, wantProtocol string) {
	metadata := adapter.InboundContext{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetSniffResult(&metadata)
		err := sniff.PeekPacket(context.Background(), &metadata, packet, sniffers...)
		if wantProtocol == "" {
			if err == nil {
				b.Fatal("expected every sniffer to reject the packet")
			}
		} else {
			if err != nil {
				b.Fatal("sniff failed: ", err)
			}
			if metadata.Protocol != wantProtocol {
				b.Fatal("sniffed ", metadata.Protocol, ", want ", wantProtocol)
			}
		}
	}
}

// quicInitial is the Chrome Initial packet from TestSniffUQUICChrome115: one datagram carrying the
// whole ClientHello, so it sniffs without any cached fragment state.
var quicInitial = mustHex(
	"cb0000000108181e17c387120abc000044d0705b6a3ef9ee37a8d3949a7d393ed078243c2ee2c3627fad1c3f107c117f4f07" +
		"1131ad61848068fcbbe5c65803c147f7f8ec5e2cd77b77beea23ba779d936dccac540f8396400e3190ea35cc2942af4171a0" +
		"4cb14272491920f90124959f44e80143678c0b52f5d31af319aaa589db2f940f004562724d0af40f737e1bb0002a071e6a1d" +
		"bc9f52c64f070806a5010abed0298053634d9c9126bd7949ae5087998ade762c0ad06691d99c0875a38c601fc1ee77bfc3b8" +
		"c11381829f2c9bdd022f4499c43ff1d6aee1a0d296861461dda217d22c568b276016ef3929e59d2f7d7ddf7809920fb7dc80" +
		"5641608949f3f8466ab3d37149aac501f0b107d808f3add4acfc657e4a82e2b88e97a6c74a00c419548760ab3414ba13915c" +
		"78a1ca79dceee8d59fbe299f20b671ac44823218368b2a026baa55170cf549519ac21dbb6d31d248bd339438a4e663bcdca1" +
		"fe3ae3f045a5dc19b122e9db9d7af9757076666dda4e9ace1c67def77fa14786f0cab3ebf7a270ea6e2b37838318c95779f8" +
		"0c3b8471948d0046c3614b3a13477c939a39a7855d85d13522a45ae0765739cd5eedef87237e824a929983ace27640c6495d" +
		"bf5a72fa0b96893dc5d28f3988249a57bdb458d460b4a57043de3da750a76b6e5d2259247ca27cd864ea18f0d09aa62ab6eb" +
		"7c014fb43179b2a1963d170b756cce83eeaebff78a828d025c811848e16ff862a8080d093478cd2208c8ab0803178325bc0d" +
		"9d6bb25e62fa50c4ad15cf80916da6578796932036c72e43eb480d1e423ed812ac75a97722f8416529b82ba8ee2219c53501" +
		"2282bb17066bd53e78b87a71abdb7ebdb2a7c2766ff8397962e87d0f85485b64b4ee81cc84f99c47f33f2b08727164419927" +
		"73f59186e38d32dbf5609a6fda94cb928cd25f5a7a3ab736b5a4236b6d5409ab18892c6a4d3480fc2350abfdf0bab1cedb55" +
		"bdf0760fdb703e6688f4de596254eed4ed3e67eb03d0717b8e15b31e735214e588c87ae36bc6c310e1894b4c15143e4ccf28" +
		"7b2dbc707a946bf9671ae3c574f9486b2c82eec784bba4cbc76113cbe0f97ac8c13cfa38f2925ab9d06887a612ce48280a91" +
		"d7e074e6caf898d88e2bbf71360899abf48a03f9a70cf2891199f2d63b116f4871af0ebb4f4906792f66cc21d1609f189138" +
		"532875c129a68c73e7bcd3b5d8100beac1d8ac4b20d94a59ac8df5a5af58a9acb20413eadf97189f5f19ff889155f0c4d375" +
		"14ec184eb6903967ff38a41fc087abb0f2cad3761d6e3f95f92a09a72f5c065b16e188088b87460241f27ecdb1bc6ece92c8" +
		"d36b2d68b58d0fb4d4b3c928c579ade8ae5a995833aadd297c30a37f7bc35440fc97070e1b198e0fac00157452177d16d280" +
		"3b4239997452b4ad3a951173bdec47a033fd7f8a7942accaa9aaa905b3c5a2175e7c3e07c48bf25331727fd69cd1e64d74d8" +
		"c9d4a6f8f4491adb7bc911505cb19877083d8f21a12475e313fccf57877ff3556318e81ed9145dd9427f2b65275440893035" +
		"f417481f721c69215af8ae103530cd0a1d35bf2cb5a27628f8d44d7c6f5ec12ce79d0a8333e0eb48771115d0a191304e46b8" +
		"db19bbe5c40f1c346dde98e76ff5e21ff38d2c34e60cb07766ed529dd6d2cbacd7fbf1ed8a0e6e40decad0ca5021e91552be" +
		"87c156d3ae2fffef41c65b14ba6d488f2c3227a1ab11ffce0e2dc47723a69da27a67a7f26e1cb13a7103af9b87a8db8e18ea")

func BenchmarkPeekPacketQUIC(b *testing.B) {
	benchmarkPeekPacket(b, quicInitial, sniff.DefaultPacketSniffers, C.ProtocolQUIC)
}

func BenchmarkPeekPacketWireGuard(b *testing.B) {
	benchmarkPeekPacket(b, wireGuardMessage(1, 148), []sniff.PacketSniffer{sniff.WireGuard}, C.ProtocolWireGuard)
}

func BenchmarkPeekPacketSTUN(b *testing.B) {
	benchmarkPeekPacket(b, buildSTUNMessage(0), sniff.DefaultPacketSniffers, C.ProtocolSTUN)
}

func BenchmarkPeekPacketUnknown(b *testing.B) {
	benchmarkPeekPacket(b, bytes.Repeat([]byte{0x00}, 64), sniff.DefaultPacketSniffers, "")
}

// BenchmarkPeekPacketWireGuardVsUTP runs the real plan prefix over a handshake initiation. It
// fails if the WireGuard reading ever loses to the uTP heuristic that runs after it.
func BenchmarkPeekPacketWireGuardVsUTP(b *testing.B) {
	sniffers := []sniff.PacketSniffer{
		sniff.DomainNameQuery,
		sniff.QUICClientHello,
		sniff.STUNMessage,
		sniff.WireGuard,
		sniff.UTP,
	}
	benchmarkPeekPacket(b, wireGuardMessage(1, 148), sniffers, C.ProtocolWireGuard)
}
