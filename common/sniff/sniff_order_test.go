package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// The plans are a contract, not a preference, so both are spelled out here as well as in the
// package. A reorder has to fail this test and be justified in the diff: the failure sample, the
// route-level regression and the false positive matrix that §6 asks for before the order may be
// touched.
//
// Stream:
//
//	TLSClientHello, HTTPHost, StreamDomainNameQuery, BitTorrent, SSH, RDP
//
// Packet:
//
//	DomainNameQuery, QUICClientHello, STUNMessage, WireGuard, UTP, UDPTracker, DTLSRecord, NTP
//
// The one collision that has actually bitten is WireGuard against uTP: a handshake initiation
// starts 01 00 00 00 and is 148 bytes, which is a legal uTP ST_DATA packet as far as that heuristic
// is concerned, so WireGuard has to come first. wireguard_test.go proves the ambiguity is structural
// and TestPacketSnifferPrecedenceCollisions fails if the order is undone.
func TestDefaultSnifferOrderIsTheContract(t *testing.T) {
	t.Parallel()
	streamOrder := []sniff.StreamSniffer{
		sniff.TLSClientHello,
		sniff.HTTPHost,
		sniff.StreamDomainNameQuery,
		sniff.BitTorrent,
		sniff.SSH,
		sniff.RDP,
	}
	require.Len(t, sniff.DefaultStreamSniffers, len(streamOrder))
	for index, expected := range streamOrder {
		require.Equal(t, reflect.ValueOf(expected).Pointer(), reflect.ValueOf(sniff.DefaultStreamSniffers[index]).Pointer(),
			"stream sniffer %d changed", index)
	}
	packetOrder := []sniff.PacketSniffer{
		sniff.DomainNameQuery,
		sniff.QUICClientHello,
		sniff.STUNMessage,
		sniff.WireGuard,
		sniff.UTP,
		sniff.UDPTracker,
		sniff.DTLSRecord,
		sniff.NTP,
	}
	require.Len(t, sniff.DefaultPacketSniffers, len(packetOrder))
	for index, expected := range packetOrder {
		require.Equal(t, reflect.ValueOf(expected).Pointer(), reflect.ValueOf(sniff.DefaultPacketSniffers[index]).Pointer(),
			"packet sniffer %d changed", index)
	}
}

// streamCollisionPayload is one canonical message per stream parser, in plan order, with the
// protocol the plan is required to report for it.
type streamCollisionPayload struct {
	name     string
	protocol string
	payload  []byte
}

// streamCollisionCorpus is ordered to match DefaultStreamSniffers, which is what lets
// TestStreamSnifferFalsePositiveMatrix check the matrix by position.
func streamCollisionCorpus(t *testing.T) []streamCollisionPayload {
	t.Helper()
	return []streamCollisionPayload{
		{"tls-client-hello", C.ProtocolTLS, captureClientHello(t, &tls.Config{ServerName: "collision.example.com"})},
		{"http-request", C.ProtocolHTTP, []byte("GET / HTTP/1.1\r\nHost: collision.example.com\r\n\r\n")},
		{"dns-over-tcp", C.ProtocolDNS, mustHex("001e740701000001000000000000012a06676f6f676c6503636f6d0000010001")},
		{"bittorrent-handshake", C.ProtocolBitTorrent, append([]byte{19}, []byte("BitTorrent protocol")...)},
		{"ssh-banner", C.ProtocolSSH, []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")},
		{"rdp-connection-request", C.ProtocolRDP, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}},
	}
}

// streamPlanOutcome runs the production stream plan over one payload.
func streamPlanOutcome(t *testing.T, payload []byte) (*adapter.InboundContext, error) {
	t.Helper()
	metadata, err, _ := peekStreamChunks(t, [][]byte{payload}, nil, nil)
	return metadata, err
}

// TestStreamSnifferPrecedenceCollisions is the stream half of the collision corpus the packet plan
// already has. Each payload is a real message of one protocol, and the assertion is derived rather
// than assumed: every parser in the plan is asked whether it accepts the payload, and the plan's
// answer must be the first parser that said yes.
//
// That is the whole content of the ordering contract - a claim ends the sweep, so a parser moved in
// front of a stronger one changes what gets reported - and deriving it means a reorder fails here
// with the payload that changed hands, which is the failure sample §6 requires before the order may
// be touched at all.
func TestStreamSnifferPrecedenceCollisions(t *testing.T) {
	t.Parallel()
	for _, testCase := range streamCollisionCorpus(t) {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			firstAcceptor := -1
			for index, parser := range sniff.DefaultStreamSniffers {
				var metadata adapter.InboundContext
				if err := parser(context.Background(), &metadata, bytes.NewReader(testCase.payload)); err == nil {
					firstAcceptor = index
					break
				}
			}
			require.GreaterOrEqual(t, firstAcceptor, 0,
				"no parser in the plan accepts %q, so this corpus entry has gone stale", testCase.name)

			metadata, err := streamPlanOutcome(t, testCase.payload)
			require.NoError(t, err, testCase.name)
			require.Equal(t, testCase.protocol, metadata.Protocol,
				"%q was claimed by the parser at position %d instead", testCase.name, firstAcceptor)
		})
	}
}

// TestStreamSnifferFalsePositiveMatrix is the matrix §6 asks for, recorded rather than assumed: for
// every canonical message of every stream protocol, which parsers in the plan accept it.
//
// The matrix is the identity. Each message of each protocol is accepted by its own parser and by
// none of the other five, so no two stream parsers are competing for these payloads and the order
// between them is not what separates them here. What the order separates is everything *between*
// the canonical shapes - the fuzz corpora and the fragmentation table cover that - and the value of
// recording the identity is that the day a parser's accept set widens to swallow another protocol's
// message, this fails first and the ordering question gets answered before the change lands.
func TestStreamSnifferFalsePositiveMatrix(t *testing.T) {
	t.Parallel()
	corpus := streamCollisionCorpus(t)
	require.Len(t, corpus, len(sniff.DefaultStreamSniffers))
	for owner, testCase := range corpus {
		var accepted []int
		for index, parser := range sniff.DefaultStreamSniffers {
			var metadata adapter.InboundContext
			if err := parser(context.Background(), &metadata, bytes.NewReader(testCase.payload)); err == nil {
				require.NotEmpty(t, metadata.Protocol, "%q: a parser accepted without reporting", testCase.name)
				accepted = append(accepted, index)
			}
		}
		require.Equal(t, []int{owner}, accepted,
			"%q is accepted by parsers %v; the corpus is ordered to match the plan, so the owner is %d",
			testCase.name, accepted, owner)
		require.Equal(t, testCase.protocol,
			protocolOfStreamParser(t, sniff.DefaultStreamSniffers[owner], testCase.payload),
			"%q: the parser at its corpus position reports another protocol", testCase.name)
	}
}

// protocolOfStreamParser reports what one parser says about one payload, which for an accepting
// parser is the protocol it owns.
func protocolOfStreamParser(t *testing.T, parser sniff.StreamSniffer, payload []byte) string {
	t.Helper()
	var metadata adapter.InboundContext
	require.NoError(t, parser(context.Background(), &metadata, bytes.NewReader(payload)))
	return metadata.Protocol
}

// TestStreamSnifferDegenerateInputs is the degenerate set §6 asks to be run alongside the corpus:
// nothing, one byte, two bytes, all-zero, all-FF and deterministic filler, at every length up to
// three and at the sizes the parsers declare. Nothing may be claimed that no parser accepts, and
// none of it may panic or read out of bounds.
func TestStreamSnifferDegenerateInputs(t *testing.T) {
	t.Parallel()
	var degenerate [][]byte
	for length := 0; length <= 3; length++ {
		degenerate = append(degenerate,
			make([]byte, length),
			bytesOfValue(0xFF, length),
			deterministicBytes(uint32(0x1000+length), length),
		)
	}
	degenerate = append(degenerate,
		make([]byte, 64),
		bytesOfValue(0xFF, 64),
		bytesOfValue(0xFF, 1500),
		make([]byte, 1500),
		deterministicBytes(0x5eed, 1500),
	)
	for index, payload := range degenerate {
		claimed := ""
		for _, parser := range sniff.DefaultStreamSniffers {
			var metadata adapter.InboundContext
			if err := parser(context.Background(), &metadata, bytes.NewReader(payload)); err == nil {
				require.NotEmpty(t, metadata.Protocol, "case %d (%d bytes)", index, len(payload))
				if claimed == "" {
					claimed = metadata.Protocol
				}
			}
		}
		metadata, err := streamPlanOutcome(t, payload)
		if claimed == "" {
			require.Error(t, err, "case %d (%d bytes) was claimed by %q", index, len(payload), metadata.Protocol)
			require.Empty(t, metadata.Protocol, "case %d (%d bytes)", index, len(payload))
			continue
		}
		require.NoError(t, err, "case %d (%d bytes)", index, len(payload))
		require.Equal(t, claimed, metadata.Protocol, "case %d (%d bytes)", index, len(payload))
	}
}
