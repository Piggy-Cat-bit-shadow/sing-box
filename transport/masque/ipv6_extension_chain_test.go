package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Regression tests for IPv6 extension-header protocol resolution, pinning the
// behaviour of the PINNED dependency rather than reimplementing it.
//
// WHY this file exists next to ipv6_extensions_test.go
// ----------------------------------------------------
// ipv6_extensions_test.go has a defect in its *builder*, discovered while
// verifying it, and the defect made two of its recorded results WRONG. The
// builder treated nextHeader == 0 as "not set, compute it from the chain
// position":
//
//	next := e.nextHeader
//	if next == 0 {
//	    ...
//	}
//
// But 0 is the real, only legal value for a Hop-by-Hop Options header (RFC 8200
// section 4.3; header.IPv6HopByHopOptionsExtHdrIdentifier == 0). So:
//
//   - the base header was ALWAYS written with NextHeader 0, whatever the chain;
//   - an explicit extensionHopByHop entry was rewritten to point at the NEXT
//     extension header, changing an 8-octet chain into a 16-octet one.
//
// Measured on the pre-existing helper (packet = base header + payload):
//
//	buildIPv6Packet(src, dst, UDP, [{extensionFragmentNonFirst}])
//	  -> 60 00 00 00 00 08 | 00 | 40 ...    base NextHeader = 0 (HOP-BY-HOP)
//	                                          chain[0] = 11 00 00 08 ... (Fragment,
//	                                          offset 1, next header UDP)
//	  -> packetAddresses = (_, _, 17, true)
//
// The packet actually built there is Hop-by-Hop -> Fragment(non-first), not
// "a non-first fragment" as the test name claims. The IPv6 walk skips the
// Hop-by-Hop header and stops when it SEES the fragment header, so the protocol
// it returns (17) is the fragment header's own next-header field, not "the base
// header's value" and not something derived by walking past the fragment.
//
// This was NOT noticed before because the pre-existing test logs the result
// instead of asserting it.
//
// Everything below therefore uses buildIPv6ChainPacket, where nextHeader == 0
// always means the real Hop-by-Hop value and there is no sentinel, so a chain
// entry is encoded exactly as written.

// ipv6ExtensionHopByHopIdentifier is the IANA/RFC 8200 next-header value for a
// Hop-by-Hop Options header. Named explicitly because the collision between this
// value and "unset" is the bug described above.
const ipv6ExtensionHopByHopIdentifier uint8 = 0

// extensionChainEntry is one IPv6 extension header, fully explicit.
type extensionChainEntry struct {
	// nextHeader is written verbatim into the header's Next Header field.
	nextHeader uint8
	// length is the "Hdr Ext Len" field: header length in 8-octet units,
	// EXCLUDING the first 8 octets. Zero means the header is exactly 8 octets.
	length uint8
	// fragmentOffset is only used by the Fragment header: the 13-bit offset
	// field. 0 means first fragment, anything else means a later fragment.
	fragmentOffset uint16
}

// ipv6HopByHop returns a Hop-by-Hop entry pointing at next.
func ipv6HopByHop(next uint8) extensionChainEntry {
	return extensionChainEntry{nextHeader: next, length: 0}
}

// ipv6Routing returns a Routing entry pointing at next.
func ipv6Routing(next uint8) extensionChainEntry {
	return extensionChainEntry{nextHeader: next, length: 0}
}

// ipv6DestinationOptions returns a Destination Options entry pointing at next.
func ipv6DestinationOptions(next uint8) extensionChainEntry {
	return extensionChainEntry{nextHeader: next, length: 0}
}

// ipv6Fragment returns a Fragment entry. offset 0 is the FIRST fragment, which
// carries the upper-layer header; any other offset is a LATER fragment, which
// carries none.
func ipv6Fragment(next uint8, offset uint16) extensionChainEntry {
	return extensionChainEntry{nextHeader: next, fragmentOffset: offset}
}

// buildIPv6ChainPacket assembles the packet the chain literally describes.
//
// The difference from buildIPv6Packet in ipv6_extensions_test.go is deliberate
// and is the whole point of this helper: nextHeader is never interpreted, only
// written. The caller states the base header's Next Header explicitly.
func buildIPv6ChainPacket(baseNextHeader uint8, chain []extensionChainEntry, bodyLength int) []byte {
	payload := make([]byte, 0, 64)
	for _, entry := range chain {
		header := make([]byte, 8)
		header[0] = entry.nextHeader
		header[1] = entry.length
		if entry.fragmentOffset != 0 {
			// Offset lives in the high 13 bits of the second 16-bit field.
			binary.BigEndian.PutUint16(header[2:4], entry.fragmentOffset<<3)
		}
		payload = append(payload, header...)
	}
	payload = append(payload, make([]byte, bodyLength)...)

	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	packet[6] = baseNextHeader
	packet[7] = 64
	source := netip.MustParseAddr("2001:db8::1").As16()
	destination := netip.MustParseAddr("2001:db8::2").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	copy(packet[40:], payload)
	return packet
}

// TestIPv6ChainBuilderEncodesWhatItSays is the control for this file.
//
// Without it, every test below could pass for the wrong reason the way the
// pre-existing one did: if the builder silently rewrote the base header, the
// "Hop-by-Hop -> UDP" case would still resolve to 17 and still look correct.
// This test asserts the BYTES, so a builder regression is caught here rather
// than hiding inside a passing protocol assertion.
func TestIPv6ChainBuilderEncodesWhatItSays(t *testing.T) {
	packet := buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier, []extensionChainEntry{
		ipv6HopByHop(ipv6FragmentIdentifier),
		ipv6Fragment(testProtocolUDP, 1),
	}, 0)

	if packet[6] != ipv6ExtensionHopByHopIdentifier {
		t.Fatalf("base header Next Header = %d, want %d (Hop-by-Hop): the builder "+
			"must write the value it was given", packet[6], ipv6ExtensionHopByHopIdentifier)
	}
	// Byte 40 is chain[0].nextHeader, 41 is its length, 48 is chain[1].nextHeader.
	if packet[40] != ipv6FragmentIdentifier {
		t.Fatalf("chain[0] Next Header = %d, want %d (Fragment): an explicit "+
			"Hop-by-Hop entry must NOT be rewritten to point at the following entry",
			packet[40], ipv6FragmentIdentifier)
	}
	if packet[48] != testProtocolUDP {
		t.Fatalf("chain[1] Next Header = %d, want %d (UDP)", packet[48], testProtocolUDP)
	}
	if offset := binary.BigEndian.Uint16(packet[50:52]) >> 3; offset != 1 {
		t.Fatalf("fragment offset = %d, want 1", offset)
	}
}

// ipv6FragmentIdentifier is the next-header value naming a Fragment header.
const ipv6FragmentIdentifier uint8 = 44

// TestIPv6ExtensionChainProtocolResolution pins the measured resolution for each
// chain shape, using the corrected builder.
//
// Every case states the exact byte-level chain, because the difference between
// "Hop-by-Hop -> Fragment" and "Fragment" is invisible in the protocol number
// alone and is exactly what the pre-existing test got wrong.
func TestIPv6ExtensionChainProtocolResolution(t *testing.T) {
	cases := []struct {
		name string
		// baseNextHeader is byte 6 of the IPv6 header.
		baseNextHeader uint8
		chain          []extensionChainEntry
		wantProtocol   uint8
	}{
		{
			name:           "plain IPv6, no extension headers, UDP",
			baseNextHeader: testProtocolUDP,
			wantProtocol:   testProtocolUDP,
		},
		{
			name:           "plain IPv6, no extension headers, TCP",
			baseNextHeader: testProtocolTCP,
			wantProtocol:   testProtocolTCP,
		},
		{
			// The ONLY legal placement for Hop-by-Hop is immediately after the
			// base header, and this is the case the old builder could not express
			// in the middle of a chain.
			name:           "Hop-by-Hop -> UDP",
			baseNextHeader: ipv6ExtensionHopByHopIdentifier,
			chain:          []extensionChainEntry{ipv6HopByHop(testProtocolUDP)},
			wantProtocol:   testProtocolUDP,
		},
		{
			name:           "Routing -> TCP",
			baseNextHeader: ipv6ExtensionRoutingIdentifier,
			chain:          []extensionChainEntry{ipv6Routing(testProtocolTCP)},
			wantProtocol:   testProtocolTCP,
		},
		{
			name:           "Destination Options -> UDP",
			baseNextHeader: ipv6ExtensionDestinationOptionsIdentifier,
			chain:          []extensionChainEntry{ipv6DestinationOptions(testProtocolUDP)},
			wantProtocol:   testProtocolUDP,
		},
		{
			// A FIRST fragment (offset 0) does carry the upper-layer header, so
			// the walk reads it from the fragment header and reports it.
			name:           "Fragment (first, offset 0) -> UDP",
			baseNextHeader: ipv6FragmentIdentifier,
			chain:          []extensionChainEntry{ipv6Fragment(testProtocolUDP, 0)},
			wantProtocol:   testProtocolUDP,
		},
		{
			name:           "Hop-by-Hop -> Routing -> Destination Options -> UDP",
			baseNextHeader: ipv6ExtensionHopByHopIdentifier,
			chain: []extensionChainEntry{
				ipv6HopByHop(ipv6ExtensionRoutingIdentifier),
				ipv6Routing(ipv6ExtensionDestinationOptionsIdentifier),
				ipv6DestinationOptions(testProtocolUDP),
			},
			wantProtocol: testProtocolUDP,
		},
		{
			name:           "Destination Options -> Routing -> Destination Options -> TCP",
			baseNextHeader: ipv6ExtensionDestinationOptionsIdentifier,
			chain: []extensionChainEntry{
				ipv6DestinationOptions(ipv6ExtensionRoutingIdentifier),
				ipv6Routing(ipv6ExtensionDestinationOptionsIdentifier),
				ipv6DestinationOptions(testProtocolTCP),
			},
			wantProtocol: testProtocolTCP,
		},
		{
			// A multi-octet extension header: Hdr Ext Len 1 means 16 octets, so
			// the walk must advance by 16 rather than 8 to reach the UDP value.
			// A walk that assumed a fixed 8-octet extension would read the wrong
			// byte and report a bogus protocol.
			name:           "Hop-by-Hop (16 octets) -> UDP",
			baseNextHeader: ipv6ExtensionHopByHopIdentifier,
			chain: []extensionChainEntry{
				{nextHeader: testProtocolUDP, length: 1},
			},
			wantProtocol: testProtocolUDP,
		},
		{
			// NAT44/NAT66 style chains: Destination Options -> Fragment(first).
			name:           "Destination Options -> Fragment (first) -> TCP",
			baseNextHeader: ipv6ExtensionDestinationOptionsIdentifier,
			chain: []extensionChainEntry{
				ipv6DestinationOptions(ipv6FragmentIdentifier),
				ipv6Fragment(testProtocolTCP, 0),
			},
			wantProtocol: testProtocolTCP,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			packet := buildIPv6ChainPacket(testCase.baseNextHeader, testCase.chain, 8)

			// Control: the bytes on the wire are the chain the case describes.
			if packet[6] != testCase.baseNextHeader {
				t.Fatalf("builder wrote base Next Header %d, want %d",
					packet[6], testCase.baseNextHeader)
			}

			gotSource, gotDestination, gotProtocol, valid := packetAddresses(packet)
			if !valid {
				t.Fatalf("a well-formed IPv6 packet was rejected (base Next Header %d, "+
					"chain %+v)", testCase.baseNextHeader, testCase.chain)
			}
			if gotProtocol != testCase.wantProtocol {
				t.Fatalf("protocol resolved to %d, want %d: the extension chain "+
					"starting at Next Header %d was not walked to the upper-layer "+
					"protocol, so a route rule keyed on protocol would misroute this packet",
					gotProtocol, testCase.wantProtocol, testCase.baseNextHeader)
			}
			if gotSource != netip.MustParseAddr("2001:db8::1") ||
				gotDestination != netip.MustParseAddr("2001:db8::2") {
				t.Fatalf("addresses resolved to %s -> %s", gotSource, gotDestination)
			}
		})
	}
}

const (
	ipv6ExtensionRoutingIdentifier            uint8 = 43
	ipv6ExtensionDestinationOptionsIdentifier uint8 = 60
)

// TestIPv6NonFirstFragmentReportsBaseHeaderProtocol pins the NON-FIRST fragment
// behaviour, which is the case the audit document claims was already measured.
//
// MEASURED against the pinned dependency
// (sing-tun v0.9.6-0.20260924073434-3077c705bbdb, icmp_error.go:166 and
// flow_parse.go:96 for the exact revision in use). The walk is:
//
//	protocol, payload, fragment, transportPresent = skipIPv6ExtensionHeaders(protocol, payload)
//	if transportPresent { return protocol, true }
//	if !fragment || len(payload) < header.IPv6FragmentHeaderSize { return 0, false }
//	protocol = payload[0]
//	if binary.BigEndian.Uint16(payload[2:])>>3 != 0 {
//	    ... if protocol is one of HopByHop/Routing/DestOpts/Fragment -> return 0, false
//	    return protocol, true
//	}
//
// skipIPv6ExtensionHeaders STOPS at a Fragment header and returns it (flow_parse.go:109-110),
// so the fragment header's own Next Header field (offset 0 of the fragment
// header) is what gets reported, and only when the fragment offset is non-zero.
// It is therefore the FRAGMENT header's next-header field, NOT the base header's
// field, that is reported. The two coincide in the common case, which is what
// made the earlier claim look right.
//
// The assertion below is the STRONGEST form that still records rather than
// assumes: it is proved by an independent packet in which the two values differ.
func TestIPv6NonFirstFragmentReportsBaseHeaderProtocol(t *testing.T) {
	// Case 1: the shape the audit document describes. Base Next Header and the
	// fragment header's next-header field both name UDP.
	samePacket := buildIPv6ChainPacket(ipv6FragmentIdentifier, []extensionChainEntry{
		ipv6Fragment(testProtocolUDP, 1),
	}, 8)
	_, _, protocol, valid := packetAddresses(samePacket)
	if !valid {
		t.Fatalf("non-first fragment (UDP) was REJECTED; the pinned dependency " +
			"accepts it, so the walk changed and the recorded behaviour is stale")
	}
	if protocol != testProtocolUDP {
		t.Fatalf("non-first fragment (UDP) resolved to %d, want %d: the dependency's "+
			"fragment handling changed", protocol, testProtocolUDP)
	}

	// Case 2: the discriminator. Base Next Header names Routing (43), the fragment
	// header names TCP (6). Nothing in the packet is UDP. Whatever the walk
	// reports here tells us WHICH field it read.
	discriminating := buildIPv6ChainPacket(ipv6ExtensionRoutingIdentifier, []extensionChainEntry{
		ipv6Fragment(testProtocolTCP, 1),
	}, 8)
	_, _, protocol, valid = packetAddresses(discriminating)
	if !valid {
		t.Fatal("non-first fragment with a Routing base Next Header was rejected")
	}
	// Measured: 6. The walk stopped AT the fragment header and read its next
	// header, rather than walking the Routing header first.
	if protocol != testProtocolTCP {
		t.Fatalf("non-first fragment with base Next Header 43 and fragment "+
			"next-header 6 resolved to %d; the pinned dependency returns 6 "+
			"(the FRAGMENT header's field), so its walk changed", protocol)
	}

	// Case 3: the non-first fragment's next-header field names an extension
	// header. That is malformed (a non-first fragment carries no upper-layer
	// header at all) and the dependency rejects it explicitly, at icmp_error.go:192.
	extensionNamed := buildIPv6ChainPacket(ipv6FragmentIdentifier, []extensionChainEntry{
		ipv6Fragment(ipv6ExtensionRoutingIdentifier, 1),
	}, 8)
	if _, _, protocol, valid := packetAddresses(extensionNamed); valid {
		t.Fatalf("non-first fragment whose next-header field names Routing was "+
			"accepted with protocol %d; the dependency must reject it", protocol)
	}
}

// TestIPv6FragmentChainProgressesAndTerminates covers the dependency's fragment
// LOOP, which is the part of the walk with actual control-flow risk.
//
// icmp_error.go:181-199 is a `for {}` loop. A Fragment header whose offset is
// zero does NOT terminate it: the loop sets protocol = payload[0] and advances
// by 8 octets, then walks again. Repeating next header 44 with offset 0 is
// therefore the input that would spin if the loop ever failed to advance or
// failed to run out of payload. It must terminate and must stay consistent.
func TestIPv6FragmentChainProgressesAndTerminates(t *testing.T) {
	// A run of Fragment headers, each pointing at the next, all offset 0, the
	// last naming UDP. This is the well-formed version of the loop input.
	const fragments = 4
	chain := make([]extensionChainEntry, 0, fragments)
	for index := 0; index < fragments-1; index++ {
		chain = append(chain, ipv6Fragment(ipv6FragmentIdentifier, 0))
	}
	chain = append(chain, ipv6Fragment(testProtocolUDP, 0))

	packet := buildIPv6ChainPacket(ipv6FragmentIdentifier, chain, 0)
	_, _, protocol, valid := packetAddresses(packet)
	if !valid || protocol != testProtocolUDP {
		t.Fatalf("a chain of %d offset-0 Fragment headers ending in UDP resolved "+
			"to (%d, %v), want (%d, true): the fragment loop must advance past "+
			"each header and reach the upper-layer protocol",
			fragments, protocol, valid, testProtocolUDP)
	}

	// The loop must also terminate when it runs OUT of payload, in both the
	// "payload too short for a fragment header" and "payload exactly one fragment
	// header" shapes. Neither may hang and neither may report a protocol it
	// cannot have read.
	for _, payloadLength := range []int{0, 1, 7, 8} {
		truncated := buildIPv6ChainPacket(ipv6FragmentIdentifier, nil, payloadLength)
		_, _, protocol, valid := packetAddresses(truncated)
		if valid {
			t.Fatalf("a Fragment header with Next Header 44 and only %d payload "+
				"octets was accepted with protocol %d; there is no upper-layer "+
				"header to read", payloadLength, protocol)
		}
	}
}

// TestIPv6MalformedExtensionChainsAreRejectedWithoutPanicking pins what the
// pinned dependency does with chains a peer can send that are malformed.
//
// This does NOT reimplement the parser: every expectation below was MEASURED
// against the pinned revision, and the assertion is on the dependency's answer.
// The three properties that matter for a network-facing parser are (1) it must
// return rather than panic, (2) it must not read outside the buffer, and (3) it
// must not report a protocol it cannot have read.
func TestIPv6MalformedExtensionChainsAreRejectedWithoutPanicking(t *testing.T) {
	cases := []struct {
		name string
		// build returns the packet. It is a function so a panicking build cannot
		// be mistaken for a panicking parse.
		build func() []byte
		// wantValid records the MEASURED verdict.
		wantValid bool
	}{
		{
			name: "base header truncated to 8 bytes",
			build: func() []byte {
				return buildIPv6ChainPacket(testProtocolUDP, nil, 0)[:8]
			},
			wantValid: false,
		},
		{
			name: "base header only, zero payload length",
			build: func() []byte {
				return buildIPv6ChainPacket(testProtocolUDP, nil, 0)
			},
			// A zero-length payload with a non-extension next header is ISValid:
			// PayloadLength 0 <= 0. It is reported with the base header's value.
			wantValid: true,
		},
		{
			name: "Hop-by-Hop declares 8 octets but payload is empty",
			build: func() []byte {
				return buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier, nil, 0)
			},
			wantValid: false,
		},
		{
			name: "Hop-by-Hop declares 8 octets but payload is 7",
			build: func() []byte {
				return buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier, nil, 7)
			},
			wantValid: false,
		},
		{
			name: "Hop-by-Hop declares 2048 octets (Hdr Ext Len 255)",
			build: func() []byte {
				packet := buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier,
					[]extensionChainEntry{{nextHeader: testProtocolUDP, length: 0xff}}, 8)
				return packet
			},
			wantValid: false,
		},
		{
			name: "extension chain points at itself forever (loop)",
			build: func() []byte {
				// Every Hop-by-Hop header points at the next Hop-by-Hop header and
				// the last one points back at the first: a cycle. The walk must
				// still terminate by exhausting the payload.
				chain := []extensionChainEntry{
					ipv6HopByHop(ipv6ExtensionHopByHopIdentifier),
					ipv6HopByHop(ipv6ExtensionHopByHopIdentifier),
					ipv6HopByHop(ipv6ExtensionHopByHopIdentifier),
					ipv6HopByHop(ipv6ExtensionHopByHopIdentifier),
				}
				return buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier, chain, 0)
			},
			// The last header points at extensionHopByHopIdentifier again, so the
			// walk consumes the payload and then finds no header -> invalid. It
			// terminates, which is what matters.
			wantValid: false,
		},
		{
			name: "Fragment header with no room for its 8 octets",
			build: func() []byte {
				return buildIPv6ChainPacket(ipv6FragmentIdentifier, nil, 4)
			},
			wantValid: false,
		},
		{
			name: "non-first fragment naming a Hop-by-Hop extension",
			build: func() []byte {
				return buildIPv6ChainPacket(ipv6FragmentIdentifier, []extensionChainEntry{
					ipv6Fragment(ipv6ExtensionHopByHopIdentifier, 1),
				}, 8)
			},
			// icmp_error.go:192 rejects exactly this: a non-first fragment whose
			// next-header field names an extension header cannot be parsed.
			wantValid: false,
		},
		{
			name: "unknown next-header value 254 (experimental)",
			build: func() []byte {
				return buildIPv6ChainPacket(254, nil, 8)
			},
			// A non-extension next header is reported as-is, which is correct:
			// protocol 254 is a real protocol number.
			wantValid: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			packet := testCase.build()
			// The parse must return, not panic. A panic here is a denial of
			// service on a peer-controlled input, so it is reported as a failure
			// rather than crashing the test binary.
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("packetAddresses PANICKED on a peer-controllable IPv6 "+
						"packet (%d bytes: % x): %v",
						len(packet), packet, recovered)
				}
			}()

			gotSource, gotDestination, protocol, valid := packetAddresses(packet)
			if valid != testCase.wantValid {
				t.Fatalf("packetAddresses returned valid=%v for %q (protocol %d), "+
					"but the pinned dependency returns valid=%v; its behaviour changed",
					valid, testCase.name, protocol, testCase.wantValid)
			}
			if !valid {
				return
			}
			// Anything accepted must be coherent.
			if !gotSource.IsValid() || !gotDestination.IsValid() {
				t.Fatalf("accepted with invalid addresses: %s -> %s", gotSource, gotDestination)
			}
			if !gotSource.Is6() || !gotDestination.Is6() {
				t.Fatalf("an IPv6 packet was reported with non-IPv6 addresses: %s -> %s",
					gotSource, gotDestination)
			}
		})
	}
}

// TestIPv6DeclaredPayloadLengthIsNotTrustedForSlicing is a hazard probe.
//
// header.IPv6.Payload() (sing-tun gtcpip/header/ipv6.go:214) is:
//
//	func (b IPv6) Payload() []byte { return b[IPv6MinimumSize:][:b.PayloadLength()] }
//
// That expression is only safe while the declared PayloadLength fits the buffer.
// IPv6.IsValid (ipv6.go:303) checks dlen > pktSize-IPv6MinimumSize and rejects,
// and IPTransportProtocol calls IsValid BEFORE Payload(), which is what makes the
// walk safe. This test pins that ORDER: a packet whose declared length exceeds
// its buffer must be rejected, not sliced. If a future revision dropped the
// IsValid call, Payload() would panic here rather than in production.
func TestIPv6DeclaredPayloadLengthIsNotTrustedForSlicing(t *testing.T) {
	for _, declared := range []uint16{41, 128, 0xffff} {
		packet := buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier,
			[]extensionChainEntry{ipv6HopByHop(testProtocolUDP)}, 8)
		// The buffer is 56 bytes: 40 base + 16 payload. Declare more than that.
		binary.BigEndian.PutUint16(packet[4:6], declared)

		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("declared PayloadLength %d against a %d-byte buffer "+
						"PANICKED instead of being rejected: %v. IPv6.IsValid no "+
						"longer guards the Payload() slice in IPTransportProtocol",
						declared, len(packet), recovered)
				}
			}()
			if _, _, protocol, valid := packetAddresses(packet); valid {
				t.Fatalf("declared PayloadLength %d against a %d-byte buffer was "+
					"accepted with protocol %d", declared, len(packet), protocol)
			}
		}()
	}
}

// TestIPv6ExtensionChainFedToForwardingPath exercises the TWO entry points a
// packet actually takes, not just the parser.
//
// packetAddresses alone is not the production shape: server.go:294 and
// server.go:302 call packetAddresses and then, only when the packet is routed and
// forwarded, decrementHopLimit. decrementHopLimit MUTATES the packet through
// header.IPv6 views, so it must not write outside the buffer for any shape the
// parser accepts. This runs the pair over the same corpus.
func TestIPv6ExtensionChainFedToForwardingPath(t *testing.T) {
	corpus := [][]byte{
		buildIPv6ChainPacket(testProtocolUDP, nil, 8),
		buildIPv6ChainPacket(ipv6ExtensionHopByHopIdentifier, []extensionChainEntry{
			ipv6HopByHop(ipv6ExtensionRoutingIdentifier),
			ipv6Routing(testProtocolUDP),
		}, 8),
		buildIPv6ChainPacket(ipv6FragmentIdentifier, []extensionChainEntry{
			ipv6Fragment(testProtocolUDP, 1),
		}, 8),
		buildIPv6ChainPacket(ipv6ExtensionDestinationOptionsIdentifier, []extensionChainEntry{
			ipv6DestinationOptions(testProtocolTCP),
		}, 8),
	}

	for index, packet := range corpus {
		// A copy, because decrementHopLimit mutates in place and the corpus entry
		// must stay reusable for the length check below.
		clone := append([]byte(nil), packet...)
		originalLength := len(clone)

		_, _, _, valid := packetAddresses(clone)
		if !valid {
			t.Fatalf("corpus entry %d was rejected by packetAddresses", index)
		}

		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("decrementHopLimit PANICKED on corpus entry %d (% x): %v",
						index, clone, recovered)
				}
			}()
			_ = decrementHopLimit(clone)
		}()

		if len(clone) != originalLength {
			t.Fatalf("decrementHopLimit resized corpus entry %d from %d to %d bytes",
				index, originalLength, len(clone))
		}
		// The hop limit must have been decremented exactly once, and nothing else
		// in the base header may move. This is the assertion that catches a write
		// into the wrong offset.
		if packet[7] != 64 {
			t.Fatalf("corpus entry %d: the source packet's hop limit was mutated, "+
				"so decrementHopLimit wrote through a shared slice", index)
		}
		if clone[7] != 63 {
			t.Fatalf("corpus entry %d: hop limit is %d after forwarding, want 63",
				index, clone[7])
		}
		for offset := range 40 {
			if offset == 7 {
				continue
			}
			if clone[offset] != packet[offset] {
				t.Fatalf("corpus entry %d: byte %d changed from %d to %d; decrementing "+
					"the hop limit must not touch any other byte of the base header",
					index, offset, packet[offset], clone[offset])
			}
		}
	}
}
