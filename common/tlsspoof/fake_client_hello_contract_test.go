package tlsspoof

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Windows spoofer reaches its driver through a path that needs
// administrator rights, so on an unprivileged machine the three Windows
// integration tests cannot run at all. buildFakeClientHello is the half of
// that path that needs no privilege, and it carries contracts the driver tests
// were the only thing exercising:
//
//   - the injected record must be a single well-formed TLS record, because the
//     whole method is "put bytes on the wire that a middlebox reads as a
//     ClientHello";
//   - it must fit in one TCP segment, because middleboxes do not reassemble a
//     fragmented ClientHello - this is the stated reason the curve preferences
//     are pinned to classical groups, and nothing else pins it;
//   - it must name the SNI it was asked for, so the fake and the real
//     ClientHello cannot be confused by construction.
//
// These run unprivileged on every platform. They are not a substitute for the
// driver tests: they say nothing about injection, the driver, or packet order.

const (
	tlsRecordHandshake = 0x16
	handshakeTypeHello = 0x01

	extensionServerName       = 0x0000
	extensionSupportedGroups  = 0x000a
	extensionALPN             = 0x0010
	groupX25519               = 0x001d
	groupX25519MLKEM768       = 0x11ec
	groupX25519Kyber768Draft0 = 0x6399

	// One IPv4 MSS on a 1500-byte path with TCP timestamps.
	singleSegmentLimit = 1460
)

func TestFakeClientHelloRefusesAnEmptySNI(t *testing.T) {
	t.Parallel()

	record, err := buildFakeClientHello("")
	require.Error(t, err, "an empty SNI must not silently produce a ClientHello")
	require.Nil(t, record)
}

func TestFakeClientHelloIsOneWellFormedHandshakeRecord(t *testing.T) {
	t.Parallel()

	record, err := buildFakeClientHello("letsencrypt.org")
	require.NoError(t, err)
	require.NotEmpty(t, record)

	require.Equal(t, byte(tlsRecordHandshake), record[0],
		"the injected bytes must open with a handshake record")
	legacyVersion := binary.BigEndian.Uint16(record[1:3])
	require.Contains(t, []uint16{0x0301, 0x0303}, legacyVersion,
		"record layer version must be a ClientHello-compatible value")

	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	require.Equal(t, len(record), 5+recordLength,
		"the record must be framed and complete: no trailing bytes, no truncation")

	require.Equal(t, byte(handshakeTypeHello), record[5], "handshake type must be ClientHello")
	handshakeLength := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	require.Equal(t, recordLength, 4+handshakeLength,
		"the handshake length must match the record body")
}

// The stated reason the curve preferences are pinned: a post-quantum hybrid key
// share adds ~1184 bytes and pushes the record past one segment. Without this
// assertion, re-enabling the default curve preferences would silently
// reintroduce a ClientHello that middleboxes drop.
func TestFakeClientHelloFitsInOneSegment(t *testing.T) {
	t.Parallel()

	record, err := buildFakeClientHello("letsencrypt.org")
	require.NoError(t, err)
	require.LessOrEqual(t, len(record), singleSegmentLimit,
		"the injected ClientHello must fit in one TCP segment; middleboxes do not reassemble fragmented ClientHellos")

	t.Logf("fake ClientHello size = %d bytes (limit %d)", len(record), singleSegmentLimit)
}

func TestFakeClientHelloOffersNoPostQuantumKeyShare(t *testing.T) {
	t.Parallel()

	record, err := buildFakeClientHello("letsencrypt.org")
	require.NoError(t, err)

	groups := requireExtension(t, record, extensionSupportedGroups)
	offered := parseUint16List(t, groups, 2)
	require.Contains(t, offered, uint16(groupX25519),
		"a browser-shaped greeting still offers x25519")
	require.NotContains(t, offered, uint16(groupX25519MLKEM768),
		"the hybrid share is what makes the record exceed one segment")
	require.NotContains(t, offered, uint16(groupX25519Kyber768Draft0))
}

func TestFakeClientHelloCarriesTheRequestedSNI(t *testing.T) {
	t.Parallel()

	first, err := buildFakeClientHello("letsencrypt.org")
	require.NoError(t, err)
	require.Equal(t, "letsencrypt.org", requireSNI(t, first))

	second, err := buildFakeClientHello("example.com")
	require.NoError(t, err)
	require.Equal(t, "example.com", requireSNI(t, second))

	require.False(t, bytes.Equal(first, second),
		"the ClientHello must be built from the requested SNI, not reused")
}

func TestFakeClientHelloAdvertisesBrowserALPN(t *testing.T) {
	t.Parallel()

	record, err := buildFakeClientHello("letsencrypt.org")
	require.NoError(t, err)

	alpn := requireExtension(t, record, extensionALPN)
	require.GreaterOrEqual(t, len(alpn), 2)
	listLength := int(binary.BigEndian.Uint16(alpn[0:2]))
	require.Equal(t, len(alpn)-2, listLength, "ALPN list length must match its body")

	require.Equal(t, []string{"h2", "http/1.1"}, parseALPNList(t, alpn[2:]))
}

// --- minimal ClientHello reader, scoped to the assertions above ---

func clientHelloBody(t *testing.T, record []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(record), 9, "record too short to hold a ClientHello header")
	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	require.GreaterOrEqual(t, 5+recordLength, 9)
	return record[9 : 5+recordLength]
}

func clientHelloExtensions(t *testing.T, record []byte) map[uint16][]byte {
	t.Helper()
	body := clientHelloBody(t, record)
	cursor := 0

	require.GreaterOrEqual(t, len(body), cursor+2+32, "missing legacy_version/random")
	cursor += 2 + 32

	require.GreaterOrEqual(t, len(body), cursor+1, "missing session_id length")
	cursor += 1 + int(body[cursor])

	require.GreaterOrEqual(t, len(body), cursor+2, "missing cipher_suites length")
	cipherLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2 + cipherLength

	require.GreaterOrEqual(t, len(body), cursor+1, "missing compression_methods length")
	cursor += 1 + int(body[cursor])

	require.GreaterOrEqual(t, len(body), cursor+2, "missing extensions length")
	extensionsLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	require.Equal(t, len(body)-cursor, extensionsLength,
		"extensions length must run to the end of the ClientHello")

	extensions := make(map[uint16][]byte)
	end := cursor + extensionsLength
	for cursor+4 <= end {
		extensionType := binary.BigEndian.Uint16(body[cursor : cursor+2])
		extensionLength := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
		cursor += 4
		require.LessOrEqual(t, cursor+extensionLength, end, "extension overruns the block")
		extensions[extensionType] = body[cursor : cursor+extensionLength]
		cursor += extensionLength
	}
	require.Equal(t, end, cursor, "extension block must be consumed exactly")
	return extensions
}

func requireExtension(t *testing.T, record []byte, extensionType uint16) []byte {
	t.Helper()
	extensions := clientHelloExtensions(t, record)
	extension, loaded := extensions[extensionType]
	require.True(t, loaded, "extension 0x%04x is missing", extensionType)
	return extension
}

func requireSNI(t *testing.T, record []byte) string {
	t.Helper()
	body := requireExtension(t, record, extensionServerName)
	require.GreaterOrEqual(t, len(body), 2, "server_name extension has no list length")
	listLength := int(binary.BigEndian.Uint16(body[0:2]))
	require.Equal(t, len(body)-2, listLength, "server_name list length must match its body")
	require.GreaterOrEqual(t, listLength, 3, "server_name list has no entry")
	require.Equal(t, byte(0), body[2], "the only defined name_type is host_name(0)")
	nameLength := int(binary.BigEndian.Uint16(body[3:5]))
	require.Equal(t, listLength-3, nameLength, "name length must fill the list")
	return string(body[5 : 5+nameLength])
}

func parseUint16List(t *testing.T, body []byte, headerLength int) []uint16 {
	t.Helper()
	require.GreaterOrEqual(t, len(body), headerLength)
	listLength := int(binary.BigEndian.Uint16(body[0:headerLength]))
	require.Equal(t, len(body)-headerLength, listLength, "list length must match its body")
	require.Zero(t, listLength%2)
	values := make([]uint16, 0, listLength/2)
	for offset := headerLength; offset < len(body); offset += 2 {
		values = append(values, binary.BigEndian.Uint16(body[offset:offset+2]))
	}
	return values
}

func parseALPNList(t *testing.T, body []byte) []string {
	t.Helper()
	var protocols []string
	for cursor := 0; cursor < len(body); {
		entryLength := int(body[cursor])
		cursor++
		require.LessOrEqual(t, cursor+entryLength, len(body), "ALPN entry overruns the list")
		protocols = append(protocols, string(body[cursor:cursor+entryLength]))
		cursor += entryLength
	}
	return protocols
}
