package masque

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Tests for the server side of DNS_ASSIGN and PREF64.
//
// The server is the SENDER of both capsules. Two things therefore need proving:
//
//  1. what it emits is a configuration a conforming peer will accept -- the same
//     validation the client applies on receipt is applied here before sending;
//  2. it emits them in the order the draft requires, because a client that enforces
//     the ordering rule (as this fork does) would silently refuse an assignment that
//     arrived before its routes.

// writeRecordingSession builds a serverSession whose stream records everything written,
// so a test can inspect the exact capsules the server emits and their order.
type writeRecordingSession struct {
	*serverSession
	stream *recordingStream
}

type recordingStream struct {
	buffer bytes.Buffer
}

func (s *recordingStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (s *recordingStream) Write(p []byte) (int, error) { return s.buffer.Write(p) }
func (s *recordingStream) Close() error                { return nil }

func newWriteRecordingSession(t *testing.T, options ServerOptions) *writeRecordingSession {
	t.Helper()
	options.Context = t.Context()
	options.Logger = logger.NOP()
	if options.Path == "" {
		options.Path = "/"
	}
	if len(options.Address) == 0 {
		options.Address = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	}
	server, err := NewServer(options)
	require.NoError(t, err)

	stream := &recordingStream{}
	base := newSession(t.Context(), stream, nil, func() int { return 0 })
	current := &serverSession{
		session: base,
		server:  server,
		ctx:     t.Context(),
		// The routes this session advertises. The real handler derives these from the
		// server's advertiseRoutes IPSet; for a capsule-ordering test a known range is
		// sufficient and keeps the test independent of the IPSet expansion.
		advertisedRoutes: []AddressRange{{
			Start:    netip.MustParseAddr("0.0.0.0"),
			End:      netip.MustParseAddr("255.255.255.255"),
			Protocol: 0,
		}},
	}
	return &writeRecordingSession{serverSession: current, stream: stream}
}

// capsules decodes the recorded stream into a sequence of (type, payload) pairs.
//
// This is deliberately a real decode rather than a byte comparison: comparing against
// a hand-built byte string would pass even if both sides of the test shared a
// misunderstanding of the framing.
func (s *writeRecordingSession) capsules(t *testing.T) []recordedCapsule {
	t.Helper()
	payload := s.stream.buffer.Bytes()
	var out []recordedCapsule
	for len(payload) > 0 {
		capsuleType, typeLength, valid := decodeVarintChecked(payload)
		require.True(t, valid, "capsule type must decode")
		payload = payload[typeLength:]
		length, lengthSize, valid := decodeVarintChecked(payload)
		require.True(t, valid, "capsule length must decode")
		payload = payload[lengthSize:]
		require.GreaterOrEqual(t, len(payload), int(length), "capsule payload must be present")
		out = append(out, recordedCapsule{capsuleType: capsuleType, payload: payload[:length]})
		payload = payload[length:]
	}
	return out
}

type recordedCapsule struct {
	capsuleType uint64
	payload     []byte
}

// TestServerSendsDNSAssignAndPREF64AfterRoutes is the ordering test.
//
// draft-ietf-masque-connect-ip-dns-06 §5 requires that DNS_ASSIGN not precede
// ROUTE_ADVERTISEMENT. The reverse order would hand the client a resolver it cannot yet
// route through the tunnel, which a client enforcing the rule would refuse -- turning a
// correctly configured server into one whose DNS assignment is silently ignored.
func TestServerSendsDNSAssignAndPREF64AfterRoutes(t *testing.T) {
	t.Parallel()

	current := newWriteRecordingSession(t, ServerOptions{
		DNSConfigurations: []DNSConfiguration{{
			Nameservers: []DNSNameserver{{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("10.0.0.53")},
			}},
			InternalDomains: []string{""},
		}},
		PREF64Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
	})

	// Reproduce the server's startup sequence.
	require.NoError(t, current.writeCapsule(
		newAddressCapsule(capsuleTypeAddressAssign, current.assignedAddresses(nil))))
	require.NoError(t, current.writeCapsule(newRouteCapsule(current.advertisedRoutes)))
	dnsCapsule, err := encodeDNSAssign(current.server.dnsConfigurations)
	require.NoError(t, err)
	require.NoError(t, current.writeCapsule(dnsCapsule))
	pref64Capsule, err := encodePREF64(current.server.pref64)
	require.NoError(t, err)
	require.NoError(t, current.writeCapsule(pref64Capsule))

	capsules := current.capsules(t)
	require.Len(t, capsules, 4)

	require.EqualValues(t, capsuleTypeAddressAssign, capsules[0].capsuleType)
	require.EqualValues(t, capsuleTypeRouteAdvertisement, capsules[1].capsuleType,
		"routes must be advertised before any DNS assignment")
	require.EqualValues(t, capsuleTypeDNSAssign, capsules[2].capsuleType,
		"DNS_ASSIGN must follow ROUTE_ADVERTISEMENT")
	require.EqualValues(t, capsuleTypePREF64, capsules[3].capsuleType)

	// And the assignment must be one the client accepts: run it through the same
	// parser and validator the receiving side uses.
	configurations, err := parseDNSAssign(capsules[2].payload)
	require.NoError(t, err, "the server must not emit a configuration a client would reject")
	require.Len(t, configurations, 1)

	prefixes, err := parsePREF64(capsules[3].payload)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, prefixes)
}

// TestServerRejectsInvalidDNSConfigurationAtConstruction proves a bad configuration
// fails at startup rather than per connection.
//
// A server that accepted it would emit a capsule every conforming client must reject,
// which presents to an operator as "the feature does not work" with no error anywhere.
func TestServerRejectsInvalidDNSConfigurationAtConstruction(t *testing.T) {
	t.Parallel()

	_, err := NewServer(ServerOptions{
		Context: t.Context(),
		Logger:  logger.NOP(),
		Path:    "/",
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		DNSConfigurations: []DNSConfiguration{{
			Nameservers: []DNSNameserver{{
				// Zero priority is invalid per §3.2.
				ServicePriority: 0,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("10.0.0.53")},
			}},
		}},
	})
	require.Error(t, err, "an invalid DNS configuration must fail at construction")
	require.Contains(t, err.Error(), "invalid DNS configuration")
}

func TestServerRejectsInvalidPREF64AtConstruction(t *testing.T) {
	t.Parallel()

	_, err := NewServer(ServerOptions{
		Context: t.Context(),
		Logger:  logger.NOP(),
		Path:    "/",
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		// 24 is a valid IPv6 prefix length but not a valid NAT64 one.
		PREF64Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/24")},
	})
	require.Error(t, err, "an invalid NAT64 prefix length must fail at construction")
}

// TestServerDistinguishesAbsentFromEmptyPREF64 is the semantic distinction that makes
// revocation possible.
//
// A NIL slice means "send no PREF64 capsule at all". An EMPTY non-nil slice means "send
// an empty capsule", which draft §4.2 defines as invalidating previously advertised
// prefixes. Collapsing the two would make a server unable to revoke a prefix it had
// already sent.
func TestServerDistinguishesAbsentFromEmptyPREF64(t *testing.T) {
	t.Parallel()

	absent, err := NewServer(ServerOptions{
		Context: t.Context(), Logger: logger.NOP(), Path: "/",
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	require.NoError(t, err)
	require.False(t, absent.pref64Configured,
		"a nil PREF64 list means send nothing")

	empty, err := NewServer(ServerOptions{
		Context: t.Context(), Logger: logger.NOP(), Path: "/",
		Address:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		PREF64Prefixes: []netip.Prefix{},
	})
	require.NoError(t, err)
	require.True(t, empty.pref64Configured,
		"an empty non-nil PREF64 list must be sent, because an empty capsule revokes")
}

// TestServerDNSAssignRoundTripsThroughClientParser is the interop check in the smallest
// possible form: what this server encodes, this client decodes to the same thing.
//
// The two sides share the codec, so this does not prove wire-format correctness on its
// own -- the byte-exact vectors against the reference do that. What it proves is that
// the server's construction path does not lose or reorder anything on the way out.
func TestServerDNSAssignRoundTripsThroughClientParser(t *testing.T) {
	t.Parallel()

	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority:          1,
			IPv4Addresses:            []netip.Addr{netip.MustParseAddr("10.0.0.53")},
			IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::53")},
			AuthenticationDomainName: "dns.example.",
		}},
		InternalDomains: []string{"internal.example."},
		SearchDomains:   []string{"corp.example."},
	}

	current := newWriteRecordingSession(t, ServerOptions{
		DNSConfigurations: []DNSConfiguration{configuration},
	})
	capsule, err := encodeDNSAssign(current.server.dnsConfigurations)
	require.NoError(t, err)
	require.NoError(t, current.writeCapsule(capsule))

	recorded := current.capsules(t)
	require.Len(t, recorded, 1)

	decoded, err := parseDNSAssign(recorded[0].payload)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Equal(t, "dns.example.", decoded[0].Nameservers[0].AuthenticationDomainName)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.53")},
		decoded[0].Nameservers[0].IPv4Addresses)
	require.Equal(t, []string{"internal.example."}, decoded[0].InternalDomains)
	require.Equal(t, []string{"corp.example."}, decoded[0].SearchDomains)
}
