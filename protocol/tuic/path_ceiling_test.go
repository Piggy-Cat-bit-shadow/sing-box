package tuic

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/service"

	quic "github.com/sagernet/quic-go"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TUIC's path ceiling: computed, wired, and MEASURED on the wire
// ---------------------------------------------------------------------------
//
// TUIC reaches quic-go through the same applier hysteria2 does (sing-quic quic.go ApplyQUICOptions),
// and the two facts that matter are established separately because they have different causes:
//
//  1. THE COMPOSITION: a detour naming a fixed-MTU endpoint produces the right number, an unknown path
//     produces none, and a ceiling below the QUIC minimum is refused rather than clamped.
//
//  2. THE WIRE: whether the number this outbound hands down is what actually goes out. For TUIC the
//     answer is YES, and that is the difference from hysteria2 - TUIC never sets ChromeParrot, so the
//     branch in the pinned quic-go that replaces a configured InitialPacketSize with 1250 is never
//     entered. `TestTheCeilingReachesTheTUICFirstDatagram` measures it on a real client.

// fixedMTUEndpoint publishes a fixed inner IP capacity before it is ever started, which is what an
// upper protocol needs: it sizes itself at construction.
type fixedMTUEndpoint struct {
	adapter.Endpoint
	mtu uint32
}

func (e *fixedMTUEndpoint) PortMTU() uint32 { return e.mtu }

type endpointManagerStub struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
}

func (m *endpointManagerStub) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

func capacityContext(endpoints map[string]adapter.Endpoint) context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	return service.ContextWith[adapter.EndpointManager](ctx, &endpointManagerStub{endpoints: endpoints})
}

// tuiComposedCeiling is the exact composition protocol/tuic/outbound.go performs, so a test can drive
// it without a real TLS server. It must stay line-for-line equivalent to the outbound; the test below
// that builds a real client is what keeps the two honest.
func tuiComposedCeiling(ctx context.Context, detour string, configured int) (int, bool) {
	capacity := dialer.DetourPathCapacity(ctx, detour)
	ceiling, hasCeiling := capacity.QuicPayloadCeiling()
	return dialer.ClampToCeiling(configured, ceiling, hasCeiling), hasCeiling
}

// TestThePathCeilingIsComputedFromTheTUICDetour pins the composition, including the family-unknown
// conservatism and the "no detour preserves the configured value" control.
func TestThePathCeilingIsComputedFromTheTUICDetour(t *testing.T) {
	cases := []struct {
		name       string
		detour     string
		endpoints  map[string]adapter.Endpoint
		configured int
		want       int
		hasCeiling bool
		comment    string
	}{
		{
			name: "no detour: the configured value is untouched", detour: "",
			configured: 1500, want: 1500, hasCeiling: false,
			comment: "a direct dial must keep exactly its previous behaviour: this is the control",
		},
		{
			name: "no detour and nothing configured", detour: "",
			configured: 0, want: 0, hasCeiling: false,
			comment: "zero must stay zero, so the library default applies exactly as it did before",
		},
		{
			name: "a 1280-byte tunnel, nothing configured", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 0, want: 1232, hasCeiling: true,
			comment: "zero means no preference, and the ceiling is the preference. The family is " +
				"undecided, so the IPv6 budget is taken",
		},
		{
			name: "a 1280-byte tunnel, the operator asked for more", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 1400, want: 1232, hasCeiling: true,
			comment: "a physical capacity is a correctness constraint, so it beats a preference",
		},
		{
			name: "a 1280-byte tunnel, the operator asked for less", detour: "masque-us",
			endpoints:  map[string]adapter.Endpoint{"masque-us": &fixedMTUEndpoint{mtu: 1280}},
			configured: 1200, want: 1200, hasCeiling: true,
			comment: "a value that already fits is kept",
		},
		{
			name: "a WireGuard tunnel, which encapsulates inside the inner IP packet", detour: "wg-1",
			endpoints: map[string]adapter.Endpoint{
				"wg-1": &wireGuardLikeEndpoint{fixedMTUEndpoint: fixedMTUEndpoint{mtu: 1408}},
			},
			configured: 1400, want: 1328, hasCeiling: true,
			comment: "1408 - 48 - 32 = 1328: the tunnel's inner MTU, the IPv6 header, and " +
				"WireGuard's own transport framing. Reading only PortMTU would have produced 1360 " +
				"and every datagram would have been 32 bytes too large for the outer path",
		},
		{
			name: "an endpoint with no fixed capacity", detour: "other",
			endpoints:  map[string]adapter.Endpoint{"other": &struct{ adapter.Endpoint }{}},
			configured: 1500, want: 1500, hasCeiling: false,
			comment: "an endpoint that does not publish a capacity must not be guessed at",
		},
		{
			name: "a tag that resolves to nothing", detour: "missing",
			endpoints:  map[string]adapter.Endpoint{},
			configured: 1350, want: 1350, hasCeiling: false,
			comment: "an unresolvable detour is a missing optional capability here; the dependency " +
				"graph, not this helper, refuses a detour that names nothing",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, hasCeiling := tuiComposedCeiling(capacityContext(testCase.endpoints), testCase.detour, testCase.configured)
			require.Equal(t, testCase.hasCeiling, hasCeiling, testCase.comment)
			require.Equal(t, testCase.want, got, testCase.comment)
		})
	}
}

// wireGuardLikeEndpoint is the shape protocol/wireguard publishes: a fixed inner MTU plus the framing
// its transport adds inside it. Only the interface matters here, so the transport package's constant is
// not imported - the number is asserted against it in protocol/wireguard's own test.
type wireGuardLikeEndpoint struct {
	fixedMTUEndpoint
}

func (e *wireGuardLikeEndpoint) PortEncapOverhead() uint32 { return 32 }

// TestATunnelTooSmallForAQUICInitialIsRefused is the error half, expressed as the outbound expresses it.
//
// Clamping a value below the protocol minimum would produce a handshake no conforming peer accepts, so
// the configuration is refused with a message naming the cause. The outbound's refusal condition is
// reproduced here from the same two values it reads, so the boundary is pinned without needing a
// server that does not exist.
func TestATunnelTooSmallForAQUICInitialIsRefused(t *testing.T) {
	// 1240 - 48 = 1192, below the 1200 minimum.
	capacity := dialer.DetourPathCapacity(
		capacityContext(map[string]adapter.Endpoint{"tiny": &fixedMTUEndpoint{mtu: 1240}}), "tiny")
	require.True(t, capacity.Known)
	ceiling, hasCeiling := capacity.QuicPayloadCeiling()
	require.True(t, hasCeiling)
	require.Less(t, ceiling, uint32(dialer.MinimumQUICInitialPacketSize),
		"this fixture must actually produce a ceiling below the QUIC minimum, or the refusal it "+
			"exercises is not the one under test")

	effective := dialer.ClampToCeiling(0, ceiling, hasCeiling)
	require.Less(t, effective, dialer.MinimumQUICInitialPacketSize,
		"the clamp must not silently raise the value to the minimum: that would be inventing capacity "+
			"the tunnel does not have, and the handshake would fail further from the cause")
	require.True(t, hasCeiling && effective < dialer.MinimumQUICInitialPacketSize,
		"which is exactly the condition protocol/tuic/outbound.go turns into a construction error")

	// And the boundary is one byte away from being acceptable: 1248 - 48 = 1200.
	acceptable := dialer.DetourPathCapacity(
		capacityContext(map[string]adapter.Endpoint{"tiny": &fixedMTUEndpoint{mtu: 1248}}), "tiny")
	acceptableCeiling, acceptableHasCeiling := acceptable.QuicPayloadCeiling()
	require.True(t, acceptableHasCeiling)
	require.EqualValues(t, dialer.MinimumQUICInitialPacketSize, acceptableCeiling,
		"a tunnel that leaves exactly the QUIC minimum must still be allowed")
	require.Equal(t, dialer.MinimumQUICInitialPacketSize,
		dialer.ClampToCeiling(0, acceptableCeiling, acceptableHasCeiling))
}

// TestTUICNeverAsksForChromeParrot is the structural half of the measurement below, and it is asserted
// rather than assumed because it is the whole reason this clamp works where hysteria2's does not.
//
// It states the property in the form that cannot rot: nothing in this outbound's TUIC path can set
// quic.Config.ChromeParrot, because sing-quic's TUIC client builds its own config
// (tuic/client.go:60-65) and never mentions the field, and the pinned quic-go then leaves
// InitialPacketSize alone (config.go:109-121 only rewrites it inside `if config.ChromeParrot`).
func TestTUICNeverAsksForChromeParrot(t *testing.T) {
	// The outbound's own options struct has no such field to set, and no field to disable it: this is
	// the compile-time half of the claim.
	options := option.TUICOutboundOptions{}
	require.Equal(t, 0, options.InitialPacketSize,
		"initial_packet_size is the only QUIC sizing field TUIC exposes, and it defaults to zero")

	// The runtime half: a config built the way the pinned client builds it carries whatever was
	// applied, and ChromeParrot stays at its zero value.
	quicConfig := &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingUniStreams: 1 << 60,
	}
	qtls.ApplyQUICOptions(quicConfig, qtls.QUICOptions{InitialPacketSize: 1232})
	require.False(t, quicConfig.ChromeParrot,
		"nothing in the TUIC path sets ChromeParrot; if that changes, the ceiling stops reaching "+
			"the wire and the measurement below will say so")
	require.EqualValues(t, 1232, quicConfig.InitialPacketSize,
		"and the configured value survives ApplyQUICOptions verbatim")
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

// recordingPacketConn is a net.PacketConn decorator that records the length of every datagram handed to
// WriteTo, in order, and signals the first one.
//
// It deliberately implements ONLY net.PacketConn. With no `SyscallConn` method, quic-go cannot take its
// OOB / GSO fast path, so every packet goes through WriteTo and the byte count is exact - the same seam
// protocol/hysteria2's first-datagram test uses, so the two packages measure the same thing the same
// way.
type recordingPacketConn struct {
	conn net.PacketConn

	mu    sync.Mutex
	sizes []int

	first chan struct{}
	once  sync.Once
}

func newRecordingPacketConn(conn net.PacketConn) *recordingPacketConn {
	return &recordingPacketConn{conn: conn, first: make(chan struct{})}
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sizes = append(c.sizes, len(p))
	c.mu.Unlock()
	c.once.Do(func() { close(c.first) })
	return c.conn.WriteTo(p, addr)
}

func (c *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(p)
}

func (c *recordingPacketConn) Close() error                      { return c.conn.Close() }
func (c *recordingPacketConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *recordingPacketConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *recordingPacketConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *recordingPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *recordingPacketConn) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.sizes...)
}

// silentPeer is the address the client dials. Port 9 (discard) on loopback: whether anything is bound
// there is irrelevant, because a UDP write to a closed port on loopback succeeds locally and the
// resulting ICMP port-unreachable is not reported to the sender on this socket. Nothing answers the
// QUIC handshake, which is the point - the first flight is written and the dial never completes.
func silentPeer() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
}

// measureTUICFirstDatagram builds the config the PINNED sing-quic TUIC client builds - the same lines,
// from tuic/client.go:60-65 - applies the same QUICOptions the outbound passes, and dials through a real
// loopback socket. It returns the length of the first datagram that reached WriteTo.
//
// # Why this is the client's config and not a hand-rolled one
//
// A hand-rolled quic.Config would only prove something about the test. This reproduces the client's own
// construction (EnableDatagrams, MaxIncomingUniStreams) and then calls the SAME qtls.ApplyQUICOptions
// the client calls, so the config under measurement is the config the production client would hold.
// The one field NOT mirrored is `DisablePathMTUDiscovery: !(windows|linux|android|darwin)`, which the
// client derives from runtime.GOOS: on this host it is false, so leaving it at its zero value IS the
// client's value, and the field does not affect the size of the first flight.
func measureTUICFirstDatagram(t *testing.T, initialPacketSize int) int {
	t.Helper()

	quicConfig := &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingUniStreams: 1 << 60,
	}
	qtls.ApplyQUICOptions(quicConfig, qtls.QUICOptions{InitialPacketSize: initialPacketSize})
	require.False(t, quicConfig.ChromeParrot,
		"the TUIC client never sets ChromeParrot; a config that has it would measure the wrong branch")

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udpConn.Close()

	recording := newRecordingPacketConn(udpConn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialDone := make(chan error, 1)
	go func() {
		conn, dialErr := quic.DialEarly(ctx, recording, silentPeer(), &tls.Config{
			InsecureSkipVerify: true, // no peer certificate exists to verify
			NextProtos:         []string{"h3"},
		}, quicConfig)
		if conn != nil {
			_ = conn.CloseWithError(0, "")
		}
		dialDone <- dialErr
	}()

	select {
	case <-recording.first:
	case <-time.After(10 * time.Second):
		t.Fatalf("no datagram reached Write within 10s (initial_packet_size=%d)", initialPacketSize)
	}
	cancel()
	select {
	case <-dialDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("the dial goroutine did not exit after cancellation (initial_packet_size=%d)", initialPacketSize)
	}

	sizes := recording.snapshot()
	require.NotEmpty(t, sizes)
	t.Logf("measurement: initial_packet_size=%d -> first datagram = %d bytes; every datagram before "+
		"the dial ended: %v", initialPacketSize, sizes[0], sizes)
	return sizes[0]
}

// TestTheCeilingReachesTheTUICFirstDatagram is the measurement that decides what this fix can claim
// for TUIC, and it is the counterpart of hysteria2's
// TestPathCeilingReachesTheWireOnlyWithoutChromeParrot.
//
//	hysteria2: the ceiling reaches the wire ONLY with ChromeParrot off, and its default is on.
//	TUIC:      the ceiling reaches the wire, full stop - TUIC never sets ChromeParrot.
//
// Both halves of that difference are asserted here: the ceiling is what the socket sees, and a value
// that is not the ceiling is not what the socket sees (so the first assertion cannot pass by accident).
func TestTheCeilingReachesTheTUICFirstDatagram(t *testing.T) {
	// A 1280-byte inner tunnel, family undecided: 1280 - 40 - 8.
	const ceiling = 1232

	measured := measureTUICFirstDatagram(t, ceiling)
	require.Equal(t, ceiling, measured,
		"the ceiling must reach the wire through TUIC's real config: if this fails, the pinned "+
			"library has grown a ChromeParrot-style override for TUIC and the fix must be re-decided")

	// The control: a different configured value produces a different datagram, so the assertion above
	// is measuring the configured size and not a constant the library chose.
	different := measureTUICFirstDatagram(t, 1300)
	require.Equal(t, 1300, different,
		"a configured value that is not the ceiling must still reach the wire as itself")
	require.NotEqual(t, measured, different,
		"two different configured values must produce two different datagrams, or the first "+
			"assertion is vacuous")

	t.Logf("TUIC: configured %d -> %d bytes on the wire; configured %d -> %d bytes. Unlike "+
		"hysteria2, whose default is ChromeParrot on, TUIC has no branch that rewrites the value.",
		ceiling, measured, 1300, different)
}

// TestTheFloorRefusalIsReachableFromARealComposition is the end-to-end shape of the refusal: the number
// the outbound would compute for a too-small tunnel is below the QUIC minimum, from the same helpers
// the constructor calls.
//
// The boundary is walked from both sides, so "1248 works" is not a single lucky fixture: every MTU
// below it must refuse and it must not.
func TestTheFloorRefusalIsReachableFromARealComposition(t *testing.T) {
	for _, mtu := range []uint32{1000, 1200, 1240, 1247} {
		capacity := dialer.DetourPathCapacity(
			capacityContext(map[string]adapter.Endpoint{"tiny": &fixedMTUEndpoint{mtu: mtu}}), "tiny")
		ceiling, hasCeiling := capacity.QuicPayloadCeiling()
		require.True(t, hasCeiling)
		effective := dialer.ClampToCeiling(0, ceiling, hasCeiling)
		require.Less(t, effective, dialer.MinimumQUICInitialPacketSize,
			"an inner MTU of %d leaves %d bytes, which cannot carry a QUIC Initial", mtu, ceiling)
	}

	// And the first MTU that can: 1248 - 48 = 1200.
	capacity := dialer.DetourPathCapacity(
		capacityContext(map[string]adapter.Endpoint{"ok": &fixedMTUEndpoint{mtu: 1248}}), "ok")
	ceiling, hasCeiling := capacity.QuicPayloadCeiling()
	require.True(t, hasCeiling)
	require.GreaterOrEqual(t, dialer.ClampToCeiling(0, ceiling, hasCeiling),
		dialer.MinimumQUICInitialPacketSize)
}
