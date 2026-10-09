// First-datagram measurement for the pinned QUIC client used by the hysteria2
// outbound, with ChromeParrot on and off.
//
// # WHAT IS MEASURED
//
// The length of the first UDP datagram that the pinned QUIC implementation —
// github.com/sagernet/quic-go, replaced in go.mod by
// github.com/Piggy-Cat-bit-shadow/quic-go v0.61.1-0.20260929231714-9c94b1e90d94 —
// actually hands to the socket layer during a hysteria2-style client dial.
//
// The number is taken from a real *net.UDPConn (loopback) wrapped in a
// net.PacketConn decorator whose WriteTo records len(p). That is the exact byte
// count quic-go passed down for the first datagram of the connection's first
// flight; nothing here is read out of a configuration field, and no test in this
// file asserts on config.InitialPacketSize.
//
// The pinned library pads the client's first flight to the connection's maximum
// packet size (packet_packer.go initialPaddingLen pads to maxPacketSize, and
// connection.go maxPacketSize returns config.InitialPacketSize on the client
// while mtuDiscoverer is nil, i.e. before any server transport parameters have
// been processed — mtuDiscoverer is only created in handleTransportParameters).
// The first datagram is therefore a single Initial packet padded with PADDING
// frames to the configured size, which is what makes the configured value
// observable on the wire before any handshake happens.
//
// ChromeParrot is what the hysteria2 outbound uses by default: outbound.go sets
// ChromeParrot: !options.DisableChromeParrot. config.go:109-125 overrides
// initialPacketSize with chromeInitialPacketSize (1250) whenever ChromeParrot is
// set, and config.go:127-152 returns a fresh Config carrying that value, so the
// override is final — an explicit initial_packet_size is discarded.
//
// WHAT IS NOT MEASURED
//
//   - IP-layer fragmentation. This file measures a UDP payload length. Whether a
//     1250-byte payload is split into IP fragments further down is decided by the
//     path MTU and by sing-tun's Go stack / the TUN device, not by quic-go, and
//     nothing here observes IP packets. Any claim about fragmentation on a WARP
//     path is outside what these tests establish.
//
//     For orientation only — arithmetic, not a measurement — 1250 bytes of UDP
//     payload is 1278 bytes on the wire over IPv4 (20 IP + 8 UDP + 1250) and 1298
//     bytes over IPv6 (40 + 8 + 1250). The first fits a 1280-byte MTU without
//     fragmenting; the second does not. quic-go treats InitialPacketSize as a UDP
//     payload size and leaves that layer alone (chrome_parrot.go calls 1250 "UDP
//     payload size for the packets we send").
//
//   - The handshake. The peer is deliberately silent and accepts nothing, so no
//     handshake ever completes and no post-handshake packet size is observed.
//
//   - No real WARP path is involved: no sing-tun, no inbound, no remote server.
//     The only transport in the loop is a loopback UDP socket.
//
// Each measurement writes more than one datagram, and only the first is asserted
// on. The first flight is not necessarily one datagram: the ClientHello may be
// written in several parts (crypto_stream.go initialCryptoStream: "The
// ClientHello might be written in multiple parts"; with ChromeParrot off quic-go
// additionally splits it at chosen offsets), and the packer pads the Initial
// packet of every such datagram to the maximum packet size, so later parts arrive
// as further, equally sized datagrams. Whatever follows the first write is either
// a further part of the first flight or a packet written while this test tears
// the dial down; every write is logged with which side of the teardown it
// happened on.
package hysteria2

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

const (
	// chromeParrotInitialPacketSize mirrors the unexported chromeInitialPacketSize
	// at chrome_parrot.go:19 of the pinned module, which config.go forces into
	// Config.InitialPacketSize for a Chrome-parroting client.
	chromeParrotInitialPacketSize = 1250

	// libraryDefaultInitialPacketSize mirrors internal/protocol params.go:12
	// (InitialPacketSize = 1280), used when the configured value is left at 0.
	// minInitialPacketSize (protocol.go:117) and maxPacketBufferSize
	// (protocol.go:111) are the clamps validateConfig applies to a configured
	// value in [1200, 1452].
	libraryDefaultInitialPacketSize = 1280
	minInitialPacketSize            = 1200
	maxPacketBufferSize             = 1452

	// firstWriteWatchdog and dialExitWatchdog are hang detectors, not timing
	// assumptions. On loopback the first write happens within milliseconds, and
	// nothing in this file waits for a handshake to complete.
	firstWriteWatchdog = 10 * time.Second
	dialExitWatchdog   = 10 * time.Second
)

// observation is everything one dial produced.
type observation struct {
	// size is len(p) of the first WriteTo: the first datagram quic-go put on
	// the socket.
	size int

	// head is a copy of the first bytes of that datagram, used to verify that
	// it really is a client Initial packet and that its declared length
	// accounts for the whole datagram (i.e. the trailing bytes are PADDING
	// inside the Initial packet, not another packet).
	head []byte

	// sizes is every datagram length written before the dial goroutine exited,
	// in order, with teardown[i] saying whether write i happened after this test
	// began tearing the dial down.
	sizes    []int
	teardown []bool

	// dialErr is what DialEarly returned (an error is expected: the peer is
	// silent, so the handshake cannot complete).
	dialErr error

	// dialReturnedAtFirstWrite reports whether the DialEarly call had already
	// returned when the first write reached the socket. Informational: the
	// measurement does not depend on it either way. It is sampled at the moment
	// the first write is observed, not after the dial has been torn down.
	dialReturnedAtFirstWrite bool
}

// measureRequest describes one dial to observe.
type measureRequest struct {
	// chromeParrot maps to quic.Config.ChromeParrot, i.e. hysteria2's
	// !options.DisableChromeParrot.
	chromeParrot bool

	// configuredInitialPacketSize maps to the value the hysteria2 outbound
	// passes as QUICOptions.InitialPacketSize (option initial_packet_size).
	configuredInitialPacketSize int

	// holdFirstWrite makes the first WriteTo block until release() is called,
	// after it has recorded the length. It makes "the write was observed while
	// DialEarly was still running" deterministic instead of a race: the write
	// is executed from the connection run loop, and DialEarly cannot return
	// while that run loop is inside WriteTo.
	holdFirstWrite bool
}

// recordingPacketConn is a net.PacketConn decorator around a real UDP socket.
// It records the length of every datagram handed to WriteTo, in order, and
// signals the first one. It deliberately implements only net.PacketConn: with no
// SyscallConn method quic-go cannot take the OOB/GSO fast path, so every packet
// goes through WriteTo (sys_conn.go basicConn.WritePacket calls c.WriteTo), and
// ECN stays unsupported instead of panicking.
type recordingPacketConn struct {
	conn net.PacketConn

	firstWrite chan struct{}
	once       sync.Once

	hold <-chan struct{}

	// teardown is set by the test just before it cancels the dial, so each write
	// can be labelled with which side of the teardown it happened on.
	teardown *atomic.Bool

	mu     sync.Mutex
	writes []writeRecord
}

type writeRecord struct {
	size           int
	head           []byte
	duringTeardown bool
}

func newRecordingPacketConn(conn net.PacketConn, hold <-chan struct{}, teardown *atomic.Bool) *recordingPacketConn {
	return &recordingPacketConn{
		conn:       conn,
		firstWrite: make(chan struct{}),
		hold:       hold,
		teardown:   teardown,
	}
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	record := writeRecord{size: len(p), duringTeardown: c.teardown.Load()}
	if head := len(p); head > 0 {
		if head > 64 {
			head = 64
		}
		record.head = append([]byte(nil), p[:head]...)
	}
	c.mu.Lock()
	c.writes = append(c.writes, record)
	isFirst := len(c.writes) == 1
	c.mu.Unlock()

	c.once.Do(func() {
		close(c.firstWrite)
	})

	// Block only the first write, and only after it was recorded. A receive
	// from a closed channel returns immediately, so released writes do not
	// stall.
	if isFirst && c.hold != nil {
		<-c.hold
	}

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

func (c *recordingPacketConn) snapshot() []writeRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]writeRecord(nil), c.writes...)
}

// observedDial is a dial in flight, started but not waited for.
type observedDial struct {
	t          *testing.T
	observing  *recordingPacketConn
	udpConn    *net.UDPConn
	cancel     context.CancelFunc
	dialDone   chan error
	dialReturn atomic.Bool
	teardown   atomic.Bool

	releaseOnce sync.Once
	hold        chan struct{}

	finishOnce sync.Once
	final      observation
}

// startObservedDial starts quic.DialEarly in its own goroutine against a real
// loopback UDP socket wrapped in recordingPacketConn.
//
// DialEarly cannot return until the handshake completes, the context is
// cancelled, or the run loop fails (transport.go doDial blocks in a select on
// ctx.Done / errChan / HandshakeComplete after starting conn.run() in a
// separate goroutine). With a silent peer it therefore blocks, which is why the
// dial is started in a goroutine here: the first flight is written by the run
// loop and is observable without the dial call ever returning.
func startObservedDial(t *testing.T, req measureRequest) *observedDial {
	t.Helper()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen loopback UDP: %v", err)
	}

	od := &observedDial{
		t:        t,
		udpConn:  udpConn,
		dialDone: make(chan error, 1),
	}

	var hold chan struct{}
	if req.holdFirstWrite {
		hold = make(chan struct{})
	}
	od.hold = hold
	observing := newRecordingPacketConn(udpConn, hold, &od.teardown)
	od.observing = observing

	ctx, cancel := context.WithCancel(context.Background())
	od.cancel = cancel

	// remoteAddr needs to be routed nowhere in particular; nothing answers it.
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // no peer certificate exists to verify
		NextProtos:         []string{"h3"},
	}
	conf := &quic.Config{
		HandshakeIdleTimeout: 500 * time.Millisecond,
		InitialPacketSize:    uint16(req.configuredInitialPacketSize),
		ChromeParrot:         req.chromeParrot,
	}

	go func() {
		conn, err := quic.DialEarly(ctx, observing, remoteAddr, tlsConf, conf)
		od.dialReturn.Store(true)
		if conn != nil {
			// Never reached against a silent peer (DialEarly returns a
			// connection only once the handshake has progressed), but close it
			// so a surprise success cannot leak goroutines or timers.
			_ = conn.CloseWithError(0, "")
		}
		od.dialDone <- err
	}()

	return od
}

// release unblocks a first WriteTo held by holdFirstWrite. It is safe to call
// more than once and in the non-holding case.
func (od *observedDial) release() {
	od.releaseOnce.Do(func() {
		if od.hold != nil {
			close(od.hold)
		}
	})
}

// waitFirstWrite waits until the first datagram has been handed to the socket
// layer. It never waits for DialEarly to return.
func (od *observedDial) waitFirstWrite() bool {
	od.t.Helper()
	timer := time.NewTimer(firstWriteWatchdog)
	defer timer.Stop()
	select {
	case <-od.observing.firstWrite:
		return true
	case <-timer.C:
		return false
	}
}

// finish releases any held write, cancels the context, closes the socket and
// waits for the dial goroutine to exit, so no goroutine is left behind.
func (od *observedDial) finish() observation {
	od.finishOnce.Do(func() {
		od.release()
		// From here on the test is tearing the dial down; writes that follow are
		// labelled as such, so a teardown packet can never be mistaken for the
		// datagram under test.
		od.teardown.Store(true)
		od.cancel()
		// Closing the socket unblocks the connection's receive loop, so the
		// run loop returns and DialEarly can return.
		_ = od.udpConn.Close()

		select {
		case err := <-od.dialDone:
			od.final.dialErr = err
		case <-time.After(dialExitWatchdog):
			od.t.Errorf("DialEarly goroutine did not exit within %s after the context was cancelled and the socket closed", dialExitWatchdog)
		}

		writes := od.observing.snapshot()
		od.final.sizes = make([]int, 0, len(writes))
		od.final.teardown = make([]bool, 0, len(writes))
		for _, w := range writes {
			od.final.sizes = append(od.final.sizes, w.size)
			od.final.teardown = append(od.final.teardown, w.duringTeardown)
		}
		if len(writes) > 0 {
			od.final.size = writes[0].size
			od.final.head = writes[0].head
		} else {
			od.final.size = -1
		}
		// dialReturnedAtFirstWrite is filled in by the caller, which samples it
		// while the dial is still in flight (or before cancelling it).
	})
	return od.final
}

// measureFirstDatagram runs one dial to completion of the observation and
// returns what the socket saw. Every measurement is logged.
func measureFirstDatagram(t *testing.T, req measureRequest) observation {
	t.Helper()
	od := startObservedDial(t, req)
	if !od.waitFirstWrite() {
		od.finish()
		t.Fatalf("no datagram reached WriteTo within %s (chromeParrot=%v configuredInitialPacketSize=%d)",
			firstWriteWatchdog, req.chromeParrot, req.configuredInitialPacketSize)
	}
	// Sample the ordering question before doing anything that could end the
	// dial: cancelling the context is what eventually makes DialEarly return
	// here, so reading the flag afterwards would always report true.
	dialReturnedAtFirstWrite := od.dialReturn.Load()
	od.release()
	obs := od.finish()
	obs.dialReturnedAtFirstWrite = dialReturnedAtFirstWrite

	t.Logf("measurement: chromeParrot=%v configuredInitialPacketSize=%d -> first datagram = %d bytes; DialEarly had already returned when the first write was observed: %v; DialEarly ended with: %v; every datagram written before the dial goroutine exited: %s",
		req.chromeParrot, req.configuredInitialPacketSize, obs.size, obs.dialReturnedAtFirstWrite, obs.dialErr, formatDatagramSequence(obs.sizes, obs.teardown))

	// The size only means "the configured packet size reached the wire" if the
	// datagram really is one client Initial packet whose declared length covers
	// the whole datagram — i.e. the configured size is PADDING inside that
	// packet. Anything else would make the number above measure something else.
	summary, singleInitial := describeInitialDatagram(obs.head, obs.size)
	if singleInitial {
		t.Logf("  first datagram parses as: %s", summary)
	} else {
		t.Errorf("first datagram is not a single client Initial packet filling the datagram (chromeParrot=%v configuredInitialPacketSize=%d): %s",
			req.chromeParrot, req.configuredInitialPacketSize, summary)
	}
	return obs
}

// describeInitialDatagram parses the long header of the first datagram and
// reports whether its declared packet length accounts for the whole datagram.
// When it does, the datagram is one Initial packet and the trailing bytes are
// PADDING frames inside that packet — which is exactly what padding to a
// configured size looks like on the wire. The summary is human-readable in both
// cases.
func describeInitialDatagram(b []byte, datagramSize int) (summary string, singleInitial bool) {
	if len(b) < 7 {
		return fmt.Sprintf("datagram too short to parse: % x", b), false
	}
	if b[0]&0x80 == 0 || b[0]&0x40 == 0 {
		return fmt.Sprintf("first byte 0x%02x is not a long header with the fixed bit set: % x", b[0], b), false
	}
	packetType := (b[0] & 0x30) >> 4 // 0 = Initial
	if packetType != 0 {
		return fmt.Sprintf("long header packet type %d (not Initial)", packetType), false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	offset := 5
	dcidLen := int(b[offset])
	offset++
	if offset+dcidLen+1 > len(b) {
		return fmt.Sprintf("destination connection ID length %d does not fit the captured bytes", dcidLen), false
	}
	offset += dcidLen
	scidLen := int(b[offset])
	offset++
	if offset+scidLen > len(b) {
		return fmt.Sprintf("source connection ID length %d does not fit the captured bytes", scidLen), false
	}
	offset += scidLen

	readVarint := func() (uint64, int, bool) {
		if offset >= len(b) {
			return 0, 0, false
		}
		length := 1 << (b[offset] >> 6)
		if offset+length > len(b) {
			return 0, 0, false
		}
		var v uint64
		for i := 0; i < length; i++ {
			v = v<<8 | uint64(b[offset+i])
		}
		v &= (1 << (7 * length)) - 1
		return v, length, true
	}

	tokenLen, tokenLenBytes, ok := readVarint()
	if !ok {
		return "token length is not a readable varint", false
	}
	offset += tokenLenBytes + int(tokenLen)
	declaredLen, declaredLenBytes, ok := readVarint()
	if !ok {
		return "packet length is not a readable varint", false
	}
	offset += declaredLenBytes

	remaining := datagramSize - offset
	summary = fmt.Sprintf(
		"version=0x%08x dcidLen=%d scidLen=%d tokenLen=%d declaredPacketLen=%d remainingDatagramBytes=%d (PN+payload+AEAD)",
		version, dcidLen, scidLen, tokenLen, declaredLen, remaining)

	switch {
	case int(declaredLen) == remaining:
		return summary + " -> single Initial packet filling the datagram, remainder is PADDING frames", true
	case int(declaredLen) < remaining:
		return summary + " -> declared length is shorter than the datagram", false
	default:
		return summary + " -> declared length exceeds the datagram", false
	}
}

// TestChromeParrotOnOffFirstDatagramSize measures the first datagram with
// ChromeParrot off and on for the same configured initial_packet_size.
//
// Both expectations below were measured against the pinned module; they are not
// taken from the library source. The measured values are logged on every run, so
// a change in the pinned revision shows up as a log line and a failure instead of
// a silently stale expectation.
func TestChromeParrotOnOffFirstDatagramSize(t *testing.T) {
	off := measureFirstDatagram(t, measureRequest{chromeParrot: false, configuredInitialPacketSize: 1232})
	on := measureFirstDatagram(t, measureRequest{chromeParrot: true, configuredInitialPacketSize: 1232})

	// Measured, not assumed: with ChromeParrot off the first datagram is the
	// configured 1232-byte payload.
	if off.size != 1232 {
		t.Errorf("ChromeParrot off with initial_packet_size=1232: first datagram = %d bytes, measured expectation is 1232", off.size)
	}
	// Measured, not assumed: with ChromeParrot on the configured 1232 is
	// discarded and the first datagram is chromeInitialPacketSize (1250).
	if on.size != chromeParrotInitialPacketSize {
		t.Errorf("ChromeParrot on with initial_packet_size=1232: first datagram = %d bytes, measured expectation is %d (chrome_parrot.go chromeInitialPacketSize)",
			on.size, chromeParrotInitialPacketSize)
	}
	// Independent corroboration that the ChromeParrot branch itself ran, rather
	// than something else happening to change the size: that branch also selects
	// Chrome's fixed 8-byte initial destination connection ID (transport.go sets
	// genInitialConnID = protocol.GenerateChromeConnectionIDForInitial when
	// conf.ChromeParrot, and protocol.ChromeConnectionIDLenInitial is 8) and a
	// zero-length source connection ID (setupTransport installs
	// ZeroLengthConnectionIDGenerator when conf.ChromeParrot). A non-parroting
	// client randomizes the destination connection ID length instead (8..20 was
	// observed across runs, so 8 alone would not prove anything there).
	if dcidLen, scidLen, ok := parseInitialHeaderLengths(on.head); ok {
		t.Logf("first datagram connection IDs with ChromeParrot on: destination length %d, source length %d", dcidLen, scidLen)
		if dcidLen != 8 {
			t.Errorf("ChromeParrot on: initial destination connection ID length = %d, want Chrome's fixed 8", dcidLen)
		}
		if scidLen != 0 {
			t.Errorf("ChromeParrot on: source connection ID length = %d, want 0 (ZeroLengthConnectionIDGenerator)", scidLen)
		}
	} else {
		t.Errorf("could not parse the connection ID lengths of the first datagram: % x", on.head)
	}
	if dcidLen, scidLen, ok := parseInitialHeaderLengths(off.head); ok {
		t.Logf("first datagram connection IDs with ChromeParrot off: destination length %d, source length %d (destination length is randomized by the library)", dcidLen, scidLen)
	}

	if on.size == off.size {
		t.Errorf("ChromeParrot did not change the first datagram size (both %d bytes); the override is expected to be observable on the wire", on.size)
	}
}

// parseInitialHeaderLengths reads the destination and source connection ID
// lengths out of the start of a long header packet.
func parseInitialHeaderLengths(head []byte) (dcidLen, scidLen int, ok bool) {
	if len(head) < 7 || head[0]&0x80 == 0 || head[0]&0x40 == 0 {
		return 0, 0, false
	}
	dcidLen = int(head[5])
	offset := 6 + dcidLen
	if offset >= len(head) {
		return 0, 0, false
	}
	return dcidLen, int(head[offset]), true
}

// TestConfiguredInitialPacketSizeIsDiscardedUnderChromeParrot is the load
// bearing claim: with ChromeParrot on (hysteria2's default), an explicit
// initial_packet_size is discarded and every configured value produces the same
// first datagram, chromeInitialPacketSize = 1250.
func TestConfiguredInitialPacketSizeIsDiscardedUnderChromeParrot(t *testing.T) {
	configured := []int{0, 1200, 1232, 1250}

	measured := make(map[int]int, len(configured))
	for _, size := range configured {
		obs := measureFirstDatagram(t, measureRequest{chromeParrot: true, configuredInitialPacketSize: size})
		measured[size] = obs.size
	}

	for _, size := range configured {
		if measured[size] != chromeParrotInitialPacketSize {
			t.Errorf("ChromeParrot on with initial_packet_size=%d: first datagram = %d bytes, want %d",
				size, measured[size], chromeParrotInitialPacketSize)
		}
	}

	// Distinct configured values must not leak through in any pair.
	for _, a := range configured {
		for _, b := range configured {
			if measured[a] != measured[b] {
				t.Errorf("ChromeParrot on: initial_packet_size=%d produced %d bytes but initial_packet_size=%d produced %d bytes; the configured value is expected to be discarded",
					a, measured[a], b, measured[b])
			}
		}
	}

	t.Logf("ChromeParrot on: configured %v -> first datagrams %v (all identical)", configured, mapValues(configured, measured))
}

// TestChromeParrotOffHonoursConfiguredValues is the control: with ChromeParrot
// off the configured value reaches the wire, 0 means the library default, and
// quic-go clamps out-of-range values to [1200, 1452].
func TestChromeParrotOffHonoursConfiguredValues(t *testing.T) {
	cases := []struct {
		configured int
		want       int
		why        string
	}{
		{0, libraryDefaultInitialPacketSize, "0 means the library default (internal/protocol params.go InitialPacketSize = 1280)"},
		{1200, minInitialPacketSize, "the minimum an Initial packet may be"},
		{1232, 1232, "a typical 1280-byte MTU choice, honoured as configured"},
		{1250, chromeParrotInitialPacketSize, "the same value ChromeParrot would force anyway"},
		{900, minInitialPacketSize, "below the minimum: clamped up to 1200"},
		{1500, maxPacketBufferSize, "above the maximum: clamped down to 1452"},
	}

	for _, tc := range cases {
		obs := measureFirstDatagram(t, measureRequest{chromeParrot: false, configuredInitialPacketSize: tc.configured})
		if obs.size != tc.want {
			t.Errorf("ChromeParrot off with initial_packet_size=%d: first datagram = %d bytes, want %d (%s)",
				tc.configured, obs.size, tc.want, tc.why)
		}
	}
}

// TestFirstDatagramIsObservedWhileDialEarlyStillRunning pins down the mechanism
// the tests above depend on: the first datagram is written from inside the
// connection's run loop, so it can be observed while the DialEarly call that
// started it has not returned and never needs to return.
//
// The first WriteTo is held until this test releases it. While it is held, the
// goroutine that called DialEarly cannot have returned: DialEarly only returns
// on context cancellation, on a run-loop error, or when the handshake completes
// (transport.go doDial), and the run loop is the goroutine currently inside
// WriteTo. The check below is therefore deterministic, not a race.
func TestFirstDatagramIsObservedWhileDialEarlyStillRunning(t *testing.T) {
	od := startObservedDial(t, measureRequest{
		chromeParrot:                true,
		configuredInitialPacketSize: 1232,
		holdFirstWrite:              true,
	})
	defer od.finish()

	if !od.waitFirstWrite() {
		t.Fatalf("no datagram reached WriteTo within %s while the dial was in flight", firstWriteWatchdog)
	}

	writes := od.observing.snapshot()
	if len(writes) == 0 {
		t.Fatalf("first write signalled but no write was recorded")
	}
	t.Logf("first datagram = %d bytes, observed while its WriteTo was still held and DialEarly had not returned (dialReturned=%v)",
		writes[0].size, od.dialReturn.Load())

	if od.dialReturn.Load() {
		t.Errorf("DialEarly returned although its first write was still blocked in WriteTo")
	}
	if writes[0].size != chromeParrotInitialPacketSize {
		t.Errorf("first datagram = %d bytes, want %d", writes[0].size, chromeParrotInitialPacketSize)
	}

	od.release()
	obs := od.finish()
	if obs.size != chromeParrotInitialPacketSize {
		t.Errorf("after release the recorded first datagram is %d bytes, want %d", obs.size, chromeParrotInitialPacketSize)
	}
	t.Logf("dial ended with: %v (an error is expected: the peer is silent, no handshake completes)", obs.dialErr)
}

func mapValues(keys []int, values map[int]int) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%d->%d", key, values[key]))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// formatDatagramSequence renders every datagram length in order, labelled with
// whether it was written while the dial was still live or after this test began
// tearing it down.
func formatDatagramSequence(sizes []int, teardown []bool) string {
	parts := make([]string, 0, len(sizes))
	for i, size := range sizes {
		phase := "during dial"
		if i < len(teardown) && teardown[i] {
			phase = "during teardown"
		}
		parts = append(parts, fmt.Sprintf("%d bytes (%s)", size, phase))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}
