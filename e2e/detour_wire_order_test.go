package e2e

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DEBUG-02: a real two-hop stand whose WIRE ORDER is observed, not inferred
// ---------------------------------------------------------------------------
//
// The direction correction rests on "the device reaches the DETOUR first". That was established from
// the real `NewDetour` plumbing with a substituted peer, which is a statement about which dialer is
// asked - not about which socket accepts first.
//
// This stand puts the claim under a real dial, with two real SOCKS5 servers and a real origin:
//
//	device -> exit-chain instance (mixed inbound)
//	              |  outbound "exit": socks -> the EXIT server, detour = "entry"
//	              |  outbound "entry": socks -> the ENTRY server
//	              v
//	          EXIT server (real SOCKS5, forwards to the entry) -> ENTRY server -> origin (TCP echo)
//
// Both servers RECORD the target of every CONNECT they are asked for. That recording is the
// evidence: it says what each hop was asked to reach, which is exactly what separates "the entry
// carried the exit's server dial" from "the device dialled the exit directly".

// socksHop is a real SOCKS5 server that records the target of every CONNECT it is asked for.
//
// It is deliberately a SERVER rather than a request recorder: it performs the full handshake,
// answers with a real bound address, and forwards bytes in both directions. A hop that recorded the
// request and then closed would prove nothing about whether the chain carries traffic.
type socksHop struct {
	name     string
	listener net.Listener
	// relay is the ONE target this hop forwards through instead of dialling directly, and only when
	// it is asked for that exact target.
	//
	// # Why an exact match and not "forward everything"
	//
	// The entry hop is asked for the EXIT's server address - that is the whole claim under test - and
	// it must then carry that connection through to where it was asked to go. When the same hop is
	// asked for anything else (the control case, or an origin) it dials normally.
	//
	// A version that forwarded EVERYTHING was circular: the exit forwarded to the entry, the entry
	// was asked for the exit, and around it went. The exact match is what makes the stand mirror the
	// production topology instead of a loop.
	relay        string
	relayThrough string

	mu       sync.Mutex
	requests []string
	accepted int
}

func (h *socksHop) address() string { return h.listener.Addr().String() }

func (h *socksHop) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.requests...)
}

func (h *socksHop) acceptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.accepted
}

func startSocksHop(t *testing.T, name string) *socksHop {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	hop := &socksHop{name: name, listener: listener}
	go hop.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return hop
}

// relayWhenAskedFor makes this hop forward through `through` whenever it is asked for `target`.
func (h *socksHop) relayWhenAskedFor(target string, through string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.relay = target
	h.relayThrough = through
}

func (h *socksHop) serve() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		h.accepted++
		h.mu.Unlock()
		go h.handle(conn)
	}
}

func (h *socksHop) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(header[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	if request[0] != 0x05 || request[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := readSocksTarget(conn, request[3])
	if err != nil {
		return
	}

	// Record BEFORE dialling, so the recording exists even when the forward fails: a hop that was
	// asked for something and could not reach it is still a hop that was asked.
	h.mu.Lock()
	h.requests = append(h.requests, target.String())
	h.mu.Unlock()

	dialAddress := target.String()
	h.mu.Lock()
	if h.relay != "" && h.relay == dialAddress {
		dialAddress = h.relayThrough
	}
	h.mu.Unlock()
	outbound, err := net.DialTimeout("tcp", dialAddress, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer outbound.Close()
	if _, err := conn.Write(buildSOCKSReply(outbound.LocalAddr())); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(outbound, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, outbound); done <- struct{}{} }()
	<-done
}

// readSocksTarget decodes the CONNECT target, INCLUDING the domain case, so a test can tell an
// address from a name - which is what the DNS-ownership rows need.
func readSocksTarget(conn net.Conn, atyp byte) (socksTarget, error) {
	var target socksTarget
	switch atyp {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return target, err
		}
		target.address = netip.AddrFrom4([4]byte(raw))
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return target, err
		}
		target.address = netip.AddrFrom16([16]byte(raw))
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return target, err
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return target, err
		}
		target.domain = string(name)
		target.isDomain = true
	default:
		return target, fmt.Errorf("unsupported atyp %d", atyp)
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return target, err
	}
	target.port = binary.BigEndian.Uint16(port)
	return target, nil
}

// socksTarget is one CONNECT target, kept in the form it arrived in.
type socksTarget struct {
	address  netip.Addr
	domain   string
	port     uint16
	isDomain bool
}

func (t socksTarget) String() string {
	if t.isDomain {
		return net.JoinHostPort(t.domain, fmt.Sprint(t.port))
	}
	return net.JoinHostPort(t.address.String(), fmt.Sprint(t.port))
}

func buildSOCKSReply(local net.Addr) []byte {
	tcpAddress, isTCP := local.(*net.TCPAddr)
	if !isTCP {
		return []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	}
	parsed, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	}
	parsed = parsed.Unmap()
	reply := []byte{0x05, 0x00, 0x00}
	if parsed.Is4() {
		reply = append(reply, 0x01)
		raw := parsed.As4()
		reply = append(reply, raw[:]...)
	} else {
		reply = append(reply, 0x04)
		raw := parsed.As16()
		reply = append(reply, raw[:]...)
	}
	return binary.BigEndian.AppendUint16(reply, uint16(tcpAddress.Port))
}

// TestTheEntryHopIsAskedForTheExitServersAddress is DEBUG-02's central assertion.
//
// # What it proves that no unit test can
//
// The exit socks outbound reaches its OWN server through the entry socks outbound. So the ENTRY
// server is asked for the EXIT server's address, and the EXIT server is asked for the ORIGIN. If the
// model's `Hops[0] == entry` were wrong, the device would reach the exit first and the entry either
// later or not at all.
//
// The distinction matters because a wrong direction makes an operator fix a healthy hop.
func TestTheEntryHopIsAskedForTheExitServersAddress(t *testing.T) {
	t.Parallel()

	origin := startEchoServer(t, "tcp", "127.0.0.1:0")
	originHost, originPort := mustSplitHostPort(t, echoAddress(origin))

	// The entry has no upstream: it dials whatever it is asked for.
	entry := startSocksHop(t, "entry")
	// The exit is a plain SOCKS server: it dials whatever it is asked for.
	exit := startSocksHop(t, "exit")
	// The ENTRY relays to the EXIT, and only when it is asked for the exit's own address. That is
	// the wire meaning of `exit.detour = entry`: the exit reaches its own server through the entry,
	// and the entry carries that connection through.
	entry.relayWhenAskedFor(exit.address(), exit.address())

	exitChainPort := freePort(t)
	exitChain := startChain(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "entry", "server": %q, "server_port": %d, "version": "5"},
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "detour": "entry"}
  ],
  "route": {"final": "exit"}
}`, exitChainPort,
		hostOnly(t, entry.address()), portOnly(t, entry.address()),
		hostOnly(t, exit.address()), portOnly(t, exit.address())))
	t.Cleanup(func() { _ = exitChain.closeNow() })

	deviceAddress := fmt.Sprintf("127.0.0.1:%d", exitChainPort)
	conn := dialSocks5(t, deviceAddress, 0x03, originHost, originPort)
	defer conn.Close()

	payload := []byte("two-hop-wire-order")
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	_, err := conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err, "the two-hop chain must carry the payload, or the recording below "+
		"would describe a chain that does not work")
	require.Equal(t, payload, got)

	// --- the evidence -----------------------------------------------------------------------
	entryRequests := entry.recorded()
	exitRequests := exit.recorded()

	require.NotEmpty(t, exitRequests,
		"the EXIT hop must have been asked for something, or the chain never used it")
	require.NotEmpty(t, entryRequests,
		"the ENTRY hop must have been asked for something. An empty recording here IS the "+
			"direction claim failing: it would mean the exit reached its own server without the "+
			"entry, i.e. that the device reached the exit first")

	require.Contains(t, entryRequests, exit.address(),
		"the ENTRY must have been asked for the EXIT's own server address (%s). Recorded: %v",
		exit.address(), entryRequests)
	require.Contains(t, exitRequests, net.JoinHostPort(originHost, fmt.Sprint(originPort)),
		"and the EXIT must have been asked for the ORIGIN (%s), which is the user's target. "+
			"Recorded: %v", net.JoinHostPort(originHost, fmt.Sprint(originPort)), exitRequests)

	require.GreaterOrEqual(t, entry.acceptCount(), 1, "the entry accepted at least one connection")
	require.GreaterOrEqual(t, exit.acceptCount(), 1, "and so did the exit")
	require.GreaterOrEqual(t, origin.accepts.Load(), int64(1),
		"and the payload reached the origin, so the whole chain is real")
}

// TestWithoutADetourTheEntryIsNotContacted is the CONTROL for the test above.
//
// The same two servers, the same origin, the same dial - with `detour` REMOVED. The entry must then
// never be contacted at all. Without this control, "the entry was asked for the exit's address"
// could be satisfied by a chain that contacts every hop unconditionally, which would make the first
// test meaningless.
func TestWithoutADetourTheEntryIsNotContacted(t *testing.T) {
	t.Parallel()

	origin := startEchoServer(t, "tcp", "127.0.0.1:0")
	originHost, originPort := mustSplitHostPort(t, echoAddress(origin))

	entry := startSocksHop(t, "entry")
	exit := startSocksHop(t, "exit")

	chainPort := freePort(t)
	chainInstance := startChain(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "entry", "server": %q, "server_port": %d, "version": "5"},
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5"}
  ],
  "route": {"final": "exit"}
}`, chainPort,
		hostOnly(t, entry.address()), portOnly(t, entry.address()),
		hostOnly(t, exit.address()), portOnly(t, exit.address())))
	t.Cleanup(func() { _ = chainInstance.closeNow() })

	conn := dialSocks5(t, fmt.Sprintf("127.0.0.1:%d", chainPort), 0x03, originHost, originPort)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	_, err := conn.Write([]byte("direct"))
	require.NoError(t, err)
	reply := make([]byte, 6)
	_, _ = io.ReadFull(conn, reply)

	require.NotEmpty(t, exit.recorded(), "the exit hop is used when it is the one routed to")
	require.Empty(t, entry.recorded(),
		"and the entry must NOT be contacted when nothing detours through it. A non-empty "+
			"recording here would mean the detour is not what put the entry on the path, which "+
			"would invalidate the test above. Recorded: %v", entry.recorded())
	require.Zero(t, entry.acceptCount(), "not even an accept")
}

// echoAddress reports where the harness echo server is listening.
//
// The harness type has no accessor, and this stand needs the address to name as the user target. It
// reads the listener rather than a copied string so it cannot go stale.
func echoAddress(server *echoServer) string { return server.listener.Addr().String() }

// mustSplitHostPort splits an address, failing the test rather than returning an error.
func mustSplitHostPort(t *testing.T, address string) (string, uint16) {
	t.Helper()
	host, portString, err := net.SplitHostPort(address)
	require.NoError(t, err)
	var port uint16
	_, err = fmt.Sscanf(portString, "%d", &port)
	require.NoError(t, err)
	return host, port
}

// hostOnly and portOnly render the two halves of an address as the config wants them: the sing-box
// socks outbound takes `server` and `server_port` as separate fields.
func hostOnly(t *testing.T, address string) string {
	t.Helper()
	host, _ := mustSplitHostPort(t, address)
	return host
}

func portOnly(t *testing.T, address string) uint16 {
	t.Helper()
	_, port := mustSplitHostPort(t, address)
	return port
}
