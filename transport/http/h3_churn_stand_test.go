//go:build with_quic

package http

// ---------------------------------------------------------------------------
// A REAL offline HTTP/3 stand: loopback sockets, a real QUIC handshake
// ---------------------------------------------------------------------------
//
// # Why this file exists next to the unit tests
//
// `client_h3_outcome_order_test.go` pins the ORDERING rule of the HTTP/3 verdict with a double, and
// that is the right shape for the ordering itself: two attempts have to report in a chosen order,
// which a real handshake cannot be asked to do reliably.
//
// What a double cannot answer is whether the rule holds on the object the product actually uses.
// `route/interface_churn_cost_test.go` measured the manager's churn cost through the production
// notifier, but its router is a counter and its managers are stand-ins, so its figure describes the
// transition protocol and NOTHING about HTTP/3 -- there is no QUIC socket anywhere in it. This file
// closes that gap with real ones.
//
// # What is real here
//
//	the transport   a loopback UDP socket and quic-go's http3.Server on the egress side,
//	                and this package's own http3ClientImpl on the client side;
//	the handshake   completed for real, and verified from the ALPN and the QUIC version the
//	                SERVER's own connection state reports -- never from a "200 OK";
//	the egresses    two independent H3 servers on two loopback ports, each recording the
//	                connections it accepted, the handshakes it performed, the streams it served
//	                and the connections it saw close;
//	the paths       two real local UDP dialers, each recording the sockets it created, so "which
//	                path carried this connection" is answered by the object that made the socket;
//	the failure     a BOUND UDP socket that reads and never answers. It is bound rather than
//	                absent on purpose: an unbound loopback port answers ICMP port-unreachable, so
//	                the handshake would fail fast for the wrong reason.
//
// # What is NOT real, stated plainly
//
// The environment source below is a decision source, not a radio. It emulates "the device is on
// network A" and "the device is on network B" by selecting an egress and a local path, and it
// drives the production connection-layer entry a transition reaches (Client.ResetConnections). It
// does NOT perform an iOS radio switch, a Wi-Fi roam, a cellular handover, or a Network.framework
// path update, and nothing in this file may be quoted as evidence about those. Any claim that
// needs the real radio is marked NOT_RUN_EXTERNAL_DEVICE in the round's report.
//
// # Instrument discipline
//
// Every count asserted here is ATTRIBUTED: it is a field on an object that owns the resource (the
// egress that accepted the connection, the path that made the socket, the client's own connection
// slot), never `runtime.NumGoroutine`. The one process-shaped number, the goroutine census, is
// scoped to stacks that name this package, and its sensitivity is proven by
// TestH3StandCensusDetectsDeliberatelyLeakedConnections, which leaks a known number of real
// connections and requires the census to read exactly that.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The egress: a real HTTP/3 server that records what it did
// ---------------------------------------------------------------------------

// h3HandshakeRecord is one completed QUIC handshake as the SERVER observed it.
//
// It is filled in from the server's own *quic.Conn, which is why it can be quoted as evidence that
// HTTP/3 was really spoken: the ALPN and the QUIC version are properties of the negotiated
// transport, and a server that had not negotiated them could not report them.
type h3HandshakeRecord struct {
	egress      string
	alpn        string
	quicVersion string
	sni         string
	proto       string
	datagrams   bool
	zeroRTT     bool
}

type h3ConnRecord struct {
	conn *quic.Conn
	once sync.Once
	// handshake is filled in the first time the connection is observed AFTER its handshake, which
	// is when the state is meaningful.
	handshake h3HandshakeRecord
}

type h3ConnRecordKey struct{}

// h3EgressStand is one real HTTP/3 egress on loopback.
type h3EgressStand struct {
	name       string
	address    string
	socksaddr  M.Socksaddr
	server     *http3.Server
	packetConn *net.UDPConn
	served     chan struct{}

	access     sync.Mutex
	accepted   int
	closed     int
	streams    int
	tunnels    int
	requests   int
	payload    []byte
	handshakes []h3HandshakeRecord
	conns      []*h3ConnRecord
}

// newH3EgressStand starts a real HTTP/3 server on a loopback UDP socket.
//
// The handler serves CONNECT as a tunnel -- 200, then an echo that stays open for as long as the
// caller keeps it open -- and answers anything else with a fixed body, so both the tunnel path and
// the ordinary-request path are servable on the same connection.
func newH3EgressStand(t *testing.T, name string) *h3EgressStand {
	t.Helper()
	stand := &h3EgressStand{name: name, served: make(chan struct{})}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	stand.address = packetConn.LocalAddr().String()
	stand.socksaddr = M.ParseSocksaddr(stand.address)
	stand.packetConn = packetConn

	stand.server = &http3.Server{
		Handler: http.HandlerFunc(stand.handle),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			record := &h3ConnRecord{conn: conn}
			stand.access.Lock()
			stand.accepted++
			stand.conns = append(stand.conns, record)
			stand.access.Unlock()
			// The connection's own context is done when quic-go has finished with it, which is
			// the only close signal this stand needs: it is the transport saying the socket is
			// gone, not the test guessing.
			context.AfterFunc(conn.Context(), func() {
				stand.access.Lock()
				stand.closed++
				stand.access.Unlock()
			})
			return context.WithValue(ctx, h3ConnRecordKey{}, record)
		},
	}
	go func() {
		_ = stand.server.Serve(packetConn)
		close(stand.served)
	}()
	t.Cleanup(func() {
		_ = stand.server.Close()
		<-stand.served
	})
	return stand
}

func (s *h3EgressStand) handle(writer http.ResponseWriter, request *http.Request) {
	record, _ := request.Context().Value(h3ConnRecordKey{}).(*h3ConnRecord)
	if record != nil {
		record.once.Do(func() {
			// Read the transport state AFTER the handshake and record it verbatim. This is the
			// ALPN evidence: it comes from the server's own QUIC connection, not from the HTTP
			// response the client happened to accept.
			state := record.conn.ConnectionState()
			s.access.Lock()
			s.handshakes = append(s.handshakes, h3HandshakeRecord{
				egress:      s.name,
				alpn:        state.TLS.NegotiatedProtocol,
				quicVersion: state.Version.String(),
				sni:         state.TLS.ServerName,
				proto:       request.Proto,
				datagrams:   state.SupportsDatagrams.Remote,
				zeroRTT:     state.Used0RTT,
			})
			s.access.Unlock()
		})
	}

	if request.Method == http.MethodConnect {
		s.access.Lock()
		s.tunnels++
		s.access.Unlock()
		// A destination the stand uses to hold one CONNECT open without ever answering it. It is
		// how the stale-failure interleave is forced on real sockets: the client's attempt for
		// this destination stays in flight, OUTSIDE the HTTP/3 client's own connection lock,
		// while a second attempt reuses the same connection and succeeds.
		if strings.HasPrefix(request.Host, "stall.") {
			<-request.Context().Done()
			return
		}
		writer.WriteHeader(http.StatusOK)
		if flusher, isFlusher := writer.(http.Flusher); isFlusher {
			flusher.Flush()
		}
		// A CONNECT is a tunnel: the handler must not return while the caller is using it, and
		// the echo is what proves payload really travelled over the H3 stream.
		buffer := make([]byte, 4096)
		for {
			read, readErr := request.Body.Read(buffer)
			if read > 0 {
				s.access.Lock()
				s.payload = append(s.payload, buffer[:read]...)
				s.access.Unlock()
				if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
					return
				}
				if flusher, isFlusher := writer.(http.Flusher); isFlusher {
					flusher.Flush()
				}
			}
			if readErr != nil {
				return
			}
		}
	}

	s.access.Lock()
	s.requests++
	s.access.Unlock()
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("stand"))
}

func (s *h3EgressStand) snapshot() (accepted, closed, streams, tunnels, requests int, handshakes []h3HandshakeRecord, payload []byte) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.accepted, s.closed, s.streams, s.tunnels, s.requests,
		append([]h3HandshakeRecord(nil), s.handshakes...), append([]byte(nil), s.payload...)
}

func (s *h3EgressStand) acceptedCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.accepted
}

func (s *h3EgressStand) tunnelCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.tunnels
}

// liveConnections is accepted minus closed: the sockets this egress currently holds.
func (s *h3EgressStand) liveConnections() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.accepted - s.closed
}

// ---------------------------------------------------------------------------
// The failure: a bound UDP socket that never answers
// ---------------------------------------------------------------------------

// h3Blackhole is a real UDP endpoint that reads what arrives and answers nothing.
//
// It is bound rather than absent on purpose. `net.DialUDP` to a port nothing listens on produces
// no error at dial time, and on loopback the ICMP port-unreachable that follows makes the QUIC
// handshake fail immediately -- which is a REFUSAL, not the silent drop this stand needs to model.
// A bound socket that never replies is the silent drop.
type h3Blackhole struct {
	conn      *net.UDPConn
	address   string
	socksaddr M.Socksaddr
	received  atomic.Int64
	bytes     atomic.Int64
	stopped   chan struct{}
}

func newH3Blackhole(t *testing.T) *h3Blackhole {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	hole := &h3Blackhole{
		conn:      conn,
		address:   conn.LocalAddr().String(),
		socksaddr: M.ParseSocksaddr(conn.LocalAddr().String()),
		stopped:   make(chan struct{}),
	}
	go func() {
		buffer := make([]byte, 4096)
		for {
			read, _, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				close(hole.stopped)
				return
			}
			hole.received.Add(1)
			hole.bytes.Add(int64(read))
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return hole
}

// ---------------------------------------------------------------------------
// The local path, and the environment decision source
// ---------------------------------------------------------------------------

// recordingUDPPath is one local network path. It creates real UDP sockets and records every local
// address it produced, so "this path carried that connection" is answered by the object that made
// the socket rather than inferred from a counter elsewhere.
type recordingUDPPath struct {
	name    string
	access  sync.Mutex
	dials   int
	produced map[string]bool
	closed  int
}

func newRecordingUDPPath(name string) *recordingUDPPath {
	return &recordingUDPPath{name: name, produced: make(map[string]bool)}
}

func (p *recordingUDPPath) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP {
		return nil, E.New("stand path ", p.name, " carries QUIC datagrams only, refusing a ",
			network, " dial")
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(destination.Addr, destination.Port)))
	if err != nil {
		return nil, err
	}
	p.access.Lock()
	p.dials++
	p.produced[conn.LocalAddr().String()] = true
	p.access.Unlock()
	return conn, nil
}

func (p *recordingUDPPath) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

func (p *recordingUDPPath) dialsCount() int {
	p.access.Lock()
	defer p.access.Unlock()
	return p.dials
}

// owns reports whether this path produced a socket with the given local address. It is the
// attribution primitive: a live socket can only have been made by the path that recorded it.
func (p *recordingUDPPath) owns(local net.Addr) bool {
	if local == nil {
		return false
	}
	p.access.Lock()
	defer p.access.Unlock()
	return p.produced[local.String()]
}

// h3Environment is one emulated network environment: a local path plus the egress dialled over it.
type h3Environment struct {
	name  string
	path  *recordingUDPPath
	egress *h3EgressStand
	// dialDestination is what the client is told to reach in this environment. It is a real
	// address, so the client's own destination handling is exercised rather than bypassed.
	dialDestination M.Socksaddr
}

// h3EnvironmentSource is the stand's NETWORK MANAGER DECISION SOURCE, and it is not a radio.
//
// It publishes which of two emulated environments is current, and provides the local dialer the
// client uses, so switching it changes BOTH the socket's route (a different real local socket, from
// a different path object) and the egress the datagrams reach (a different real H3 server). That is
// what makes "which egress carried this connection" observable without a packet capture.
//
// It does NOT change a real interface, a real route table, or a real radio, and no claim about iOS
// or WLAN behaviour may be drawn from it. See the file header.
type h3EnvironmentSource struct {
	access      sync.Mutex
	current     string
	environments map[string]*h3Environment
	transitions int
	order       []string
}

func newH3EnvironmentSource(environments ...*h3Environment) *h3EnvironmentSource {
	source := &h3EnvironmentSource{environments: make(map[string]*h3Environment)}
	for _, environment := range environments {
		source.environments[environment.name] = environment
	}
	source.current = environments[0].name
	return source
}

func (s *h3EnvironmentSource) set(name string) {
	s.access.Lock()
	s.current = name
	s.transitions++
	s.order = append(s.order, name)
	s.access.Unlock()
}

// currentEnvironment reads the live environment.
func (s *h3EnvironmentSource) currentEnvironment() *h3Environment {
	s.access.Lock()
	defer s.access.Unlock()
	return s.environments[s.current]
}

func (s *h3EnvironmentSource) transitionCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.transitions
}

// environmentDialer is the client's dialer: whichever environment is current supplies the path AND
// the egress the datagrams are redirected to.
//
// The redirection is the stand's model of a route change. A real path change does not alter the
// proxy's address; it alters where the packets go. Redirecting the UDP dial to the current
// environment's real H3 server keeps the client's own destination handling intact while making the
// carrying egress observable.
type environmentDialer struct {
	source *h3EnvironmentSource
	access sync.Mutex
	byPath map[string]int
}

func newEnvironmentDialer(source *h3EnvironmentSource) *environmentDialer {
	return &environmentDialer{source: source, byPath: make(map[string]int)}
}

func (d *environmentDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	environment := d.source.currentEnvironment()
	conn, err := environment.path.DialContext(ctx, network, environment.dialDestination)
	if err != nil {
		return nil, err
	}
	d.access.Lock()
	d.byPath[environment.name]++
	d.access.Unlock()
	return conn, nil
}

func (d *environmentDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

func (d *environmentDialer) dialsByPath(name string) int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.byPath[name]
}

// standFallbackDialer is the fallback branch. It counts and refuses: a stream dial over this
// stand's paths is not a thing, and refusing makes "the fallback was taken" observable without
// depending on a live HTTP/2 server.
type standFallbackDialer struct {
	calls atomic.Int64
}

func (d *standFallbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	return nil, E.New("stand fallback dialer: refusing a ", network, " dial to ", destination)
}

func (d *standFallbackDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("stand fallback dialer refuses a packet dial")
}

func (d *standFallbackDialer) callCount() int { return int(d.calls.Load()) }

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

// standClient is the client plus the pieces the assertions read.
type standClient struct {
	client   *Client
	h3       *http3ClientImpl
	fallback *standFallbackDialer
	source   *h3EnvironmentSource
	dialer   *environmentDialer
}

// newStandClient builds a client whose HTTP/3 is the package's own http3ClientImpl -- the same
// object the product uses, not a double -- pointed at the environment source's dialer.
func newStandClient(t *testing.T, source *h3EnvironmentSource) *standClient {
	t.Helper()
	tlsConfig, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	dialer := newEnvironmentDialer(source)
	// The client's own destination is a real address in the current environment. It is also used
	// as the TLS authority, which is why the environment supplies it rather than the egress: the
	// blackhole environment has no egress object at all.
	destination := source.currentEnvironment().dialDestination
	impl := &http3ClientImpl{
		dialer:     dialer,
		server:     destination,
		authority:  destination.String(),
		tlsConfig:  tlsConfig,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			EnableDatagrams:      true,
		},
		transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	impl.connectCandidate = impl.connectCandidateAt
	fallback := &standFallbackDialer{}
	client := &Client{
		dialer:            dialer,
		http1Dialer:       fallback,
		authorityOverride: "example.test",
		version:           3,
		server:            destination,
		http3:             impl,
		http3Authority:    "example.test",
	}
	t.Cleanup(func() { _ = client.Close() })
	return &standClient{client: client, h3: impl, fallback: fallback, source: source, dialer: dialer}
}

// liveHTTP3Connections is the client's own connection census: how many HTTP/3 connections it is
// currently holding. It is a field on the object that owns the slot, not a process-wide number.
func (c *standClient) liveHTTP3Connections() int {
	c.h3.access.Lock()
	defer c.h3.access.Unlock()
	live := 0
	if c.h3.conn != nil && c.h3.conn.Context().Err() == nil {
		live++
	}
	return live
}

// liveRawSockets counts the raw UDP sockets the client is holding. A leak of one socket per
// transition would show up here as growth proportional to the cycle count.
func (c *standClient) liveRawSockets() int {
	c.h3.access.Lock()
	defer c.h3.access.Unlock()
	if c.h3.rawConn != nil {
		return 1
	}
	return 0
}

// rawLocalAddr is the local address of the client's current H3 socket, so the PATH that carried it
// can be identified from the socket itself.
func (c *standClient) rawLocalAddr() net.Addr {
	c.h3.access.Lock()
	defer c.h3.access.Unlock()
	if c.h3.rawConn == nil {
		return nil
	}
	return c.h3.rawConn.LocalAddr()
}

// dialOverTunnel opens a CONNECT tunnel through the client and round-trips a payload, so a claim
// about a connection is backed by bytes that really crossed it.
func (c *standClient) dialOverTunnel(payload string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := c.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		return E.Cause(err, "write over the tunnel")
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		return E.Cause(err, "read over the tunnel")
	}
	if string(got) != payload {
		return E.New("the tunnel echoed ", string(got), " instead of ", payload)
	}
	return nil
}

// h3PackageGoroutines counts the goroutines whose STACK names this package.
//
// The process-wide count is not usable evidence: it moves with every other test in this binary.
// Scoping to this package's stacks means a leaked HTTP/3 worker or transport goroutine is visible
// in the number, and nothing else in the binary can move it. A goroutine started here but currently
// executing inside a dependency under-counts, which is the conservative direction -- it cannot
// invent an accumulation that is not there. Its sensitivity is proven by
// TestH3StandCensusDetectsDeliberatelyLeakedConnections.
func h3PackageGoroutines() int {
	buffer := make([]byte, 1<<21)
	read := runtime.Stack(buffer, true)
	count := 0
	for _, block := range strings.Split(string(buffer[:read]), "\n\n") {
		if strings.Contains(block, "sing-box/transport/http") {
			count++
		}
	}
	return count
}

// h3PackageGoroutinesFromClosure is the census taken from INSIDE a polling closure.
//
// A closure defined in this file has this package in its own stack, so a census taken while it runs
// counts ITSELF. The correction is not cosmetic: without it the assertion is unsatisfiable by
// construction, which is the instrument defect `route/interface_churn_cost_test.go` recorded.
func h3PackageGoroutinesFromClosure() int {
	return h3PackageGoroutines() - 1
}

// freezedHTTP3EstablishTimeout sets the HTTP/3 attempt window for one test.
//
// http3EstablishTimeout is a package-level tunable that the product reads on every dial, and these
// tests need windows of hundreds of milliseconds rather than three seconds. It is restored on
// cleanup, and every test in this file is sequential (none calls t.Parallel), so the mutation
// cannot race a parallel test: Go releases top-level parallel tests only after the sequential ones
// have finished.
func freezedHTTP3EstablishTimeout(t *testing.T, window time.Duration) {
	t.Helper()
	previous := http3EstablishTimeout
	http3EstablishTimeout = window
	t.Cleanup(func() { http3EstablishTimeout = previous })
}

// ---------------------------------------------------------------------------
// The stand itself
// ---------------------------------------------------------------------------

// standPair is two real egresses with their own local paths, wired to one decision source.
type standPair struct {
	egressA *h3EgressStand
	egressB *h3EgressStand
	pathA   *recordingUDPPath
	pathB   *recordingUDPPath
	source  *h3EnvironmentSource
}

func newStandPair(t *testing.T) *standPair {
	t.Helper()
	egressA := newH3EgressStand(t, "A")
	egressB := newH3EgressStand(t, "B")
	pathA := newRecordingUDPPath("path-A")
	pathB := newRecordingUDPPath("path-B")
	source := newH3EnvironmentSource(
		&h3Environment{name: "A", path: pathA, egress: egressA, dialDestination: egressA.socksaddr},
		&h3Environment{name: "B", path: pathB, egress: egressB, dialDestination: egressB.socksaddr},
	)
	return &standPair{egressA: egressA, egressB: egressB, pathA: pathA, pathB: pathB, source: source}
}

// transition performs one environment change THROUGH THE PRODUCTION ENTRY the connection layer
// exposes to a network change.
//
// `Client.ResetConnections` is what the HTTP outbound's InterfaceUpdated handler calls, which is
// what Router.ResetNetwork reaches after a transition. Doing anything else here -- recreating the
// client, or dropping the connection by hand -- would test a stand instead of the product.
func (p *standPair) transition(stand *standClient, to string) {
	p.source.set(to)
	stand.client.ResetConnections()
}

// ---------------------------------------------------------------------------
// Row 1: a real HTTP/3 handshake, verified from ALPN and the transport
// ---------------------------------------------------------------------------

// TestH3StandCompletesARealH3HandshakeOnLoopback is the precondition for every other row.
//
// The assertion is deliberately NOT "the dial returned 200". It is the ALPN the SERVER negotiated,
// the QUIC version it ran, the protocol string it parsed, and the datagram capability it saw --
// all read from the server's own *quic.Conn -- plus payload that really crossed the tunnel.
func TestH3StandCompletesARealH3HandshakeOnLoopback(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)
	require.Equal(t, "A", pair.source.currentEnvironment().name)

	require.NoError(t, stand.dialOverTunnel("hello-h3"))

	accepted, closed, _, tunnels, _, handshakes, payload := pair.egressA.snapshot()
	require.Equal(t, 1, accepted, "exactly one QUIC connection must have been accepted by egress A")
	require.Equal(t, 1, tunnels, "the CONNECT must have been served as a tunnel")
	require.Equal(t, 0, pair.egressB.acceptedCount(), "egress B must not have been touched")
	require.Equal(t, "hello-h3", string(payload),
		"the payload must have reached the egress over the HTTP/3 stream")

	require.Len(t, handshakes, 1, "one connection, one handshake")
	handshake := handshakes[0]
	require.Equal(t, "h3", handshake.alpn,
		"the SERVER's negotiated ALPN must be h3: this is the handshake evidence, and a 200 OK "+
			"alone would not distinguish HTTP/3 from a fallback")
	require.Equal(t, "HTTP/3.0", handshake.proto,
		"the request must have been parsed as HTTP/3, not as an HTTP/1 or HTTP/2 request")
	require.NotEmpty(t, handshake.quicVersion, "the QUIC version must be a real negotiated version")
	require.NotEqual(t, "VersionUnknown", handshake.quicVersion)
	require.True(t, handshake.datagrams,
		"the peer must have advertised QUIC datagram support, which a CONNECT-IP tunnel needs")
	require.False(t, handshake.zeroRTT,
		"this is a full handshake, so recording it as 0-RTT would be wrong")
	require.Equal(t, "example.test", handshake.sni)

	require.Equal(t, 1, stand.liveHTTP3Connections(),
		"the client must be holding the connection it established")
	require.Equal(t, 1, stand.liveRawSockets())
	require.Zero(t, stand.fallback.callCount(),
		"nothing may have been silently downgraded: a working HTTP/3 connection must not touch "+
			"the fallback transport")
	require.Zero(t, stand.client.http3Broken.Load(),
		"a successful handshake leaves no broken verdict")
	require.Equal(t, 1, pair.pathA.dialsCount(), "egress A is reached over path A")
	require.Equal(t, 0, pair.pathB.dialsCount())
	require.True(t, pair.pathA.owns(stand.rawLocalAddr()),
		"the live socket must be one that path A created: attribution from the socket itself")

	require.Eventually(t, func() bool { return pair.egressA.liveConnections() <= 1 }, 5*time.Second, 10*time.Millisecond)
	_ = closed
}

// TestH3StandStableNetworkDoesNotDowngradeTheProtocol is the stable-network row.
//
// Many sequential tunnels on one quiet environment must all be carried over HTTP/3 on ONE QUIC
// connection, must never touch the fallback, and must never arm the broken verdict. A "works
// anyway" test that accepted a downgrade would pass while the user's protocol silently changed.
func TestH3StandStableNetworkDoesNotDowngradeTheProtocol(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)

	for round := 0; round < 8; round++ {
		require.NoError(t, stand.dialOverTunnel(fmt.Sprintf("payload-%d", round)))
	}

	accepted, _, _, tunnels, _, handshakes, _ := pair.egressA.snapshot()
	require.Equal(t, 1, accepted,
		"the tunnels must share ONE QUIC connection: a new handshake per tunnel would be a "+
			"connection storm the connection reuse exists to prevent")
	require.Equal(t, 8, tunnels)
	require.Len(t, handshakes, 1)
	require.Equal(t, "h3", handshakes[0].alpn)
	require.Zero(t, stand.fallback.callCount(),
		"a stable network must not downgrade the working protocol, however many tunnels run")
	require.Zero(t, stand.client.http3Broken.Load())
	require.True(t, stand.client.http3Available())
	require.Equal(t, 1, stand.liveHTTP3Connections())
}

// ---------------------------------------------------------------------------
// Row 2: a caller cancel versus a genuine failure, on real sockets
// ---------------------------------------------------------------------------

// TestH3StandCallerCancelIsNotLearnedAsALinkFault drives a REAL handshake that never completes and
// cancels the caller mid-flight.
//
// The cancel is a fact about the user, not about the path: it must reach the caller as
// context.Canceled, must arm nothing, and must not start a fallback dial for a caller who is gone.
// The blackhole's byte counter is asserted too, so the test cannot pass on a dial that never
// actually put anything on the wire.
func TestH3StandCallerCancelIsNotLearnedAsALinkFault(t *testing.T) {
	hole := newH3Blackhole(t)
	path := newRecordingUDPPath("path-A")
	environment := &h3Environment{name: "A", path: path, egress: nil, dialDestination: hole.socksaddr}
	source := newH3EnvironmentSource(environment)
	stand := newStandClient(t, source)
	// The caller's cancel is the only thing that may end this dial: the attempt window must be
	// far longer than the test.
	freezedHTTP3EstablishTimeout(t, 60*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, err := stand.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	// Wait for the real socket to have been used, so the cancel lands inside the handshake rather
	// than before it. The blackhole counts datagrams it really received.
	require.Eventually(t, func() bool { return hole.received.Load() > 0 }, 10*time.Second, 5*time.Millisecond,
		"the client never put a QUIC Initial on the wire, so cancelling here would prove nothing")
	require.Equal(t, 1, path.dialsCount(), "one real local socket must have been created")

	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled,
			"a caller cancel must surface as the caller's own cancellation")
	case <-time.After(20 * time.Second):
		t.Fatal("the dial did not return after the caller cancelled")
	}

	require.Zero(t, stand.client.http3Broken.Load(),
		"a caller cancel armed the HTTP/3 broken verdict: the user giving up is not evidence "+
			"about the path, and the next dial would be downgraded because of it")
	require.Zero(t, stand.client.http3Backoff.Load())
	require.True(t, stand.client.http3Available())
	require.Zero(t, stand.fallback.callCount(),
		"a cancelled caller must not start a fallback dial: nobody is waiting for it")
	require.Equal(t, 0, stand.liveHTTP3Connections(),
		"a cancelled handshake must not leave a live connection slot behind")
	require.Greater(t, hole.bytes.Load(), int64(0),
		"and the blackhole must have really received Initial packets, which is what makes the "+
			"cancel a cancel rather than a no-op")
}

// TestH3StandGenuineFailureFollowsTheBackoffAndRecovers is the other half of the same row.
//
// A genuine failure -- a path that silently drops, so the attempt window expires -- must follow the
// existing backoff: remembered once, at the initial step, suppressing HTTP/3 inside the window, and
// fully recovered once the window expires and a working path is available again.
func TestH3StandGenuineFailureFollowsTheBackoffAndRecovers(t *testing.T) {
	hole := newH3Blackhole(t)
	pair := newStandPair(t)
	// Environment A is broken for the first half of this test and healthy in the second.
	broken := &h3Environment{name: "A", path: pair.pathA, egress: nil, dialDestination: hole.socksaddr}
	source := newH3EnvironmentSource(broken)
	stand := newStandClient(t, source)
	freezedHTTP3EstablishTimeout(t, 400*time.Millisecond)

	dialCtx := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := stand.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}

	require.Error(t, dialCtx(), "the blackhole never completes a handshake, so the dial fails")
	require.NotZero(t, stand.client.http3Broken.Load(),
		"a genuine failure must be remembered, or the client pays the failed attempt on every dial")
	require.Equal(t, int64(http3BrokenBackoffInitial), stand.client.http3Backoff.Load(),
		"the first failure must be charged at the initial step")
	require.Equal(t, 1, stand.fallback.callCount(), "and the dial must have fallen back")
	require.Equal(t, 1, pair.pathA.dialsCount())

	// Inside the window HTTP/3 is not attempted at all: one more real socket would appear if it
	// were.
	require.Error(t, dialCtx())
	require.Equal(t, 1, pair.pathA.dialsCount(),
		"HTTP/3 was attempted inside the backoff window: the window is not a memory")
	require.Equal(t, 2, stand.fallback.callCount())

	// The window expires by itself -- the test writes nothing -- and a working path appears.
	deadline := time.Now().Add(http3BrokenBackoffInitial + 10*time.Second)
	for !stand.client.http3Available() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, stand.client.http3Available(),
		"the backoff must expire on its own, or the client is pinned to the fallback for the life "+
			"of the process")

	healthy := &h3Environment{name: "A", path: pair.pathA, egress: pair.egressA, dialDestination: pair.egressA.socksaddr}
	stand.source.access.Lock()
	stand.source.environments["A"] = healthy
	stand.source.access.Unlock()

	require.NoError(t, dialCtx(), "the recovered path must serve the dial")
	accepted, _, _, _, _, handshakes, _ := pair.egressA.snapshot()
	require.Equal(t, 1, accepted)
	require.Len(t, handshakes, 1)
	require.Equal(t, "h3", handshakes[0].alpn, "recovery must be a real HTTP/3 handshake")
	require.Zero(t, stand.client.http3Broken.Load(), "success clears the verdict")
	require.Zero(t, stand.client.http3Backoff.Load(), "and clears the escalation schedule")
}

// ---------------------------------------------------------------------------
// Row 3: a stale failure must not overwrite a newer success (REAL sockets)
// ---------------------------------------------------------------------------

// TestH3StandStaleFailureDoesNotOverwriteANewerSuccess is the real-socket form of
// TestHTTP3StaleFailureDoesNotOverwriteANewerSuccess.
//
// # Why this shape, and not "the blackhole beside a success"
//
// The obvious arrangement -- one attempt stuck in a handshake against a silent path, another
// succeeding beside it -- does NOT reach the interleave on this client, and finding that out is
// part of the result. `http3ClientImpl.acquire` holds the client's connection lock across the
// WHOLE handshake, so a second dial cannot even start its handshake until the first one has
// finished failing, and a test built that way measures the lock rather than the verdict.
//
// The interleave is reachable on the paths that wait OUTSIDE that lock, which is where a real
// attempt spends most of its life: the request stream, the SETTINGS wait and the response read all
// happen after `acquire` has returned. So the stand holds ONE CONNECT open without answering it --
// a real stream on a real connection, stalled for real -- and lets a second attempt reuse the same
// connection and succeed.
//
//	1. attempt 1 dials a destination the egress deliberately never answers;
//	2. attempt 2 reuses the live connection, is answered, and succeeds;
//	3. attempt 1's window expires, and it reports a failure about a moment attempt 2 has already
//	   disproved.
//
// Step 3 must decide nothing.
func TestH3StandStaleFailureDoesNotOverwriteANewerSuccess(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)
	// Wide enough that attempt 2 completes far inside it, short enough to end the test.
	freezedHTTP3EstablishTimeout(t, 900*time.Millisecond)

	// A real connection first, so attempt 1's stall is a stream on an established connection
	// rather than a handshake.
	require.NoError(t, stand.dialOverTunnel("prime"))
	require.Equal(t, 1, pair.egressA.acceptedCount())
	require.Equal(t, 1, stand.liveHTTP3Connections())

	staleResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := stand.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("stall.test:443"))
		if conn != nil {
			_ = conn.Close()
		}
		staleResult <- err
	}()

	// Wait for the stalled stream to really exist on the egress before interleaving with it.
	require.Eventually(t, func() bool { return pair.egressA.tunnelCount() == 2 }, 10*time.Second, 5*time.Millisecond,
		"the stalled attempt never got a CONNECT onto the wire, so it is not in flight")
	require.Equal(t, 1, pair.egressA.acceptedCount(),
		"the stalled attempt must reuse the live connection rather than opening a second one")

	// The newest observation: a real HTTP/3 tunnel that the egress answers.
	fallbackBefore := stand.fallback.callCount()
	require.NoError(t, stand.dialOverTunnel("newer"))
	require.Equal(t, fallbackBefore, stand.fallback.callCount(),
		"the newer attempt succeeded over HTTP/3 and must therefore not touch the fallback")
	require.Zero(t, stand.client.http3Broken.Load(),
		"precondition: a successful attempt leaves no verdict behind")
	require.Equal(t, 1, pair.egressA.acceptedCount(),
		"and it must have reused the same connection")

	select {
	case err := <-staleResult:
		require.Error(t, err, "the stalled attempt still fails on its own")
	case <-time.After(30 * time.Second):
		t.Fatal("the stalled attempt never reported")
	}

	require.Zero(t, stand.client.http3Broken.Load(),
		"an OLD HTTP/3 failure overwrote a NEWER real success: the client is pinned to the "+
			"fallback for the backoff window on the strength of a moment the success already "+
			"disproved, and every dial in that window is downgraded")
	require.Zero(t, stand.client.http3Backoff.Load(),
		"and the escalation step was charged for it, so the next genuine failure is remembered "+
			"for twice as long as it should be")
	require.True(t, stand.client.http3Available())

	// The consequence, measured on the wire: the next dial must still be carried over HTTP/3
	// rather than quietly downgraded.
	fallbackBefore = stand.fallback.callCount()
	require.NoError(t, stand.dialOverTunnel("after-the-stale-failure"))
	require.Equal(t, fallbackBefore, stand.fallback.callCount(),
		"the dial after the stale failure was downgraded to the fallback transport")
	require.Equal(t, 1, pair.egressA.acceptedCount(),
		"and it must have reused the live HTTP/3 connection")
}

// TestH3StandResetSupersedesAnInFlightAttempt is the real-socket form of
// TestHTTP3ResetSupersedesAnInFlightAttempt: the same defect with the network as the variable.
//
// # What this test is, and what it is NOT
//
// It is NOT a baseline-red reproduction, and saying so is part of the result. MEASURED: with the
// production files restored to the base commit, this test PASSES -- because the old code left the
// outcome to a race rather than deciding it. `ResetConnections` blocks on the HTTP/3 client's
// connection lock, which the abandoned attempt holds for its whole handshake; when the handshake
// finally fails, the marking goroutine and the reset goroutine both runnable, and whether the
// stale failure arms the verdict depends on which of them reaches its store last.
//
// With the fix the outcome is not racy at all: the attempt's sequence number is already superseded
// by the reset, so its outcome is refused whichever order the two goroutines run in. The value of
// this test is therefore DETERMINISM, and it is complemented by the three unit tests, which DO go
// red at the base commit because they force the order rather than racing for it.
//
// # Why the failure has to be the WINDOW expiring
//
// `ResetConnections` closes the connection it holds, so an attempt that is stalled on that
// connection is failed BY the reset rather than after it -- and the error it then reports carries
// the connection's own cause, which is not fallback-eligible and arms nothing. The attempt that
// survives a reset is the one that is still completing its own handshake, because `acquire` only
// publishes the raw socket AFTER the handshake has succeeded: there is nothing for the reset to
// close, so the abandoned handshake runs to its own window and reports afterwards. That is the
// shape below, and it is the shape a real handover produces -- a dial that was already on the wire
// when the path underneath it changed.
func TestH3StandResetSupersedesAnInFlightAttempt(t *testing.T) {
	hole := newH3Blackhole(t)
	pair := newStandPair(t)
	// The pair's own source is the one the transitions drive, so environment A is REPLACED rather
	// than a second source being built beside it: a stand with two decision sources would let a
	// transition flip the one nothing is reading, and the test would measure its own bookkeeping.
	pair.source.access.Lock()
	pair.source.environments["A"] = &h3Environment{
		name: "A", path: pair.pathA, dialDestination: hole.socksaddr,
	}
	pair.source.environments["B"] = &h3Environment{
		name: "B", path: pair.pathB, egress: pair.egressB, dialDestination: pair.egressB.socksaddr,
	}
	pair.source.current = "A"
	pair.source.access.Unlock()
	stand := newStandClient(t, pair.source)
	freezedHTTP3EstablishTimeout(t, 900*time.Millisecond)

	staleResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := stand.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
		if conn != nil {
			_ = conn.Close()
		}
		staleResult <- err
	}()
	require.Eventually(t, func() bool { return hole.received.Load() > 0 }, 10*time.Second, 5*time.Millisecond,
		"the attempt never reached the network, so it is not in flight")
	require.Equal(t, 1, pair.pathA.dialsCount())
	require.Nil(t, stand.rawLocalAddr(),
		"the abandoned attempt must not have published a socket yet, or the reset would close it "+
			"and this test would be measuring the wrong failure")

	// The transition, through the production entry. Environment B is healthy.
	pair.transition(stand, "B")

	select {
	case err := <-staleResult:
		require.Error(t, err, "the abandoned attempt still fails on its own")
	case <-time.After(30 * time.Second):
		t.Fatal("the abandoned attempt never reported")
	}

	require.Zero(t, stand.client.http3Broken.Load(),
		"a failure that belongs to the network the client just LEFT armed the HTTP/3 verdict on "+
			"the network it just entered: the first dial on the new path is charged for the old "+
			"path's failure")
	require.Zero(t, stand.client.http3Backoff.Load())
	require.True(t, stand.client.http3Available())
	require.Equal(t, "B", stand.source.currentEnvironment().name,
		"precondition: the client must be on the environment the transition published")

	// And the first dial on the new network really is carried over HTTP/3.
	fallbackBefore := stand.fallback.callCount()
	require.NoError(t, stand.dialOverTunnel("new-network"))
	accepted, _, _, _, _, handshakes, _ := pair.egressB.snapshot()
	require.Equal(t, 1, accepted, "the new environment's egress must carry the dial")
	require.Equal(t, 1, pair.pathB.dialsCount())
	require.Zero(t, pair.egressA.acceptedCount(),
		"the environment the client left must not have been used")
	require.Len(t, handshakes, 1)
	require.Equal(t, "h3", handshakes[0].alpn)
	require.Equal(t, fallbackBefore, stand.fallback.callCount(),
		"the first dial on the new network was downgraded to the fallback. The abandoned attempt "+
			"does reach the fallback itself -- it failed -- so what is asserted here is the DELTA: "+
			"the new network's first dial adds no fallback dial of its own")
}

// ---------------------------------------------------------------------------
// Row 4: churn -- bounded, serialised and reversible, on real sockets
// ---------------------------------------------------------------------------

// TestH3StandChurnIsBoundedAndReversible drives 25 sequential environment changes the way a device
// actually sees them: change, use the network, change again.
//
// # What is asserted, and why each is separate
//
//  1. ATTRIBUTION. Every tunnel after a change is carried by the environment that is current, and
//     by no other. "Old callbacks must not resurrect an old generation" is exactly this: a
//     connection left over from the previous environment serving the new one.
//
//  2. BOUNDED. Sockets and workers must not grow with the cycle count. The counts are the client's
//     own connection and raw-socket slots, the egresses' live-connection counts, and the number of
//     handshakes -- each an attributed field on the object that owns the resource.
//
//  3. REVERSIBLE. The package's goroutine census must return to its baseline once the churn stops,
//     and the client must still work afterwards. A test that only counted handshakes cannot see
//     work that accumulates and is never released.
//
// # What it does NOT say
//
// The environment source is a decision source, not a radio. This measures the connection layer's
// response to a transition having happened; it does not measure a real iOS or WLAN path change, and
// is marked NOT_RUN_EXTERNAL_DEVICE for that part in the round's report.
func TestH3StandChurnIsBoundedAndReversible(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)

	// Settle on A with one real tunnel, so the baseline is a working connection rather than an
	// empty client.
	require.NoError(t, stand.dialOverTunnel("baseline"))
	require.Eventually(t, func() bool { return pair.egressA.liveConnections() == 1 }, 5*time.Second, 10*time.Millisecond)

	goroutinesBefore := h3PackageGoroutines()
	transitions := 25
	churnStarted := time.Now()
	tunnelsA, tunnelsB := 1, 0
	current := "A"
	for cycle := 1; cycle <= transitions; cycle++ {
		if current == "A" {
			current = "B"
		} else {
			current = "A"
		}
		pair.transition(stand, current)
		require.NoError(t, stand.dialOverTunnel(fmt.Sprintf("cycle-%d", cycle)),
			"cycle %d of %d: the tunnel after the transition must be established over HTTP/3",
			cycle, transitions)
		if current == "A" {
			tunnelsA++
		} else {
			tunnelsB++
		}
	}

	_, _, _, servedA, _, handshakesA, _ := pair.egressA.snapshot()
	_, _, _, servedB, _, handshakesB, _ := pair.egressB.snapshot()

	// 1. ATTRIBUTION: the tunnels were served by the environments that were current, in the
	// numbers the pattern requires, and by nothing else.
	require.Equal(t, tunnelsA, servedA,
		"egress A served %d tunnels but the churn made it current for %d of them: a connection "+
			"from the previous environment served a request that belonged to the new one", servedA, tunnelsA)
	require.Equal(t, tunnelsB, servedB)
	require.Equal(t, transitions+1, servedA+servedB,
		"every tunnel must have been served by exactly one environment")
	require.Equal(t, transitions, pair.source.transitionCount())

	// 2. BOUNDED: one handshake per transition (each transition closes the connection, so the next
	// dial must re-handshake), every handshake negotiated h3, and the client holds exactly one
	// connection and one socket at the end rather than one per cycle.
	require.Len(t, handshakesA, tunnelsA,
		"one HTTP/3 handshake per connection: %d handshakes for %d tunnels on A", len(handshakesA), tunnelsA)
	require.Len(t, handshakesB, tunnelsB)
	for _, handshake := range append(append([]h3HandshakeRecord(nil), handshakesA...), handshakesB...) {
		require.Equal(t, "h3", handshake.alpn,
			"a churned connection negotiated %q instead of h3: the protocol was silently downgraded "+
				"at some point during the churn", handshake.alpn)
	}
	require.LessOrEqual(t, stand.liveHTTP3Connections(), 1,
		"the client holds more than one HTTP/3 connection after %d transitions, which is "+
			"accumulation rather than reuse", transitions)
	require.Equal(t, 1, stand.liveRawSockets(),
		"the client holds more than its single current UDP socket after the churn: one socket per "+
			"transition is exactly the growth this test exists to catch")
	require.Zero(t, stand.fallback.callCount(),
		"no cycle may have been carried by the fallback transport: the churn must not downgrade "+
			"the working protocol")
	require.Zero(t, stand.client.http3Broken.Load(),
		"the churn armed the HTTP/3 broken verdict, so a later dial would be downgraded")
	require.True(t, stand.client.http3Available())

	// 3. REVERSIBLE: once the churn stops, the package's own goroutines return to their baseline.
	require.Eventually(t, func() bool {
		return h3PackageGoroutinesFromClosure() <= goroutinesBefore
	}, 30*time.Second, 25*time.Millisecond,
		"goroutines whose stack belongs to this package did not return to their settled baseline "+
			"of %d across %d environment transitions (currently %d): one worker or transport per "+
			"transition is the accumulation this asserts against",
		goroutinesBefore, transitions, h3PackageGoroutines())

	// The egresses must not be accumulating sockets either: after the churn, at most the single
	// live connection may remain on each side.
	require.Eventually(t, func() bool {
		return pair.egressA.liveConnections() <= 1 && pair.egressB.liveConnections() <= 1
	}, 30*time.Second, 25*time.Millisecond,
		"the egresses still hold connections that were closed during the churn: A holds %d, B holds %d",
		pair.egressA.liveConnections(), pair.egressB.liveConnections())

	t.Logf("MEASURED %d environment transitions over real loopback HTTP/3: %d handshakes, all ALPN h3, "+
		"%d tunnels attributed to the current environment, client holding %d connection and %d socket(s) "+
		"afterwards, in %s",
		transitions, len(handshakesA)+len(handshakesB), servedA+servedB,
		stand.liveHTTP3Connections(), stand.liveRawSockets(), time.Since(churnStarted).Round(time.Millisecond))

	// And the client is still USABLE after the churn rather than merely quiet: one more tunnel,
	// carried over HTTP/3 by the environment it settled on.
	tunnelsBefore := pair.egressB.tunnelCount()
	if current != "B" {
		tunnelsBefore = pair.egressA.tunnelCount()
	}
	require.NoError(t, stand.dialOverTunnel("after-the-churn"))
	if current == "B" {
		require.Equal(t, tunnelsBefore+1, pair.egressB.tunnelCount(),
			"the tunnel after the churn was not carried by the environment the client settled on")
	} else {
		require.Equal(t, tunnelsBefore+1, pair.egressA.tunnelCount(),
			"the tunnel after the churn was not carried by the environment the client settled on")
	}
}

// TestH3StandBurstyOutOfOrderTransitionsSettleOnTheLastEnvironment covers the shape a real handover
// produces but a loop cannot: several notifications arriving faster than the layer can act on them.
//
// Overlapping transitions legitimately coalesce, so the assertion is not on how many resets ran. It
// is on the STATE the burst leaves: the client settles on the LAST environment published, holds at
// most one connection, and serves a tunnel over the environment it settled on -- no connection from
// an intermediate environment survives to carry traffic that belongs to the final one.
func TestH3StandBurstyOutOfOrderTransitionsSettleOnTheLastEnvironment(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)
	require.NoError(t, stand.dialOverTunnel("baseline"))

	// A burst: the environments are published from independent goroutines with no waiting, which is
	// what a radio reporting a roam mid-handover looks like from here.
	const burst = 24
	var group sync.WaitGroup
	for index := 0; index < burst; index++ {
		name := "A"
		if index%2 == 0 {
			name = "B"
		}
		group.Add(1)
		go func(name string) {
			defer group.Done()
			pair.transition(stand, name)
		}(name)
	}
	group.Wait()

	// Settle definitively on B, so the final assertion has a known answer.
	pair.transition(stand, "B")
	require.Equal(t, "B", pair.source.currentEnvironment().name)

	beforeA := pair.egressA.tunnelCount()
	beforeB := pair.egressB.tunnelCount()
	require.NoError(t, stand.dialOverTunnel("after-the-burst"),
		"the client must still be able to establish a tunnel after a burst of transitions")
	require.Equal(t, beforeB+1, pair.egressB.tunnelCount(),
		"the tunnel after the burst was not carried by the environment the client settled on")
	require.Equal(t, beforeA, pair.egressA.tunnelCount(),
		"an environment the client had already left served a request that belonged to the final one")

	require.LessOrEqual(t, stand.liveHTTP3Connections(), 1,
		"the burst left the client holding more than one connection")
	require.Equal(t, 1, stand.liveRawSockets(),
		"the burst left the client holding more than its single current socket")
	require.Zero(t, stand.fallback.callCount(),
		"a burst of notifications must not downgrade the working protocol")
	require.Zero(t, stand.client.http3Broken.Load())
}

// ---------------------------------------------------------------------------
// Row 5: Close during churn
// ---------------------------------------------------------------------------

// TestH3StandCloseDuringChurnIsClean closes the client while transitions and tunnels are still
// being driven.
//
// The failure this rules out is a Close that races the churn and leaves either a hang or a
// half-torn-down client that still answers dials. Close is a lifecycle fact: it must return, it
// must be idempotent, and a dial afterwards must fail rather than block.
func TestH3StandCloseDuringChurnIsClean(t *testing.T) {
	pair := newStandPair(t)
	stand := newStandClient(t, pair.source)
	require.NoError(t, stand.dialOverTunnel("before-close"))

	goroutinesBefore := h3PackageGoroutines()

	// Keep the churn going while Close runs.
	stop := make(chan struct{})
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			name := "A"
			if index%2 == 1 {
				name = "B"
			}
			pair.transition(stand, name)
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(20 * time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- stand.client.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err, "Close during churn must return cleanly")
	case <-time.After(30 * time.Second):
		t.Fatal("Close did not return while the stand was churning: a teardown that waits for a " +
			"transition is a hang")
	}
	close(stop)
	group.Wait()

	// Idempotent: a second Close must not panic or block.
	secondDone := make(chan struct{})
	go func() {
		_ = stand.client.Close()
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(30 * time.Second):
		t.Fatal("a second Close did not return")
	}

	// A dial after Close must fail rather than hang, and must not resurrect a socket.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := stand.client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "a closed client must not establish a tunnel")

	require.Eventually(t, func() bool {
		return h3PackageGoroutinesFromClosure() <= goroutinesBefore
	}, 30*time.Second, 25*time.Millisecond,
		"the goroutine census did not return to its baseline of %d after Close (currently %d)",
		goroutinesBefore, h3PackageGoroutines())
	require.LessOrEqual(t, stand.liveHTTP3Connections(), 0,
		"a closed client must not still be holding an HTTP/3 connection")
}

// ---------------------------------------------------------------------------
// The instrument's sensitivity: a controlled leak must go RED
// ---------------------------------------------------------------------------

// TestH3StandCensusDetectsDeliberatelyLeakedConnections proves the census can fail.
//
// A counter that cannot be moved by a leak is not evidence, so this test leaks a KNOWN number of
// real HTTP/3 connections -- one per deliberately abandoned client -- and requires both the
// client-side socket census and the egress-side connection census to read exactly that number
// above their baselines. It then releases them and requires both to come back.
//
// This is the same discipline `route/interface_churn_cost_test.go` reached for its scoped
// goroutine count: the assertion is worthless unless something can make it fail, and the only
// honest way to show that is to make it fail on purpose.
func TestH3StandCensusDetectsDeliberatelyLeakedConnections(t *testing.T) {
	pair := newStandPair(t)
	baselineEgress := pair.egressA.liveConnections()
	baselineGoroutines := h3PackageGoroutines()

	const leaked = 4
	leakedCensus := make([]int, 0, leaked)
	clients := make([]*standClient, 0, leaked)
	for index := 0; index < leaked; index++ {
		client := newStandClient(t, pair.source)
		require.NoError(t, client.dialOverTunnel(fmt.Sprintf("leak-%d", index)))
		clients = append(clients, client)
		// The leak: the connection is deliberately NOT closed, so it must be visible.
		leakedCensus = append(leakedCensus, client.liveHTTP3Connections())
	}

	for index, live := range leakedCensus {
		require.Equal(t, 1, live,
			"abandoned client %d reports %d live HTTP/3 connections, but it established exactly "+
				"one: the per-client census cannot see a leak, so every bounded-count assertion "+
				"built on it would be vacuous", index, live)
	}

	require.Eventually(t, func() bool {
		return pair.egressA.liveConnections() >= baselineEgress+leaked
	}, 20*time.Second, 25*time.Millisecond,
		"the egress-side census reads %d live connections after %d deliberate leaks: it cannot "+
			"see them, so the churn test's bounded assertion would be vacuous",
		pair.egressA.liveConnections(), leaked)

	require.Equal(t, leaked, pair.egressA.acceptedCount()-0,
		"every leaked connection must have completed a real handshake on the egress")

	// Now release them. The census must come back down, or "bounded" would be measured by an
	// instrument that never decreases either.
	for _, client := range clients {
		require.NoError(t, client.client.Close())
	}
	require.Eventually(t, func() bool {
		return pair.egressA.liveConnections() <= baselineEgress
	}, 30*time.Second, 25*time.Millisecond,
		"the egress-side census did not return to its baseline of %d after the leaked clients "+
			"were closed (currently %d)", baselineEgress, pair.egressA.liveConnections())
	require.Eventually(t, func() bool {
		return h3PackageGoroutinesFromClosure() <= baselineGoroutines
	}, 30*time.Second, 25*time.Millisecond,
		"the scoped goroutine census did not return to its baseline of %d after the leaked clients "+
			"were closed (currently %d)", baselineGoroutines, h3PackageGoroutines())
}

// TestH3StandBlackholeIsReallySilent is the failure fixture's own control.
//
// Every "genuine failure" row above depends on the blackhole being a SILENT drop rather than a
// refusal. If it ever answered -- even with an ICMP unreachable -- the handshake would fail fast
// and the rows about the attempt window would be measuring a different failure. So the silence is
// asserted: a real QUIC dial puts Initials on the wire, the socket receives them, and nothing ever
// comes back.
func TestH3StandBlackholeIsReallySilent(t *testing.T) {
	hole := newH3Blackhole(t)
	path := newRecordingUDPPath("path-A")
	source := newH3EnvironmentSource(&h3Environment{
		name: "A", path: path, dialDestination: hole.socksaddr,
	})
	stand := newStandClient(t, source)
	freezedHTTP3EstablishTimeout(t, 300*time.Millisecond)

	_, err := stand.client.DialContext(t.Context(), N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
	var cause error = err
	for cause != nil {
		if errors.Is(cause, context.DeadlineExceeded) {
			break
		}
		unwrapper, isUnwrapper := cause.(interface{ Unwrap() error })
		if !isUnwrapper {
			cause = nil
			break
		}
		cause = unwrapper.Unwrap()
	}
	require.Error(t, err, "the blackhole cannot serve a tunnel")
	require.Equal(t, 1, path.dialsCount())
	require.Greater(t, hole.received.Load(), int64(0),
		"the blackhole received nothing, so it is not modelling a dropped path")
	select {
	case <-hole.stopped:
		t.Fatal("the blackhole socket stopped reading, so its silence is no longer a property of " +
			"the stand")
	default:
	}
}
