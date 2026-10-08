// Package e2e drives the real sing-box chain end to end.
//
// # Why this package exists
//
// Every other test in this repository exercises one component with a double standing in for its
// neighbours: the mixed inbound is driven by a scripted net.Conn, the router is driven by a fake
// outbound, the TUN stack is driven by a relay handler that is "the route layer in miniature".
// Each of those is the right shape for the question it asks, and none of them can answer the one
// question this package asks:
//
//	does a real client, speaking a real protocol to a real listener, actually reach the far end
//	the configuration selects, with the metadata the rules matched on?
//
// The failure mode that lives in that gap is a chain that is green in every unit test and broken
// in the product: a listener bound on the wrong family, a CONNECT parser that loses early data, a
// rule that matches in the router but whose metadata never reaches the tracker, a DNS split that
// resolves from the wrong server, an outbound that is selected but never dialled.
//
// # Shape
//
// A real *box.Box is built from a real JSON configuration, a real client connects to a real
// loopback port, and every observation is taken at a boundary the product itself owns:
//
//   - the far end is a real loopback socket (or a real second protocol server);
//   - the route decision is captured by an adapter.ConnectionTracker appended to the live router,
//     which is the same interface the connection manager and the Clash API use;
//   - the DNS server is a real UDP/TCP DNS responder that counts and records the queries it
//     receives, so "which server answered" is measured rather than inferred.
//
// Nothing in this package modifies the product. It is an observer on the outside of the chain.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singtun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

var _ adapter.ConnectionTracker = (*flowRecorder)(nil)

// ---------------------------------------------------------------------------
// Box construction
// ---------------------------------------------------------------------------

// chainLogLevel is the sing-box log level for every box this package starts. "trace" is worth
// turning on by hand when a scenario fails: the route decision, the selected outbound and the DNS
// exchange are all logged at that level.
const chainLogLevel = "warning"

// chain is a running box plus the observations taken from it.
type chain struct {
	t        *testing.T
	instance *box.Box
	ctx      context.Context
	cancel   context.CancelFunc
	tracker  *flowRecorder
	closed   atomic.Bool
}

// startChain builds a box from configJSON and starts it.
//
// Every port in the configuration is allocated by freePort and substituted by the caller before
// this point, so a failure here is a real startup failure rather than a port collision. The one
// exception is the deliberate retry loop: a port can be taken between allocation and bind by
// anything else on the machine, and re-allocating is the only honest way to distinguish that from
// a product bug. A configuration error is never retried - it is reported with the full text.
func startChain(t *testing.T, configJSON string) *chain {
	t.Helper()
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	require.NotEmpty(t, configJSON)
	var (
		instance *box.Box
		err      error
	)
	for attempt := 0; attempt < 3; attempt++ {
		var options option.Options
		err = options.UnmarshalJSONContext(ctx, []byte(configJSON))
		if err != nil {
			cancel()
			t.Fatalf("configuration was rejected before the box was built: %v\n--- config ---\n%s", err, configJSON)
		}
		instance, err = box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			cancel()
			t.Fatalf("box.New failed: %v\n--- config ---\n%s", err, configJSON)
		}
		err = instance.Start()
		if err == nil {
			break
		}
		instance.Close()
		if !strings.Contains(err.Error(), "address already in use") {
			cancel()
			t.Fatalf("box.Start failed: %v\n--- config ---\n%s", err, configJSON)
		}
		t.Logf("port collision on attempt %d, retrying: %v", attempt, err)
	}
	require.NoError(t, err, "box.Start never succeeded")
	result := &chain{t: t, instance: instance, ctx: ctx, cancel: cancel, tracker: newFlowRecorder()}
	instance.Router().AppendTracker(result.tracker)
	t.Cleanup(func() {
		if result.closed.CompareAndSwap(false, true) {
			require.NoError(t, instance.Close())
		}
		cancel()
	})
	return result
}

// closeNow closes the box inside the test rather than at cleanup, for the Close-under-load
// scenarios. Idempotent, so the cleanup hook stays harmless.
func (c *chain) closeNow() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.instance.Close()
}

func (c *chain) router() adapter.Router { return c.instance.Router() }

// ---------------------------------------------------------------------------
// Flow recording: the route decision as the product reports it
// ---------------------------------------------------------------------------

// flowRecord is a snapshot of the metadata the router handed to the tracker, taken at the moment
// the decision was final. OutboundChain is reduced to tags because that is the identity a rule
// author reasons about.
type flowRecord struct {
	Network                  string
	Source                   string
	Destination              string
	OriginDestination        string
	RouteOriginalDestination string
	Domain                   string
	Protocol                 string
	Client                   string
	User                     string
	Inbound                  string
	InboundType              string
	DestinationAddresses     []string
	RouteRule                string
	RouteOutbound            string
	OutboundChain            []string
	TrafficClass             trafficclass.Class
	FakeIP                   bool
}

type flowRecorder struct {
	mu    sync.Mutex
	flows []flowRecord
	// signal is closed-and-replaced on every append so a test can wait for a flow instead of
	// sleeping. Buffered channel of size 1, drained on read.
	signal chan struct{}
}

func newFlowRecorder() *flowRecorder {
	return &flowRecorder{signal: make(chan struct{}, 1)}
}

func (r *flowRecorder) record(metadata adapter.InboundContext) {
	record := flowRecord{
		Network:                  metadata.Network,
		Source:                   metadata.Source.String(),
		Destination:              metadata.Destination.String(),
		Domain:                   metadata.Domain,
		Protocol:                 metadata.Protocol,
		Client:                   metadata.Client,
		User:                     metadata.User,
		Inbound:                  metadata.Inbound,
		InboundType:              metadata.InboundType,
		RouteRule:                metadata.RouteRule,
		RouteOutbound:            metadata.RouteOutbound,
		TrafficClass:             metadata.TrafficClass,
		FakeIP:                   metadata.FakeIP,
		OriginDestination:        metadata.OriginDestination.String(),
		RouteOriginalDestination: metadata.RouteOriginalDestination.String(),
	}
	for _, address := range metadata.DestinationAddresses {
		record.DestinationAddresses = append(record.DestinationAddresses, address.String())
	}
	for _, outbound := range metadata.OutboundChain {
		if outbound == nil {
			record.OutboundChain = append(record.OutboundChain, "<nil>")
			continue
		}
		record.OutboundChain = append(record.OutboundChain, outbound.Tag())
	}
	r.mu.Lock()
	r.flows = append(r.flows, record)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *flowRecorder) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	r.record(metadata)
	return conn
}

func (r *flowRecorder) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	r.record(metadata)
	return conn
}

func (r *flowRecorder) RoutedFlow(_ context.Context, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) singtun.FlowTracker {
	r.record(metadata)
	return nil
}

func (r *flowRecorder) snapshot() []flowRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]flowRecord(nil), r.flows...)
}

func (r *flowRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}

// waitForFlows blocks until at least n flows have been recorded, and returns all of them. It is a
// wait on an observation, not a sleep: the signal is raised by the recorder itself.
func (r *flowRecorder) waitForFlows(t *testing.T, n int, timeout time.Duration) []flowRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		flows := r.snapshot()
		if len(flows) >= n {
			return flows
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out after %s waiting for %d recorded flow(s), saw %d: %s", timeout, n, len(flows), formatFlows(flows))
		}
		select {
		case <-r.signal:
		case <-time.After(min(remaining, 50*time.Millisecond)):
		}
	}
}

func formatFlows(flows []flowRecord) string {
	encoded, err := json.MarshalIndent(flows, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", flows)
	}
	return string(encoded)
}

// ---------------------------------------------------------------------------
// Ports and listeners
// ---------------------------------------------------------------------------

// freePort reserves a loopback port by binding and immediately releasing it. The window between
// release and the box binding it is the reason startChain retries on "address already in use".
func freePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return uint16(port)
}

// ---------------------------------------------------------------------------
// Far ends: echo servers on loopback, v4 and v6
// ---------------------------------------------------------------------------

// echoServer is a real TCP peer that echoes every byte it receives. It records how many
// connections it accepted and how many bytes it echoed, so a test can tell "the proxy reported
// success" apart from "bytes actually crossed".
type echoServer struct {
	listener net.Listener
	accepts  atomic.Int64
	bytes    atomic.Int64
}

func startEchoServer(t *testing.T, network, address string) *echoServer {
	t.Helper()
	listener, err := net.Listen(network, address)
	require.NoError(t, err, "loopback listener %s %s", network, address)
	server := &echoServer{listener: listener}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			server.accepts.Add(1)
			go func() {
				defer conn.Close()
				_, copyErr := io.Copy(connWriter{conn: conn, counter: &server.bytes}, conn)
				_ = copyErr
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

type connWriter struct {
	conn    net.Conn
	counter *atomic.Int64
}

func (w connWriter) Write(p []byte) (int, error) {
	n, err := w.conn.Write(p)
	w.counter.Add(int64(n))
	return n, err
}

// tlsEchoServer is the long-connection peer: a real TLS listener with a self-signed certificate.
type tlsEchoServer struct {
	listener net.Listener
	accepts  atomic.Int64
}

func startTLSEchoServer(t *testing.T, network, address string) (*tlsEchoServer, tls.Certificate, *x509.CertPool) {
	t.Helper()
	certificate, pool := generateCertificate(t)
	listener, err := tls.Listen(network, address, &tls.Config{Certificates: []tls.Certificate{certificate}})
	require.NoError(t, err)
	server := &tlsEchoServer{listener: listener}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			server.accepts.Add(1)
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server, certificate, pool
}

// generateCertificate produces a self-signed certificate valid for the loopback addresses and for
// the synthetic domains this package uses. A real trusted chain is not the point; a real handshake
// that the client verifies is, because it proves the bytes crossed the proxy rather than that a
// proxy accepted a CONNECT.
func generateCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e.chain.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"e2e.chain.test", "split.test", "direct.test", "proxied.test", "sniffed.test", "forwarded.test", "resolved.test", "resolved-rule.test", "order-first.test", "blocked.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// udpEchoServer echoes datagrams back to their sender.
type udpEchoServer struct {
	conn    net.PacketConn
	packets atomic.Int64
}

func startUDPEchoServer(t *testing.T, network, address string) *udpEchoServer {
	t.Helper()
	conn, err := net.ListenPacket(network, address)
	require.NoError(t, err, "loopback packet listener %s %s", network, address)
	server := &udpEchoServer{conn: conn}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			server.packets.Add(1)
			_, _ = conn.WriteTo(buffer[:n], from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return server
}

// ---------------------------------------------------------------------------
// Origin servers for the forward-proxy (non-CONNECT) path
// ---------------------------------------------------------------------------

// httpOrigin is a real origin server behind the system HTTP proxy. It records the requests it
// receives, so a forward-proxy test can tell "the proxy answered" from "the origin was reached".
type httpOrigin struct {
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	requests []string
	// upgraded counts WebSocket-style upgrades that completed and then echoed their bytes.
	upgraded atomic.Int64
	echoed   atomic.Int64
}

func startHTTPOrigin(t *testing.T) *httpOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	origin := &httpOrigin{listener: listener}
	mux := http.NewServeMux()
	mux.HandleFunc("/body", func(writer http.ResponseWriter, request *http.Request) {
		origin.mu.Lock()
		origin.requests = append(origin.requests, request.Method+" "+request.URL.Path+" host="+request.Host+" ua="+request.Header.Get("User-Agent"))
		origin.mu.Unlock()
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("forward-proxy-body"))
	})
	mux.HandleFunc("/ws", func(writer http.ResponseWriter, request *http.Request) {
		if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, buffer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		origin.mu.Lock()
		origin.requests = append(origin.requests, "UPGRADE "+request.URL.Path)
		origin.mu.Unlock()
		origin.upgraded.Add(1)
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buffer.Flush()
		go func() {
			defer conn.Close()
			payload := make([]byte, 4096)
			for {
				read, readErr := conn.Read(payload)
				if readErr != nil {
					return
				}
				origin.echoed.Add(int64(read))
				if _, writeErr := conn.Write(payload[:read]); writeErr != nil {
					return
				}
			}
		}()
	})
	origin.server = &http.Server{Handler: mux}
	go func() { _ = origin.server.Serve(listener) }()
	t.Cleanup(func() {
		_ = origin.server.Close()
		listener.Close()
	})
	return origin
}

func (o *httpOrigin) address() string { return o.listener.Addr().String() }

func (o *httpOrigin) port() uint16 { return uint16(o.listener.Addr().(*net.TCPAddr).Port) }

func (o *httpOrigin) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.requests...)
}

func (o *httpOrigin) waitForRequest(t *testing.T, contains string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, request := range o.seen() {
			if strings.Contains(request, contains) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for the origin to receive %q, saw %v", timeout, contains, o.seen())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Real clients: raw SOCKS5 and raw HTTP CONNECT
// ---------------------------------------------------------------------------

// socks5Request performs a SOCKS5 handshake and returns the raw reply code, so a test can assert
// that a rejected destination is refused rather than silently connected. The connection is
// returned even on failure, because the caller still has to close it.
func socks5Request(t *testing.T, proxyAddress string, addressType byte, host string, port uint16) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err, "SOCKS5 greeting reply")
	require.Equal(t, byte(0x05), greeting[0], "SOCKS5 version in greeting reply")
	require.Equal(t, byte(0x00), greeting[1], "SOCKS5 method: no-auth expected")
	request := []byte{0x05, 0x01, 0x00, addressType}
	switch addressType {
	case 0x01:
		parsed, parseErr := netip.ParseAddr(host)
		require.NoError(t, parseErr)
		rawAddress := parsed.As4()
		request = append(request, rawAddress[:]...)
	case 0x04:
		parsed, parseErr := netip.ParseAddr(host)
		require.NoError(t, parseErr)
		rawAddress := parsed.As16()
		request = append(request, rawAddress[:]...)
	case 0x03:
		require.LessOrEqual(t, len(host), 255)
		request = append(request, byte(len(host)))
		request = append(request, host...)
	default:
		t.Fatalf("unsupported address type %d", addressType)
	}
	request = binary.BigEndian.AppendUint16(request, port)
	_, err = conn.Write(request)
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		// A refusal that closes the connection instead of answering is still a refusal; report it
		// as a non-zero code so the assertion is on the outcome, not on the wire shape.
		conn.Close()
		return nil, 0xFF
	}
	require.Equal(t, byte(0x05), reply[0])
	if reply[1] != 0x00 {
		return conn, reply[1]
	}
	switch reply[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		length := make([]byte, 1)
		_, err = io.ReadFull(conn, length)
		require.NoError(t, err)
		_, err = io.ReadFull(conn, make([]byte, int(length[0])+2))
	default:
		t.Fatalf("unsupported SOCKS5 reply address type %d", reply[3])
	}
	require.NoError(t, err, "SOCKS5 connect reply body")
	conn.SetDeadline(time.Time{})
	return conn, 0x00
}

// dialSocks5 performs a SOCKS5 handshake by hand so the address type on the wire is chosen by the
// test rather than by whatever a client library decides. That distinction is the whole point of
// the IPv6 and domain rows: an IPv4-mapped IPv6 destination and a real IPv6 destination look
// identical to a client that "just works".
func dialSocks5(t *testing.T, proxyAddress string, addressType byte, host string, port uint16) net.Conn {
	t.Helper()
	conn, code := socks5Request(t, proxyAddress, addressType, host, port)
	require.Equal(t, byte(0x00), code, "SOCKS5 reply code: success expected, got 0x%02x", code)
	return conn
}

// dialSocks5UserPass performs a SOCKS5 handshake with username/password authentication, which is
// the only way metadata.User can be populated and therefore the only way an auth_user rule can be
// exercised end to end.
func dialSocks5UserPass(t *testing.T, proxyAddress string, username string, password string, host string, port uint16) net.Conn {
	t.Helper()
	conn := negotiateSocks5UserPass(t, proxyAddress, username, password)
	t.Cleanup(func() { conn.Close() })
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, port)
	_, err := conn.Write(request)
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "SOCKS5 connect reply head")
	require.Equal(t, byte(0x05), reply[0])
	require.Equal(t, byte(0x00), reply[1], "SOCKS5 reply code: success expected, got 0x%02x", reply[1])
	switch reply[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		length := make([]byte, 1)
		_, err = io.ReadFull(conn, length)
		require.NoError(t, err)
		_, err = io.ReadFull(conn, make([]byte, int(length[0])+2))
	default:
		t.Fatalf("unsupported SOCKS5 reply address type %d", reply[3])
	}
	require.NoError(t, err, "SOCKS5 connect reply body")
	conn.SetDeadline(time.Time{})
	return conn
}

// dialSocks5UserPassExpectFailure requires that a rejected authentication does not become an
// authenticated flow.
func dialSocks5UserPassExpectFailure(t *testing.T, proxyAddress string, username string, password string, host string, port uint16) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), reply[1], "the inbound must select username/password auth")
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	_, err = conn.Write(auth)
	require.NoError(t, err)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		return // closed instead of answering: still a refusal
	}
	require.NotEqual(t, byte(0x00), reply[1], "a wrong password must not authenticate")
}

func negotiateSocks5UserPass(t *testing.T, proxyAddress string, username string, password string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "SOCKS5 greeting reply")
	require.Equal(t, byte(0x05), reply[0])
	require.Equal(t, byte(0x02), reply[1], "the inbound must select username/password auth")
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	_, err = conn.Write(auth)
	require.NoError(t, err)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "SOCKS5 authentication reply")
	require.Equal(t, byte(0x00), reply[1], "authentication must succeed")
	return conn
}

// dialSocks5UDP performs a UDP ASSOCIATE and returns a connected UDP socket to the relay, framed
// the way SOCKS5 requires. The datagram destination is carried per packet, which is what makes
// this a genuinely different path from the TCP tunnel: the flow exists only inside the relay.
func dialSocks5UDP(t *testing.T, proxyAddress string, host string, port uint16) net.Conn {
	t.Helper()
	control := dialSocks5Command(t, proxyAddress, 0x03)
	require.NotNil(t, control)
	t.Cleanup(func() { control.Close() })
	relay := control.RemoteAddr().String()
	if control.relayAddress.IsValid() {
		relay = netip.AddrPortFrom(control.relayAddress.Addr().Unmap(), control.relayAddress.Port()).String()
	}
	conn, err := net.Dial("udp", relay)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	framed := &socksUDPConn{Conn: conn, destination: netip.AddrPortFrom(netip.MustParseAddr(host), port)}
	return framed
}

type socksUDPConn struct {
	net.Conn
	destination netip.AddrPort
}

// Write frames one datagram with the SOCKS5 UDP request header. RSV is two zero bytes, FRAG is
// zero (no fragmentation), then the address in its literal form.
func (c *socksUDPConn) Write(payload []byte) (int, error) {
	header := []byte{0x00, 0x00, 0x00}
	address := c.destination.Addr()
	if address.Is4() {
		header = append(header, 0x01)
		rawAddress := address.As4()
		header = append(header, rawAddress[:]...)
	} else {
		header = append(header, 0x04)
		rawAddress := address.As16()
		header = append(header, rawAddress[:]...)
	}
	header = binary.BigEndian.AppendUint16(header, c.destination.Port())
	framed := append(header, payload...)
	_, err := c.Conn.Write(framed)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// Read strips the SOCKS5 UDP header. Fragmented replies (FRAG != 0) are reported as an error
// rather than silently accepted, because this client never asks for fragmentation.
func (c *socksUDPConn) Read(buffer []byte) (int, error) {
	framed := make([]byte, 65535)
	n, err := c.Conn.Read(framed)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("short SOCKS5 UDP reply: %d bytes", n)
	}
	if framed[2] != 0 {
		return 0, fmt.Errorf("unexpected SOCKS5 UDP fragment number %d", framed[2])
	}
	var headerLength int
	switch framed[3] {
	case 0x01:
		headerLength = 4 + 4 + 2
	case 0x04:
		headerLength = 4 + 16 + 2
	case 0x03:
		if n < 5 {
			return 0, fmt.Errorf("short SOCKS5 UDP reply")
		}
		headerLength = 4 + 1 + int(framed[4]) + 2
	default:
		return 0, fmt.Errorf("unsupported SOCKS5 UDP address type %d", framed[3])
	}
	if n < headerLength {
		return 0, fmt.Errorf("short SOCKS5 UDP reply: %d < %d", n, headerLength)
	}
	return copy(buffer, framed[headerLength:n]), nil
}

type socksCommandConn struct {
	net.Conn
	relayAddress netip.AddrPort
}

// dialSocks5Command issues a command whose success shape differs from CONNECT: UDP ASSOCIATE
// answers with the relay endpoint the client must send datagrams to.
func dialSocks5Command(t *testing.T, proxyAddress string, command byte) *socksCommandConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), greeting[1])
	// The address in an ASSOCIATE request is the client's expected source; all zeroes is what
	// every real client sends and it means "wherever this TCP connection came from".
	request := []byte{0x05, command, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err = conn.Write(request)
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), reply[1], "SOCKS5 command 0x%02x reply code", command)
	result := &socksCommandConn{Conn: conn}
	switch reply[3] {
	case 0x01:
		raw := make([]byte, 4+2)
		_, err = io.ReadFull(conn, raw)
		require.NoError(t, err)
		result.relayAddress = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[:4])), binary.BigEndian.Uint16(raw[4:]))
	case 0x04:
		raw := make([]byte, 16+2)
		_, err = io.ReadFull(conn, raw)
		require.NoError(t, err)
		result.relayAddress = netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[:16])), binary.BigEndian.Uint16(raw[16:]))
	case 0x03:
		length := make([]byte, 1)
		_, err = io.ReadFull(conn, length)
		require.NoError(t, err)
		_, err = io.ReadFull(conn, make([]byte, int(length[0])+2))
		require.NoError(t, err)
	default:
		t.Fatalf("unsupported SOCKS5 reply address type %d", reply[3])
	}
	return result
}

// dialHTTPConnect performs a CONNECT by hand and returns the tunnel plus the response head, so a
// test can assert the status line and headers rather than only that a connection opened.
func dialHTTPConnect(t *testing.T, proxyAddress string, target string, extraHeaders string) (net.Conn, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	require.NoError(t, err)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + extraHeaders + "\r\n"
	_, err = conn.Write([]byte(request))
	require.NoError(t, err)
	head, err := readHTTPHead(conn)
	require.NoError(t, err, "CONNECT response head")
	require.Contains(t, head, "200", "CONNECT response head: %q", head)
	conn.SetDeadline(time.Time{})
	return conn, head
}

func readHTTPHead(conn net.Conn) (string, error) {
	var builder strings.Builder
	buffer := make([]byte, 1)
	for builder.Len() < 8192 {
		_, err := io.ReadFull(conn, buffer)
		if err != nil {
			return builder.String(), err
		}
		builder.WriteByte(buffer[0])
		if strings.HasSuffix(builder.String(), "\r\n\r\n") {
			return builder.String(), nil
		}
	}
	return builder.String(), fmt.Errorf("HTTP head exceeded 8192 bytes without a terminator")
}

// ---------------------------------------------------------------------------
// Far end for the outbound: a real SOCKS5 server that records what it was asked for
// ---------------------------------------------------------------------------

// socksRequest is the request exactly as it arrived on the wire, so a test can assert the address
// FORM the outbound chose (domain vs IPv4 vs IPv6) and not only the resolved destination.
type socksRequest struct {
	AddressType byte
	Host        string
	Port        uint16
}

func (r socksRequest) String() string {
	return fmt.Sprintf("atyp=%d %s:%d", r.AddressType, r.Host, r.Port)
}

// socksSink is a real SOCKS5 server standing in for the remote node. It answers with a real
// connection to the requested destination, so the chain past it is real too, and it records every
// request. Writing this by hand rather than reusing the product's own SOCKS client is deliberate:
// a server shares no code with the client, so a bug in the client cannot make its own test pass.
type socksSink struct {
	listener net.Listener
	requests []socksRequest
	mu       sync.Mutex
	accepts  atomic.Int64
	refused  atomic.Int64
	// backendOverride maps what the client asked for - a domain, or an address as written - to the
	// loopback address the sink should dial instead. A remote node in the real world resolves the
	// name itself and routes the address itself; in a hermetic test neither `.test` names nor
	// unroutable addresses exist, and this keeps the far side of the proxy real (a real socket,
	// real bytes) while still proving what actually arrived on the wire.
	backendOverride map[string]string
}

func startSocksSink(t *testing.T, address string) *socksSink {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	require.NoError(t, err)
	sink := &socksSink{listener: listener}
	go sink.serve()
	t.Cleanup(func() { listener.Close() })
	return sink
}

func (s *socksSink) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepts.Add(1)
		go s.handle(conn)
	}
}

func (s *socksSink) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	request := socksRequest{}
	var host string
	switch head[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(raw)).String()
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(raw)).String()
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		host = string(raw)
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	request.AddressType = head[3]
	request.Host = host
	request.Port = binary.BigEndian.Uint16(portBytes)
	s.mu.Lock()
	s.requests = append(s.requests, request)
	s.mu.Unlock()
	upstreamAddress := net.JoinHostPort(host, fmt.Sprint(request.Port))
	if s.backendOverride != nil {
		if backend, found := s.backendOverride[upstreamAddress]; found {
			upstreamAddress = backend
		}
	}
	upstream, err := net.DialTimeout("tcp", upstreamAddress, 5*time.Second)
	if err != nil {
		s.refused.Add(1)
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func (s *socksSink) seen() []socksRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]socksRequest(nil), s.requests...)
}

func (s *socksSink) waitForRequests(t *testing.T, n int, timeout time.Duration) []socksRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		requests := s.seen()
		if len(requests) >= n {
			return requests
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %d SOCKS request(s) at the far end, saw %v", timeout, n, requests)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForHost waits for the far end to be asked for a specific host.
//
// Scenarios assert on the request they caused rather than on its position in the list: a position
// couples every assertion to the order the subtests happen to run in, which turns an unrelated
// subtest into a confusing failure somewhere else.
func (s *socksSink) waitForHost(t *testing.T, host string, timeout time.Duration) socksRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, request := range s.seen() {
			if request.Host == host {
				return request
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for a SOCKS request for %q at the far end, saw %v", timeout, host, s.seen())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForHostPort is waitForHost for a host that legitimately appears more than once.
func (s *socksSink) waitForHostPort(t *testing.T, host string, port uint16, timeout time.Duration) socksRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, request := range s.seen() {
			if request.Host == host && request.Port == port {
				return request
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for a SOCKS request for %s:%d at the far end, saw %v", timeout, host, port, s.seen())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Real DNS server
// ---------------------------------------------------------------------------

// dnsResponder is a real DNS server on UDP and TCP. It is intentionally hand-written rather than
// built from the product's own DNS code: a split-routing test whose responder shares a
// implementation with the resolver cannot distinguish "the rule selected server B" from "both
// implementations agree on the same wrong answer".
//
// The handler records every question it is asked, which is what makes "did the split actually
// split" a measurement: an assertion is on the SET of questions each server received.
type dnsResponder struct {
	tag      string
	udp      net.PacketConn
	tcp      net.Listener
	mu       sync.Mutex
	question []string
	// answer maps a queried name to the address to return. A name with no entry gets NXDOMAIN,
	// so a misrouted query fails loudly instead of silently resolving.
	answer map[string]netip.Addr
	// delay is applied before every answer so a test can exercise the timeout path.
	delay time.Duration
}

func startDNSResponder(t *testing.T, tag string, answers map[string]netip.Addr) *dnsResponder {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	responder := &dnsResponder{tag: tag, udp: udp, tcp: tcp, answer: answers}
	go responder.serveUDP()
	go responder.serveTCP()
	t.Cleanup(func() {
		udp.Close()
		tcp.Close()
	})
	return responder
}

func (d *dnsResponder) port() uint16 {
	return uint16(d.udp.LocalAddr().(*net.UDPAddr).Port)
}

func (d *dnsResponder) record(name string, queryType uint16) {
	d.mu.Lock()
	d.question = append(d.question, fmt.Sprintf("%s/%d", name, queryType))
	d.mu.Unlock()
}

func (d *dnsResponder) asked() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.question...)
}

func (d *dnsResponder) waitForQuestions(t *testing.T, n int, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		questions := d.asked()
		if len(questions) >= n {
			return questions
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %d question(s) at DNS server %q, saw %v", timeout, n, d.tag, questions)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (d *dnsResponder) serveUDP() {
	buffer := make([]byte, 4096)
	for {
		n, from, err := d.udp.ReadFrom(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:n]...)
		go func() {
			response := d.buildResponse(query)
			if response == nil {
				return
			}
			_, _ = d.udp.WriteTo(response, from)
		}()
	}
}

func (d *dnsResponder) serveTCP() {
	for {
		conn, err := d.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			for {
				lengthBytes := make([]byte, 2)
				if _, err = io.ReadFull(conn, lengthBytes); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(lengthBytes))
				if _, err = io.ReadFull(conn, query); err != nil {
					return
				}
				response := d.buildResponse(query)
				if response == nil {
					return
				}
				if _, err = conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(response)))); err != nil {
					return
				}
				if _, err = conn.Write(response); err != nil {
					return
				}
			}
		}()
	}
}

// buildResponse answers with a single A or AAAA record for the queried name, or NXDOMAIN. The
// answer section is rebuilt from the question, so the response is a well-formed message rather
// than a canned byte string.
func (d *dnsResponder) buildResponse(query []byte) []byte {
	name, queryType, questionEnd, ok := parseQuestion(query)
	if !ok {
		return nil
	}
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	d.record(name, queryType)
	response := make([]byte, 0, 512)
	response = append(response, query[0], query[1]) // transaction id
	if queryType == 1 || queryType == 28 {
		response = append(response, 0x81, 0x80) // response, recursion available
	} else {
		response = append(response, 0x81, 0x83) // NXDOMAIN for anything else
	}
	response = append(response, 0x00, 0x01) // question count
	address, found := d.answer[name]
	if !found || (queryType != 1 && queryType != 28) {
		response = append(response, 0x00, 0x00) // answer count
		response = append(response, 0x00, 0x00)
		response = append(response, 0x00, 0x00)
		return append(response, query[12:questionEnd]...)
	}
	if (queryType == 1) != address.Is4() {
		// The name exists but not in this family: NOERROR with no answer, which is what a real
		// server returns and what the resolver's family logic has to handle.
		response = append(response, 0x00, 0x00)
		response = append(response, 0x00, 0x00)
		response = append(response, 0x00, 0x00)
		return append(response, query[12:questionEnd]...)
	}
	response = append(response, 0x00, 0x01) // one answer
	response = append(response, 0x00, 0x00)
	response = append(response, 0x00, 0x00)
	response = append(response, query[12:questionEnd]...)
	response = append(response, 0xC0, 0x0C) // name pointer to the question
	if queryType == 1 {
		response = append(response, 0x00, 0x01)
	} else {
		response = append(response, 0x00, 0x1C)
	}
	response = append(response, 0x00, 0x01) // class IN
	response = append(response, 0x00, 0x00, 0x00, 0x3C)
	rawLength := 4
	if queryType == 28 {
		rawLength = 16
	}
	response = binary.BigEndian.AppendUint16(response, uint16(rawLength))
	if queryType == 1 {
		rawAddress := address.As4()
		response = append(response, rawAddress[:]...)
	} else {
		rawAddress := address.As16()
		response = append(response, rawAddress[:]...)
	}
	return response
}

// parseQuestion walks the (uncompressed, which is what a query always is) question section and
// returns the lowercased name, the query type and the offset one past the question.
func parseQuestion(message []byte) (string, uint16, int, bool) {
	if len(message) < 12 {
		return "", 0, 0, false
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(message) {
			return "", 0, 0, false
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 != 0 || offset+length > len(message) {
			return "", 0, 0, false
		}
		labels = append(labels, string(message[offset:offset+length]))
		offset += length
	}
	if offset+4 > len(message) {
		return "", 0, 0, false
	}
	queryType := binary.BigEndian.Uint16(message[offset : offset+2])
	return strings.ToLower(strings.Join(labels, ".")), queryType, offset + 4, true
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// requireEcho writes a payload and requires the exact bytes back. It is the assertion that bytes
// really crossed the chain, as opposed to a handshake having completed.
func requireEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := conn.Write([]byte(payload))
	require.NoError(t, err, "write through the proxied connection")
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "read the echoed payload back through the proxied connection")
	require.Equal(t, payload, string(reply))
}

func requireEchoUDP(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := conn.Write([]byte(payload))
	require.NoError(t, err, "write datagram through the proxied connection")
	reply := make([]byte, 65535)
	n, err := conn.Read(reply)
	require.NoError(t, err, "read the echoed datagram back")
	require.Equal(t, payload, string(reply[:n]))
}

// dnsQueryPayload builds a minimal well-formed DNS query for name/type, used to drive the UDP
// path of a proxied tunnel without pulling in a DNS client library.
func dnsQueryPayload(id uint16, name string, queryType uint16) []byte {
	message := binary.BigEndian.AppendUint16(nil, id)
	message = append(message, 0x01, 0x00) // standard query, recursion desired
	message = append(message, 0x00, 0x01)
	message = append(message, 0x00, 0x00)
	message = append(message, 0x00, 0x00)
	message = append(message, 0x00, 0x00)
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0x00)
	message = binary.BigEndian.AppendUint16(message, queryType)
	message = binary.BigEndian.AppendUint16(message, 0x0001) // class IN
	return message
}

func readDNSAddress(t *testing.T, payload []byte) netip.Addr {
	t.Helper()
	require.GreaterOrEqual(t, len(payload), 12)
	answerCount := binary.BigEndian.Uint16(payload[6:8])
	require.Greater(t, answerCount, uint16(0), "DNS response carried no answers: %x", payload)
	_, queryType, offset, ok := parseQuestion(payload)
	require.True(t, ok, "DNS response question section was unparseable: %x", payload)
	for index := 0; index < int(answerCount); index++ {
		offset = skipName(payload, offset)
		require.LessOrEqual(t, offset+10, len(payload))
		recordType := binary.BigEndian.Uint16(payload[offset : offset+2])
		length := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
		offset += 10
		require.LessOrEqual(t, offset+length, len(payload))
		if (recordType == 1 || recordType == 28) && queryType == recordType {
			address, isAddress := netip.AddrFromSlice(payload[offset : offset+length])
			require.True(t, isAddress)
			return address
		}
		offset += length
	}
	t.Fatalf("no matching answer record in %x", payload)
	return netip.Addr{}
}

func skipName(message []byte, offset int) int {
	for offset < len(message) {
		length := int(message[offset])
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += 1 + length
	}
	return offset
}

// tempDir returns a per-test directory that the cleanup removes.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sing-box-e2e-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
