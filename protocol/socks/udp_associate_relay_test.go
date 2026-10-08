package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// An unspecified BND.ADDR in a UDP ASSOCIATE reply must be resolved against the configured
// server, not dialled as an address.
//
// # The failure this pins
//
// The SOCKS5 client dials the relay at whatever BND.ADDR the server sent. Public proxies answer
// "0.0.0.0" or "::" meaning "any address of mine", which the RFC allows. Go reads an unspecified
// literal as the LOCAL SYSTEM, so every datagram went to 127.0.0.1 with no error: TCP through the
// same proxy worked and UDP silently did not, which is the hardest kind of report to chase.
func TestRelayAddressNormalisesUnspecifiedBind(t *testing.T) {
	t.Parallel()

	ipServer := M.ParseSocksaddr("203.0.113.7:1080")
	domainServer := M.ParseSocksaddr("proxy.example:1080")

	testCases := []struct {
		name       string
		bind       string
		serverAddr M.Socksaddr
		want       string
		wantErr    bool
	}{
		{name: "v4 unspecified over an IP server", bind: "0.0.0.0:2000", serverAddr: ipServer, want: "203.0.113.7:2000"},
		{name: "v6 unspecified over an IP server", bind: "[::]:2000", serverAddr: ipServer, want: "203.0.113.7:2000"},
		{name: "v4 unspecified over a domain server", bind: "0.0.0.0:2000", serverAddr: domainServer, want: "proxy.example:2000"},
		{name: "v6 unspecified over a domain server", bind: "[::]:2000", serverAddr: domainServer, want: "proxy.example:2000"},
		{name: "empty host over an IP server", bind: ":2000", serverAddr: ipServer, want: "203.0.113.7:2000"},
		{name: "v4-mapped unspecified", bind: "[::ffff:0.0.0.0]:2000", serverAddr: ipServer, want: "203.0.113.7:2000"},
		{name: "concrete IP is honoured", bind: "198.51.100.9:2000", serverAddr: ipServer, want: "198.51.100.9:2000"},
		{name: "loopback is honoured", bind: "127.0.0.1:2000", serverAddr: ipServer, want: "127.0.0.1:2000"},
		{name: "private address is honoured", bind: "10.1.2.3:2000", serverAddr: ipServer, want: "10.1.2.3:2000"},
		{name: "zero port names no relay", bind: "0.0.0.0:0", serverAddr: ipServer, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			relay := newRelayDialer(nil, testCase.serverAddr)
			got, err := relay.relayAddress(M.ParseSocksaddr(testCase.bind))
			if testCase.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, got.String())
		})
	}
}

// A concrete BND.ADDR, and every TCP dial, must reach the underlying dialer unchanged.
func TestRelayDialerPassesThroughEverythingElse(t *testing.T) {
	t.Parallel()

	recorder := &recordingDialer{}
	relay := newRelayDialer(recorder, M.ParseSocksaddr("203.0.113.7:1080"))

	// TCP is the CONNECT path and the control connection; the wrapper must not touch it.
	require.NoError(t, relayDialAndClose(t, relay, N.NetworkTCP, "example.com:443"))
	require.Equal(t, []dialRecord{{network: N.NetworkTCP, destination: "example.com:443"}}, recorder.records())

	recorder.reset()
	require.NoError(t, relayDialAndClose(t, relay, N.NetworkUDP, "198.51.100.9:2000"))
	require.Equal(t, []dialRecord{{network: N.NetworkUDP, destination: "198.51.100.9:2000"}}, recorder.records())
}

// The contract the shim depends on: the upstream SOCKS5 client dials the relay at the raw
// BND.ADDR it was given, through the dialer it was constructed with.
//
// This is the condition-of-removal tripwire. If sing ever normalises the bind itself, this test
// fails and the wrapper can be deleted rather than kept as dead weight.
func TestUpstreamClientDialsBndBindAsIs(t *testing.T) {
	t.Parallel()

	proxy := newFakeSocks5Proxy(t, "0.0.0.0:2000")
	recorder := &recordingDialer{tcpTarget: proxy.listener.Addr().String()}
	client := socks.NewClient(recorder, M.ParseSocksaddr("203.0.113.7:1080"), socks.Version5, "", "")

	packetConn, err := client.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.NoError(t, err)
	require.NoError(t, packetConn.Close())
	require.NoError(t, proxy.wait())

	records := recorder.records()
	require.Len(t, records, 2, "one TCP control connection and one UDP relay dial")
	require.Equal(t, N.NetworkTCP, records[0].network)
	require.Equal(t, N.NetworkUDP, records[1].network)
	require.Equal(t, "0.0.0.0:2000", records[1].destination,
		"the raw unspecified bind must reach the dialer; if it does not, sing has started "+
			"normalising it and the relay wrapper is no longer needed")
}

// And the same handshake through the wrapper must land on the configured server.
func TestRelayDialerNormalisesBindThroughTheUpstreamClient(t *testing.T) {
	t.Parallel()

	proxy := newFakeSocks5Proxy(t, "0.0.0.0:2000")
	recorder := &recordingDialer{tcpTarget: proxy.listener.Addr().String()}
	relay := newRelayDialer(recorder, M.ParseSocksaddr("203.0.113.7:1080"))
	client := socks.NewClient(relay, M.ParseSocksaddr("203.0.113.7:1080"), socks.Version5, "", "")

	packetConn, err := client.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.NoError(t, err)
	require.NoError(t, packetConn.Close())
	require.NoError(t, proxy.wait())

	records := recorder.records()
	require.Len(t, records, 2)
	require.Equal(t, "203.0.113.7:1080", records[0].destination, "TCP must stay untouched")
	require.Equal(t, "203.0.113.7:2000", records[1].destination,
		"the relay must be dialled at the configured server with the port the server chose")
}

// relayDialAndClose dials and immediately closes, since these assertions are about the dial call.
func relayDialAndClose(t *testing.T, dialer N.Dialer, network string, destination string) error {
	t.Helper()
	conn, err := dialer.DialContext(context.Background(), network, M.ParseSocksaddr(destination))
	if err != nil {
		return err
	}
	return conn.Close()
}

type dialRecord struct {
	network     string
	destination string
}

// recordingDialer remembers what it was asked for.
//
// TCP dials are forwarded to the fake proxy listener rather than answered locally, so the
// library performs a real handshake over a real socket. The destination is still recorded as the
// caller wrote it, because the assertion is about which ADDRESS the client asked for.
type recordingDialer struct {
	access  sync.Mutex
	entries []dialRecord
	// tcpTarget is where a TCP dial is actually connected; empty means an inert pipe, which is
	// enough for the tests that only inspect the recorded address.
	tcpTarget string
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.entries = append(d.entries, dialRecord{network: network, destination: destination.String()})
	d.access.Unlock()
	if network == N.NetworkUDP {
		// A real unconnected UDP socket, because the caller wraps the result as a net.Conn for
		// the relay and may close it; a pipe would not survive the packet-conn wrapper.
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return nil, err
		}
		connected := &connectedUDPConn{UDPConn: udpConn, remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
		return connected, nil
	}
	if d.tcpTarget != "" {
		return net.Dial("tcp", d.tcpTarget)
	}
	clientConn, serverConn := net.Pipe()
	// Nothing reads the far end; draining it keeps the pipe's peer from blocking forever.
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
		_ = serverConn.Close()
	}()
	return clientConn, nil
}

// connectedUDPConn is a UDP socket presented with a RemoteAddr, which is the shape a dialed UDP
// connection has and the shape the relay wrapper expects.
type connectedUDPConn struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (c *connectedUDPConn) RemoteAddr() net.Addr { return c.remote }

func (c *connectedUDPConn) Write(b []byte) (int, error) {
	return c.WriteToUDP(b, c.remote)
}

func (d *recordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (d *recordingDialer) records() []dialRecord {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]dialRecord(nil), d.entries...)
}

func (d *recordingDialer) reset() {
	d.access.Lock()
	d.entries = nil
	d.access.Unlock()
}

// fakeSocks5Proxy answers one SOCKS5 UDP ASSOCIATE with the given bind address.
//
// It is written by hand rather than taken from sing because the point is to pin the CLIENT's
// behaviour: the reply has to be exactly what a real server sends, including an unspecified
// BND.ADDR, and the server side of the library is not what is under test.
type fakeSocks5Proxy struct {
	listener net.Listener
	done     chan error
}

func newFakeSocks5Proxy(t *testing.T, bindAddress string) *fakeSocks5Proxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	proxy := &fakeSocks5Proxy{listener: listener, done: make(chan error, 1)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		proxy.done <- proxy.serve(bindAddress)
	}()
	return proxy
}

func (p *fakeSocks5Proxy) serve(bindAddress string) error {
	conn, err := p.listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	// Greeting: VER NMETHODS METHODS[NMETHODS].
	var greeting [2]byte
	if _, err = io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 0x05 {
		return errors.New("unexpected socks version")
	}
	if _, err = io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
		return err
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	var request [4]byte
	if _, err = io.ReadFull(conn, request[:]); err != nil {
		return err
	}
	var toSkip int
	switch request[3] {
	case 0x01:
		toSkip = 4
	case 0x04:
		toSkip = 16
	case 0x03:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return err
		}
		toSkip = int(length[0])
	default:
		return errors.New("unknown address type")
	}
	if _, err = io.CopyN(io.Discard, conn, int64(toSkip)); err != nil {
		return err
	}
	var requestPort [2]byte
	if _, err = io.ReadFull(conn, requestPort[:]); err != nil {
		return err
	}
	bind := M.ParseSocksaddr(bindAddress)
	address := bind.Addr
	addressType := byte(0x01)
	if address.Is6() {
		addressType = 0x04
	} else if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	reply := make([]byte, 0, 22)
	reply = append(reply, 0x05, 0x00, 0x00, addressType)
	reply = append(reply, address.AsSlice()...)
	reply = append(reply, byte(bind.Port>>8), byte(bind.Port))
	_, err = conn.Write(reply)
	return err
}

func (p *fakeSocks5Proxy) wait() error {
	select {
	case err := <-p.done:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("fake socks5 proxy did not finish")
	}
}
