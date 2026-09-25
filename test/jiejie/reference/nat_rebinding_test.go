package reference_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// A UDP NAT rebinding relay.
//
// The point is to change the source address the SERVER sees for an established
// QUIC connection, without touching the client at all. That is what a NAT does
// when its mapping expires or its external port changes, and it is the case the
// QUIC path manager exists to handle.
//
// quic-go's public API has no "rebind this connection" call, and patching it was
// out of scope, so the rebinding is produced below the QUIC layer:
//
//	client  ->  127.0.0.1:relayPort        (stable, never changes)
//	relay   ->  upstream socket A -> server
//	              [rebind]
//	relay   ->  upstream socket B -> server
//
// The client keeps sending to the same relay address and the same QUIC connection,
// while the server sees the remote port change. Path validation is then entirely
// quic-go's responsibility, which is exactly the division of labour the task
// requires: sing-box must not reimplement PATH_CHALLENGE/PATH_RESPONSE, and this
// harness must not fake it.

// udpNATRelay forwards UDP between a stable client-facing address and a swappable
// upstream socket.
type udpNATRelay struct {
	t *testing.T

	// clientFacing is the address the client dials and keeps using.
	clientFacing *net.UDPConn
	// upstream is the socket currently talking to the server. It is replaced by
	// rebind, which is what changes the observed source port.
	upstream *net.UDPConn

	serverAddress string

	access     sync.Mutex
	clientAddr *net.UDPAddr
	closed     bool
	// upstreamPort records the local port of each upstream socket, in order, so a
	// test can prove the rebound socket really did have a different source port.
	upstreamPorts []int

	// Counters, so a failure can say WHICH direction stopped rather than only that
	// no reply came back.
	clientToUpstream atomic.Int64
	upstreamToClient atomic.Int64
}

// packetCounts returns how many packets crossed the relay in each direction.
func (r *udpNATRelay) packetCounts() (fromClient int64, toClient int64) {
	return r.clientToUpstream.Load(), r.upstreamToClient.Load()
}

// startUDPNATRelay starts the relay and returns it along with the stable address a
// client should dial.
func startUDPNATRelay(t *testing.T, serverAddress string) (*udpNATRelay, string) {
	t.Helper()

	clientFacing, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	relay := &udpNATRelay{
		t:             t,
		clientFacing:  clientFacing,
		serverAddress: serverAddress,
	}
	require.NoError(t, relay.openUpstream())

	go relay.forwardClientToUpstream()
	go relay.forwardUpstreamToClient()

	t.Cleanup(relay.close)
	return relay, clientFacing.LocalAddr().String()
}

// openUpstream creates a fresh socket toward the server. Each call produces a
// different local port, which is what makes the rebind observable to the server.
func (r *udpNATRelay) openUpstream() error {
	serverAddr, err := net.ResolveUDPAddr("udp", r.serverAddress)
	if err != nil {
		return err
	}
	upstream, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	r.access.Lock()
	r.upstream = upstream
	r.upstreamPorts = append(r.upstreamPorts, upstream.LocalAddr().(*net.UDPAddr).Port)
	r.access.Unlock()
	return nil
}

// forwardClientToUpstream carries client packets to whichever upstream socket is
// current. It remembers the client's address so replies can be routed back.
func (r *udpNATRelay) forwardClientToUpstream() {
	buffer := make([]byte, 65535)
	for {
		n, from, err := r.clientFacing.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		if r.closed {
			r.access.Unlock()
			return
		}
		r.clientAddr = from
		upstream := r.upstream
		r.access.Unlock()

		if _, err := upstream.Write(buffer[:n]); err != nil {
			// A socket being swapped out can fail here; the next packet goes
			// through the new one.
			continue
		}
		r.clientToUpstream.Add(1)
	}
}

// forwardUpstreamToClient carries server packets back to the remembered client.
func (r *udpNATRelay) forwardUpstreamToClient() {
	buffer := make([]byte, 65535)
	for {
		r.access.Lock()
		upstream := r.upstream
		r.access.Unlock()
		if upstream == nil {
			return
		}
		n, err := upstream.Read(buffer)
		if err != nil {
			// The socket was replaced or closed; the loop below re-reads the
			// current one.
			time.Sleep(2 * time.Millisecond)
			r.access.Lock()
			closed := r.closed
			r.access.Unlock()
			if closed {
				return
			}
			continue
		}
		r.access.Lock()
		clientAddr := r.clientAddr
		r.access.Unlock()
		if clientAddr == nil {
			continue
		}
		if _, err := r.clientFacing.WriteToUDP(buffer[:n], clientAddr); err != nil {
			continue
		}
		r.upstreamToClient.Add(1)
	}
}

// rebind replaces the upstream socket, which changes the source port the server
// sees for every packet afterwards. The old socket is closed so no traffic can
// leak through it and make the test pass for the wrong reason.
func (r *udpNATRelay) rebind() {
	r.t.Helper()

	r.access.Lock()
	previous := r.upstream
	r.access.Unlock()

	require.NoError(r.t, r.openUpstream())

	if previous != nil {
		// Close only after the new socket is installed, so the forwarding loop
		// always has a live socket to read.
		_ = previous.Close()
	}

	r.access.Lock()
	ports := append([]int(nil), r.upstreamPorts...)
	r.access.Unlock()
	require.GreaterOrEqual(r.t, len(ports), 2)
	require.NotEqual(r.t, ports[len(ports)-2], ports[len(ports)-1],
		"the rebind must produce a socket with a DIFFERENT local port, or the "+
			"server would see no change at all and the test would prove nothing")
}

// upstreamPortsSeen returns the local ports of every upstream socket used, in
// order.
func (r *udpNATRelay) upstreamPortsSeen() []int {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]int(nil), r.upstreamPorts...)
}

func (r *udpNATRelay) close() {
	r.access.Lock()
	if r.closed {
		r.access.Unlock()
		return
	}
	r.closed = true
	upstream := r.upstream
	r.upstream = nil
	r.access.Unlock()

	_ = r.clientFacing.Close()
	if upstream != nil {
		_ = upstream.Close()
	}
}

// ---------------------------------------------------------------------------
// A CONNECT-UDP client behind the relay
// ---------------------------------------------------------------------------

// relayedConnectUDPClient is a CONNECT-UDP client whose QUIC connection goes
// through a NAT relay, so its observed source address can be changed underneath
// it.
type relayedConnectUDPClient struct {
	relay      *udpNATRelay
	quicConn   *quic.Conn
	transport  *http3.Transport
	clientConn *http3.ClientConn
}

// startRelayedConnectUDPClient dials the MASQUE server through a relay.
func startRelayedConnectUDPClient(t *testing.T, server *singBoxServer, relayDialAddress string) *relayedConnectUDPClient {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, relayDialAddress, &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: true}
	client := &relayedConnectUDPClient{
		quicConn:   quicConn,
		transport:  transport,
		clientConn: transport.NewClientConn(quicConn),
	}
	t.Cleanup(func() {
		client.clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return client
}

// openTunnel performs an RFC 9298 CONNECT-UDP through the relay.
func (c *relayedConnectUDPClient) openTunnel(t *testing.T, target string) (*http3.RequestStream, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	request := connectUDPRequest(target)
	require.NoError(t, stream.SendRequestHeader(&request))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode,
		"the CONNECT-UDP request must be accepted through the relay")
	return stream, ""
}

// datagramEchoRoundTrip sends one payload as an HTTP Datagram on the tunnel and
// returns the origin's answer.
//
// It is the smallest unit of data-path evidence: a payload in and the origin's
// own reply out. Every migration case is built from it, so a failure points at the
// case rather than at the plumbing.
func datagramEchoRoundTrip(t *testing.T, stream *http3.RequestStream, payload string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Context ID 0 followed by the UDP payload.
	require.NoError(t, stream.SendDatagram(append([]byte{0}, []byte(payload)...)))

	type received struct {
		data []byte
		err  error
	}
	done := make(chan received, 1)
	go func() {
		data, err := stream.ReceiveDatagram(ctx)
		done <- received{data, err}
	}()

	select {
	case result := <-done:
		require.NoError(t, result.err, "the tunnel must deliver the origin's reply")
		contextID, contextLength, ok := decodeVarint(result.data)
		require.True(t, ok, "the reply must carry a context ID")
		require.Equal(t, uint64(0), contextID,
			"the reply must use context ID 0, the only context this endpoint carries")
		return string(result.data[contextLength:])
	case <-time.After(15 * time.Second):
		t.Fatal("no reply arrived within 15s")
		return ""
	}
}
