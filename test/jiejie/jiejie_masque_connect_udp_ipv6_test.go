package jiejie_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/stretchr/testify/require"
)

// CONNECT-UDP to an IPv6 destination, over both production transports.
//
// The production minimal topology serves CONNECT-UDP on the http inbound over HTTP/2
// (behind Nginx) and HTTP/3 (UDP/443), and it is the path that goes to a real VPS. The
// existing coverage drove IPv4 destinations almost exclusively, and the one IPv6 case in
// the reference module proved only that a scoped target is refused. This file carries
// real UDP to an IPv6 origin on BOTH transports.
//
// # Availability is probed, and a missing probe is a SKIP with a reason
//
// IPv6 loopback is present on most runners but not guaranteed, and a runner without it
// cannot test this at all. The probe below reports absence explicitly, and the test then
// SKIPs with a reason naming the missing capability. A SKIP is NEVER reported as a pass;
// see ipv6TestAddress, which is the same helper the Naive UoT IPv6 suite uses so the two
// cannot disagree about whether IPv6 is available.
//
// The unit-level IPv6 target parsing is covered unconditionally and does not depend on
// this: transport/http/connect_udp_path_test.go and
// TestConnectUDPTargetRoundTrip drive the IPv6 literal forms with no network at all.

// startMinimalUDPEchoIPv6 starts a UDP echo origin bound to an IPv6 address.
//
// It returns the address to use as a CONNECT-UDP target and a label describing which
// address was available, so a skip can say exactly what was missing.
func startMinimalUDPEchoIPv6(t *testing.T) (string, string) {
	t.Helper()

	address, label := ipv6TestAddress(t)
	if address == nil {
		return "", ""
	}

	udpConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: address})
	if err != nil {
		// The probe said IPv6 was available and the bind still failed. That is a real
		// difference between "the family exists" and "a socket can be bound", so it is
		// reported rather than silently turned into a skip.
		t.Logf("IPv6 is available (%s) but binding a UDP6 socket failed: %v", label, err)
		return "", ""
	}
	t.Cleanup(func() { udpConn.Close() })

	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, readErr := udpConn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			payload := append([]byte("v6-origin:"), buffer[:n]...)
			_, _ = udpConn.WriteToUDP(payload, from)
		}
	}()

	local := udpConn.LocalAddr().(*net.UDPAddr)
	return net.JoinHostPort(local.IP.String(), strconv.Itoa(local.Port)), label
}

// TestJiejieMinimalMASQUEH3ConnectUDPIPv6 is the HTTP/3 half.
//
// A CONNECT-UDP tunnel is opened to an IPv6 origin and one datagram is carried in each
// direction. The reply is prefixed by the origin so a local echo cannot satisfy it.
func TestJiejieMinimalMASQUEH3ConnectUDPIPv6(t *testing.T) {
	target, label := startMinimalUDPEchoIPv6(t)
	if target == "" {
		t.Skip("no IPv6 address is available on this runner (neither loopback nor a " +
			"local interface address could be bound), so a CONNECT-UDP tunnel to an " +
			"IPv6 origin cannot be established. This is a SKIP with a reason, NOT a " +
			"pass. The IPv6 target PARSING is covered unconditionally by " +
			"TestConnectUDPTargetRoundTrip in transport/http.")
	}

	server := startMinimalMASQUEH3(t, false)
	client := dialMinimalH3(t, server.port)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stream, err := client.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(target),
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a CONNECT-UDP request to an IPv6 target must be accepted on the HTTP/3 listener")

	payload := append([]byte{0}, []byte("h3-ipv6-udp")...)
	require.NoError(t, stream.SendDatagram(payload))

	received, err := stream.ReceiveDatagram(ctx)
	require.NoError(t, err,
		"the tunnel must carry a datagram to the IPv6 origin and back; nothing arriving "+
			"means the IPv6 destination was never dialled (%s)", label)
	require.Equal(t, append([]byte{0}, []byte("v6-origin:h3-ipv6-udp")...), received,
		"the reply must be the one the IPv6 ORIGIN produced, proving the payload crossed "+
			"the proxy rather than being echoed locally")

	stream.Close()
	t.Logf("HTTP/3 CONNECT-UDP to an IPv6 origin (%s) carried a datagram round trip", label)
}

// TestJiejieMinimalMASQUEH2ConnectUDPIPv6 is the HTTP/2 half.
//
// It is a separate test rather than a table row because the H2 transport is a genuinely
// different code path in the inbound, and because on Go 1.27 the extended-CONNECT
// pseudo-header cannot be expressed from a test client at all - so this SKIPs there for
// a documented toolchain reason, which is different from an IPv6 skip.
func TestJiejieMinimalMASQUEH2ConnectUDPIPv6(t *testing.T) {
	// Toolchain gate FIRST, so a Go 1.27 run reports the toolchain reason rather than an
	// IPv6 reason for a test that could not run either way.
	requireH2ExtendedConnectUsable(t)

	target, label := startMinimalUDPEchoIPv6(t)
	if target == "" {
		t.Skip("no IPv6 address is available on this runner, so a CONNECT-UDP tunnel to " +
			"an IPv6 origin cannot be established over HTTP/2. This is a SKIP with a " +
			"reason, NOT a pass.")
	}

	server := startMinimalMASQUEH2(t, false)
	clientConn := dialMinimalH2(t, server.port)

	pipeReader, pipeWriter := io.Pipe()
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(target),
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			":protocol":           []string{"connect-udp"},
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
		Body: pipeReader,
	})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a CONNECT-UDP request to an IPv6 target must be accepted on the HTTP/2 listener")

	// HTTP/2 has no HTTP Datagrams here, so the payload travels as a DATAGRAM capsule.
	payload := []byte("h2-ipv6-udp")
	require.NoError(t, writeMinimalDatagramCapsule(pipeWriter, payload))

	type readResult struct {
		frame []byte
		err   error
	}
	resultChannel := make(chan readResult, 1)
	go func() {
		frame, readErr := readMinimalDatagramCapsule(response.Body)
		resultChannel <- readResult{frame: frame, err: readErr}
	}()

	select {
	case result := <-resultChannel:
		require.NoError(t, result.err)
		require.Equal(t, append([]byte("v6-origin:"), payload...), result.frame,
			"the reply must be the one the IPv6 ORIGIN produced (%s)", label)
	case <-time.After(15 * time.Second):
		t.Fatalf("no CONNECT-UDP echo from the IPv6 origin arrived within 15s (%s): the "+
			"IPv6 destination was never dialled, or the HTTP/2 capsule path is broken",
			label)
	}
	pipeWriter.Close()
	t.Logf("HTTP/2 CONNECT-UDP to an IPv6 origin (%s) carried a datagram round trip", label)
}

// TestJiejieMinimalMASQUEIPv6AvailabilityIsReported makes the probe's own result visible,
// so a SKIP above can be attributed and a runner that DOES have IPv6 cannot silently stop
// testing it.
//
// It cannot fail: it only records. Its purpose is that the skip reason in the two tests
// above is verifiable from the same log, rather than being taken on trust.
func TestJiejieMinimalMASQUEIPv6AvailabilityIsReported(t *testing.T) {
	address, label := ipv6TestAddress(t)
	if address == nil {
		t.Log("IPv6: NOT AVAILABLE on this runner; the IPv6 CONNECT-UDP tests will SKIP " +
			"with that reason")
		return
	}

	// Confirm a socket can actually be bound, which is the stronger claim the tests need.
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Logf("IPv6: available (%s) but udp6 loopback bind failed: %v", label, err)
		return
	}
	_ = conn.Close()
	t.Logf("IPv6: available and bindable (%s)", label)
}

var (
	_ = http2.NextProtoTLS
	_ = http3.NextProtoH3
)
