package jiejie_test

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// ALPN isolation on a tcp+udp Native Naive inbound, measured at runtime.
//
// Why this file exists separately from the tcp-only matrix: the tcp-only matrix
// cannot detect the defect this covers. On a tcp-only inbound there is no HTTP/3
// listener, so h3 is absent from the ALPN list for an unrelated reason - the
// transport does not exist - and every assertion passes whether or not the TCP
// and QUIC views are actually separate.
//
// On a tcp+udp inbound both transports run from one TLS object, and that is where
// the question is real: does a TCP client ever negotiate h3, a QUIC-only
// protocol? These tests answer it with real handshakes on both transports.
//
// The required behaviour:
//
//	TCP  TLS -> h2, http/1.1
//	QUIC TLS -> h3

// startNaiveInboundTCPAndUDP starts an inbound serving both transports, which is
// the configuration under test.
//
// It returns the port and whether the process can actually serve HTTP/3. Under
// the production tag set the QUIC package is deliberately not linked, so a udp
// inbound starts TCP and warns that HTTP/3 is disabled; the isolation question
// cannot be asked there and the caller must SKIP rather than fail. When QUIC IS
// linked, a failure to establish HTTP/3 is a real defect and must not be skipped -
// the previous version of the h3 suite treated exactly that condition as an
// environment SKIP, which is how a broken QUIC path stayed invisible.
func startNaiveInboundTCPAndUDP(t *testing.T) (uint16, bool) {
	t.Helper()
	port := startNaiveInboundWithNetwork(t, "tcp\nudp")
	if !http3SupportLinked() {
		return port, false
	}
	return port, true
}

// http3SupportLinked reports whether this build links protocol/naive/quic.
//
// The check is build-tag-based rather than behavioural: asking whether a
// handshake happens to succeed cannot distinguish "QUIC is not in this build"
// from "QUIC is in this build and is broken", and those two must not be treated
// the same way.
func http3SupportLinked() bool {
	return naiveHTTP3Included
}

// negotiateQUICALPN performs a real QUIC handshake and reports the negotiated
// application protocol.
//
// A successful return means the QUIC handshake completed, so the negotiated
// value is what the server actually agreed to rather than what it advertised.
func negotiateQUICALPN(t *testing.T, port uint16, offered []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx,
		"127.0.0.1:"+strconv.Itoa(int(port)),
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         offered,
		}, &quic.Config{})
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	return conn.ConnectionState().TLS.NegotiatedProtocol, nil
}

// TestJiejieNaiveTCPAndUDPALPNIsolation is the runtime proof for a mixed inbound.
//
// Every case performs a REAL handshake. No case asserts on a config object,
// because a config object that lists the right protocols proves nothing about
// what a handshake actually negotiates.
func TestJiejieNaiveTCPAndUDPALPNIsolation(t *testing.T) {
	port, quicLinked := startNaiveInboundTCPAndUDP(t)
	if !quicLinked {
		t.Skipf("this build does not link HTTP/3 support (the production tag set " +
			"omits protocol/naive/quic), so the TCP/QUIC isolation question cannot " +
			"be asked. Run under with_quic without jiejie_server_minimal. This is a " +
			"SKIP, not a pass.")
	}

	// Establish the QUIC listener first. On a tcp+udp inbound the HTTP/3
	// initialiser runs after the TCP listener starts, so a test that only
	// handshook before H3 existed would miss anything the initialiser changed.
	//
	// A failure HERE is fatal rather than a skip: QUIC support is linked, so an
	// unreachable HTTP/3 listener is a defect.
	_, quicErr := negotiateQUICALPN(t, port, []string{http3.NextProtoH3})
	require.NoError(t, quicErr,
		"HTTP/3 support is linked but the listener is unreachable: that is a "+
			"defect, not an environment limitation. Without this the isolation "+
			"question is moot and the test would prove nothing")
	t.Logf("QUIC listener established on port %d", port)

	t.Run("TCP offering h3 alone must not negotiate h3", func(t *testing.T) {
		negotiated, err := negotiateTCPALPN(t, port, []string{http3.NextProtoH3})
		if err != nil {
			// A clean handshake failure is the ideal outcome: nothing was offered
			// that this listener supports.
			t.Logf("h3-only offer rejected at the TCP handshake: %v", err)
			return
		}
		require.NotEqual(t, http3.NextProtoH3, negotiated,
			"a TCP listener negotiated h3, which is a QUIC-only protocol: the "+
				"shared TLS config leaked the QUIC ALPN into the TCP view")
		t.Logf("h3-only offer negotiated %q", negotiated)
	})

	t.Run("TCP offering h3 and h2 must negotiate h2", func(t *testing.T) {
		negotiated, err := negotiateTCPALPN(t, port, []string{http3.NextProtoH3, "h2"})
		require.NoError(t, err)
		require.Equal(t, "h2", negotiated,
			"when a client offers a protocol both transports could name, the TCP "+
				"listener must choose the HTTP one")
	})

	t.Run("TCP offering h3 and http/1.1 must negotiate http/1.1", func(t *testing.T) {
		negotiated, err := negotiateTCPALPN(t, port, []string{http3.NextProtoH3, "http/1.1"})
		require.NoError(t, err)
		require.Equal(t, "http/1.1", negotiated)
	})

	t.Run("TCP offering all three must negotiate h2", func(t *testing.T) {
		negotiated, err := negotiateTCPALPN(t, port,
			[]string{"h2", "http/1.1", http3.NextProtoH3})
		require.NoError(t, err)
		require.NotEqual(t, http3.NextProtoH3, negotiated,
			"a TCP listener must never negotiate h3")
		require.Equal(t, "h2", negotiated)
	})

	t.Run("QUIC offering h3 must negotiate h3", func(t *testing.T) {
		negotiated, err := negotiateQUICALPN(t, port, []string{http3.NextProtoH3})
		require.NoError(t, err, "the QUIC listener must accept h3")
		require.Equal(t, http3.NextProtoH3, negotiated)
	})

	t.Run("QUIC offering only h2 must not establish", func(t *testing.T) {
		negotiated, err := negotiateQUICALPN(t, port, []string{"h2"})
		if err == nil {
			require.NotEqual(t, "h2", negotiated,
				"a QUIC connection negotiated h2: the QUIC listener must accept "+
					"only the HTTP/3 ALPN")
		} else {
			t.Logf("QUIC h2-only offer rejected as expected: %v", err)
		}
	})

	// The two transports must not have contaminated each other: after all of the
	// above, each still answers correctly. This is the post-condition that a
	// mutate-before-handshake implementation would fail intermittently.
	t.Run("both transports still answer correctly afterwards", func(t *testing.T) {
		tcpNegotiated, err := negotiateTCPALPN(t, port, []string{"h2"})
		require.NoError(t, err)
		require.Equal(t, "h2", tcpNegotiated)

		quicNegotiated, err := negotiateQUICALPN(t, port, []string{http3.NextProtoH3})
		require.NoError(t, err)
		require.Equal(t, http3.NextProtoH3, quicNegotiated)
	})
}

// TestJiejieNaiveTCPAndUDPALPNIsolationUnderConcurrency runs TCP and QUIC
// handshakes CONCURRENTLY.
//
// This is the case a "set the ALPN list just before each handshake" fix would
// fail: the two transports would race on one object, and a TCP client would
// intermittently negotiate h3. A design with genuinely separate views cannot
// produce that, so this test is what distinguishes isolation from a timing
// coincidence.
func TestJiejieNaiveTCPAndUDPALPNIsolationUnderConcurrency(t *testing.T) {
	port, quicLinked := startNaiveInboundTCPAndUDP(t)
	if !quicLinked {
		t.Skipf("this build does not link HTTP/3 support, so a TCP/QUIC race " +
			"cannot be exercised. This is a SKIP, not a pass.")
	}

	_, err := negotiateQUICALPN(t, port, []string{http3.NextProtoH3})
	require.NoError(t, err, "the QUIC listener must be up before the race begins")

	type result struct {
		transport  string
		negotiated string
		err        error
	}
	const rounds = 12
	results := make(chan result, rounds*2)

	for range rounds {
		go func() {
			negotiated, tcpErr := negotiateTCPALPN(t, port, []string{"h2", "http/1.1", http3.NextProtoH3})
			results <- result{"tcp", negotiated, tcpErr}
		}()
		go func() {
			negotiated, quicErr := negotiateQUICALPN(t, port, []string{http3.NextProtoH3})
			results <- result{"quic", negotiated, quicErr}
		}()
	}

	for range rounds * 2 {
		select {
		case got := <-results:
			switch got.transport {
			case "tcp":
				require.NoError(t, got.err, "a TCP handshake failed during the race")
				require.NotEqual(t, http3.NextProtoH3, got.negotiated,
					"a TCP handshake negotiated h3 while a QUIC handshake was in "+
						"flight: the transports are racing on one TLS object")
			case "quic":
				require.NoError(t, got.err, "a QUIC handshake failed during the race")
				require.Equal(t, http3.NextProtoH3, got.negotiated)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("a handshake never completed; the transports may be deadlocked " +
				"on a shared object")
		}
	}
	t.Logf("%d concurrent TCP+QUIC handshake pairs completed with no cross-talk", rounds)
}
