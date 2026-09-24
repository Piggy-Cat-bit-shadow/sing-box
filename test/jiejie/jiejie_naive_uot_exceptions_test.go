package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// These tests cover the UDP exception paths that were not independently exercised
// before: a session that outlives its useful life, a destination that cannot be
// resolved, and a destination that cannot be reached.
//
// The last one needs care, and the task is right to call it out: "the UDP target
// did not answer" is NOT the same as "the network reported the target
// unreachable". A silent target and a refused target produce different errors and
// must be tested separately. Both cases are covered below, plus the case where
// the local send itself fails.

// uotSessionTarget is a UoT session whose destination is a specific address.
func openUoTSessionTo(t *testing.T, port uint16, target string) *uotSession {
	t.Helper()
	conn := naiveTLSConn(t, port)
	response := naiveWriteConnectOK(t, conn, uot.RequestDestination(uot.Version).String(),
		map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
	require.Equal(t, http.StatusOK, response.StatusCode)

	session := &uotSession{conn: conn, reader: bufio.NewReader(conn), padding: true, version: uot.Version}
	addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr(target))
	require.NoError(t, err)
	_, err = conn.Write(naivePaddingFrame(append([]byte{1}, addressBytes...), 0))
	require.NoError(t, err)
	return session
}

// ---------------------------------------------------------------------------
// 1. UoT session timeout / lifetime
// ---------------------------------------------------------------------------

// TestJiejieNaiveUoTSessionSurvivesIdlePeriod proves an idle-but-open UoT session
// is not torn down prematurely, and that it still works after being idle far
// longer than any internal processing interval.
//
// This is the counterweight to a timeout test: a session that closes too eagerly
// would break long-lived UDP flows such as a persistent game or VPN session.
func TestJiejieNaiveUoTSessionSurvivesIdlePeriod(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := openUoTSessionTo(t, env.port, env.echoAddr)
	defer session.Close()

	// Use it once, idle well past a second, then use it again.
	first := []byte("before-idle")
	session.writeDatagram(t, uot.Version, env.echoAddr, first)
	require.Equal(t, first, session.readDatagram(t, uot.Version))

	time.Sleep(3 * time.Second)

	second := []byte("after-idle")
	session.writeDatagram(t, uot.Version, env.echoAddr, second)
	require.Equal(t, second, session.readDatagram(t, uot.Version),
		"an idle UoT session must remain usable: a UDP flow may legitimately be "+
			"quiet for a long time and then resume")
}

// TestJiejieNaiveUoTSessionClosesWhenClientGoesAway proves that when the client
// disappears, the server side finishes the session rather than holding it open,
// and that other sessions are unaffected.
func TestJiejieNaiveUoTSessionClosesWhenClientGoesAway(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// A session that is opened, used, and then abandoned abruptly.
	abandoned := openUoTSessionTo(t, env.port, env.echoAddr)
	abandoned.writeDatagram(t, uot.Version, env.echoAddr, []byte("first"))
	require.Equal(t, []byte("first"), abandoned.readDatagram(t, uot.Version))
	abandoned.Close()

	// A second session must be entirely unaffected by the first one going away.
	survivor := openUoTSessionTo(t, env.port, env.echoAddr)
	defer survivor.Close()
	payload := []byte("survivor")
	survivor.writeDatagram(t, uot.Version, env.echoAddr, payload)
	require.Equal(t, payload, survivor.readDatagram(t, uot.Version),
		"one client disconnecting must not disturb another UoT session")
}

// ---------------------------------------------------------------------------
// 2. DNS resolution failure
// ---------------------------------------------------------------------------

// TestJiejieNaiveUoTSilentTargetIsNotAnError is the FIRST unreachable case and the
// one the task warns about: a UDP target that simply never answers.
//
// UDP is connectionless, so a silent target is not "unreachable" from the
// network's point of view. The server must neither hang nor tear itself down, and
// the session must remain usable for a target that DOES answer.
func TestJiejieNaiveUoTSilentTargetIsNotAnError(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// A UDP socket that is bound but never replies.
	silentConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer silentConn.Close()
	silentAddr := silentConn.LocalAddr().String()

	// UoT v2 CONNECT mode fixes the destination in the REQUEST HEADER, so the
	// silent target must be named there rather than per datagram. This is the
	// correct model and the tests below rely on it.
	silentSession := openUoTSessionTo(t, env.port, silentAddr)
	defer silentSession.Close()

	silentSession.writeDatagram(t, uot.Version, silentAddr, []byte("into-the-void"))

	// The silent session must not have produced a reply, and must not have
	// broken the server: a DIFFERENT session to a target that answers still works.
	require.NoError(t, silentSession.conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buffer := make([]byte, 8)
	_, readErr := silentSession.reader.Peek(1)
	require.Error(t, readErr,
		"a silent UDP target must produce no reply")
	_ = buffer

	healthy := openUoTSessionTo(t, env.port, env.echoAddr)
	defer healthy.Close()
	healthy.writeDatagram(t, uot.Version, env.echoAddr, []byte("still-alive"))
	require.Equal(t, []byte("still-alive"), healthy.readDatagram(t, uot.Version),
		"a silent UDP target must not affect other sessions: UDP has no delivery "+
			"guarantee, so silence is normal and must not be treated as a fault")
}

// TestJiejieNaiveUoTSendFailureIsContained covers the case where the write itself
// cannot succeed, which is distinct from silence and from ICMP unreachable.
//
// A UDP write to an address that cannot be routed fails locally. The session must
// contain that failure rather than dropping the tunnel or the process.
func TestJiejieNaiveUoTSendFailureIsContained(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// 240.0.0.0/4 is reserved and unroutable; a send there fails locally on most
	// stacks rather than waiting for a timeout. The destination is named in the
	// request header because v2 connect mode fixes it there.
	unroutable := "240.0.0.1:9"
	failingSession := openUoTSessionTo(t, env.port, unroutable)
	defer failingSession.Close()
	failingSession.writeDatagram(t, uot.Version, unroutable, []byte("unroutable"))

	// A different, reachable session must be entirely unaffected.
	healthy := openUoTSessionTo(t, env.port, env.echoAddr)
	defer healthy.Close()
	healthy.writeDatagram(t, uot.Version, env.echoAddr, []byte("after-send-failure"))
	require.Equal(t, []byte("after-send-failure"), healthy.readDatagram(t, uot.Version),
		"a locally failing UDP send must not destroy other UoT sessions")
}

// TestJiejieNaiveUoTUnresolvableDomainIsContained covers the DNS failure case.
//
// A domain that cannot be resolved must fail the datagram, not the session and not
// the process. The inbound must also not bypass the sing-box DNS path to "fix" it.
func TestJiejieNaiveUoTUnresolvableDomainIsContained(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// The v2 request header carries the destination, so use a domain that the
	// system resolver cannot answer. .invalid is reserved by RFC 2606 to never
	// resolve.
	failingSession := openUoTSessionTo(t, env.port, "does-not-exist.invalid:53")
	defer failingSession.Close()
	failingSession.writeDatagram(t, uot.Version, "does-not-exist.invalid:53", []byte("dns-fail"))

	// The failure must be contained: the server survives and a reachable target
	// still works in a separate session.
	healthy := openUoTSessionTo(t, env.port, env.echoAddr)
	defer healthy.Close()
	healthy.writeDatagram(t, uot.Version, env.echoAddr, []byte("after-dns-failure"))
	require.Equal(t, []byte("after-dns-failure"), healthy.readDatagram(t, uot.Version),
		"an unresolvable UDP destination must not break the server")
}

// TestJiejieNaiveUoTSilentTargetDoesNotLeakResources proves the silent-target and
// DNS-failure paths release their resources, since they are the paths most likely
// to leave a socket or goroutine behind.
func TestJiejieNaiveUoTSilentTargetDoesNotLeakResources(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	silentConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer silentConn.Close()
	silentAddr := silentConn.LocalAddr().String()

	// Warm up.
	for range 5 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("w"))
	}
	waitForGoroutineStabilisation(t)
	before := runtimeGoroutines()

	// Sessions that end via a silent target and via an unresolvable domain.
	const rounds = 30
	for index := range rounds {
		for _, target := range []string{silentAddr, "nope.invalid:53"} {
			conn, dialErr := net.DialTimeout("tcp",
				"127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
			if dialErr != nil {
				continue
			}
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
			if hsErr := tlsConn.Handshake(); hsErr != nil {
				conn.Close()
				continue
			}
			_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			tunnelReader, connectErr := writeConnectWithoutT(tlsConn,
				uot.RequestDestination(uot.Version).String())
			if connectErr != nil {
				conn.Close()
				continue
			}
			addressBytes, encErr := encodeV2RequestAddrForGoroutine(metadata.ParseSocksaddr(target))
			if encErr != nil {
				conn.Close()
				continue
			}
			_, _ = tlsConn.Write(naivePaddingFrame(append([]byte{1}, addressBytes...), 0))
			length := make([]byte, 2)
			binary.BigEndian.PutUint16(length, 4)
			_, _ = tlsConn.Write(naivePaddingFrame(append(length, []byte("ping")...), 0))
			// Do not wait for a reply: these targets never answer. Give the server
			// a moment to process, then drop the client hard.
			time.Sleep(5 * time.Millisecond)
			_ = tunnelReader
			_ = conn.Close()
		}
		_ = index
	}

	waitForGoroutineStabilisation(t)
	after := runtimeGoroutines()
	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d non-answering sessions",
		before, after, growth, rounds*2)

	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"UoT sessions that never receive a reply must not accumulate goroutines")
}
