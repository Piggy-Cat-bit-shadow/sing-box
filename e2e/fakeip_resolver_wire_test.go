package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A `domain_resolver` that names a FakeIP server must not be able to put a synthetic address on the
// wire, and this is the product-level detector for it.
//
// # The configuration, and why it is one the product accepts
//
// `domain_resolver` and `destination_dns_ownership` live in the same dial fields, and nothing in the
// configuration layer refuses a FakeIP server there: the box STARTS. The DNS layer is where the
// contradiction has to be caught, because a fakeip server does not resolve a name - it invents an
// address inside its own range and remembers the pair, so the answer is meaningful only inside this
// process. A peer that receives it is asked to reach a destination that does not exist, and the box's
// own second decision maps it back to the name it came from.
//
// # What was measured before the guard, on this exact stand
//
//   - `MEASURED domain "leak.test" -> reply code 0x00, hop recorded [198.18.0.2:443]`
//
// The hop is a real SOCKS5 server that records the target of every CONNECT it is asked for, so that
// recording is a wire fact rather than a log line. Two things are wrong with it at once: the flow
// SUCCEEDS, and the destination is an address only the box can interpret.
//
// The assertions below are the inverse, and they are deliberately about BOTH halves: a refusal that
// still asked the peer would leave the wire fact in place.
func TestAFakeIPDomainResolverNeverPutsASyntheticAddressOnTheWire(t *testing.T) {
	const userTarget = "fakeip-resolver-leak.test"

	hop := startSocksHop(t, "exit")
	mixedPort := freePort(t)
	instance := startChain(t, fakeIPResolverConfig(t, mixedPort, hop))
	t.Cleanup(func() { _ = instance.closeNow() })

	conn, code := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", mixedPort), 0x03, userTarget, 443)
	if conn != nil {
		defer conn.Close()
	}

	// The wire fact, read after the client observed its reply so the peer's request - if there is one -
	// has been recorded. A refused flow leaves this empty.
	recorded := awaitHopRecording(t, hop, 200*time.Millisecond)
	t.Logf("domain %q -> reply code 0x%02x, hop recorded %v", userTarget, code, recorded)

	require.Empty(t, recorded,
		"the peer was asked for %v: a fakeip server answered a destination lookup, so the address it "+
			"invented travelled to a peer that cannot interpret it", recorded)
	require.NotEqual(t, byte(0x00), code,
		"the connect reported SUCCESS while nothing was reachable: the peer was never asked, so "+
			"whatever the client received referred to a destination that does not exist")
	require.Zero(t, hop.acceptCount(),
		"the hop accepted %d connection(s) for a destination that must never reach it", hop.acceptCount())
}

// awaitHopRecording gives an in-flight request a bounded window to be recorded, so that "the hop was
// never asked" is measured after the flow has had its chance rather than before. A fixed sleep would
// either race the request or slow every green run; this polls and returns what it saw.
func awaitHopRecording(t *testing.T, hop *socksHop, window time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		recorded := hop.recorded()
		if len(recorded) > 0 || time.Now().After(deadline) {
			return recorded
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeIPResolverConfig is the smallest box that reaches the branch: a FakeIP server, a hosts server as
// the default so the configuration is otherwise ordinary, one mixed inbound, and one SOCKS5 hop that
// owns destination DNS through the FAKEIP server.
func fakeIPResolverConfig(t *testing.T, mixedPort uint16, hop *socksHop) string {
	t.Helper()
	hopHost, hopPort := mustSplitHostPort(t, hop.address())
	return fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"tag": "fake", "type": "fakeip", "inet4_range": "198.18.0.0/15"},
      {"tag": "static", "type": "hosts", "predefined": {"unused.test": "127.0.0.1"}}
    ],
    "final": "static"
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [{
    "type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
    "domain_resolver": "fake", "destination_dns_ownership": true
  }],
  "route": {"final": "exit"}
}`, mixedPort, hopHost, hopPort)
}
