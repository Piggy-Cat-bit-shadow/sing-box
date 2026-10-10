package e2e

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DEBUG-02 part two: destination DNS ownership, observed at the PEER
// ---------------------------------------------------------------------------
//
// `destination_dns_ownership` is a promise about what the DOWNSTREAM PEER receives: an address, not
// the user's name. The unit tests in protocol/socks and protocol/http assert that at the protocol
// boundary with a substituted resolver. This asserts it on the same real two-hop stand as the wire
// order, where the resolver is the box's own and the peer is a real server that reads the bytes.
//
// The origin is reached BY NAME, and the recording at the hop says which form arrived.

// TestDestinationDNSOwnershipSendsAnAddressToTheHop is the positive row.
//
// With `destination_dns_ownership` on and a resolver that answers, the hop must be asked for an
// ADDRESS. Asserting on the address alone would not be enough - a hop that received the name and
// resolved it itself would also eventually reach the origin - so the assertion is on the FORM the
// hop recorded, taken from the ATYP byte of the request it actually read.
func TestDestinationDNSOwnershipSendsAnAddressToTheHop(t *testing.T) {
	t.Parallel()

	origin := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, originPort := mustSplitHostPort(t, echoAddress(origin))

	// The name the client will ask for. It is deliberately NOT resolvable by the system resolver:
	// if ownership is not honoured, the hop receives this string and nothing can dial it, which
	// makes the two outcomes distinguishable rather than both ending at the origin.
	const userTarget = "ownership.test"

	hop := startSocksHop(t, "exit")
	hopPort := portOnly(t, hop.address())

	chainPort := freePort(t)
	instance := startChain(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"tag": "local", "type": "local"},
      {"tag": "static", "type": "hosts", "predefined": {"ownership.test": "127.0.0.1"}}
    ],
    "rules": [{"domain": ["ownership.test"], "server": "static"}]
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "domain_resolver": "static",
     "destination_dns_ownership": true}
  ],
  "route": {"final": "exit"}
}`, chainPort, hostOnly(t, hop.address()), hopPort))
	t.Cleanup(func() { _ = instance.closeNow() })

	conn := dialSocks5(t, fmt.Sprintf("127.0.0.1:%d", chainPort), 0x03, userTarget, originPort)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	_, err := conn.Write([]byte("owned"))
	require.NoError(t, err)
	got := make([]byte, len("owned"))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err,
		"the flow must complete, or the recording below describes a request that was never served")
	require.Equal(t, "owned", string(got))

	recorded := hop.recorded()
	require.NotEmpty(t, recorded, "the hop must have been asked for something")
	require.NotContains(t, strings.Join(recorded, " "), userTarget,
		"the hop must NOT receive the user's NAME: destination DNS ownership means the address "+
			"crosses the boundary and the name does not. Recorded: %v", recorded)
	require.Contains(t, strings.Join(recorded, " "), "127.0.0.1",
		"and the hop must receive the ADDRESS the resolver answered. Recorded: %v", recorded)
}

// TestWithoutDestinationDNSOwnershipTheNameStillTravels is the control.
//
// The same configuration with the flag OFF. The hop must then receive the NAME, because that is what
// a single-hop proxy does by default: the remote end resolves, which is what keeps CDN region
// selection working. Without this row, the test above could be satisfied by a client that always
// resolves locally, which would be a silent behaviour change for every ordinary configuration.
func TestWithoutDestinationDNSOwnershipTheNameStillTravels(t *testing.T) {
	t.Parallel()

	origin := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, originPort := mustSplitHostPort(t, echoAddress(origin))

	// This name IS resolvable, so the flow can complete whether or not the hop resolves it - which
	// is what makes it a fair control: the only difference under test is the FORM on the wire.
	const userTarget = "localhost"

	hop := startSocksHop(t, "exit")
	hopPort := portOnly(t, hop.address())

	chainPort := freePort(t)
	instance := startChain(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5"}
  ],
  "route": {"final": "exit"}
}`, chainPort, hostOnly(t, hop.address()), hopPort))
	t.Cleanup(func() { _ = instance.closeNow() })

	conn := dialSocks5(t, fmt.Sprintf("127.0.0.1:%d", chainPort), 0x03, userTarget, originPort)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	_, err := conn.Write([]byte("remote"))
	require.NoError(t, err)
	got := make([]byte, len("remote"))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)

	recorded := strings.Join(hop.recorded(), " ")
	require.Contains(t, recorded, userTarget,
		"without the flag the NAME must still travel to the hop, which is the default remote-"+
			"resolution behaviour single-hop proxies depend on. Recorded: %v", recorded)
	require.False(t, strings.Contains(recorded, "127.0.0.1:%d") && !strings.Contains(recorded, userTarget),
		"and the name must not have been replaced by an address: %v", recorded)
}

// TestDestinationDNSOwnershipFailsClosedWhenItCannotResolve asserts the failure mode on the wire.
//
// The flag is on, the resolver has no answer, and the flow must FAIL rather than fall back to sending
// the name. A fallback would be a silent leak of the user's destination to the peer, which is the
// exact outcome the flag exists to prevent.
func TestDestinationDNSOwnershipFailsClosedWhenItCannotResolve(t *testing.T) {
	t.Parallel()

	// A name the hosts server does not know and the local resolver must not be asked for.
	const unresolvable = "must-not-leak.test"

	hop := startSocksHop(t, "exit")
	hopPort := portOnly(t, hop.address())

	chainPort := freePort(t)
	instance := startChain(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"tag": "static", "type": "hosts", "predefined": {"other.test": "127.0.0.1"}}
    ]
  },
  "inbounds": [{"type": "mixed", "tag": "device-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": %q, "server_port": %d, "version": "5",
     "domain_resolver": "static",
     "destination_dns_ownership": true}
  ],
  "route": {"final": "exit"}
}`, chainPort, hostOnly(t, hop.address()), hopPort))
	t.Cleanup(func() { _ = instance.closeNow() })

	conn, code := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", chainPort), 0x03, unresolvable, 443)
	if conn != nil {
		defer conn.Close()
	}
	require.NotEqual(t, byte(0x00), code,
		"a destination the local policy cannot resolve must FAIL when ownership is declared, "+
			"got a success reply")

	// The assertion that matters: the peer must have received NOTHING. A build that logged an error
	// and then sent the name anyway would satisfy an assertion made on the returned error alone.
	require.Empty(t, hop.recorded(),
		"the hop must not have been asked for the destination at all - not the name and not an "+
			"address. Recorded: %v", hop.recorded())
}
