package e2e

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// dnsRecordingWriter is the packet writer a hijacked DNS response is delivered to. It is the same
// interface the TUN packet loop provides, so a response arriving here is a response the tunnel
// would have written back to the device.
type dnsRecordingWriter struct {
	mu       sync.Mutex
	payloads [][]byte
	signal   chan struct{}
}

func newDNSRecordingWriter() *dnsRecordingWriter {
	return &dnsRecordingWriter{signal: make(chan struct{}, 1)}
}

func (w *dnsRecordingWriter) WritePacket(packet *buf.Buffer, _ M.Socksaddr) error {
	w.mu.Lock()
	w.payloads = append(w.payloads, append([]byte(nil), packet.Bytes()...))
	w.mu.Unlock()
	packet.Release()
	select {
	case w.signal <- struct{}{}:
	default:
	}
	return nil
}

// WaitForPacket is a wait on an observation rather than a sleep.
func (w *dnsRecordingWriter) WaitForPacket(t *testing.T, count int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		w.mu.Lock()
		payloads := append([][]byte(nil), w.payloads...)
		w.mu.Unlock()
		if len(payloads) >= count {
			return payloads
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %d DNS response(s), saw %d", timeout, count, len(payloads))
		}
		select {
		case <-w.signal:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

var _ N.PacketWriter = (*dnsRecordingWriter)(nil)

// queryThroughHijack sends a DNS query through the router's TUN hijack entry point, exactly as the
// tun packet loop does, and returns the response payload.
//
// This is the product's own DNS entry point for a hijacked packet: the tun stack calls it inline
// from the goroutine that dispatches every forwarded packet. Driving it directly covers hijack ->
// DNS rules -> transport -> server -> cache -> reverse mapping, and deliberately does NOT cover the
// tun stack's packet plumbing above it; tun_chain_test.go covers that half.
func queryThroughHijack(t *testing.T, running *chain, name string, queryType uint16) []byte {
	t.Helper()
	writer := newDNSRecordingWriter()
	payload := dnsQueryPayload(0x1234, name, queryType)
	metadata := adapter.InboundContext{
		Inbound:     "tun-in",
		InboundType: C.TypeTun,
		Network:     N.NetworkUDP,
		Source:      M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 5353),
		Destination: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 53),
	}
	running.router().HijackDNSPacket(context.Background(), payload, writer, metadata)
	responses := writer.WaitForPacket(t, 1, 15*time.Second)
	return responses[0]
}

// dnsChainConfig is a split-DNS configuration: three independent servers, a rule that sends one
// domain to the second, and a fakeip server in front of a third domain.
//
// The two upstream servers answer the SAME names with DIFFERENT addresses, so "which server
// answered" can be told apart from the response itself as well as from each server's question log.
const dnsChainConfig = `{
  "log": {"level": "%s"},
  "dns": {
    "servers": [
      {"tag": "primary", "type": "udp", "server": "127.0.0.1", "server_port": %d},
      {"tag": "secondary", "type": "udp", "server": "127.0.0.1", "server_port": %d},
      {"tag": "fakeip", "type": "fakeip", "inet4_range": "198.18.0.0/15"}
    ],
    "rules": [
      {"domain": ["split-b.test"], "server": "secondary"},
      {"domain": ["fake.test"], "server": "fakeip"}
    ],
    "final": "primary",
    "strategy": "ipv4_only",
    "reverse_mapping": true
  },
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "remote", "server": "127.0.0.1", "server_port": %d, "version": "5"}
  ],
  "route": {
    "rules": [
      {"domain": ["fake.test"], "action": "route", "outbound": "remote"},
      {"domain": ["split-b.test"], "action": "route", "outbound": "remote"}
    ],
    "final": "direct"
  }
}`

// TestDNSSplitRouting measures the DNS chain with real servers.
func TestDNSSplitRouting(t *testing.T) {
	primary := startDNSResponder(t, "primary", map[string]netip.Addr{
		"split-a.test": netip.MustParseAddr("127.0.0.1"),
		"split-b.test": netip.MustParseAddr("127.0.0.2"),
		"revmap.test":  netip.MustParseAddr("127.0.0.1"),
	})
	secondary := startDNSResponder(t, "secondary", map[string]netip.Addr{
		"split-a.test": netip.MustParseAddr("127.0.0.9"),
		"split-b.test": netip.MustParseAddr("127.0.0.1"),
	})
	sink := startSocksSink(t, "127.0.0.1:0")
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sink.backendOverride = map[string]string{
		"split-b.test:" + fmt.Sprint(echoPort): echo.listener.Addr().String(),
		"fake.test:" + fmt.Sprint(echoPort):    echo.listener.Addr().String(),
	}
	proxyPort := freePort(t)
	config := fmt.Sprintf(dnsChainConfig, chainLogLevel, primary.port(), secondary.port(), proxyPort,
		uint16(sink.listener.Addr().(*net.TCPAddr).Port))
	running := startChain(t, config)
	proxyAddress := fmt.Sprintf("127.0.0.1:%d", proxyPort)

	t.Run("split_rule_selects_secondary", func(t *testing.T) {
		response := queryThroughHijack(t, running, "split-b.test", 1)
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, response),
			"the secondary server's answer must be the one returned")
		require.Contains(t, secondary.asked(), "split-b.test/1")
		require.NotContains(t, primary.asked(), "split-b.test/1",
			"a split that leaks the query to the primary server is not a split")
	})

	t.Run("final_uses_primary", func(t *testing.T) {
		response := queryThroughHijack(t, running, "split-a.test", 1)
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, response))
		require.Contains(t, primary.asked(), "split-a.test/1")
		require.NotContains(t, secondary.asked(), "split-a.test/1")
	})

	t.Run("cached_answer_does_not_requery", func(t *testing.T) {
		before := len(primary.asked())
		response := queryThroughHijack(t, running, "split-a.test", 1)
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, response))
		require.Equal(t, before, len(primary.asked()), "the second identical query must be served from cache")
	})

	// -------------------------------------------------------------------
	// What a network reset does to the cache, measured rather than assumed.
	//
	// The answer cache SURVIVES by policy: ResetNetwork advances the
	// generation, resets the transports and purges the reverse mapping, but
	// it does not clear the response cache. That is upstream behaviour
	// ("Avoid clearing DNS caches during network resets"), pinned in
	// dns/reset_ordering_window_test.go. The generation guard governs what
	// may be WRITTEN, not what may be read - so the expectation that a
	// cached answer must not cross a network generation is not what this
	// product does, and the two subtests below pin both halves of the real
	// contract at the chain level.
	// -------------------------------------------------------------------
	t.Run("network_reset_keeps_the_response_cache", func(t *testing.T) {
		before := len(primary.asked())
		running.router().ResetNetwork()
		response := queryThroughHijack(t, running, "split-a.test", 1)
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, response))
		require.Equal(t, before, len(primary.asked()),
			"the documented policy is that a network reset does not clear the answer cache")
	})

	t.Run("reverse_mapping_names_a_literal_destination", func(t *testing.T) {
		// revmap.test resolves to 127.0.0.1, which is also the echo server's address, so a
		// connection to the LITERAL address must be matched as the domain the answer named.
		require.Equal(t, netip.MustParseAddr("127.0.0.1"), readDNSAddress(t, queryThroughHijack(t, running, "revmap.test", 1)))
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "reverse-mapping")
		flows := running.tracker.waitForFlows(t, 1, 10*time.Second)
		flow := flows[len(flows)-1]
		require.Equal(t, "revmap.test", flow.Domain,
			"a destination address that a previous answer named must carry that name on the flow")
		require.Equal(t, "127.0.0.1:"+fmt.Sprint(echoPort), flow.Destination,
			"the reverse mapping names the flow; it must not rewrite the destination")
	})

	t.Run("network_reset_purges_the_reverse_mapping", func(t *testing.T) {
		// No DNS query between the reset and the connection: a name that only the purge could
		// have removed must be gone. Asking again would re-learn the mapping from the (still
		// cached) answer and measure nothing.
		running.router().ResetNetwork()
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "reverse-mapping-purged")
		flows := running.tracker.waitForFlows(t, 2, 10*time.Second)
		require.Empty(t, flows[len(flows)-1].Domain,
			"a reverse mapping learned before a network reset must not outlive it")
	})

	t.Run("fakeip_maps_and_unmaps", func(t *testing.T) {
		response := queryThroughHijack(t, running, "fake.test", 1)
		address := readDNSAddress(t, response)
		require.True(t, address.Is4(), "fakeip must answer with an IPv4 address for an A query")
		require.True(t, netip.MustParsePrefix("198.18.0.0/15").Contains(address),
			"the fake address must come from the configured range, got %s", address)
		// The reverse mapping is the half that makes the fake address usable: a flow that connects
		// to it must be routed as the domain, not as 198.18.x.y.
		conn := dialSocks5(t, proxyAddress, 0x01, address.String(), echoPort)
		defer conn.Close()
		requireEcho(t, conn, "fakeip-reverse-mapping")
		request := sink.waitForHost(t, "fake.test", 10*time.Second)
		require.Equal(t, "fake.test", request.Host,
			"a connection to a fake address must be forwarded as the mapped domain")
		flows := running.tracker.waitForFlows(t, 3, 10*time.Second)
		flow := flows[len(flows)-1]
		require.True(t, flow.FakeIP, "the flow must be marked as a fakeip flow")
		require.Equal(t, address.String()+":"+fmt.Sprint(echoPort), flow.OriginDestination)
		require.Equal(t, "fake.test:"+fmt.Sprint(echoPort), flow.Destination)
		require.Equal(t, "remote", flow.RouteOutbound)
		require.Contains(t, flow.RouteRule, "fake.test")
	})

	t.Run("connection_to_domain_uses_secondary_server", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x03, "split-b.test", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "dns-split-end-to-end")
		require.Contains(t, secondary.asked(), "split-b.test/1")
		require.NotContains(t, primary.asked(), "split-b.test/1")
	})
}
