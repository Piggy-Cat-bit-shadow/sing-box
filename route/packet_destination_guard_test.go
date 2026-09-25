package route

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestPacketDestinationCacheKeyNormalisesEquivalentForms guards the memoisation
// used by the datagram ACL: two spellings of the same destination must share one
// decision, otherwise a client could sidestep a cached reject by reformatting
// the address, and an IPv4-mapped IPv6 address must not be judged separately
// from the IPv4 address it denotes.
func TestPacketDestinationCacheKeyNormalisesEquivalentForms(t *testing.T) {
	cases := []struct {
		name  string
		left  M.Socksaddr
		right M.Socksaddr
	}{
		{
			name:  "same IPv4",
			left:  M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 80),
			right: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 80),
		},
		{
			name:  "IPv4 mapped versus plain",
			left:  M.SocksaddrFrom(netip.MustParseAddr("::ffff:127.0.0.1"), 80),
			right: M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 80),
		},
		{
			name:  "same domain",
			left:  M.Socksaddr{Fqdn: "example.test", Port: 80},
			right: M.Socksaddr{Fqdn: "example.test", Port: 80},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			leftKey := cacheKey(testCase.left)
			rightKey := cacheKey(testCase.right)
			if leftKey != rightKey {
				t.Fatalf("equivalent destinations must share a cache key: %q != %q",
					leftKey, rightKey)
			}
		})
	}
}

// TestPacketDestinationCacheKeyDistinguishesPorts ensures the port participates
// in the decision, since a rule may match on it.
func TestPacketDestinationCacheKeyDistinguishesPorts(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")
	if cacheKey(M.SocksaddrFrom(address, 80)) == cacheKey(M.SocksaddrFrom(address, 443)) {
		t.Fatal("different ports must not share a cache key")
	}
}

// TestPacketDestinationCacheKeyDistinguishesAddresses ensures unrelated
// addresses never collide.
func TestPacketDestinationCacheKeyDistinguishesAddresses(t *testing.T) {
	if cacheKey(M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 80)) ==
		cacheKey(M.SocksaddrFrom(netip.MustParseAddr("10.0.0.1"), 80)) {
		t.Fatal("different addresses must not share a cache key")
	}
}

// The guard must remain the ONLY way a guarded datagram is read.
//
// sing/common has several read paths that do not go through ReadPacket:
// ReadFrom (N.NetPacketReader), ReadCachedPacket (N.CachedPacketReader),
// CreatePacketReadWaiter (N.PacketReadWaiter / N.ReaderWithUpstream) and
// CreatePacketBatchReadWaiter. Each unwraps or type-asserts its way to a
// faster path when the connection exposes it.
//
// The guard is currently safe only because it embeds the NARROW N.PacketConn
// interface, whose only read method is ReadPacket. Embedding the wider
// N.NetPacketConn instead would silently promote ReadFrom past the check, and
// adding ReaderReplaceable/UpstreamReader would let the copy machinery unwrap
// to the raw connection. That would re-open the very bypass this guard exists
// to close, and it would do so without any test failing.
//
// This test pins the invariant, so a refactor that widens the embedding or
// adds a replaceable marker fails loudly here instead of quietly disabling the
// per-datagram target check on the production UDP path.
func TestPacketDestinationGuardExposesNoBypassReadPath(t *testing.T) {
	var guarded any = &packetDestinationGuard{}

	if _, ok := guarded.(N.NetPacketReader); ok {
		t.Fatal("the guard must not expose ReadFrom: CopyPacket and the read " +
			"waiters would use it and skip the per-datagram destination check")
	}
	if _, ok := guarded.(N.CachedPacketReader); ok {
		t.Fatal("the guard must not expose ReadCachedPacket: the cached-packet " +
			"fast path delivers a buffer without a destination check")
	}
	if _, ok := guarded.(N.PacketReadWaiter); ok {
		t.Fatal("the guard must not expose a packet read waiter: it reads " +
			"directly from the underlying connection")
	}
	if _, ok := guarded.(N.ReaderWithUpstream); ok {
		t.Fatal("the guard must not advertise a replaceable reader: the copy " +
			"machinery would unwrap past the guard to the raw connection")
	}
	if _, ok := guarded.(N.WithUpstreamReader); ok {
		t.Fatal("the guard must not expose UpstreamReader: the copy machinery " +
			"would unwrap past the guard to the raw connection")
	}
}

// checkPacketDestination returns a yes/no decision, not an outbound. This is a
// deliberate scope limit and it only stays safe while no rule selects a
// DIFFERENT outbound for a per-datagram target than the session would use.
//
// If such a rule existed, a datagram would be permitted by the guard and then
// sent through the outbound already chosen for the SESSION, silently ignoring
// the routing decision the rule expresses - traffic leaving through a path the
// operator did not choose. That is worse than a refusal.
//
// The production topology satisfies the precondition: the only rules that
// select an outbound for traffic reaching naive-in UDP are
//   - "ip_is_private -> direct", where direct is also the final outbound, so
//     the route decision and the default agree; and
//   - the ACL reject, which refuses before any outbound is chosen.
//
// The residential-socks rule requires network=tcp and so can never match a UoT
// datagram.
//
// This test encodes that precondition, so adding a rule that genuinely selects
// a different outbound for a datagram target makes the limitation fail loudly
// here instead of silently in production.
func TestPacketDestinationGuardOutboundSelectionPrecondition(t *testing.T) {
	topology, err := os.ReadFile("../release/jiejie-production-topology.json")
	if err != nil {
		t.Skipf("production topology not readable from this package: %v", err)
	}
	var parsed struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err = json.Unmarshal(topology, &parsed); err != nil {
		t.Fatalf("production topology is not valid JSON: %v", err)
	}

	for index, rule := range parsed.Route.Rules {
		outbound, selectsOutbound := rule["outbound"].(string)
		if !selectsOutbound || outbound == "" {
			continue
		}
		// Selecting the same outbound the session already uses cannot change
		// the path, so it is not a per-datagram routing decision.
		if outbound == parsed.Route.Final {
			continue
		}
		if networks, hasNetwork := rule["network"]; hasNetwork {
			if list, ok := networks.([]any); ok {
				appliesToUDP := false
				for _, network := range list {
					if network == "udp" {
						appliesToUDP = true
					}
				}
				if !appliesToUDP {
					continue
				}
			}
		}
		t.Fatalf("rule[%d] can select outbound %q for a UoT datagram, but the "+
			"guard permits per-datagram targets without re-routing them; such a "+
			"rule would be silently ignored. Use a reject rule, or extend the "+
			"guard to carry the outbound decision.", index, outbound)
	}
}

// TestPacketDestinationGuardPermitsWhenNoRuleMatches is the cross-protocol
// safety property.
//
// common/uot/router.go is shared by twelve protocol inbounds (anytls, http,
// mixed, naive, shadowsocks, snell, socks, tuic, vless, vmess ...). Flagging a
// session as carrying per-datagram destinations therefore installs this guard
// for all of them, not only Naive. That is safe only if the guard is INERT when
// the operator has written no rule for the traffic: it must permit, and must
// not resolve, rewrite or drop anything on its own initiative.
//
// checkPacketDestination is what decides that, so it is exercised here directly
// with a router that has no rules. A default (permit) result is the contract
// the other protocols rely on.
func TestPacketDestinationGuardPermitsWhenNoRuleMatches(t *testing.T) {
	router := &Router{}
	metadata := adapter.InboundContext{
		Network: N.NetworkUDP,
		Destination: M.SocksaddrFrom(
			netip.MustParseAddr("127.0.0.1"), 53,
		),
	}
	permitted, err := router.checkPacketDestination(context.Background(), &metadata)
	if err != nil {
		t.Fatalf("a rule-free router must not error: %v", err)
	}
	if !permitted {
		t.Fatal("a rule-free router must permit: the guard is installed for " +
			"every protocol that uses common/uot, so a default-deny here would " +
			"break UDP for all of them")
	}
}
