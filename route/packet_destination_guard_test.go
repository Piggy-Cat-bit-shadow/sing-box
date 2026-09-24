package route

import (
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
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
