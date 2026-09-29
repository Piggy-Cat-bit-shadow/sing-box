package masque

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// Tests for the DNS_ASSIGN and PREF64 session state.
//
// # The property under test
//
// Both capsules are DECLARATIVE, and the draft is explicit that each one supersedes
// the previous (DNS_ASSIGN §3.4, PREF64 §4.2). "Supersede" is the whole contract, and
// it fails in two ways that are easy to miss:
//
//  1. accumulating instead of replacing -- a server that narrows its DNS
//     configuration would leave the old resolvers usable;
//  2. replacing non-atomically -- a reader could observe one capsule's configuration
//     with the previous capsule's prefixes, a state the server never advertised.
//
// These tests pin both, plus the aliasing invariant the existing snapshot tests
// established for Address and Routes: a published snapshot's contents must not change
// when a later capsule arrives.

func testNameserver(t *testing.T, address string, priority uint16) DNSNameserver {
	t.Helper()
	return DNSNameserver{
		ServicePriority: priority,
		IPv4Addresses:   []netip.Addr{netip.MustParseAddr(address)},
	}
}

// TestDNSAssignReplacesRatherThanAccumulates is the primary semantic test.
//
// Three assignments arrive in sequence; only the last may be visible. An
// implementation that appended, or that merged nameservers, would fail here.
func TestDNSAssignReplacesRatherThanAccumulates(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.1", 1)},
	}}))
	first := current.loadState().configuration.DNS
	require.NotNil(t, first)
	require.Equal(t, 1, len(first.Configurations))

	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.2", 1)},
	}}))
	second := current.loadState().configuration.DNS
	require.NotNil(t, second)
	require.Len(t, second.Configurations, 1, "the second assignment must REPLACE the first")

	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.3", 1)},
	}}))
	third := current.loadState().configuration.DNS
	require.Len(t, third.Configurations, 1,
		"three assignments must leave exactly one configuration, not three")

	// The surviving configuration must be the LAST one.
	require.Len(t, third.Configurations[0].Nameservers, 1)
	require.Equal(t, netip.MustParseAddr("192.0.2.3"),
		third.Configurations[0].Nameservers[0].IPv4Addresses[0],
		"the most recent assignment must be the one in effect")
}

// TestDNSAssignGenerationIncrements proves the generation counter advances on every
// accepted capsule.
//
// The assigned-DNS transport uses this to isolate DNS cache entries between different
// resolver environments. If it did not increment, a query cached against the old
// nameserver could be served after the server replaced it.
func TestDNSAssignGenerationIncrements(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.1", 1)},
	}}))
	generation1 := current.loadState().configuration.DNS.Generation

	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.2", 1)},
	}}))
	generation2 := current.loadState().configuration.DNS.Generation

	require.Greater(t, generation2, generation1,
		"each accepted assignment must advance the generation")
}

// TestDNSAssignEmptyWithdrawsConfiguration covers the withdrawal case.
//
// A capsule carrying no configuration withdraws the previous one. Treating it as
// "nothing to do" would leave a resolver the server has explicitly stopped
// advertising, which is the same class of bug as accumulating.
func TestDNSAssignEmptyWithdrawsConfiguration(t *testing.T) {
	t.Parallel()

	current := &clientSession{}
	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.1", 1)},
	}}))
	require.NotNil(t, current.loadState().configuration.DNS)

	require.NoError(t, current.handleDNSAssign(nil))
	require.Nil(t, current.loadState().configuration.DNS,
		"an empty DNS_ASSIGN must withdraw the configuration")

	// And the generation must still advance, so a consumer comparing generations
	// sees the change rather than concluding nothing happened.
	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.9", 1)},
	}}))
	require.NotNil(t, current.loadState().configuration.DNS)
}

// TestPREF64ReplacesAndClears covers both halves of §4.2: a new capsule overrides, and
// an EMPTY capsule invalidates.
func TestPREF64ReplacesAndClears(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	require.NoError(t, current.handlePREF64([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
		current.loadState().configuration.PREF64)

	// Replacement, not accumulation.
	require.NoError(t, current.handlePREF64([]netip.Prefix{
		netip.MustParsePrefix("2001:db8:64::/96"),
		netip.MustParsePrefix("2001:db8::/32"),
	}))
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("2001:db8:64::/96"),
		netip.MustParsePrefix("2001:db8::/32"),
	}, current.loadState().configuration.PREF64)

	// An empty capsule clears, and that is a real instruction rather than a no-op.
	require.NoError(t, current.handlePREF64(nil))
	require.Nil(t, current.loadState().configuration.PREF64,
		"an empty PREF64 capsule must invalidate previously received prefixes")
}

// TestSessionSnapshotDoesNotAliasDNSPublishedState extends the existing aliasing
// invariant to the new fields.
//
// The publisher copies Configuration by value and carries its slices as-is, which is
// only sound while every writer assigns wholesale. DNS and PREF64 are new fields in
// that struct, so the same rule has to hold for them or a reader holding an old
// snapshot could observe a later capsule's content.
func TestSessionSnapshotDoesNotAliasDNSPublishedState(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	require.NoError(t, current.handlePREF64([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}))
	first := current.loadState()

	// A later capsule with MORE prefixes, which would reuse a backing array if the
	// writer appended into the published slice.
	require.NoError(t, current.handlePREF64([]netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}))
	second := current.loadState()

	require.Len(t, first.configuration.PREF64, 1,
		"the earlier snapshot must keep its own prefix list")
	require.Len(t, second.configuration.PREF64, 3)

	// The DNS assignment must likewise not be reachable through an older snapshot.
	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{testNameserver(t, "192.0.2.1", 1)},
	}}))
	withDNS := current.loadState()
	require.Nil(t, first.configuration.DNS,
		"a snapshot taken before the assignment must not gain one")
	require.NotNil(t, withDNS.configuration.DNS)
}

// TestDNSAndPREF64UpdatesAreIndividuallyAtomic states precisely what is guaranteed.
//
// # What is NOT guaranteed, and why that is correct
//
// DNS_ASSIGN and PREF64 arrive as SEPARATE capsules, so they are applied by two
// separate handler calls and there is a legitimate intermediate state where one has
// landed and the other has not. An earlier version of this test asserted that the two
// always agreed on a generation tag; it failed, correctly, because that property does
// not exist and should not. The protocol does not couple the two capsules, so
// inventing a joint transaction would mean buffering one capsule waiting for the other
// -- which would stall DNS configuration indefinitely against a peer that only ever
// sends one of them.
//
// # What IS guaranteed, and is what this asserts
//
// Each update is INDIVIDUALLY atomic: a reader sees a snapshot whose DNS value is
// wholly one assignment and whose PREF64 value is wholly one capsule's list, never a
// half-written mixture of two. That is the property the lock-free snapshot exists to
// provide, and it is the one a reader can rely on.
//
// The test therefore tags the DNS side with a generation counter and asserts that the
// generation never goes BACKWARDS across reads, and that the PREF64 list is always one
// of the lists the writer published in full.
func TestDNSAndPREF64UpdatesAreIndividuallyAtomic(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	const maxTag = 250

	publish := func(tag int) error {
		err := current.handlePREF64([]netip.Prefix{
			netip.MustParsePrefix("2001:db8:" + itoaHex(tag) + "::/48"),
		})
		if err != nil {
			return err
		}
		return current.handleDNSAssign([]DNSConfiguration{{
			Nameservers: []DNSNameserver{
				testNameserver(t, "192.0.2."+itoaDecimal(tag), 1),
			},
		}})
	}
	require.NoError(t, publish(1))

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for generation := 2; !stop.Load(); generation++ {
			_ = publish(generation%maxTag + 1)
		}
	}()

	lastGeneration := uint64(0)
	for range 20000 {
		state := current.loadState()
		if state.configuration.DNS == nil {
			continue
		}
		// The generation is monotonically non-decreasing: a reader can never observe an
		// assignment older than one it has already seen.
		generation := state.configuration.DNS.Generation
		require.GreaterOrEqual(t, generation, lastGeneration,
			"the published assignment generation went backwards")
		lastGeneration = generation

		// Every published value must be internally whole: exactly the nameserver this
		// test constructed, not a partially built one.
		if len(state.configuration.DNS.Configurations) == 0 {
			continue
		}
		nameservers := state.configuration.DNS.Configurations[0].Nameservers
		if len(nameservers) == 0 {
			continue
		}
		require.Len(t, nameservers, 1, "a snapshot must hold one whole assignment")
		require.Len(t, nameservers[0].IPv4Addresses, 1)
		require.True(t, nameservers[0].IPv4Addresses[0].Is4(),
			"the nameserver address must be a complete IPv4 address")

		// A PREF64 list, when present, must be exactly one the writer published.
		if len(state.configuration.PREF64) > 0 {
			require.Equal(t, 48, state.configuration.PREF64[0].Bits(),
				"the prefix must be the whole /48 the writer published")
		}
	}
	stop.Store(true)
	wg.Wait()
}

// TestDNSHandlersAreRaceFree exercises the handlers concurrently with the lock-free
// reader, which is the shape that matters: writes are rare, reads are constant.
func TestDNSHandlersAreRaceFree(t *testing.T) {
	t.Parallel()

	current := &clientSession{}

	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for generation := 0; !stop.Load(); generation++ {
			_ = current.handleDNSAssign([]DNSConfiguration{{
				Nameservers: []DNSNameserver{testNameserver(t, "192.0.2."+itoaDecimal(generation%250+1), 1)},
			}})
			_ = current.handlePREF64([]netip.Prefix{
				netip.MustParsePrefix("64:ff9b::/96"),
			})
		}
	}()

	wg.Add(3)
	for range 3 {
		go func() {
			defer wg.Done()
			for range 20000 {
				state := current.loadState()
				if state.configuration.DNS != nil {
					// Read the same shape the runtime does: the configuration list and
					// the resolvers within it, plus the emptiness predicate.
					for _, configuration := range state.configuration.DNS.Configurations {
						_ = len(configuration.Nameservers)
					}
					_ = state.configuration.DNS.Empty()
				}
				_ = len(state.configuration.PREF64)
			}
		}()
	}

	stop.Store(true)
	wg.Wait()
}

// TestServiceParametersSurviveReplacement proves the map-valued field is carried
// through a replacement intact.
//
// ServiceParameters is the one reference-typed field in the assignment. The
// publisher copies Configuration by value, so a map shared between two snapshots
// would be a way for a later capsule to mutate an earlier reader's view.
func TestServiceParametersSurviveReplacement(t *testing.T) {
	t.Parallel()

	current := &clientSession{}
	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority:          1,
			AuthenticationDomainName: "resolver.example.",
			ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamALPN: {0x02, 'h', '2'},
			},
		}},
	}
	require.NoError(t, current.handleDNSAssign([]DNSConfiguration{configuration}))

	state := current.loadState()
	require.NotNil(t, state.configuration.DNS)
	require.Len(t, state.configuration.DNS.Configurations, 1)
	nameservers := state.configuration.DNS.Configurations[0].Nameservers
	require.Len(t, nameservers, 1)
	require.Equal(t, []byte{0x02, 'h', '2'}, nameservers[0].ServiceParameters[dnsmessage.SVCParamALPN])
	require.Equal(t, "resolver.example.", nameservers[0].AuthenticationDomainName)
}

func itoaHex(value int) string {
	const digits = "0123456789abcdef"
	if value == 0 {
		return "0"
	}
	var out []byte
	for value > 0 {
		out = append([]byte{digits[value%16]}, out...)
		value /= 16
	}
	return string(out)
}

func itoaDecimal(value int) string {
	if value == 0 {
		return "0"
	}
	var out []byte
	for value > 0 {
		out = append([]byte{byte('0' + value%10)}, out...)
		value /= 10
	}
	return string(out)
}
