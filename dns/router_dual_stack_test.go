package dns

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for the incremental family lookup's own contract (§13, §49).
//
// These exercise the publishing logic and the strict-strategy short circuit. The exchange
// itself is Router.Lookup, which the existing DNS suites already cover - re-testing rule
// evaluation and caching here would duplicate that coverage without adding confidence.

func TestLookupFamiliesRejectsNilPublisher(t *testing.T) {
	// A nil publisher would silently discard every result, so it is refused rather than
	// tolerated.
	router := &Router{}
	err := router.LookupFamilies(context.Background(), "example.test.", adapter.DNSQueryOptions{}, nil)
	require.Error(t, err)
}

func TestLookupFamiliesPublishesAsFamiliesComplete(t *testing.T) {
	// Drives the REAL Router.LookupFamilies. A Router with just a client and a logger is
	// enough, because the no-rule path goes straight to the client with the strategy forced -
	// which is exactly the code under test.
	transport := &familySchedulingTransport{
		delayA:      0,
		delayAAAA:   80 * time.Millisecond,
		addressA:    "192.0.2.1",
		addressAAAA: "2001:db8::1",
	}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	router := &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		client: client,
	}

	type arrival struct {
		ipv6      bool
		addresses int
		at        time.Duration
	}
	var (
		access   sync.Mutex
		arrivals []arrival
	)
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := router.LookupFamilies(ctx, "example.test.", adapter.DNSQueryOptions{
		Transport: transport,
		Strategy:  C.DomainStrategyPreferIPv6,
	}, func(result adapter.DNSFamilyResult) {
		access.Lock()
		arrivals = append(arrivals, arrival{ipv6: result.IPv6, addresses: len(result.Addresses), at: time.Since(start)})
		access.Unlock()
	})
	require.NoError(t, err)

	access.Lock()
	defer access.Unlock()
	require.Len(t, arrivals, 2, "both families must be published")
	require.False(t, arrivals[0].ipv6, "the fast family must be published first")
	require.Less(t, arrivals[0].at, 80*time.Millisecond,
		"the fast family must not be held back by its slower sibling")
	require.Greater(t, arrivals[0].addresses, 0)
}

func TestLookupFamiliesStrictStrategyIssuesOneQuery(t *testing.T) {
	// A strict strategy must issue exactly one family's query, through the real path.
	for _, testCase := range []struct {
		name     string
		strategy C.DomainStrategy
		ipv6     bool
	}{
		{"ipv4_only", C.DomainStrategyIPv4Only, false},
		{"ipv6_only", C.DomainStrategyIPv6Only, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			}
			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()
			router := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), client: client}

			var published []adapter.DNSFamilyResult
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := router.LookupFamilies(ctx, "example.test.", adapter.DNSQueryOptions{
				Transport: transport,
				Strategy:  testCase.strategy,
			}, func(result adapter.DNSFamilyResult) {
				published = append(published, result)
			})
			require.NoError(t, err)
			require.Len(t, published, 1, "a strict strategy must publish exactly one family")
			require.Equal(t, testCase.ipv6, published[0].IPv6)
			require.EqualValues(t, 1, transport.queryCount.Load(),
				"a strict strategy must issue only its own family's query")
		})
	}
}

// TestStrictRouterDefaultIssuesOneFamily is Group A §15.
//
// The caller passes AsIS. The router's configured default is a strict single-family strategy. The
// effective policy is therefore that strict strategy, and the forbidden family's query must never
// be emitted - not merely filtered out afterwards.
//
// # The defect this pins
//
// LookupFamilies resolved the effective strategy and used it to CHOOSE the strict branch, but then
// called r.Lookup with the caller's RAW options. Client.Lookup reads options.Strategy to decide
// which family to query, and the raw value was still AsIS, so the branch that was supposed to
// issue one family issued... whichever family Client.Lookup defaults to. The policy that selected
// the branch never reached the code that acts on it.
func TestStrictRouterDefaultIssuesOneFamily(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		routerDefault    C.DomainStrategy
		forbidden        uint16
		expectedStrategy C.DomainStrategy
	}{
		{"router default ipv4_only", C.DomainStrategyIPv4Only, mDNS.TypeAAAA, C.DomainStrategyIPv4Only},
		{"router default ipv6_only", C.DomainStrategyIPv6Only, mDNS.TypeA, C.DomainStrategyIPv6Only},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			}
			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()
			router := &Router{
				ctx:                   context.Background(),
				logger:                log.NewNOPFactory().Logger(),
				client:                client,
				defaultDomainStrategy: testCase.routerDefault,
			}

			var published []adapter.DNSFamilyResult
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// AsIS: the caller expresses no preference, so the router's default decides.
			err := router.LookupFamilies(ctx, "example.test.", adapter.DNSQueryOptions{
				Transport: transport,
				Strategy:  C.DomainStrategyAsIS,
			}, func(result adapter.DNSFamilyResult) {
				published = append(published, result)
			})
			require.NoError(t, err)

			for _, questionType := range transport.observedTypes() {
				require.NotEqual(t, testCase.forbidden, questionType,
					"the router default is a strict single-family strategy, so the forbidden "+
						"family's query must never be issued; it was")
			}

			require.Len(t, published, 1, "a strict strategy reports exactly one family result")
			require.Equal(t, testCase.expectedStrategy, published[0].EffectiveStrategy,
				"the reported effective strategy must be the router default that actually applied, "+
					"not the caller's AsIS")
		})
	}
}

// TestStrictRouterDefaultDoesNotEmitForbiddenFamilyThroughLookup is the Client.Lookup half of the
// same contract, driven directly.
func TestStrictRouterDefaultDoesNotEmitForbiddenFamilyThroughLookup(t *testing.T) {
	transport := &familySchedulingTransport{
		addressA:    "192.0.2.1",
		addressAAAA: "2001:db8::1",
	}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// AsIS with the router default applied, exactly as finalizeExchangeOptions would.
	_, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{
		Strategy: C.DomainStrategyIPv4Only,
	}, func(response *mDNS.Msg) bool { return response.Rcode == mDNS.RcodeSuccess })
	require.NoError(t, err)

	for _, questionType := range transport.observedTypes() {
		require.NotEqual(t, mDNS.TypeAAAA, questionType,
			"ipv4_only must not emit an AAAA query")
	}
}
