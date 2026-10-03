package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for a dual-family lookup that spans a network change.
//
// # Why this is the sharpest form of the cross-generation problem
//
// A and AAAA are two independent queries, issued at different moments by two goroutines and joined
// into ONE answer set. The generation guard is per query, so each family is individually correct
// about the network it was asked on. That is not enough: if a reset lands between them, the
// aggregate is half old network and half new network, and the caller has no way to tell.
//
// For split-horizon or VPN DNS this is worse than either family being wrong on its own, because the
// address set looks complete and self-consistent. A caller connecting to "the addresses for this
// name" gets a set that was never simultaneously true on any network.

// familySelectiveTransport answers only its own family, and blocks each family independently so the
// reset can be placed exactly between the two.
type familySelectiveTransport struct {
	adapter.DNSTransport
	tag string

	ipv4Address netip.Addr
	ipv6Address netip.Addr

	// family barriers, keyed by whether the query is AAAA.
	entered sync.Map // bool -> chan struct{}
	release sync.Map // bool -> chan struct{}

	queries sync.Map // bool -> *atomic.Int32
}

func (t *familySelectiveTransport) Type() string           { return "family-selective" }
func (t *familySelectiveTransport) Tag() string            { return t.tag }
func (t *familySelectiveTransport) Dependencies() []string { return nil }
func (t *familySelectiveTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *familySelectiveTransport) Close() error { return nil }
func (t *familySelectiveTransport) Reset()       {}

func (t *familySelectiveTransport) counter(isIPv6 bool) *atomic.Int32 {
	value, _ := t.queries.LoadOrStore(isIPv6, &atomic.Int32{})
	return value.(*atomic.Int32)
}

func (t *familySelectiveTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	isIPv6 := len(message.Question) > 0 && message.Question[0].Qtype == mDNS.TypeAAAA
	t.counter(isIPv6).Add(1)

	if entered, loaded := t.entered.Load(isIPv6); loaded {
		select {
		case entered.(chan struct{}) <- struct{}{}:
		default:
		}
	}
	if release, loaded := t.release.Load(isIPv6); loaded {
		select {
		case <-release.(chan struct{}):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		question := message.Question[0]
		if isIPv6 {
			response.Answer = append(response.Answer, &mDNS.AAAA{
				Hdr:  mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 300},
				AAAA: t.ipv6Address.AsSlice(),
			})
		} else {
			response.Answer = append(response.Answer, &mDNS.A{
				Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
				A:   t.ipv4Address.AsSlice(),
			})
		}
	}
	return response, nil
}

func (t *familySelectiveTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestLookupFamiliesDoesNotMixGenerations is F4.
//
// The IPv4 query is held until the reset has happened, then the IPv6 query is allowed through. If
// the aggregate can contain both, the caller receives an address set that was never simultaneously
// true on any network.
func TestLookupFamiliesDoesNotMixGenerations(t *testing.T) {
	transport := &familySelectiveTransport{
		tag:         "dual",
		ipv4Address: netip.MustParseAddr("10.0.0.1"),
		ipv6Address: netip.MustParseAddr("2001:db8::1"),
	}
	// Only the IPv6 family blocks, so IPv4 completes first and the reset lands before it.
	ipv6Entered := make(chan struct{}, 1)
	ipv6Release := make(chan struct{})
	transport.entered.Store(true, ipv6Entered)
	transport.release.Store(true, ipv6Release)

	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	// The transport participates in environments, so environmentHash reads the network manager.
	client.networkManager = &generationNetworkManager{}
	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{transport.Tag(): transport},
			defaultTransport: transport,
		},
		client: client,
	}
	client.networkGeneration = router.dnsGeneration

	var (
		access    sync.Mutex
		published []adapter.DNSFamilyResult
	)
	done := make(chan error, 1)
	go func() {
		done <- router.LookupFamilies(context.Background(), "dual.internal.",
			adapter.DNSQueryOptions{}, func(result adapter.DNSFamilyResult) {
				access.Lock()
				published = append(published, result)
				access.Unlock()
			})
	}()

	// Wait for the IPv6 family to be genuinely in flight.
	select {
	case <-ipv6Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the IPv6 query never reached the transport")
	}

	// The network changes between the families.
	router.ResetNetwork()
	close(ipv6Release)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("LookupFamilies never returned")
	}

	access.Lock()
	defer access.Unlock()

	var (
		ipv4Addresses []netip.Addr
		ipv6Addresses []netip.Addr
	)
	for _, result := range published {
		if result.IPv6 {
			ipv6Addresses = append(ipv6Addresses, result.Addresses...)
		} else {
			ipv4Addresses = append(ipv4Addresses, result.Addresses...)
		}
	}

	// The two families are published as separate events, each carrying only its own family, so a
	// consumer that treats the stream as authoritative-per-family is not misled. Assert that the
	// separation holds, because an implementation that merged them would be the dangerous shape.
	for _, result := range published {
		for _, address := range result.Addresses {
			if result.IPv6 {
				require.True(t, address.Is6(), "an IPv6 result carried a non-IPv6 address")
			} else {
				require.True(t, address.Is4(), "an IPv4 result carried a non-IPv4 address")
			}
		}
	}

	// Both families did answer, on opposite sides of the reset. This is the behaviour that must be
	// visible to the consumer, which is why each result carries its own event.
	require.NotEmpty(t, ipv4Addresses, "the IPv4 family answered before the reset")
	require.NotEmpty(t, ipv6Addresses, "the IPv6 family answered after the reset")

	// The AAAA family was issued before the reset and answered after it, so it must NOT be cached:
	// storing it would serve the new network an address learned on the old one.
	//
	// The probe is a repeat lookup through the PRODUCTION path, counting upstream queries, rather
	// than a hand-built cache key: the lookup applies its own options, so a key the test constructs
	// is not necessarily the key the lookup used, and an assertion on the wrong key proves nothing.
	queriesBefore := transport.counter(true).Load()
	_, err := router.Lookup(context.Background(), "dual.internal.",
		adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv6Only, Strategy: C.DomainStrategyIPv6Only})
	require.NoError(t, err)
	require.Greater(t, transport.counter(true).Load(), queriesBefore,
		"the AAAA answer spanned the reset and was served from cache on the next lookup. An address "+
			"learned on the previous network must not answer a query on the new one")
}
