package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Item 3: a dual-family lookup must not merge the two generations into one address set.
//
// # What "merge" would mean, and why it is checked here rather than assumed
//
// LookupFamilies issues A and AAAA as independent queries from independent goroutines, so a network
// change can land between them and the two answers can genuinely come from different networks. That
// is unavoidable for an incremental API.
//
// The dangerous shape is a caller receiving them as ONE set: "here are the addresses for this name",
// half from the network that was left and half from the network that is current, self-consistent
// looking and true on neither. The safe shape is each family arriving as its own event, so the
// consumer treats them as candidate arrivals and an address from a superseded network simply loses a
// connection race.
//
// This test pins the safe shape by driving a reset between the families and asserting the events stay
// separated - each carries only its own family - while the reset itself writes no cache.

// gatedFamilyTransport answers each family from a barrier the test controls.
type gatedFamilyTransport struct {
	adapter.DNSTransport
	tag string

	ipv4Address netip.Addr
	ipv6Address netip.Addr

	ipv6Entered chan struct{}
	ipv6Release chan struct{}
	once        sync.Once
}

func (t *gatedFamilyTransport) Type() string           { return "gated-family" }
func (t *gatedFamilyTransport) Tag() string            { return t.tag }
func (t *gatedFamilyTransport) Dependencies() []string { return nil }
func (t *gatedFamilyTransport) Environment() []string  { return []string{"wifi"} }
func (t *gatedFamilyTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *gatedFamilyTransport) Close() error { return nil }
func (t *gatedFamilyTransport) Reset()       {}

func (t *gatedFamilyTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	response := new(mDNS.Msg)
	response.SetReply(message)
	if len(message.Question) == 0 {
		return response, nil
	}
	question := message.Question[0]
	if question.Qtype == mDNS.TypeAAAA {
		t.once.Do(func() { close(t.ipv6Entered) })
		select {
		case <-t.ipv6Release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		response.Answer = append(response.Answer, &mDNS.AAAA{
			Hdr:  mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 300},
			AAAA: t.ipv6Address.AsSlice(),
		})
		return response, nil
	}
	response.Answer = append(response.Answer, &mDNS.A{
		Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
		A:   t.ipv4Address.AsSlice(),
	})
	return response, nil
}

func (t *gatedFamilyTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestLookupFamiliesNeverMergesGenerations is item 3.
func TestLookupFamiliesNeverMergesGenerations(t *testing.T) {
	transport := &gatedFamilyTransport{
		tag:         "gated-family",
		ipv4Address: netip.MustParseAddr("10.0.0.1"),
		ipv6Address: netip.MustParseAddr("2001:db8::1"),
		ipv6Entered: make(chan struct{}),
		ipv6Release: make(chan struct{}),
	}

	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
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
		done <- router.LookupFamilies(context.Background(), "split.internal.",
			adapter.DNSQueryOptions{}, func(result adapter.DNSFamilyResult) {
				access.Lock()
				published = append(published, result)
				access.Unlock()
			})
	}()

	// Barrier: the AAAA query is in flight, so the A family has already been answered.
	select {
	case <-transport.ipv6Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the AAAA query never reached the transport")
	}

	// The network changes between the two families, which is the interleaving that makes the two
	// answers come from different networks.
	router.ResetNetwork()
	close(transport.ipv6Release)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("LookupFamilies never returned")
	}

	access.Lock()
	defer access.Unlock()

	require.Len(t, published, 2,
		"each family must be published as its own event. A single combined event is the shape that "+
			"cannot express that its two halves came from different networks")

	// Each event carries only its own family: no event is a union, so a consumer can never receive
	// an address set that mixes the two networks.
	var ipv4Events, ipv6Events int
	for _, result := range published {
		for _, address := range result.Addresses {
			if result.IPv6 {
				require.True(t, address.Is6() || address.Is4In6(),
					"an event marked IPv6 carried %s, which is not an IPv6 address", address)
			} else {
				require.True(t, address.Is4(),
					"an event marked IPv4 carried %s, which is not an IPv4 address", address)
			}
		}
		if result.IPv6 {
			ipv6Events++
		} else {
			ipv4Events++
		}
	}
	require.Equal(t, 1, ipv4Events, "exactly one IPv4 event")
	require.Equal(t, 1, ipv6Events, "exactly one IPv6 event")

	// The two families straddled the reset, which is the condition under test.
	require.EqualValues(t, 1, router.dnsGeneration(),
		"the reset must have happened between the families, or this test proves nothing")
}
