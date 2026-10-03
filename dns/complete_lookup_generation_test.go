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

// Whether one COMPLETE lookup can be assembled from two different network generations.
//
// # Why this is a different contract from the streaming API
//
// LookupFamilies publishes each family as it arrives, so a consumer treats the events as separate
// observations and a family from a superseded network simply loses a connection race.
//
// A complete Lookup is the opposite: it runs both families, waits for BOTH, and returns them as ONE
// address set. The caller receives a single result that claims to be the addresses for the name. If
// the A half came from the network that was left and the AAAA half from the network that is current,
// that set was never true on any network - and it looks entirely self-consistent.
//
// # Why the generations can differ
//
// Each family is its own goroutine calling its own Exchange, and each captures the generation when
// ITS request is issued. Nothing ties the two to a shared epoch, so a reset landing between them
// splits them.

// familyPhaseTransport blocks the AAAA family before its exchange and the A family inside it, so the
// test can order the two captures precisely.
type familyPhaseTransport struct {
	adapter.DNSTransport
	tag string

	ipv4Address netip.Addr
	ipv6Address netip.Addr

	// ipv4Entered fires once the A query is inside the transport.
	ipv4Entered chan struct{}
	// ipv6Gate holds the AAAA family before it reaches the transport.
	ipv6Gate chan struct{}

	once sync.Once
}

func (t *familyPhaseTransport) Type() string           { return "family-phase" }
func (t *familyPhaseTransport) Tag() string            { return t.tag }
func (t *familyPhaseTransport) Dependencies() []string { return nil }
func (t *familyPhaseTransport) Environment() []string  { return []string{"wifi"} }
func (t *familyPhaseTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *familyPhaseTransport) Close() error { return nil }
func (t *familyPhaseTransport) Reset()       {}

func (t *familyPhaseTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) == 0 {
		return new(mDNS.Msg), nil
	}
	question := message.Question[0]

	if question.Qtype == mDNS.TypeA {
		// The A family is the one that completes first, on the old generation.
		t.once.Do(func() { close(t.ipv4Entered) })
	} else {
		// The AAAA family waits here, before its exchange begins.
		select {
		case <-t.ipv6Gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	if question.Qtype == mDNS.TypeAAAA {
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
	return response, nil
}

func (t *familyPhaseTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

// TestCompleteLookupDoesNotMixNetworkGenerations is B1.
//
// The A family is allowed to complete on generation G1; the AAAA family is held until after a reset
// has advanced to G2. The complete lookup must not return the two as one address set.
func TestCompleteLookupDoesNotMixNetworkGenerations(t *testing.T) {
	transport := &familyPhaseTransport{
		tag:         "family-phase",
		ipv4Address: netip.MustParseAddr("10.0.0.1"),
		ipv6Address: netip.MustParseAddr("2001:db8::1"),
		ipv4Entered: make(chan struct{}),
		ipv6Gate:    make(chan struct{}),
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
	// The client reads the ROUTER's generation, which is what ResetNetwork advances. Wiring the
	// client to a private counter would let the test advance one and the router read the other, so
	// the guard under test would never see the change.
	client.networkGeneration = router.dnsGeneration

	type lookupOutcome struct {
		addresses []netip.Addr
		err       error
	}
	done := make(chan lookupOutcome, 1)
	go func() {
		addresses, err := router.Lookup(context.Background(), "split.internal.",
			adapter.DNSQueryOptions{})
		done <- lookupOutcome{addresses, err}
	}()

	// Barrier: the A family is inside its exchange, on generation G1.
	select {
	case <-transport.ipv4Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the A family never reached the transport")
	}

	// The network changes while AAAA is still held before its exchange. This is the production
	// reset, so the router's generation is what advances.
	router.ResetNetwork()

	close(transport.ipv6Gate)

	var received lookupOutcome
	select {
	case received = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup never returned")
	}

	// The lookup spanned a reset, so it must not present the two families as one answer set.
	require.Error(t, received.err,
		"a COMPLETE lookup returned a single address set assembled from two different network "+
			"generations: the A family answered on the old epoch and the AAAA family on the new one. "+
			"That set was never simultaneously true on any network, and nothing in the result "+
			"distinguishes the halves, so the caller cannot tell it is half-stale")
	require.Nil(t, received.addresses,
		"and no partial address set may be returned alongside the error")
	require.Contains(t, received.err.Error(), "different networks",
		"the error must say what happened rather than surfacing as a generic lookup failure")
}

// TestCompleteLookupOnOneGenerationReturnsBothFamilies is the control.
//
// With no reset the complete lookup must still return both families, so the epoch check has not
// simply disabled dual-family resolution.
func TestCompleteLookupOnOneGenerationReturnsBothFamilies(t *testing.T) {
	transport := &familyPhaseTransport{
		tag:         "family-phase-control",
		ipv4Address: netip.MustParseAddr("10.0.0.1"),
		ipv6Address: netip.MustParseAddr("2001:db8::1"),
		ipv4Entered: make(chan struct{}),
		ipv6Gate:    make(chan struct{}),
	}
	// The AAAA family is never held.
	close(transport.ipv6Gate)

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

	addresses, err := router.Lookup(context.Background(), "control.internal.",
		adapter.DNSQueryOptions{})
	require.NoError(t, err, "with no network change the complete lookup must succeed")

	var hasIPv4, hasIPv6 bool
	for _, address := range addresses {
		if address.Is4() {
			hasIPv4 = true
		}
		if address.Is6() {
			hasIPv6 = true
		}
	}
	require.True(t, hasIPv4 && hasIPv6,
		"both families must still be returned, or the epoch check has broken dual-family resolution "+
			"rather than protecting it")
}
