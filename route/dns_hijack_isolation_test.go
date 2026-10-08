package route

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A hijacked DNS packet must not be able to hold the packet loop.
//
// # The failure mode
//
// Both tun stacks call the inbound's NewDNSPacket SYNCHRONOUSLY from the packet dispatcher:
// sing-tun's ForwardDispatcher calls hijackDNSPacket inline from the forward loop, and the
// gvisor stack calls it inline from the UDP forwarder. The chain from there
// (inbound -> Router.HijackDNSPacket -> DNS router -> adapter.DNSClient.ExchangeAsync) is only
// asynchronous in its DELIVERY: the enqueue itself blocks while the DNS transport is acquired
// and dialled.
//
// So a perfectly legal configuration - one DNS server with a detour to an outbound whose path
// silently drops packets - parks the packet loop for the full DNS timeout (C.DNSTimeout, 10s)
// on every unique query routed to it. Everything that shares that loop stops with it: other
// DNS servers, ICMP, packet forwarding and every new TCP flow. The symptom is the tunnel
// "alive but dead" (logs keep showing inbound DNS packets, nothing is ever answered) with no
// error logged anywhere, because nothing failed - it is all waiting.
//
// # What this test pins
//
// NewDNSPacket must return promptly while a DNS exchange is still in flight. The deadline is
// two orders of magnitude below the DNS timeout, so a regression to synchronous enqueue cannot
// pass by being slow.
func TestDNSPacketHijackDoesNotBlockPacketLoop(t *testing.T) {
	t.Parallel()

	stalled := newBlockingExchangeRouter()
	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		dns:    stalled,
	}

	// Synthetic DNS query for a name nothing else in the test depends on.
	query := new(dns.Msg)
	query.SetQuestion("stall.example.", dns.TypeA)
	payload, err := query.Pack()
	require.NoError(t, err)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		router.HijackDNSPacket(
			context.Background(),
			payload,
			discardingPacketWriter{},
			adapter.InboundContext{
				Inbound:     "tun-in",
				InboundType: "tun",
				Network:     "udp",
				Source:      M.ParseSocksaddr("10.0.0.2:41000"),
				Destination: M.ParseSocksaddr("1.1.1.1:53"),
			},
		)
	}()

	select {
	case <-returned:
	case <-time.After(300 * time.Millisecond):
		if stalled.calls.Load() > 0 {
			t.Fatal("hijacked DNS packet blocked the packet loop while the exchange was in flight; " +
				"the packet dispatcher stayed inside NewDNSPacket for the whole DNS timeout")
		}
		t.Fatal("hijacked DNS packet did not reach the DNS router within the deadline")
	}

	// The exchange itself is still outstanding by design: the packet loop returned without
	// waiting for it. Releasing it here is what lets the handler goroutine finish; the packet
	// is dropped on the floor either way.
	stalled.releaseStalled()
}

func TestDNSPacketHijackRejectsMalformedPayload(t *testing.T) {
	t.Parallel()

	stalled := newBlockingExchangeRouter()
	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		dns:    stalled,
	}

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		router.HijackDNSPacket(
			context.Background(),
			[]byte{0x00, 0x01, 0x02},
			discardingPacketWriter{},
			adapter.InboundContext{
				Network:     "udp",
				Source:      M.ParseSocksaddr("10.0.0.2:41000"),
				Destination: M.ParseSocksaddr("1.1.1.1:53"),
			},
		)
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("hijacked DNS packet with an unparsable payload did not return")
	}
	require.Zero(t, stalled.calls.Load(), "an unparsable DNS payload must not reach the DNS router")
}

// blockingExchangeRouter is a DNS router whose exchange never completes on its own.
//
// It models the real dead-detour case without a network: the dial is what takes the DNS
// timeout, and here the exchange simply blocks until the test releases it.
type blockingExchangeRouter struct {
	calls   atomic.Int64
	release chan struct{}
	once    sync.Once
}

func newBlockingExchangeRouter() *blockingExchangeRouter {
	return &blockingExchangeRouter{release: make(chan struct{})}
}

// releaseStalled unblocks every exchange this router has parked and is safe to call more than
// once, so a test can release the handler without knowing how many times it was entered.
func (r *blockingExchangeRouter) releaseStalled() {
	r.once.Do(func() {
		close(r.release)
	})
}

// ExchangeAsync blocks exactly the way a real transport does when its outbound is a black
// hole: the caller does not return until the dial gives up or the query is released. Modelling
// it with a goroutine would hide precisely the property under test.
func (r *blockingExchangeRouter) ExchangeAsync(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions, callback func(response *dns.Msg, err error)) {
	r.calls.Add(1)
	select {
	case <-r.release:
		callback(nil, E.New("stalled exchange released"))
	case <-ctx.Done():
		callback(nil, ctx.Err())
	}
}

func (r *blockingExchangeRouter) Exchange(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	r.ExchangeAsync(ctx, message, options, func(response *dns.Msg, err error) {
		_ = err
	})
	return nil, E.New("not used")
}

func (r *blockingExchangeRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, E.New("not used")
}

func (r *blockingExchangeRouter) ClearCache()   {}
func (r *blockingExchangeRouter) ResetNetwork() {}

func (r *blockingExchangeRouter) LookupReverseMapping(ip netip.Addr) (string, bool) {
	return "", false
}
func (r *blockingExchangeRouter) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (r *blockingExchangeRouter) Close() error { return nil }

type discardingPacketWriter struct{}

func (discardingPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

// The isolation must not be bought with unbounded growth.
//
// One goroutine per hijacked packet is the naive reading of "do not block the loop", and it is
// the same bug wearing different clothes: while the resolver is dead for its whole ten-second
// timeout, every arriving query parks a goroutine that does nothing. A bounded number of
// in-flight queries plus a dropped packet (which the client retries) is the invariant.
func TestDNSPacketHijackConcurrencyIsBounded(t *testing.T) {
	t.Parallel()

	// Mirrors the bound dnsHijackConcurrency asserts (256): the overflow calls below must be
	// refused, so the count may never exceed it. Kept as a literal because the constant is
	// private to the package and the test must fail if the bound is raised without thought.
	const maxInFlight = 256

	stalled := newBlockingExchangeRouter()
	defer stalled.releaseStalled()
	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		dns:    stalled,
	}

	query := new(dns.Msg)
	query.SetQuestion("flood.example.", dns.TypeA)
	payload, err := query.Pack()
	require.NoError(t, err)

	metadata := adapter.InboundContext{
		Inbound:     "tun-in",
		InboundType: "tun",
		Network:     "udp",
		Source:      M.ParseSocksaddr("10.0.0.2:41000"),
		Destination: M.ParseSocksaddr("1.1.1.1:53"),
	}

	// Twice the bound: if the cap is not enforced, in-flight reaches 2x and the assertion
	// below reports it instead of the process growing without limit.
	const attempts = maxInFlight * 2
	for i := 0; i < attempts; i++ {
		router.HijackDNSPacket(context.Background(), payload, discardingPacketWriter{}, metadata)
	}

	require.Eventually(t, func() bool {
		return router.dnsHijackInFlight.Load() == maxInFlight
	}, 2*time.Second, 5*time.Millisecond,
		"in-flight hijacked DNS queries must saturate at the bound, not grow with the packet rate")

	require.LessOrEqual(t, stalled.calls.Load(), int64(maxInFlight),
		"packets over the bound must be dropped before they reach the DNS router")
}
