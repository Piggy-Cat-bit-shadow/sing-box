package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A FakeIP server must never be the thing that answers a DESTINATION lookup, and this is the detector
// for the one path that let it.
//
// # Why the answer is not merely wrong but unusable
//
// A fakeip server does not resolve a name; it invents an address inside its own range and remembers the
// pair. That address means something only to this process - so a dialer that receives one dials a
// destination that either goes nowhere or is interpreted a second time by the same box. The reverse
// mapping that would identify it is deliberately kept free of fakeip answers
// (reverseMappingAnswersFrom, router.go:1621) for exactly this reason, and every other path that could
// put a fakeip server in front of a real address refuses it: the rule walk skips one when
// allowFakeIP is false, the transport manager refuses one as a default, and the evaluate action refuses
// it outright.
//
// `Router.Lookup`'s `options.Transport != nil` branch did not, and that branch is reached from
// production configuration: common/dialer's NewDNSQueryOptions sets Transport from
// `domain_resolver` on an outbound (dialer.go:107-112) or from route.default_domain_resolver
// (dialer.go:123-130).
//
// # What is asserted, and why the counting transport is the evidence
//
// The refusal is only trustworthy if the fakeip server was never ASKED - an error raised after the
// query would still have created the mapping and left the store holding a name it should not have. So
// the transport counts its own exchanges and the test requires zero.
func TestADestinationLookupRefusesAFakeIPResolver(t *testing.T) {
	counting := newFakeIPExchangeCounter(netip.MustParsePrefix("198.18.0.0/15"), "fakeip")

	real := &fakeDNSTransport{tag: "real", rcode: 0, address: netip.MustParseAddr("93.184.216.34")}
	router := &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{"fakeip": counting, "real": real},
			defaultTransport: real,
		},
	}
	router.policyStoreGuard.router = router
	router.client = NewClient(ClientOptions{
		Context:          context.Background(),
		Logger:           log.NewNOPFactory().Logger(),
		PolicyGeneration: router.policyEpoch,
		PolicyStoreGuard: &router.policyStoreGuard,
	})
	router.client.Start()

	addresses, err := router.Lookup(context.Background(), "leak.test", adapter.DNSQueryOptions{
		Transport: counting,
	})
	t.Logf("Lookup(leak.test, Transport=fakeip) -> %v, err=%v, exchanges=%d",
		addresses, err, counting.exchanges.Load())

	require.Error(t, err,
		"a fakeip server resolved a destination lookup: the address it invents is meaningful only "+
			"inside this process, and the caller dials what it is given")
	require.ErrorContains(t, err, "fakeip",
		"the refusal must name the server, or the operator cannot find the `domain_resolver` to change")
	require.Empty(t, addresses, "an address was returned alongside the refusal")
	require.Zero(t, counting.exchanges.Load(),
		"the fakeip server was still asked: it will have created the mapping, which is the state the "+
			"refusal exists to prevent")
	require.Zero(t, counting.issued.Load(), "the fixture never issued an address, so it proves nothing")

	// The positive control, and the reason this is not a blanket refusal: the ordinary path still
	// works, and the ordinary path is the one that must never reach a fakeip server for a destination.
	addresses, err = router.Lookup(context.Background(), "leak.test", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("93.184.216.34")}, addresses,
		"the unguarded path must keep answering from the real server")
	require.Positive(t, real.queryCount.Load(),
		"the unguarded path must have asked the real server rather than answering from nowhere")
	require.Zero(t, counting.exchanges.Load(),
		"the rule/default path consulted the fakeip server for a destination as well")
	require.Equal(t, C.DNSTypeFakeIP, counting.Type(), "the fixture must really report the fakeip type")
}

// fakeIPExchangeCounter is a DNSTransport that reports the fakeip type and counts both the questions
// put to it and the addresses it issued.
//
// It is a labelled double rather than the production dns/transport/fakeip.Transport, and that is forced
// rather than chosen: that package imports this one, so a test in this package cannot import it back.
// What the guard reads is the transport's declared TYPE and TAG, which this reproduces exactly, and the
// production transport is exercised by e2e/zz_d4_fakeip_probe_test.go, which builds a real box.
//
// A refusal that still asked the question would be no refusal at all, which is why the count is the
// evidence and the error alone is not.
type fakeIPExchangeCounter struct {
	TransportAdapter
	prefix    netip.Prefix
	exchanges atomic.Int32
	issued    atomic.Int32
}

func newFakeIPExchangeCounter(prefix netip.Prefix, tag string) *fakeIPExchangeCounter {
	return &fakeIPExchangeCounter{
		TransportAdapter: NewTransportAdapter(C.DNSTypeFakeIP, tag, nil),
		prefix:           prefix,
	}
}

func (c *fakeIPExchangeCounter) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (c *fakeIPExchangeCounter) Close() error { return nil }
func (c *fakeIPExchangeCounter) Reset()       {}

func (c *fakeIPExchangeCounter) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	c.exchanges.Add(1)
	question := message.Question[0]
	address := c.prefix.Addr().Next()
	c.issued.Add(1)
	return FixedResponse(message.Id, question, []netip.Addr{address}, C.DefaultDNSTTL), nil
}

func (c *fakeIPExchangeCounter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	response, err := c.Exchange(ctx, message)
	callback(response, err)
}
