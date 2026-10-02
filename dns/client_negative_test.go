package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/atomic"
)

// Tests for QNAME-wide NXDOMAIN negative caching.
//
// The behaviour under test is a query COUNT, not a cache hit: the whole point is
// that a name established as non-existent costs one upstream query rather than one
// per record type. Each test therefore asserts against the transport's exchange
// counter, because a test that only checked "the second call returned NXDOMAIN"
// would pass even if the cache did nothing and the upstream was asked again.

// negativeTransport answers with whatever the test scripted and counts exchanges.
type negativeTransport struct {
	queryCount atomic.Int32

	// respond builds the reply. It receives the request so a test can vary the
	// answer by qtype, which is how the NODATA-versus-NXDOMAIN distinction is
	// exercised.
	respond func(request *mDNS.Msg) *mDNS.Msg

	// err, when set, makes every exchange fail.
	err error

	// tag identifies the transport in the cache key. Two transports with the same
	// tag deliberately share a namespace, so a test that wants to prove namespaces
	// are separate must give them different tags.
	tag string
}

func (t *negativeTransport) Start(stage adapter.StartStage) error { return nil }
func (t *negativeTransport) Close() error                         { return nil }
func (t *negativeTransport) Type() string                         { return "negative" }
func (t *negativeTransport) Tag() string {
	if t.tag != "" {
		return t.tag
	}
	return "negative"
}
func (t *negativeTransport) Dependencies() []string { return nil }
func (t *negativeTransport) Reset()                 {}

func (t *negativeTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	if t.err != nil {
		return nil, t.err
	}
	return t.respond(message), nil
}

func (t *negativeTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func (t *negativeTransport) count() int { return int(t.queryCount.Load()) }

// soaAuthority builds the SOA record RFC 2308 requires for a cacheable negative
// answer. The TTL the client should honour is min(header TTL, MINIMUM).
func soaAuthority(name string, headerTTL, minimum uint32) mDNS.RR {
	return &mDNS.SOA{
		Hdr:     mDNS.RR_Header{Name: name, Rrtype: mDNS.TypeSOA, Class: mDNS.ClassINET, Ttl: headerTTL},
		Ns:      "ns.example.org.",
		Mbox:    "hostmaster.example.org.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minimum,
	}
}

// nxdomainResponse builds a proper NXDOMAIN with a SOA, which is the only shape the
// name cache is allowed to widen.
func nxdomainResponse(request *mDNS.Msg, headerTTL, minimum uint32) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(request)
	response.Rcode = mDNS.RcodeNameError
	response.Ns = []mDNS.RR{soaAuthority("example.org.", headerTTL, minimum)}
	return response
}

// noDataResponse is NOERROR with an empty answer: the name exists, this type does
// not. It must never be widened to the name.
func noDataResponse(request *mDNS.Msg) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(request)
	response.Rcode = mDNS.RcodeSuccess
	response.Ns = []mDNS.RR{soaAuthority("example.org.", 300, 300)}
	return response
}

func negativeQuery(name string, qtype uint16) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{Id: 1, RecursionDesired: true},
		Question: []mDNS.Question{{
			Name:   name,
			Qtype:  qtype,
			Qclass: mDNS.ClassINET,
		}},
	}
}

func newNegativeClient(t *testing.T, transport *negativeTransport) *Client {
	t.Helper()
	return NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
}

// exchange runs one query through the same entry point the router uses.
func exchange(t *testing.T, client *Client, transport *negativeTransport, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.Helper()
	return client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
}

// --- the core behaviour -------------------------------------------------------

func TestNXDomain_OneUpstreamQueryPerName(t *testing.T) {
	// The headline case: four record types, one query.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	types := []uint16{mDNS.TypeA, mDNS.TypeAAAA, mDNS.TypeHTTPS, mDNS.TypeSVCB}
	for index, qtype := range types {
		message := negativeQuery("ads.example.", qtype)
		response, err := exchange(t, client, transport, message)
		if err != nil {
			t.Fatalf("query %d (type %d): %v", index, qtype, err)
		}
		if response.Rcode != mDNS.RcodeNameError {
			t.Fatalf("query %d (type %d): want NXDOMAIN, got %s", index, qtype, mDNS.RcodeToString[response.Rcode])
		}
	}

	if got := transport.count(); got != 1 {
		t.Fatalf("upstream exchanges: want 1 for four record types of one name, got %d", got)
	}
}

func TestNXDomain_AnsweredForEachTypeSeparately(t *testing.T) {
	// The reply must be built for the question actually asked. Replaying the first
	// A question to an AAAA query is a protocol error, and a resolver is entitled to
	// throw it away.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	first := negativeQuery("ads.example.", mDNS.TypeA)
	first.Id = 1111
	if _, err := exchange(t, client, transport, first); err != nil {
		t.Fatal(err)
	}

	second := negativeQuery("ads.example.", mDNS.TypeAAAA)
	second.Id = 2222
	response, err := exchange(t, client, transport, second)
	if err != nil {
		t.Fatal(err)
	}

	if response.Id != 2222 {
		t.Errorf("response id: want 2222 (the current request), got %d", response.Id)
	}
	if len(response.Question) != 1 {
		t.Fatalf("want exactly one question, got %d", len(response.Question))
	}
	if response.Question[0].Qtype != mDNS.TypeAAAA {
		t.Errorf("question type: want AAAA, got %d", response.Question[0].Qtype)
	}
	if response.Question[0].Name != "ads.example." {
		t.Errorf("question name: want ads.example., got %s", response.Question[0].Name)
	}
	if response.Rcode != mDNS.RcodeNameError {
		t.Errorf("rcode: want NXDOMAIN, got %s", mDNS.RcodeToString[response.Rcode])
	}
	if len(response.Ns) == 0 {
		t.Error("a cached NXDOMAIN must still carry its SOA authority")
	}
}

func TestNXDomain_CaseInsensitiveName(t *testing.T) {
	// DNS names are case-insensitive, so a different case is the same name and must
	// not cost another query.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("Ads.Example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	response, err := exchange(t, client, transport, negativeQuery("aDs.eXaMpLe.", mDNS.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if response.Rcode != mDNS.RcodeNameError {
		t.Fatal("want NXDOMAIN for the differently-cased name")
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("case difference must not cost a query: want 1, got %d", got)
	}
}

// --- what must NOT be cached name-wide ---------------------------------------

func TestNXDomain_NoDataIsNotNameWide(t *testing.T) {
	// NOERROR with an empty answer means this TYPE is absent, not the name. Widening
	// it would break every other type on a name that exists.
	transport := &negativeTransport{respond: noDataResponse}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("present.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("present.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}

	if got := transport.count(); got != 2 {
		t.Fatalf("NODATA must not answer other types: want 2 exchanges, got %d", got)
	}
}

func TestNXDomain_WithoutSOAIsNotCached(t *testing.T) {
	// No SOA means no RFC 2308 TTL, so there is no basis for holding the verdict.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		response := new(mDNS.Msg)
		response.SetReply(request)
		response.Rcode = mDNS.RcodeNameError
		return response // no SOA
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("nosoa.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("nosoa.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("an NXDOMAIN without SOA must not be cached: want 2 exchanges, got %d", got)
	}
}

func TestNXDomain_ErrorRcodesAreNotCached(t *testing.T) {
	// SERVFAIL and REFUSED say nothing about whether the name exists. Caching them
	// name-wide would turn a transient upstream fault into an outage for every type.
	for _, rcode := range []int{mDNS.RcodeServerFailure, mDNS.RcodeRefused, mDNS.RcodeFormatError} {
		t.Run(mDNS.RcodeToString[rcode], func(t *testing.T) {
			transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
				response := new(mDNS.Msg)
				response.SetReply(request)
				response.Rcode = rcode
				response.Ns = []mDNS.RR{soaAuthority("example.org.", 300, 300)}
				return response
			}}
			client := newNegativeClient(t, transport)

			_, _ = exchange(t, client, transport, negativeQuery("fault.example.", mDNS.TypeA))
			_, _ = exchange(t, client, transport, negativeQuery("fault.example.", mDNS.TypeAAAA))

			if got := transport.count(); got != 2 {
				t.Fatalf("%s must not be cached name-wide: want 2 exchanges, got %d",
					mDNS.RcodeToString[rcode], got)
			}
		})
	}
}

func TestNXDomain_TransportErrorIsNotCached(t *testing.T) {
	transport := &negativeTransport{err: context.DeadlineExceeded}
	client := newNegativeClient(t, transport)

	_, _ = exchange(t, client, transport, negativeQuery("timeout.example.", mDNS.TypeA))
	_, _ = exchange(t, client, transport, negativeQuery("timeout.example.", mDNS.TypeAAAA))

	if got := transport.count(); got != 2 {
		t.Fatalf("a transport error must not be cached: want 2 exchanges, got %d", got)
	}
}

// --- TTL ----------------------------------------------------------------------

func TestNXDomain_ExpiresAndQueriesAgain(t *testing.T) {
	// The verdict must lapse. A short SOA TTL is used so the test does not sleep long.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 1, 1) // min(1,1) = 1 second
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("short.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	// Immediately: served from the cache.
	if _, err := exchange(t, client, transport, negativeQuery("short.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("before expiry: want 1 exchange, got %d", got)
	}

	time.Sleep(1100 * time.Millisecond)

	if _, err := exchange(t, client, transport, negativeQuery("short.example.", mDNS.TypeHTTPS)); err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("after expiry the upstream must be asked again: want 2 exchanges, got %d", got)
	}
}

func TestNXDomain_UsesMinimumOfSOATTLAndMinimum(t *testing.T) {
	// RFC 2308: the negative TTL is min(SOA header TTL, SOA MINIMUM). With a header
	// TTL of 1 and MINIMUM of 3600 the verdict must lapse after roughly a second, not
	// an hour.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 1, 3600)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("min.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := exchange(t, client, transport, negativeQuery("min.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("want the shorter of TTL and MINIMUM: want 2 exchanges, got %d", got)
	}
}

// --- namespace scoping --------------------------------------------------------

func TestNXDomain_DifferentTransportDoesNotShare(t *testing.T) {
	// Two servers can disagree about a name. A verdict from one must not answer the
	// other.
	first := &negativeTransport{tag: "server-a", respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	second := &negativeTransport{tag: "server-b", respond: func(request *mDNS.Msg) *mDNS.Msg {
		response := new(mDNS.Msg)
		response.SetReply(request)
		response.Rcode = mDNS.RcodeSuccess
		response.Answer = []mDNS.RR{&mDNS.A{
			Hdr: mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		}}
		return response
	}}
	client := newNegativeClient(t, first)

	if _, err := exchange(t, client, first, negativeQuery("split.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	response, err := exchange(t, client, second, negativeQuery("split.example.", mDNS.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if response.Rcode == mDNS.RcodeNameError {
		t.Fatal("a verdict from one transport must not answer another")
	}
	if got := second.count(); got != 1 {
		t.Fatalf("the second transport must be asked: want 1, got %d", got)
	}
}

func TestNXDomain_DisableCacheIsHonoured(t *testing.T) {
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := NewClient(ClientOptions{
		Context:      context.Background(),
		Logger:       log.NewNOPFactory().Logger(),
		DisableCache: true,
	})

	if _, err := exchange(t, client, transport, negativeQuery("nocache.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("nocache.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != 2 {
		t.Fatalf("disable_cache must disable the negative cache too: want 2 exchanges, got %d", got)
	}
}

func TestNXDomain_PositiveEntrySurvives(t *testing.T) {
	// A positive answer already in the exact cache must keep being served. The
	// negative cache sits behind it and must not shadow it.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return FixedResponse(request.Id, request.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.9")}, 300)
	}}
	client := newNegativeClient(t, transport)

	first, err := exchange(t, client, transport, negativeQuery("present.example.", mDNS.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Answer) == 0 {
		t.Fatal("expected a positive answer")
	}
	second, err := exchange(t, client, transport, negativeQuery("present.example.", mDNS.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if second.Rcode != mDNS.RcodeSuccess || len(second.Answer) == 0 {
		t.Fatal("the positive answer must still be served from the exact cache")
	}
	if got := transport.count(); got != 1 {
		t.Fatalf("want 1 exchange, got %d", got)
	}
}

// --- benchmarks -----------------------------------------------------------------
//
// These measure the three lookup paths a request can take. The negative hit is the
// one this work adds, and it has to be cheaper than the upstream query it replaces -
// otherwise caching the verdict would not be worth doing. It does no network work at
// all, so the comparison against a miss is really a measure of what was removed.

func benchmarkQuery(qtype uint16) *mDNS.Msg {
	return negativeQuery("ads.example.", qtype)
}

func BenchmarkDNSExactCacheHit(b *testing.B) {
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return FixedResponse(request.Id, request.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 3600)
	}}
	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
	message := benchmarkQuery(mDNS.TypeA)
	if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDNSNXDomainNameCacheHit(b *testing.B) {
	// Warm with an A query, then measure an AAAA query of the same name, which the
	// name cache answers without contacting the transport.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 3600, 3600)
	}}
	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
	if _, err := client.Exchange(context.Background(), transport, benchmarkQuery(mDNS.TypeA), adapter.DNSQueryOptions{}, nil); err != nil {
		b.Fatal(err)
	}
	message := benchmarkQuery(mDNS.TypeAAAA)
	if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDNSCacheMiss(b *testing.B) {
	// Caching disabled, so every iteration performs a full exchange. This is the
	// baseline the two hits are compared against.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return FixedResponse(request.Id, request.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 3600)
	}}
	client := NewClient(ClientOptions{
		Context:      context.Background(),
		Logger:       log.NewNOPFactory().Logger(),
		DisableCache: true,
	})
	message := benchmarkQuery(mDNS.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}
