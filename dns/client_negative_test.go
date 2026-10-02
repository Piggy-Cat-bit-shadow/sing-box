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
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
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
	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
	// Start() is what wires the caches, and production reaches it the same way: the DNS
	// Router calls client.Start() during its own start stage. Constructing without it
	// used to be enough when the negative cache was initialised from the memory-exact
	// path, which is precisely the coupling that left persistent-backend deployments
	// without a name cache. Tests now follow the real lifecycle.
	client.Start()
	return client
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
	client.Start()

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
	client.Start()
	message := benchmarkQuery(mDNS.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// --- TTL decrement (§9) ---------------------------------------------------------

func TestNXDomain_ReportsRemainingTTLNotOriginal(t *testing.T) {
	// A verdict recorded at TTL 5 must not still claim 5 seconds a second later. A client
	// that honours negative caching would otherwise hold the name far longer than the
	// authoritative server asked for.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 5, 5)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("ttl.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)

	response, err := exchange(t, client, transport, negativeQuery("ttl.example.", mDNS.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	require.Equal(t, 1, transport.count(), "the name-wide verdict must still be serving this")

	soa := findSOA(t, response)
	// Deliberately a range rather than an exact value: the scheduler decides how much of
	// the second elapsed, and pinning 3 or 4 would make this flaky rather than strict.
	require.Greater(t, soa.Hdr.Ttl, uint32(0), "the remaining TTL must not have run out")
	require.Less(t, soa.Hdr.Ttl, uint32(5),
		"the reported TTL must be the REMAINING lifetime, not the original 5 seconds")
}

func findSOA(t *testing.T, response *mDNS.Msg) *mDNS.SOA {
	t.Helper()
	for _, record := range response.Ns {
		if soa, isSOA := record.(*mDNS.SOA); isSOA {
			return soa
		}
	}
	t.Fatal("the cached NXDOMAIN must carry its SOA authority")
	return nil
}

// --- CNAME safety (§10) ---------------------------------------------------------

func cnameNXDomainResponse(request *mDNS.Msg) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(request)
	response.Rcode = mDNS.RcodeNameError
	// The alias exists; its TARGET does not. This is the shape that must not be widened
	// to the queried name.
	response.Answer = []mDNS.RR{&mDNS.CNAME{
		Hdr:    mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET, Ttl: 300},
		Target: "missing.example.",
	}}
	response.Ns = []mDNS.RR{soaAuthority("example.org.", 300, 300)}
	return response
}

func TestNXDomain_CNAMEChainIsNotWidenedToQNAME(t *testing.T) {
	// A terminal NXDOMAIN reached through a CNAME says the TARGET is absent, not the name
	// that was asked about. Caching that name-wide would make the alias itself look
	// non-existent for every record type.
	transport := &negativeTransport{respond: cnameNXDomainResponse}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("alias.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}

	// A different type for the same name must go upstream, because no name-wide verdict
	// was justified.
	if _, err := exchange(t, client, transport, negativeQuery("alias.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 2, transport.count(),
		"an NXDOMAIN that travelled through a CNAME must not answer other types locally")
}

func TestNXDomain_CNAMEQueryNotAnsweredAsNXDOMAIN(t *testing.T) {
	// The strongest form of the same rule: querying the CNAME itself must not be answered
	// from a name-wide verdict, because the alias demonstrably exists.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		if request.Question[0].Qtype == mDNS.TypeCNAME {
			response := new(mDNS.Msg)
			response.SetReply(request)
			response.Rcode = mDNS.RcodeSuccess
			response.Answer = []mDNS.RR{&mDNS.CNAME{
				Hdr:    mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET, Ttl: 300},
				Target: "missing.example.",
			}}
			return response
		}
		return cnameNXDomainResponse(request)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("alias.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	response, err := exchange(t, client, transport, negativeQuery("alias.example.", mDNS.TypeCNAME))
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode,
		"the alias exists, so a CNAME query must not be answered NXDOMAIN from the cache")
	require.NotEmpty(t, response.Answer)
}

// --- real SOA TTL, not the rewritten value (§11) --------------------------------

func TestNXDomain_ZeroSOATTLIsNotPromotedByNameWide(t *testing.T) {
	// The zone said "do not cache this" with a zero negative TTL. An operator's rewrite_ttl
	// must not turn that into a name-wide verdict: the exact cache may honour the rewrite,
	// but widening a non-cacheable answer across every record type is a different act.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 0, 0) // min(0,0) = 0
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("zero.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("zero.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 2, transport.count(),
		"a zero negative TTL must not be promoted to a name-wide verdict")
}

// --- persistent backend (§12) ---------------------------------------------------

// persistentStore is a fake adapter.DNSCacheStore, standing in for a real persistent
// exact-cache backend such as a Redis or file store.
//
// It stores nothing: the point of the test is that the NAME-WIDE cache works independently
// of whichever exact backend exists, so a store that never returns a hit is the strongest
// form of the assertion - any local answer must have come from the name cache.
type persistentStore struct {
	saved int
}

func (s *persistentStore) LoadDNSCache(string, string, uint16) ([]byte, time.Time, bool) {
	return nil, time.Time{}, false
}

func (s *persistentStore) SaveDNSCache(string, string, uint16, []byte, time.Time) error {
	s.saved++
	return nil
}

func (s *persistentStore) SaveDNSCacheAsync(string, string, uint16, []byte, time.Time, logger.Logger) {
	s.saved++
}

func (s *persistentStore) ClearDNSCache() error { return nil }

func TestNXDomain_WorksWithPersistentBackend(t *testing.T) {
	// The name-wide cache must not depend on the memory exact backend being the one in
	// use. Initialising it from initializeMemoryCache meant a persistent deployment got no
	// name cache at all, and every record type cost its own upstream query.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	store := &persistentStore{}
	client := NewClient(ClientOptions{
		Context:  context.Background(),
		Logger:   log.NewNOPFactory().Logger(),
		DNSCache: func() adapter.DNSCacheStore { return store },
	})
	client.Start()
	require.Nil(t, client.cache, "the memory exact cache must not be in use for this test")
	require.NotNil(t, client.nxdomainCache, "the name-wide cache must exist independently")

	if _, err := exchange(t, client, transport, negativeQuery("persist.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("persist.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 1, transport.count(),
		"the name-wide verdict must serve the second type even with a persistent exact cache")
}

// --- idempotent init (§13) ------------------------------------------------------

func TestNXDomain_InitializeIsIdempotent(t *testing.T) {
	// Called twice, the cache must not be recreated: doing so would silently drop every
	// verdict already recorded, with extra upstream queries as the only symptom.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("idem.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	before := client.nxdomainCache
	require.Equal(t, 1, client.nxdomainCache.Len())

	client.initializeNXDomainCache()

	require.Same(t, before, client.nxdomainCache, "re-initialising must not replace the cache")
	require.Equal(t, 1, client.nxdomainCache.Len(), "existing verdicts must survive")
}

// --- ClearCache (§14) -----------------------------------------------------------

func TestNXDomain_ClearCacheClearsNegativeCache(t *testing.T) {
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	if _, err := exchange(t, client, transport, negativeQuery("clear.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, transport, negativeQuery("clear.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 1, transport.count(), "the verdict must be serving before the clear")

	client.ClearCache()

	if _, err := exchange(t, client, transport, negativeQuery("clear.example.", mDNS.TypeHTTPS)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 2, transport.count(),
		"ClearCache must discard name-wide verdicts, or it did not clear the state the caller asked about")
}

// --- disable_expire coherence (§15) ---------------------------------------------

func TestNXDomain_DisableExpireKeepsVerdicts(t *testing.T) {
	// The ordinary exact cache ignores lifetimes under disable_expire, so the name-wide
	// cache must too. Expiring one and not the other would answer neighbouring query types
	// inconsistently for no reason an operator could observe or intend.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 1, 1)
	}}
	client := NewClient(ClientOptions{
		Context:       context.Background(),
		Logger:        log.NewNOPFactory().Logger(),
		DisableExpire: true,
	})
	client.Start()

	if _, err := exchange(t, client, transport, negativeQuery("noexpire.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := exchange(t, client, transport, negativeQuery("noexpire.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 1, transport.count(),
		"disable_expire must keep name-wide verdicts, as it does for the exact cache")
}

// --- positive vs negative coexistence (§16) -------------------------------------

func TestNXDomain_PositiveExactCacheWinsOverNegativeName(t *testing.T) {
	// The real question is precedence, and the earlier version of this test could not
	// answer it: it asked for A twice, so it never created a negative verdict at all.
	//
	// This establishes a positive A, then an NXDOMAIN for the SAME NAME under a different
	// type, then asks for A again. The positive entry must still win, from the exact cache.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		if request.Question[0].Qtype == mDNS.TypeA {
			return FixedResponse(request.Id, request.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.7")}, 300)
		}
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	first, err := exchange(t, client, transport, negativeQuery("mixed.example.", mDNS.TypeA))
	require.NoError(t, err)
	require.NotEmpty(t, first.Answer, "precondition: A must be positive")

	// Create the contradicting name-wide verdict.
	if _, err := exchange(t, client, transport, negativeQuery("mixed.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 2, transport.count(), "precondition: the AAAA must have gone upstream")

	// The positive entry must still be served, and must not be clobbered.
	third, err := exchange(t, client, transport, negativeQuery("mixed.example.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, third.Rcode,
		"the exact positive entry must win over the name-wide negative verdict")
	require.NotEmpty(t, third.Answer, "the positive answer must still carry its address")
	require.Equal(t, 2, transport.count(),
		"the positive hit must not cost an upstream query")
}

// --- namespace separation (§17) -------------------------------------------------

func TestNXDomain_ECSSubnetNamespaceIsSeparate(t *testing.T) {
	// A verdict reached with one client subnet must not answer a different one: an
	// authoritative server is entitled to give different answers per subnet.
	transport := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, transport)

	withSubnet := adapter.DNSQueryOptions{ClientSubnet: netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := client.Exchange(context.Background(), transport,
		negativeQuery("ecs.example.", mDNS.TypeA), withSubnet, nil); err != nil {
		t.Fatal(err)
	}

	otherSubnet := adapter.DNSQueryOptions{ClientSubnet: netip.MustParsePrefix("198.51.100.0/24")}
	if _, err := client.Exchange(context.Background(), transport,
		negativeQuery("ecs.example.", mDNS.TypeAAAA), otherSubnet, nil); err != nil {
		t.Fatal(err)
	}

	require.Equal(t, 2, transport.count(),
		"a different client subnet is a different namespace and must go upstream")
}

func TestNXDomain_EnvironmentNamespaceIsSeparate(t *testing.T) {
	// Same reasoning for the transport environment: a network change can change the answer.
	first := &negativeTransport{respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	second := &negativeTransport{tag: "other-env", respond: func(request *mDNS.Msg) *mDNS.Msg {
		return nxdomainResponse(request, 300, 300)
	}}
	client := newNegativeClient(t, first)

	if _, err := exchange(t, client, first, negativeQuery("env.example.", mDNS.TypeA)); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(t, client, second, negativeQuery("env.example.", mDNS.TypeAAAA)); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, 1, second.count(),
		"a different transport environment must be asked, not answered from another namespace")
}
