package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Tests for a DNS transport whose environment fingerprint is legitimately and permanently zero.
//
// # Why zero cannot simply mean "unknown"
//
// environmentHash returns 0 in two situations that look identical but are not:
//
//	participates in environments, and nothing is known yet   -> 0 means UNKNOWN
//	participates, Environment() is empty, NetworkEnvironment() is permanently 0 -> 0 is the IDENTITY
//
// The second case is a real configuration: a transport that advertises no environment keys on a
// platform that reports no network environment. Its fingerprint is 0 for the whole process lifetime,
// and it is correct and stable.
//
// Treating every zero as "unknown" therefore disables caching permanently for such a transport -
// every query goes upstream, which is a silent behaviour change rather than a safety property.
//
// The invariant that must survive is different and narrower: a response must not be re-attributed to
// a DIFFERENT environment than the one its query was issued under. That is about generations, not
// about the number zero.

// zeroEnvironmentNetworkManager reports a permanently zero network environment.
type zeroEnvironmentNetworkManager struct {
	adapter.NetworkManager
}

func (m *zeroEnvironmentNetworkManager) NetworkEnvironment() uint64 { return 0 }

// zeroEnvironmentTransport participates in environments but advertises none.
type zeroEnvironmentTransport struct {
	adapter.DNSTransport
	tag string
	// environment is empty by default, which is the stable-zero configuration.
	environment []string
	// queries counts upstream exchanges, so "did this cache" is observable.
	queries atomic.Int32
}

func (t *zeroEnvironmentTransport) Tag() string                          { return t.tag }
func (t *zeroEnvironmentTransport) Type() string                         { return "zero-env" }
func (t *zeroEnvironmentTransport) Dependencies() []string               { return nil }
func (t *zeroEnvironmentTransport) Environment() []string                { return t.environment }
func (t *zeroEnvironmentTransport) Start(stage adapter.StartStage) error { return nil }
func (t *zeroEnvironmentTransport) Close() error                         { return nil }
func (t *zeroEnvironmentTransport) Reset()                               {}

func (t *zeroEnvironmentTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	t.queries.Add(1)
	response := new(dns.Msg)
	response.SetReply(message)
	if len(message.Question) > 0 {
		question := message.Question[0]
		record := &dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		}
		response.Answer = append(response.Answer, record)
	}
	return response, nil
}

// newZeroEnvironmentClient builds a client bound to a permanently-zero environment.
func newZeroEnvironmentClient(t *testing.T) (*Client, *zeroEnvironmentTransport) {
	t.Helper()
	networkManager := &zeroEnvironmentNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context: ctx,
		Logger:  log.NewNOPFactory().NewLogger("dns-zero-env"),
	})
	client.Start()
	transport := &zeroEnvironmentTransport{tag: "zero-env"}
	return client, transport
}

// exchangeA performs one A lookup through the client, returning the upstream query count after it.
func exchangeA(t *testing.T, client *Client, transport *zeroEnvironmentTransport, name string) int32 {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	options := adapter.DNSQueryOptions{}
	_, err := client.Exchange(context.Background(), transport, message, options, nil)
	require.NoError(t, err)
	return transport.queries.Load()
}

// TestStableZeroEnvironmentStillCaches is the release blocker for this point.
//
// A transport whose fingerprint is permanently zero must cache normally. Nothing about the network
// changed between the two queries, so the second must be answered from cache.
func TestStableZeroEnvironmentStillCaches(t *testing.T) {
	client, transport := newZeroEnvironmentClient(t)

	require.EqualValues(t, 0, client.environmentHash(transport),
		"the fixture must actually produce a zero fingerprint, or this test proves nothing")

	first := exchangeA(t, client, transport, "example.com")
	require.EqualValues(t, 1, first, "the first query reaches upstream")

	second := exchangeA(t, client, transport, "example.com")
	require.EqualValues(t, 1, second,
		"the second identical query must be answered from cache. A zero fingerprint is this "+
			"transport's real and stable identity, so refusing to store it disables caching for the "+
			"whole process lifetime - every query goes upstream, which is a silent behaviour change "+
			"rather than a safety property")
}

// TestZeroEnvironmentTransportStillDeduplicates is the same statement across record types.
func TestZeroEnvironmentTransportStillDeduplicates(t *testing.T) {
	client, transport := newZeroEnvironmentClient(t)

	exchangeA(t, client, transport, "example.com")
	after := transport.queries.Load()

	for repeat := 0; repeat < 5; repeat++ {
		exchangeA(t, client, transport, "example.com")
	}

	require.Equal(t, after, transport.queries.Load(),
		"repeated lookups of one name must not each reach upstream")
}

// TestChangedEnvironmentIsStillRejected keeps the invariant the zero rule was protecting.
//
// A response issued under one environment must not be stored once the environment has changed.
func TestChangedEnvironmentIsStillRejected(t *testing.T) {
	client, _ := newZeroEnvironmentClient(t)

	// A participating transport WITH an environment, so the fingerprint is real.
	transport := &environmentTransport{tag: "env", environment: []string{"wifi-a"}}

	question := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		environment:  0x1234,
	}

	_, storable := client.finishCacheKey(transport, key)
	require.False(t, storable,
		"a response whose query captured environment 0x1234 must not be stored when the current "+
			"environment differs")
}

// nxdomainZeroEnvironmentTransport answers NXDOMAIN with an SOA, so the name-wide negative cache
// is exercised through the same finishCacheKey path.
type nxdomainZeroEnvironmentTransport struct {
	zeroEnvironmentTransport
	answers atomic.Int32
}

func (t *nxdomainZeroEnvironmentTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	t.answers.Add(1)
	response := new(dns.Msg)
	response.SetReply(message)
	response.Rcode = dns.RcodeNameError
	if len(message.Question) > 0 {
		response.Ns = append(response.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		})
	}
	return response, nil
}

// TestStableZeroEnvironmentNXDomainCaches is the negative-cache half of this point.
//
// The name-wide NXDOMAIN verdict must be recorded for a stable-zero transport too: it is the same
// cache-write decision, so a fingerprint rule that disabled caching would disable this as well -
// and this cache is the one that saves one upstream query per record type.
func TestStableZeroEnvironmentNXDomainCaches(t *testing.T) {
	client, _ := newZeroEnvironmentClient(t)
	transport := &nxdomainZeroEnvironmentTransport{}
	transport.tag = "zero-env-nxdomain"

	require.EqualValues(t, 0, client.environmentHash(transport),
		"the fixture must actually produce a zero fingerprint")

	lookup := func(qtype uint16) {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn("absent.example.com"), qtype)
		_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err)
	}

	lookup(dns.TypeA)
	afterFirst := transport.answers.Load()
	require.EqualValues(t, 1, afterFirst, "the first query reaches upstream")

	// A different record type for the SAME name must reuse the name-wide verdict.
	lookup(dns.TypeAAAA)
	require.EqualValues(t, afterFirst, transport.answers.Load(),
		"the name-wide NXDOMAIN verdict must be reusable for another record type. Refusing to "+
			"store it because the fingerprint is zero costs one upstream query per record type, "+
			"which is exactly what the name-wide cache exists to prevent")
}

// TestStableZeroEnvironmentPersistentCacheIsWritten checks the persistent path.
//
// storeCache mirrors to the persistent store, and it is reached only when finishCacheKey reports
// storable, so a fingerprint rule that refused zero would also stop persistence.
func TestStableZeroEnvironmentPersistentCacheIsWritten(t *testing.T) {
	store := &recordingDNSCacheStore{}

	networkManager := &zeroEnvironmentNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	client := NewClient(ClientOptions{
		Context: ctx,
		Logger:  log.NewNOPFactory().NewLogger("dns-zero-env-persistent"),
		DNSCache: func() adapter.DNSCacheStore {
			return store
		},
	})
	client.Start()

	transport := &zeroEnvironmentTransport{tag: "zero-env-persistent"}
	require.EqualValues(t, 0, client.environmentHash(transport))

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Greater(t, store.saves.Load(), int32(0),
		"a stable-zero transport must still persist its answers. finishCacheKey gates the "+
			"persistent write as well as the in-memory one, so refusing zero loses both")
}

// recordingDNSCacheStore counts persistent saves.
type recordingDNSCacheStore struct {
	adapter.DNSCacheStore
	saves atomic.Int32
}

func (s *recordingDNSCacheStore) SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger) {
	s.saves.Add(1)
}

func (s *recordingDNSCacheStore) SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error {
	s.saves.Add(1)
	return nil
}

func (s *recordingDNSCacheStore) LoadDNSCache(transportName string, qName string, qType uint16) ([]byte, time.Time, bool) {
	return nil, time.Time{}, false
}

func (s *recordingDNSCacheStore) ClearDNSCache() error { return nil }

// TestStableZeroEnvironmentOptimisticRefreshStores is the fourth path.
//
// The background refresh calls finishCacheKey independently of the foreground exchange, so it has
// its own decision. A stable-zero transport must refresh its own cache, or an optimistic hit would
// be served until it expires and then never renewed.
func TestStableZeroEnvironmentOptimisticRefreshStores(t *testing.T) {
	client, transport := newZeroEnvironmentClient(t)

	// Prime the cache, then confirm the key the client actually builds carries a zero environment -
	// which is what makes the refresh decision the same one under test.
	exchangeA(t, client, transport, "refresh.example.com")

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn("refresh.example.com."), dns.TypeA)
	key := client.newCacheKey(transport, message.Question[0], message, adapter.DNSQueryOptions{})

	require.EqualValues(t, 0, key.environment,
		"the built key must carry the zero fingerprint, so the refresh path takes the same "+
			"decision as the foreground path")

	stored, storable := client.finishCacheKey(transport, key)
	require.True(t, storable,
		"the background refresh must be allowed to store for a stable-zero transport, or an "+
			"optimistic hit is served until it expires and never renewed")
	require.EqualValues(t, 0, stored.environment)
}
