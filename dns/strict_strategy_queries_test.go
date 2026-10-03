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

// End-to-end strict-family tests.
//
// # What these prove that a mock cannot
//
// A strict strategy is a QUERY-LEVEL policy. "ipv4_only" must mean the AAAA query is never sent,
// not that it is sent and its answer discarded - a discarded query is still a query the user's
// resolver saw, and under a strict policy it is traffic the user asked not to produce.
//
// So these assert on the QTYPEs a real DNS transport actually received, travelling through
// LookupFamilies and the router's own strategy resolution, rather than on a mocked
// EffectiveStrategy field.

// recordingDNSRouter builds a Router whose lookups go to a transport that records every QTYPE.
type queryRecordingTransport struct {
	adapter.DNSTransport

	access   sync.Mutex
	qTypes   []uint16
	addressA string
	address6 string
}

func (t *queryRecordingTransport) Type() string                   { return "recorder" }
func (t *queryRecordingTransport) Tag() string                    { return "recorder" }
func (t *queryRecordingTransport) Dependencies() []string         { return nil }
func (t *queryRecordingTransport) Start(adapter.StartStage) error { return nil }
func (t *queryRecordingTransport) Close() error                   { return nil }
func (t *queryRecordingTransport) Reset()                         {}

func (t *queryRecordingTransport) observed() []uint16 {
	t.access.Lock()
	defer t.access.Unlock()
	return append([]uint16(nil), t.qTypes...)
}

func (t *queryRecordingTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	qType := message.Question[0].Qtype
	t.access.Lock()
	t.qTypes = append(t.qTypes, qType)
	t.access.Unlock()

	response := new(mDNS.Msg)
	response.SetReply(message)
	if qType == mDNS.TypeA && t.addressA != "" {
		response.Answer = append(response.Answer, &mDNS.A{
			Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
			A:   parseIPv4ForTest(t.addressA),
		})
	}
	if qType == mDNS.TypeAAAA && t.address6 != "" {
		response.Answer = append(response.Answer, &mDNS.AAAA{
			Hdr:  mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 60},
			AAAA: parseIPv6ForTest(t.address6),
		})
	}
	return response, nil
}

func (t *queryRecordingTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

// TestStrictStrategyNeverEmitsTheForbiddenFamily is §8, §9, §12.
//
// The forbidden family's query must not reach the resolver, whether the strict strategy came from
// the caller or from the router's own configured default while the caller said AsIS.
func TestStrictStrategyNeverEmitsTheForbiddenFamily(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		callerState   C.DomainStrategy
		routerDefault C.DomainStrategy
		forbidden     uint16
		expected      uint16
	}{
		{
			name:        "caller ipv4_only",
			callerState: C.DomainStrategyIPv4Only,
			forbidden:   mDNS.TypeAAAA,
			expected:    mDNS.TypeA,
		},
		{
			name:        "caller ipv6_only",
			callerState: C.DomainStrategyIPv6Only,
			forbidden:   mDNS.TypeA,
			expected:    mDNS.TypeAAAA,
		},
		{
			name:          "AsIS with router default ipv4_only",
			callerState:   C.DomainStrategyAsIS,
			routerDefault: C.DomainStrategyIPv4Only,
			forbidden:     mDNS.TypeAAAA,
			expected:      mDNS.TypeA,
		},
		{
			name:          "AsIS with router default ipv6_only",
			callerState:   C.DomainStrategyAsIS,
			routerDefault: C.DomainStrategyIPv6Only,
			forbidden:     mDNS.TypeA,
			expected:      mDNS.TypeAAAA,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &queryRecordingTransport{addressA: "192.0.2.1", address6: "2001:db8::1"}
			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()
			router := &Router{
				ctx:                   context.Background(),
				logger:                log.NewNOPFactory().Logger(),
				client:                client,
				defaultDomainStrategy: testCase.routerDefault,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := router.LookupFamilies(ctx, "strict.test.", adapter.DNSQueryOptions{
				Transport: transport,
				Strategy:  testCase.callerState,
			}, func(adapter.DNSFamilyResult) {})
			require.NoError(t, err)

			observed := transport.observed()
			require.NotEmpty(t, observed, "the permitted family must actually be queried")

			for _, qType := range observed {
				require.NotEqual(t, testCase.forbidden, qType,
					"a strict strategy is a QUERY-LEVEL policy: the forbidden family must never be "+
						"sent, not sent and discarded. Observed %v", observed)
			}
			require.Contains(t, observed, testCase.expected,
				"the permitted family must be queried; observed %v", observed)
		})
	}
}

// TestPreferStrategyQueriesBothFamilies is §10's companion.
//
// A preference is not a restriction: both families are queried, and the strategy is what orders
// them.
func TestPreferStrategyQueriesBothFamilies(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		strategy C.DomainStrategy
	}{
		{"prefer_ipv4", C.DomainStrategyPreferIPv4},
		{"prefer_ipv6", C.DomainStrategyPreferIPv6},
	} {
		strategy := testCase.strategy
		t.Run(testCase.name, func(t *testing.T) {
			transport := &queryRecordingTransport{addressA: "192.0.2.1", address6: "2001:db8::1"}
			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()
			router := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), client: client}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// The publisher is invoked from each family's goroutine, so the collected slice is
			// guarded rather than appended to concurrently.
			var (
				resultsAccess sync.Mutex
				results       []adapter.DNSFamilyResult
			)
			err := router.LookupFamilies(ctx, "prefer.test.", adapter.DNSQueryOptions{
				Transport: transport,
				Strategy:  strategy,
			}, func(result adapter.DNSFamilyResult) {
				resultsAccess.Lock()
				results = append(results, result)
				resultsAccess.Unlock()
			})
			require.NoError(t, err)

			observed := transport.observed()
			require.Contains(t, observed, mDNS.TypeA, "a preference must still query both families")
			require.Contains(t, observed, mDNS.TypeAAAA)

			// Both published results must report the same effective strategy.
			resultsAccess.Lock()
			published := append([]adapter.DNSFamilyResult(nil), results...)
			resultsAccess.Unlock()

			require.NotEmpty(t, published)
			for _, result := range published {
				require.Equal(t, strategy, result.EffectiveStrategy,
					"the effective strategy reported must be the one that applied")
			}
		})
	}
}
