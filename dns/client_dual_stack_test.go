package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for incremental dual-stack resolution (§78-§82).
//
// The property under test is that one family's answer is not held hostage by the other. Each
// test drives a fake transport whose families complete on controlled schedules, so the
// timings are deterministic and no network is involved.

// familySchedulingTransport answers A and AAAA on independent schedules.
type familySchedulingTransport struct {
	queryCount atomic32

	// answerA and answerAAAA decide what each family returns. The delay is applied before
	// responding, and a negative delay means "block until the context ends", which models a
	// resolver that never answers.
	delayA    time.Duration
	delayAAAA time.Duration

	addressA    string
	addressAAAA string

	// noDataA / noDataAAAA answer NOERROR with no records, which is NODATA rather than a
	// failure and must not be treated as one.
	noDataA    bool
	noDataAAAA bool
}

func (t *familySchedulingTransport) Start(adapter.StartStage) error { return nil }
func (t *familySchedulingTransport) Close() error                   { return nil }
func (t *familySchedulingTransport) Type() string                   { return "family-scheduling" }
func (t *familySchedulingTransport) Tag() string                    { return "family-scheduling" }
func (t *familySchedulingTransport) Dependencies() []string         { return nil }
func (t *familySchedulingTransport) Reset()                         {}

func (t *familySchedulingTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	qType := message.Question[0].Qtype

	delay := t.delayA
	address := t.addressA
	noData := t.noDataA
	if qType == mDNS.TypeAAAA {
		delay = t.delayAAAA
		address = t.addressAAAA
		noData = t.noDataAAAA
	}

	if delay < 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	if !noData && address != "" {
		record := &mDNS.A{Hdr: mDNS.RR_Header{
			Name:   message.Question[0].Name,
			Rrtype: qType,
			Class:  mDNS.ClassINET,
			Ttl:    300,
		}}
		if qType == mDNS.TypeAAAA {
			response.Answer = append(response.Answer, &mDNS.AAAA{
				Hdr:  record.Hdr,
				AAAA: parseIPv6ForTest(address),
			})
		} else {
			response.Answer = append(response.Answer, &mDNS.A{
				Hdr: record.Hdr,
				A:   parseIPv4ForTest(address),
			})
		}
	}
	return response, nil
}

func (t *familySchedulingTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

// TestIncrementalLookupDoesNotWaitForAHungFamily is §78 and §79.
//
// One family answers promptly and the other never answers. The lookup must complete at the
// resolution-delay scale, not at the DNS timeout scale.
func TestIncrementalLookupDoesNotWaitForAHungFamily(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		transport *familySchedulingTransport
		wantAddr  string
	}{
		{
			name: "A fast, AAAA hung",
			transport: &familySchedulingTransport{
				delayA:      5 * time.Millisecond,
				delayAAAA:   -1, // never answers
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			},
			wantAddr: "192.0.2.1",
		},
		{
			name: "AAAA fast, A hung",
			transport: &familySchedulingTransport{
				delayA:      -1, // never answers
				delayAAAA:   5 * time.Millisecond,
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			},
			wantAddr: "2001:db8::1",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := NewClient(ClientOptions{
				Context: context.Background(),
				Logger:  log.NewNOPFactory().Logger(),
			})
			client.Start()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			start := time.Now()
			response4, response6, err := client.collectFamilies(
				ctx, testCase.transport, "example.test.",
				adapter.DNSQueryOptions{}, nil,
				50*time.Millisecond, false,
			)
			elapsed := time.Since(start)

			require.NoError(t, err)
			require.Less(t, elapsed, time.Second,
				"a hung family must not delay the answer beyond the resolution delay")

			var found bool
			for _, address := range append(response4, response6...) {
				if address.String() == testCase.wantAddr {
					found = true
				}
			}
			require.True(t, found, "the fast family's address must be returned")
		})
	}
}

// TestIncrementalLookupPreferredFamilyGrace is §80.
//
// A slightly slower PREFERRED family must still win, but only within the grace period: a
// preferred family that arrives long after the grace period must not delay the connection.
func TestIncrementalLookupPreferredFamilyGrace(t *testing.T) {
	t.Run("preferred arrives within the grace period", func(t *testing.T) {
		transport := &familySchedulingTransport{
			delayA:      0, // IPv4 is fast but NOT preferred
			delayAAAA:   10 * time.Millisecond,
			addressA:    "192.0.2.1",
			addressAAAA: "2001:db8::1",
		}
		client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
		client.Start()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		start := time.Now()
		response4, response6, err := client.collectFamilies(
			ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil,
			50*time.Millisecond, true, // prefer IPv6
		)
		elapsed := time.Since(start)

		require.NoError(t, err)
		// Both families answered well within the window, so both must be present. This is the
		// case where waiting briefly for the preferred family is worthwhile: the grace period
		// applies and the preferred family is not lost.
		require.NotEmpty(t, response6, "the preferred family arrived within the grace period")
		require.NotEmpty(t, response4, "the fast family must also be returned")
		require.Less(t, elapsed, time.Second, "both answers were available quickly")
	})

	t.Run("preferred arrives long after the grace period", func(t *testing.T) {
		transport := &familySchedulingTransport{
			delayA:      0,
			delayAAAA:   -1, // the preferred family never arrives
			addressA:    "192.0.2.1",
			addressAAAA: "2001:db8::1",
		}
		client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
		client.Start()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		start := time.Now()
		response4, _, err := client.collectFamilies(
			ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil,
			50*time.Millisecond, true,
		)
		elapsed := time.Since(start)

		require.NoError(t, err)
		require.NotEmpty(t, response4, "the fast family must be used rather than waiting for the preferred one")
		require.Less(t, elapsed, time.Second,
			"waiting for a hung preferred family beyond the grace period defeats the purpose")
	})
}

// TestIncrementalLookupNODATAIsNotFailure is §81.
//
// NOERROR with no records is an answer about one family, not a failure. The other family must
// still be used.
func TestIncrementalLookupNODATAIsNotFailure(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		transport *familySchedulingTransport
		wantAddr  string
	}{
		{
			name: "AAAA NODATA, A healthy",
			transport: &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
				noDataAAAA:  true,
			},
			wantAddr: "192.0.2.1",
		},
		{
			name: "A NODATA, AAAA healthy",
			transport: &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
				noDataA:     true,
			},
			wantAddr: "2001:db8::1",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			response4, response6, err := client.collectFamilies(
				ctx, testCase.transport, "example.test.", adapter.DNSQueryOptions{}, nil,
				50*time.Millisecond, false,
			)
			require.NoError(t, err, "NODATA in one family must not be an error")

			var found bool
			for _, address := range append(response4, response6...) {
				if address.String() == testCase.wantAddr {
					found = true
				}
			}
			require.True(t, found, "the healthy family must be returned despite the other's NODATA")
		})
	}
}

// TestIncrementalBothFamiliesEmptyIsAnError is the mirror: only when neither family yields
// anything is the lookup a failure.
func TestIncrementalBothFamiliesEmptyIsAnError(t *testing.T) {
	transport := &familySchedulingTransport{noDataA: true, noDataAAAA: true}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.collectFamilies(
		ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil,
		50*time.Millisecond, false,
	)
	require.Error(t, err, "with no usable address in either family the lookup must fail")
}

// TestFamilyCollectorPublishesEachResultOnce is the collector's own contract (§25).
func TestFamilyCollectorPublishesEachResultOnce(t *testing.T) {
	// preferIPv6, so an IPv4 result arriving first is the NON-preferred one and is the case
	// the grace period exists for.
	var (
		access    sync.Mutex
		published []familyResult
	)
	collector := newFamilyCollector(func(result familyResult) {
		access.Lock()
		published = append(published, result)
		access.Unlock()
	}, 30*time.Millisecond, true)

	count := func() int {
		access.Lock()
		defer access.Unlock()
		return len(published)
	}

	// The non-preferred family arrives first and is held.
	collector.publish(familyResult{IPv6: false, Addresses: nil})
	require.Equal(t, 0, count(), "the non-preferred family waits for the grace period")

	time.Sleep(80 * time.Millisecond)
	require.Equal(t, 1, count(), "the held result must be published when the grace period expires")

	// The preferred family arriving afterwards is published immediately: the decision was
	// already made and nothing is held a second time.
	collector.publish(familyResult{IPv6: true, Addresses: nil})
	require.Equal(t, 2, count(), "a later result must publish immediately")

	collector.close()
	require.Equal(t, 2, count(), "close must not republish anything")
}

func TestFamilyCollectorPublishesPreferredFamilyImmediately(t *testing.T) {
	// When the PREFERRED family answers first there is nothing better to wait for, so it must
	// not be delayed by the grace period.
	var (
		access    sync.Mutex
		published []familyResult
	)
	collector := newFamilyCollector(func(result familyResult) {
		access.Lock()
		published = append(published, result)
		access.Unlock()
	}, 50*time.Millisecond, true)

	collector.publish(familyResult{IPv6: true})
	access.Lock()
	count := len(published)
	access.Unlock()
	require.Equal(t, 1, count, "the preferred family must publish immediately, not after the grace period")
}

// TestFamilyCollectorReleasesHungPreferredFamily is the §23 requirement stated as a test:
// an answer in hand is never withheld indefinitely.
func TestFamilyCollectorReleasesHungPreferredFamily(t *testing.T) {
	// The non-preferred family answers; the preferred one never does. The answer in hand must
	// still be released - an answer already available is never withheld indefinitely.
	var (
		access    sync.Mutex
		published []familyResult
	)
	collector := newFamilyCollector(func(result familyResult) {
		access.Lock()
		published = append(published, result)
		access.Unlock()
	}, 30*time.Millisecond, true) // prefer IPv6, which never arrives

	count := func() int {
		access.Lock()
		defer access.Unlock()
		return len(published)
	}

	collector.publish(familyResult{IPv6: false})
	require.Equal(t, 0, count(), "held for the grace period")

	time.Sleep(80 * time.Millisecond)
	require.Equal(t, 1, count(),
		"a non-preferred answer must be released even though the preferred family never came")
}

// TestFamilyCollectorClosePublishesHeldResult is the regression for a family being dropped.
//
// The first family is held for its grace period. If the caller returns before that timer
// fires, close must publish it - otherwise the FAST answer is the one discarded, which is
// worse than not streaming at all.
func TestFamilyCollectorClosePublishesHeldResult(t *testing.T) {
	var (
		access    sync.Mutex
		published []familyResult
	)
	collector := newFamilyCollector(func(result familyResult) {
		access.Lock()
		published = append(published, result)
		access.Unlock()
	}, time.Hour, true) // a grace period that will never elapse on its own

	collector.publish(familyResult{IPv6: false, Addresses: nil})

	access.Lock()
	before := len(published)
	access.Unlock()
	require.Equal(t, 0, before, "precondition: the result is held")

	collector.close()

	access.Lock()
	after := len(published)
	access.Unlock()
	require.Equal(t, 1, after, "close must publish a result still held, not drop it")

	// And it must not publish a second time.
	collector.close()
	access.Lock()
	final := len(published)
	access.Unlock()
	require.Equal(t, 1, final, "close must be idempotent")
}

func parseIPv4ForTest(value string) []byte {
	address := netip.MustParseAddr(value)
	raw := address.As4()
	return raw[:]
}

func parseIPv6ForTest(value string) []byte {
	address := netip.MustParseAddr(value)
	raw := address.As16()
	return raw[:]
}

// atomic32 is a small counter for the fake transport; it only needs to be race-safe.
type atomic32 struct {
	access sync.Mutex
	value  int32
}

func (c *atomic32) Add(delta int32) {
	c.access.Lock()
	c.value += delta
	c.access.Unlock()
}

func (c *atomic32) Load() int32 {
	c.access.Lock()
	defer c.access.Unlock()
	return c.value
}

// TestLookupReturnsTheCompleteSet is the §28/§29 regression.
//
// Lookup is the complete-lookup contract. Callers use it for routing, rule matching, the
// candidate list published on metadata, and diagnostics - all of which expect the whole
// address set. Streaming it would silently halve the answer for every one of them: routing
// would evaluate rules against one family while the other was still in flight.
//
// A lagging family must therefore be WAITED FOR, even though the connection path deliberately
// does not wait.
func TestLookupReturnsTheCompleteSet(t *testing.T) {
	transport := &familySchedulingTransport{
		delayA:      0,
		delayAAAA:   80 * time.Millisecond, // slower than the streaming grace period
		addressA:    "192.0.2.1",
		addressAAAA: "2001:db8::1",
	}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addresses, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	var has4, has6 bool
	for _, address := range addresses {
		if address.Is4() || address.Is4In6() {
			has4 = true
		} else {
			has6 = true
		}
	}
	require.True(t, has4, "Lookup must return the IPv4 address")
	require.True(t, has6,
		"Lookup must WAIT for the slower family: an incomplete set changes routing and rule matching")
}
