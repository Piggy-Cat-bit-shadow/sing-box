package dns

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Tests for the DNS side of the dual-stack work.
//
// The latency-oriented streaming path lives in the connection layer, where a late family can
// join a race in progress, and is covered by the dialer's end-to-end tests. What matters here
// is that the complete-lookup contract other callers depend on is unchanged.

// familySchedulingTransport answers A and AAAA on independent schedules.
type familySchedulingTransport struct {
	queryCount atomic32

	// answerA and answerAAAA decide what each family returns. The delay is applied before
	// responding, and a negative delay means "block until the context ends", which models a
	// resolver that never answers.
	delayA    time.Duration
	delayAAAA time.Duration

	// holdAAAA, when non-nil, keeps the AAAA query unanswered until the test closes it. A nil
	// channel blocks forever, so leaving it unset disables the gate and every caller that does not
	// set it behaves exactly as before. It exists so a test can state "the fast family is published
	// before its slower sibling answers" as an event rather than as a wall-clock bound on the
	// publication.
	holdAAAA <-chan struct{}

	addressA    string
	addressAAAA string

	// noDataA / noDataAAAA answer NOERROR with no records, which is NODATA rather than a
	// failure and must not be treated as one.
	noDataA    bool
	noDataAAAA bool

	// servfailA / servfailAAAA answer SERVFAIL, which is an upstream failure of ONE family
	// rather than a failure of the whole lookup.
	servfailA    bool
	servfailAAAA bool

	// observed records the QTYPE of every question the transport was asked, so a test can prove
	// that a forbidden family was never EMITTED rather than merely filtered out of the result.
	observedAccess sync.Mutex
	observed       []uint16
}

// observedTypes returns the QTYPE of every question this transport has received.
func (t *familySchedulingTransport) observedTypes() []uint16 {
	t.observedAccess.Lock()
	defer t.observedAccess.Unlock()
	return append([]uint16(nil), t.observed...)
}

func (t *familySchedulingTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *familySchedulingTransport) Close() error                                   { return nil }
func (t *familySchedulingTransport) Type() string                                   { return "family-scheduling" }
func (t *familySchedulingTransport) Tag() string                                    { return "family-scheduling" }
func (t *familySchedulingTransport) Dependencies() []string                         { return nil }
func (t *familySchedulingTransport) Reset()                                         {}

func (t *familySchedulingTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	qType := message.Question[0].Qtype

	t.observedAccess.Lock()
	t.observed = append(t.observed, qType)
	t.observedAccess.Unlock()

	delay := t.delayA
	address := t.addressA
	noData := t.noDataA
	servfail := t.servfailA
	if qType == mDNS.TypeAAAA {
		delay = t.delayAAAA
		address = t.addressAAAA
		noData = t.noDataAAAA
		servfail = t.servfailAAAA
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
	if qType == mDNS.TypeAAAA && t.holdAAAA != nil {
		select {
		case <-t.holdAAAA:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	response := new(mDNS.Msg)
	response.SetReply(message)
	if servfail {
		response.Rcode = mDNS.RcodeServerFailure
		response.Id = message.Id
		return response, nil
	}
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

// atomic32 is a small race-safe counter for the fake transport.
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

// TestLookupWaitsForTheSlowFamilyAndLeavesNoOrphan is §11.
//
// Lookup must wait for BOTH families, and must not leave a family query running after it
// returns. A partial-answer implementation would satisfy neither: it would return early, and
// the abandoned exchange would keep running until its own timeout.
func TestLookupWaitsForTheSlowFamilyAndLeavesNoOrphan(t *testing.T) {
	const slowFamilyDelay = 250 * time.Millisecond

	transport := &familySchedulingTransport{
		delayA:      0,
		delayAAAA:   slowFamilyDelay,
		addressA:    "192.0.2.1",
		addressAAAA: "2001:db8::1",
	}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	addresses, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil)
	elapsed := time.Since(start)

	require.NoError(t, err)

	// Both families present: this is the completeness guarantee.
	var has4, has6 bool
	for _, address := range addresses {
		if address.Is4() || address.Is4In6() {
			has4 = true
		} else {
			has6 = true
		}
	}
	require.True(t, has4, "the IPv4 address must be present")
	require.True(t, has6, "the IPv6 address must be present, even though it answered %v later",
		slowFamilyDelay)

	// The wait must be for the SLOW family, not a fixed grace period. Returning at ~50ms would
	// mean the IPv6 answer was dropped.
	require.GreaterOrEqual(t, elapsed, slowFamilyDelay,
		"Lookup returned before the slow family answered, so its result was dropped")

	// By the time Lookup returns, both exchanges have completed. The transport counted exactly
	// two queries, so neither family was abandoned mid-flight.
	require.EqualValues(t, 2, transport.queryCount.Load(),
		"both family queries must have completed before Lookup returned")
}

// TestLookupCancellationUnwindsBothFamilies is the lifecycle half of §11.
//
// When the context ends, BOTH family exchanges must exit rather than one continuing to run
// until its own timeout after Lookup has already returned.
func TestLookupCancellationUnwindsBothFamilies(t *testing.T) {
	// Both families block until the context ends, so neither can complete on its own.
	transport := &familySchedulingTransport{
		delayA:    -1,
		delayAAAA: -1,
	}
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()

	before := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{}, nil)
	require.Error(t, err, "a lookup whose families never answer must fail")

	// Give the unwinding a moment, then confirm the query goroutines are gone rather than
	// lingering until a multi-second timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines before=%d after=%d; a family query outlived Lookup",
		before, runtime.NumGoroutine())
}

// TestLookupHonoursCallerCancellationOverPartialSuccess is §45.
//
// A succeeds while AAAA is still blocked, and the caller then cancels. Lookup must report the
// cancellation rather than returning the partial answer with a nil error: the caller asked for the
// COMPLETE set, said so by using Lookup rather than the streaming path, and then withdrew the
// request. Returning [A], nil tells it the operation completed normally.
//
// This is distinct from an upstream family failure, where the caller's context is still live and a
// usable partial family is the correct answer - that case is covered separately below.
func TestLookupHonoursCallerCancellationOverPartialSuccess(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		fastIsAAAA  bool
		blockedType uint16
	}{
		{"A succeeds, AAAA blocked", false, mDNS.TypeAAAA},
		{"AAAA succeeds, A blocked", true, mDNS.TypeA},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			}
			if testCase.fastIsAAAA {
				// A blocks forever; AAAA answers at once.
				transport.delayA = -1
			} else {
				transport.delayAAAA = -1
			}

			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()

			ctx, cancel := context.WithCancel(context.Background())

			// Cancel once the fast family has had time to answer, so the lookup is genuinely
			// waiting on the blocked one when the caller withdraws.
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancel()
			}()

			_, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{
				Strategy: C.DomainStrategyPreferIPv4,
			}, func(response *mDNS.Msg) bool { return response.Rcode == mDNS.RcodeSuccess })

			require.Error(t, err,
				"the caller cancelled while the lookup was still waiting; returning a partial "+
					"answer with a nil error reports a completed operation")
			require.ErrorIs(t, err, context.Canceled,
				"the cancellation must be reported as such, got %v", err)
		})
	}
}

// TestLookupKeepsUsableFamilyWhenOtherFamilyFailsUpstream is §46.
//
// One family answers and the other returns SERVFAIL, with the caller's context still live. That is
// an ordinary partial result: the caller did not withdraw anything, and the usable family must
// still be returned. This is the compatibility boundary of the cancellation fix - the fix must
// react to the CALLER's lifecycle, not to any family-level error.
func TestLookupKeepsUsableFamilyWhenOtherFamilyFailsUpstream(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		failingV6 bool
	}{
		{"A succeeds, AAAA SERVFAIL", true},
		{"AAAA succeeds, A SERVFAIL", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &familySchedulingTransport{
				addressA:    "192.0.2.1",
				addressAAAA: "2001:db8::1",
			}
			if testCase.failingV6 {
				transport.servfailAAAA = true
			} else {
				transport.servfailA = true
			}

			client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			client.Start()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			addresses, err := client.Lookup(ctx, transport, "example.test.", adapter.DNSQueryOptions{
				Strategy: C.DomainStrategyPreferIPv4,
			}, func(response *mDNS.Msg) bool { return response.Rcode == mDNS.RcodeSuccess })

			require.NoError(t, err,
				"a SERVFAIL in one family with a live caller context is a partial result, not a "+
					"failed lookup")
			require.NotEmpty(t, addresses,
				"the family that answered must still be returned")
		})
	}
}
