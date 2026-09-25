package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func enabledLimits() option.UnauthenticatedLimits {
	return (&option.UnauthenticatedLimitsOptions{
		Enabled:            true,
		MaxConcurrentPerIP: 2,
		RequestsPerSecond:  1,
		Burst:              2,
		IdleTimeout:        badoption.Duration(time.Minute),
		MaxTrackedIPs:      16,
	}).Build()
}

func TestUnauthenticatedLimiterDisabled(t *testing.T) {
	limiter := newUnauthenticatedLimiter((&option.UnauthenticatedLimitsOptions{}).Build())
	if limiter != nil {
		t.Fatal("a disabled limiter must not be constructed")
	}
	// A nil limiter must allow everything.
	if !limiter.allowed("1.2.3.4:1000", time.Now()) {
		t.Fatal("a nil limiter must allow all traffic")
	}
	if limiter.trackedCount() != 0 {
		t.Fatal("a nil limiter must track nothing")
	}
}

func TestUnauthenticatedLimiterDefaultsApplied(t *testing.T) {
	limits := (&option.UnauthenticatedLimitsOptions{Enabled: true}).Build()
	if !limits.Enabled {
		t.Fatal("limiter must be enabled")
	}
	if limits.MaxConcurrentPerIP != option.DefaultUnauthenticatedMaxConcurrent {
		t.Fatalf("expected default concurrency, got %d", limits.MaxConcurrentPerIP)
	}
	if limits.RequestsPerSecond != option.DefaultUnauthenticatedRPS {
		t.Fatalf("expected default rps, got %v", limits.RequestsPerSecond)
	}
	if limits.Burst != option.DefaultUnauthenticatedBurst {
		t.Fatalf("expected default burst, got %d", limits.Burst)
	}
	if limits.IdleTimeout != option.DefaultUnauthenticatedIdleTimeout {
		t.Fatalf("expected default idle timeout, got %v", limits.IdleTimeout)
	}
	if limits.MaxTrackedIPs != option.DefaultUnauthenticatedMaxTrackedIPs {
		t.Fatalf("expected default tracked IP cap, got %d", limits.MaxTrackedIPs)
	}
}

// TestUnauthenticatedLimiterIgnoresPort is the key normalization rule: the
// budget is per IP, so opening many source ports must not multiply it.
func TestUnauthenticatedLimiterIgnoresPort(t *testing.T) {
	limiter := newUnauthenticatedLimiter(enabledLimits())
	now := time.Now()
	// Ports change, IP stays the same. Burst is 2, so the third must fail.
	if !limiter.allowed("1.2.3.4:1000", now) {
		t.Fatal("first request must be allowed")
	}
	if !limiter.allowed("1.2.3.4:2000", now) {
		t.Fatal("second request must be allowed")
	}
	if limiter.allowed("1.2.3.4:3000", now) {
		t.Fatal("the third request must be limited: the port must not create a new budget")
	}
	if limiter.trackedCount() != 1 {
		t.Fatalf("all ports of one IP must share one entry, got %d entries", limiter.trackedCount())
	}
}

// TestUnauthenticatedLimiterNormalizesIPv4MappedIPv6 ensures a host cannot
// double its budget by mixing address families.
func TestUnauthenticatedLimiterNormalizesIPv4MappedIPv6(t *testing.T) {
	limiter := newUnauthenticatedLimiter(enabledLimits())
	now := time.Now()
	if !limiter.allowed("1.2.3.4:1000", now) {
		t.Fatal("first IPv4 request must be allowed")
	}
	if !limiter.allowed("[::ffff:1.2.3.4]:2000", now) {
		t.Fatal("second request must be allowed")
	}
	if limiter.allowed("[::ffff:1.2.3.4]:3000", now) {
		t.Fatal("IPv4-mapped IPv6 must share the IPv4 budget")
	}
	if limiter.trackedCount() != 1 {
		t.Fatalf("mapped and plain IPv4 must share one entry, got %d", limiter.trackedCount())
	}
}

func TestUnauthenticatedLimiterDistinctIPv6Budgets(t *testing.T) {
	limiter := newUnauthenticatedLimiter(enabledLimits())
	now := time.Now()
	if !limiter.allowed("[2001:db8::1]:1000", now) {
		t.Fatal("first IPv6 host must be allowed")
	}
	// A different IPv6 address has its own budget.
	if !limiter.allowed("[2001:db8::2]:1000", now) {
		t.Fatal("second IPv6 host must be allowed")
	}
	if limiter.trackedCount() != 2 {
		t.Fatalf("distinct IPv6 hosts must be tracked separately, got %d", limiter.trackedCount())
	}
}

func TestUnauthenticatedLimiterBurstThenRefill(t *testing.T) {
	limiter := newUnauthenticatedLimiter(enabledLimits())
	now := time.Now()
	for index := range 2 {
		if !limiter.allowed("1.2.3.4:1000", now) {
			t.Fatalf("request %d must be within burst", index+1)
		}
	}
	if limiter.allowed("1.2.3.4:1000", now) {
		t.Fatal("burst must be exhausted")
	}
	// After enough time for one token (rps=1) the request is allowed again.
	if !limiter.allowed("1.2.3.4:1000", now.Add(1100*time.Millisecond)) {
		t.Fatal("a refilled token must allow the next request")
	}
	// Tokens never exceed the burst.
	later := now.Add(time.Hour)
	if !limiter.allowed("1.2.3.4:1000", later) {
		t.Fatal("refilled tokens must allow a request")
	}
}

func TestUnauthenticatedLimiterConcurrencyPerIP(t *testing.T) {
	limits := enabledLimits()
	limits.RequestsPerSecond = 1000
	limits.Burst = 1000
	limits.MaxConcurrentPerIP = 3
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	var releases []func()
	for index := range 3 {
		release, allowed := limiter.acquire("1.2.3.4:1000", now)
		if !allowed {
			t.Fatalf("request %d must be within the concurrency limit", index+1)
		}
		releases = append(releases, release)
	}
	// The fourth concurrent request for the same IP must be rejected.
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("the concurrency limit must reject the fourth in-flight request")
	}
	// A different IP is unaffected.
	if _, allowed := limiter.acquire("5.6.7.8:1000", now); !allowed {
		t.Fatal("another IP must not be affected by the first IP's concurrency")
	}
	// Releasing frees a slot.
	releases[0]()
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); !allowed {
		t.Fatal("releasing must free a concurrency slot")
	}
}

func TestUnauthenticatedLimiterReleaseIsIdempotent(t *testing.T) {
	limits := enabledLimits()
	limits.MaxConcurrentPerIP = 1
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()
	release, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("first request must be allowed")
	}
	release()
	release()
	release()
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); !allowed {
		t.Fatal("concurrency must not go negative after repeated release")
	}
}

// TestLimiterReleaseIsTrulyPerAcquisitionIdempotent is the regression test for a
// real bug in the release closure.
//
// The old release decremented "whatever slot this IP currently holds":
//
//	release := func() {
//	    lock
//	    if current.concurrent > 0 { current.concurrent-- }
//	}
//
// That only prevents the counter going negative. It is NOT idempotent per
// acquisition: with max_concurrent_per_ip=2 and requests A and B both holding a
// slot, a second A.release() decrements again and frees B's slot, so a THIRD
// request is admitted while B is still running. This test pins the correct
// behaviour: one acquisition may release at most once, and another
// acquisition's slot is never touched.
func TestLimiterReleaseIsTrulyPerAcquisitionIdempotent(t *testing.T) {
	limits := enabledLimits()
	limits.MaxConcurrentPerIP = 2
	// A generous bucket so the concurrency limit, not the token limit, is what
	// rejects requests here.
	limits.Burst = 100
	limits.RequestsPerSecond = 100
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	releaseA, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("A must be admitted")
	}
	releaseB, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("B must be admitted while the limit is 2")
	}
	// Both slots are now held, so the account is full. This baseline is what
	// makes the post-release assertion meaningful: any decrement beyond A's own
	// single slot is observable as an extra admission.
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("the third concurrent request must be refused before any release")
	}

	// A releases three times, but only the first may take effect. Exactly one
	// slot is freed, so exactly one further request fits -- and a second one must
	// still be refused because B has not released.
	//
	// Under the old release semantics each extra call decremented again, so both
	// of A's extra calls wrongly freed B's slot and TWO further requests were
	// admitted while B was still running.
	releaseA()
	releaseA()
	releaseA()

	releaseC, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("A's single legitimate release must free exactly one slot")
	}
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("a repeated release of A must not free B's slot: the account is full " +
			"again once C takes A's freed slot, so this request must be rejected " +
			"while B is still running")
	}

	// Repeating C's release must not free anything else either. At this point
	// only B holds a slot, so exactly one more request fits and the one after
	// that must still be refused.
	releaseC()
	releaseC()
	releaseC2, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("the slot freed by A must still be reusable after C released it")
	}
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("a repeated release of C must not free B's slot")
	}
	_ = releaseC2

	// Now B really finishes, freeing the last held slot.
	releaseB()
	releaseD, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("after B releases, a new request must be admitted")
	}
	// B's release was one-shot, so repeating it must not free D's slot.
	releaseB()
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("a repeated release of B must not free another acquisition's slot")
	}

	// D's repeated release is also a no-op, and the counter must never have gone
	// negative: with everything released, two requests fit and the third does not.
	releaseD()
	releaseD()
	releaseE, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("with nothing in flight a new request must be admitted; a negative " +
			"concurrency counter would show up here")
	}
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("the second slot must be available after a clean release")
	}
	if _, allowed := limiter.acquire("1.2.3.4:1000", now); allowed {
		t.Fatal("the concurrency limit must still be enforced after all the releases")
	}
	releaseE()
}

// TestUnauthenticatedLimiterExpiry verifies idle entries are reclaimed so the
// map does not grow without bound over time.
//
// Expiry is amortized rather than per-request, so the sweep is driven by enough
// acquisitions or by the map reaching its cap. Doing it on every request made
// acquire O(tracked IPs) per request.
func TestUnauthenticatedLimiterExpiry(t *testing.T) {
	limits := enabledLimits()
	limits.IdleTimeout = 10 * time.Second
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()
	if !limiter.allowed("1.2.3.4:1000", now) {
		t.Fatal("first request must be allowed")
	}
	if limiter.trackedCount() != 1 {
		t.Fatalf("expected 1 tracked IP, got %d", limiter.trackedCount())
	}
	// Enough later traffic from another IP to trigger the periodic sweep.
	later := now.Add(time.Minute)
	for range cleanupInterval {
		limiter.allowed("5.6.7.8:1000", later)
	}
	if limiter.trackedCount() != 1 {
		t.Fatalf("the idle entry must have expired, got %d entries", limiter.trackedCount())
	}
}

// TestUnauthenticatedLimiterDoesNotSweepEveryRequest proves the amortized-expiry
// claim directly: a single request must not cost O(tracked IPs).
//
// Sweeping on every acquire made the limiter's hot path linear in the number of
// tracked addresses, so with max_tracked_ips=4096 every request scanned 4096
// entries while holding the mutex. This test fills the map well past
// cleanupInterval with entries that are NOT idle-expired, then measures how many
// entries the expiry sweeps walked across a small number of requests.
//
// The assertion is on the total visited count rather than on the counter value,
// so it cannot be satisfied by a sweep that happens to run at a different time:
// if expiry went back to running on every acquire, each request would visit every
// tracked entry and the total would immediately exceed the bound below.
func TestUnauthenticatedLimiterDoesNotSweepEveryRequest(t *testing.T) {
	limits := enabledLimits()
	limits.IdleTimeout = time.Hour // nothing should expire during this test
	limits.MaxTrackedIPs = 4096
	limits.RequestsPerSecond = 100000
	limits.Burst = 100000
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	const tracked = 1000
	for index := range tracked {
		limiter.allowed(fmt.Sprintf("10.%d.%d.1:1000", index/256, index%256), now)
	}
	if count := limiter.trackedCount(); count < cleanupInterval {
		t.Fatalf("precondition: expected more than %d tracked IPs, got %d", cleanupInterval, count)
	}
	if limiter.trackedCount() == 0 {
		t.Fatal("entries must not be reclaimed while they are not idle-expired")
	}

	// Measure only the requests issued after the map was filled.
	visitedBefore := limiter.visitedCount()
	const requests = 16
	for index := range requests {
		limiter.allowed(fmt.Sprintf("172.16.0.%d:1000", index), now)
	}
	visited := limiter.visitedCount() - visitedBefore

	// At most one sweep may occur in 16 acquisitions (cleanupInterval is 256), so
	// the total entries walked cannot exceed one pass over the map. Per-request
	// sweeping would walk requests*tracked = 16,000 entries.
	if maxVisited := limiter.trackedCount(); visited > maxVisited {
		t.Fatalf("expiry should be amortized: %d requests visited %d entries, "+
			"which is more than one pass over the %d tracked IPs",
			requests, visited, maxVisited)
	}
}

func TestUnauthenticatedLimiterDoesNotExpireInFlightEntries(t *testing.T) {
	limits := enabledLimits()
	limits.IdleTimeout = time.Millisecond
	limits.RequestsPerSecond = 0.0001
	limits.Burst = 1
	limits.MaxConcurrentPerIP = 10
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()
	release, allowed := limiter.acquire("1.2.3.4:1000", now)
	if !allowed {
		t.Fatal("first request must be allowed")
	}
	// Time passes well beyond the idle timeout while still in flight.
	later := now.Add(time.Hour)
	if !limiter.allowed("5.6.7.8:1000", later) {
		t.Fatal("second IP must be allowed")
	}
	if limiter.trackedCount() != 2 {
		t.Fatalf("an in-flight entry must not be expired, got %d entries", limiter.trackedCount())
	}
	release()
}

// TestUnauthenticatedLimiterTrackedIPCap is the anti-map-exhaustion defence: a
// flood from random addresses must not grow the map without bound.
func TestUnauthenticatedLimiterTrackedIPCap(t *testing.T) {
	limits := enabledLimits()
	limits.MaxTrackedIPs = 8
	limits.RequestsPerSecond = 1000
	limits.Burst = 1000
	limiter := newUnauthenticatedLimiter(limits)
	now := time.Now()

	for index := range 500 {
		source := fmt.Sprintf("10.0.%d.%d:1000", index/256, index%256)
		limiter.allowed(source, now.Add(time.Duration(index)*time.Millisecond))
		if count := limiter.trackedCount(); count > limits.MaxTrackedIPs {
			t.Fatalf("tracked IP count %d exceeded the cap %d", count, limits.MaxTrackedIPs)
		}
	}
	if count := limiter.trackedCount(); count > limits.MaxTrackedIPs {
		t.Fatalf("final tracked IP count %d exceeded the cap %d", count, limits.MaxTrackedIPs)
	}
}

func TestUnauthenticatedLimiterConcurrentAccess(t *testing.T) {
	limits := enabledLimits()
	limits.MaxTrackedIPs = 64
	limits.RequestsPerSecond = 1000
	limits.Burst = 1000
	limits.MaxConcurrentPerIP = 1000
	limiter := newUnauthenticatedLimiter(limits)
	var waitGroup sync.WaitGroup
	for worker := range 16 {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			now := time.Now()
			for index := range 200 {
				source := fmt.Sprintf("10.0.%d.%d:1000", worker, index%256)
				release, allowed := limiter.acquire(source, now)
				if allowed {
					release()
				}
			}
		}(worker)
	}
	waitGroup.Wait()
	if count := limiter.trackedCount(); count > limits.MaxTrackedIPs {
		t.Fatalf("tracked IP count %d exceeded the cap under concurrency", count)
	}
}

func TestNormalizedIP(t *testing.T) {
	testCases := []struct {
		source   string
		expected string
		valid    bool
	}{
		{source: "1.2.3.4:1000", expected: "1.2.3.4", valid: true},
		{source: "1.2.3.4", expected: "1.2.3.4", valid: true},
		{source: "[::ffff:1.2.3.4]:80", expected: "1.2.3.4", valid: true},
		{source: "[2001:db8::1]:443", expected: "2001:db8::1", valid: true},
		{source: "", valid: false},
		{source: "not-an-ip:80", valid: false},
	}
	for _, testCase := range testCases {
		address, valid := normalizedIP(testCase.source)
		if valid != testCase.valid {
			t.Fatalf("%q: validity got %v, want %v", testCase.source, valid, testCase.valid)
		}
		if valid && address.String() != testCase.expected {
			t.Fatalf("%q: got %q, want %q", testCase.source, address.String(), testCase.expected)
		}
	}
}

// TestUnauthenticatedLimiterNeverEmitsAuthChallenge is the anti-fingerprinting
// requirement: a rejected request must never look like a proxy rejection.
func TestUnauthenticatedLimiterNeverEmitsAuthChallenge(t *testing.T) {
	limits := enabledLimits()
	limits.RequestsPerSecond = 0.0001
	limits.Burst = 1
	limits.MaxConcurrentPerIP = 1
	handler := &httpHandler{server: &Server{
		logger:                 testLogger(),
		overLimitDecoy:         NewOverLimitDecoy(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: newUnauthenticatedLimiter(limits),
	}}
	source := parseSource(t, "1.2.3.4:5000")
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.rejectUnauthenticated(testContext(), recorder, request, source)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", recorder.Code)
	}
	if value := recorder.Header().Get("Proxy-Authenticate"); value != "" {
		t.Fatalf("must not emit Proxy-Authenticate, got %q", value)
	}
	if value := recorder.Header().Get("WWW-Authenticate"); value != "" {
		t.Fatalf("must not emit WWW-Authenticate, got %q", value)
	}
	if recorder.Code == http.StatusProxyAuthRequired {
		t.Fatal("must not return 407")
	}
	if recorder.Code == http.StatusUnauthorized {
		t.Fatal("must not return 401")
	}
	// And it must look like an ordinary web server response.
	if !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected an html response, got %q", recorder.Header().Get("Content-Type"))
	}
	if !strings.Contains(recorder.Body.String(), "429") {
		t.Fatalf("expected a 429 body, got %q", recorder.Body.String())
	}
}

// TestUnauthenticatedLimiterDoesNotHitMasqueradeBackend is the P0-6 assertion.
//
// The limiter exists to bound the resources an unauthenticated peer consumes.
// Serving the proxy masquerade over-limit would still issue one backend request
// per probe, so the backend must stop receiving traffic once the budget is
// exhausted. This counts real backend hits.
func TestUnauthenticatedLimiterDoesNotHitMasqueradeBackend(t *testing.T) {
	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		backendHits.Add(1)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("decoy site"))
	}))
	defer backend.Close()

	masquerade, masqueradeErr := NewMasqueradeHandler(context.Background(), &option.Hysteria2Masquerade{
		Type: "proxy",
		ProxyOptions: option.Hysteria2MasqueradeProxy{
			URL:         backend.URL,
			RewriteHost: true,
		},
	})
	if masqueradeErr != nil {
		t.Fatalf("build masquerade: %v", masqueradeErr)
	}

	limits := enabledLimits()
	limits.RequestsPerSecond = 0.0001
	limits.Burst = 1
	limits.MaxConcurrentPerIP = 1
	server := &Server{
		logger:                 testLogger(),
		masquerade:             masquerade,
		overLimitDecoy:         NewOverLimitDecoy(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: newUnauthenticatedLimiter(limits),
	}
	handler := &httpHandler{server: server}
	source := parseSource(t, "1.2.3.4:5000")
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	// The first unauthenticated request is within budget and legitimately reaches
	// the masquerade backend.
	release, overLimit := handler.admitUnauthenticated(source)
	if overLimit {
		t.Fatal("the first request must be within budget")
	}
	recorder := httptest.NewRecorder()
	server.masquerade.ServeHTTP(recorder, request)
	release()
	if hits := backendHits.Load(); hits != 1 {
		t.Fatalf("an in-budget masquerade request is expected to reach the backend once, got %d", hits)
	}

	// Every later request is over budget. Each must be answered locally.
	for index := range 10 {
		release, overLimit = handler.admitUnauthenticated(source)
		if !overLimit {
			t.Fatalf("request %d must be over budget", index+2)
		}
		recorder = httptest.NewRecorder()
		handler.rejectUnauthenticated(testContext(), recorder, request, source)
		release()
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", recorder.Code)
		}
		if value := recorder.Header().Get("Proxy-Authenticate"); value != "" {
			t.Fatalf("must not emit Proxy-Authenticate, got %q", value)
		}
	}
	if hits := backendHits.Load(); hits != 1 {
		t.Fatalf("an over-limit request must NOT reach the masquerade backend; backend hits rose to %d", hits)
	}
}

// TestUnauthenticatedLimiterDoesNotBlockBeforeAuthentication is the critical
// correctness rule: exceeding the unauthenticated budget must not, by itself,
// refuse a request. Only a failed authentication combined with an exceeded
// budget is rejected, so a legitimate client that reconnects frequently is
// never denied service.
func TestUnauthenticatedLimiterDoesNotBlockBeforeAuthentication(t *testing.T) {
	limits := enabledLimits()
	limits.RequestsPerSecond = 0.0001
	limits.Burst = 1
	limits.MaxConcurrentPerIP = 1
	handler := &httpHandler{server: &Server{
		logger:                 testLogger(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: newUnauthenticatedLimiter(limits),
	}}
	source := parseSource(t, "1.2.3.4:5000")

	// Consume the budget.
	release, overLimit := handler.admitUnauthenticated(source)
	if overLimit {
		t.Fatal("the first request must be within budget")
	}
	release()

	// Every subsequent request is flagged over budget, but the flag alone must
	// never produce a response: the caller still attempts authentication.
	release, overLimit = handler.admitUnauthenticated(source)
	release()
	if !overLimit {
		t.Fatal("the budget must be reported as exceeded")
	}
	// There is no writer involved, proving admission does not answer.
}

// TestUnauthenticatedLimiterDisabledAdmitsEverything checks that no limiter
// means no accounting and no rejection.
func TestUnauthenticatedLimiterDisabledAdmitsEverything(t *testing.T) {
	handler := &httpHandler{server: &Server{logger: testLogger()}}
	source := parseSource(t, "1.2.3.4:5000")
	for range 100 {
		release, overLimit := handler.admitUnauthenticated(source)
		release()
		if overLimit {
			t.Fatal("without a limiter nothing may be reported as over budget")
		}
	}
}

// TestUnauthenticatedLimiterNotConstructedWhenDisabled checks the whole server
// path: an unset or disabled option installs no limiter, so upstream behaviour
// is preserved.
func TestUnauthenticatedLimiterNotConstructedWhenDisabled(t *testing.T) {
	for _, options := range []*option.UnauthenticatedLimitsOptions{nil, {Enabled: false}} {
		server := NewServer(ServerOptions{
			Logger:                testLogger(),
			UnauthenticatedLimits: options,
		})
		if server.unauthenticatedLimiter != nil {
			t.Fatal("a disabled or absent limiter must not be installed")
		}
	}
}

func TestUnauthenticatedLimiterConstructedWhenEnabled(t *testing.T) {
	server := NewServer(ServerOptions{
		Logger: testLogger(),
		UnauthenticatedLimits: &option.UnauthenticatedLimitsOptions{
			Enabled: true,
		},
	})
	if server.unauthenticatedLimiter == nil {
		t.Fatal("an enabled limiter must be installed")
	}
}

// testLogger returns a discard logger for handler tests.
func testLogger() logger.ContextLogger {
	return log.NewNOPFactory().Logger()
}

func testContext() context.Context {
	return context.Background()
}

func parseSource(t *testing.T, source string) M.Socksaddr {
	t.Helper()
	return M.ParseSocksaddr(source)
}

// TestAuthenticatedRequestsNeverTouchTheLimiter is the regression for the
// limiter's most important property.
//
// An authenticated proxy request must not acquire a slot, consume a token, or
// consult the limiter map at all. Acquiring before authenticating made legitimate
// traffic pay for the limiter and could delay it under abuse.
//
// The test drives the REAL handler (httpHandler.ServeHTTP) with valid
// credentials while the limiter is already saturated, and proves the limiter
// state was never touched by comparing a snapshot of it before and after.
func TestAuthenticatedRequestsNeverTouchTheLimiter(t *testing.T) {
	limits := enabledLimits()
	limits.RequestsPerSecond = 0
	limits.Burst = 0
	limits.MaxConcurrentPerIP = 1
	limiter := newUnauthenticatedLimiter(limits)
	server := &Server{
		logger:                 testLogger(),
		authenticator:          auth.NewAuthenticator([]auth.User{{Username: "user", Password: "pass"}}),
		overLimitDecoy:         NewOverLimitDecoy(),
		masquerade:             countingMasquerade(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: limiter,
	}
	handler := &httpHandler{server: server, handler: closingHandler{}}

	request := httptest.NewRequest(http.MethodConnect, "http://203.0.113.77:8080", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
	request.RemoteAddr = "203.0.113.9:1234"

	limiter.access.Lock()
	statesBefore := len(limiter.states)
	acquisitionsBefore := limiter.acquisitions
	limiter.access.Unlock()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusTooManyRequests {
		t.Fatal("an authenticated request must never be answered by the over-limit decoy")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("an authenticated CONNECT is expected to be accepted, got %d", recorder.Code)
	}

	limiter.access.Lock()
	statesAfter := len(limiter.states)
	acquisitionsAfter := limiter.acquisitions
	limiter.access.Unlock()

	if statesAfter != statesBefore {
		t.Fatalf("an authenticated request must not create limiter state: %d -> %d",
			statesBefore, statesAfter)
	}
	if acquisitionsAfter != acquisitionsBefore {
		t.Fatalf("an authenticated request must not be accounted by the limiter: %d -> %d",
			acquisitionsBefore, acquisitionsAfter)
	}
}

// TestFailedAuthenticationIsAccounted proves the mirror case: a failed
// authentication IS accounted, otherwise the limiter would never engage.
func TestFailedAuthenticationIsAccounted(t *testing.T) {
	limits := enabledLimits()
	limits.RequestsPerSecond = 0
	limits.Burst = 0
	limits.MaxConcurrentPerIP = 1
	limiter := newUnauthenticatedLimiter(limits)
	server := &Server{
		logger:                 testLogger(),
		authenticator:          auth.NewAuthenticator([]auth.User{{Username: "user", Password: "pass"}}),
		overLimitDecoy:         NewOverLimitDecoy(),
		masquerade:             countingMasquerade(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: limiter,
	}
	handler := &httpHandler{server: server}

	request := httptest.NewRequest(http.MethodConnect, "http://203.0.113.77:8080", nil)
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:wrong")))
	// The limiter is keyed on the TRANSPORT PEER, not on X-Forwarded-For. The
	// header is set here to prove it is ignored: if it were trusted, a client
	// could rotate it to obtain a fresh budget for every request and the limiter
	// would never engage.
	request.Header.Set("X-Forwarded-For", "203.0.113.9")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if limiter.accountedCount() != 1 {
		t.Fatalf("a failed authentication must be accounted exactly once, got %d", limiter.accountedCount())
	}
	if rec := recorder.Result(); rec.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("an over-budget failure is expected to be answered by the local decoy, got %d", rec.StatusCode)
	}
}

// closingHandler accepts a tunnel and immediately closes it, which is what
// releases serveConnect. discardHandler (used elsewhere) accepts and never
// closes, so it would block this test forever.
type closingHandler struct{}

func (closingHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	onClose(nil)
}

func (closingHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	onClose(nil)
}

// countingMasquerade is a masquerade handler that succeeds without any backend
// network access.
func countingMasquerade() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
}

// TestUnauthenticatedBodyIsBounded proves the request body an unauthenticated
// peer can push at the decoy backend is actually capped.
//
// The proxy masquerade forwards the request to a real backend, so without a
// bound a failed-authentication request could stream an arbitrarily large body
// through it and consume unbounded server resources. maxUnauthenticatedBodyBytes
// bounds that body; this test drives the real handler and measures how many bytes
// the backend actually receives.
func TestUnauthenticatedBodyIsBounded(t *testing.T) {
	var received atomic.Int64
	backendDone := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		count, _ := io.Copy(io.Discard, request.Body)
		received.Store(count)
		writer.WriteHeader(http.StatusOK)
		select {
		case backendDone <- struct{}{}:
		default:
		}
	}))
	defer backend.Close()

	masquerade, masqueradeErr := NewMasqueradeHandler(context.Background(), &option.Hysteria2Masquerade{
		Type: "proxy",
		ProxyOptions: option.Hysteria2MasqueradeProxy{
			URL:         backend.URL,
			RewriteHost: true,
		},
	})
	require.NoError(t, masqueradeErr)

	server := &Server{
		logger:                 testLogger(),
		authenticator:          auth.NewAuthenticator([]auth.User{{Username: "user", Password: "pass"}}),
		masquerade:             masquerade,
		overLimitDecoy:         NewOverLimitDecoy(),
		maxHeaderBytes:         1 << 20,
		unauthenticatedLimiter: newUnauthenticatedLimiter(enabledLimits()),
	}
	handler := &httpHandler{server: server}

	// Ten times the bound, so the cap is unambiguously the limiting factor.
	const offered = 10 * maxUnauthenticatedBodyBytes
	request := httptest.NewRequest(http.MethodPost, backend.URL+"/upload", strings.NewReader(strings.Repeat("x", offered)))
	request.Header.Set("X-Forwarded-For", "203.0.113.9")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	// The reverse proxy copies the body asynchronously, so wait for the backend
	// to finish reading before sampling the byte count. Without this the
	// assertion races the transfer and can observe a partial count.
	select {
	case <-backendDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the backend never finished reading the body")
	}
	// The backend is reached, so the request is genuinely in budget and the
	// cap -- not the limiter -- is what stops the body.
	count := received.Load()
	if count == 0 {
		t.Fatal("the in-budget unauthenticated request is expected to reach the backend")
	}
	if count > maxUnauthenticatedBodyBytes {
		t.Fatalf("the backend received %d bytes, which exceeds the %d byte bound",
			count, int64(maxUnauthenticatedBodyBytes))
	}
	// http.MaxBytesReader aborts the transfer at the bound, so the backend sees
	// exactly the bound rather than a truncated tail. Proving the exact value is
	// what shows the cap is enforced on the data path instead of the body simply
	// having been dropped.
	if count != maxUnauthenticatedBodyBytes {
		t.Fatalf("expected the backend to receive exactly the %d byte bound, got %d",
			int64(maxUnauthenticatedBodyBytes), count)
	}
}
