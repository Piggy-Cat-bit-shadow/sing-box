package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
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

// TestUnauthenticatedLimiterExpiry verifies idle entries are reclaimed so the
// map does not grow without bound over time.
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
	// A later request from another IP triggers expiry of the idle entry.
	limiter.allowed("5.6.7.8:1000", now.Add(time.Minute))
	if limiter.trackedCount() != 1 {
		t.Fatalf("the idle entry must have expired, got %d entries", limiter.trackedCount())
	}
}

// TestUnauthenticatedLimiterDoesNotExpireInFlightEntries makes sure an IP
// cannot reset its own budget by simply waiting while a request is in flight.
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
// requirement: when the limiter rejects a request it must never answer with
// 401/407 or an authentication header.
func TestUnauthenticatedLimiterNeverEmitsAuthChallenge(t *testing.T) {
	testCases := []struct {
		name       string
		masquerade http.Handler
	}{
		{name: "without masquerade"},
		{name: "with masquerade", masquerade: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/html")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("<html>normal site</html>"))
		})},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			limits := enabledLimits()
			limits.RequestsPerSecond = 0.0001
			limits.Burst = 1
			limits.MaxConcurrentPerIP = 1
			server := &Server{
				logger:                 testLogger(),
				masquerade:             testCase.masquerade,
				maxHeaderBytes:         1 << 20,
				unauthenticatedLimiter: newUnauthenticatedLimiter(limits),
			}
			handler := &httpHandler{server: server}
			source := parseSource(t, "1.2.3.4:5000")

			assertNoAuthChallenge := func(recorder *httptest.ResponseRecorder) {
				t.Helper()
				if recorder.Code == http.StatusUnauthorized || recorder.Code == http.StatusProxyAuthRequired {
					t.Fatalf("limiter must never return %d", recorder.Code)
				}
				if value := recorder.Header().Get("WWW-Authenticate"); value != "" {
					t.Fatalf("limiter must never emit WWW-Authenticate, got %q", value)
				}
				if value := recorder.Header().Get("Proxy-Authenticate"); value != "" {
					t.Fatalf("limiter must never emit Proxy-Authenticate, got %q", value)
				}
			}

			// First request consumes the single token.
			firstRecorder := httptest.NewRecorder()
			release, limited := handler.admitUnauthenticated(testContext(), firstRecorder, source)
			if limited {
				t.Fatal("the first request must be admitted")
			}
			release()

			// Second request exceeds the budget.
			secondRecorder := httptest.NewRecorder()
			_, limited = handler.admitUnauthenticated(testContext(), secondRecorder, source)
			if !limited {
				t.Fatal("the second request must be limited")
			}
			assertNoAuthChallenge(secondRecorder)

			if testCase.masquerade != nil {
				if secondRecorder.Code != http.StatusOK {
					t.Fatalf("a limited request must receive the masquerade response, got %d", secondRecorder.Code)
				}
				if !strings.Contains(secondRecorder.Body.String(), "normal site") {
					t.Fatalf("expected the masquerade body, got %q", secondRecorder.Body.String())
				}
			} else if secondRecorder.Code != http.StatusTooManyRequests {
				t.Fatalf("without masquerade a limited request must be a generic 429, got %d", secondRecorder.Code)
			}
		})
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
