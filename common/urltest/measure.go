package urltest

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// MeasureOptions describes one measurement request.
type MeasureOptions struct {
	// Link is the target. Empty means DefaultURLTestURL.
	Link string
	// ExpectedStatus is the accepted HTTP status set. Empty accepts any status.
	ExpectedStatus ExpectedStatus
}

// Measurement is the outcome of one successful measurement.
type Measurement struct {
	// Delay is the measured round trip in milliseconds, always at least 1 on success.
	Delay uint16
	// StatusCode is the HTTP status of the response the delay was measured against.
	StatusCode int
	// Scope identifies the target this measurement belongs to, so callers can store the result
	// without re-deriving the key and risking a different normalisation.
	Scope MeasurementScope
}

// URLTest measures a node's delay, preserving the historical signature.
//
// It is a compatibility wrapper over Measure: the timing lives in exactly one place, so the
// Clash API, the native API and the URLTest group cannot drift apart.
func URLTest(ctx context.Context, link string, detour N.Dialer) (uint16, error) {
	result, err := Measure(ctx, MeasureOptions{Link: link}, detour)
	if err != nil {
		return 0, err
	}
	return result.Delay, nil
}

// Measure performs one unified-delay measurement.
//
// (The displayed delay follows Mihomo unified-delay=true semantics: the first HEAD warms the
// proxy, TCP, TLS and HTTP path, and the second HEAD - reusing the same transport - is the one
// timed. This is a proxy round-trip measurement, not an ICMP ping and not a physical link RTT.)
//
// # The algorithm
//
//	dial once
//	one http.Transport + one http.Client
//	HEAD #1                     <- warm-up, NOT timed
//	secondStart := now
//	HEAD #2                     <- timed, reusing the same connection
//	delay = now - secondStart
//
// The first request pays the fixed costs - proxy handshake, lazy handshake, target connect, TLS,
// multiplex session setup - so two nodes with very different handshake prices report comparable
// steady-state numbers. No protocol-specific clock reset is needed, and there is none.
//
// # Failure handling
//
// The warm-up must succeed; if it does not there is nothing to measure.
//
// The second request failing is treated as a Mihomo fallback ONLY when the failure is not caused
// by the caller's context or by a timeout. A cancelled or expired measurement is reported as an
// error, because a caller that has stopped waiting must not be handed a success - doing so
// produced a "successful" history entry for a request the Clash layer had already reported as a
// timeout, and inside the URLTest group it raced against the batch's own context.
func Measure(ctx context.Context, options MeasureOptions, detour N.Dialer) (Measurement, error) {
	normalized, err := NormalizeURLTestURL(options.Link)
	if err != nil {
		return Measurement{}, err
	}
	scope := MeasurementScope{URL: normalized, Expected: options.ExpectedStatus.Canonical()}

	// One debug snapshot for the whole measurement, so a concurrent SetDebugLogger cannot make
	// the first request log through one logger and the second through another.
	// Loaded once for the whole measurement, so the first and second requests cannot log through
	// different loggers if SetDebugLogger runs concurrently.
	debug := currentDebugConfig.Load()
	debugEnabled := debug != nil && debug.enabled && debug.logger != nil

	parsed, err := url.Parse(normalized)
	if err != nil {
		return Measurement{}, err
	}
	destination := M.ParseSocksaddrHostPortStr(parsed.Hostname(), urlTestPort(parsed))

	// measurementStart is used only by the fallback path, which reports the whole attempt's cost.
	measurementStart := time.Now()

	// One dial for the whole measurement; both requests share it through the transport below.
	dialStart := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", destination)
	if err != nil {
		return Measurement{}, err
	}
	defer instance.Close()
	dialElapsed := time.Since(dialStart)

	// ONE transport for both requests. A second transport, or closing this one in between, would
	// force the second request to dial and handshake again - exactly the cost the warm-up exists
	// to exclude.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return instance, nil
		},
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
	}
	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()

	// firstStatus is the response the fallback path reports if the second request fails.
	var firstStatus int

	// --- request 1: the warm-up, not timed ---
	firstRequest, err := http.NewRequest(http.MethodHead, normalized, nil)
	if err != nil {
		return Measurement{}, err
	}
	// The phase duration is only meaningful for the debug line, so it is only computed when that
	// line will be emitted. The timer itself is two instructions, but computing it unconditionally
	// would be work the disabled path never uses.
	var firstElapsed time.Duration
	if debugEnabled {
		firstStart := time.Now()
		firstResponse, firstErr := client.Do(firstRequest.WithContext(ctx))
		firstElapsed = time.Since(firstStart)
		if firstErr != nil {
			return Measurement{}, firstErr
		}
		firstResponse.Body.Close()
		firstStatus = firstResponse.StatusCode
	} else {
		firstResponse, firstErr := client.Do(firstRequest.WithContext(ctx))
		if firstErr != nil {
			return Measurement{}, firstErr
		}
		firstResponse.Body.Close()
		firstStatus = firstResponse.StatusCode
	}

	// --- request 2: the measured one ---
	secondRequest, err := http.NewRequest(http.MethodHead, normalized, nil)
	if err != nil {
		return Measurement{}, err
	}
	secondStart := time.Now()
	secondResponse, secondErr := client.Do(secondRequest.WithContext(ctx))
	if secondErr == nil {
		secondResponse.Body.Close()
		if !options.ExpectedStatus.Match(secondResponse.StatusCode) {
			return Measurement{}, statusMismatch(options.ExpectedStatus, secondResponse.StatusCode, scope)
		}
		warmElapsed := time.Since(secondStart)
		if debugEnabled {
			debug.logger.Debug("urltest dial=", dialElapsed, " first_request=", firstElapsed,
				" warm_request=", warmElapsed, " warm_reused=assumed")
		}
		return Measurement{
			Delay:      durationToDelay(warmElapsed),
			StatusCode: secondResponse.StatusCode,
			Scope:      scope,
		}, nil
	}

	// The second request failed. Whether that is a usable fallback or a real failure depends on
	// WHY it failed; see shouldFallbackSecondRequest.
	if !shouldFallbackSecondRequest(ctx, secondErr) {
		return Measurement{}, secondErr
	}
	if !options.ExpectedStatus.Match(firstStatus) {
		// The fallback's response does not satisfy the caller, so there is nothing to report.
		return Measurement{}, statusMismatch(options.ExpectedStatus, firstStatus, scope)
	}
	if debugEnabled {
		debug.logger.Debug("urltest dial=", dialElapsed, " first_request=", firstElapsed,
			" warm_request=failed", " fallback=first_path")
	}
	return Measurement{
		Delay:      durationToDelay(time.Since(measurementStart)),
		StatusCode: firstStatus,
		Scope:      scope,
	}, nil
}

// statusMismatch reports an expected-status failure without leaking response bodies or dial state.
func statusMismatch(expected ExpectedStatus, actual int, scope MeasurementScope) error {
	return E.New("unexpected status ", actual, " for ", scope.URL, ", expected ", expected.Canonical())
}

// shouldFallbackSecondRequest reports whether a failed second request is the Mihomo repeat-request
// incompatibility rather than the caller's own deadline.
//
// # Why this distinction exists
//
// Mihomo falls back to the first request's timing when the second fails, on the grounds that a
// node which answered once is not down. That reading is right for a repeat-request failure - a
// connection reset, an EOF, a server that closes keep-alive connections - and wrong for a
// cancellation, where the node was never given a chance to answer.
//
// Without this check the two were indistinguishable, so a measurement the caller had already
// abandoned was recorded as a success. In the Clash API that meant an HTTP timeout response
// alongside a successful history entry; in the URLTest group it meant the batch context expiring
// while the result channel was also ready, and Go choosing between them at random.
//
// The caller's context is consulted FIRST: a request that failed because the context ended must
// be reported as ended, whatever error the HTTP layer wrapped it in.
func shouldFallbackSecondRequest(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return true
}

// durationToDelay converts a duration to the reported millisecond delay.
//
// # Why the floor is 1
//
// The rest of the system uses 0 to mean "no result" - no history, a failed test, a node not yet
// measured. A successful measurement that took less than a millisecond would therefore report a
// value indistinguishable from failure and could be dropped by any consumer testing for zero. The
// smallest representable successful delay is 1ms.
func durationToDelay(duration time.Duration) uint16 {
	if duration <= 0 {
		return 0
	}
	milliseconds := duration.Milliseconds()
	if milliseconds < 1 {
		return 1
	}
	if milliseconds > 0xFFFF {
		return 0xFFFF
	}
	return uint16(milliseconds)
}
