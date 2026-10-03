package urltest

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// newMeasurementTransport builds the HTTP transport used for both requests of one measurement.
//
// # The one-shot handoff
//
// The pre-dialed connection is handed to net/http AT MOST ONCE. Returning it unconditionally was
// wrong ownership: net/http may call DialContext again, and for an idempotent request like HEAD it
// does so when a connection it already used fails. The transport would then be given a connection
// that is already closed.
//
// The sentinel keeps the guarantee the caller depends on - one measurement, one outbound
// connection - and turns a would-be silent reuse into an error that the second-request handling
// already classifies as a repeat-request failure, so the node stays usable through the fallback.
func newMeasurementTransport(instance net.Conn, ctx context.Context) *http.Transport {
	var handedOut atomic.Bool
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !handedOut.CompareAndSwap(false, true) {
				return nil, errURLTestConnectionNotReusable
			}
			return instance, nil
		},
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
		// A health check needs a few hundred bytes of headers at most. The default ceiling is
		// about 10 MiB, which an unusual or hostile endpoint could make the process allocate for
		// every measurement - memory that matters on a 50 MiB NetworkExtension budget.
		//
		// 256 KiB is far above any real CDN response and far below the default.
		MaxResponseHeaderBytes: 256 << 10,
	}
}

// errURLTestConnectionNotReusable is returned when the transport asks for a second connection.
//
// It is a plain error, not a timeout and not a cancellation, so the second-request handling treats
// it as a repeat-request failure and keeps the node usable through the Mihomo fallback - which is
// the correct reading: the node answered once, and only the transport's attempt to obtain another
// connection failed.
var errURLTestConnectionNotReusable = errors.New("URL test transport attempted to open a second connection")

// MeasureOptions describes one measurement request.
type MeasureOptions struct {
	// Link is the target. Empty means DefaultURLTestURL.
	Link string
	// ExpectedStatus is the accepted HTTP status set. Empty accepts any status.
	ExpectedStatus ExpectedStatus
	// Debug, when set, receives the phase timings of this measurement.
	//
	// # Why a callback rather than a package-level logger
	//
	// A global logger made the measurement engine depend on process-wide state that any Box could
	// replace. A temporary Box built by a configuration check would install its own logger over
	// the one belonging to the running Box, and after the temporary Box was closed the running Box
	// kept logging through a dead factory. The atomics made that race-free but not correct: the
	// ownership was wrong.
	//
	// A callback belongs to the caller, so the caller's lifecycle is the only one that matters.
	// When it is nil no phase timing is computed at all.
	Debug func(MeasureDebug)
}

// MeasureDebug carries the phase timings of one measurement.
//
// It is produced only when MeasureOptions.Debug is set, so the timings cost nothing on the normal
// path.
type MeasureDebug struct {
	// Dial is the outbound dial that opens the connection both requests share.
	Dial time.Duration
	// Warmup is the first request, which sets up the proxy path, TLS and the connection pool.
	Warmup time.Duration
	// Warm is the timed second request.
	Warm time.Duration
	// UsedFallback reports that the second request failed in a way that kept the node usable, so
	// the reported delay is the whole attempt rather than the timed request.
	UsedFallback bool
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
// withMeasurementTimeout bounds ctx by timeout, without ever extending a caller's own deadline.
//
// Applying the timeout UNCONDITIONALLY is what makes the result min(parent, now+timeout). Passing a
// shorter timeout than the parent's remaining time narrows the deadline; passing a longer one leaves
// the parent's in place, because context.WithTimeout only ever tightens. The previous version only
// applied the timeout when the caller had NO deadline, so a caller with a 60s deadline got 60s
// instead of C.TCPTimeout - the measurement was effectively unbounded relative to what it intended.
//
// It is a separate function so a test can exercise the three cases with millisecond timeouts rather
// than waiting out the real one.
func withMeasurementTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

func Measure(ctx context.Context, options MeasureOptions, detour N.Dialer) (Measurement, error) {
	return measureWithTimeout(ctx, options, detour, C.TCPTimeout)
}

// measureWithTimeout is Measure with an explicit active-probe budget.
//
// It exists so a test can exercise the queue-versus-probe boundary in milliseconds instead of
// waiting out C.TCPTimeout. The budget applies only from the moment a coordinator slot is held;
// the caller's own deadline bounds the whole operation including the wait.
func measureWithTimeout(ctx context.Context, options MeasureOptions, detour N.Dialer, probeTimeout time.Duration) (Measurement, error) {
	// ONE parse, three results, BEFORE any budget is spent.
	//
	// The request, the identity and the dial target are decided together and then used as decided.
	// Deriving them separately - the previous code re-parsed the normalised string to find the host
	// and port - is how a canonicalisation chosen for identity can end up changing what is fetched.
	//
	// It also runs before the slot is taken, so an unusable target fails without consuming a
	// measurement slot at all.
	target, err := ParseMeasurementTarget(options.Link)
	if err != nil {
		return Measurement{}, err
	}

	// ONE slot per measurement, taken from the Box's coordinator.
	//
	// It is acquired HERE rather than by each caller, so every path is bounded by construction:
	// automatic group checks, Clash delay probes, native single-node tests, generic group tests and
	// endpoint tests all reach the network through Measure. A caller that had to remember to Acquire
	// would eventually forget, and the bound would be advisory rather than real.
	//
	// The release is deferred before anything else can fail, so a slot cannot leak on an error path.
	// A context with no coordinator means unbounded, which is what an isolated unit test or a
	// library caller gets.
	//
	// It waits on the CALLER's context, so a caller deadline still bounds the wait.
	if coordinator := CoordinatorFromContext(ctx); coordinator != nil {
		release, acquireErr := coordinator.Acquire(ctx)
		if acquireErr != nil {
			return Measurement{}, acquireErr
		}
		defer release()
	}

	// The ACTIVE PROBE budget starts here, once the slot is held.
	//
	// # Why the order matters
	//
	// The deadline used to be established before Acquire, so the time spent waiting for a slot was
	// charged against the probe budget. Under saturation - several groups checking at once, all
	// sharing one Box budget - a member could exhaust its budget while queued, never dial at all,
	// and still be reported as a measurement failure. The group then DELETED that node's health
	// evidence: a node that was never tested was recorded as unhealthy, which is evidence being
	// changed without a measurement.
	//
	// C.TCPTimeout bounds the network probe. The caller's deadline bounds the whole operation,
	// queue included, and is applied by layering on top of whatever the caller already supplied.
	//
	// It remains the EARLIER of the caller's deadline and ours, because WithTimeout only tightens.
	var cancelMeasurement context.CancelFunc
	ctx, cancelMeasurement = withMeasurementTimeout(ctx, probeTimeout)
	defer cancelMeasurement()
	scope := MeasurementScope{URL: target.ScopeURL, Expected: options.ExpectedStatus.Canonical()}

	debugEnabled := options.Debug != nil
	var debugReport MeasureDebug

	// measurementStart is used only by the fallback path, which reports the whole attempt's cost.
	measurementStart := time.Now()

	// One dial for the whole measurement; both requests share it through the transport below.
	//
	// The destination was validated by ParseMeasurementTarget, so an unusable port fails there
	// rather than being handed to a detour to discover.
	dialStart := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", target.Destination)
	if err != nil {
		return Measurement{}, err
	}
	defer instance.Close()
	dialElapsed := time.Since(dialStart)

	transport := newMeasurementTransport(instance, ctx)

	// No client-level timeout. The measurement context already carries the deadline above, and a
	// second policy here would bound each request separately - so a measurement could take up to
	// twice the intended total while looking like it respected one.
	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	// firstStatus is the response the fallback path reports if the second request fails.
	var firstStatus int

	// --- request 1: the warm-up, not timed ---
	firstRequest, err := http.NewRequest(http.MethodHead, target.RequestURL, nil)
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
	secondRequest, err := http.NewRequest(http.MethodHead, target.RequestURL, nil)
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
			debugReport.Dial = dialElapsed
			debugReport.Warmup = firstElapsed
			debugReport.Warm = warmElapsed
			options.Debug(debugReport)
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
		debugReport.Dial = dialElapsed
		debugReport.Warmup = firstElapsed
		debugReport.UsedFallback = true
		// The reported delay is the WHOLE ATTEMPT, not the first request.
		//
		// The name used to say "first_path", which described a delay that was in fact
		// dial + warm-up + the wait for the second request to fail. Anyone reading a log to work
		// out where the time went would have been told the wrong thing.
		options.Debug(debugReport)
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
