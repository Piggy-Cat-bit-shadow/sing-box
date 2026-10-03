package clashapi

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
)

// clashDelayQuery is the shared parsing and context derivation for a manual delay request.
//
// # Why it is shared
//
// /proxies/{name}/delay and /group/{name}/delay do the same job for two shapes of target, and they
// had drifted: the proxy path was brought onto the shared measurement contracts while the group path
// kept the older behaviour. A client issuing the SAME query parameters therefore got different
// semantics depending on whether it named a node or a group - a different target, a different
// acceptance rule, and a measurement that wrote selection evidence instead of a diagnostic.
//
// Sharing the parse is what stops the two diverging again, and it is deliberately a small helper
// rather than a routing framework.
type clashDelayQuery struct {
	// URL is the requested target, used exactly as given. Empty means the default.
	URL string
	// Timeout is the caller's requested budget in milliseconds, always positive.
	Timeout time.Duration
	// Expected is the accepted status set. Empty accepts any status.
	Expected urltest.ExpectedStatus
}

// parseClashDelayQuery reads the shared query parameters, reporting whether the request is valid.
//
// A malformed request is the caller's error, so every failure here is a 400 and the caller must not
// dial anything. Silently ignoring a parameter would measure against a rule the client never asked
// for and report the result as if it were the requested one.
func parseClashDelayQuery(query url.Values) (clashDelayQuery, bool) {
	// An explicit scheme is honoured; only an empty value means "use the default".
	//
	// The group path used to blank any `http://` URL, which fell through to the gstatic HTTPS
	// default: a client explicitly asking to measure a plain-HTTP endpoint measured a TLS endpoint
	// on another host instead - a different destination, an extra handshake, and a number that
	// cannot be compared with any other client's measurement of the same URL.
	parsed := clashDelayQuery{URL: query.Get("url")}

	// The timeout must be POSITIVE. A non-positive duration makes the context already expired, so
	// "timeout=0" or "timeout=-1" produced an instant, meaningless "measurement" that looked like a
	// failed probe rather than a bad request.
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil || timeout <= 0 {
		return clashDelayQuery{}, false
	}
	parsed.Timeout = time.Millisecond * time.Duration(timeout)

	// `expected` restricts which HTTP status counts as reachable, in the Mihomo syntax.
	expected, err := urltest.ParseExpectedStatus(query.Get("expected"))
	if err != nil {
		return clashDelayQuery{}, false
	}
	parsed.Expected = expected

	return parsed, true
}

// clashMeasurementContext derives the context a manual measurement runs under.
//
// # Values and lifetime come from the server, not from the request
//
// Measure reads the Box's own services out of the context: the certificate roots it must trust, the
// time service it timestamps with, and the URL-test Coordinator that bounds how many measurements
// run at once. The HTTP request's context carries none of them.
//
// Using the request context as the base therefore replaced the Box context entirely, so a manual
// group measurement bypassed the per-Box concurrency limit and failed against a private-root HTTPS
// endpoint that the identical node-level measurement handled - same engine, same node, different
// answer purely because of which context reached it.
//
// The request context contributes exactly what a caller owns: its cancellation. A client that
// disconnects stops the measurement, and the server's lifetime still governs it otherwise.
func clashMeasurementContext(serverCtx context.Context, requestCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancelServer := context.WithCancel(serverCtx)

	// No extra watcher goroutine: AfterFunc arms a runtime timer that is stopped by the returned
	// function, so the cleanup is part of the cancel chain rather than something to remember.
	stopRequestWatch := context.AfterFunc(requestCtx, cancelServer)

	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)

	return ctx, func() {
		stopRequestWatch()
		cancelTimeout()
		cancelServer()
	}
}
