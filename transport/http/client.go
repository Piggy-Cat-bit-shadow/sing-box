package http

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

type tlsDialer interface {
	DialTLSContext(ctx context.Context, destination M.Socksaddr) (aTLS.Conn, error)
}

// HTTP3CandidateConnector establishes ONE HTTP/3 candidate.
//
// It performs the whole of connection setup -- the UDP dial, the QUIC handshake start, and the
// congestion-control installation -- in this package's own order, and returns the connected
// QUIC connection plus the socket underneath it.
//
// # Why this is a closure rather than exposed configuration
//
// A caller that wants to choose among several addresses needs to build candidates itself, but it
// must not need to know HOW a candidate is built. An earlier seam handed out the dialer, the TLS
// config and the QUIC config instead, and the consequence was real: the caller called
// DialEarly itself and could only return after the handshake completed, so congestion control
// was installed AFTER the handshake had already exchanged packets under the default controller.
//
// With a closure, the ordering lives here, once, and a caller cannot get it wrong.
type HTTP3CandidateConnector func(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error)

// HTTP3ConnDialer is an optional seam that replaces candidate SELECTION.
//
// # What this package still owns
//
// Everything that happens around a connection: the congestion-control installation ordering, the
// transport.NewClientConn wrapping, the single-connection memoization, and the lifetime and
// cleanup of both the QUIC connection and its UDP socket.
//
// # What the hook owns
//
// Which candidate to use, and when to give up on one. It receives the server address and a
// connector, and returns the winning connection. It is responsible for closing any candidate it
// creates and does not choose.
//
// nil -- the default, and every non-MASQUE caller -- preserves the existing path verbatim:
// connect one candidate and use it.
type HTTP3ConnDialer func(ctx context.Context, server M.Socksaddr, connectCandidate HTTP3CandidateConnector) (net.Conn, *quic.Conn, error)

type ClientOptions struct {
	Dialer                 N.Dialer
	HTTP1Dialer            N.Dialer
	RawDialer              N.Dialer
	TLSConfig              aTLS.Config
	Server                 M.Socksaddr
	Authority              string
	Username               string
	Password               string
	Path                   string
	Headers                http.Header
	Version                int
	DisableVersionFallback bool
	HTTP2Options           option.HTTP2Options
	HTTP3Options           option.QUICOptions
	// HTTP3ConnDialer optionally replaces the UDP-dial + QUIC-handshake step of the
	// HTTP/3 client. See HTTP3ConnDialer in client_h3.go for what it is for and why it
	// is deliberately narrow. nil keeps the existing behaviour, which is every caller
	// except the MASQUE client.
	HTTP3ConnDialer HTTP3ConnDialer
	// lifecycleLogger is carried through to the HTTP/3 client for TRACE-level connection
	// lifecycle tracing. It is unexported because it is an internal wiring detail: callers
	// pass their logger to NewClientWithTLS, and that is the only entry point that sets it.
	lifecycleLogger logger.ContextLogger
}

// http3Authority is set when this client is configured for HTTP/3, and is the authority
// that generic HTTP/3 requests are validated against. See Client.validateSameOrigin.

type http3Client interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error)
	ResetConnection()
	Close() error
}

var NewHTTP3Client func(options ClientOptions, authorization string) (http3Client, error)

type Client struct {
	dialer                          N.Dialer
	http1Dialer                     N.Dialer
	tlsDialer                       tlsDialer
	server                          M.Socksaddr
	authorityOverride               string
	authorization                   string
	host                            string
	path                            string
	headers                         http.Header
	version                         int
	disableVersionFallback          bool
	http2Transport                  *http2.Transport
	http2Access                     sync.Mutex
	http2Conns                      []*http2ClientConn
	http2Unsupported                atomic.Bool
	http2ExtendedConnectUnsupported atomic.Bool
	http3                           http3Client
	http3Broken                     atomic.Int64
	http3Backoff                    atomic.Int64
	// http3Attempt issues the sequence number that stamps one HTTP/3 attempt, and http3Outcome is
	// the highest sequence whose outcome has already been recorded. Together they are what makes
	// the verdict a memory of the NEWEST attempt rather than of whichever attempt reported last.
	// See claimHTTP3Outcome.
	http3Attempt atomic.Uint64
	http3Outcome atomic.Uint64
	// http3VerdictMu makes the CLAIM and its EFFECT one transaction.
	//
	// # Why the claim alone was not enough, and this is a measured defect rather than a worry
	//
	// claimHTTP3Outcome orders the DECISIONS, and every caller then mutated the verdict in a
	// separate read-modify-write. Two attempts can therefore both pass the claim -- the older one
	// first -- and then land their effects in the opposite order. MEASURED by an independent
	// adversary, two goroutines released from one gate and driving exactly what DialContext calls,
	// 200000 iterations:
	//
	//	an old failure armed the verdict AFTER a newer success cleared it   1896 / 200000
	//	an old failure re-armed it AFTER a real ResetConnections cleared it 1758 / 200000
	//
	// The second line is the A->B->A case this guard exists for, and it means the fix removed the
	// DETERMINISTIC version of the bug while leaving a racy one behind. The mirror direction (an
	// old success clearing a newer failure) was not observed in 200000 iterations, because the
	// lagging effect there is a single store with a window of one or two instructions; it is the
	// same mechanism and it is covered by the same transaction, not by a separate argument.
	//
	// The critical section is a handful of instructions with no I/O and no blocking, and it is
	// entered once per HTTP/3 ATTEMPT -- not per dial, not per packet. The claim stays lock-free
	// for direct callers, and the decision is still not serialised behind a handshake: nothing
	// inside the section can wait on anything outside it.
	http3VerdictMu sync.Mutex
	// closed is set by Close. A closed client must not create a connection: see Close.
	closed atomic.Bool
	// lifecycleLogger is used ONLY for connection-lifecycle tracing. Every call site must
	// stay at TRACE/DEBUG: the success path must be silent at INFO and above, and nothing
	// sensitive (Authorization, Proxy-Authorization, credentials, destination query strings)
	// may be passed.
	lifecycleLogger logger.ContextLogger
	// http3Authority is the authority this client's HTTP/3 connection is authenticated
	// for. Generic HTTP/3 requests are validated against it so an authenticated
	// connection cannot be turned into a cross-origin tunnel.
	http3Authority string
}

func NewClientWithTLS(ctx context.Context, logger logger.ContextLogger, outboundDialer N.Dialer, serverOptions option.ServerOptions, tlsOptions option.OutboundTLSOptions, options ClientOptions) (*Client, error) {
	if options.Version == 3 && !tlsOptions.Enabled {
		return nil, C.ErrTLSRequired
	}
	alpnIsDefault := tlsOptions.Enabled && len(tlsOptions.ALPN) == 0
	if alpnIsDefault {
		if options.Version == 1 {
			tlsOptions.ALPN = []string{"http/1.1"}
		} else {
			tlsOptions.ALPN = []string{http2.NextProtoTLS, "http/1.1"}
		}
	}
	var err error
	options.Dialer, err = tls.NewDialerFromOptions(ctx, logger, outboundDialer, serverOptions.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	if options.Version >= 2 && (alpnIsDefault || slices.Contains(tlsOptions.ALPN, "http/1.1")) {
		http1TLSOptions := tlsOptions
		http1TLSOptions.ALPN = []string{"http/1.1"}
		options.HTTP1Dialer, err = tls.NewDialerFromOptions(ctx, logger, outboundDialer, serverOptions.Server, http1TLSOptions)
		if err != nil {
			return nil, err
		}
	}
	if options.Version == 3 {
		if alpnIsDefault {
			tlsOptions.ALPN = []string{"h3"}
		}
		options.TLSConfig, err = tls.NewClient(ctx, logger, serverOptions.Server, tlsOptions)
		if err != nil {
			return nil, err
		}
	}
	options.RawDialer = outboundDialer
	options.Server = serverOptions.Build()
	options.lifecycleLogger = logger
	return NewClient(options)
}

func NewClient(options ClientOptions) (*Client, error) {
	client := &Client{
		lifecycleLogger:        options.lifecycleLogger,
		dialer:                 options.Dialer,
		http1Dialer:            options.HTTP1Dialer,
		server:                 options.Server,
		authorityOverride:      options.Authority,
		path:                   options.Path,
		headers:                options.Headers.Clone(),
		version:                options.Version,
		disableVersionFallback: options.DisableVersionFallback,
	}
	if client.headers != nil {
		client.host = client.headers.Get("Host")
		client.headers.Del("Host")
	}
	if client.host != "" && client.path != "" {
		return nil, E.New("Host header and path are not allowed at the same time")
	}
	client.version = ResolveVersion(client.version, client.path, client.host)
	if client.version >= 2 && (client.path != "" || client.host != "") {
		return nil, E.New("path and Host header are only supported by HTTP/1")
	}
	if client.dialer == nil {
		client.dialer = N.SystemDialer
	}
	if client.http1Dialer == nil {
		client.http1Dialer = client.dialer
	}
	if dialer, isTLSDialer := options.Dialer.(tlsDialer); isTLSDialer && client.version >= 2 {
		client.tlsDialer = dialer
		http2Transport, err := httpclient.ConfigureHTTP2Transport(options.HTTP2Options)
		if err != nil {
			return nil, err
		}
		http2Transport.DisableCompression = true
		client.http2Transport = http2Transport
	} else if client.version == 2 && options.DisableVersionFallback {
		return nil, E.New("HTTP/2 requires TLS")
	}
	if client.version == 3 && NewHTTP3Client == nil {
		return nil, C.ErrQUICNotIncluded
	}
	if options.Username != "" {
		client.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password))
	}
	if client.version == 3 {
		http3, err := NewHTTP3Client(options, client.authorization)
		if err != nil {
			return nil, err
		}
		client.http3 = http3
		// Give the HTTP/3 client the same logger for lifecycle tracing only. It is optional:
		// an implementation that does not accept one simply does not trace.
		if tracer, isTracer := http3.(http3LifecycleTracer); isTracer {
			tracer.SetLifecycleLogger(options.lifecycleLogger)
		}
		// Record the authority this connection is authenticated for. The generic request
		// path validates against it, so an authenticated connection cannot be used to
		// reach an origin its certificate does not cover.
		client.http3Authority = client.authorityOverride
		if client.http3Authority == "" {
			client.http3Authority = options.Server.String()
		}
	}
	return client, nil
}

func ResolveVersion(version int, path string, host string) int {
	if version != 0 {
		return version
	}
	if path != "" || host != "" {
		return 1
	}
	return 2
}

func (c *Client) http3Available() bool {
	if c.http3 == nil {
		return false
	}
	brokenUntil := c.http3Broken.Load()
	return brokenUntil == 0 || time.Now().UnixNano() >= brokenUntil
}

// beginHTTP3Attempt issues the sequence number that stamps one HTTP/3 attempt.
//
// It is taken BEFORE the attempt is made, so "newer" means "started later" rather than "reported
// later". That is the ordering the verdict needs: an attempt that started earlier describes an
// earlier moment, and if a later attempt has already succeeded, the earlier one's failure is
// evidence about a condition that is over.
func (c *Client) beginHTTP3Attempt() uint64 {
	return c.http3Attempt.Add(1)
}

// claimHTTP3Outcome reports whether this attempt's outcome is still the newest observation, and
// records it if so.
//
// # Why the verdict has to be ordered at all
//
// markHTTP3Broken and clearHTTP3Broken used to act on arrival order, and arrival order is not
// attempt order. Two dials can be in flight across the attempt boundary -- the HTTP/3 client
// serialises the handshake, but a dial that has already returned from its attempt and one that is
// about to make one are independent goroutines -- so an attempt that started first can report
// last. A stale failure then arms the verdict directly on top of a newer success, pinning the
// client to the fallback transport for the backoff window (and charging an escalation step, so up
// to the ceiling) on the strength of a condition the success already disproved. The mirror case
// is just as wrong: a stale success clears a newer failure, so a client that has just watched
// HTTP/3 fail pays a failed attempt on every dial.
//
// # Why the claim is a compare-and-swap loop rather than a mutex
//
// This is on the dial path, and a mutex here would serialise the decision of every H3 dial behind
// every other one. One atomic load and, at most, one CAS is the whole cost, and the loop only
// spins when a genuinely concurrent outcome lands between the load and the store.
//
// # What it does not do
//
// It never refuses an outcome that is NEWER than the last one recorded, so the memory is not
// weakened: a failure that happens after the last success is still remembered, at the initial
// step. It only refuses outcomes that a newer attempt has already superseded.
func (c *Client) claimHTTP3Outcome(attempt uint64) bool {
	for {
		recorded := c.http3Outcome.Load()
		if attempt <= recorded {
			return false
		}
		if c.http3Outcome.CompareAndSwap(recorded, attempt) {
			return true
		}
	}
}

// resetHTTP3Verdict marks every attempt issued so far as stale AND clears the verdict, as one
// transaction.
//
// A network transition is the case this exists for: an attempt that was in flight against the
// network being LEFT belongs to that network, so its outcome is not evidence about the one just
// entered. Without this, ResetConnections clears the verdict and the abandoned attempt immediately
// re-arms it, charging the first dial on the new path for the old path's failure.
//
// # Why the supersede and the clear cannot be two statements
//
// They were, and the isolation between them is exactly what let an abandoned attempt through:
// MEASURED, an old failure re-armed the verdict after a real ResetConnections had cleared it in
// 1758 of 200000 iterations. Superseding only rejects outcomes that have not yet CLAIMED; an
// outcome that claimed just before the supersede and stores just after it is not rejected by
// anything, so the clear has to happen inside the same critical section as the supersede.
func (c *Client) resetHTTP3Verdict() {
	c.http3VerdictMu.Lock()
	defer c.http3VerdictMu.Unlock()
	c.claimHTTP3Outcome(c.http3Attempt.Load())
	c.http3Broken.Store(0)
	c.http3Backoff.Store(0)
}

// markHTTP3Broken records a failed HTTP/3 attempt and advances the backoff schedule by one step.
//
// `attempt` is the sequence number beginHTTP3Attempt issued for the attempt being reported. An
// outcome that a newer attempt has already superseded is refused: see claimHTTP3Outcome.
//
// # One failing event, one step
//
// The step is CLAIMED, once, by a compare-and-swap on the deadline. The dial that finds the memory
// unarmed -- or expired -- escalates; every other dial that failed in the same event finds a
// window already open, and its failure is already covered by that window.
//
// The claim is what makes this a memory of EVENTS rather than of DIALS. Without it the
// read-modify-write ran once per failing dial, so a burst of parallel dials met one transient
// failure and multiplied the schedule by 2^N in the same instant: sixteen parallel dials -- a page
// load, a reconnect storm, anything after one blip on the UDP path -- landed on the five-minute
// ceiling straight away. A single fast failure then read as "HTTP/3 has been down for minutes",
// and because every later burst repeated it, the ceiling stayed pinned for the life of the client.
// That is the outcome this memory exists to bound, not to manufacture.
//
// A failure that arrives while a window is open is deliberately NOT charged again: it cannot be
// distinguished from the failure that opened the window, and charging one event twice is the
// direction that strands the caller on HTTP/2.
func (c *Client) markHTTP3Broken(attempt uint64) {
	// The claim and the effect are one transaction: see http3VerdictMu.
	c.http3VerdictMu.Lock()
	defer c.http3VerdictMu.Unlock()
	if !c.claimHTTP3Outcome(attempt) {
		return
	}
	now := time.Now()
	brokenUntil := c.http3Broken.Load()
	if brokenUntil != 0 && now.UnixNano() < brokenUntil {
		// The failure that armed this window is still being remembered: this one belongs to the
		// same event, and the window already covers it.
		return
	}
	next := http3BrokenBackoffInitial
	if previous := time.Duration(c.http3Backoff.Load()); previous != 0 {
		next = min(previous*2, http3BrokenBackoffMax)
	}
	if !c.http3Broken.CompareAndSwap(brokenUntil, now.Add(next).UnixNano()) {
		// Another dial claimed this event first; the window it armed is the one that is
		// remembered, and this failure is covered by it.
		return
	}
	c.http3Backoff.Store(int64(next))
}

// clearHTTP3Broken discards the verdict for a successful HTTP/3 attempt.
//
// `attempt` is the sequence number beginHTTP3Attempt issued. A success that a NEWER attempt has
// already superseded does not clear the verdict, for the reason given on claimHTTP3Outcome: the
// newer attempt is the more recent observation of the path, and the older one cannot speak for it.
func (c *Client) clearHTTP3Broken(attempt uint64) {
	// The claim and the effect are one transaction: see http3VerdictMu.
	c.http3VerdictMu.Lock()
	defer c.http3VerdictMu.Unlock()
	if !c.claimHTTP3Outcome(attempt) {
		return
	}
	c.http3Broken.Store(0)
	c.http3Backoff.Store(0)
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	case N.NetworkUDP:
		return nil, os.ErrInvalid
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if c.http3Available() {
		// The sequence number is taken BEFORE the attempt, so an outcome is judged against the
		// newest attempt STARTED rather than the one that happened to report last. See
		// claimHTTP3Outcome.
		http3Attempt := c.beginHTTP3Attempt()
		// The H3 attempt gets its OWN window, not the caller's whole dial budget; see
		// http3EstablishTimeout. context.WithTimeout resolves to the EARLIER of this window and
		// the caller's deadline, so a caller with less time than the window is not delayed by it.
		probeCtx, cancelProbe := context.WithTimeout(ctx, http3EstablishTimeout)
		conn, err := c.http3.DialContext(probeCtx, destination)
		probeExpired := probeCtx.Err() != nil
		cancelProbe()
		if err == nil {
			c.clearHTTP3Broken(http3Attempt)
			return conn, nil
		}
		// The CALLER gave up, or the core is closing. That is a local lifecycle event: it is not
		// evidence about H3 and it is not a reason to fall back - the user is gone, and starting an
		// H2 dial for them would be work nobody is waiting for.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Strict mode is checked BEFORE the failure is classified, and it covers EVERY way H3 can
		// fail - including running out of the window above.
		//
		// The check used to sit inside `if !probeExpired`, so a window expiry skipped it and fell
		// through to HTTP/2 while also arming the H3-broken memory; the next dial then saw H3 as
		// unavailable and went to HTTP/2 as well. A configuration that said "do not fall back to
		// another HTTP version" fell back on that dial and on every dial during the backoff.
		//
		// Nothing is armed here either, for the same reason: arming the memory is itself a fallback,
		// because it makes the next dial skip H3.
		//
		// This is a user-facing option on two config surfaces (the MASQUE client and the plain HTTP
		// outbound), so "strict" has to mean strict rather than "strict except when it matters".
		if c.disableVersionFallback {
			if probeExpired {
				// A window expiry surfaces as the probe context's own deadline, which would be
				// indistinguishable from the caller's deadline at the call site. Name the cause.
				return nil, E.Cause(err, "HTTP/3 attempt exceeded ", http3EstablishTimeout)
			}
			return nil, err
		}
		// An attempt that merely ran out of its window is still an attempt that did not work.
		// Returning that error would hand a QUIC timeout to the caller and never try H2, which is
		// the opposite of what the window is for.
		if !probeExpired && !errors.Is(err, ErrHTTP3Unavailable) {
			return nil, err
		}
		c.markHTTP3Broken(http3Attempt)
	}
	if c.tlsDialer != nil && !c.http2Unsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, err
		}
		if clientConn != nil {
			return c.connectHTTP2(ctx, clientConn, destination)
		}
		if c.disableVersionFallback {
			conn.Close()
			return nil, ErrHTTP2Unsupported
		}
		return c.connectAndClose(ctx, conn, destination)
	}
	conn, err := c.http1Dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	return c.connectAndClose(ctx, conn, destination)
}

func (c *Client) closeHTTP2Locked() {
	for _, clientConn := range c.http2Conns {
		clientConn.Close()
	}
	c.http2Conns = nil
}

func (c *Client) ResetConnections() {
	c.http2Access.Lock()
	c.closeHTTP2Locked()
	c.http2Access.Unlock()
	c.http2Unsupported.Store(false)
	c.http2ExtendedConnectUnsupported.Store(false)
	if c.http3 != nil {
		c.http3.ResetConnection()
		// Anything already in flight belongs to the network being left, so it is superseded AND
		// the verdict is cleared inside ONE critical section: see resetHTTP3Verdict. Doing the two
		// as separate statements left a window in which an abandoned attempt re-armed the verdict
		// on the network that was just entered, measured at 1758/200000.
		c.resetHTTP3Verdict()
	}
}

func (c *Client) connect(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stop()
	request := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if c.host != "" && c.host != destination.Fqdn {
		request.Host = c.host
		request.URL = &url.URL{Opaque: destination.String()}
	} else {
		request.URL = &url.URL{Host: destination.String()}
	}
	if c.path != "" {
		err := badhttp.URLSetPath(request.URL, c.path)
		if err != nil {
			return nil, err
		}
	}
	maps.Copy(request.Header, buildRequestHeader(c.headers, c.authorization, false))
	err := request.Write(conn)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, statusError(response)
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
		return bufio.NewCachedConn(conn, buffer), nil
	}
	return conn, nil
}

func buildRequestHeader(headers http.Header, authorization string, originAuthorization bool) http.Header {
	header := headers.Clone()
	if header == nil {
		header = make(http.Header)
	}
	if _, loaded := header["User-Agent"]; !loaded {
		header["User-Agent"] = nil
	}
	if authorization != "" {
		if originAuthorization {
			header.Set("Authorization", authorization)
		} else {
			header.Set("Proxy-Authorization", authorization)
		}
	}
	return header
}

// Close releases the client, and a closed client stops being a dialer.
//
// # Why the closed flag is not decoration
//
// Close is reached from the outbound's composition scope at shutdown and on a configuration
// reload. Before the flag existed, a dial that raced that teardown found `c.http3` non-nil and the
// verdict clear, so it went on to perform a whole QUIC handshake and install a connection on a
// transport that had ALREADY been closed. Nothing owns that connection afterwards: the scope has
// run, so no later Close reaches it, and the socket lives until the process does.
//
// MEASURED on the loopback HTTP/3 stand (h3_churn_stand_test.go,
// TestH3StandCloseDuringChurnIsClean): a tunnel established after Close returned successfully over
// HTTP/3, with no error at all.
//
// The flag is set BEFORE the teardown, so a dial that observes the client as open is either
// already inside a teardown that will reach its connection, or has been refused. It is checked
// first in every entry point that can create a connection, and the error is net.ErrClosed, which
// the route layer already classifies as a closed/canceled lifecycle event rather than a fault.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.http2Access.Lock()
	defer c.http2Access.Unlock()
	c.closeHTTP2Locked()
	if c.http3 != nil {
		c.http3.Close()
	}
	return nil
}

const (
	http3BrokenBackoffInitial = 5 * time.Second
	http3BrokenBackoffMax     = 5 * time.Minute
)

// http3EstablishTimeout is the window the HTTP/3 attempt gets inside one dial.
//
// # Why the version fallback needs a bound of its own
//
// The fallback to HTTP/2 exists in the code below, but without a window of its own it is
// unreachable in exactly the failure it was written for. A peer whose UDP path is silently
// blackholed - packets dropped, nothing refused - makes the QUIC handshake wait until the
// CALLER's deadline (15s for a proxied dial, more for a detour), and only then does the code
// reach the H2 branch. The caller has usually given up by then, so the observed behaviour is
// "this node does not work over UDP", not "this node fell back".
//
// A bounded window makes the fallback real, and it costs that window once per backoff period
// rather than once per connection: an expired window marks H3 broken below, exactly as an
// explicit refusal does.
//
// A var rather than a const because it is a tunable that tests shrink, like the two backoff
// bounds above it.
var http3EstablishTimeout = 3 * time.Second

var (
	ErrHTTP2Unsupported           = E.New("server does not support HTTP/2")
	ErrHTTP3Unavailable           = E.New("HTTP/3 unavailable")
	errExtendedConnectUnsupported = E.New("server does not support HTTP/2 extended CONNECT")
	errExtendedConnectUnavailable = E.New("HTTP/2 extended CONNECT is unavailable in this build: Go 1.27+ requires the badlinkname build tag")
)

func statusError(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusProxyAuthRequired:
		return E.New("authentication required")
	case http.StatusMethodNotAllowed:
		return E.New("method not allowed")
	default:
		return E.New("unexpected status: ", response.Status)
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, err := c.listenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return deadline.NewPacketConn(bufio.NewNetPacketConn(&boundPacketConn{PacketConn: packetConn, destination: destination.Unwrap()})), nil
}

func (c *Client) listenPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	// The transport kind is not needed here: this path only needs the stream. It is discarded
	// deliberately rather than plumbed through a caller that has no use for it.
	conn, stream, _, err := c.openTunnel(ctx, tunnelRequest{
		protocol:    connectUDPProtocol,
		url:         connectUDPURL(destination),
		destination: destination,
	})
	if err != nil {
		return nil, err
	}
	if stream != nil {
		return newHTTP3PacketConn(stream, destination, M.Socksaddr{}), nil
	}
	return newCapsuleConn(std_bufio.NewReader(conn), conn, destination), nil
}

var _ N.Dialer = (*Client)(nil)

type boundPacketConn struct {
	N.PacketConn
	destination M.Socksaddr
}

func (c *boundPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.Unwrap() != c.destination {
		buffer.Release()
		return E.New("connect-udp: destination mismatch: ", destination)
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *boundPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *boundPacketConn) Upstream() any {
	return c.PacketConn
}
