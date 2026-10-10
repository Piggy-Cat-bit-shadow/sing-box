// Package v2rayxhttp implements the client side of the Xray "XHTTP"
// (a.k.a. "splithttp") v2ray transport for sing-box-lx. It is a lean-native
// implementation written on sing-box/sing primitives and the in-tree
// v2rayhttp HTTP/2 conn helpers, rather than vendoring Xray internals.
// See SPECS/TASKS/002-XHTTP_CLIENT_TRANSPORT.
//
// Wire protocol (mirrors Xray-core transport/internet/splithttp):
//
//	A random per-dial session id is generated. Requests target
//	"<path>/<sessionId>" (and, for upload packets, "<path>/<sessionId>/<seq>").
//	Every request carries a random-length X-Padding header in the
//	configured x_padding_bytes range to blur the on-wire size signature.
//
//	stream-one : a single POST whose request body carries client->server
//	             bytes and whose response body carries server->client bytes
//	             (one fully bidirectional HTTP/2 stream). Closest to
//	             httpupgrade; this is the mode "auto" falls back to here.
//	stream-up  : a single streamed POST for the upload direction plus a
//	             separate GET whose response body is the download direction.
//	packet-up  : a GET download stream plus sequential POST upload packets,
//	             each "<path>/<sessionId>/<seq>" carrying one write.
package v2rayxhttp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
)

const (
	modeAuto      = "auto"
	modePacketUp  = "packet-up"
	modeStreamUp  = "stream-up"
	modeStreamOne = "stream-one"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

var _ adapter.IdleConnectionKeeper = (*Client)(nil)

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	// xmux owns the pool of HTTP connections; every dial takes one from it and
	// releases it when the conn closes (SPECS/TASKS/059).
	xmux         *xmuxManager
	scheme       string
	host         string
	path         string
	mode         string
	headers      http.Header
	paddingRange intRange
	// meta holds the normalized placement/key/method selection (session, seq,
	// uplink-data, X-Padding obfs). Computed once in NewClient.
	meta metaConfig
	// realityEnabled records whether the TLS config is a Reality client config.
	// It drives mode=auto resolution (Reality → stream-one, like Xray).
	realityEnabled bool
	// httpVersion is the HTTP version the pool speaks (lx: SPEC 104). On HTTP/1.1
	// long requests go out with "Connection: close".
	httpVersion httpVersion
	// noGRPCHeader suppresses the default "Content-Type: application/grpc" on
	// streamed-body requests (stream-one, stream-up). See option.NoGRPCHeader.
	noGRPCHeader bool
}

// NewClient builds an XHTTP client transport. The tlsConfig (possibly Reality)
// selects the HTTP version (lx: SPEC 104): HTTP/2 over the TLS dialer by
// default, HTTP/1.1 for tls.alpn ["http/1.1"] and for a cleartext server,
// HTTP/3 over QUIC for tls.alpn ["h3"].
func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	mode := options.Mode
	if mode == "" {
		mode = modeAuto
	}
	switch mode {
	case modeAuto, modePacketUp, modeStreamUp, modeStreamOne:
	default:
		return nil, E.New("v2ray-xhttp: unknown mode: ", mode)
	}

	paddingRange, err := parseRangeOr(options.XPaddingBytes, "x_padding_bytes", intRange{100, 1000})
	if err != nil {
		return nil, err
	}

	meta, err := normalizeMeta(metaOptions{
		SessionPlacement:     options.SessionPlacement,
		SessionKey:           options.SessionKey,
		SeqPlacement:         options.SeqPlacement,
		SeqKey:               options.SeqKey,
		SessionTable:         options.SessionTable,
		SessionLength:        options.SessionLength,
		UplinkDataPlacement:  options.UplinkDataPlacement,
		UplinkDataKey:        options.UplinkDataKey,
		UplinkChunkSize:      options.UplinkChunkSize,
		UplinkHTTPMethod:     options.UplinkHTTPMethod,
		XPaddingObfsMode:     options.XPaddingObfsMode,
		XPaddingKey:          options.XPaddingKey,
		XPaddingHeader:       options.XPaddingHeader,
		XPaddingPlacement:    options.XPaddingPlacement,
		XPaddingMethod:       options.XPaddingMethod,
		ScMaxEachPostBytes:   options.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: options.ScMinPostsIntervalMs,
	}, mode)
	if err != nil {
		return nil, err
	}

	xmuxConfig, err := normalizeXmux(options.Xmux)
	if err != nil {
		return nil, err
	}

	var logger log.ContextLogger
	if logFactory := service.FromContext[log.Factory](ctx); logFactory != nil {
		logger = logFactory.NewLogger("xhttp")
	}
	// Messages go out under the "xhttp" logger tag: "xhttp: <message>".
	warn := func(message string) {
		if logger != nil {
			logger.Warn(message)
		}
	}

	// lx: SPEC 104 — the HTTP version follows tls.alpn, REALITY and the presence
	// of TLS, by Xray's decideHTTPVersion. newConn builds one pooled HTTP
	// connection; XMUX holds several of these and decides which one carries a
	// given stream (SPECS/TASKS/059).
	realityEnabled := tlsConfigIsReality(tlsConfig)
	version := decideHTTPVersion(tlsConfig, realityEnabled)
	var (
		scheme  string
		newConn func() xmuxConn
	)
	switch version {
	case httpVersion3:
		scheme = "https"
		newConn, err = newHTTP3Transport(dialer, serverAddr, tlsConfig, xmuxConfig.keepAlivePeriod, warn)
		if err != nil {
			return nil, err
		}
	case httpVersion11:
		// Without TLS too: Xray speaks HTTP/1.1 to a cleartext server, and reverse
		// proxies on a cleartext port usually accept nothing else.
		var tlsDialer tls.Dialer
		if tlsConfig == nil {
			scheme = "http"
		} else {
			scheme = "https"
			tlsDialer = tls.NewDialer(dialer, tlsConfig)
		}
		newConn = func() xmuxConn {
			return &http1XmuxConn{transport: newHTTP1Transport(dialer, tlsDialer)}
		}
	default:
		scheme = "https"
		if realityEnabled && realityALPNNeedsH2(tlsConfig.NextProtos()) {
			warn(`REALITY uses HTTP/2, tls.alpn replaced with ["h2"]`)
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		tlsDialer := tls.NewDialer(dialer, tlsConfig)
		newConn = func() xmuxConn {
			return &http2XmuxConn{transport: &http2.Transport{
				ReadIdleTimeout: xmuxConfig.keepAlivePeriod,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.STDConfig) (net.Conn, error) {
					return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
				},
			}}
		}
	}
	if logger != nil {
		logger.Debug("HTTP version ", version)
	}

	var host string
	if options.Host != "" {
		host = options.Host
	} else if tlsConfig != nil && tlsConfig.ServerName() != "" {
		host = tlsConfig.ServerName()
	} else {
		host = serverAddr.String()
	}

	// Keep the configured path verbatim (only guarantee a leading slash). A
	// trailing slash is load-bearing: reverse proxies (e.g. nginx `location
	// /upload/ {}`) 301-redirect a bare "/upload" to "/upload/", and our download
	// RoundTrip does not follow redirects, so the 301 surfaces as a dial error.
	// The one place the slash must go is stream-one's bare path (empty sessionId),
	// where the Xray server keys the bidirectional branch on an exact bare path —
	// that trim happens locally in applyMeta, not globally here (lx: SPEC 002).
	path := options.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	headers := make(http.Header)
	for key, value := range options.Headers {
		headers[key] = value
	}

	xmux := newXmuxManager(xmuxConfig, newConn)
	// The pool's transitions (a connection opened, a connection retired and why)
	// are what is worth observing about XMUX — the pool size itself follows from
	// the config. Debug level, so it costs nothing unless someone is looking.
	// See SPECS/TASKS/059 §8.2.
	if logger != nil {
		xmux.onEvent = func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		}
	}

	return &Client{
		ctx:            ctx,
		dialer:         dialer,
		serverAddr:     serverAddr,
		xmux:           xmux,
		scheme:         scheme,
		host:           host,
		path:           path,
		mode:           mode,
		headers:        headers,
		paddingRange:   paddingRange,
		meta:           meta,
		realityEnabled: realityEnabled,
		httpVersion:    version,
		noGRPCHeader:   options.NoGRPCHeader,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	sessionID := c.newSessionID()
	// One pooled connection carries this whole dial: both halves of a split mode
	// and every upload POST of packet-up. It is released once, when the conn
	// closes — see releaseOnce in conn.go. getContext may wait out the breaker's
	// backoff window before opening a transport (lx: SPEC 076).
	xmuxClient, err := c.xmux.getContext(ctx)
	if err != nil {
		return nil, err
	}
	xmuxClient.addOpenUsage(1)
	// lx: SPEC 077 — one release handle for the whole dial. The conn's Close and
	// fail share it with this error path, so a raise that fails INSIDE the dial
	// (fail already released the slot before the error surfaced here) cannot
	// release twice and drive openUsage negative.
	release := newXmuxRelease(xmuxClient)
	conn, err := c.dialMode(ctx, sessionID, xmuxClient, release)
	if err != nil {
		release.release()
		return nil, err
	}
	return conn, nil
}

func (c *Client) dialMode(ctx context.Context, sessionID string, xmuxClient *xmuxClient, release *xmuxRelease) (net.Conn, error) {
	switch c.mode {
	case modeAuto:
		// Match Xray's auto resolution (transport/internet/splithttp/dialer.go):
		// Reality → stream-one; otherwise → packet-up (the most broadly compatible
		// mode, live-validated against Xray 3x-ui). Xray also picks stream-up when
		// downloadSettings is present, but we don't support asymmetric transport.
		if c.realityEnabled {
			return c.dialStreamOne(ctx, sessionID, xmuxClient, release)
		}
		return c.dialPacketUp(ctx, sessionID, xmuxClient, release)
	case modePacketUp:
		return c.dialPacketUp(ctx, sessionID, xmuxClient, release)
	case modeStreamUp:
		return c.dialStreamUp(ctx, sessionID, xmuxClient, release)
	case modeStreamOne:
		return c.dialStreamOne(ctx, sessionID, xmuxClient, release)
	default:
		return nil, E.New("v2ray-xhttp: unknown mode: ", c.mode)
	}
}

func (c *Client) Close() error {
	c.xmux.Close()
	return nil
}

// CloseIdleConnections releases pooled connections that carry no live stream.
//
// It implements adapter.IdleConnectionKeeper, which is how this transport is reached by the runtime
// lifecycle: the VLESS outbound forwards the call, the reference manager forwards that, and the
// memory-trim pass ends here. A network change does NOT come through this - it calls Close and
// retires everything.
//
// This is the TRIM action and it is deliberately weaker than RetireSuspect: it must not be able to
// make the next stream dial a different connection, because a memory pass that did would be a
// reconnect trigger. The reuse boundary uses RetireSuspect.
func (c *Client) CloseIdleConnections() {
	c.xmux.CloseIdleConnections()
}

// RetireSuspect refuses new streams on every pooled connection, closing the ones that carry nothing.
//
// It implements adapter.ReuseSuspect, which is the one capability a pool can have that an idle-only
// release cannot express, and it is reached only by the reuse boundary: the VLESS outbound forwards
// it, and the reference manager calls it instead of CloseIdleConnections for the pools that have it.
// See xmuxManager.RetireSuspect for why a connection with a live stream is drained rather than closed
// and why that is the only action that is neither wrong nor a stall.
func (c *Client) RetireSuspect() {
	c.xmux.RetireSuspect()
}

// SetKeepIdleConnections honours the idle policy.
//
// XHTTP has no "keep one warm connection" mode distinct from its pool, so refusing to keep idle
// connections means the same thing as closing them: release what is not in use, and let the next
// demand dial. Implementing it as a no-op when keep is true is deliberate - there is nothing to
// pre-warm, and pre-warming would be a dial this fork's lifecycle model does not want on a timer.
func (c *Client) SetKeepIdleConnections(keep bool) {
	if !keep {
		c.xmux.CloseIdleConnections()
	}
}

// baseURL builds a fresh request URL targeting the normalized base path. The
// placement engine (applyMeta) appends session/seq path segments and query params
// as configured; applyXPadding attaches the padding. The base path is set via
// sHTTP.URLSetPath so percent-encoding matches the rest of sing-box.
//
// # A configured QUERY is a query, not path content
//
// XHTTP deployments routinely put a query in the configured path:
//
//	"path": "/?proxyip=149.56.109.62"    the Cloudflare Worker / edgetunnel / relay shape
//	"path": "/base?x=1"
//
// The worker reads that query to pick an upstream, so losing it is losing the relay.
//
// `URLSetPath` is `net/url.(*URL).setPath`, which percent-encodes everything handed to it AS A PATH.
// A `?` is not a legal path character, so a configured query used to arrive as a literal path segment:
//
//	configured   /?proxyip=149.56.109.62
//	URL.Path     /%3Fproxyip=149.56.109.62     (request line: GET /%3Fproxyip=149.56.109.62 HTTP/1.1)
//	URL.RawQuery ""                            an EMPTY query, so the worker sees no `proxyip`
//
// Nothing errors: the request is well formed and the origin answers. That is why the split happens
// BEFORE setPath rather than by repairing the path afterwards - once the `?` is inside Path it is
// already escaped, and `RawQuery` no longer carries the operator's bytes.
//
// The split is `strings.Cut` on the FIRST `?`, which is exactly where a URI's query begins (RFC 3986
// section 3). A `?` inside a query VALUE arrives percent-encoded, so it is already `%3F` by the time
// it is configured and is not a separator here; a `?` inside a path SEGMENT is likewise written
// `%3F`. The query half is assigned to RawQuery verbatim, so the operator's own encoding - including
// deliberate `%20` and an empty `c=` - reaches the wire unchanged and is never re-encoded.
func (c *Client) baseURL() (*url.URL, error) {
	u := &url.URL{
		Scheme: c.scheme,
		Host:   c.serverAddr.String(),
	}
	configuredPath, configuredQuery, hasQuery := strings.Cut(c.path, "?")
	if !strings.HasPrefix(configuredPath, "/") {
		// A bare "?query" with no path is a legal URI reference; it targets "/".
		configuredPath = "/" + configuredPath
	}
	if err := sHTTP.URLSetPath(u, configuredPath); err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	if hasQuery {
		u.RawQuery = configuredQuery
	}
	return u, nil
}

// newRequest constructs an XHTTP request: it builds the base URL, lets the
// placement engine position the sessionID and (packet-up) seqStr, then attaches
// X-Padding. An empty sessionID emits no session metadata (stream-one targets the
// bare path with no sessionId, which is how the server routes the bidirectional
// branch). An empty seqStr emits no seq (stream modes).
func (c *Client) newRequest(ctx context.Context, method, sessionID, seqStr string, body interface{ Read([]byte) (int, error) }) (*http.Request, error) {
	u, err := c.baseURL()
	if err != nil {
		return nil, err
	}
	basePath := u.Path
	request := &http.Request{
		Method: method,
		URL:    u,
		Header: c.headers.Clone(),
		Host:   c.host,
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	c.applyMeta(request, basePath, sessionID, seqStr)
	c.applyXPadding(request)
	if body != nil {
		request.Body = readCloser{body}
	}
	// lx: SPEC 104 — on HTTP/1.1 the long requests (download GET, streamed
	// bodies; no seq) take their own connection, like Xray's DisableKeepAlives
	// client; packet-up upload POSTs (with a seq) stay on keep-alive.
	if c.httpVersion == httpVersion11 && seqStr == "" {
		request.Close = true
	}
	return request.WithContext(ctx), nil
}

// newSessionID returns a random session id for one dial. With session_table and
// session_length configured it draws length.rand() characters from the alphabet,
// mirroring Xray's GenerateSessionID; otherwise it falls back to the dashed-UUID
// form. The server treats the id as an opaque grouping key and never needs to know
// which form was used, so this is a client-only obfuscation knob.
func (c *Client) newSessionID() string {
	if c.meta.sessionTable == "" {
		return newUUIDSessionID()
	}
	table := c.meta.sessionTable
	id := make([]byte, c.meta.sessionLength.rand())
	for i := range id {
		id[i] = table[randIntn(len(table))]
	}
	return string(id)
}

// newUUIDSessionID returns a random session id formatted as a dashed UUID string
// (8-4-4-4-12), matching Xray's sessionId = uuid.New().String() (verified against
// XTLS/Xray-core transport/internet/splithttp dialer.go). This is the default and
// the form an unconfigured Xray peer also produces.
func newUUIDSessionID() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	const hexdigits = "0123456789abcdef"
	var h [32]byte
	for i, v := range b {
		h[i*2] = hexdigits[v>>4]
		h[i*2+1] = hexdigits[v&0x0f]
	}
	return string(h[0:8]) + "-" + string(h[8:12]) + "-" + string(h[12:16]) + "-" + string(h[16:20]) + "-" + string(h[20:32])
}

// readCloser adapts a plain reader to io.ReadCloser for use as a request body
// without pulling in an extra import.
type readCloser struct {
	r interface{ Read([]byte) (int, error) }
}

func (r readCloser) Read(p []byte) (int, error) { return r.r.Read(p) }
func (r readCloser) Close() error               { return nil }

// drainAndClose fully discards then closes an HTTP response body.
func drainAndClose(body interface {
	Read([]byte) (int, error)
	Close() error
},
) {
	buffer := buf.Get(buf.BufferSize)
	for {
		if _, err := body.Read(buffer); err != nil {
			break
		}
	}
	buf.Put(buffer)
	_ = body.Close()
}
