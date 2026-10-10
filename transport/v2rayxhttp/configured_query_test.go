package v2rayxhttp

import (
	"context"
	"net/url"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// ---------------------------------------------------------------------------
// A configured QUERY in the path must survive to the request line
// ---------------------------------------------------------------------------
//
// # The configuration this is about
//
// XHTTP deployments routinely need a query on the configured path:
//
//	"path": "/?proxyip=149.56.109.62"
//	"path": "/base?x=1"
//
// The first is the Cloudflare Worker / edgetunnel / relay shape, where the worker reads the query to
// pick an upstream. It is not decoration: a worker that does not see `proxyip` does not relay.
//
// # The failure mode
//
// `NewClient` keeps the configured path verbatim, and `baseURL` passes it through
// `sHTTP.URLSetPath`, which is `net/url.(*URL).setPath` - a function that percent-encodes everything it
// is given as a PATH. `?` is not a legal path character, so it becomes `%3F`:
//
//	configured   /?proxyip=149.56.109.62
//	URL.Path     /%3Fproxyip=149.56.109.62
//	request line GET /%3Fproxyip=149.56.109.62 HTTP/1.1
//
// The origin sees a path segment literally named `%3Fproxyip=149.56.109.62` and an EMPTY query. No
// error is produced anywhere: the request is well formed, the server answers, and the relay silently
// does the wrong thing. That is why the assertion below is on the request LINE and not on
// `URL.RawQuery` - a test that only checked `RawQuery` would pass for an implementation that dropped
// the query from the path and never put it anywhere.

// requestURIFor builds one request with the given client and returns both the request line target and
// the parsed URL, so a failure can distinguish "the query was mangled" from "the query was lost".
func requestURIFor(t *testing.T, c *Client, sessionID, seqStr string) (requestURI string, u *url.URL) {
	t.Helper()
	request, err := c.newRequest(context.Background(), "POST", sessionID, seqStr, nil)
	if err != nil {
		t.Fatalf("newRequest(%q,%q): %v", sessionID, seqStr, err)
	}
	return request.URL.RequestURI(), request.URL
}

// TestConfiguredQuerySurvivesToTheRequestURI is the reproduction.
//
// It is asserted on `URL.RequestURI()`, which is exactly what the HTTP write path puts after the method
// in the request line, so the assertion is about the bytes an origin receives.
func TestConfiguredQuerySurvivesToTheRequestURI(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		want       string
	}{
		{
			"the worker/relay shape",
			"/?proxyip=149.56.109.62",
			"/?proxyip=149.56.109.62",
		},
		{
			"a path with a query",
			"/base?x=1",
			"/base?x=1",
		},
		{
			"several parameters keep their order and encoding",
			"/base?a=1&b=two%20words&c=",
			"/base?a=1&b=two%20words&c=",
		},
		{
			"a bare query with no path",
			"?proxyip=149.56.109.62",
			"/?proxyip=149.56.109.62",
		},
		{
			"no query at all: the previous behaviour, unchanged",
			"/upload/",
			"/upload/",
		},
		{
			"a percent escape in the PATH is not double-encoded",
			"/a%20b",
			"/a%20b",
		},
		{
			"a question mark inside a query value is data, not a separator",
			"/base?q=a%3Fb",
			"/base?q=a%3Fb",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newHeaderSessionClient(testCase.configured)
			requestURI, u := requestURIFor(t, client, "sid123", "")

			if strings.Contains(u.Path, "?") {
				t.Fatalf("URL.Path is %q, which contains a literal question mark: the configured query "+
					"was taken as PATH content", u.Path)
			}
			if requestURI != testCase.want {
				t.Fatalf("request line target = %q, want %q (configured path %q).\n"+
					"URL.Path=%q URL.RawQuery=%q",
					requestURI, testCase.want, testCase.configured, u.Path, u.RawQuery)
			}
		})
	}
}

// TestConfiguredQueryWithPathPlacementKeepsBoth pins the interaction that is easiest to get wrong: path
// placement appends the session id (and seq) as path SEGMENTS while the configured query must stay a
// query. A fix that moved the whole configured string into RawQuery would drop the base path; a fix that
// left it in the path would escape the query; and a fix that ran the placement against the whole
// configured string instead of the path half would put the session id AFTER the query.
func TestConfiguredQueryWithPathPlacementKeepsBoth(t *testing.T) {
	meta, _ := normalizeMeta(metaOptions{}, modePacketUp)
	client := &Client{
		scheme:       "https",
		host:         "example.com",
		serverAddr:   M.ParseSocksaddr("example.com:443"),
		path:         "/base?x=1",
		paddingRange: intRange{0, 0},
		meta:         meta,
	}

	cases := []struct {
		name      string
		sessionID string
		seqStr    string
		want      string
	}{
		{
			"session segment is inserted before the query",
			"sid123", "",
			"/base/sid123?x=1",
		},
		{
			"session and seq segments, in that order, before the query",
			"sid123", "7",
			"/base/sid123/7?x=1",
		},
		{
			"stream-one's bare path keeps the query",
			"", "",
			"/base/?x=1",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requestURI, u := requestURIFor(t, client, testCase.sessionID, testCase.seqStr)
			if requestURI != testCase.want {
				t.Fatalf("request line target = %q, want %q\nURL.Path=%q URL.RawQuery=%q",
					requestURI, testCase.want, u.Path, u.RawQuery)
			}
		})
	}
}

// TestConfiguredQueryCoexistsWithPlacementQuery pins the case that needs real merging rather than a
// copy: a query-placement session id and a configured query must BOTH be present, and neither may
// overwrite the other. `setQuery` re-encodes RawQuery, so a fix that assigned RawQuery directly from the
// configured string would lose the session id, and one that assigned it from the session id would lose
// the operator's parameter.
func TestConfiguredQueryCoexistsWithPlacementQuery(t *testing.T) {
	meta, _ := normalizeMeta(metaOptions{
		SessionPlacement: placementQuery,
		SeqPlacement:     placementQuery,
	}, modePacketUp)
	client := &Client{
		scheme:       "https",
		host:         "example.com",
		serverAddr:   M.ParseSocksaddr("example.com:443"),
		path:         "/base?proxyip=149.56.109.62",
		paddingRange: intRange{0, 0},
		meta:         meta,
	}

	requestURI, u := requestURIFor(t, client, "sid123", "7")

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("RawQuery %q does not parse: %v", u.RawQuery, err)
	}
	if query.Get("proxyip") != "149.56.109.62" {
		t.Fatalf("the configured parameter was lost: RawQuery=%q (request line %q). A query-placement "+
			"session id must be MERGED into the configured query, not replace it", u.RawQuery, requestURI)
	}
	if query.Get(meta.sessionKey) != "sid123" {
		t.Fatalf("the session id was not placed: RawQuery=%q", u.RawQuery)
	}
	if query.Get(meta.seqKey) != "7" {
		t.Fatalf("the seq was not placed: RawQuery=%q", u.RawQuery)
	}
	if u.Path != "/base" {
		t.Fatalf("URL.Path = %q, want the configured path with no query in it", u.Path)
	}
}

// TestConfiguredQuerySurvivesPadding pins that the X-Padding helper does not replace the configured
// query. The legacy (non-obfs) form builds its OWN referer URL and assigns RawQuery on that copy of the
// path; if it were ever pointed at the request URL instead, the operator's parameter would be replaced
// by the padding key.
//
// Padding fires only when the configured range is non-zero, so the range is set here: a version of this
// test that left it at zero would pass without the padding path ever running, which is the shape of a
// test that proves nothing.
func TestConfiguredQuerySurvivesPadding(t *testing.T) {
	meta, _ := normalizeMeta(metaOptions{}, modePacketUp)
	client := &Client{
		scheme:       "https",
		host:         "example.com",
		serverAddr:   M.ParseSocksaddr("example.com:443"),
		path:         "/?proxyip=149.56.109.62",
		paddingRange: intRange{16, 16},
		meta:         meta,
	}

	request, err := client.newRequest(context.Background(), "POST", "", "", nil)
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	if request.URL.RequestURI() != "/?proxyip=149.56.109.62" {
		t.Fatalf("padding changed the request line target to %q", request.URL.RequestURI())
	}
	// The padding really did fire, so the assertion above is about coexistence rather than about a
	// helper that never ran.
	referer := request.Header.Get("Referer")
	if referer == "" {
		t.Fatalf("padding did not fire, so this test proves nothing about coexistence")
	}
	if !strings.Contains(referer, "x_padding=") {
		t.Fatalf("the referer is not a padding URL: %q", referer)
	}
}
