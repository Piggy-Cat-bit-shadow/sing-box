package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the separation of request URL, measurement identity and dial destination.
//
// # Why the separation matters
//
// They were one normalised string, so a canonicalisation chosen for IDENTITY was also what got
// fetched and what got dialled. That is how "make two equivalent spellings share a scope" turns
// into "silently rewrite the request the user configured". Each of the three now has exactly the
// strictness its own job needs.

// TestEquivalentTargetsShareScope is §33, §43.
func TestEquivalentTargetsShareScope(t *testing.T) {
	for _, group := range [][]string{
		{"https://EXAMPLE.com:443/a", "https://example.com/a", "https://example.com:443/a"},
		{"http://example.com:80/a", "http://example.com/a"},
		{"https://example.com/a#frag", "https://example.com/a", "https://example.com/a#other"},
	} {
		t.Run(group[0], func(t *testing.T) {
			var scope string
			for index, link := range group {
				target, err := ParseMeasurementTarget(link)
				require.NoError(t, err, "%q must parse", link)
				if index == 0 {
					scope = target.ScopeURL
					continue
				}
				require.Equal(t, scope, target.ScopeURL,
					"%q and %q are the same measurement and must share one scope; two scopes would "+
						"split a node's history for one target", group[0], link)
			}
		})
	}
}

// TestNonDefaultPortStaysDistinct keeps a real difference a difference.
func TestNonDefaultPortStaysDistinct(t *testing.T) {
	base, err := ParseMeasurementTarget("https://example.com/a")
	require.NoError(t, err)

	other, err := ParseMeasurementTarget("https://example.com:8443/a")
	require.NoError(t, err)

	require.NotEqual(t, base.ScopeURL, other.ScopeURL,
		"a non-default port is a different endpoint, so it must not share a scope")

	// And explicitly writing the default port must NOT be treated as different.
	explicit, err := ParseMeasurementTarget("https://example.com:443/a")
	require.NoError(t, err)
	require.Equal(t, base.ScopeURL, explicit.ScopeURL,
		"writing the default port explicitly describes the same endpoint")
}

// TestDefaultPortsCanonicalizeOnlyForScope is §43.
//
// The default port may be dropped from the identity, but the request must keep what the user wrote
// and the dial must still have a port.
func TestDefaultPortsCanonicalizeOnlyForScope(t *testing.T) {
	target, err := ParseMeasurementTarget("https://example.com:443/a")
	require.NoError(t, err)

	require.Equal(t, "https://example.com/a", target.ScopeURL,
		"the identity omits a default port so both spellings agree")
	require.Equal(t, "https://example.com:443/a", target.RequestURL,
		"but the request keeps exactly what was configured")
	require.EqualValues(t, 443, target.Destination.Port,
		"and the dial target still has the port it needs")

	plain, err := ParseMeasurementTarget("https://example.com/a")
	require.NoError(t, err)
	require.EqualValues(t, 443, plain.Destination.Port,
		"an omitted HTTPS port resolves to 443 for the dial")

	httpTarget, err := ParseMeasurementTarget("http://example.com/a")
	require.NoError(t, err)
	require.EqualValues(t, 80, httpTarget.Destination.Port,
		"and an omitted HTTP port resolves to 80")
}

// TestRequestURLPreservesRequestSemantics is §33, §43.
//
// Canonicalisation for identity must not rewrite the request.
func TestRequestURLPreservesRequestSemantics(t *testing.T) {
	for _, link := range []string{
		"https://example.com/path/to/thing?z=1&a=2&m=3",
		"https://example.com/UPPER/Case?Mixed=Value",
		"https://example.com/a%2Fb?q=%20space",
		"https://user:pass@example.com/private",
	} {
		t.Run(link, func(t *testing.T) {
			target, err := ParseMeasurementTarget(link)
			require.NoError(t, err)

			// The query ORDER must survive: it is part of the request, and reordering it for a
			// scope key would change what a server sees.
			expected, err := parseForTest(link)
			require.NoError(t, err)

			require.Equal(t, expected.Path, mustParsePath(t, target.RequestURL),
				"the path must not be rewritten")
			require.Equal(t, expected.RawQuery, mustParseQuery(t, target.RequestURL),
				"the query must not be reordered or rewritten: it is part of the request")
		})
	}
}

// TestInvalidPortFailsBeforeDial is §31, §43.
//
// An unusable port must be rejected by the parser, so a detour is never asked to dial it.
func TestInvalidPortFailsBeforeDial(t *testing.T) {
	for _, link := range []string{
		"https://example.com:0/a",
		"https://example.com:99999/a",
		"https://example.com:-1/a",
		"https://example.com:abc/a",
	} {
		t.Run(link, func(t *testing.T) {
			_, err := ParseMeasurementTarget(link)
			require.Error(t, err,
				"an unusable port must fail here, before any detour is asked to connect")
		})
	}
}

// TestInvalidPortNeverReachesTheDialer proves it end to end with a dial counter.
func TestInvalidPortNeverReachesTheDialer(t *testing.T) {
	dialer := &countingDialer{}

	for _, link := range []string{"https://example.com:0/generate_204", "https://example.com:99999/generate_204"} {
		_, err := Measure(context.Background(), MeasureOptions{Link: link}, dialer)
		require.Error(t, err)
	}

	require.EqualValues(t, 0, dialer.dials.Load(),
		"a target with an invalid port must be rejected without dialling anything; the previous "+
			"code left the port to net/http, so the dial was attempted first")
}

// TestUnsupportedSchemeFailsBeforeDial keeps the scheme contract.
func TestUnsupportedSchemeFailsBeforeDial(t *testing.T) {
	dialer := &countingDialer{}
	for _, link := range []string{"ftp://example.com/a", "example.com/a", "socks5://example.com/a"} {
		_, err := Measure(context.Background(), MeasureOptions{Link: link}, dialer)
		require.Error(t, err, "%q must be refused", link)
	}
	require.EqualValues(t, 0, dialer.dials.Load())
}

// TestMeasurementUsesTheSplitTarget end to end: the request that reaches the server is the one
// configured, and the dial goes to the resolved port.
func TestMeasurementUsesTheSplitTarget(t *testing.T) {
	var (
		requestedPath  atomic.Value
		requestedQuery atomic.Value
		requestedHost  atomic.Value
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPath.Store(request.URL.Path)
		requestedQuery.Store(request.URL.RawQuery)
		requestedHost.Store(request.Host)
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}
	measurement, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204?z=1&a=2"}, dialer)
	require.NoError(t, err)
	require.GreaterOrEqual(t, measurement.Delay, uint16(1))

	require.Equal(t, "/generate_204", requestedPath.Load())
	require.Equal(t, "z=1&a=2", requestedQuery.Load(),
		"the query must arrive in the order it was configured")
	require.EqualValues(t, 1, dialer.dials.Load(), "exactly one dial")
}

// --- small helpers ---

func parseForTest(link string) (parsedTarget, error) {
	target, err := ParseMeasurementTarget(link)
	if err != nil {
		return parsedTarget{}, err
	}
	path, query := splitForTest(target.RequestURL)
	return parsedTarget{Path: path, RawQuery: query}, nil
}

type parsedTarget struct {
	Path     string
	RawQuery string
}

func splitForTest(rawURL string) (string, string) {
	for index := 0; index < len(rawURL); index++ {
		if rawURL[index] == '?' {
			return rawURL[:index], rawURL[index+1:]
		}
	}
	return rawURL, ""
}

func mustParsePath(t *testing.T, rawURL string) string {
	t.Helper()
	path, _ := splitForTest(rawURL)
	return path
}

func mustParseQuery(t *testing.T, rawURL string) string {
	t.Helper()
	_, query := splitForTest(rawURL)
	return query
}

var _ = net.IPv4len
var _ M.Socksaddr
