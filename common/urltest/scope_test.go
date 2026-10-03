package urltest

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// Tests for target normalisation, the expected-status parser and scope identity.

func TestNormalizeURLTestURLEmptyUsesTheDefault(t *testing.T) {
	normalized, err := NormalizeURLTestURL("")
	require.NoError(t, err)
	require.Equal(t, DefaultURLTestURL, normalized)
}

func TestNormalizeURLTestURLExplicitDefaultIsIdentical(t *testing.T) {
	// The empty target and the explicit default must be the SAME scope, or the same node would
	// accumulate two histories for one measurement.
	fromEmpty, err := NormalizeURLTestURL("")
	require.NoError(t, err)
	fromExplicit, err := NormalizeURLTestURL(DefaultURLTestURL)
	require.NoError(t, err)
	require.Equal(t, fromEmpty, fromExplicit)
}

func TestNormalizeURLTestURLRejectsUnsupportedSchemes(t *testing.T) {
	for _, link := range []string{
		"ftp://example.com/test",
		"file:///tmp/a",
		"ws://example.com/",
		"wss://example.com/",
		"ssh://example.com/",
		"gopher://example.com/",
		"://bad",
		"https:///missing-host",
		"example.com/generate_204",
	} {
		t.Run(link, func(t *testing.T) {
			_, err := NormalizeURLTestURL(link)
			require.Error(t, err,
				"an unusable target must be refused here, before anything is dialled")
		})
	}
}

func TestNormalizeURLTestURLRejectsInvalidPorts(t *testing.T) {
	for _, link := range []string{
		"http://example.com:0/",
		"http://example.com:99999/",
		"https://example.com:abc/",
	} {
		_, err := NormalizeURLTestURL(link)
		require.Error(t, err, "invalid port in %s", link)
	}
}

func TestNormalizeURLTestURLDropsFragmentButKeepsPathAndQuery(t *testing.T) {
	withFragment, err := NormalizeURLTestURL("https://example.com/generate_204?a=1#section")
	require.NoError(t, err)
	withoutFragment, err := NormalizeURLTestURL("https://example.com/generate_204?a=1")
	require.NoError(t, err)

	require.Equal(t, withoutFragment, withFragment,
		"a fragment is never sent to the server, so it cannot describe a different measurement")

	require.Contains(t, withFragment, "/generate_204?a=1",
		"the path and query do change the request and must be preserved")
}

func TestNormalizeURLTestURLTwoFragmentsAreOneScope(t *testing.T) {
	first, err := NormalizeURLTestURL("https://example.com/generate_204#a")
	require.NoError(t, err)
	second, err := NormalizeURLTestURL("https://example.com/generate_204#b")
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestParseExpectedStatusSyntax(t *testing.T) {
	cases := map[string]string{
		"":                "*",
		"*":               "*",
		"204":             "204",
		"200-299":         "200-299",
		"200/204":         "200/204",
		"200,204":         "200/204",
		"200/204/301-399": "200/204/301-399",
		"200,204,301-399": "200/204/301-399",
		"299-200":         "200-299",
	}
	for input, wantKey := range cases {
		t.Run(input, func(t *testing.T) {
			parsed, err := ParseExpectedStatus(input)
			require.NoError(t, err)
			require.Equal(t, wantKey, parsed.Canonical(),
				"the canonical key must not depend on the caller's spelling")
		})
	}
}

func TestParseExpectedStatusMatches(t *testing.T) {
	strict, err := ParseExpectedStatus("204")
	require.NoError(t, err)
	require.True(t, strict.Match(204))
	require.False(t, strict.Match(302))
	require.False(t, strict.Match(200))

	rangeSet, err := ParseExpectedStatus("200-299")
	require.NoError(t, err)
	require.True(t, rangeSet.Match(200))
	require.True(t, rangeSet.Match(204))
	require.True(t, rangeSet.Match(299))
	require.False(t, rangeSet.Match(302))

	multi, err := ParseExpectedStatus("200,204,301-399")
	require.NoError(t, err)
	require.True(t, multi.Match(200))
	require.True(t, multi.Match(204))
	require.True(t, multi.Match(301))
	require.True(t, multi.Match(399))
	require.False(t, multi.Match(201))

	any, err := ParseExpectedStatus("*")
	require.NoError(t, err)
	require.True(t, any.Match(0), "no constraint accepts any status")
	require.True(t, any.Match(500))
}

func TestParseExpectedStatusRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{
		"abc",
		"0",
		"204-",
		"-204",
		"200--299",
		"204//200",
		"204,",
		"70000",
		"204-abc",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := ParseExpectedStatus(input)
			require.Error(t, err, "malformed expected status must be refused: %q", input)
		})
	}
}

func TestParseExpectedStatusRangeCountBound(t *testing.T) {
	// The value arrives from a query string, so the parser must not build an unbounded set.
	var many string
	for index := 0; index < 40; index++ {
		if index > 0 {
			many += "/"
		}
		many += "200"
	}
	_, err := ParseExpectedStatus(many)
	require.Error(t, err)

	// The bound itself is accepted.
	atLimit := ""
	for index := 0; index < maxExpectedStatusRanges; index++ {
		if index > 0 {
			atLimit += "/"
		}
		atLimit += "200"
	}
	_, err = ParseExpectedStatus(atLimit)
	require.NoError(t, err)
}

// --- scope identity (§43, §44) ---------------------------------------------------------

func TestScopeDiffersByURL(t *testing.T) {
	first, err := NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	second, err := NewMeasurementScope("https://b.example/generate_204", nil)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestScopeDiffersByExpected(t *testing.T) {
	// Same URL, different status expectation: a strict health check failing must not be able to
	// invalidate a result collected under "any status".
	strict, err := ParseExpectedStatus("204")
	require.NoError(t, err)

	anyScope, err := NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	strictScope, err := NewMeasurementScope("https://a.example/generate_204", strict)
	require.NoError(t, err)

	require.NotEqual(t, anyScope, strictScope)
	require.Equal(t, "*", anyScope.Expected)
	require.Equal(t, "204", strictScope.Expected)
}

func TestScopeIgnoresEquivalentSpellings(t *testing.T) {
	comma, err := ParseExpectedStatus("200,204")
	require.NoError(t, err)
	slash, err := ParseExpectedStatus("200/204")
	require.NoError(t, err)

	first, err := NewMeasurementScope("https://a.example/x", comma)
	require.NoError(t, err)
	second, err := NewMeasurementScope("https://a.example/x", slash)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

// --- history isolation (§43, §44) ------------------------------------------------------

func TestScopedHistoryIsolation(t *testing.T) {
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	scopeB, err := NewMeasurementScope("https://b.example/generate_204", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", scopeB, &adapter.URLTestHistory{Delay: 200})

	require.EqualValues(t, 20, storage.LoadURLTestHistoryFor("node-a", scopeA).Delay)
	require.EqualValues(t, 200, storage.LoadURLTestHistoryFor("node-a", scopeB).Delay)
}

func TestScopedHistoryDeleteDoesNotAffectOtherTargets(t *testing.T) {
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/generate_204", nil)
	require.NoError(t, err)
	scopeB, err := NewMeasurementScope("https://b.example/generate_204", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", scopeB, &adapter.URLTestHistory{Delay: 90})

	storage.DeleteURLTestHistoryFor("node-a", scopeB)

	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", scopeB))
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", scopeA),
		"a failure against one target must not erase the result for another")
	require.EqualValues(t, 20, storage.LoadURLTestHistoryFor("node-a", scopeA).Delay)
}

func TestScopedHistoryDeleteDoesNotCrossExpected(t *testing.T) {
	storage := NewHistoryStorage()

	strict, err := ParseExpectedStatus("204")
	require.NoError(t, err)

	anyScope, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	strictScope, err := NewMeasurementScope("https://a.example/x", strict)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", anyScope, &adapter.URLTestHistory{Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", strictScope, &adapter.URLTestHistory{Delay: 50})

	storage.DeleteURLTestHistoryFor("node-a", strictScope)

	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", strictScope))
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", anyScope),
		"a strict check failing must not erase the unconstrained measurement")
}

func TestLatestHistoryFollowsTheMostRecentStore(t *testing.T) {
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	scopeB, err := NewMeasurementScope("https://b.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	require.EqualValues(t, 20, storage.LoadURLTestHistory("node-a").Delay)

	storage.StoreURLTestHistoryFor("node-a", scopeB, &adapter.URLTestHistory{Delay: 200})
	require.EqualValues(t, 200, storage.LoadURLTestHistory("node-a").Delay,
		"the display entry must show the most recent measurement")
}

func TestDeletingTheLatestRepointsToTheRemainingMeasurement(t *testing.T) {
	// A failed test against one target must not blank the UI while another valid measurement for
	// the same node still exists.
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	scopeB, err := NewMeasurementScope("https://b.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", scopeB, &adapter.URLTestHistory{Delay: 90})

	// B is the latest; deleting it must fall back to A rather than clearing the display.
	storage.DeleteURLTestHistoryFor("node-a", scopeB)

	latest := storage.LoadURLTestHistory("node-a")
	require.NotNil(t, latest, "the display entry must survive while another measurement remains")
	require.EqualValues(t, 20, latest.Delay)
}

func TestDeletingTheLastMeasurementClearsTheLatest(t *testing.T) {
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)

	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	storage.DeleteURLTestHistoryFor("node-a", scopeA)

	require.Nil(t, storage.LoadURLTestHistory("node-a"))
}

func TestDeleteAllRemovesEveryScope(t *testing.T) {
	storage := NewHistoryStorage()

	scopeA, err := NewMeasurementScope("https://a.example/x", nil)
	require.NoError(t, err)
	scopeB, err := NewMeasurementScope("https://b.example/x", nil)
	require.NoError(t, err)
	storage.StoreURLTestHistoryFor("node-a", scopeA, &adapter.URLTestHistory{Delay: 20})
	storage.StoreURLTestHistoryFor("node-a", scopeB, &adapter.URLTestHistory{Delay: 90})

	storage.DeleteURLTestHistory("node-a")

	require.Nil(t, storage.LoadURLTestHistory("node-a"))
	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", scopeA))
	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", scopeB))
}
