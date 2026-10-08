package group

import (
	"context"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Tests for target selection, the record model and result classification.
//
// Every test builds its members as in-tree fakes with injectable behaviour and
// call counters, so the assertions are about what the group actually asked the
// network to do rather than about the fields it happens to keep.

func TestConstructorValidation(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("group-test")
	for _, testCase := range []struct {
		name    string
		options option.GroupDNSServerOptions
		want    string
	}{
		{
			name:    "empty servers",
			options: option.GroupDNSServerOptions{},
			want:    "group[g]: servers is required and must not be empty",
		},
		{
			name:    "self reference",
			options: option.GroupDNSServerOptions{Servers: badoption.Listable[string]{"g"}},
			want:    "group[g]: group cannot contain itself",
		},
		{
			name:    "duplicate",
			options: option.GroupDNSServerOptions{Servers: badoption.Listable[string]{"a", "a"}},
			want:    "group[g]: duplicate server: a",
		},
		{
			name:    "unknown mode",
			options: option.GroupDNSServerOptions{Servers: badoption.Listable[string]{"a"}, Mode: "roundrobin"},
			want:    "group[g]: unknown mode: roundrobin (expected stable, fastest or parallel)",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewTransport(context.Background(), logger, "g", testCase.options)
			require.EqualError(t, err, testCase.want)
		})
	}
}

func TestConstructorDefaultsAndDependencies(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("group-test")

	rawTransport, err := NewTransport(context.Background(), logger, "g", option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"a", "b"},
	})
	require.NoError(t, err)
	transport := rawTransport.(*Transport)
	require.Equal(t, ModeStable, transport.mode, "an empty mode must default to stable")
	require.Equal(t, DefaultErrorTTL, transport.errorTTL)
	require.Equal(t, DefaultWinTTL, transport.winTTL)
	require.Equal(t, []string{"a", "b"}, transport.Dependencies(),
		"the member list is the dependency list the manager orders starts from")

	// A win_ttl outside fastest is unused, not an error: the field must be
	// accepted so a user can switch modes without rewriting the server.
	rawTransport, err = NewTransport(context.Background(), logger, "g", option.GroupDNSServerOptions{
		Servers: badoption.Listable[string]{"a"},
		Mode:    ModeStable,
		WinTTL:  badoption.Duration(time.Minute),
	})
	require.NoError(t, err)
	require.Equal(t, DefaultWinTTL, rawTransport.(*Transport).winTTL)
}

// TestStableKeepsCurrentRescuesAndDoesNotReturn covers the three stable-mode
// claims in one narrative: stickiness, rescue on failure, and no automatic
// migration back to a recovered ex-member.
func TestStableKeepsCurrentRescuesAndDoesNotReturn(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a", "b", "c"))
	harness.allSucceed()
	ctx := testContext(t)

	_, err := harness.exchange(ctx)
	require.NoError(t, err)
	first := harness.current()
	require.NotEmpty(t, first, "stable must choose a current member")

	_, err = harness.exchange(ctx)
	require.NoError(t, err)
	require.Equal(t, first, harness.current(), "a clean current member must be kept")
	require.Equal(t, int64(2), harness.calls(first), "the sticky member must be the one asked")

	// The current member now fails: the sticky attempt fails, the error is
	// recorded, and the rescue fan replaces it.
	harness.byTag[first].fail()
	response, err := harness.exchange(ctx)
	require.NoError(t, err, "the rescue fan must answer the query")
	require.NotNil(t, response)
	replacement := harness.current()
	require.NotEqual(t, first, replacement, "a failing target must be replaced by the rescue winner")
	require.Greater(t, harness.liveErrors(first), 0, "the failed target must have an error record")

	// The old member recovers. Stable must NOT migrate back to it: both it and
	// the replacement are clean, and stickiness owns the choice.
	harness.transport.noteSuccess(first, harness.generation())
	require.Zero(t, harness.liveErrors(first), "recovery erases the error record")
	callsBefore := harness.calls(first)
	_, err = harness.exchange(ctx)
	require.NoError(t, err)
	require.Equal(t, replacement, harness.current(),
		"a recovered ex-member must not be returned to automatically")
	require.Equal(t, callsBefore, harness.calls(first), "the recovered ex-member must not be asked")
}

func TestParallelFansEveryQueryAndMintsNoWins(t *testing.T) {
	harness := newGroupHarness(t, parallelOptions("a", "b", "c"))
	harness.allSucceed()
	ctx := testContext(t)

	_, err := harness.exchange(ctx)
	require.NoError(t, err)
	harness.awaitTotalCalls(t, 3, "parallel must fan over every clean member")
	require.Empty(t, harness.current(), "parallel must never set a current member")

	_, err = harness.exchange(ctx)
	require.NoError(t, err)
	waitFor(t, "both parallel fans to reach every member", func() bool {
		for _, fake := range harness.fakes {
			if fake.callCount() != 2 {
				return false
			}
		}
		return true
	})
	require.Equal(t, int64(6), harness.totalCalls(), "parallel must fan again on the next query")
	for _, fake := range harness.fakes {
		require.Zero(t, harness.liveWins(fake.tag), "parallel must not mint wins")
		require.Equal(t, int64(2), fake.callCount())
	}
}

func TestAllDirtyMakesExactlyOneAttemptInEveryMode(t *testing.T) {
	for _, mode := range []string{ModeStable, ModeFastest, ModeParallel} {
		t.Run(mode, func(t *testing.T) {
			harness := newGroupHarness(t, option.GroupDNSServerOptions{
				Servers: badoption.Listable[string]{"a", "b", "c"},
				Mode:    mode,
			})
			for _, fake := range harness.fakes {
				fake.fail()
			}
			for _, fake := range harness.fakes {
				harness.markDirty(fake.tag)
			}

			_, err := harness.exchange(testContext(t))
			require.Error(t, err, "every member is failing")
			require.Equal(t, int64(1), harness.totalCalls(),
				"with no clean member the query must be exactly ONE attempt, never one per member")
		})
	}
}

func TestSurvivalRotatesByOldestError(t *testing.T) {
	options := stableOptions("a", "b", "c")
	options.ErrorTTL = badoption.Duration(time.Hour)
	harness := newGroupHarness(t, options)
	for _, fake := range harness.fakes {
		fake.fail()
	}
	harness.setSurvivalRecords(map[string]time.Duration{
		"a": 90 * time.Second,
		"b": 60 * time.Second,
		"c": 30 * time.Second,
	})

	ctx := testContext(t)
	_, err := harness.exchange(ctx)
	require.Error(t, err)
	require.Equal(t, int64(1), harness.calls("a"), "fewest errors, oldest last error: a goes first")
	require.Zero(t, harness.calls("b"))
	require.Zero(t, harness.calls("c"))

	// a's failure is now the newest, so the next query must rotate to b.
	_, err = harness.exchange(ctx)
	require.Error(t, err)
	require.Equal(t, int64(1), harness.calls("b"), "a now has two errors; the next oldest is b")
	require.Zero(t, harness.calls("c"))
}

func TestSurvivalSuccessRestoresClean(t *testing.T) {
	options := stableOptions("a", "b")
	options.ErrorTTL = badoption.Duration(time.Hour)
	harness := newGroupHarness(t, options)
	harness.allSucceed()
	harness.setSurvivalRecords(map[string]time.Duration{
		"a": 90 * time.Second,
		"b": 30 * time.Second,
	})

	ctx := testContext(t)
	_, err := harness.exchange(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), harness.calls("a"), "a is the least dirty member and survives")
	require.Zero(t, harness.liveErrors("a"), "a survival success must erase the member's errors")
	require.Equal(t, 1, harness.liveErrors("b"))

	_, err = harness.exchange(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), harness.calls("a"), "the restored member is the only clean one")
	require.Zero(t, harness.calls("b"))
}

func TestErrorTTLExpiryRestoresCleanSetLazily(t *testing.T) {
	options := stableOptions("a", "b")
	options.ErrorTTL = badoption.Duration(time.Minute)
	harness := newGroupHarness(t, options)
	harness.allSucceed()
	// a's record is already older than error_ttl; b's is live. Nothing schedules
	// a timer: the query simply does not see a as dirty any more.
	harness.setSurvivalRecords(map[string]time.Duration{
		"a": 2 * time.Minute,
		"b": 0,
	})

	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	require.Equal(t, int64(1), harness.calls("a"), "an expired error record must return a to the clean set")
	require.Zero(t, harness.calls("b"))
	require.Zero(t, harness.liveErrors("a"))
}

func TestFailureClassification(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response *mDNS.Msg
		err      error
		failure  bool
	}{
		{"transport error", nil, errFake, true},
		{"timeout", nil, context.DeadlineExceeded, true},
		{"servfail as rcode error", nil, dns.RcodeError(mDNS.RcodeServerFailure), true},
		{"servfail as message", servfailResponse(queryMessage()), nil, true},
		{"nxdomain as rcode error", nil, dns.RcodeError(mDNS.RcodeNameError), false},
		{"nxdomain as message", nxdomainResponse(queryMessage()), nil, false},
		{"empty answer", successResponse(queryMessage()), nil, false},
		{"no response", nil, nil, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.failure, isFailure(testCase.response, testCase.err))
		})
	}
}

func TestValidAnswersAreReturnedWithoutRescue(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response func(message *mDNS.Msg) *mDNS.Msg
		rcode    int
	}{
		{"nxdomain", nxdomainResponse, mDNS.RcodeNameError},
		{"empty answer", successResponse, mDNS.RcodeSuccess},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newGroupHarness(t, stableOptions("a", "b"))
			harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				return testCase.response(message), nil
			})
			harness.byTag["b"].succeed()
			harness.setCurrent("a")

			response, err := harness.exchange(testContext(t))
			require.NoError(t, err)
			require.Equal(t, testCase.rcode, response.Rcode,
				"a valid answer must be returned exactly as the member produced it")
			require.Zero(t, harness.calls("b"), "a valid answer must not fan to another member")
			require.Zero(t, harness.liveErrors("a"), "a valid answer must not record an error")
		})
	}
}

func TestFailuresRescueToTheOtherMember(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response func(message *mDNS.Msg) (*mDNS.Msg, error)
	}{
		{"transport error", func(message *mDNS.Msg) (*mDNS.Msg, error) { return nil, errFake }},
		{"timeout", func(message *mDNS.Msg) (*mDNS.Msg, error) { return nil, context.DeadlineExceeded }},
		{"servfail", func(message *mDNS.Msg) (*mDNS.Msg, error) { return servfailResponse(message), nil }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newGroupHarness(t, stableOptions("a", "b"))
			harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				return testCase.response(message)
			})
			harness.byTag["b"].succeed()
			harness.setCurrent("a")

			response, err := harness.exchange(testContext(t))
			require.NoError(t, err, "the rescue fan must answer once the target fails")
			require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
			require.Equal(t, int64(1), harness.calls("b"), "a failure must rescue through the clean member")
			require.Greater(t, harness.liveErrors("a"), 0, "a failure must be recorded")
			require.Equal(t, "b", harness.current())
		})
	}
}

func TestResetAmnestiesRecordsCurrentAndGeneration(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	harness.allSucceed()

	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	require.NotEmpty(t, harness.current())
	require.Greater(t, harness.recordCount(), 0)
	generationBefore := harness.generation()

	harness.transport.Reset()
	require.Zero(t, harness.recordCount(), "Reset must replace the record tables")
	require.Empty(t, harness.current(), "Reset must clear the sticky target")
	require.Greater(t, harness.generation(), generationBefore, "Reset must bump the generation")

	// A write from before the amnesty must be dropped rather than poison the
	// fresh tables.
	harness.transport.noteError("a", generationBefore)
	require.Zero(t, harness.recordCount(), "a pre-Reset write must not reach the new tables")
}

func TestExchangeBeforeStartIsRejected(t *testing.T) {
	rawTransport, err := NewTransport(
		context.Background(),
		log.NewNOPFactory().NewLogger("group-test"),
		"g",
		stableOptions("a"),
	)
	require.NoError(t, err)
	_, err = rawTransport.Exchange(testContext(t), queryMessage())
	require.EqualError(t, err, "group[g]: not started")
}

func TestRegistrationProvidesTheOptionsType(t *testing.T) {
	registry := dns.NewTransportRegistry()
	RegisterTransport(registry)
	options, loaded := registry.CreateOptions(C.DNSTypeGroup)
	require.True(t, loaded, "the group type must be registered under the shared transport registry")
	require.IsType(t, (*option.GroupDNSServerOptions)(nil), options)
}
