package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Configuration-validation tests for the URLTest group.

func configContext(t *testing.T) context.Context {
	t.Helper()
	return pause.WithDefaultManager(
		service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
}

// TestNegativeDurationsAreRejectedAtConfiguration is §48, §64(Q).
//
// A negative duration reached time.NewTicker, which panics. That is a runtime crash with a stack
// trace, long after the configuration was accepted, instead of a diagnostic naming the field.
func TestNegativeDurationsAreRejectedAtConfiguration(t *testing.T) {
	node := &stubOutbound{tag: "node-a"}

	for _, testCase := range []struct {
		name        string
		interval    time.Duration
		idleTimeout time.Duration
	}{
		{"negative interval", -time.Second, 0},
		{"negative idle_timeout", 0, -time.Second},
		{"both negative", -time.Second, -time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := NewURLTestGroupWithExpected(
					configContext(t),
					&stubOutboundManager{},
					log.NewNOPFactory().NewLogger("group"),
					[]adapter.Outbound{node},
					"https://probe.example/generate_204",
					"",
					testCase.interval,
					0,
					testCase.idleTimeout,
					false,
				)
				require.Error(t, err,
					"a negative duration must be refused when the group is built, not when a "+
						"ticker is created later")
			})
		})
	}
}

// TestIntervalExceedingIdleTimeoutIsRejected keeps the existing rule.
func TestIntervalExceedingIdleTimeoutIsRejected(t *testing.T) {
	node := &stubOutbound{tag: "node-a"}
	_, err := NewURLTestGroupWithExpected(
		configContext(t), &stubOutboundManager{}, log.NewNOPFactory().NewLogger("group"),
		[]adapter.Outbound{node}, "https://probe.example/generate_204", "",
		10*time.Minute, 0, time.Minute, false)
	require.Error(t, err)
}

// TestInvalidExpectedStatusFailsConfiguration is §17.
//
// The expression is parsed with the target, so an unusable one fails configuration rather than
// surfacing only when the first background check runs - by which time the operator has been told
// nothing and the group looks healthy.
func TestInvalidExpectedStatusFailsConfiguration(t *testing.T) {
	node := &stubOutbound{tag: "node-a"}

	for _, expression := range []string{"abc", "200-abc", "70000"} {
		t.Run(expression, func(t *testing.T) {
			_, err := NewURLTestGroupWithExpected(
				configContext(t), &stubOutboundManager{}, log.NewNOPFactory().NewLogger("group"),
				[]adapter.Outbound{node}, "https://probe.example/generate_204", expression,
				0, 0, 0, false)
			require.Error(t, err,
				"an unusable expected_status must fail configuration")
		})
	}
}

// TestExpectedStatusBecomesPartOfTheScope is §18.
//
// Two groups measuring the same URL but accepting different statuses are asking different
// questions, so their results must not share a scope.
func TestExpectedStatusBecomesPartOfTheScope(t *testing.T) {
	node := &stubOutbound{tag: "node-a"}

	build := func(expression string) *URLTestGroup {
		group, err := NewURLTestGroupWithExpected(
			configContext(t), &stubOutboundManager{}, log.NewNOPFactory().NewLogger("group"),
			[]adapter.Outbound{node}, "https://probe.example/generate_204", expression,
			0, 0, 0, false)
		require.NoError(t, err)
		return group
	}

	anyStatus := build("")
	only204 := build("204")
	sameAsOnly204 := build("204,")

	require.NotEqual(t, anyStatus.scope, only204.scope,
		"a group accepting any status and one requiring 204 ask different questions about the "+
			"same URL, so they must not share a scope")

	require.Equal(t, only204.scope, sameAsOnly204.scope,
		"while two spellings of the same accepted set must share one, or the same target would "+
			"occupy two scopes")

	require.Equal(t, "204", only204.scope.Expected)
	require.Equal(t, "*", anyStatus.scope.Expected,
		"an unconfigured expected_status keeps the historical 'accept anything' semantics")
}
