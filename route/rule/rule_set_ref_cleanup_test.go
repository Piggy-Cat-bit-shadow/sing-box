package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	slogger "github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Evidence that a real rule-set's Cleanup() release is governed by the reference counter, which is
// what makes the TUN inbound's missing DecRef an actual resource leak rather than a bookkeeping
// blemish.
//
// The chain is: TUN Start IncRef -> the rule-set keeps its parsed rules across updates and refuses
// to drop them in Cleanup -> the router calls Cleanup once the Box has started, expecting the
// rule-sets whose consumers are gone to release their rules -> with the reference never released, the
// rules of every rule-set a TUN referenced are pinned for the lifetime of the process.
//
// These tests use the REAL implementations, not a double, because the question is precisely whether
// the production Cleanup honours the counter.

// newInlineRuleSet builds a real LocalRuleSet from an inline rule, so Match() has something to find.
func newInlineRuleSet(t *testing.T, domain string) *LocalRuleSet {
	t.Helper()
	ruleSet, err := NewLocalRuleSet(
		context.Background(),
		slogger.NOP(),
		"ref-cleanup-test",
		option.RuleSet{
			Type: "inline",
			InlineOptions: option.PlainRuleSet{
				Rules: []option.HeadlessRule{{
					Type: "default",
					DefaultOptions: option.DefaultHeadlessRule{
						Domain: []string{domain},
					},
				}},
			},
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, ruleSet.rules, "the fixture must have parsed rules for the release to be observable")
	return ruleSet
}

// TestLocalRuleSetCleanupHonoursRefs is the real-object half of S01.
func TestLocalRuleSetCleanupHonoursRefs(t *testing.T) {
	ruleSet := newInlineRuleSet(t, "pinned.example.com")
	metadata := &adapter.InboundContext{Domain: "pinned.example.com"}
	require.True(t, ruleSet.Match(metadata), "the fixture rule-set must match its own domain to begin with")

	// A live consumer, exactly as the TUN inbound is one.
	ruleSet.IncRef()

	ruleSet.Cleanup()
	require.NotEmpty(t, ruleSet.rules,
		"Cleanup must not drop the rules while a consumer still holds a reference")
	require.True(t, ruleSet.Match(metadata),
		"and the rules must still work, which is the behaviour the reference protects")

	ruleSet.DecRef()

	ruleSet.Cleanup()
	require.Empty(t, ruleSet.rules,
		"once the last reference is released, Cleanup must actually drop the rules; this is the "+
			"release the TUN inbound used to make impossible")
	require.False(t, ruleSet.Match(metadata),
		"and the rule-set must no longer match, which is the externally visible consequence")
}

// TestRemoteRuleSetCleanupHonoursRefs is the same contract for the remote implementation, which is
// the one updated on a timer and therefore the one whose rules are worth pinning.
func TestRemoteRuleSetCleanupHonoursRefs(t *testing.T) {
	ruleSet := &RemoteRuleSet{}
	// The rule value is irrelevant: Cleanup only decides whether the slice survives, and a nil
	// element keeps the fixture from needing a full rule graph.
	ruleSet.rules = []adapter.HeadlessRule{nil}

	ruleSet.IncRef()
	ruleSet.Cleanup()
	require.NotEmpty(t, ruleSet.rules, "a referenced remote rule-set must keep its rules across Cleanup")

	ruleSet.DecRef()
	ruleSet.Cleanup()
	require.Empty(t, ruleSet.rules,
		"an unreferenced remote rule-set must release its rules, so an update does not have to keep "+
			"them alive for a consumer that is gone")
}

// TestRuleSetDecRefRejectsNegativeCounts pins that the counter is strict in production, which is what
// makes a double DecRef a defect that cannot be quietly absorbed.
func TestRuleSetDecRefRejectsNegativeCounts(t *testing.T) {
	require.Panics(t, func() {
		(&LocalRuleSet{}).DecRef()
	}, "LocalRuleSet must panic on a negative reference count")
	require.Panics(t, func() {
		(&RemoteRuleSet{}).DecRef()
	}, "RemoteRuleSet must panic on a negative reference count")
}
