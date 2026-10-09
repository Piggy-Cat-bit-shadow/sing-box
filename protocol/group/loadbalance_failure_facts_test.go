package group

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The failure-fact table.
//
// # What this is and what it is NOT
//
// It is NOT a table that decides policy. §5.2 of the architecture-closure prompt forbids collapsing
// every subsystem onto one enum, and the same errno genuinely means different things in different
// places: EADDRNOTAVAIL to the dual-stack scheduler is evidence about an ADDRESS FAMILY, to the
// load-balance ledger it is explicitly NOT evidence about a member ("the local interface, which every
// member shares"), and to the failover retry it is worth another attempt. All three readings are
// correct for their own question, which is exactly why there is no universal class.
//
// What it does is pin, per fact, the final behaviour of each subsystem that consumes it - retry,
// global member penalty, health, recovery - so that a future change to a shared predicate cannot
// silently move one of them without the others being considered.
//
// # Why the table is written twice
//
// The first half asserts the FACTS (adapter.IsCallerCancellation / IsOwnTeardown /
// IsResourceSuspended). The second half asserts the POLICIES that consume them
// (RetryThisFlow / PenalizeMemberGlobally). A change that made both halves agree by changing the
// expectations would be visible as a large diff here rather than as a one-line silence.

// factRow is one error and the answer each consumer must give for it.
type factRow struct {
	name string
	err  error

	// The facts.
	callerCancellation bool
	ownTeardown        bool
	policySuppression  bool

	// The policies.
	retry  bool
	global bool
}

func factTable() []factRow {
	wrapped := fmt.Errorf("dial tcp 10.0.0.1:443: %w", syscall.ECONNREFUSED)
	joinedCancelled := errors.Join(errors.New("attempt 1"), context.Canceled)
	joinedClosed := errors.Join(errors.New("attempt 1"), net.ErrClosed)
	joinedSuspended := errors.Join(errors.New("attempt 1"), adapter.ErrResourceSuspended)
	return []factRow{
		// --- the three "the measurement never happened" conditions -----------------------------
		{name: "context.Canceled", err: context.Canceled, callerCancellation: true},
		{name: "net.ErrClosed", err: net.ErrClosed, ownTeardown: true},
		{name: "ErrResourceSuspended", err: adapter.ErrResourceSuspended, policySuppression: true},
		{name: "wrapped context.Canceled", err: fmt.Errorf("open connection: %w", context.Canceled), callerCancellation: true},
		{name: "multierror carrying context.Canceled", err: joinedCancelled, callerCancellation: true},
		{name: "multierror carrying net.ErrClosed", err: joinedClosed, ownTeardown: true},
		{name: "multierror carrying the suspended sentinel", err: joinedSuspended, policySuppression: true},

		// --- retryable path conditions ----------------------------------------------------------
		{name: "context.DeadlineExceeded", err: context.DeadlineExceeded, retry: true},
		{name: "os.ErrDeadlineExceeded", err: os.ErrDeadlineExceeded, retry: true},
		{name: "EHOSTUNREACH", err: syscall.EHOSTUNREACH, retry: true, global: true},
		{name: "ENETUNREACH", err: syscall.ENETUNREACH, retry: true, global: true},
		// The local interface is shared by every member, so the failover retry uses it but the
		// ledger must not blame the member for it. This is the divergence that proves a single
		// universal class cannot exist.
		{name: "EADDRNOTAVAIL", err: syscall.EADDRNOTAVAIL, retry: true},
		{name: "ENETDOWN", err: syscall.ENETDOWN, retry: true},
		{name: "ETIMEDOUT", err: syscall.ETIMEDOUT, retry: true},
		{name: "ECONNREFUSED", err: syscall.ECONNREFUSED, retry: true, global: true},
		{name: "wrapped ECONNREFUSED", err: wrapped, retry: true, global: true},

		// --- measured and bad, but not evidence about the path ----------------------------------
		{name: "ECONNRESET", err: syscall.ECONNRESET},
		{name: "io.EOF", err: io.EOF},

		// --- not understood at all: every consumer must be conservative -------------------------
		{name: "nil", err: nil},
		{name: "unknown error", err: errors.New("something nobody has classified")},
	}
}

// TestFailureFactsAreClassifiedByBehaviour is the fact half.
func TestFailureFactsAreClassifiedByBehaviour(t *testing.T) {
	for _, row := range factTable() {
		t.Run(row.name, func(t *testing.T) {
			require.Equal(t, row.callerCancellation, adapter.IsCallerCancellation(row.err),
				"IsCallerCancellation(%v)", row.err)
			require.Equal(t, row.ownTeardown, adapter.IsOwnTeardown(row.err),
				"IsOwnTeardown(%v)", row.err)
			require.Equal(t, row.policySuppression, adapter.IsResourceSuspended(row.err),
				"IsResourceSuspended(%v)", row.err)
			// The three facts are disjoint by construction. An error that satisfied two of them
			// would make "which subsystem ended this?" unanswerable, which is the collapse this
			// whole file exists to prevent.
			satisfied := 0
			for _, fact := range []bool{row.callerCancellation, row.ownTeardown, row.policySuppression} {
				if fact {
					satisfied++
				}
			}
			require.LessOrEqual(t, satisfied, 1, "the facts are not disjoint for %v", row.err)
		})
	}
}

// TestFailureFactsDriveEachPolicyWithItsOwnAnswer is the policy half.
//
// The two policies are asserted separately, and a row may legitimately disagree between them - that
// disagreement is the point of §5.2 and is what the table documents rather than removes.
func TestFailureFactsDriveEachPolicyWithItsOwnAnswer(t *testing.T) {
	member := &penaltyTestMember{tag: "node", outboundType: "vless"}
	for _, row := range factTable() {
		t.Run(row.name, func(t *testing.T) {
			require.Equal(t, row.retry, RetryThisFlow(row.err),
				"RetryThisFlow(%v): the flow-level decision changed", row.err)
			require.Equal(t, row.global, PenalizeMemberGlobally(member, row.err),
				"PenalizeMemberGlobally(%v): the member-level decision changed", row.err)
		})
	}
}

// TestTheFactsCoverTheWholeCancellationFamily is the property the other two halves are checked
// against: every row that is "not a fact about the node" is recognised as one of the three, and every
// row that IS a fact about the node is recognised as none of them.
//
// It is the assertion that would fail if a new sentinel were added without being classified, which is
// how a cancellation quietly becomes a node failure again.
func TestTheFactsCoverTheWholeCancellationFamily(t *testing.T) {
	for _, row := range factTable() {
		notMeasured := adapter.IsCallerCancellation(row.err) ||
			adapter.IsOwnTeardown(row.err) ||
			adapter.IsResourceSuspended(row.err)
		// A nil error is "no failure", not "not measured"; the unknown error is deliberately
		// unclassified and must be treated as a real failure by the health layer's default branch.
		isNoFailure := row.err == nil
		isUnknown := row.name == "unknown error"
		if isNoFailure || isUnknown {
			require.False(t, notMeasured, "%s must not be classified as 'not measured'", row.name)
			continue
		}
		require.Equal(t, !(row.retry || row.global || row.name == "ECONNRESET" || row.name == "io.EOF"),
			notMeasured, "%s: the cancellation family and the path-failure family disagree", row.name)
	}
}

// penaltyTestMember is the minimum adapter.Outbound PenalizeMemberGlobally needs: a tag and a type,
// because the member's KIND is what decides whether an errno describes the destination or the member's
// own first hop.
type penaltyTestMember struct {
	adapter.Outbound
	tag          string
	outboundType string
}

func (m *penaltyTestMember) Type() string { return m.outboundType }
func (m *penaltyTestMember) Tag() string  { return m.tag }

// TestADestinationDialIsNeverBlamedOnTheMember pins the one structural input the penalty classifier
// has. It is here rather than in the table because it is a property of the MEMBER, not of the error:
// the same errno must produce two different answers for a direct member and a proxying one, and that
// pair is the clearest statement of why §5.2 forbids a universal class.
func TestADestinationDialIsNeverBlamedOnTheMember(t *testing.T) {
	proxying := &penaltyTestMember{tag: "proxy", outboundType: "vless"}
	direct := &penaltyTestMember{tag: "direct", outboundType: "direct"}
	block := &penaltyTestMember{tag: "block", outboundType: "block"}

	for _, err := range []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH} {
		require.True(t, PenalizeMemberGlobally(proxying, err),
			"a proxying member's first hop refused: %v", err)
		require.False(t, PenalizeMemberGlobally(direct, err),
			"a direct member's refusal describes the DESTINATION, not the member: %v", err)
		require.False(t, PenalizeMemberGlobally(block, err),
			"a block member's refusal describes the rule, not a member: %v", err)
	}
}
