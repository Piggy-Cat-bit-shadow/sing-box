package group

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"

	"github.com/stretchr/testify/require"
)

// Failure / outcome facts, at the behaviour level.
//
// # The rule these tests exist for
//
// A measurement that never happened is NOT a measurement that failed. Three different conditions can
// end a probe without the node having answered, and all three must leave the member's health evidence
// exactly as they found it:
//
//	the resource is idle and this probe may not wake it   adapter.ErrResourceSuspended
//	THIS process ended the operation                       net.ErrClosed
//	the caller went away                                   context.Canceled
//
// Only the first was handled. The other two fell through to the health-failure branch, so a network
// transition - which closes the members' transports and makes in-flight dials fail with net.ErrClosed
// - deleted the health history of every member it caught mid-probe. The selection could then move
// because the device changed networks, which is the same class of mistake as waking an idle tunnel to
// measure it: a fact about the CORE being read as a fact about the NODE.
//
// The three are covered together here rather than one per condition, because the point is that they
// are one fact family at the health layer and must stay one answer.

// healthFactCase is one way a probe can end without an answer.
type healthFactCase struct {
	name string
	// err is what the member's dial returns.
	err error
	// roundCancelled cancels the round's own context instead, which is the fourth shape: the round
	// itself was abandoned.
	roundCancelled bool
}

func healthFactCases() []healthFactCase {
	return []healthFactCase{
		{name: "suspended sentinel", err: adapter.ErrResourceSuspended},
		{name: "wrapped suspended sentinel", err: errors.Join(errors.New("dial failed"), adapter.ErrResourceSuspended)},
		{name: "this process closed the transport", err: net.ErrClosed},
		{name: "wrapped net.ErrClosed", err: errors.Join(errors.New("dial failed"), net.ErrClosed)},
		{name: "caller cancelled", err: context.Canceled},
		{name: "round cancelled", roundCancelled: true},
	}
}

// TestAProbeThatNeverHappenedLeavesTheHealthEvidenceAlone is the §5.4 requirement for every condition
// that means "not measured", asserted at the observable-behaviour layer: the history storage the
// selection reads.
func TestAProbeThatNeverHappenedLeavesTheHealthEvidenceAlone(t *testing.T) {
	for _, testCase := range healthFactCases() {
		t.Run(testCase.name, func(t *testing.T) {
			member := &probeMarkingOutbound{tag: "node", dialErr: testCase.err}
			group, storage := newGroupFixture(t, "https://probe.example/generate_204", member)
			scope, err := urltest.NewMeasurementScope("https://probe.example/generate_204", nil)
			require.NoError(t, err)

			previous := &adapter.URLTestHistory{Time: time.Now(), Delay: 42}
			storage.StoreHealthHistory("node", scope, previous)

			roundCtx := context.Background()
			if testCase.roundCancelled {
				var cancel context.CancelFunc
				roundCtx, cancel = context.WithCancel(roundCtx)
				cancel()
			}
			group.CheckOutbounds(roundCtx, true)

			after := storage.LoadURLTestHistoryFor("node", scope)
			require.NotNil(t, after,
				"health evidence was deleted for a probe that never happened: the device would treat a %s as a node failure",
				testCase.name)
			require.EqualValues(t, previous.Delay, after.Delay,
				"health evidence was replaced for a probe that never happened")
		})
	}
}

// TestARealDialFailureStillDeletesTheHealthEvidence is the other direction, and it is what keeps the
// test above from being satisfied by simply never deleting anything.
//
// A path error is a measurement that DID happen and came back bad. The member's health evidence must
// go, or a dead node keeps its old latency and keeps being selected.
func TestARealDialFailureStillDeletesTheHealthEvidence(t *testing.T) {
	for _, pathErr := range []error{
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ECONNREFUSED,
		syscall.ETIMEDOUT,
		// A remote close is a measurement that happened and came back bad. It must NOT be read as
		// this process's own teardown, which is why net.ErrClosed means "closed on this side" and
		// this does not.
		syscall.ECONNRESET,
		errors.New("no route to host"),
	} {
		t.Run(pathErr.Error(), func(t *testing.T) {
			member := &probeMarkingOutbound{tag: "node", dialErr: pathErr}
			group, storage := newGroupFixture(t, "https://probe.example/generate_204", member)
			scope, err := urltest.NewMeasurementScope("https://probe.example/generate_204", nil)
			require.NoError(t, err)

			storage.StoreHealthHistory("node", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 42})
			group.CheckOutbounds(context.Background(), true)

			require.Nil(t, storage.LoadURLTestHistoryFor("node", scope),
				"a real dial failure (%s) must remove the member's health evidence, or a dead node keeps its old latency", pathErr)
		})
	}
}
