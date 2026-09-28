//go:build with_lx_command

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Race and lifecycle tests for the command surface.
//
// The three RPCs read and write state that StartOrReloadService, CloseService and
// the service's own reload path mutate concurrently: the instance pointer, the
// service status and the URL-test history. These tests run those operations against
// each other. They are meaningful under `go test -race`, which is how CI runs them;
// without -race they still assert that no call returns a wrong-shaped answer while
// the service is being torn down.

// TestGetGroupsDuringConcurrentReload drives GetGroups while the service is
// repeatedly reloaded.
//
// The contract under load: every call must either succeed with a snapshot or be
// refused with FailedPrecondition. It must never panic, never return a nil
// response with a nil error (which the client would deserialize as an empty group
// list — indistinguishable from "this core has no groups", the exact symptom being
// fixed), and never block indefinitely.
func TestGetGroupsDuringConcurrentReload(t *testing.T) {
	fixture := newLiveFixture(t)
	harness := fixture.harness

	const reloads = 8
	stop := make(chan struct{})
	var reloader sync.WaitGroup
	reloader.Add(1)
	go func() {
		defer reloader.Done()
		for i := 0; i < reloads; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// A reload tears the instance down and builds a new one. The RPCs must
			// tolerate the window where instance is nil and the status is STARTING.
			_ = harness.service.StartOrReloadService(
				context.Background(), testFixtureConfig(fixture.testURL, fixture.cachePath), nil,
			)
		}
	}()

	var readers sync.WaitGroup
	deadline := time.Now().Add(3 * time.Second)
	for reader := 0; reader < 4; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for time.Now().Before(deadline) {
				response, err := harness.client.GetGroups(context.Background(), &emptypb.Empty{})
				if err != nil {
					// The only acceptable failure while reloading is a refusal.
					code := status.Code(err)
					if code != codes.FailedPrecondition && code != codes.Unavailable &&
						code != codes.Canceled && code != codes.DeadlineExceeded {
						t.Errorf("GetGroups failed with an unexpected code during reload: %v", err)
						return
					}
					continue
				}
				if response == nil {
					t.Error("GetGroups returned a nil response with a nil error; the client " +
						"would read that as an empty group list, which is the reported symptom")
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	reloader.Wait()

	// After the churn the service must be usable again.
	require.Eventually(t, func() bool {
		groups, err := harness.client.GetGroups(context.Background(), &emptypb.Empty{})
		return err == nil && groups != nil && len(groups.Group) > 0
	}, 10*time.Second, 50*time.Millisecond,
		"the service must return to a working state after concurrent reloads")
}

// TestGetOutboundsDuringConcurrentReload is the outbound-side twin.
func TestGetOutboundsDuringConcurrentReload(t *testing.T) {
	fixture := newLiveFixture(t)
	harness := fixture.harness

	stop := make(chan struct{})
	var reloader sync.WaitGroup
	reloader.Add(1)
	go func() {
		defer reloader.Done()
		for i := 0; i < 8; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = harness.service.StartOrReloadService(
				context.Background(), testFixtureConfig(fixture.testURL, fixture.cachePath), nil,
			)
		}
	}()

	var readers sync.WaitGroup
	deadline := time.Now().Add(3 * time.Second)
	for reader := 0; reader < 4; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for time.Now().Before(deadline) {
				response, err := harness.client.GetOutbounds(context.Background(), &emptypb.Empty{})
				if err != nil {
					code := status.Code(err)
					if code != codes.FailedPrecondition && code != codes.Unavailable &&
						code != codes.Canceled && code != codes.DeadlineExceeded {
						t.Errorf("GetOutbounds failed with an unexpected code during reload: %v", err)
						return
					}
					continue
				}
				if response == nil {
					t.Error("GetOutbounds returned a nil response with a nil error")
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	reloader.Wait()
}

// TestURLTestOutboundCancellationDuringReload cancels an in-flight URL test while
// the service is being reloaded.
//
// This is the combination that a naive implementation gets wrong in both
// directions: holding the service lock across the test would stall the reload for
// the length of the test, while parenting the test to the service context would let
// it outlive the call. The call must come back promptly, and the reload must still
// complete.
func TestURLTestOutboundCancellationDuringReload(t *testing.T) {
	fixture := newLiveFixture(t)
	harness := fixture.harness

	ctx, cancel := context.WithCancel(context.Background())

	callDone := make(chan error, 1)
	start := time.Now()
	go func() {
		// A long timeout, so only the cancel can end this promptly.
		_, err := harness.client.URLTestOutbound(ctx, &URLTestOutboundRequest{
			OutboundTag: "node-a",
			Link:        fixture.testURL,
			Timeout:     60000,
		})
		callDone <- err
	}()

	// Reload concurrently with the in-flight test.
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		_ = harness.service.StartOrReloadService(
			context.Background(), testFixtureConfig(fixture.testURL, fixture.cachePath), nil,
		)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-callDone:
		require.Less(t, time.Since(start), 30*time.Second,
			"a cancelled URL test must not run for its full timeout while a reload "+
				"is in progress")
	case <-time.After(30 * time.Second):
		require.Fail(t, "the cancelled URL test never returned; it is not bound to "+
			"the call context")
	}

	select {
	case <-reloadDone:
	case <-time.After(60 * time.Second):
		require.Fail(t, "the reload did not complete; the URL test is holding a lock "+
			"across its network operation, so one slow node stalls the whole service")
	}

	// And the service must still work afterwards.
	require.Eventually(t, func() bool {
		groups, err := harness.client.GetGroups(context.Background(), &emptypb.Empty{})
		return err == nil && groups != nil
	}, 10*time.Second, 50*time.Millisecond)
}

// TestConcurrentURLTestsAreIndependent runs several single-node tests at once.
//
// Each must get its OWN result: a shared buffer, a shared context or a shared
// response object would make one node's delay appear under another's tag.
func TestConcurrentURLTestsAreIndependent(t *testing.T) {
	fixture := newLiveFixture(t)

	tags := []string{"node-a", "node-b", "direct"}
	var waitGroup sync.WaitGroup
	results := make([]string, len(tags))
	errors := make([]error, len(tags))

	for i, tag := range tags {
		waitGroup.Add(1)
		go func(index int, outboundTag string) {
			defer waitGroup.Done()
			response, err := fixture.harness.client.URLTestOutbound(
				context.Background(), &URLTestOutboundRequest{
					OutboundTag: outboundTag,
					Link:        fixture.testURL,
					Timeout:     10000,
				})
			errors[index] = err
			if response != nil {
				results[index] = response.Error
			}
		}(i, tag)
	}
	waitGroup.Wait()

	for i, tag := range tags {
		require.NoError(t, errors[i], "concurrent test of %s must not fail at the transport", tag)
		require.Empty(t, results[i],
			"concurrent test of %s reported an application error; the node exists and "+
				"the target is local, so each test must succeed independently", tag)
	}

	// Every tested node must carry its own history entry.
	group := findGroup(t, fixture.getGroups(t), "🤖 AI")
	for _, tag := range []string{"node-a", "node-b"} {
		item := findItem(t, group, tag)
		require.NotZero(t, item.UrlTestTime,
			"node %s must have its own history entry; a missing one means concurrent "+
				"tests overwrote each other's results", tag)
	}
}

// TestGetGroupsWhileStopping asserts the error contract at teardown: once the
// service is stopped, the RPCs must be REFUSED rather than returning an empty
// snapshot that looks like a working core with no proxies.
func TestGetGroupsWhileStopping(t *testing.T) {
	fixture := newLiveFixture(t)

	// Confirm it works before stopping, so a later failure is attributable.
	require.NotEmpty(t, fixture.getGroups(t).Group)

	require.NoError(t, fixture.harness.service.CloseService())

	_, err := fixture.harness.client.GetGroups(context.Background(), &emptypb.Empty{})
	require.Error(t, err,
		"a stopped service must refuse GetGroups; returning an empty list would be "+
			"indistinguishable from a core that has no groups")
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"the method must remain registered after the service stops")
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"a stopped service must be reported as FailedPrecondition, which proves the "+
			"handler ran and refused deliberately; got %v", err)

	_, err = fixture.harness.client.GetOutbounds(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
