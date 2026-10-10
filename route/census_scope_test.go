package route

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestTheCensusPredicateExcludesTheRouteRuleSubpackage pins the SCOPE of the leak instrument, which
// is a claim about the instrument rather than about the code under test.
//
// # The defect it pins
//
// The census matched the bare substring `sing-box/route`, which is also a prefix of the SUBPACKAGE
// import path `github.com/sagernet/sing-box/route/rule`. A goroutine owned by route/rule was
// therefore counted as this package's, so the churn test's "did the package's goroutine count come
// back" assertion could be moved by a package it says nothing about. An instrument another package
// can move is an instrument that can report a leak in code that did not leak - the failure mode
// section 10.10 repaired in `common/sniff`, where a process-global census reported a leak in a test
// that had not leaked.
//
// The blocks below are the exact frame shapes `runtime.Stack` produces, so the assertion is about
// the predicate's behaviour on real input rather than about a string constant.
func TestTheCensusPredicateExcludesTheRouteRuleSubpackage(t *testing.T) {
	ownFrame := "goroutine 42 [select]:\n" +
		"github.com/sagernet/sing-box/route.(*NetworkManager).updateInterface(0xc000010000, 0x0)\n" +
		"\tC:/src/sing-box/route/network.go:1073 +0x1a5\n" +
		"created by github.com/sagernet/sing-box/route.(*NetworkManager).Start in goroutine 1\n" +
		"\tC:/src/sing-box/route/network.go:900 +0x88\n"
	ruleSubpackageFrame := "goroutine 43 [select]:\n" +
		"github.com/sagernet/sing-box/route/rule.(*RuleSet).check(0xc000020000)\n" +
		"\tC:/src/sing-box/route/rule/rule.go:210 +0x9c\n" +
		"created by github.com/sagernet/sing-box/route/rule.NewRuleSet in goroutine 1\n" +
		"\tC:/src/sing-box/route/rule/rule.go:88 +0x44\n"
	externalTestPackageFrame := "goroutine 44 [running]:\n" +
		"github.com/sagernet/sing-box/route_test.someHelper()\n" +
		"\tC:/src/sing-box/route/external_helper_test.go:12 +0x30\n"

	require.True(t, routeStackBlockCounts(ownFrame),
		"this package's own frame must be counted, or the census under-reports and the leak assertion "+
			"becomes satisfiable by leaking")
	require.False(t, routeStackBlockCounts(ruleSubpackageFrame),
		"route/rule is a different package and its import path contains `sing-box/route` as a prefix; "+
			"counting it lets another package move this leak assertion")
	require.False(t, routeStackBlockCounts(externalTestPackageFrame),
		"route_test is a different package from route; the frame boundary excludes it for the same "+
			"reason, and every test file in this directory is `package route`")

	// The discriminating control: the OLD predicate is reproduced here and shown to accept what the
	// new one rejects. Without this, a predicate that simply returned false for everything would
	// satisfy the assertions above.
	oldPredicate := func(block string) bool { return strings.Contains(block, "sing-box/route") }
	require.True(t, oldPredicate(ruleSubpackageFrame),
		"the old predicate accepted the route/rule frame; if this ever stops being true the fixture "+
			"above no longer demonstrates the defect it pins")
}

// TestTheNarrowedCensusStillSeesOneLeakedRouteWorker is the sensitivity control for the narrowing
// above, and it is the half that makes the change safe to make.
//
// Narrowing a predicate can make an assertion easier to satisfy, which is the direction that turns a
// leak check into decoration. So the narrowed census is shown to move for EXACTLY one goroutine
// started by this package, and to come back when that goroutine is released - the same two-part
// proof (sensitivity, then reversibility) the D7 investigator had to produce before its numbers were
// used, and the same one `common/sniff` was missing when its `+4` allowance hid up to three.
//
// The census is polled from a plain loop rather than from `require.Eventually`, because testify runs
// that closure on its own goroutine and a census taken there would have to reason about a frame this
// package does not own. See routeGoroutinesFromClosure for the correction the churn test needs when
// it does poll from inside one.
func TestTheNarrowedCensusStillSeesOneLeakedRouteWorker(t *testing.T) {
	baseline := routeGoroutines()

	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		// A function literal defined in this file is `route.TestTheNarrowedCensusStillSeesOneLeakedRouteWorker.func1`
		// on its stack, so it is exactly the shape the narrowed predicate must still count.
		close(started)
		<-release
	}()
	<-started

	observed := growthOf(t, baseline, 5*time.Second)
	require.Equal(t, baseline+1, observed,
		"a single goroutine started by this package must move the census by exactly one; a census that "+
			"cannot be moved proves nothing, and one that moves by more is counting something else "+
			"(baseline was %d)", baseline)

	close(release)

	returned := shrinkOf(t, baseline, 5*time.Second)
	require.Equal(t, baseline, returned,
		"the census must come back to its baseline once the worker is released, or the instrument "+
			"reports an accumulation that is not there (baseline was %d)", baseline)
}

// growthOf polls the census until it exceeds baseline, and returns the first such reading - or the
// last reading if the deadline passes, so the caller's Equal is what fails rather than a timeout.
func growthOf(t *testing.T, baseline int, window time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		observed := routeGoroutines()
		if observed > baseline || time.Now().After(deadline) {
			return observed
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// shrinkOf polls the census until it is back at baseline, with the same "return the last reading"
// rule so the assertion is the thing that reports the failure.
func shrinkOf(t *testing.T, baseline int, window time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(window)
	for {
		observed := routeGoroutines()
		if observed <= baseline || time.Now().After(deadline) {
			return observed
		}
		time.Sleep(5 * time.Millisecond)
	}
}
