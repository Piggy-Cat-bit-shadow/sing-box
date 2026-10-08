package libbox

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/daemon"

	"github.com/stretchr/testify/require"
)

// # What these tests are for
//
// The shared policy is proved exhaustively in common/runtimecoord. What is left to prove here is the
// part that only exists at the ABI edge: that the surface is scalar and therefore safe on the
// go1.25 packed-frame path; that a fact arriving after the service stopped is a no-op rather than a
// resurrection; and that this file is a transport, so it can never mark - or unmark - a measurement
// as demand.

// newPlatformEventsTestService starts a real StartedService on a per-test working directory.
//
// baseContext reads the package-level path and ownership globals, and a Box creates its cache file
// under the working path with a chown to the configured user. In the app those are set by
// SetupOptions; in a test they default to "" and uid 0, which is a chown to root and fails. They are
// therefore set here and restored afterwards, so the ownership policy under test is the same one the
// product uses and no other test in this package inherits the temporary value.
func newPlatformEventsTestService(t *testing.T, configContent string) (*daemon.StartedService, *CommandServer) {
	t.Helper()
	previousWorking, previousTemp, previousUser, previousGroup := sWorkingPath, sTempPath, sUserID, sGroupID
	sWorkingPath = t.TempDir()
	sTempPath = t.TempDir()
	sUserID = os.Getuid()
	sGroupID = os.Getgid()
	t.Cleanup(func() {
		sWorkingPath, sTempPath, sUserID, sGroupID = previousWorking, previousTemp, previousUser, previousGroup
	})

	ctx := baseContext(nil)
	startedService := daemon.NewStartedService(daemon.ServiceOptions{Context: ctx})
	t.Cleanup(startedService.Close)
	server := &CommandServer{StartedService: startedService}
	require.NoError(t, startedService.StartOrReloadService(ctx, configContent, nil))
	t.Cleanup(func() { _ = startedService.CloseService() })
	return startedService, server
}

// TestPlatformEventsDoNotTouchMeasurementOrigins is the "the marker cannot be lost on the Android
// call chain" check.
//
// The Phase 1.5 background-probe marker decides whether a periodic health round may wake a suspended
// endpoint. It is set by the entry point that knows what the round is for and re-applied to the
// operation context after the group rebuilds it. A platform lifecycle fact has no business touching
// it: if the Android sink rebuilt a context, or put its own value on one, the marker would be dropped
// and an automatic round would look like demand - a measurement waking the tunnel engine it exists to
// leave asleep.
//
// Go cannot check a negative like that at runtime, so the source of the transport is parsed. The
// check is deliberately on THIS file only: protocol/group and clashapi are where the marker is
// legitimately set, and they have their own runtime tests.
func TestPlatformEventsDoNotTouchMeasurementOrigins(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "platform_events.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	var importPaths []string
	for _, importSpec := range file.Imports {
		importPaths = append(importPaths, strings.Trim(importSpec.Path.Value, `"`))
	}
	// context is imported for the target's non-blocking core calls; nothing else may be needed.
	for _, path := range importPaths {
		require.NotEqual(t, "github.com/sagernet/sing-box/adapter", path,
			"the platform sink must not reach the probe-origin helpers at all")
	}

	var banned []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		switch selector.Sel.Name {
		case "ContextWithBackgroundProbe", "ContextWithProbeOrigin", "MeasurementContext", "WithValue", "WithCancel", "WithTimeout":
			banned = append(banned, selector.Sel.Name)
		}
		return true
	})
	require.Empty(t, banned,
		"the platform sink must not construct or decorate a measurement context: %s", strings.Join(banned, ", "))
}

// TestPlatformEventsAreScalarAtTheBoundary restates the ABI rule where a reader of this file will see
// it, and fails if a future edit adds a result to the new surface.
//
// The exhaustive check is TestGomobileMethodResultSurface, which walks every declaration in the
// package. This one is local so the reason is attached to the file that would break it.
func TestPlatformEventsAreScalarAtTheBoundary(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "platform_events.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	var offending []string
	ast.Inspect(file, func(node ast.Node) bool {
		funcDecl, isFunc := node.(*ast.FuncDecl)
		if !isFunc || funcDecl.Recv == nil {
			return true
		}
		if !ast.IsExported(funcDecl.Name.Name) {
			return true
		}
		if funcDecl.Type.Results == nil {
			return true
		}
		for _, result := range funcDecl.Type.Results.List {
			offending = append(offending, funcDecl.Name.Name+" -> "+renderType(result.Type))
		}
		return true
	})
	require.Empty(t, offending,
		"a bound result puts a value in the packed cgo frame; the platform sink must report facts inward only: %v", offending)
}

func renderType(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + renderType(typed.X)
	case *ast.ArrayType:
		return "[]" + renderType(typed.Elt)
	case *ast.SelectorExpr:
		return renderType(typed.X) + "." + typed.Sel.Name
	}
	return "?"
}

// TestPlatformEventsWithoutAServiceAreInert: the sink may be created before a service starts, and
// every fact must be a no-op until there is one to act on.
func TestPlatformEventsWithoutAServiceAreInert(t *testing.T) {
	nilEvents := NewPlatformEvents(nil)
	nilEvents.SetScreenOn(false)
	nilEvents.SetAppForeground(true)
	nilEvents.MemoryTrim(15)
	nilEvents.ReportDeviceWake()
	nilEvents.Close()
	nilEvents.Close()

	startedService := daemon.NewStartedService(daemon.ServiceOptions{Context: baseContext(nil)})
	t.Cleanup(startedService.Close)
	server := &CommandServer{StartedService: startedService}
	events := NewPlatformEvents(server)
	require.Nil(t, startedService.Instance(), "the fixture must not have a running instance")

	// The full vocabulary, with no Box to act on. The point is the absence of a panic and the absence
	// of an instance: a fact that arrives before the service started is dropped, not queued.
	events.SetScreenOn(true)
	events.SetAppForeground(true)
	events.MemoryTrim(10)
	events.MemoryTrim(15)
	events.ReportDeviceWake()
	require.Nil(t, startedService.Instance())
	events.Close()
	// And after Close, still nothing.
	events.SetScreenOn(false)
	events.MemoryTrim(15)
}

// TestPlatformEventsDriveTheLiveBox starts a real Box and drives the API against it.
//
// This is the wiring proof: the facts reach the pause manager the Android client already uses and the
// NetworkManager's progressive pass, and the reset-shaped pass advances the network generation
// exactly once per emergency. It uses an empty configuration, so the Box has its managers but no
// inbound, outbound or endpoint to dial - which is what makes it a unit test rather than a device
// test while still exercising the real objects.
func TestPlatformEventsDriveTheLiveBox(t *testing.T) {
	startedService, server := newPlatformEventsTestService(t, "{}")

	instance := startedService.Instance()
	require.NotNil(t, instance)
	pauseManager := instance.PauseManager()
	require.NotNil(t, pauseManager)
	network := instance.Box().Network()
	require.NotNil(t, network)

	events := NewPlatformEvents(server)
	t.Cleanup(events.Close)

	// Foreground on a device that intends to be used.
	events.SetScreenOn(true)
	events.SetAppForeground(true)
	require.False(t, pauseManager.IsDevicePaused())

	// Screen off pauses the device axis. The app is backgrounded with it, which is what a screen-off
	// transition actually looks like.
	events.SetAppForeground(false)
	events.SetScreenOn(false)
	require.True(t, pauseManager.IsDevicePaused(),
		"a screen-off fact must reach the pause manager the Apple client drives")

	// Screen on with the app still in the background defers the wake: the device is usable but nobody
	// is looking at this app, and the deferred nudge must not have been sent yet.
	events.SetScreenOn(true)
	require.True(t, pauseManager.IsDevicePaused(),
		"screen-on with the app in the background must not lift the pause by itself")

	// The app comes forward: the deferred wake is released.
	events.SetAppForeground(true)
	require.False(t, pauseManager.IsDevicePaused())

	// A progressive trim reaches NetworkManager.TrimMemory without a reset.
	generationBefore := networkResetGeneration(network)
	events.MemoryTrim(10)
	require.Equal(t, generationBefore, networkResetGeneration(network),
		"a progressive trim must not advance the network generation: it may only make the process smaller")

	// The reset-shaped level does advance it, once.
	events.MemoryTrim(15)
	require.Equal(t, generationBefore+1, networkResetGeneration(network),
		"the process-ending level is the reset-shaped pass, and one emergency is one reset")
	for range 5 {
		events.MemoryTrim(15)
	}
	require.Equal(t, generationBefore+1, networkResetGeneration(network),
		"repeated readings of the same emergency must not become a reconnect storm")

	// Close, then a fact: the sink is a floor.
	events.Close()
	events.MemoryTrim(15)
	events.SetScreenOn(false)
	require.Equal(t, generationBefore+1, networkResetGeneration(network))
}

// networkResetGeneration reads the reset epoch through the optional capability, so the test states
// what it needs rather than assuming the concrete type.
func networkResetGeneration(network any) uint64 {
	counter, ok := network.(interface{ NetworkResetGeneration() uint64 })
	if !ok {
		return 0
	}
	return counter.NetworkResetGeneration()
}

// TestPlatformEventsAfterServiceStoppedAreDropped is the resurrection case at the ABI edge: the
// service stops without the sink being closed, and a late platform callback must find nothing.
func TestPlatformEventsAfterServiceStoppedAreDropped(t *testing.T) {
	startedService, server := newPlatformEventsTestService(t, "{}")

	events := NewPlatformEvents(server)
	t.Cleanup(events.Close)

	instance := startedService.Instance()
	require.NotNil(t, instance)

	// Stop the service but leave the sink open, which is the ordering a client crash produces.
	require.NoError(t, startedService.CloseService())
	require.Nil(t, startedService.Instance())

	// Refill the pause state so a late fact would be visible if it were acted on.
	pauseManager := instance.PauseManager()
	pauseManager.DeviceWake()

	// The stale callback from the old Box.
	events.SetScreenOn(false)
	events.SetAppForeground(false)
	events.MemoryTrim(15)
	events.ReportDeviceWake()

	require.False(t, pauseManager.IsDevicePaused(),
		"a callback for a stopped service must not mutate the old instance's pause state")
}

// TestPlatformEventsCoalesceRepeatedScreenFacts keeps the two axes honest at the ABI edge: repeated
// identical facts are one event, and the app-background axis does not pause the tunnel.
func TestPlatformEventsCoalesceRepeatedScreenFacts(t *testing.T) {
	startedService, server := newPlatformEventsTestService(t, "{}")

	events := NewPlatformEvents(server)
	t.Cleanup(events.Close)

	pauseManager := startedService.Instance().PauseManager()
	events.SetScreenOn(true)
	events.SetAppForeground(true)

	// Backgrounding the app alone must not pause the device axis: a VPN exists to carry traffic for
	// whatever app is in front, and the other apps still need the tunnel.
	events.SetAppForeground(false)
	require.False(t, pauseManager.IsDevicePaused(),
		"app background must not stop the tunnel carrying traffic for the foreground app")

	// But it does defer the wake nudge, and the nudge is what this axis owns.
	events.SetScreenOn(false)
	require.True(t, pauseManager.IsDevicePaused())
	events.SetScreenOn(true)
	require.True(t, pauseManager.IsDevicePaused(), "the wake waits for the user")

	// Repeated identical facts do not thrash the pause manager.
	for range 1000 {
		events.SetScreenOn(true)
	}
	require.True(t, pauseManager.IsDevicePaused())

	events.SetAppForeground(true)
	require.False(t, pauseManager.IsDevicePaused())
}

// TestPlatformEventsConcurrentFactsAreRaceFree drives every axis from several goroutines. Run under
// -race; the assertion is that nothing panics or deadlocks and that Close still wins.
func TestPlatformEventsConcurrentFactsAreRaceFree(t *testing.T) {
	startedService, server := newPlatformEventsTestService(t, "{}")
	_ = startedService

	events := NewPlatformEvents(server)
	t.Cleanup(events.Close)

	var waitGroup sync.WaitGroup
	for worker := range 4 {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for index := range 200 {
				events.SetScreenOn((worker+index)%2 == 0)
				events.SetAppForeground((worker+index)%3 == 0)
				events.MemoryTrim(int32(5 * (index % 3)))
			}
		}(worker)
	}
	waitGroup.Wait()
	events.Close()
	events.SetScreenOn(false)
	events.MemoryTrim(15)
}

// TestRuntimeCoordTrimLevelsMatchThePlatformContract pins the numbers this API forwards to Android's
// ComponentCallbacks2 constants, so the Java side and the Go mapping cannot drift apart silently.
func TestRuntimeCoordTrimLevelsMatchThePlatformContract(t *testing.T) {
	require.EqualValues(t, 5, runtimecoord.TrimRunningModerate)
	require.EqualValues(t, 10, runtimecoord.TrimRunningLow)
	require.EqualValues(t, 15, runtimecoord.TrimRunningCritical)
	require.EqualValues(t, 20, runtimecoord.TrimUIHidden)
	require.EqualValues(t, 40, runtimecoord.TrimBackground)
	require.EqualValues(t, 60, runtimecoord.TrimModerate)
	require.EqualValues(t, 80, runtimecoord.TrimComplete)
}
