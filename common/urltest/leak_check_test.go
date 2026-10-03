package urltest

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRepeatedMeasurementsDoNotLeakGoroutines guards §15.
//
// The unified-delay flow adds a second HTTP request per measurement. This confirms it does not
// add a second goroutine, timer or socket that outlives the call.
func TestRepeatedMeasurementsDoNotLeakGoroutines(t *testing.T) {
	server := newDelayServer(t, func(int) time.Duration { return 0 })

	// Warm up so one-off runtime goroutines are already running.
	for i := 0; i < 5; i++ {
		_, err := URLTest(context.Background(), server.url(), directDialer{})
		require.NoError(t, err)
	}
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		_, err := URLTest(context.Background(), server.url(), directDialer{})
		require.NoError(t, err)
	}

	// Give any lingering runtime helpers a moment to exit.
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	require.LessOrEqual(t, after, before+5,
		"50 measurements must not accumulate goroutines; before=%d after=%d", before, after)
}

// TestIdleConnectionsAreClosedAfterMeasurement guards the socket/FD side of §15.
func TestIdleConnectionsAreClosedAfterMeasurement(t *testing.T) {
	server := newDelayServer(t, func(int) time.Duration { return 0 })

	_, err := URLTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	// CloseIdleConnections is deferred in urlTest, so by the time it returns no idle connection
	// may remain from this measurement. A follow-up opens a fresh one, which is the observable
	// consequence: the previous connection was not kept alive across measurements.
	before := server.connections.Load()
	_, err = URLTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)
	after := server.connections.Load()

	require.EqualValues(t, before+1, after,
		"each measurement must use its own connection and release it afterwards; a retained "+
			"idle connection would be a persistent FD and memory cost this work must not add")
}
