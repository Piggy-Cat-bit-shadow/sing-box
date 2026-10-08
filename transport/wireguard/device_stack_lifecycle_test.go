package wireguard

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// A Start that races a Close must not send on a closed event channel.
//
// # The failure this pins
//
// The stack device reports "up" by sending on its events channel, and its Close closes that
// channel. Box.Close is legal at any point of Box.Start, so a stop landing while the device is
// coming up could close the channel between the send's start and its completion - a panic in an
// internal goroutine, which is not recoverable and takes the process with it. The send is now
// guarded by the closed channel, which is published before the events channel is closed.
func TestStackDeviceStartAfterCloseIsRefused(t *testing.T) {
	t.Parallel()

	device := newTestStackDevice(t)
	require.NoError(t, device.Close())

	require.ErrorIs(t, device.Start(), os.ErrClosed,
		"a start after close must be refused, not panic on a closed event channel")
}

// This test runs under -race, and it is the local leg that caught the module's own Start/Close race
// before the fork fixed it.
//
// The pinned fork (sync/go-stack-plus-040-and-race, stack_go.go) makes the Go stack's Start/Close a
// published handshake: Close owns the started state and snapshots the resources under the publish
// lock, Start refuses once closed, and nothing can start again after Close returns. Before that fix
// this test - and intermittently the two lifecycle tests around it - failed under -race on the
// module's race. What is being pinned here is the fork's own contract: no panic from the event
// channel, concurrently with a start/close handshake the detector can see.
func TestStackDeviceConcurrentStartAndCloseDoNotPanic(t *testing.T) {
	t.Parallel()

	device := newTestStackDevice(t)

	var waitGroup sync.WaitGroup
	// One Start and one Close, concurrently - which is the real shape: a service that is starting
	// while a stop arrives. Repeating Start is not something the library ever does.
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		_ = device.Start()
	}()
	go func() {
		defer waitGroup.Done()
		_ = device.Close()
	}()
	waitGroup.Wait()
}

// Close stays idempotent, so a second teardown does not close a channel twice.
func TestStackDeviceCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	device := newTestStackDevice(t)
	require.NoError(t, device.Close())
	require.NoError(t, device.Close())
	require.NoError(t, device.Close())
}

func newTestStackDevice(t *testing.T) *stackDevice {
	t.Helper()
	created, err := NewDevice(DeviceOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
		MTU:     1420,
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	require.NoError(t, err)
	stackDevice, isStackDevice := created.(*stackDevice)
	require.True(t, isStackDevice)
	return stackDevice
}
