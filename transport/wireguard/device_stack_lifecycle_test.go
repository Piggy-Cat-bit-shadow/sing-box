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

// This test is deliberately NOT run under -race.
//
// The sing-tun Go stack at the pinned revision has a known Start/Close race of its own (the same
// three upstream races documented for the start/close window); it is outside this fork's code and
// outside this guarantee. What is being pinned here is the fork's own contract: no panic from the
// event channel. Run with -race and the module's race is what fires, not this one.
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
