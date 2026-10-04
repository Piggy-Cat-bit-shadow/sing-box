package route

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

// One interface update that both moves the network environment AND has a pending interface reset must
// produce exactly ONE reset.
//
// # Why both reasons fire together
//
// notifyInterfaceUpdate sets networkResetPending, and updateInterface then recomputes the environment.
// A real interface change does both at once: the default interface changed (so an interface reset is
// pending) and the gateway/SSID fingerprint moved with it (so the environment boundary fires). The
// two decisions were made independently and each called resetNetworkLocked, so a single physical
// transition tore the network down twice - and the second reset was not a response to a second event.
//
// # What the test observes
//
// It drives the production decision path rather than the inner helper: updateInterface itself, with
// the pending flag and the environment both set. Reset count is asserted with Equal, not Greater,
// because the defect is precisely that the count is one too high.

// interfaceTransitionHarness is a NetworkManager wired so updateInterface reaches a real decision.
type interfaceTransitionHarness struct {
	manager *NetworkManager
	router  *countingRouter
	// release hands back a resetRunAccess taken by holdResetLock.
	release chan struct{}
}

// newInterfaceTransitionHarness builds a started manager whose environment fingerprint the test
// drives through the Wi-Fi SSID.
//
// The fingerprint is a hash of the default interface's gateways, its SSID, or its gateway hardware
// addresses. An SSID is the simplest of the three to move without a host: WIFIState reads a field on
// the manager, so the test can transition A -> B by publishing a different SSID, which is also the
// exact transition onWIFIStateChanged exists for.
func newInterfaceTransitionHarness(t *testing.T) *interfaceTransitionHarness {
	t.Helper()
	router := newCountingRouter()
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()
	// The notifier dispatches through the pause manager, so the harness supplies one.
	manager.pauseManager = &noopPauseManager{}
	// A default interface with one gateway, so the fingerprint is non-empty and the transition has
	// something to move. networkInterfaces is what DefaultNetworkInterface resolves against.
	// Gateways live on adapter.NetworkInterface (the control.Interface it embeds carries only index,
	// name and addresses), so the gateway the fingerprint reads is supplied there.
	manager.interfaceMonitor = &staticInterfaceMonitor{
		current: &control.Interface{Index: 1, Name: "en0"},
	}
	manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}})
	h := &interfaceTransitionHarness{manager: manager, router: router, release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
	})
	return h
}

// setSSID publishes a Wi-Fi SSID, which is the environment transition the test drives.
func (h *interfaceTransitionHarness) setSSID(ssid string) {
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: ssid}
	h.manager.stateAccess.Unlock()
}

// markInterfaceResetPending arms the other reason updateInterface resets for.
//
// It goes through the real notifier: the notification is what CLAIMS the transition, so writing the
// flag directly would exercise a state the product cannot reach - a pending reset whose transition
// nobody owns.
func (h *interfaceTransitionHarness) markInterfaceResetPending() {
	h.manager.notifyInterfaceUpdate(nil, 0)
}

func (h *interfaceTransitionHarness) resetCount() int { return dnsResetCount(h.router) }

// holdResetLock takes resetRunAccess so a dispatched update blocks instead of racing the assertions.
// release (closed by the test, or by cleanup) hands it back.
func (h *interfaceTransitionHarness) holdResetLock(t *testing.T) {
	t.Helper()
	held := make(chan struct{})
	go func() {
		h.manager.resetRunAccess.Lock()
		close(held)
		<-h.release
		h.manager.resetRunAccess.Unlock()
	}()
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("could not take resetRunAccess")
	}
}

// staticInterfaceMonitor is a DefaultInterfaceMonitor whose answer the test controls.
type staticInterfaceMonitor struct {
	current *control.Interface
}

func (m *staticInterfaceMonitor) Start() error                         { return nil }
func (m *staticInterfaceMonitor) Close() error                         { return nil }
func (m *staticInterfaceMonitor) DefaultInterface() *control.Interface { return m.current }
func (m *staticInterfaceMonitor) OverrideAndroidVPN() bool             { return false }
func (m *staticInterfaceMonitor) AndroidVPNEnabled() bool              { return false }
func (m *staticInterfaceMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (m *staticInterfaceMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {
}
func (m *staticInterfaceMonitor) RegisterMyInterface(string) {}
func (m *staticInterfaceMonitor) MyInterfaces() []string     { return nil }

// TestInterfaceEnvironmentTransitionCoalescesPendingReset is the reproduction.
func TestInterfaceEnvironmentTransitionCoalescesPendingReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Settle the fingerprint on SSID "A" first, so the update below is a genuine A -> B move.
	harness.setSSID("A")
	require.Equal(t, 0, harness.resetCount(), "establishing the first fingerprint is not a transition")
	harness.setSSID("B")
	harness.markInterfaceResetPending()

	generationBefore := harness.manager.NetworkResetGeneration()
	before := harness.resetCount()

	// The production entry: one interface update carrying both reasons.
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"one interface update carrying both an environment transition and a pending interface reset "+
			"must reset exactly once. Two resets means the same physical transition tore the network "+
			"down twice: once for the environment boundary and once for the pending flag, with no "+
			"second event behind either")
	require.EqualValues(t, generationBefore+1, harness.manager.NetworkResetGeneration(),
		"the reset epoch must advance exactly once per logical transition")
}

// TestInterfaceEnvironmentTransitionAloneResetsOnce is the control for the environment reason.
func TestInterfaceEnvironmentTransitionAloneResetsOnce(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")

	before := harness.resetCount()
	generationBefore := harness.manager.NetworkResetGeneration()
	harness.setSSID("B")

	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"an environment transition with no pending interface reset must still reset")
	require.EqualValues(t, generationBefore+1, harness.manager.NetworkResetGeneration())
}

// TestInterfacePendingResetAloneResetsOnce is the control for the pending reason.
func TestInterfacePendingResetAloneResetsOnce(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Settle the fingerprint, then leave it alone, so only the pending event remains as a reason.
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	before := harness.resetCount()

	// The notification itself CLAIMS the transition - that is what makes the network unstable before
	// its update can be blocked on the reset lock - so the epoch has already moved by the time the
	// update consumes it. The update must perform the boundary without claiming a second time.
	harness.markInterfaceResetPending()
	generationAfterNotify := harness.manager.NetworkResetGeneration()

	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"a pending interface event with no environment transition must still reset")
	require.EqualValues(t, generationAfterNotify, harness.manager.NetworkResetGeneration(),
		"the update consumes the token the notification claimed; claiming again would double the "+
			"epoch for one logical event")
}

// TestInterfaceUpdateWithNoReasonDoesNotReset is the negative control.
//
// A repeated notification for an unchanged interface and an unchanged environment is exactly the
// noise the debounce exists to absorb. It must not tear down pooled connections.
func TestInterfaceUpdateWithNoReasonDoesNotReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	before := harness.resetCount()

	for i := 0; i < 5; i++ {
		harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	}

	require.Equal(t, before, harness.resetCount(),
		"an update with neither reason must not reset; repeated teardown of pooled connections on a "+
			"stable network is the failure this guards")
}

// TestCancelledInterfaceUpdateDoesNotConsumeNewPendingReset covers the concurrent notification case.
//
// A newer interface event cancels the in-flight update's context and takes over. The cancelled update
// must not consume the pending flag that belongs to the new event, or the new transition is lost.
func TestCancelledInterfaceUpdateDoesNotConsumeNewPendingReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")

	// Arm the event by hand rather than through the notifier.
	//
	// The notifier is exercised by TestSupersedeUsesRealNotifyInterfaceUpdate; here the subject is the
	// CANCELLED update's decision, and driving the notifier would dispatch a second update that
	// performs the reset concurrently - making the counts race the very thing under test. What is
	// being asserted is that a cancelled update neither resets nor consumes the flag.
	harness.manager.interfaceUpdateAccess.Lock()
	harness.manager.networkResetPending = true
	harness.manager.networkResetPendingToken = harness.manager.beginTransition()
	harness.manager.interfaceUpdateAccess.Unlock()

	// The old update's context is already cancelled when it reaches the decision, as it would be
	// after a newer notification cancelled it.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	before := harness.resetCount()
	harness.manager.updateInterface(cancelledCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before, harness.resetCount(),
		"a cancelled update must not reset")

	// The pending flag must still be armed for the update that owns the new event.
	harness.manager.interfaceUpdateAccess.Lock()
	stillPending := harness.manager.networkResetPending
	harness.manager.interfaceUpdateAccess.Unlock()
	require.True(t, stillPending,
		"the cancelled update consumed the pending reset that belongs to the newer event; that "+
			"transition is then lost, because the newer update sees nothing to do")

	// And the newer update performs it, exactly once.
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	require.Equal(t, before+1, harness.resetCount(),
		"the newer update must still perform the pending reset")
}
