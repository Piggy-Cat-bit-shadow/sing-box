package tun

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Behavioural trace of the layer every TUN stack shares: sing-tun's ForwardDispatcher.
//
// The engine-level trace in native_bypass_trace_test.go runs one stack end to end. This one runs the
// dispatcher directly, which is where the verdict is interpreted for the go, gvisor and system
// stacks alike, and where the question "is this verdict consumed?" is answered.
//
// `Dispatch` returning true means the dispatcher took the packet: it was forwarded into a Port, or
// rejected, or dropped. Returning false means the packet continues into the stack, which is the
// userspace path in every TUN stack. That single bit is the difference between a bypass and a
// proxy, and it is what the Direct Offload work assumed rather than checked.

// dispatcherWriteback records what the dispatcher hands back toward the platform.
type dispatcherWriteback struct {
	access  sync.Mutex
	written [][]byte
}

func (w *dispatcherWriteback) ReturnHeadroom() int { return 0 }

func (w *dispatcherWriteback) WriteReturnPackets(packets [][]byte) error {
	w.access.Lock()
	defer w.access.Unlock()
	for _, packet := range packets {
		w.written = append(w.written, append([]byte(nil), packet...))
	}
	return nil
}

func (w *dispatcherWriteback) count() int {
	w.access.Lock()
	defer w.access.Unlock()
	return len(w.written)
}

// newTraceDispatcher builds a real dispatcher over the given handler.
//
// The UDP timeout is a field of a struct since sing-tun d769a708, where forward NAT gained UDP
// mapping and filtering alongside it. Only the timeout is set: the zero Mapping and Filtering are
// NATMappingEndpointIndependent and NATFilteringEndpointIndependent, which is the behaviour the bare
// duration used to imply and the same default the fork's own configuration resolves to. Nothing
// about what this dispatcher is asked to prove has changed - the parameter moved, it was not
// relaxed.
func newTraceDispatcher(t *testing.T, handler *traceHandler) (*tun.ForwardDispatcher, *tun.ForwardStage, *dispatcherWriteback) {
	t.Helper()
	writeback := &dispatcherWriteback{}
	dispatcher := tun.NewForwardDispatcher(handler, writeback, logger.NOP(), tun.UDPNatOptions{Timeout: 30 * time.Second}, time.Minute)
	t.Cleanup(dispatcher.Close)
	return dispatcher, dispatcher.NewStage(writeback), writeback
}

// TestDispatcherConsumesOnlyAFlow is the shared-layer trace, covering every verdict the router can
// produce.
func TestDispatcherConsumesOnlyAFlow(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	cases := []struct {
		name     string
		verdict  tun.FlowVerdict
		consumed bool
	}{
		{
			name:     "accept continues into the stack",
			verdict:  tun.FlowVerdict{Action: tun.ActionAccept},
			consumed: false,
		},
		{
			// This is the verdict the whole Direct Offload feature returns. If this case ever fails,
			// the pinned sing-tun has started honouring ActionBypass in the TUN path - which is the
			// change that would make a tracked native bypass possible, and which the Direct Offload
			// scope, documentation and eligibility rules would then have to be re-derived from.
			name:     "bypass ALSO continues into the stack",
			verdict:  tun.FlowVerdict{Action: tun.ActionBypass},
			consumed: false,
		},
		{
			name:     "flow is consumed and forwarded into the Port",
			verdict:  tun.FlowVerdict{Action: tun.ActionFlow, Port: &tracePort{}},
			consumed: true,
		},
		{
			name:     "reject is consumed",
			verdict:  tun.FlowVerdict{Action: tun.ActionReject},
			consumed: true,
		},
		{
			name:     "drop is consumed",
			verdict:  tun.FlowVerdict{Action: tun.ActionDrop},
			consumed: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
				return testCase.verdict
			})
			_, stage, writeback := newTraceDispatcher(t, handler)

			consumed := stage.Dispatch(tcpSYN(source, destination, 1000))
			require.Equal(t, testCase.consumed, consumed)
			require.Zero(t, writeback.count(),
				"the dispatcher never writes an application packet back to the platform: it either "+
					"consumes it or continues into the stack, and neither hands it back out")
			stage.Flush()
		})
	}
}

// TestDispatcherTreatsBypassAndAcceptIdentically compares the two verdicts on every observable the
// dispatcher has, rather than on one hand-picked one.
func TestDispatcherTreatsBypassAndAcceptIdentically(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	observe := func(action tun.FlowAction) (consumed bool, judged int, written int, trackerCreated int) {
		created := 0
		handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
			return tun.FlowVerdict{
				Action: action,
				NewTracker: func() tun.FlowTracker {
					created++
					return &traceFlow{}
				},
			}
		})
		_, stage, writeback := newTraceDispatcher(t, handler)

		consumed = stage.Dispatch(tcpSYN(source, destination, 2000))
		// The same flow again, so the installed entry is exercised rather than only the install.
		stage.Dispatch(tcpSYN(source, destination, 2001))
		stage.Flush()

		judgedCount, _, _ := handler.counts()
		return consumed, judgedCount, writeback.count(), created
	}

	acceptConsumed, acceptJudged, acceptWritten, acceptTrackers := observe(tun.ActionAccept)
	bypassConsumed, bypassJudged, bypassWritten, bypassTrackers := observe(tun.ActionBypass)

	require.Equal(t, acceptConsumed, bypassConsumed)
	require.Equal(t, acceptJudged, bypassJudged,
		"both verdicts judge the flow the same number of times")
	require.Equal(t, acceptWritten, bypassWritten)
	require.Equal(t, acceptTrackers, bypassTrackers,
		"and neither one creates the tracker the caller offered")

	require.False(t, bypassConsumed,
		"if this fails, the pinned sing-tun now consumes ActionBypass in the TUN path: that is a "+
			"capability change, and Direct Offload's scope and documentation must be re-derived "+
			"from it rather than adjusted until this passes")
	require.Zero(t, bypassTrackers,
		"if this fails, a tracker offered on a bypass verdict is now reachable: that is the "+
			"beginning of the tracked native bypass this round was looking for")
}

// TestDispatcherConsumesAnAcceptEntrysSecondPacketTheSameWay pins the lifecycle the accept entry
// DOES provide: the verdict is cached per flow, so the router is asked once.
func TestDispatcherConsumesAnAcceptEntrysSecondPacketTheSameWay(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass}
	})
	_, stage, _ := newTraceDispatcher(t, handler)

	require.False(t, stage.Dispatch(tcpSYN(source, destination, 3000)))
	require.False(t, stage.Dispatch(tcpSYN(source, destination, 3001)))
	stage.Flush()

	judged, _, _ := handler.counts()
	require.Equal(t, 1, judged,
		"the flow table caches the bypass verdict, so the cost of the flow is one decision and "+
			"then nothing - but the packet still goes into the stack every time")
}

// TestDispatcherRemovesAnAcceptEntryOnReset pins that the entry's TCP lifecycle is real, even though
// nothing is attached to it.
func TestDispatcherRemovesAnAcceptEntryOnReset(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.2:40000")
	destination := netip.MustParseAddrPort("93.184.216.34:443")

	handler := newTraceHandler(func(uint8, netip.AddrPort, netip.AddrPort) tun.FlowVerdict {
		return tun.FlowVerdict{Action: tun.ActionBypass}
	})
	_, stage, _ := newTraceDispatcher(t, handler)

	require.False(t, stage.Dispatch(tcpSYN(source, destination, 4000)))
	require.False(t, stage.Dispatch(tcpRST(source, destination, 4001)))
	// After the reset the entry is gone, so the next packet is judged again.
	require.False(t, stage.Dispatch(tcpSYN(source, destination, 4002)))
	stage.Flush()

	judged, _, _ := handler.counts()
	require.Equal(t, 2, judged,
		"a reset removes the entry, which is the lifecycle a tracker would have reported")
}

// tcpRST builds a checksummed IPv4 TCP RST, which is what tears an accept entry down.
func tcpRST(source, destination netip.AddrPort, sequence uint32) []byte {
	packet := tcpSYN(source, destination, sequence)
	packet[33] = 0x04
	binary.BigEndian.PutUint16(packet[36:], 0)
	binary.BigEndian.PutUint16(packet[36:], transportChecksum(
		6,
		netip.AddrFrom4([4]byte(packet[12:16])),
		netip.AddrFrom4([4]byte(packet[16:20])),
		packet[20:],
	))
	return packet
}
