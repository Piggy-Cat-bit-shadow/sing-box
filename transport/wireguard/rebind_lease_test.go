package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"github.com/stretchr/testify/require"
)

// D7-02: a rebind whose lease is revoked may not commit the endpoint to a new socket as if the
// generation it was granted for still existed.
//
// # Why every test here opens a REAL socket
//
// The defect lives in the seam between this package and the dialer's listener control, and that seam is
// only reachable with a live bind: the socket is reopened by `device.Device.BindUpdate`, inside a
// listener control function that is handed no context. A fixture that stubs the rebind - the `rebindHook`
// seam this package's other recovery tests use - never enters it, so it can say nothing about it. The
// lesson this file is built around is that three green fixtures once never entered the path they claimed
// to test; every fixture below therefore PROVES which branch it entered, from a counter that would read
// zero if it were missed, from the public `Device.Bind()` accessor, and from a dumped stack.
//
// # The two places a rebind can be revoked, and what this package can do about each
//
//	BEFORE the socket operation starts  ->  the reopen is not attempted
//	                                       (TestSupersededRebindDoesNotCommitTheSocket)
//	AFTER it has started                ->  the reopen completes, and is not claimed as a recovery
//	                                       (TestCtxCannotReachASocketOperationAlreadyRunning)
//
// The second is the stated bound rather than a defect: `wireguard-go`'s conn/bind_std.go reaches the
// control hook through `net.ListenConfig.Control` from `ListenPacket(context.Background(), ...)`, so no
// context from this repository can reach a running socket operation. What this package CAN do - and now
// does - is refuse to report that operation as a recovery for the generation that revoked it.

// ---------------------------------------------------------------------------------------------
// Fixture: a dialer whose listener control this test owns
// ---------------------------------------------------------------------------------------------

// stdBindDialer is a working dialer that ADVERTISES the listener capability, which is the entire reason
// the endpoint under test takes the standard-bind branch instead of building a ClientBind.
//
// It implements `dialer.UDPListener` - `UDPListenerControl() (control.Func, bool)` - which is the
// interface `Endpoint.Start` type-asserts to decide between `conn.StdNetBind` and `NewClientBind`. A
// dialer without it, such as this package's `plainDialer`, silently takes the other branch, where the
// control hook below is never called and every assertion in this file would be vacuous.
type stdBindDialer struct {
	gate *socketGate
	// socketFlights counts calls to the control hook. It is the reachability instrument: it reads zero
	// unless the endpoint reached the standard bind's listener control, which is its only caller.
	socketFlights atomic.Int64
	// connects counts the other dialer route this fixture must NOT be using. Both binds are constructed
	// by Start; only one is used. A non-zero value means these tests are not about the standard bind, and
	// `proveStandardBindBranch` fails rather than letting them pass for the wrong reason.
	connects atomic.Int64
}

var _ N.Dialer = (*stdBindDialer)(nil)

func (d *stdBindDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.connects.Add(1)
	var netDialer net.Dialer
	return netDialer.DialContext(ctx, network, destination.String())
}

func (d *stdBindDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.connects.Add(1)
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, N.NetworkUDP, "0.0.0.0:0")
}

// UDPListenerControl returns the hook this test blocks. `Start` wraps it in
// `familyTolerantListenerControl` and hands the result to `conn.NewStdNetBind`, so the hook ends up inside
// `net.ListenConfig.Control` - the function with no context parameter that reopens the socket.
func (d *stdBindDialer) UDPListenerControl() (control.Func, bool) {
	return func(network, address string, rawConn syscall.RawConn) error {
		d.socketFlights.Add(1)
		return d.gate.enter()
	}, false
}

// socketGate blocks a real socket open and runs a probe inside it.
//
// # What it blocks, exactly
//
// `enter` runs inside the dialer's listener control, which `wireguard-go` calls from
// `net.ListenConfig.Control` while `ListenPacket` is opening the socket. At that moment the old socket has
// already been closed by `BindUpdate` and the new one is being created, so this is the commit point of the
// rebind - not a proxy for it.
//
// # The two things a test can do from here
//
//   - BLOCK (`arm`): the operation cannot finish until the test releases it, which pins the "in flight" state
//     so an assertion about it is not a sample of a race.
//   - REVOKE (`probe`): run code at the instant the commit is underway. This is what makes the defect
//     reproducible without a timing window: a generation advanced from here lands strictly AFTER
//     `RebindStale`'s entry check and strictly BEFORE its socket work completes, which is exactly the state
//     D7-02 is about and exactly the state no ordering of external calls can produce deterministically.
//
// It is armable rather than always-blocking because the endpoint opens its starting socket through the same
// hook: a gate that blocked from the beginning would hang `Endpoint.Start`.
type socketGate struct {
	access sync.Mutex
	armed  bool
	enters chan struct{}
	open   chan struct{}
	// probe, when set, runs inside the socket operation before it is allowed to proceed.
	probe func()
	// attempts counts socket operations that reached the hook, across arms.
	attempts int64
	// fail, when set, is the error the control hook returns instead of succeeding: the socket-open failure
	// case of the matrix, injected at the earliest point a dialer can fail an operation.
	fail func() error
}

func newSocketGate() *socketGate {
	return &socketGate{
		enters: make(chan struct{}, 4096),
		open:   make(chan struct{}),
	}
}

// probeAtSocketOpen registers code to run inside the next socket operation that reaches the gate, before the
// operation is allowed to continue.
func (g *socketGate) probeAtSocketOpen(probe func()) {
	g.access.Lock()
	defer g.access.Unlock()
	g.probe = probe
}

// failWith makes every socket operation fail with the error the function produces.
func (g *socketGate) failWith(failure func() error) {
	g.access.Lock()
	defer g.access.Unlock()
	g.fail = failure
}

func (g *socketGate) succeed() {
	g.access.Lock()
	defer g.access.Unlock()
	g.fail = nil
}

// arm makes the next socket operations block. Each arm gets a fresh `open` channel, so an entry signalled
// by a previous arm cannot be mistaken for this one's.
func (g *socketGate) arm() {
	g.access.Lock()
	defer g.access.Unlock()
	g.armed = true
	g.open = make(chan struct{})
}

func (g *socketGate) release() {
	g.access.Lock()
	defer g.access.Unlock()
	if g.armed {
		g.armed = false
		close(g.open)
	}
}

// enter is called from inside the socket operation. An unarmed gate lets the operation proceed, which is
// how `Start` opens the endpoint's first socket.
func (g *socketGate) enter() error {
	g.access.Lock()
	g.attempts++
	armed := g.armed
	open := g.open
	failure := g.fail
	probe := g.probe
	// A probe runs once: both address families reach this hook, and a probe that ran twice would revoke a
	// generation twice and make the assertion about which generation was revoked ambiguous.
	g.probe = nil
	g.access.Unlock()

	if failure != nil {
		return failure()
	}
	if probe != nil {
		probe()
	}
	if !armed {
		return nil
	}
	// Buffered and non-blocking: both address families can be in flight, and the signal must not itself
	// block the operation under measurement.
	select {
	case g.enters <- struct{}{}:
	default:
	}
	<-open
	return nil
}

// socketAttempts reports how many socket operations reached the hook.
func (g *socketGate) socketAttempts() int64 {
	g.access.Lock()
	defer g.access.Unlock()
	return g.attempts
}

// awaitEntry blocks until a socket operation has actually reached the gate. A test that timed out here is
// reporting that the fixture never entered the branch it claims to test - the failure mode this file
// exists to make impossible to miss.
func (g *socketGate) awaitEntry(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-g.enters:
	case <-time.After(within):
		t.Fatalf("no socket operation reached the listener control within %s, so the rebind never "+
			"entered conn.StdNetBind's Open - the branch this test claims to exercise", within)
	}
}

// ---------------------------------------------------------------------------------------------
// Fixture: a started endpoint that owns a real socket
// ---------------------------------------------------------------------------------------------

type rebindFixture struct {
	endpoint    *Endpoint
	coordinator *runtimecoord.Coordinator
	dialer      *stdBindDialer
	gate        *socketGate
	tag         string
	// startedPort is the port the endpoint held when Start returned, recorded before any rebind so a test
	// can tell a real ephemeral reopen from an early return.
	startedPort uint16
}

var rebindFixtureCounter atomic.Int64

// newRebindFixture builds a started endpoint that owns a real UDP socket, with a coordinator installed so
// the generation itself can be advanced.
//
// `listenPort` selects the branch under test: 0 is the ephemeral branch, where a rebind releases the port
// through `IpcSet("listen_port=0")` so the reopen picks a new one, and the reopen happens inside that
// call. A concrete port is the pinned branch, where the rebind calls `Device.BindUpdate` directly and the
// port cannot move.
func newRebindFixture(t *testing.T, listenPort uint16) *rebindFixture {
	t.Helper()
	gate := newSocketGate()
	fixtureDialer := &stdBindDialer{gate: gate}
	coordinator := runtimecoord.New()
	ctx := service.ContextWith[*runtimecoord.Coordinator](
		pause.WithDefaultManager(context.Background()), coordinator)
	// A unique tag per fixture: it is what scopes the goroutine census to THIS endpoint, since frame names
	// are not unique across instances of the same type.
	tag := "wg-rebind-" + strconv.FormatInt(rebindFixtureCounter.Add(1), 10)

	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Tag:        tag,
		Dialer:     fixtureDialer,
		MTU:        1420,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
		ListenPort: listenPort,
		Peers: []PeerOptions{{
			Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 51820),
			PublicKey:  testListenPeerPublicKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))

	fixture := &rebindFixture{
		endpoint:    endpoint,
		coordinator: coordinator,
		dialer:      fixtureDialer,
		gate:        gate,
		tag:         tag,
	}
	fixture.startedPort = endpoint.currentListenPort(endpoint.device.Load())
	t.Cleanup(func() {
		gate.release()
		_ = endpoint.Close()
		_ = coordinator.Close()
	})
	return fixture
}

// proveStandardBindBranch asserts, from evidence rather than from intent, that this fixture reached the
// path it claims to test.
//
// Three independent facts:
//
//  1. `Device.Bind()` - a PUBLIC accessor on the pinned dependency - returns a `*conn.StdNetBind`. If the
//     endpoint had built a `ClientBind` instead, this fails here rather than inside a later assertion that
//     could pass for the wrong reason.
//  2. The control hook has been called, so the wrapper chain (`familyTolerantListenerControl` around the
//     dialer's own control) is in the live path rather than bypassed.
//  3. The other dialer route has never been used. Both binds are constructed by `Start`; only one is used,
//     and a non-zero count here would mean the endpoint is not running on the bind asserted in (1).
func (f *rebindFixture) proveStandardBindBranch(t *testing.T) {
	t.Helper()
	wgDevice := f.endpoint.device.Load()
	require.NotNil(t, wgDevice)
	require.IsType(t, &conn.StdNetBind{}, wgDevice.Bind(),
		"the fixture dialer must put the endpoint on the standard bind: on the ClientBind branch the "+
			"socket reopen happens in this repository's own code and the defect under test is elsewhere")
	require.Greater(t, f.dialer.socketFlights.Load(), int64(0),
		"the dialer's listener control was never called, so the wrapper under test is not in the live "+
			"path and every assertion about it would be vacuous")
	require.Zero(t, f.dialer.connects.Load(),
		"the other dialer route was used, so this endpoint is not the standard-bind endpoint these "+
			"assertions describe")
}

// livePort reads the port the running device reports.
func (f *rebindFixture) livePort(t *testing.T) uint16 {
	t.Helper()
	port := f.endpoint.currentListenPort(f.endpoint.device.Load())
	require.NotZero(t, port, "a started endpoint must report the port it holds")
	return port
}

// ---------------------------------------------------------------------------------------------
// Instrument: a goroutine census scoped to one endpoint
// ---------------------------------------------------------------------------------------------

// markerRecoveryLoop is the frame the census counts, spelled once.
const markerRecoveryLoop = "wireguard.(*Endpoint).recoveryLoop"

// markerReceiveIncoming is the frame of the pinned dependency's per-socket receive goroutine. `BindUpdate`
// starts one per receive function it gets from `bind.Open` - one per address family for the standard bind -
// and `closeBindLocked` waits for all of them to exit before it returns. Their count is therefore the
// socket-count instrument.
const markerReceiveIncoming = "wireguard-go/device.(*Device).RoutineReceiveIncoming"

// frameReceiverAddress returns the address of the receiver printed on the frame of `function` inside
// `goroutine`, or "" if that frame is not there.
//
// This is how the census is scoped to ONE endpoint. Go prints a goroutine's ARGUMENTS, and the first
// argument of a method is the receiver - `wireguard.(*Endpoint).recoveryLoop(0xa4063d0e288)` - so the
// address that identifies the instance is on the frame itself. It is NOT on `EndpointOptions.Tag`: a string
// is printed as its contents only when it is a direct argument, and this tag reaches the worker through a
// struct field, which the printer shows as a pointer.
//
// The frame line carries the FULL package path, so the marker is searched for rather than used as a prefix;
// the arguments are then read from the LAST '(' of the line, which is the one that opens the argument list
// (method names in this codebase contain no parentheses before it for the frames this is used on, and the
// marker itself carries the receiver's own parentheses).
//
// The address compared against is one the same process produced, at run time, so no assumption is made
// about how the runtime pads or formats an address.
func frameReceiverAddress(goroutine, function string) string {
	for _, line := range strings.Split(goroutine, "\n") {
		line = strings.TrimSpace(line)
		index := strings.Index(line, function+"(")
		if index < 0 {
			continue
		}
		// The marker's own parentheses mean the argument list opens at its last '('.
		rest := line[index+len(function):]
		if !strings.HasPrefix(rest, "(") {
			continue
		}
		rest = rest[1:]
		end := strings.IndexAny(rest, ",)")
		if end < 0 {
			end = len(rest)
		}
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

// endpointFrameAddress is the text the runtime prints for one pointer, produced here by the same printer
// the stack dump uses so the two cannot disagree about formatting.
func endpointFrameAddress(pointer any) string {
	rendered := fmt.Sprintf("%v", []any{pointer})
	// `[0x2c5fbed57608]` is what the slice printer produces for a single pointer.
	return strings.TrimSuffix(strings.TrimPrefix(rendered, "["), "]")
}

// endpointGoroutineCensus counts the goroutines whose stack runs inside `function` on this endpoint.
//
// It refuses to count a goroutine whose stack names one of ITS OWN caller's frames. That exclusion is what
// makes the instrument safe to call from a closure - the shape inside a `require.Eventually` - where the
// calling goroutine's stack is a prefix of the census's own. `censusSelfFrames` returns that frame set, so
// the exclusion is a property of the caller rather than a promise in a comment.
func endpointGoroutineCensus(function string, address string, selfFrames []string) int {
	buffer := make([]byte, 1<<22)
	buffer = buffer[:runtime.Stack(buffer, true)]
	census := 0
	for _, goroutine := range strings.Split(string(buffer), "\n\n") {
		if !strings.Contains(goroutine, function) {
			continue
		}
		if frameReceiverAddress(goroutine, function) != address {
			continue
		}
		self := false
		for _, frame := range selfFrames {
			if strings.Contains(goroutine, frame+"(") {
				self = true
				break
			}
		}
		if !self {
			census++
		}
	}
	return census
}

// censusSelfFrames names the frames of the goroutine that calls it, so a census can refuse to count the
// goroutine it is running on.
func censusSelfFrames() []string {
	var skip [64]uintptr
	count := runtime.Callers(1, skip[:])
	frames := make([]string, 0, count)
	for _, pc := range skip[:count] {
		if function := runtime.FuncForPC(pc); function != nil {
			frames = append(frames, function.Name())
		}
	}
	return frames
}

// goroutineCensus counts the recovery workers running on exactly this endpoint.
//
// # Why it is not runtime.NumGoroutine
//
// That number is process-global: under `-race -count=3`, with other tests' goroutines and the test
// framework's own in flight, it cannot distinguish "this endpoint has a resident worker" from "somebody
// else does". A previous round was caught producing a self-contradicting sentence from exactly that.
//
// # Why the receiver's address, and why stacks
//
// Go prints a goroutine's arguments, and the first argument of a method is its receiver, so the frame
// `wireguard.(*Endpoint).recoveryLoop(0x481c66b0288)` carries the address that identifies the instance.
// Two endpoints of the same type are indistinguishable by name and ARE distinguishable by that address,
// which is the whole requirement: the census is scoped to the instance under test. A first attempt scoped
// it by `EndpointOptions.Tag` and read 0 for sixty live workers, because the tag reaches the worker through
// a struct field and the printer shows that as a pointer, not as a string.
//
// # Why the census cannot count itself
//
// The scan enumerates `runtime.Callers` frames of the CURRENT goroutine and refuses to count any goroutine
// whose stack names one of them. A closure that calls the census - the shape inside a `require.Eventually`
// - has a stack that is a PREFIX of this function's, so all of its frames are in the exclusion set.
// `TestCensusInstrumentIsSensitiveAndDoesNotCountItself` asserts that rather than trusting it.
func goroutineCensus(t *testing.T, endpoint *Endpoint) int {
	t.Helper()
	return endpointGoroutineCensus(markerRecoveryLoop, endpointFrameAddress(endpoint), censusSelfFrames())
}

// socketCensus counts the pinned dependency's receive goroutines for this endpoint's device: one per
// address family per socket, so it is the socket-count instrument.
//
// It is scoped by the DEVICE pointer, not the endpoint's: `RoutineReceiveIncoming` is a method on
// `*device.Device`, and `BindUpdate` is what starts it, so the device is the receiver its frame prints. The
// endpoint is a different allocation, and a first attempt to scope this by the endpoint read 0 on a
// perfectly live socket.
func socketCensus(t *testing.T, endpoint *Endpoint) int {
	t.Helper()
	wgDevice := endpoint.device.Load()
	require.NotNil(t, wgDevice, "a socket census needs a published device")
	return deviceReceiveCensus(wgDevice)
}

// deviceReceiveCensus counts the receive goroutines of a device that has already been unpinned from its
// endpoint. A teardown test needs exactly that: after Close there is no published device left to ask, while the
// goroutines that belonged to it are precisely the ones whose disappearance is being asserted.
func deviceReceiveCensus(wgDevice *device.Device) int {
	return endpointGoroutineCensus(markerReceiveIncoming, endpointFrameAddress(wgDevice), censusSelfFrames())
}

// requireStackIsInsideTheLibrariesSocketControl requires the dumped stack to prove where the blocked socket
// operation actually ran.
//
// This is the "prove which branch YOUR fixture enters" assertion, taken from the running operation itself:
// a stack is not a claim about the code, it is the code. Each frame named below is one link of the chain
// the defect lives on, and the last one is the boundary itself:
//
//	this test's control  <-  familyTolerantListenerControl  <-  conn.listenNet's control closure
//	  <-  net.(*sysListener).listenUDP  <-  net.(*netFD).listenDatagram  <-  net.socket
//	  <-  net.(*ListenConfig).ListenPacket  <-  conn.listenNet  <-  conn.(*StdNetBind).Open
//	  <-  device.(*Device).BindUpdate  <-  device.handleDeviceLine  <-  IpcSetOperation  <-  RebindStale
//
// The `net.ListenConfig` link is written as `net.(*ListenConfig).ListenPacket` because that is the frame Go
// prints: the method has a pointer receiver, so the type in the frame carries the star.
func requireStackIsInsideTheLibrariesSocketControl(t *testing.T, frames []string) {
	t.Helper()
	require.NotEmpty(t, frames, "the stack of the blocked socket operation must have been dumped")
	joined := strings.Join(frames, "\n")
	for _, link := range []struct {
		frame string
		why   string
	}{
		{"wireguard.(*stdBindDialer).UDPListenerControl", "this test's own control hook is the blocked frame"},
		{"bind_family.go", "and it is reached through the family-tolerant wrapper this repository installs"},
		{"conn.listenNet.func1", "whose caller is listenNet's control closure"},
		{"net.(*ListenConfig).ListenPacket", "which net.ListenConfig calls - no context parameter in its path"},
		{"conn.(*StdNetBind).Open", "from the standard bind's Open"},
		{"device.(*Device).BindUpdate", "from the device's BindUpdate"},
		{"device.(*Device).IpcSetOperation", "from the UAPI call RebindStale made"},
		{"wireguard.(*Endpoint).RebindStale", "from the rebind under test"},
	} {
		require.Contains(t, joined, link.frame,
			"the blocked socket operation's stack must contain %q, because %s", link.frame, link.why)
	}
	// And the reason no context of ours is anywhere in that chain is a property of the TYPES: the hook the
	// chain ends in takes no context, which is checked against the standard library's own declaration rather
	// than against this test's description of it.
	requireNoContextInTheListenerControlSignature(t)
}

// requireNoContextInTheListenerControlSignature asserts, by reflection, that the interface this repository
// installs its listener control through has no context parameter anywhere in its signature - and that the
// method that reaches it has none either.
//
// This is the boundary D7-02 cannot cross, stated as a fact about the types rather than as a claim in a
// comment. `net.ListenConfig.Control` IS a `control.Func`; the field's type is what proves that, and a
// future Go release that changed either signature would fail here rather than silently making a
// cancellation guarantee available that this repository does not have.
func requireNoContextInTheListenerControlSignature(t *testing.T) {
	t.Helper()

	controlField, found := reflect.TypeOf(net.ListenConfig{}).FieldByName("Control")
	require.True(t, found, "net.ListenConfig must still expose a Control field")
	require.Equal(t, reflect.TypeOf(control.Func(nil)), controlField.Type,
		"net.ListenConfig.Control must be a control.Func, or the hook this repository installs is not "+
			"the thing this test blocks")
	require.False(t, strings.Contains(controlField.Type.String(), "context"),
		"a listener control with a context parameter would make a cancellable socket open available; the "+
			"whole stated bound of RebindStale rests on its having none")

	// The method has a pointer receiver, so it is on the pointer type: `listenNet` calls it on a
	// `net.ListenConfig` value, whose address is taken for the call.
	listenPacket, found := reflect.TypeOf(&net.ListenConfig{}).MethodByName("ListenPacket")
	require.True(t, found, "net.ListenConfig must still expose ListenPacket")
	contexts := 0
	for index := 0; index < listenPacket.Type.NumIn(); index++ {
		if listenPacket.Type.In(index) == reflect.TypeOf((*context.Context)(nil)).Elem() {
			contexts++
		}
	}
	require.Equal(t, 1, contexts,
		"ListenPacket must take exactly one context, and it is not the one the control hook receives: "+
			"wireguard-go passes context.Background() there, which is why a revocation cannot reach it")
	// The shape of the parameter list, spelled out. `In(0)` is the RECEIVER, as it always is for a method
	// type, so the context is `In(1)`: the two never meet because the control hook is a FIELD whose type has
	// nowhere to put one. `listenNet` is therefore free to pass a live context to ListenPacket - it passes a
	// background one - and the hook still cannot see it.
	require.Equal(t, "*net.ListenConfig", listenPacket.Type.In(0).String(),
		"a method type's first parameter is its receiver")
	require.Equal(t, "context.Context", listenPacket.Type.In(1).String(),
		"the context must be ListenPacket's own parameter, not something the control hook can be handed")
	require.Equal(t, 4, listenPacket.Type.NumIn(),
		"ListenPacket must take a receiver, one context, a network and an address, and nothing else")
}

// ---------------------------------------------------------------------------------------------
// Test 1 - the defect: a superseded rebind must not claim the superseding generation
// ---------------------------------------------------------------------------------------------

// A rebind whose generation is superseded while its socket is being reopened must not claim a recovery for
// the generation that superseded it - and must still leave the endpoint with exactly one socket.
//
// # Where the revocation lands, and why the whole test depends on it
//
//   - NOT before the call. A lease already expired at entry is refused by the guard `RebindStale` has always
//     had, so a test that revokes first measures that guard and passes on the unfixed code - measured, in
//     this file's own history, as a green run against the base commit that proved nothing.
//   - INSIDE the socket operation. Nothing outside the call can schedule that: `RebindStale` runs to
//     completion in microseconds and there is no seam between its check and its UAPI call. The dialer's
//     listener control IS inside it, so the probe runs there (`probeAtSocketOpen`), and the ordering becomes
//     a property of the fixture rather than of the scheduler.
//
// # Why this cannot be an abort, stated as an assertion rather than as a comment
//
// The probe fires once the operation has begun. At that instant the old socket is already closed and the new
// one is being created, so there is nothing left to abandon: walking away would leave the endpoint with no
// socket. The claim this test therefore makes is not "no socket was opened" - that is impossible, and a test
// demanding it would encode a guarantee this layer does not have - it is that the reopen is not REPORTED as a
// recovery for the generation that revoked it, and that the endpoint still holds exactly one socket.
func TestSupersededRebindDoesNotClaimTheNewGeneration(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	portBefore := fixture.livePort(t)
	require.False(t, udpPortIsFree(t, portBefore), "the endpoint must hold its port before the rebind")
	attemptsBefore := fixture.gate.socketAttempts()

	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted, "the first rebind of a generation must be granted")
	require.False(t, lease.Expired(), "the lease must be live when the rebind starts")

	// The revocation happens while the reopen is underway. What the rebind could see at that moment is
	// recorded, so the assertions below describe what was true rather than what was intended.
	var revokedInside atomic.Bool
	var leaseExpiredInside atomic.Bool
	var contextCancelledInside atomic.Bool
	fixture.gate.probeAtSocketOpen(func() {
		revokedInside.Store(true)
		fixture.coordinator.Advance(1)
		leaseExpiredInside.Store(lease.Expired())
		contextCancelledInside.Store(lease.Context().Err() != nil)
	})

	err := fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)

	require.True(t, revokedInside.Load(),
		"the socket operation must have been entered, or this test did not observe the state it describes")
	require.True(t, leaseExpiredInside.Load() && contextCancelledInside.Load(),
		"the fixture must actually have revoked the lease inside the socket operation: expired=%v cancelled=%v",
		leaseExpiredInside.Load(), contextCancelledInside.Load())

	// The reopen ran, and it ran exactly once: one operation per address family. A different number would
	// mean the fixture stopped short of the state under test, or opened a second socket.
	require.Equal(t, int64(2), fixture.gate.socketAttempts()-attemptsBefore,
		"the reopen must have run to completion, one socket operation per address family")

	// And this is what the unfixed code got wrong: it returned SUCCESS for that reopen, so a caller would
	// record generation N+1 as recovered by work performed for generation N.
	require.True(t, revokedRebindClaimed(err),
		"the reopen was reported as a recovery for a generation that had been superseded while it ran: got "+
			"%v; a caller recording that would be treating an old result as current-generation health", err)
	require.ErrorIs(t, err, context.Canceled,
		"the revocation must stay visible through errors.Is, or a caller filtering cancellations would "+
			"report it as a rebind failure instead of a revoked recovery")

	// Resource uniqueness. The abort that is impossible here is not needed for it: one socket, one port.
	require.NotEqual(t, portBefore, fixture.livePort(t),
		"the ephemeral reopen completed, so the port moved: an unchanged port would mean this test observed "+
			"no reopen at all")
	require.False(t, udpPortIsFree(t, fixture.livePort(t)), "and the endpoint must hold it")
	require.Eventually(t, func() bool {
		return socketCensus(t, fixture.endpoint) == socketsPerStandardBind
	}, 3*time.Second, 2*time.Millisecond,
		"the endpoint must hold exactly one socket's worth of receivers after a revoked reopen, not two")
}

// The same revocation, reached through the wake path, so a change applied to only one of the two entry points
// is caught.
func TestRevokedWakeRebindDoesNotClaimTheNewGeneration(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	portBefore := fixture.livePort(t)
	attemptsBefore := fixture.gate.socketAttempts()

	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindDeviceWake)
	require.True(t, granted)
	require.False(t, lease.Expired())

	var revokedInside atomic.Bool
	fixture.gate.probeAtSocketOpen(func() {
		revokedInside.Store(true)
		fixture.coordinator.Advance(1)
	})

	ctx, cancel := context.WithTimeout(lease.Context(), fixture.endpoint.rebindTimeout())
	defer cancel()
	err := fixture.endpoint.RebindStale(ctx, adapter.RebindDeviceWake)

	require.True(t, revokedInside.Load(), "the socket operation must have been entered")
	require.Equal(t, int64(2), fixture.gate.socketAttempts()-attemptsBefore,
		"the reopen must have run to completion, one socket operation per address family")
	require.True(t, revokedRebindClaimed(err),
		"a device-wake rebind must not claim a recovery for the generation that superseded it: got %v", err)
	require.NotEqual(t, portBefore, fixture.livePort(t))
}

// A revocation that arrives BEFORE the rebind starts stops it at the entry guard, which is the boundary
// the previous round already documented. This test keeps that boundary measured as the commit-point guard
// is added around it.
func TestRebindRevokedBeforeItStartsNeverReachesTheDevice(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	portBefore := fixture.livePort(t)
	flightsBefore := fixture.dialer.socketFlights.Load()

	fixture.gate.arm()
	err := fixture.endpoint.RebindStale(ctx, adapter.RebindHandshakeGiveUp)
	fixture.gate.release()

	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, fixture.dialer.socketFlights.Load()-flightsBefore,
		"a rebind with an already-cancelled context must not open a socket")
	require.Equal(t, portBefore, fixture.livePort(t))
}

// The worker path, driven without a race: a rebind revoked while it is in flight must release its lease and
// must not consume the new generation's recovery window.
//
// # Why the socket operation is held
//
// The lease's lifetime is the whole point, and polling for "a lease exists" races it: the worker grants the
// lease and completes it milliseconds later. Holding the socket operation makes the in-flight state
// DETERMINISTIC - the rebind cannot finish while it is blocked - so each assertion below is made about a
// state that is pinned rather than sampled. That is also what lets the revocation land while the lease is
// provably still owned.
func TestRevokedRebindThroughTheRecoveryWorkerReleasesItsLease(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	endpoint.recovery.settle = 10 * time.Millisecond
	endpoint.recovery.poll = 5 * time.Millisecond

	flightsAfterStart := fixture.dialer.socketFlights.Load()

	// Arm first: the worker's rebind will be held inside the socket operation, so "in flight" is a state
	// the test owns while it makes its assertions.
	fixture.gate.arm()

	// A provably dead session is what earns a rebind, and it starts the worker.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	fixture.gate.awaitEntry(t, 5*time.Second)

	lease := endpoint.registration.InflightLease()
	require.NotNil(t, lease,
		"the lease must still be owned while its socket operation is held: a lease released before its "+
			"socket work finished would let a second rebind start on top of the first")
	require.EqualValues(t, 0, lease.Generation(), "the lease belongs to generation 0")
	require.False(t, lease.Expired())
	// ONE socket operation, which the awiting entry above has already observed: this is the first thing the
	// test pins, before the revocation. The count is 1 per socket operation and NOT 1 per rebind: the
	// standard bind reaches the listener control once per address family, and it is the first of the two that
	// signals the gate.
	require.GreaterOrEqual(t, fixture.dialer.socketFlights.Load()-flightsAfterStart, int64(1),
		"the worker must have entered a socket operation")

	// Revoke it WHILE it is in flight, which is what a handover does. The revocation is published inside the
	// held window, so the lease that is running is provably the superseded one.
	fixture.coordinator.Advance(1)
	require.True(t, lease.Expired(), "the in-flight lease must be expired by the generation change")
	require.ErrorIs(t, lease.Context().Err(), context.Canceled)
	// Two socket operations were entered for the one rebind this lease granted - one per address family -
	// and no more. A third would mean something retried inside the same series.
	attemptsForTheRevokedRebind := fixture.dialer.socketFlights.Load() - flightsAfterStart
	require.LessOrEqual(t, attemptsForTheRevokedRebind, int64(socketsPerStandardBind),
		"one rebind may enter at most one socket operation per address family: %d were entered, so a "+
			"second reopen was started on top of the first", attemptsForTheRevokedRebind)

	// Release, and let the worker finish its bookkeeping.
	fixture.gate.release()
	require.Eventually(t, func() bool {
		return endpoint.registration.InflightLease() == nil
	}, 10*time.Second, 2*time.Millisecond,
		"a revoked rebind must still release its lease, or the recovery is wedged forever")

	// The generation advance does two things, and both are asserted: it revokes the in-flight lease, and it
	// re-arms the recovery window so the NEW generation can recover without waiting for the old window.
	require.EqualValues(t, 1, fixture.coordinator.Epoch())
	require.True(t, lease.Expired(), "the lease that ran must be the superseded one")
	require.True(t, endpoint.registration.WakeAllowsRebind(),
		"the new generation must be able to recover: a revoked rebind may not consume its window")

	// The endpoint holds exactly one socket afterwards - which is the resource claim, and it holds whatever
	// happens next: the recovery window is re-armed, so the still-stale session may legitimately earn a
	// SECOND rebind for the new generation. That is the coordinator's design rather than a defect, and the
	// assertion must not pretend otherwise.
	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 5*time.Second, 2*time.Millisecond,
		"the endpoint must hold exactly one socket's worth of receivers, whatever the revoked rebind left "+
			"behind")
	require.False(t, udpPortIsFree(t, fixture.livePort(t)),
		"and it must hold the port it reports")
}

// ---------------------------------------------------------------------------------------------
// Test 2 - the stated bound: a context cannot reach an operation that has already started
// ---------------------------------------------------------------------------------------------

// The measurement the package documentation refers to, and the assertion that the honest bound is
// reported rather than papered over.
//
// A rebind is held INSIDE a real socket open, the generation advances underneath it, and the operation
// completes anyway. This is asserted as the boundary rather than fixed, and the test says so in its name:
// the cancelled context cannot reach `net.ListenConfig.Control`, because `wireguard-go`'s conn/bind_std.go
// calls it from `ListenPacket(context.Background(), ...)` - a background context created inside the pinned
// dependency, for a function whose signature has no context parameter at all.
//
// The two things this package CAN do about it are both asserted here: it does not claim the reopen as a
// recovery for the generation that revoked it, and the endpoint does not end up with two sockets.
func TestCtxCannotReachASocketOperationAlreadyRunning(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	portBefore := fixture.livePort(t)
	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	// Arm the gate, then run the rebind on its own goroutine so the test can observe the state from
	// outside while it is held.
	fixture.gate.arm()
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	}()

	// The rebind is now INSIDE the socket operation, and this is proved from the running stack rather
	// than from the fixture's intent.
	fixture.gate.awaitEntry(t, 5*time.Second)
	frames := dumpGoroutineStacks("ListenConfig")
	requireStackIsInsideTheLibrariesSocketControl(t, frames)
	flightsWhileHeld := fixture.dialer.socketFlights.Load()
	require.Greater(t, flightsWhileHeld, int64(0),
		"the socket operation must have been entered for this test to be about anything")

	// Revoke the generation underneath it.
	fixture.coordinator.Advance(1)
	require.True(t, lease.Expired(), "the lease must be expired while the socket operation is running")
	require.ErrorIs(t, lease.Context().Err(), context.Canceled)

	// The operation is still in flight - and it is still in flight because nothing can stop it, not
	// because the test has not released it yet.
	select {
	case <-rebindDone:
		t.Fatal("the rebind returned while its socket operation was still held, so this test did not " +
			"observe the state it describes")
	default:
	}

	// Release the socket operation. It completes: this is the bound, not a defect.
	fixture.gate.release()
	select {
	case err := <-rebindDone:
		require.True(t, revokedRebindClaimed(err),
			"the reopened socket must NOT be reported as a recovery for the generation that revoked it: "+
				"a caller recording it would be treating an old result as current-generation health")
		require.ErrorIs(t, err, context.Canceled,
			"the revocation must stay visible through errors.Is, or a caller filtering cancellations "+
				"would report it as a rebind failure")
	case <-time.After(10 * time.Second):
		t.Fatal("the rebind did not return after its socket operation was released")
	}

	// The socket WAS reopened. The port moved, because the ephemeral branch released it through IpcSet
	// before reopening: if it did not move, this test did not observe a completed reopen.
	require.NotEqual(t, portBefore, fixture.livePort(t),
		"the revoked socket operation completed, so a new port is the expected outcome - an unchanged "+
			"port would mean the reopen never happened and the claims above are empty")
	require.False(t, udpPortIsFree(t, fixture.livePort(t)), "and the endpoint must hold the new port")
}

// The pinned-port form of the same bound. The port cannot move here, so the evidence that the socket
// operation ran is the control hook itself.
func TestCtxCannotReachASocketOperationAlreadyRunningOnAPinnedPort(t *testing.T) {
	port := freeUDPPort(t)
	fixture := newRebindFixture(t, port)
	fixture.proveStandardBindBranch(t)

	require.EqualValues(t, port, fixture.livePort(t))
	flightsBefore := fixture.dialer.socketFlights.Load()

	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	fixture.gate.arm()
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	}()
	fixture.gate.awaitEntry(t, 5*time.Second)

	fixture.coordinator.Advance(1)
	require.True(t, lease.Expired())

	fixture.gate.release()
	select {
	case err := <-rebindDone:
		require.True(t, revokedRebindClaimed(err))
	case <-time.After(10 * time.Second):
		t.Fatal("a pinned-port rebind did not return after its socket operation was released")
	}

	require.Greater(t, fixture.dialer.socketFlights.Load(), flightsBefore,
		"the socket operation must actually have run: a revoked rebind that never reached the hook would "+
			"make this test a duplicate of the abort case")
	require.EqualValues(t, port, fixture.livePort(t),
		"a pinned port cannot move: the reopen is performed on the configured port")
	require.False(t, udpPortIsFree(t, port), "and the endpoint must still hold it")
}

// The library's control hook ignores a context even when one is available and already dead, which is the
// mechanism behind the bound above, isolated from this repository's code.
//
// `net.ListenConfig.ListenPacket(ctx, ...)` is called by `listenNet` with `context.Background()`, and a
// cancelled context passed to a `ListenPacket` does not stop `Control` from running: the socket is still
// created, and the hook is still handed the raw connection. That is why "hand the operation a cancelled
// context" is not an available fix.
func TestListenControlRunsUnderAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := make(chan struct{}, 1)
	var listener net.ListenConfig
	listener.Control = func(network, address string, conn syscall.RawConn) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	}
	socket, err := listener.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer socket.Close()

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("the control hook must run even under a cancelled context; if it did not, this " +
			"repository could interrupt a socket open by cancelling a context and D7-02 would be fixable")
	}
}

// ---------------------------------------------------------------------------------------------
// Test 3 - resource uniqueness
// ---------------------------------------------------------------------------------------------

// A rebind reopens the socket IN PLACE: `BindUpdate` closes the old bind and waits for its receive
// goroutines to exit (`closeBindLocked`'s `netc.stopping.Wait()`) before the new sockets exist. So "at most
// one socket" is a property of the pinned dependency's ordering, and the thing THIS package can get wrong
// is asking for a second reopen - which the guard is what prevents.
//
// The census is taken from INSIDE the socket operation, through the gate's observer, because that is the
// only state in which a second socket would be visible: at every quiescent point the count is zero whether
// or not a leak exists, so a census taken from the test goroutine would prove nothing. The counts below
// are exact, not bounds, and the receive routine's own appearance afterwards is asserted too - a census
// that reads 0 for the wrong reason would be caught by that.
func TestRebindHoldsExactlyOneSocketWhileItReopens(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	// One receive routine per address family per live socket, started by BindUpdate after the sockets
	// exist. Two is this machine's number for one standard bind, and it is asserted exactly rather than as
	// a bound: a census that read 0 for the wrong reason would otherwise make the reading below vacuous.
	endpoint := fixture.endpoint
	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 3*time.Second, 2*time.Millisecond,
		"a started endpoint must have one receive routine per family: this census is the instrument the "+
			"uniqueness claim rests on, so it is checked on a state whose answer is known")

	inFlight := make(chan int, 4)
	fixture.gate.probeAtSocketOpen(func() {
		// Running INSIDE the socket operation, between the old socket's receive routines having exited and
		// the new socket's having been started.
		inFlight <- socketCensus(t, endpoint)
	})

	lease, granted := endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	fixture.gate.arm()
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	}()
	fixture.gate.awaitEntry(t, 5*time.Second)

	observed := <-inFlight
	fixture.gate.release()
	require.NoError(t, <-rebindDone)

	require.Zero(t, observed,
		"a receive goroutine was still resident at the moment the socket operation was entered, so either "+
			"the old socket was not released or a second one is held: %d were counted, expected 0", observed)

	// And the endpoint is left with exactly one socket's worth of receivers afterwards.
	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 3*time.Second, 2*time.Millisecond,
		"the endpoint must end the rebind with exactly one socket's receivers, not zero and not two")

	// Which socket it is, asked of the OS rather than of the endpoint: the port moved, which is the whole
	// purpose of the ephemeral branch and the evidence that a real reopen was observed.
	newPort := fixture.livePort(t)
	require.NotZero(t, newPort)
	require.False(t, udpPortIsFree(t, newPort), "the endpoint must hold exactly the port it reports")
	require.NotEqual(t, fixture.startedPort, newPort, "the ephemeral rebind must reopen on a new port")
	require.True(t, udpPortIsFree(t, fixture.startedPort),
		"the port the endpoint started on must have been released by the rebind, not merely superseded")
}

// socketsPerStandardBind is the number of receive goroutines one `*conn.StdNetBind` produces on this
// machine: one for udp4 and one for udp6. The tests assert it as an exact number so that a census which
// silently counts nothing fails instead of making a uniqueness claim vacuous.
var socketsPerStandardBind = 2

// Close must release the socket even when a rebind's socket operation is in flight, and must not return
// over an operation that is still running. The release below is what makes this a test of Close rather
// than of the clock: the same claim is made with and without the release.
func TestCloseIsSafeWhileASocketOperationIsInFlight(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	heldPort := fixture.livePort(t)
	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	fixture.gate.arm()
	rebindDone := make(chan error, 1)
	go func() {
		rebindDone <- fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	}()
	fixture.gate.awaitEntry(t, 5*time.Second)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- fixture.endpoint.Close()
	}()

	// Close must not return while the socket operation is still held: it tears the device down, and the
	// device is what is holding the operation.
	select {
	case <-closeDone:
		t.Fatal("Close returned while a socket operation was still in flight, so it cannot have released " +
			"the socket that operation is holding")
	case <-time.After(200 * time.Millisecond):
	}

	// Release the operation. Close must then complete: this layer's contract is that a Close is safe when
	// the underlying operation EVENTUALLY returns, not that it can interrupt it.
	fixture.gate.release()
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Close did not return after the socket operation it was waiting on was released")
	}
	select {
	case <-rebindDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the rebind did not return after Close released the socket operation")
	}

	// The socket the endpoint held is free again, asked of the OS rather than of the endpoint's own
	// bookkeeping: a Close that raced a rebind must not strand a socket.
	require.True(t, udpPortIsFree(t, heldPort),
		"the endpoint must not still hold port %d after Close returned", heldPort)
	fixture.endpoint.stateAccess.Lock()
	closing := fixture.endpoint.closing
	fixture.endpoint.stateAccess.Unlock()
	require.True(t, closing)
}

// Double Close, and a rebind after Close, must both be safe - a Close that ran while a rebind held a lease
// must not leave the lease, the device or the socket behind.
func TestCloseIsIdempotentAfterARevokedRebind(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	port := fixture.livePort(t)
	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	require.NoError(t, fixture.endpoint.Close())
	require.True(t, lease.Expired(),
		"Close must revoke an in-flight lease: invalidating the registration is what cancels it")
	require.ErrorIs(t, lease.Context().Err(), context.Canceled)

	// A rebind arriving after Close finds a closed endpoint and refuses rather than reopening a socket.
	fixture.gate.arm()
	flightsBefore := fixture.dialer.socketFlights.Load()
	err := fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	fixture.gate.release()
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled) || errors.Is(err, errRebindNotPossible),
		"a rebind on a closed endpoint must report a lifecycle outcome rather than open a socket: got %v", err)
	require.Zero(t, fixture.dialer.socketFlights.Load()-flightsBefore)

	// The deviceless half of Close is reachable by calling it again.
	require.NoError(t, fixture.endpoint.Close())
	require.True(t, udpPortIsFree(t, port), "the socket must be released and not reopened")
}

// The fixture must also cover the failure path: a socket that cannot be opened must leave the endpoint
// with no socket rather than a half-open one, and must report the failure to the caller.
//
// This is the "socket-open error" case of the matrix. The control hook itself is what fails, which is the
// earliest point in a socket operation that a dialer can fail it.
func TestASocketOpenFailureIsReportedAndLeavesNoSocket(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	portBefore := fixture.livePort(t)
	lease, granted := fixture.endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)

	fixture.gate.failWith(func() error { return syscall.EINVAL })
	err := fixture.endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	fixture.gate.succeed()

	require.Error(t, err, "a socket that cannot be opened must be reported, not swallowed")
	require.False(t, revokedRebindClaimed(err), "this rebind was not revoked: its socket simply failed to open")
	require.False(t, lease.Expired())

	// Uphill, not downhill: the endpoint must still be usable. A failed reopen is allowed to leave the
	// bind closed (the pinned dependency closes it before it opens), but the next rebind must be able to
	// heal it, and this is what proves the failure did not wedge the endpoint.
	require.Eventually(t, func() bool {
		return fixture.endpoint.RebindStale(context.Background(), adapter.RebindSessionExpired) == nil
	}, 5*time.Second, 10*time.Millisecond,
		"a rebind after a failed socket open must succeed: a transient bind failure may not be terminal")
	healed := fixture.livePort(t)
	require.NotEqual(t, portBefore, healed, "the healing rebind is an ephemeral reopen, so the port moves")
	require.False(t, udpPortIsFree(t, healed))
}

// ---------------------------------------------------------------------------------------------
// Stress: the acceptance counts, on real sockets
// ---------------------------------------------------------------------------------------------

// Fifteen Start/Close cycles with a real socket each, and a full recovery worker run inside each one, with no
// socket, port or recovery worker left behind at the end.
//
// # Why the counts are exact and taken per instance
//
// `runtime.NumGoroutine` cannot answer this: it is process-global, and under `-race -count=3` it cannot tell
// "this cycle leaked" from "somebody else started something". The census here is scoped to the device that
// cycle created, and the port is asked of the OS. A leak of one receive goroutine per cycle would be fifteen
// at the end, which is a failure rather than a number to interpret.
func TestFifteenStartCloseCyclesWithRecoveriesLeakNothing(t *testing.T) {
	const cycles = 15
	ports := make([]uint16, 0, cycles)

	for cycle := 0; cycle < cycles; cycle++ {
		fixture := newRebindFixture(t, 0)
		fixture.proveStandardBindBranch(t)
		endpoint := fixture.endpoint
		wgDevice := endpoint.device.Load()
		ports = append(ports, fixture.livePort(t))
		require.Equal(t, socketsPerStandardBind, socketCensus(t, endpoint),
			"cycle %d: a started endpoint must own exactly one socket's receivers", cycle)

		// A full recovery worker run: a stale session, a real rebind through the worker, and a clean exit.
		endpoint.recovery.settle = time.Millisecond
		endpoint.recovery.poll = time.Millisecond
		endpoint.registration.SetRecoveryWindow(time.Millisecond)
		require.NoError(t, endpoint.RebindStale(context.Background(), adapter.RebindSessionExpired),
			"cycle %d: a direct rebind on a live endpoint must succeed", cycle)

		require.NoError(t, endpoint.Close(), "cycle %d: Close must succeed", cycle)
		require.NoError(t, endpoint.Close(), "cycle %d: a second Close must be safe", cycle)
		require.Eventually(t, func() bool {
			return deviceReceiveCensus(wgDevice) == 0
		}, 10*time.Second, 2*time.Millisecond,
			"cycle %d: no receive goroutine may outlive its endpoint", cycle)
		require.Zero(t, goroutineCensus(t, endpoint),
			"cycle %d: no recovery worker may outlive its endpoint", cycle)
	}

	// Every port from every cycle is free: fifteen cycles did not leave fifteen sockets behind.
	for index, port := range ports {
		require.True(t, udpPortIsFree(t, port),
			"cycle %d left port %d held after Close", index, port)
	}
}

// Twenty-four recoveries through the recovery worker on one endpoint, each driven by a real stale session,
// asserting that the recovery acts exactly once per series and that the socket count never grows.
//
// # Why the worker and not `RebindStale` directly
//
// The worker is where the coalescing policy lives: one lease per series, one rebind per lease. Driving it
// twenty-four times is what shows the counts hold across a long run rather than in a single call, and the
// socket census after each one is what shows no reopen leaked.
func TestTwentyFourRecoveriesThroughTheWorker(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	require.Equal(t, socketsPerStandardBind, socketCensus(t, endpoint))
	endpoint.recovery.settle = time.Millisecond
	endpoint.recovery.poll = time.Millisecond
	endpoint.registration.SetRecoveryWindow(time.Millisecond)

	for series := 0; series < 24; series++ {
		// A fresh proven failure, which is what earns a rebind. The generation is advanced the way a handover
		// does, so the window of the previous series cannot be what stops the next one.
		fixture.coordinator.Advance(uint64(series + 1))
		peer := testPeer
		peer[2] = byte(series)
		endpoint.sessionStateChanged(peer, device.PeerSessionHandshake)
		endpoint.sessionStateChanged(peer, device.PeerSessionExpired)
		require.True(t, endpoint.hasStaleSession(), "series %d: the session must be provably dead", series)

		require.Eventually(t, func() bool {
			return endpoint.registration.InflightLease() == nil && !endpoint.WorkerResident()
		}, 10*time.Second, time.Millisecond,
			"series %d: the recovery worker must finish and release its lease", series)

		require.Eventually(t, func() bool {
			return socketCensus(t, endpoint) == socketsPerStandardBind
		}, 10*time.Second, time.Millisecond,
			"series %d: the endpoint must hold exactly one socket after a recovery", series)
		require.False(t, udpPortIsFree(t, fixture.livePort(t)),
			"series %d: the endpoint must hold the port it reports", series)
	}
}

// Twenty consecutive rebinds on one endpoint, each on a fresh ephemeral port, with the endpoint still owning
// exactly one socket afterwards.
//
// # Why the port history is the assertion
//
// "The rebind succeeded" is reported by the endpoint, so it is the endpoint's own claim. The independent fact
// is the OS port table: after each rebind the previous port must be free and the reported port must be held.
// A leak of one socket per rebind would take twenty rebinds to show as a port that is held but not reported,
// and that is exactly what is checked.
func TestTwentyConsecutiveRebindsKeepOneSocket(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	attemptsBefore := fixture.gate.socketAttempts()
	previous := fixture.livePort(t)
	released := make([]uint16, 0, 20)

	for cycle := 0; cycle < 20; cycle++ {
		require.False(t, udpPortIsFree(t, previous),
			"cycle %d: the endpoint must hold its port before the rebind", cycle)

		// Ask for the lease the way a real series does. A refusal is the window rather than the endpoint, and
		// a generation change is what re-arms it in the field - so the test advances one, which also keeps the
		// twenty cycles a count of REBINDS rather than of refusals.
		lease, granted := endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
		if !granted {
			fixture.coordinator.Advance(uint64(cycle + 1))
			lease, granted = endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
		}
		require.True(t, granted, "cycle %d: a rebind must be grantable", cycle)

		err := endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
		lease.Complete()
		require.NoError(t, err, "cycle %d: the rebind must succeed on a live lease", cycle)

		current := fixture.livePort(t)
		require.False(t, udpPortIsFree(t, current),
			"cycle %d: the endpoint must hold the port it reports", cycle)
		require.True(t, udpPortIsFree(t, previous),
			"cycle %d: the port the endpoint left behind (%d) must have been released, not merely "+
				"superseded - a held port that is no longer reported is a leaked socket",
			cycle, previous)
		released = append(released, previous)
		previous = current
	}

	// One socket operation per family per rebind, and no more: a second reopen inside one rebind would show
	// up here as a count above the number of cycles.
	require.Equal(t, int64(20*socketsPerStandardBind), fixture.gate.socketAttempts()-attemptsBefore,
		"twenty rebinds must enter exactly one socket operation per family each")

	// And the endpoint is left with exactly one socket's worth of receivers, holding one port.
	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 5*time.Second, 2*time.Millisecond,
		"after twenty rebinds the endpoint must hold exactly one socket")
	require.False(t, udpPortIsFree(t, fixture.livePort(t)))

	// Every port but the current one is free: the endpoint holds ONE port, not a history of them.
	for _, port := range released {
		require.True(t, udpPortIsFree(t, port),
			"port %d from an earlier rebind is still held: twenty rebinds left more than one socket", port)
	}
}

// Ten pause/wake cycles interleaved with rebinds, on one endpoint: the socket must be released and reopened
// without the endpoint ever holding two, and the recovery must still be able to act afterwards.
//
// `onPauseUpdated` is the network-pause half of the pause contract: `EventNetworkPause` takes the device down
// (which closes the bind) and `EventNetworkWake` brings it back up (which opens one). A rebind arriving in
// either state must not leave a socket behind.
//
// # Why the OS port table is the assertion, and not the reported port
//
// `device.net.port` is the port the device was ASKED for, and `Down` does not clear it: after a pause the
// device still reports the port it used to hold while holding nothing. So "no socket" cannot be read off the
// device here, and the honest question is the one the OS answers - is the port free? - asked before and after
// each transition.
func TestPauseWakeCyclesInterleavedWithRebindsKeepOneSocket(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	for cycle := 0; cycle < 10; cycle++ {
		held := fixture.livePort(t)
		require.False(t, udpPortIsFree(t, held),
			"cycle %d: the endpoint must hold its port before the pause", cycle)

		endpoint.onPauseUpdated(pause.EventNetworkPause)
		require.True(t, udpPortIsFree(t, held),
			"cycle %d: a network pause must RELEASE the socket - the port the device still reports (%d) is "+
				"the port it was asked for, not one it holds", cycle, held)

		endpoint.onPauseUpdated(pause.EventNetworkWake)
		require.Eventually(t, func() bool {
			return !udpPortIsFree(t, held)
		}, 10*time.Second, 2*time.Millisecond,
			"cycle %d: waking the network must reopen the bind, on the port it was configured with", cycle)

		live := fixture.livePort(t)
		require.False(t, udpPortIsFree(t, live),
			"cycle %d: the endpoint must hold the port it reports after a wake", cycle)
		require.Eventually(t, func() bool {
			return socketCensus(t, endpoint) == socketsPerStandardBind
		}, 10*time.Second, 2*time.Millisecond,
			"cycle %d: a wake must leave exactly one socket, not two", cycle)

		// And a rebind on the woken device, which is the interleaving under test.
		lease, granted := endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
		if !granted {
			fixture.coordinator.Advance(uint64(cycle + 1))
			lease, granted = endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
		}
		require.True(t, granted, "cycle %d: the rebind must be granted", cycle)
		err := endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
		lease.Complete()
		require.NoError(t, err, "cycle %d: the rebind must succeed on a woken device", cycle)

		after := fixture.livePort(t)
		require.False(t, udpPortIsFree(t, after),
			"cycle %d: the endpoint must hold the port it reports after a rebind", cycle)
		require.True(t, udpPortIsFree(t, live),
			"cycle %d: the port from before the rebind must have been released", cycle)
	}
}

// A fault-injected socket-open failure, then Close, then another Close: the failure must not leave a socket
// and must not wedge the teardown.
func TestCloseAfterAFaultInjectedOpenFailureLeavesNoSocket(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	port := fixture.livePort(t)
	// The device is captured BEFORE the Close: Close unpublishes it, and the census needs the receiver's
	// pointer to count the goroutines that belonged to it.
	wgDevice := endpoint.device.Load()
	require.NotNil(t, wgDevice)

	lease, granted := endpoint.registration.BeginRebind(adapter.RebindSessionExpired)
	require.True(t, granted)
	fixture.gate.failWith(func() error { return syscall.EADDRINUSE })
	err := endpoint.RebindStale(lease.Context(), adapter.RebindSessionExpired)
	fixture.gate.succeed()
	lease.Complete()

	require.Error(t, err, "the injected socket failure must be reported")
	require.False(t, revokedRebindClaimed(err), "and it must not be reported as a revocation")

	// Close must release whatever the failed rebind left, and a second Close must be safe.
	require.NoError(t, endpoint.Close())
	require.NoError(t, endpoint.Close())
	require.True(t, udpPortIsFree(t, port),
		"port %d must be free after Close, even though a rebind failed in front of it", port)
	require.Eventually(t, func() bool {
		return deviceReceiveCensus(wgDevice) == 0
	}, 5*time.Second, 2*time.Millisecond,
		"no receive goroutine may outlive the Close: each one belongs to a socket that was not released")
}

// revokedRebindMarker is the phrase that identifies a revoked rebind in an error.
const revokedRebindMarker = "rebind lease was revoked"

// revokedRebindClaimed reports whether an error says the rebind completed without being able to claim its
// generation.
//
// # Why this file reads the message and the instrument file does not
//
// This file has to COMPILE against the base commit - it is the one run against the unfixed revision to show
// the defect is real - and the base commit has no revocation sentinel to probe with `errors.Is`. A test file
// cannot be conditionally compiled, so the predicate here is the weaker one: the message.
//
// That weakness is bounded and is asserted elsewhere: `TestRevokedRebindPredicateIsAboutTheLease` in
// rebind_lease_instrument_test.go builds an error whose text reads like a revoked rebind while carrying no
// sentinel, shows this predicate is fooled by it, and shows the production predicate is not. It also shows
// the two agree on every genuinely revoked rebind, which is what keeps this file's probes from being vacuous.
func revokedRebindClaimed(err error) bool {
	return err != nil && strings.Contains(err.Error(), revokedRebindMarker)
}

// dumpGoroutineStacks returns the frames of every goroutine whose stack contains `filter`, for the
// "prove which branch" assertions. It asserts nothing itself; the caller does.
func dumpGoroutineStacks(filter string) []string {
	buffer := make([]byte, 1<<22)
	buffer = buffer[:runtime.Stack(buffer, true)]
	var frames []string
	for _, goroutine := range strings.Split(string(buffer), "\n\n") {
		if strings.Contains(goroutine, filter) {
			frames = append(frames, goroutine)
		}
	}
	return frames
}
