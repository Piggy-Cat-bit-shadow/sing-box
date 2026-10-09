package route

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The auto-redirect output mark is claimed once, by the inbound that owns the redirect, and read on
// every dial the box makes. protocol/tun/inbound.go claims it as the last side effect of NewInbound;
// adapter/inbound/manager.go runs that constructor OUTSIDE the lock that installs the tag.
//
// These tests pin the three properties that arrangement depends on, with the real NetworkManager,
// the real inbound Registry and the real inbound Manager:
//
//  1. the claim is exclusive even when it is entered concurrently,
//  2. the registry that wires the product serialises constructors, so box.go's own startup cannot
//     enter the claim twice at once,
//  3. a claim is single shot and can be released by its owner, so a constructor whose object is
//     discarded cannot keep the mark.
const testAutoRedirectMark = uint32(0x2024)

type markProbeInbound struct {
	tag   string
	close atomic.Int32
}

func (i *markProbeInbound) Type() string                                   { return "mark-probe" }
func (i *markProbeInbound) Tag() string                                    { return i.tag }
func (i *markProbeInbound) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (i *markProbeInbound) Close() error                                   { i.close.Add(1); return nil }

type markProbeOptions struct{}

func newAutoRedirectTestManager(t *testing.T) (context.Context, *NetworkManager) {
	t.Helper()
	networkManager, err := NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	return ctx, networkManager
}

// constructorGauge records how many constructors were ever inside their body at the same time.
type constructorGauge struct {
	active atomic.Int32
	peak   atomic.Int32
}

func (g *constructorGauge) enter() {
	current := g.active.Add(1)
	for {
		peak := g.peak.Load()
		if current <= peak || g.peak.CompareAndSwap(peak, current) {
			return
		}
	}
}

func (g *constructorGauge) leave() {
	g.active.Add(-1)
}

// TestInboundCreateSerializesAutoRedirectOutputMarkClaim drives the real inbound Manager and the
// real Registry the way box.go wires them: several Create calls released from one barrier, each for
// a DISTINCT tag, each constructor claiming the mark exactly as protocol/tun/inbound.go:301 does.
//
// The registry holds its lock across the constructor, so only one claim can be in flight; the others
// are refused by the claim itself. If a future change moves the constructor outside the registry
// lock, this test is where the losing interleaving becomes visible: peak would exceed 1 and more than
// one Create would succeed.
func TestInboundCreateSerializesAutoRedirectOutputMarkClaim(t *testing.T) {
	ctx, networkManager := newAutoRedirectTestManager(t)
	gauge := &constructorGauge{}
	registry := inbound.NewRegistry()
	inbound.Register[markProbeOptions](registry, "mark-probe", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options markProbeOptions) (adapter.Inbound, error) {
		gauge.enter()
		defer gauge.leave()
		networkManager := service.FromContext[adapter.NetworkManager](ctx)
		err := networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark)
		if err != nil {
			return nil, err
		}
		// Invite an overlap: if two constructors could be inside at once, yielding makes it certain
		// rather than likely that the gauge observes it.
		runtime.Gosched()
		return &markProbeInbound{tag: tag}, nil
	})
	manager := inbound.NewManager(registry, nil)

	const workers = 8
	start := make(chan struct{})
	results := make([]error, workers)
	var waitGroup sync.WaitGroup
	for i := 0; i < workers; i++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			results[index] = manager.Create(ctx, nil, log.NewNOPFactory().NewLogger("mark-probe"), "probe-"+strconv.Itoa(index), "mark-probe", nil)
		}(i)
	}
	close(start)
	waitGroup.Wait()

	var succeeded int
	for index, err := range results {
		if err == nil {
			succeeded++
			continue
		}
		require.ErrorContains(t, err, "only one auto-redirect can be configured", "worker ", index)
	}
	require.Equal(t, 1, succeeded, "exactly one Create may own the mark")
	require.EqualValues(t, 1, gauge.peak.Load(), "the registry must not let two constructors claim the mark at once")
	require.Len(t, manager.Inbounds(), 1)
	require.Equal(t, testAutoRedirectMark, networkManager.AutoRedirectOutputMark())
}

// TestAutoRedirectOutputMarkClaimIsExclusiveUnderConcurrency releases several claims from one barrier
// and requires exactly one of them to win. The check-and-set is the guard that keeps a second
// auto-redirect inbound from overwriting the mark the first one's routing depends on.
func TestAutoRedirectOutputMarkClaimIsExclusiveUnderConcurrency(t *testing.T) {
	_, networkManager := newAutoRedirectTestManager(t)

	const workers = 16
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	var succeeded atomic.Int32
	var winner atomic.Uint32
	for i := 0; i < workers; i++ {
		waitGroup.Add(1)
		go func(mark uint32) {
			defer waitGroup.Done()
			<-start
			if err := networkManager.RegisterAutoRedirectOutputMark(mark); err == nil {
				succeeded.Add(1)
				winner.Store(mark)
			}
		}(uint32(i + 1))
	}
	close(start)
	waitGroup.Wait()

	require.EqualValues(t, 1, succeeded.Load(), "a second concurrent claim must be refused")
	require.Equal(t, winner.Load(), networkManager.AutoRedirectOutputMark(), "the stored mark must be the winner's")
}

// TestAutoRedirectOutputMarkClaimIsSingleShotIncludingZero pins the sentinel. A claim of zero is
// still a claim: the previous spelling of this guard tested the stored VALUE, so a zero mark left the
// field indistinguishable from unclaimed and a later auto-redirect inbound could claim on top of it.
func TestAutoRedirectOutputMarkClaimIsSingleShotIncludingZero(t *testing.T) {
	_, networkManager := newAutoRedirectTestManager(t)

	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(0))
	require.ErrorContains(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark), "only one auto-redirect can be configured")
	require.Zero(t, networkManager.AutoRedirectOutputMark())
}

// TestAutoRedirectOutputMarkReleaseReopensExactlyOneClaim covers the release convention: the owner
// hands the mark back, a later owner can claim it, and a release that does not match the current claim
// leaves it alone.
//
// A release is matched by value, which is enough because a claim is exclusive: a second owner can only
// take a mark once the previous one has been handed back, so a stale release of the SAME value cannot
// arrive after the value was re-claimed - the previous owner's release is what made the value
// claimable again in the first place.
func TestAutoRedirectOutputMarkReleaseReopensExactlyOneClaim(t *testing.T) {
	_, networkManager := newAutoRedirectTestManager(t)

	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
	networkManager.ReleaseAutoRedirectOutputMark(testAutoRedirectMark)
	require.Zero(t, networkManager.AutoRedirectOutputMark())

	otherMark := testAutoRedirectMark ^ 0xFF
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(otherMark))

	// The discarded owner releases the mark it held, after the new owner took a different one.
	networkManager.ReleaseAutoRedirectOutputMark(testAutoRedirectMark)
	require.Equal(t, otherMark, networkManager.AutoRedirectOutputMark())

	// And its own release still works.
	networkManager.ReleaseAutoRedirectOutputMark(otherMark)
	require.Zero(t, networkManager.AutoRedirectOutputMark())
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
}

// TestAutoRedirectOutputMarkReleaseKeepsTheClaimTableConsistent pins what the release must leave
// behind: the guard has to open again, or a box that discards its only auto-redirect inbound could
// never configure another one.
func TestAutoRedirectOutputMarkReleaseKeepsTheClaimTableConsistent(t *testing.T) {
	_, networkManager := newAutoRedirectTestManager(t)

	// A release with no claim behind it is a no-op rather than a way to reset the guard.
	networkManager.ReleaseAutoRedirectOutputMark(testAutoRedirectMark)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
	require.Error(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
	networkManager.ReleaseAutoRedirectOutputMark(testAutoRedirectMark)
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
}

type rawConnStub struct{ fd uintptr }

func (c *rawConnStub) Control(f func(fd uintptr)) error    { f(c.fd); return nil }
func (c *rawConnStub) Read(f func(fd uintptr) bool) error  { f(c.fd); return nil }
func (c *rawConnStub) Write(f func(fd uintptr) bool) error { f(c.fd); return nil }

// TestAutoRedirectOutputMarkFuncReadsWithoutRacing runs the closure the dialer installs on every
// socket while a claim is taken. The closure reads the mark on every dial, so a claim concurrent with
// a dial must not race with it. The handshake gets the reader into the loop before the claim and keeps
// it there across the claim; the yields are what make the overlap happen on every run instead of on a
// lucky one.
func TestAutoRedirectOutputMarkFuncReadsWithoutRacing(t *testing.T) {
	_, networkManager := newAutoRedirectTestManager(t)
	markFunc := networkManager.AutoRedirectOutputMarkFunc()
	rawConn := &rawConnStub{}

	// control.RoutingMark is only implemented on Linux; past the zero check the closure calls it
	// directly, so the invocation is guarded and the read it performs on the way there is not.
	markImplemented := control.RoutingMark(1) != nil
	read := func() {
		if markImplemented {
			_ = markFunc("tcp", "127.0.0.1:80", rawConn)
			return
		}
		_ = networkManager.AutoRedirectOutputMark()
	}

	readerStarted := make(chan struct{})
	readerStop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		close(readerStarted)
		for {
			select {
			case <-readerStop:
				return
			default:
			}
			read()
		}
	}()
	<-readerStarted
	for range 8 {
		runtime.Gosched()
	}
	require.NoError(t, networkManager.RegisterAutoRedirectOutputMark(testAutoRedirectMark))
	close(readerStop)
	<-readerDone

	require.Equal(t, testAutoRedirectMark, networkManager.AutoRedirectOutputMark())
	// The mark the dialer reads after the claim is the one that was claimed.
	require.NotNil(t, networkManager.AutoRedirectOutputMarkFunc())
}

var (
	_ syscall.RawConn = (*rawConnStub)(nil)
	_ adapter.Inbound = (*markProbeInbound)(nil)
	// protocol/tun hands the claim back through this exact method. It is asserted rather than declared
	// in adapter.NetworkManager, so the shape is pinned here to keep the two packages agreeing on it.
	_ autoRedirectMarkReleaser = (*NetworkManager)(nil)
)

type autoRedirectMarkReleaser interface {
	ReleaseAutoRedirectOutputMark(mark uint32)
}
