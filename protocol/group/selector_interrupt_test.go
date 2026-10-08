package group

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Switching a selector member must interrupt the connections carried by it.
//
// # The failure this guards against (LX 064)
//
// `interrupt_exist_connections` on a selector was dead for inbound traffic: the group handed the
// LEAF outbound to the connection manager, so the connection was dialled through the leaf's own
// DialContext and never registered with the group's interrupt group. The list stayed empty,
// Interrupt closed nothing, and switching nodes left the old connections running until their own
// timeouts - the setting only appeared to work for Stop/Start.
//
// This tree is on the upstream mechanism (AttachConnection plus route's registerInterrupt) rather
// than the LX inbound wrapper, so the defect cannot be written the same way. What is pinned here
// is the group's own half of the contract: a connection dialled through the group is registered,
// and a selection change interrupts exactly what the setting says it should.
func TestSelectorSelectionChangeInterruptsCarriedConnections(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                         string
		interruptExternalConnections bool
		isExternal                   bool
		wantInterrupted              bool
	}{
		{name: "external connection, interrupt enabled", interruptExternalConnections: true, isExternal: true, wantInterrupted: true},
		{name: "external connection, interrupt disabled", interruptExternalConnections: false, isExternal: true, wantInterrupted: false},
		{name: "internal connection, interrupt enabled", interruptExternalConnections: true, isExternal: false, wantInterrupted: true},
		{name: "internal connection, interrupt disabled", interruptExternalConnections: false, isExternal: false, wantInterrupted: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			selector, leaf := newSelectorFixture(t, testCase.interruptExternalConnections)

			ctx := context.Background()
			if testCase.isExternal {
				ctx = interrupt.ContextWithIsExternalConnection(ctx)
			}
			conn, err := selector.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("93.184.216.34:443"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			require.True(t, selector.SelectOutbound("node-b"))
			require.Equal(t, testCase.wantInterrupted, leaf.lastConn().closed.Load(),
				"a selection change must interrupt the connections the setting covers")
		})
	}
}

// A switch to the outbound that is already selected is not a switch, so it must not interrupt.
func TestSelectorReselectingTheSameOutboundDoesNotInterrupt(t *testing.T) {
	t.Parallel()

	selector, leaf := newSelectorFixture(t, true)
	conn, err := selector.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("93.184.216.34:443"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.True(t, selector.SelectOutbound("node-a"))
	require.False(t, leaf.lastConn().closed.Load(),
		"re-selecting the current member must not tear its connections down")
}

func newSelectorFixture(t *testing.T, interruptExternalConnections bool) (*Selector, *trackingOutbound) {
	t.Helper()
	leaf := &trackingOutbound{tag: "node-a"}
	other := &trackingOutbound{tag: "node-b"}
	manager := &taggedOutboundManager{byTag: map[string]adapter.Outbound{"node-a": leaf, "node-b": other}}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	created, err := NewSelector(ctx, nil, log.NewNOPFactory().NewLogger("selector"), "group", option.SelectorOutboundOptions{
		Outbounds:                 []string{"node-a", "node-b"},
		Default:                   "node-a",
		InterruptExistConnections: interruptExternalConnections,
	})
	require.NoError(t, err)
	selector, isSelector := created.(*Selector)
	require.True(t, isSelector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))
	return selector, leaf
}

// trackingOutbound hands out connections that remember being closed.
type trackingOutbound struct {
	adapter.Outbound
	tag string
	// ignoredOptions keeps the embedded interface from being nil in a way vet complains about.
	ignoredOptions option.DialerOptions

	access   sync.Mutex
	last     *trackedConn
	allConns []*trackedConn
}

func (o *trackingOutbound) Type() string      { return C.TypeDirect }
func (o *trackingOutbound) Tag() string       { return o.tag }
func (o *trackingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *trackingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn := &trackedConn{}
	o.access.Lock()
	o.last = conn
	o.allConns = append(o.allConns, conn)
	o.access.Unlock()
	return conn, nil
}

func (o *trackingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (o *trackingOutbound) lastConn() *trackedConn {
	o.access.Lock()
	defer o.access.Unlock()
	return o.last
}

// trackedConn is a connection that remembers being closed.
type trackedConn struct {
	closed    atomic.Bool
	closeOnce sync.Once
}

func (c *trackedConn) Read(p []byte) (int, error)         { return 0, net.ErrClosed }
func (c *trackedConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *trackedConn) LocalAddr() net.Addr                { return nil }
func (c *trackedConn) RemoteAddr() net.Addr               { return nil }
func (c *trackedConn) SetDeadline(t time.Time) error      { return nil }
func (c *trackedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *trackedConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() { c.closed.Store(true) })
	return nil
}

var (
	_ net.Conn         = (*trackedConn)(nil)
	_ adapter.Outbound = (*trackingOutbound)(nil)
	_                  = outbound.NewAdapter
)
