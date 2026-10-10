package wireguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	// conn is read on the connect() fast path, which deliberately does not take connAccess, and
	// written by connect() and Close(). It is an atomic pointer so that read has a defined value
	// rather than a torn one.
	conn        atomic.Pointer[wireConn]
	done        chan struct{}
	isConnect   bool
	connectAddr netip.AddrPort
	reserved    [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	// The bind context is created HERE, not in Open, so a Send or a receive that arrives before Open
	// has a parent to derive its dial deadline from. Deriving it lazily left a nil context in that
	// window, and `context.WithTimeout(nil, ...)` panics - from wireguard-go's send or receive
	// goroutine, which is process-fatal rather than a failed operation. Open replaces it with a
	// fresh one, which is what makes the bind restartable after a Close.
	bindCtx, bindDone := context.WithCancel(ctx)
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		bindCtx:             bindCtx,
		bindDone:            bindDone,
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

// clientBindDialTimeout bounds how long establishing the bind's socket may take.
//
// Without it the dial inherits only the bind context's cancellation, and that context lives as
// long as the endpoint: a detour outbound whose path silently drops packets parks the dial
// indefinitely while connAccess is held. Everything that needs connAccess then queues behind a
// dial that has no end in sight - sends, the bind's own Close, and every rebind - which is how a
// single half-dead node froze the process's network machinery instead of failing one endpoint.
// It is a var so a test can shrink it.
var clientBindDialTimeout = constant.TCPTimeout

// errNoDialer is the capability boundary for a bind built without a dialer.
//
// os.ErrInvalid rather than a new sentinel: what is wrong is the construction of this bind, not the
// state of the network, and a caller that wants to distinguish it from a transient failure only
// needs to know that retrying cannot help.
var errNoDialer = E.Cause(os.ErrInvalid, "wireguard: bind has no dialer")

// logError reports through the logger when the embedder supplied one.
//
// The logger is optional for the same reason the pause manager is: a box always installs both, a
// bare embedder may install neither, and calling a method on a nil interface is a panic on a
// background goroutine.
func (c *ClientBind) logError(err error) {
	if c.logger != nil {
		c.logger.Error(err)
	}
}

// waitActive honours the pause manager when one is installed, and does nothing when there is none.
//
// service.FromContext returns a nil interface for a service that was never registered, so the call
// this replaces would have dereferenced a nil pause.Manager.
func (c *ClientBind) waitActive() {
	if c.pauseManager != nil {
		c.pauseManager.WaitActive()
	}
}

func (c *ClientBind) connect() (*wireConn, error) {
	// Checked before anything else is touched: this function is called from wireguard-go's receive
	// loop and from its send path, both on goroutines the caller does not own, and a nil dereference
	// there takes the process down instead of failing an operation.
	if c.dialer == nil {
		return nil, errNoDialer
	}
	serverConn := c.conn.Load()
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn = c.conn.Load()
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	dialCtx, cancelDial := context.WithTimeout(c.bindCtx, clientBindDialTimeout)
	defer cancelDial()
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(dialCtx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
		if err != nil {
			return nil, err
		}
		created := &wireConn{
			PacketConn: bufio.NewUnbindPacketConn(udpConn),
			done:       make(chan struct{}),
		}
		c.conn.Store(created)
		return created, nil
	}
	udpConn, err := c.dialer.ListenPacket(dialCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
	if err != nil {
		return nil, err
	}
	created := &wireConn{
		PacketConn: bufio.NewPacketConn(udpConn),
		done:       make(chan struct{}),
	}
	c.conn.Store(created)
	return created, nil
}

// Open prepares the bind for a run.
//
// # Why a nil dialer is refused HERE
//
// Told apart from the send and receive paths on purpose: this is the call wireguard-go makes from
// its bind update, so returning an error here fails the device's up transition and, with it, the
// endpoint's start. A bind that cannot establish a socket is a capability the endpoint does not
// have, and an endpoint that comes up with it would have no receive path at all - reachable, and
// silently unable to carry a single packet.
//
// It deliberately does NOT substitute a system dialer. The dialer carries the operator's detour,
// bind_interface and routing mark; dialling around it would send the tunnel's traffic out of a path
// the operator did not choose, which is a worse failure than refusing to start.
func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	if c.dialer == nil {
		return nil, 0, errNoDialer
	}
	select {
	case <-c.done:
		// A bind is opened again after a Close by every rebind and every down/up transition, so a
		// closed bind must be restartable rather than permanently spent.
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		select {
		case <-c.done:
			// The bind is closed, so this receive loop is finished - and it has to say so.
			//
			// Returning a nil error here left wireguard-go's receive loop calling back
			// immediately, forever: it only exits on an error, so the loop became a hot spin at
			// 100% of a core. Because the loop's deferred Done() is what a Close waits on, that
			// spin also meant the device could never finish stopping - Endpoint.Close hung
			// indefinitely while the process stayed busy.
			return 0, net.ErrClosed
		default:
		}
		c.logError(E.Cause(err, "connect to server"))
		// One retry per second while the dial keeps failing, but only while the device still has
		// a reason to be up: the sleep is not interruptible, so an unbounded number of them after
		// the bind was closed is what the c.done check above exists to prevent.
		c.waitActive()
		if !c.sleepRetry() {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		udpConn.Close()
		select {
		case <-c.done:
			// Same reason as the connect failure above: a closed bind must end the loop with an
			// error, not with a nil that asks wireguard-go to call straight back in.
			return 0, net.ErrClosed
		default:
			c.logError(E.Cause(err, "read packet"))
			err = nil
		}
		return
	}
	sizes[0] = n
	if n > 3 {
		b := packets[0]
		clear(b[1:4])
	}
	eps[0] = remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort())
	count = 1
	return
}

func (c *ClientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	common.Close(common.PtrOrNil(c.conn.Load()))
	return nil
}

// sleepRetry waits a second, reporting whether the bind is still open when it wakes. The wait
// itself is not interruptible, so callers must re-check done rather than assume the sleep proves
// anything about the bind's state.
func (c *ClientBind) sleepRetry() bool {
	time.Sleep(time.Second)
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	if c.dialer == nil {
		// Answered before the retry machinery on purpose: this failure is permanent, and the retry
		// path sleeps a second before reporting it. Sleeping there would add a second of delay to
		// EVERY packet the device tries to send, turning a construction error into a stall.
		return errNoDialer
	}
	udpConn, err := c.connect()
	if err != nil {
		c.waitActive()
		if !c.sleepRetry() {
			return net.ErrClosed
		}
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[destination]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedAccess.Lock()
	c.reservedForEndpoint[destination] = reserved
	c.reservedAccess.Unlock()
}

type wireConn struct {
	net.PacketConn
	conn   net.Conn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.conn != nil {
		return w.conn.Write(b)
	}
	return w.PacketConn.WriteTo(b, M.SocksaddrFromNetIP(addr).UDPAddr())
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.PacketConn.Close()
	close(w.done)
	return nil
}

var _ conn.Endpoint = (*remoteEndpoint)(nil)

type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc() {
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return netip.AddrPort(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return netip.AddrPort(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
