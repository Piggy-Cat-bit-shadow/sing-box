package interrupt

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the locking rule the group primitive must obey.
//
// # Why the lock may not be held while a child Close runs (LX 084)
//
// A group can hold a closer that belongs to ANOTHER group. Nested selectors produce exactly that:
// dialing through `outer -> inner -> node` wraps the connection once per group, so the outer group's
// list holds the inner group's *interrupt.Conn. The wrap order depends on the direction the
// connection travelled:
//
//	outbound (detour):  outer.DialContext -> inner.DialContext -> node, wrapped as outer(inner(raw))
//	inbound            : inner wraps a connection the outer group already wrapped, i.e. inner(outer(raw))
//
// Closing the two shapes takes the two locks in opposite orders. If `Interrupt` or `Close` holds its
// own lock while calling the child's Close, the two orders collide in a classic ABBA deadlock, and
// every later NewConn/Interrupt on either group blocks behind it - the whole data path of both
// groups stops until the process restarts, with the UI already showing the new selection because
// SelectOutbound stores before it interrupts.
//
// The rule is therefore: remove the entry under the lock, release it, and only then close the child.
// These tests pin that rule directly. They are written as determinism-first checks - a closer that
// needs the same lock again - rather than as a timing-dependent two-goroutine race, so the failure
// is reproducible instead of probabilistic.

// closerFunc adapts a function to io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// reentrantConn is a net.Conn whose Close needs its group's lock, which is what a nested group's
// wrapper does in production.
type reentrantConn struct {
	net.Conn
	onClose func()
}

func (c *reentrantConn) Close() error {
	c.onClose()
	return nil
}

func (c *reentrantConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *reentrantConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *reentrantConn) SetDeadline(time.Time) error      { return nil }
func (c *reentrantConn) SetReadDeadline(time.Time) error  { return nil }
func (c *reentrantConn) SetWriteDeadline(time.Time) error { return nil }

// requireCompletes runs fn and fails the test if it does not return. A deadlocked implementation
// blocks forever rather than returning an error, so a failure here is the deadlock itself.
func requireCompletes(t *testing.T, description string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(description, ": the group lock was held across a child Close, so this deadlocked")
	}
}

// TestInterruptDoesNotHoldTheLockWhileClosingAChild is the direct statement of the rule.
//
// The child needs the group's own lock in order to finish closing, which is precisely what the
// primitive forbids. An implementation that closes under the lock deadlocks here, every time.
func TestInterruptDoesNotHoldTheLockWhileClosingAChild(t *testing.T) {
	group := NewGroup()

	closed := false
	group.Add(closerFunc(func() error {
		// Another group's wrapper would take that other group's lock. Taking THIS group's lock is
		// the same hazard in its smallest form, and it is deterministic.
		group.Interrupt(true)
		closed = true
		return nil
	}), true)

	requireCompletes(t, "Interrupt over a child that re-enters the group", func() {
		group.Interrupt(true)
	})

	require.True(t, closed, "the child must actually have been closed")
	require.Equal(t, 0, group.connections.Size(),
		"an interrupted connection is removed from the group, so a later Close cannot try to close "+
			"it a second time")
}

// TestConnCloseDoesNotHoldTheLockWhileClosingTheUnderlyingConn is the same rule on the wrapper.
//
// Closing the wrapper returned by NewConn must not hold the group lock while the underlying
// connection closes, because the underlying connection may itself be another group's wrapper.
func TestConnCloseDoesNotHoldTheLockWhileClosingTheUnderlyingConn(t *testing.T) {
	group := NewGroup()

	underlyingClosed := false
	conn := group.NewConn(&reentrantConn{onClose: func() {
		group.Interrupt(true)
		underlyingClosed = true
	}}, true)

	requireCompletes(t, "Conn.Close over an underlying connection that re-enters the group", func() {
		_ = conn.Close()
	})

	require.True(t, underlyingClosed)
	require.Equal(t, 0, group.connections.Size())
}

// TestPacketConnCloseDoesNotHoldTheLockWhileClosingTheUnderlyingConn covers the third wrapper: the
// UDP path registers its own PacketConn and had the same shape.
func TestPacketConnCloseDoesNotHoldTheLockWhileClosingTheUnderlyingConn(t *testing.T) {
	group := NewGroup()

	underlyingClosed := false
	conn := group.NewPacketConn(&reentrantPacketConn{onClose: func() {
		group.Interrupt(true)
		underlyingClosed = true
	}}, true)

	requireCompletes(t, "PacketConn.Close over an underlying connection that re-enters the group", func() {
		_ = conn.Close()
	})

	require.True(t, underlyingClosed)
	require.Equal(t, 0, group.connections.Size())
}

// reentrantPacketConn is the packet-connection form of reentrantConn.
type reentrantPacketConn struct {
	net.PacketConn
	onClose func()
}

func (c *reentrantPacketConn) Close() error {
	c.onClose()
	return nil
}

func (c *reentrantPacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, io.EOF }

func (c *reentrantPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return 0, nil }

func (c *reentrantPacketConn) LocalAddr() net.Addr             { return M.Socksaddr{} }
func (c *reentrantPacketConn) SetDeadline(time.Time) error     { return nil }
func (c *reentrantPacketConn) SetReadDeadline(time.Time) error { return nil }

// TestNestedGroupsInOppositeOrdersDoNotDeadlock is the production shape of LX 084: two groups that
// hold each other's wrappers, interrupted at the same time in opposite orders.
//
// This is the case the deterministic tests above generalise; it is kept as a real two-goroutine
// test because the distinct-lock variant is what a reader will look for.
func TestNestedGroupsInOppositeOrdersDoNotDeadlock(t *testing.T) {
	inner := NewGroup()
	outer := NewGroup()

	// inner holds a wrapper belonging to outer: closing it takes outer's lock.
	inner.Add(outer.NewConn(&reentrantConn{onClose: func() {}}, true), true)
	// outer holds a wrapper belonging to inner: closing it takes inner's lock.
	outer.Add(inner.NewConn(&reentrantConn{onClose: func() {}}, true), true)

	var (
		start   = make(chan struct{})
		waiting sync.WaitGroup
	)
	waiting.Add(2)
	for _, group := range []*Group{inner, outer} {
		group := group
		go func() {
			defer waiting.Done()
			<-start
			group.Interrupt(true)
		}()
	}
	close(start)

	completed := make(chan struct{})
	go func() {
		waiting.Wait()
		close(completed)
	}()
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("two groups holding each other's wrappers deadlocked: each Interrupt held its own " +
			"lock while closing the other group's wrapper, and a later connection through either " +
			"group would block behind the same lock until the process restarted")
	}
}
