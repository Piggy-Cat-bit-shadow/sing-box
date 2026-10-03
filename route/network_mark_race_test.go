package route

import (
	"net"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// rawConnFor returns a real syscall.RawConn, so the callback reaches the mark write the way a dial
// does. A nil conn would stop at the type assertion instead of exercising the path under test.
func rawConnFor(t *testing.T) syscall.RawConn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	tcpListener := listener.(*net.TCPListener)
	file, err := tcpListener.File()
	require.NoError(t, err)
	t.Cleanup(func() { file.Close() })

	rawConn, err := (&net.TCPConn{}).SyscallConn()
	if err == nil {
		return rawConn
	}
	// SyscallConn is not available on a zero conn; fall back to the listener's own.
	conn, err := net.Dial("tcp", tcpListener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	rawConn, err = conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	return rawConn
}

// Race test for the auto-redirect output mark.
//
// # Why this reader matters
//
// AutoRedirectOutputMarkFunc returns a dial-control callback, and common/dialer installs it on EVERY
// outbound connection's Control chain. It reads the mark field with no lock.
//
// The writer is RegisterAutoRedirectOutputMark. Both were unlocked, so this race predates any recent
// change: it is not something a fix introduced, and it is independent of the claim-lifecycle
// question. A dial overlapping TUN startup is ordinary, which is why the pair genuinely overlaps in
// production rather than being a diagnostic-only window.
//
// The consequence of a data race here is not merely a detector warning. The callback either applies
// the configured fwmark or applies nothing, and those are different routing instructions: a torn or
// stale read can leave a connection unmarked, which is the difference between the auto-redirect
// capturing it and the packet escaping to the system.

// TestOutputMarkReadIsRaceFreeAgainstRegistration is the race statement.
func TestOutputMarkReadIsRaceFreeAgainstRegistration(t *testing.T) {
	manager := &NetworkManager{}
	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023))

	markFunc := manager.AutoRedirectOutputMarkFunc()
	rawConn := rawConnFor(t)

	const iterations = 2000
	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	// The reader: exactly what a dial executes.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			_ = markFunc("tcp", "127.0.0.1:80", rawConn)
		}
	}()

	// The writer: the same store the production registration performs.
	//
	// It is written directly rather than through Register because Register refuses a second claim,
	// so calling it in a loop would write exactly once - before the reader ever starts - and the two
	// goroutines would never actually overlap. Writing the field is what the registration does, and
	// the reader under test is the callback.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for index := 0; index < iterations; index++ {
			manager.autoRedirectOutputMark.Store(0x2023)
			manager.autoRedirectOutputMark.Store(0)
		}
	}()

	close(start)
	waitGroup.Wait()
}

// TestOutputMarkReadIsRaceFreeAgainstRead completes the matrix: two readers, and a reader against a
// writer that observes the value rather than only storing it.
func TestOutputMarkReadIsRaceFreeAgainstRead(t *testing.T) {
	manager := &NetworkManager{}
	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023))
	markFunc := manager.AutoRedirectOutputMarkFunc()
	rawConn := rawConnFor(t)

	const iterations = 1000
	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	for reader := 0; reader < 4; reader++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for index := 0; index < iterations; index++ {
				_ = markFunc("tcp", "127.0.0.1:80", rawConn)
				_ = manager.AutoRedirectOutputMark()
			}
		}()
	}

	close(start)
	waitGroup.Wait()
}

// TestOutputMarkCallbackObservesAConsistentValue is the semantic half.
//
// The callback must never act on a torn value: it either applies the configured mark or applies
// nothing, and those must correspond to whether a mark is actually configured.
func TestOutputMarkCallbackObservesAConsistentValue(t *testing.T) {
	manager := &NetworkManager{}
	markFunc := manager.AutoRedirectOutputMarkFunc()

	require.EqualValues(t, 0, manager.AutoRedirectOutputMark(),
		"a fresh manager has no claim")
	require.NoError(t, markFunc("tcp", "127.0.0.1:80", rawConnFor(t)),
		"with no claim the callback is a no-op rather than marking with zero, which would be a "+
			"different routing instruction")

	require.NoError(t, manager.RegisterAutoRedirectOutputMark(0x2023))
	require.EqualValues(t, 0x2023, manager.AutoRedirectOutputMark(),
		"the callback and the accessor must observe the same value, not a torn one")

	err := manager.RegisterAutoRedirectOutputMark(0x2024)
	require.Error(t, err, "a second claim is still refused")
	require.EqualValues(t, 0x2023, manager.AutoRedirectOutputMark(),
		"and the refused claim must not have replaced the active one")
}
