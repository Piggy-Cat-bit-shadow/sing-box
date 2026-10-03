package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

func TestTCPTransportRetriesReadErrorOnReusedConn(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		firstConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		firstRequest, readErr := ReadMessage(firstConn)
		if readErr != nil {
			firstConn.Close()
			serverDone <- readErr
			return
		}
		firstResponse := new(mDNS.Msg)
		firstResponse.SetReply(firstRequest)
		writeErr := WriteMessage(firstConn, firstRequest.Id, firstResponse)
		if writeErr != nil {
			firstConn.Close()
			serverDone <- writeErr
			return
		}
		_, readErr = ReadMessage(firstConn)
		firstConn.Close()
		if readErr != nil {
			serverDone <- readErr
			return
		}
		secondConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer secondConn.Close()
		secondRequest, readErr := ReadMessage(secondConn)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		secondResponse := new(mDNS.Msg)
		secondResponse.SetReply(secondRequest)
		serverDone <- WriteMessage(secondConn, secondRequest.Id, secondResponse)
	}()

	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
		write: func(conn net.Conn, message *mDNS.Msg, queryId uint16) error {
			return WriteMessage(conn, queryId, message)
		},
		readNext: func(conn net.Conn) (*mDNS.Msg, error) {
			return ReadMessage(conn)
		},
		retryReadError: true,
	})
	defer multiplexer.Close()

	firstMessage := new(mDNS.Msg)
	firstMessage.SetQuestion("first.example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = multiplexer.Exchange(ctx, firstMessage)
	cancel()
	if err != nil {
		t.Fatal("first query failed: ", err)
	}

	secondMessage := new(mDNS.Msg)
	secondMessage.SetQuestion("second.example.com.", mDNS.TypeAAAA)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_, err = multiplexer.Exchange(ctx, secondMessage)
	cancel()
	if err != nil {
		t.Fatal("second query failed: ", err)
	}
	select {
	case err = <-serverDone:
		if err != nil {
			t.Fatal("DNS server failed: ", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS server did not finish")
	}
}

func newTestTCPTransport(t *testing.T, listener net.Listener) *TCPTransport {
	transportDialer, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return NewTCPRaw(boxDNS.NewTransportAdapter(C.DNSTypeTCP, "test", nil), transportDialer, M.SocksaddrFromNet(listener.Addr()))
}

func testExchange(transport *TCPTransport, questionName string) error {
	message := new(mDNS.Msg)
	message.SetQuestion(questionName, mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := transport.Exchange(ctx, message)
	return err
}

func TestTCPTransportSingleQueryServer(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				request, readErr := ReadMessage(conn)
				if readErr != nil {
					return
				}
				response := new(mDNS.Msg)
				response.SetReply(request)
				WriteMessage(conn, request.Id, response)
			}()
		}
	}()

	transport := newTestTCPTransport(t, listener)
	defer transport.Close()

	const queryCount = 8
	results := make(chan error, queryCount)
	for range queryCount {
		go func() {
			results <- testExchange(transport, "example.com.")
		}()
	}
	for range queryCount {
		err = <-results
		if err != nil {
			t.Fatal("query failed: ", err)
		}
	}
	// These queries run CONCURRENTLY, so one connection each is the expected outcome: the serial
	// pool provides reuse across sequential queries, not a single global connection. What must
	// not happen is more connections than queries - that would mean a query was dialled twice.
	time.Sleep(200 * time.Millisecond)
	if count := accepted.Load(); count > queryCount {
		t.Fatalf("the transport opened %d connections for %d concurrent queries; reuse must "+
			"never produce more connections than queries", count, queryCount)
	}
}

// TestTCPTransportSequentialQueriesReuseOneConnection is the reuse property the previous
// assertion was reaching for: SEQUENTIAL queries must share a connection.
func TestTCPTransportSequentialQueriesReuseOneConnection(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				for {
					request, readErr := ReadMessage(conn)
					if readErr != nil {
						return
					}
					response := new(mDNS.Msg)
					response.SetReply(request)
					if WriteMessage(conn, request.Id, response) != nil {
						return
					}
				}
			}()
		}
	}()

	transport := newTestTCPTransport(t, listener)
	defer transport.Close()

	const queryCount = 8
	for index := 0; index < queryCount; index++ {
		if err := testExchange(transport, "example.com."); err != nil {
			t.Fatal("query: ", err)
		}
	}

	if count := accepted.Load(); count != 1 {
		t.Fatalf("sequential queries opened %d connections for %d queries; the serial pool "+
			"must hold one connection across them", count, queryCount)
	}
}

func TestMultiplexerTimeoutInvalidatesConn(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- conn
		}
	}()
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
		write: func(conn net.Conn, message *mDNS.Msg, queryId uint16) error {
			return WriteMessage(conn, queryId, message)
		},
		readNext: func(conn net.Conn) (*mDNS.Msg, error) {
			return ReadMessage(conn)
		},
	})
	defer multiplexer.Close()

	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err = multiplexer.Exchange(ctx, message)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected deadline exceeded, got ", err)
	}
	if elapsed > 2*time.Second {
		t.Fatal("timeout not enforced, took ", elapsed)
	}

	firstConn := <-accepted
	firstConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.Copy(io.Discard, firstConn)
	if err != nil {
		t.Fatal("expected the client side to close the connection, got ", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	multiplexer.Exchange(ctx2, message)
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("expected a fresh connection for the second query")
	}
}

// TestMultiplexerSlowQueryDoesNotPoisonThePool is the serial-path equivalent of the old
// "slow query keeps the active connection" test.
//
// Under the shared pool that test asserted a timed-out query did not replace the pooled
// connection. On the serial path the property that matters is different and still important: a
// query that times out must leave the pool in a state the next query can use, rather than
// stranding a connection that is tracked but unusable.
func TestMultiplexerSlowQueryDoesNotPoisonThePool(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					request, readErr := ReadMessage(conn)
					if readErr != nil {
						return
					}
					// Delay the answer so the caller's deadline expires first.
					time.Sleep(2 * time.Second)
					response := new(mDNS.Msg)
					response.SetReply(request)
					if WriteMessage(conn, request.Id, response) != nil {
						return
					}
				}
			}()
		}
	}()

	transport := newTestTCPTransport(t, listener)
	defer transport.Close()

	// This query is expected to time out.
	slowCtx, slowCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer slowCancel()
	slowMessage := new(mDNS.Msg)
	slowMessage.SetQuestion("slow.example.", mDNS.TypeA)
	if _, err = transport.Exchange(slowCtx, slowMessage); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected the slow query to time out, got ", err)
	}

	// The pool must still be usable, and must not be tracking a connection it cannot serve.
	pool := transport.multiplexer.serial
	pool.access.Lock()
	tracked := len(pool.state.all)
	idle := pool.state.idle.Len()
	pool.access.Unlock()
	if tracked != idle {
		t.Fatalf("after a timed-out query the pool tracks %d connections but holds %d idle; "+
			"a checked-out connection was stranded", tracked, idle)
	}
}
