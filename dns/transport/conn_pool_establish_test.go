package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConnPoolOrderedSerialisesEstablishment is the DNS reconnect storm, in miniature.
//
// A network transition invalidates a transport's socket while queries are waiting on it. Every
// waiter then takes the same branch of acquireOrdered: no idle connection, so dial. Without a slot
// cap that is one TCP handshake and one TLS handshake per waiter, all at once, with all but one of
// the results closed unused.
//
// The cap is what stops it, so this asserts the property directly: while one establishment is in
// progress, no other has begun.
func TestConnPoolOrderedSerialisesEstablishment(t *testing.T) {
	var concurrent, total atomic.Int32
	started := make(chan struct{})
	unblock := make(chan struct{})

	pool := NewConnPool(ConnPoolOptions[*int]{
		Mode:        ConnPoolOrdered,
		MaxInflight: 1,
		IsAlive:     func(conn *int) bool { return conn != nil },
		Close:       func(conn *int, cause error) {},
	})
	defer pool.Close()

	dial := func(ctx context.Context) (*int, error) {
		inFlight := concurrent.Add(1)
		defer concurrent.Add(-1)
		if inFlight > 1 {
			t.Errorf("%d establishments ran at once; the slot cap did not hold", inFlight)
		}
		if total.Add(1) == 1 {
			close(started)
		}
		<-unblock
		return new(int), nil
	}

	const waiters = 8
	var group sync.WaitGroup
	for range waiters {
		group.Add(1)
		go func() {
			defer group.Done()
			conn, _, err := pool.Acquire(context.Background(), dial)
			if err != nil {
				return
			}
			// Released back for reuse, which is what lets the waiters behind find it instead of
			// dialling themselves.
			pool.Release(conn, true)
		}()
	}

	<-started
	// Give the other seven every chance to pile in. If the cap were absent they would all be
	// inside dial by now.
	time.Sleep(50 * time.Millisecond)
	if got := total.Load(); got != 1 {
		t.Fatalf("%d establishments started while one was in flight, want 1", got)
	}

	close(unblock)
	group.Wait()
}

// TestConnPoolWithoutACapStorms is the negative control: it shows the cap is load-bearing rather
// than incidental, by demonstrating the same fixture storms when the option is absent.
//
// This is the behaviour the serial DNS pool shipped with, because MaxInflight is only honoured in
// ConnPoolOrdered mode and the serial pool never set it - so the semaphore the pool is capable of
// creating was never created, and the cap did nothing.
func TestConnPoolWithoutACapStorms(t *testing.T) {
	var concurrent, peak atomic.Int32
	started := make(chan struct{})
	unblock := make(chan struct{})

	pool := NewConnPool(ConnPoolOptions[*int]{
		// No MaxInflight: the pool the serial DNS path used to build.
		Mode:    ConnPoolOrdered,
		IsAlive: func(conn *int) bool { return conn != nil },
		Close:   func(conn *int, cause error) {},
	})
	defer pool.Close()

	dial := func(ctx context.Context) (*int, error) {
		inFlight := concurrent.Add(1)
		defer concurrent.Add(-1)
		for {
			seen := peak.Load()
			if inFlight <= seen || peak.CompareAndSwap(seen, inFlight) {
				break
			}
		}
		if inFlight == 2 {
			select {
			case <-started:
			default:
				close(started)
			}
		}
		<-unblock
		return new(int), nil
	}

	const waiters = 8
	var group sync.WaitGroup
	for range waiters {
		group.Add(1)
		go func() {
			defer group.Done()
			conn, _, err := pool.Acquire(context.Background(), dial)
			if err != nil {
				return
			}
			pool.Release(conn, true)
		}()
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("without a cap the establishment is not concurrent, so the control proves nothing")
	}
	close(unblock)
	group.Wait()

	if got := peak.Load(); got < 2 {
		t.Fatalf("peak concurrency was %d; the control did not reproduce the storm", got)
	}
}
