package adapter

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/stretchr/testify/require"
)

// Tests for the error semantics of Scope.Close.
//
// # Why the close path needs its own rule
//
// A Scope is closed on an orderly shutdown AND while a network transition is already tearing things
// down. In both cases a resource that is already gone reports a CLOSED error and a resource whose
// context was cancelled reports a CANCELLED one. Those are the expected outcome of closing, not
// failures of it: aggregating them into the Close result makes a clean shutdown look like a fault,
// which is the same rule this project already applies elsewhere - a local cancellation is not a
// remote failure.
//
// The filter is deliberately narrow. Only Scope.Close, which is a declared close context, applies
// it; the same errors on a business I/O path are not harmless and are not touched here. And because
// a cleanup may return an AGGREGATE of several errors, the result is expanded first and each error
// is judged on its own: filtering an aggregate as a unit would discard a real failure merely because
// a cancelled error travelled with it.

// recordingLogger captures what the Scope reports. Only the methods the close path uses are
// overridden; the embedded interface is nil and is never reached.
type recordingLogger struct {
	log.ContextLogger
	access sync.Mutex
	lines  []string
}

func (l *recordingLogger) record(args ...any) {
	l.access.Lock()
	l.lines = append(l.lines, F.ToString(args...))
	l.access.Unlock()
}

func (l *recordingLogger) Trace(args ...any) { l.record(args...) }
func (l *recordingLogger) Debug(args ...any) { l.record(args...) }

func (l *recordingLogger) captured() string {
	l.access.Lock()
	defer l.access.Unlock()
	return strings.Join(l.lines, "\n")
}

func newSemanticScope(logger log.ContextLogger) *Scope {
	return NewScope(context.Background(), logger)
}

// TestScopeCloseDoesNotReportAlreadyClosedResourcesAsFailures is the spurious-failure case.
//
// Every one of these is what a resource says when the thing closing it has already been torn down by
// a network transition or by an earlier stage of the same shutdown.
func TestScopeCloseDoesNotReportAlreadyClosedResourcesAsFailures(t *testing.T) {
	alreadyGone := []error{
		net.ErrClosed,
		os.ErrClosed,
		io.ErrClosedPipe,
		io.EOF,
		syscall.EPIPE,
		syscall.ECONNRESET,
		E.Cause(net.ErrClosed, "close listener"),
	}
	for _, closedErr := range alreadyGone {
		scope := newSemanticScope(log.NewNOPFactory().Logger())
		scope.Add(func() error { return closedErr })
		require.NoError(t, scope.Close(),
			"a resource that is already closed must not be reported as a cleanup failure: %v", closedErr)
	}
}

// TestScopeCloseDoesNotReportCancellationAsFailure is the same rule for the cancellation axis.
func TestScopeCloseDoesNotReportCancellationAsFailure(t *testing.T) {
	cancelled := []error{
		context.Canceled,
		context.DeadlineExceeded,
		E.Cause(context.Canceled, "wait for in-flight work"),
	}
	for _, cancelErr := range cancelled {
		scope := newSemanticScope(log.NewNOPFactory().Logger())
		scope.Add(func() error { return cancelErr })
		require.NoError(t, scope.Close(),
			"a cancellation observed while closing is not a failure of the close: %v", cancelErr)
	}
}

// TestScopeCloseStillReportsRealFailures is the boundary that keeps the filter honest.
//
// A teardown that could not unmount a route, flush state or persist a cache is a real failure, and
// it has to reach the caller.
func TestScopeCloseStillReportsRealFailures(t *testing.T) {
	realFailures := []error{
		errors.New("flush cache: no space left on device"),
		errors.New("remove route: operation not permitted"),
		errors.New("persist rule-set: disk quota exceeded"),
		E.Cause(errors.New("permission denied"), "tear down tun routes"),
	}
	for _, realErr := range realFailures {
		scope := newSemanticScope(log.NewNOPFactory().Logger())
		scope.Add(func() error { return realErr })
		require.ErrorIs(t, scope.Close(), realErr,
			"a real teardown failure must still be reported: %v", realErr)
	}
}

// TestScopeCloseKeepsARealFailureInsideAnAggregate is the reason the result is expanded before it is
// filtered.
//
// A single cleanup can return several errors at once. If the aggregate were judged as a unit, one
// cancelled error travelling with a real failure would hide the failure completely.
func TestScopeCloseKeepsARealFailureInsideAnAggregate(t *testing.T) {
	realErr := errors.New("persist rule-set: disk quota exceeded")
	scope := newSemanticScope(log.NewNOPFactory().Logger())
	scope.Add(func() error {
		return E.Errors(net.ErrClosed, realErr, context.Canceled)
	})

	closeErr := scope.Close()
	require.ErrorIs(t, closeErr, realErr,
		"a real failure must survive inside an aggregate that also carries closed and cancelled "+
			"errors; filtering the aggregate as a unit would discard it")
	require.NotErrorIs(t, closeErr, net.ErrClosed,
		"the already-closed error must be filtered out of the result")
	require.NotErrorIs(t, closeErr, context.Canceled,
		"the cancellation must be filtered out of the result")
}

// TestScopeCloseKeepsARealFailureAlongsideCancellation covers the same rule across two cleanups,
// which is the ordinary shape: one component is already gone, another genuinely failed.
func TestScopeCloseKeepsARealFailureAlongsideCancellation(t *testing.T) {
	realErr := errors.New("remove route: operation not permitted")
	scope := newSemanticScope(log.NewNOPFactory().Logger())
	scope.Add(func() error { return realErr })
	scope.Add(func() error { return net.ErrClosed })
	scope.Add(func() error { return context.Canceled })

	closeErr := scope.Close()
	require.ErrorIs(t, closeErr, realErr)
	require.NotErrorIs(t, closeErr, net.ErrClosed)
	require.NotErrorIs(t, closeErr, context.Canceled)
}

// TestScopeCloseKeepsTheFilteredErrorsAsEvidence is §7's "the error chain must not lose evidence".
//
// The closed and cancelled errors are removed from the RESULT, because the caller cannot act on
// them. They are the record of what the close actually observed, so they are reported instead of
// being dropped - a filter that silently discards is how a double release or an unexpected
// cancellation becomes invisible.
func TestScopeCloseKeepsTheFilteredErrorsAsEvidence(t *testing.T) {
	logger := &recordingLogger{}
	scope := newSemanticScope(logger)
	scope.Add(func() error { return E.Cause(net.ErrClosed, "close listener") })

	require.NoError(t, scope.Close())

	captured := logger.captured()
	require.Contains(t, captured, "close listener",
		"the filtered error must still be reported: removing it from the result is a decision about "+
			"what the caller can act on, not a reason to lose the observation")
	require.Contains(t, captured, net.ErrClosed.Error())
}
