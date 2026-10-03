package dialer

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for a DNSDualStackRouter that fails without publishing anything.
//
// # The defect these pin
//
// The streaming path waited for the first family result, watching only that signal and the parent
// context. A DNSDualStackRouter is an OPTIONAL interface, and a third-party implementation is
// free to return an error without ever calling publish - which is a perfectly ordinary way to
// report "this lookup failed". The consumer would then block until the caller's whole context
// expired, turning an immediate DNS failure into a connect timeout.

// silentErrorRouter fails immediately and never publishes.
type silentErrorRouter struct {
	adapter.DNSRouter
	err error
}

func (r *silentErrorRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	return r.err
}

func (r *silentErrorRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, r.err
}

// TestStreamingRouterErrorWithoutPublishReturnsPromptly is §8.
func TestStreamingRouterErrorWithoutPublishReturnsPromptly(t *testing.T) {
	routerErr := errors.New("boom")
	inner := &literalDialer{start: time.Now()}

	dialer := &resolveDialer{
		router:        &silentErrorRouter{err: routerErr},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	// The caller's context is generous: the point is that the failure must not wait for it.
	ctx, cancel := context.WithTimeout(recoveryContext(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	elapsed := time.Since(start)

	require.Error(t, err, "a resolver that failed without publishing must fail the dial")
	require.Contains(t, err.Error(), "boom",
		"the resolver's own error must be surfaced, not replaced by a generic message")
	require.Less(t, elapsed, 3*time.Second,
		"the dial waited %v for a resolver that had already returned an error; a router that "+
			"fails without publishing must not block until the caller's context expires", elapsed)
}

// TestStreamingRouterPartialThenErrorStillSucceeds is the companion case.
//
// A family that succeeded must still produce a connection if the lookup later fails. The late
// error is reported through the same channel the failure path reads, and must not be allowed to
// turn an established connection into a failed one.
func TestStreamingRouterPartialThenErrorStillSucceeds(t *testing.T) {
	healthy := netip.MustParseAddr("192.0.2.1")
	routerErr := errors.New("late failure")

	inner := newOwningDialer()
	inner.setOutcome(healthy.String(), owningOutcome{success: true})

	dialer := &resolveDialer{
		router:        &partialErrorRouter{address: healthy, err: routerErr},
		dialer:        inner,
		parallel:      true,
		fallbackDelay: 10 * time.Millisecond,
		queryOptions:  adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4},
	}

	ctx, cancel := context.WithTimeout(recoveryContext(), 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	require.NoError(t, err,
		"a family that answered must still connect; a later lookup error must not fail it")
	require.NotNil(t, conn)
}

// partialErrorRouter publishes one family and then returns an error.
type partialErrorRouter struct {
	adapter.DNSRouter
	address netip.Addr
	err     error
}

func (r *partialErrorRouter) LookupFamilies(ctx context.Context, domain string, options adapter.DNSQueryOptions, publish func(adapter.DNSFamilyResult)) error {
	publish(adapter.DNSFamilyResult{
		IPv6:      false,
		Addresses: []netip.Addr{r.address},
	})
	return r.err
}

func (r *partialErrorRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return []netip.Addr{r.address}, r.err
}
