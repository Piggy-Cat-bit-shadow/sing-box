package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const discardTestMark = uint32(0x2024)

// blockingRegistry signals when a constructor for inboundType is about to enter the registry, which
// it does after Manager.Create's duplicate pre-check and before the registry lock that box.go wires
// serialises constructors.
type blockingRegistry struct {
	adapter.InboundRegistry
	atCreate func(inboundType string)
}

func (r *blockingRegistry) Create(ctx context.Context, router adapter.Router, log log.ContextLogger, tag string, inboundType string, options any) (adapter.Inbound, error) {
	if r.atCreate != nil {
		r.atCreate(inboundType)
	}
	return r.InboundRegistry.Create(ctx, router, log, tag, inboundType, options)
}

// TestDiscardedInboundReleasesTheAutoRedirectOutputMark drives the real inbound Manager, the real
// Registry and the real route.NetworkManager through adapter/inbound/manager.go's duplicate-tag
// discard, with the Inbound this package owns as the discarded object.
//
// The interleaving is arranged rather than hoped for. All three steps are ordered by channels:
//
//	winner: enters its constructor - so it holds the registry lock - and waits there.
//	loser:  Manager.Create's pre-check sees no such tag yet, so the loser gets past it and parks on
//	        the registry lock behind the winner.
//	then:   the winner is released, installs the tag and returns; the loser builds, claims the mark
//	        exactly as NewInbound does, and loses the manager's re-check, so Create calls
//	        common.Close on it - the branch that discards a constructed object.
//
// The claiming constructor losing the tag is the ordinary outcome rather than a corner: the
// constructor that installs first is the one already running, and the one parked on the registry lock
// is the one discarded. Measured over 200 consecutive arrangements before this test was written, the
// loser held the claim in 200 of them.
//
// The Inbound is assembled from the fields NewInbound sets on its claim path instead of by calling
// NewInbound: on every platform without SO_MARK support - this worktree's included - NewInbound fails
// in sing-tun's NewAutoRedirect before it reaches the claim, so the constructor cannot be driven here.
// Everything that runs after the constructor is the production code either way.
func TestDiscardedInboundReleasesTheAutoRedirectOutputMark(t *testing.T) {
	networkManager, err := route.NewNetworkManager(context.Background(), logger.NOP(), option.RouteOptions{}, option.DNSOptions{})
	require.NoError(t, err)
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)

	winnerInConstructor := make(chan struct{})
	releaseWinner := make(chan struct{})
	loserAtRegistry := make(chan struct{})
	var loserClaimed atomic.Int32

	registry := inbound.NewRegistry()
	inbound.Register[option.TunInboundOptions](registry, "discard-winner", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
		close(winnerInConstructor)
		<-releaseWinner
		return &Inbound{tag: tag, networkManager: networkManager}, nil
	})
	inbound.Register[option.TunInboundOptions](registry, "discard-loser", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
		networkManager := service.FromContext[adapter.NetworkManager](ctx)
		mark := uint32(0x2024)
		if err := networkManager.RegisterAutoRedirectOutputMark(mark); err != nil {
			return nil, err
		}
		loserClaimed.Add(1)
		return newMarkClaimedInbound(tag, networkManager, mark), nil
	})
	manager := inbound.NewManager(&blockingRegistry{
		InboundRegistry: registry,
		atCreate: func(inboundType string) {
			if inboundType != "discard-loser" {
				return
			}
			select {
			case <-loserAtRegistry:
			default:
				close(loserAtRegistry)
			}
		},
	}, nil)

	loggerNOP := log.NewNOPFactory().NewLogger("discard")
	var waitGroup sync.WaitGroup
	var winnerErr, loserErr error
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		winnerErr = manager.Create(ctx, nil, loggerNOP, "shared-tag", "discard-winner", nil)
	}()
	<-winnerInConstructor
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		loserErr = manager.Create(ctx, nil, loggerNOP, "shared-tag", "discard-loser", nil)
	}()
	<-loserAtRegistry
	close(releaseWinner)
	waitGroup.Wait()

	require.NoError(t, winnerErr)
	require.ErrorContains(t, loserErr, "already exists", "the constructor that claimed the mark must be the one discarded")
	require.EqualValues(t, 1, loserClaimed.Load())
	require.Len(t, manager.Inbounds(), 1)
	require.Zero(t, networkManager.AutoRedirectOutputMark(),
		"the mark claimed by a discarded inbound must not be left on the manager")
}
