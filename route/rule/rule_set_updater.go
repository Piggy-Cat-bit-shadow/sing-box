package rule

import (
	"context"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing/service"
)

type RuleSetUpdater struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ruleSets []*RemoteRuleSet
	// powerGovernor is the fork's sleep authority, or nil when none was installed. RemoteRuleSet has
	// carried an unused pauseManager field since before this - the intent to defer these refreshes was
	// there and the wiring never was.
	powerGovernor *power.Governor
}

func NewRuleSetUpdater(ctx context.Context, ruleSets []adapter.RuleSet) *RuleSetUpdater {
	var remoteRuleSets []*RemoteRuleSet
	for _, ruleSet := range ruleSets {
		remoteRuleSet, isRemote := ruleSet.(*RemoteRuleSet)
		if isRemote {
			remoteRuleSets = append(remoteRuleSets, remoteRuleSet)
		}
	}
	if len(remoteRuleSets) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &RuleSetUpdater{
		ctx:           ctx,
		cancel:        cancel,
		ruleSets:      remoteRuleSets,
		powerGovernor: service.FromContext[*power.Governor](ctx),
	}
}

func (u *RuleSetUpdater) Start() {
	go u.loopUpdate()
}

func (u *RuleSetUpdater) Close() error {
	u.cancel()
	return nil
}

func (u *RuleSetUpdater) loopUpdate() {
	nextUpdates := make([]time.Time, len(u.ruleSets))
	for i, ruleSet := range u.ruleSets {
		nextUpdates[i] = ruleSet.lastUpdated.Add(ruleSet.updateInterval)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	// The first pass loads every rule set, and is deliberately NOT deferred: routing needs the rules
	// before the tunnel is usable, and the device is awake at that point by definition. Only the
	// periodic refreshes that follow are deferrable.
	initial := true
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-timer.C:
		}
		if !initial && u.powerGovernor != nil {
			// A refresh that cannot be deferred would wake a sleeping device to fetch rules it will not
			// use until it wakes anyway. Waiting costs nothing: the rules are stale by at most one
			// pause, and the fetch happens the moment there is somebody to use it.
			if !u.powerGovernor.WaitProviderRefresh(u.ctx) {
				return
			}
		}
		initial = false
		now := time.Now()
		var updated bool
		for i, ruleSet := range u.ruleSets {
			if now.Before(nextUpdates[i]) {
				continue
			}
			ruleSet.updateOnce()
			nextUpdates[i] = now.Add(ruleSet.updateInterval)
			updated = true
		}
		if updated {
			runtime.GC()
		}
		timer.Reset(waitUntilNext(nextUpdates))
	}
}

func waitUntilNext(nextUpdates []time.Time) time.Duration {
	next := nextUpdates[0]
	for _, nextUpdate := range nextUpdates[1:] {
		if nextUpdate.Before(next) {
			next = nextUpdate
		}
	}
	wait := time.Until(next)
	if wait < 0 {
		return 0
	}
	return wait
}
