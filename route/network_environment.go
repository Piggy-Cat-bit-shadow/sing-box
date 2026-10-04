package route

import (
	"context"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
)

func (r *NetworkManager) NetworkEnvironment() uint64 {
	r.stateAccess.RLock()
	defer r.stateAccess.RUnlock()
	return r.networkEnvironment
}

// postUpdateNetworkEnvironment recomputes the environment and establishes the boundary NOW.
//
// # Why there is no debounce
//
// It used to defer both by a second, coalescing bursts of notifications. That made the boundary a
// latency detail, and it is not one: the boundary is what re-pins each transport's cache namespace to
// the network it is actually on. During the delay the pin still named the old network while the
// transports were already free to re-dial on the new one - they acquire from a pool and dial through
// the dialer when a connection is invalidated - so a new network's answer could be filed under the
// old network's namespace with no timer ever becoming involved.
//
// # What absorbs the bursts instead
//
// The recompute is what decides whether anything happened: it compares the fingerprint and does
// nothing when it is unchanged. A burst of repeated notifications therefore costs a hash comparison
// and no teardown, which is the same protection the timer provided, without a window in which the
// boundary is owed but not yet taken.
//
// # Locking
//
// None of this function's callers holds resetRunAccess - the network monitor callback, the interface
// list refresh, and the Wi-Fi state change all arrive without it - so the exported, self-locking
// reset is the correct form here. updateInterface, which DOES hold the lock, does not come through
// this function: it recomputes and establishes the boundary itself, inline, under the lock it
// already has.
func (r *NetworkManager) postUpdateNetworkEnvironment() {
	r.updateNetworkEnvironment()
}

// updateNetworkEnvironment refreshes the fingerprint and, on a real transition, establishes the
// transport/generation boundary.
//
// It is the ENTRY POINT FOR CALLERS THAT DO NOT HOLD resetRunAccess - the network monitor callback,
// the interface list refresh, and the Wi-Fi state change all arrive without it. updateInterface, which
// holds resetRunAccess for a wider critical section, does not come through here: it recomputes and
// establishes its boundary inline, so that one interface update produces one reset. Taking the
// exported form from a lock holder would self-deadlock, because sync.Mutex is not reentrant.
func (r *NetworkManager) updateNetworkEnvironment() {
	changed, token := r.recomputeNetworkEnvironment()
	if !changed {
		return
	}
	r.boundEnvironmentTransitionExported(token)
}

// recomputeNetworkEnvironment refreshes the fingerprint and reports whether it changed.
//
// It holds environmentUpdateAccess for the whole computation, which is what serialises concurrent
// updates and stops a pending timer from firing into a half-updated state. It deliberately does NOT
// take the reset: the reset can block on resetRunAccess, and Close takes that lock while waiting for
// startedCancel - so holding environmentUpdateAccess across it would stop every later
// postUpdateNetworkEnvironment behind a Close that is itself waiting. That is a three-way cycle, and
// it hung the jiejie reference suite for the full 40-minute test timeout.
func (r *NetworkManager) recomputeNetworkEnvironment() (bool, transitionToken) {
	r.environmentUpdateAccess.Lock()
	defer r.environmentUpdateAccess.Unlock()
	var defaultInterface *adapter.NetworkInterface
	if r.interfaceMonitor != nil {
		defaultInterface = r.DefaultNetworkInterface()
	}
	var (
		gatewayStrings  []string
		hardwareStrings []string
		wifiSSID        string
	)
	if defaultInterface != nil {
		gateways := defaultInterface.Gateways
		if len(gateways) == 0 {
			gateways = systemGateways(defaultInterface.Interface.Index)
		}
		gateways = common.Uniq(gateways)
		slices.SortFunc(gateways, netip.Addr.Compare)
		gatewayStrings = common.Map(gateways, netip.Addr.String)
		wifiState := r.WIFIState()
		if wifiState.SSID != "" {
			wifiSSID = wifiState.SSID
		} else if len(gateways) > 0 {
			hardwareAddresses := systemNeighborHardwareAddresses(defaultInterface.Interface.Index, gateways)
			for _, gateway := range gateways {
				hardwareAddress := hardwareAddresses[gateway]
				if len(hardwareAddress) > 0 {
					hardwareStrings = append(hardwareStrings, hardwareAddress.String())
				}
			}
		}
	}
	var options []string
	if len(gatewayStrings) > 0 {
		options = append(options, "gateway "+formatEnvironmentValues(gatewayStrings))
	}
	if wifiSSID != "" {
		options = append(options, "ssid "+wifiSSID)
	}
	if len(hardwareStrings) > 0 {
		options = append(options, "gateway_mac "+formatEnvironmentValues(hardwareStrings))
	}
	var environmentHash uint64
	if len(options) > 0 {
		digest := fnv.New64a()
		for _, option := range options {
			digest.Write([]byte(option))
			digest.Write([]byte{0})
		}
		environmentHash = digest.Sum64()
	}
	r.stateAccess.Lock()
	changed := environmentHash != r.networkEnvironment
	if !changed {
		r.stateAccess.Unlock()
		return false, noTransition
	}
	r.networkEnvironment = environmentHash
	// The test hook runs HERE: after the fingerprint is written, before the transition is claimed,
	// while stateAccess is still held. That is precisely the instant the ordering is about, so a test
	// parked here observes the window if the claim is not part of it.
	if r.environmentPublished != nil {
		r.environmentPublished()
	}
	// Claim the transition BEFORE releasing stateAccess.
	//
	// Readers of NetworkEnvironment take stateAccess.RLock, so holding it here is what makes "the
	// new fingerprint is visible" and "the network is no longer settled" a single observation. Doing
	// the claim after the unlock - which is what this replaced - left a window in which a reader saw
	// the new environment while every ownership token still described the old one.
	token := r.beginTransition()
	r.stateAccess.Unlock()
	// A zero fingerprint is a real environment, not a missing reading.
	//
	// The hash is built from the default interface's gateways, the Wi-Fi SSID, or the gateway
	// hardware addresses, so it is zero exactly when the device has no default interface, no gateways
	// and no SSID - a disconnected network, or one whose link is down. The value is PUBLISHED as the
	// environment either way, which is what makes skipping the boundary here an inconsistency: the
	// manager would report "not the previous network" while the transports stayed pinned to it, so a
	// transport re-dialling as the device comes back up on the next network would file that network's
	// answers under the old namespace. Returning early for an empty fingerprint meant exactly that
	// transition - the one where the old network is definitively gone - was the only one without a
	// boundary.
	if len(options) > 0 {
		r.logger.Info("updated network environment: ", strings.Join(options, ", "))
	} else {
		r.logger.Info("updated network environment: no default interface, gateways or SSID")
	}

	// The transition was claimed above, while stateAccess was still held, so the publish and the
	// claim are one observation. The caller decides whether a reset body runs; what is settled here
	// is only that the network is no longer stable.
	return true, token
}

// boundEnvironmentTransition establishes the transport/generation boundary for a confirmed
// environment change.
//
// # Why the environment alone is not enough
//
// The DNS cache is namespaced by a per-transport environment pin, and the pin was only moved by
// Router.ResetNetwork. But a transport does not hold one socket for its lifetime: TCP, TLS and HTTPS
// acquire from a pool and re-dial through their dialer when a connection is invalidated or missing,
// and a dial resolves the device's routes at that moment. So after an SSID change on one interface -
// which reaches here through onWIFIStateChanged or UpdateInterfaces, and historically reset NOTHING -
// the old pooled connection can die and the next query can travel over the new network while the pin
// still says the old one. The answer is then filed under a network that did not serve it, and a
// query issued on that network can be handed it.
//
// Rebinding the pins without resetting the transports would be worse than the bug: a live connection
// on the OLD network would start filing its answers under the NEW environment. The transport's
// connections have to be torn down at the same boundary, so the pin and the socket move together.
// That is what ResetNetwork does, which is why this calls into the reset rather than poking the
// environment map.
//
// ClearCache is deliberately NOT called. Entries belonging to the old environment are correct for
// that environment and are kept; they simply stop being reachable from the new one.
//
// # Locking, and why this is a separate function
//
// The caller has already released environmentUpdateAccess. It MUST be released before this runs:
// this takes resetRunAccess, and Close holds startedCancel while waiting for resetRunAccess, so a
// holder of environmentUpdateAccess that waited here would block every later
// postUpdateNetworkEnvironment behind a Close that is itself waiting to proceed. That cycle hung the
// jiejie reference suite for its full test timeout.
//
// This takes the exported, self-locking form because the debounced timer holds no reset lock.
// updateInterface, the one caller that already holds resetRunAccess, does not come through here - it
// calls resetNetworkLocked directly for the same boundary. Reaching for the exported form from a lock
// holder would self-deadlock, because sync.Mutex is not reentrant.
//
// # Initialisation
//
// Gated on startedCtx, not on the old value: NetworkEnvironment is a hash for which 0 is a real,
// representable fingerprint, so "old == 0" cannot distinguish a first observation from a genuine
// transition. startedCtx is nil until Start, which is the lifecycle fact that actually
// distinguishes them.
// THE LINEARIZATION POINT of an environment transition is r.beginTransition() below: the instant the
// epoch advances. Everything before it belongs to the previous network; everything after it - the
// reset body, the transport re-pinning, the re-dialled connections - belongs to the new one. The
// fingerprint is published immediately before it, under the same call, so no reader can observe the
// new environment with the old ownership.
//
// The epoch is claimed BEFORE resetRunAccess is taken. That ordering is the whole point of this
// function's shape: waiting for the lock is exactly the interval in which the transition is
// half-published, and claiming afterwards would leave that interval observable. Claiming first makes
// the wait harmless - a long wait only delays the reset body, and by then the epoch has already told
// every other subsystem to treat the previous network's operations as stale.
func (r *NetworkManager) boundEnvironmentTransitionExported(token transitionToken) {
	if !r.environmentTransitionApplies() {
		return
	}
	if r.logger != nil {
		r.logger.Info("network environment changed, resetting network transports")
	}
	// The epoch was claimed by recomputeNetworkEnvironment, in the same step that published the new
	// fingerprint. Here the body runs and the transition commits, so the network is unstable for
	// exactly the interval between publishing and finishing the reset - however long the lock is
	// contended, and one epoch per logical transition.
	// `token` is the one THIS transition's claim produced, carried from recomputeNetworkEnvironment.
	// Recovering it with Load() here would return whatever claimed last, letting a superseded
	// transition commit ownership belonging to its successor.
	defer r.commitTransition(token)
	if !r.transitionOwns(token) {
		return
	}
	r.resetRunAccess.Lock()
	defer r.resetRunAccess.Unlock()
	// Re-checked UNDER the reset lock: acquiring it is precisely the wait during which a newer claim
	// happens, so the check before the lock alone would let a superseded body through.
	if !r.transitionOwns(token) {
		return
	}
	r.resetNetworkLocked(r.startedCtx)
}

// boundEnvironmentTransitionLocked is the inner form for a caller holding resetRunAccess.
func (r *NetworkManager) boundEnvironmentTransitionLocked(ctx context.Context, token transitionToken) {
	if !r.environmentTransitionApplies() {
		return
	}
	if r.logger != nil {
		r.logger.Info("network environment changed, resetting network transports")
	}
	// The epoch was claimed by recomputeNetworkEnvironment, in the same step that published the new
	// fingerprint - NOT here. Claiming again would advance the epoch twice for one logical
	// transition, and a token recovered afterwards would be the wrong one.
	defer r.commitTransition(token)
	if !r.transitionOwns(token) {
		return
	}
	r.resetNetworkLocked(ctx)
}

// environmentTransitionApplies reports whether a confirmed environment change should be bounded now.
//
// Gated on startedCtx rather than on the old environment value: NetworkEnvironment is a hash for
// which 0 is a real, representable fingerprint, so "old == 0" cannot distinguish a first observation
// from a genuine transition. startedCtx is nil until Start and cancelled by Close, which is the
// lifecycle fact that actually distinguishes them - and the cancellation check also keeps a timer
// that fires during shutdown from starting a reset the manager is already tearing down.
func (r *NetworkManager) environmentTransitionApplies() bool {
	if r.startedCtx == nil {
		return false
	}
	if r.startedCtx.Err() != nil {
		return false
	}
	return true
}

func formatEnvironmentValues(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "[" + strings.Join(values, " ") + "]"
}
