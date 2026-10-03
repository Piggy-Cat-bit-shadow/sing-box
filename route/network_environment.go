package route

import (
	"context"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
)

func (r *NetworkManager) NetworkEnvironment() uint64 {
	r.stateAccess.RLock()
	defer r.stateAccess.RUnlock()
	return r.networkEnvironment
}

func (r *NetworkManager) postUpdateNetworkEnvironment() {
	r.environmentUpdateAccess.Lock()
	defer r.environmentUpdateAccess.Unlock()
	if r.environmentUpdateTimer == nil {
		r.environmentUpdateTimer = time.AfterFunc(time.Second, r.updateNetworkEnvironment)
	} else {
		r.environmentUpdateTimer.Reset(time.Second)
	}
}

// updateNetworkEnvironment refreshes the fingerprint and, on a real transition, establishes the
// transport/generation boundary.
//
// It is the ENTRY POINT FOR CALLERS THAT DO NOT HOLD resetRunAccess - the debounced timer, which
// runs from an AfterFunc goroutine with no reset lock at all. updateInterface, which holds
// resetRunAccess for a wider critical section, calls updateNetworkEnvironmentLocked instead: taking
// the exported form here would self-deadlock, because sync.Mutex is not reentrant.
func (r *NetworkManager) updateNetworkEnvironment() {
	if !r.recomputeNetworkEnvironment() {
		return
	}
	r.boundEnvironmentTransitionExported()
}

// updateNetworkEnvironmentLocked is the same operation for a caller that already holds
// resetRunAccess. It must use the inner reset, for the reason above.
func (r *NetworkManager) updateNetworkEnvironmentLocked(ctx context.Context) {
	if !r.recomputeNetworkEnvironment() {
		return
	}
	r.boundEnvironmentTransitionLocked(ctx)
}

// recomputeNetworkEnvironment refreshes the fingerprint and reports whether it changed.
//
// It holds environmentUpdateAccess for the whole computation, which is what serialises concurrent
// updates and stops a pending timer from firing into a half-updated state. It deliberately does NOT
// take the reset: the reset can block on resetRunAccess, and Close takes that lock while waiting for
// startedCancel - so holding environmentUpdateAccess across it would stop every later
// postUpdateNetworkEnvironment behind a Close that is itself waiting. That is a three-way cycle, and
// it hung the jiejie reference suite for the full 40-minute test timeout.
func (r *NetworkManager) recomputeNetworkEnvironment() bool {
	r.environmentUpdateAccess.Lock()
	defer r.environmentUpdateAccess.Unlock()
	if r.environmentUpdateTimer != nil {
		r.environmentUpdateTimer.Stop()
	}
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
	r.networkEnvironment = environmentHash
	r.stateAccess.Unlock()
	if !changed || len(options) == 0 {
		return false
	}
	r.logger.Info("updated network environment: ", strings.Join(options, ", "))

	return true
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
func (r *NetworkManager) boundEnvironmentTransitionExported() {
	if !r.environmentTransitionApplies() {
		return
	}
	if r.logger != nil {
		r.logger.Info("network environment changed, resetting network transports")
	}
	r.ResetNetwork(r.startedCtx)
}

// boundEnvironmentTransitionLocked is the inner form for a caller holding resetRunAccess.
func (r *NetworkManager) boundEnvironmentTransitionLocked(ctx context.Context) {
	if !r.environmentTransitionApplies() {
		return
	}
	if r.logger != nil {
		r.logger.Info("network environment changed, resetting network transports")
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
