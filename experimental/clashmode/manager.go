package clashmode

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

type Manager struct {
	ctx       context.Context
	logger    log.Logger
	dnsRouter adapter.DNSRouter
	// mode holds the active Clash mode.
	//
	// It is stored in an atomic.Value rather than a plain string because the two sides of this field
	// are genuinely concurrent and neither may wait for the other:
	//
	//   - the READ is the connection routing path. `ClashModeItem.Match` (route/rule, line 36) calls
	//     Mode() for every connection that reaches a `clash_mode` rule, and route/reference.go reads it
	//     while building rule references. It must be lock-free: a routing decision cannot queue behind a
	//     controller.
	//   - the WRITE is the controller path. `PATCH /configs` (experimental/clashapi/configs.go:63) and
	//     the daemon's service API (daemon/started_service.go:750) call SetMode at any time, and Start
	//     restores a persisted mode.
	//
	// A plain string let those two run unsynchronised - a torn or stale read on the routing path, and a
	// data race the race detector reports at manager.go:88 against manager.go:63. An atomic load is the
	// whole cost on the read side.
	mode atomic.Value
	// updateAccess serialises the mode SWITCH and the update-hook list, so a switch has one
	// linearization point: the same-mode check and the publication are one step, and two controllers
	// switching at once cannot interleave into a value neither asked for.
	//
	// It deliberately does NOT cover Mode(): that would put the routing path behind a control-plane
	// lock, and the hooks loop calls out to arbitrary subscribers while holding it.
	//
	// It is also released before the DNS cache invalidation and the persistence call at the end of
	// SetMode. Those can block, log and re-enter other components, and holding a control lock across
	// them is how a slow disk turns into stalled routing.
	updateAccess sync.Mutex
	modeList     []string
	updateHooks  []*observable.Subscriber[struct{}]
	// modeSequence numbers the switches, and is what keeps an OLDER persistence call from landing
	// after a newer one.
	//
	// # The defect it closes
	//
	// SetMode publishes the mode, releases the lock, and only then calls `cacheFile.StoreMode`, which
	// may touch a disk. Nothing ordered those calls, so two controllers switching concurrently could
	// have them complete in the opposite order from the switches they belong to:
	//
	//	A: switch to Global, park inside StoreMode
	//	B: switch to Direct, StoreMode returns
	//	A: StoreMode returns, writing Global over Direct
	//
	// The runtime then holds Direct while the persisted value is Global, and the NEXT process start
	// restores a mode the user had already left. MEASURED before this field existed:
	// `runtime="Direct" persisted="Global" write order=[Direct Global]`.
	//
	// # What makes the ticket mean anything
	//
	// A ticket is only an ordering fact if it is claimed at the same moment as the mode it belongs to,
	// so the claim lives INSIDE the updateAccess critical section that publishes the mode (see
	// claimSequence). Claiming it after the unlock leaves the window the ticket is supposed to close: a
	// switch can publish, lose the CPU, and only then take a ticket, so it takes a HIGHER ticket than a
	// switch that published after it and wins an ordering race it had already lost.
	//
	// MEASURED LIMIT: with the write gate and the convergence loop below both in place, moving the claim
	// after the unlock is NOT observable through the manager's contract - the harness reports
	// `[NOT-RED]`, because the gate is what orders the writes and the loop writes the mode observed under
	// the gate rather than the one the caller was handed. The claim position is therefore kept as
	// required-by-construction and defense in depth, NOT as the field that closes the defect: it is the
	// gate that does. Stated here so a later reader does not carry away a stronger claim than the
	// evidence supports.
	//
	// # Why a sequence and not the existing lock
	//
	// Putting StoreMode back inside `updateAccess` would hold a control-plane lock across a disk write,
	// which is the shape that turns a slow filesystem into stalled routing. The sequence makes
	// persistence LAST-WRITER-WINS BY SWITCH ORDER: only a switch that still holds the newest ticket
	// writes, and the write gate below makes that check and the write one step. `Mode()` stays a
	// lock-free atomic load, and the mode's publication is never delayed by persistence.
	modeSequence atomic.Uint64
	// persistAccess is the WRITE GATE. It serialises the backend writes, and it is the reason a ticket
	// check can be trusted.
	//
	// # The second defect, which the ticket alone does not close
	//
	// "Check the ticket, then write" is a check-then-act on a value another goroutine can change:
	//
	//	A: claims ticket 1, checks it, passes, and is preempted BEFORE handing its value to the backend
	//	B: claims ticket 2, checks it, passes, writes Direct and returns
	//	A: resumes and writes Global - a value the user has already left
	//
	// MEASURED on the ticket-only version with a backend that is slow before it commits:
	// `runtime="Direct" persisted="Global" write order=[Direct Global]`. So the ticket has to be checked
	// again with something held that the newer switch must also take, and only then may the write
	// happen. That is this lock, and it is deliberately NOT `updateAccess`:
	//
	//   - it is taken only on the persistence path, so a slow disk cannot stall a mode PUBLICATION
	//     (a second SetMode still publishes, and Mode() still never takes a lock);
	//   - it is not held across the hooks or the DNS cache invalidation, which stay outside it;
	//   - the ticket is re-read INSIDE it, and the value written is the one observed inside it, so a
	//     write of an older value cannot follow a newer one no matter how the switch calls interleave.
	//     Reverse-break evidence: removing the re-read from inside the gate turns
	//     TestOlderStoreParkedBeforeCommitCannotOverwriteANewerSwitch and
	//     TestASupersededSwitchStillLeavesTheBackendOnTheAcceptedMode red.
	//
	// A switch whose write fails leaves the backend holding an older value and says so through the
	// logger; it does not drive the backend back to a stale value, and the next switch writes again.
	persistAccess sync.Mutex
}

func NewManager(ctx context.Context, logger log.Logger, defaultMode string, modeList []string) *Manager {
	if defaultMode == "" {
		defaultMode = "Rule"
	}
	if !common.Contains(modeList, defaultMode) {
		modeList = append([]string{defaultMode}, modeList...)
	}
	manager := &Manager{
		ctx:       ctx,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		modeList:  modeList,
	}
	manager.mode.Store(defaultMode)
	return manager
}

func (m *Manager) Name() string {
	return "clash mode manager"
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile == nil {
		return nil
	}
	// The restore is serialised with SetMode for the same reason SetMode is serialised with itself: it
	// is a mode SWITCH, and the field it writes is the one routing reads. It goes through the same write
	// gate as a persisted switch, so it cannot load a value and then store it over a mode the user
	// changed while the load was in flight.
	return m.restorePersistedMode(cacheFile)
}

// claimSequence takes the ticket that numbers this switch.
//
// It exists as a named step because its POSITION is the contract, not its body: it must be called while
// `updateAccess` is held, in the same critical section that publishes the mode. A version of this file
// that called it after the unlock is what let a switch that published first claim a higher ticket than a
// switch that published second, and thereby win an ordering race it had already lost.
func (m *Manager) claimSequence() uint64 {
	return m.modeSequence.Add(1)
}

// restorePersistedMode applies the persisted mode if it is one this build accepts.
//
// It runs at the Start lifecycle stage, where no controller can be holding a mode yet, and it is
// serialised on the SAME write gate as a persisted switch for one reason: an older StoreMode call may
// still be parked in a backend that is slow BEFORE it commits, and a restore that slipped past it would
// be the one stale value a following startup could not explain. Waiting for the gate makes the disk
// order the switch order.
//
// The lock order is `updateAccess` then `persistAccess`, which is the order SetMode uses. Taking them
// the other way round here would be a lock-order inversion against SetMode.
func (m *Manager) restorePersistedMode(cacheFile adapter.CacheFile) error {
	m.updateAccess.Lock()
	m.persistAccess.Lock()
	defer m.persistAccess.Unlock()
	defer m.updateAccess.Unlock()
	restored := cacheFile.LoadMode()
	if common.Any(m.modeList, func(it string) bool {
		return strings.EqualFold(it, restored)
	}) {
		// The restore is a switch, so it claims a ticket like any other. It does not store anything
		// back: the value came from the backend, and writing it back would be a stale write waiting
		// to happen if a controller switched during the load above.
		m.modeSequence.Add(1)
		m.mode.Store(restored)
	}
	return nil
}

// Mode returns the active Clash mode.
//
// This is called on the connection routing path, so it performs one atomic load and takes no lock.
func (m *Manager) Mode() string {
	mode, _ := m.mode.Load().(string)
	return mode
}

func (m *Manager) ModeList() []string {
	return m.modeList
}

func (m *Manager) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.updateHooks = append(m.updateHooks, hook)
}

func (m *Manager) SetMode(newMode string) {
	if !common.Contains(m.modeList, newMode) {
		newMode = common.Find(m.modeList, func(it string) bool {
			return strings.EqualFold(it, newMode)
		})
	}
	if !common.Contains(m.modeList, newMode) {
		return
	}

	// Publish the switch, claim its ticket and hand the notification to the updateHooks list as ONE
	// step. All three have to be inside this critical section:
	//
	//   - the comparison and the store, so a second controller cannot split them;
	//   - the TICKET CLAIM, because the ticket is only evidence of switch order if it is taken at the
	//     same moment as the mode it numbers. Claiming it after the unlock lets a switch that published
	//     FIRST take a higher ticket by being descheduled, and it then wins a race it already lost.
	m.updateAccess.Lock()
	if newMode == m.Mode() {
		m.updateAccess.Unlock()
		return
	}
	m.mode.Store(newMode)
	sequence := m.claimSequence()
	updateHooks := m.updateHooks
	m.updateAccess.Unlock()

	// Everything below runs with the control lock RELEASED.
	//
	// The hooks are third-party code that may block or re-enter, ClearCache drops the DNS caches, and
	// persistMode may touch the disk. Holding the lock across any of them would let a slow subscriber or
	// a slow filesystem stall the next mode switch - and, before Mode() became lock-free, every
	// connection that reached a `clash_mode` rule.
	for _, hook := range updateHooks {
		hook.Emit(struct{}{})
	}
	if m.dnsRouter != nil {
		m.dnsRouter.ClearCache()
	}
	m.persistMode(sequence)
	if m.logger != nil {
		m.logger.Info("updated mode: ", newMode)
	}
}

// persistMode makes the backend hold the mode the runtime holds, unless a newer switch has taken over
// the job.
//
// See Manager.modeSequence and Manager.persistAccess. The rule is: a switch writes only while it holds
// the newest ticket, and it writes the NEWEST mode rather than the one it was called with, repeating
// until it has written a mode no later switch replaced. It takes no mode argument on purpose - the only
// safe value to write is the one read from inside the gate.
//
// # Why it converges rather than skips
//
// The first version of this gate skipped the write whenever the ticket had gone stale, on the theory
// that the newer switch would write its own value. That is wrong, and the barrier test caught it: the
// newer switch can run entirely WHILE the older one is already inside the backend, so the newer switch
// finds its own ticket current, sees the gate busy, and - under the skip rule - returns, while the older
// write then lands on top of it. MEASURED: `runtime="Direct" persisted="Global"`. The gate has to be
// owned by whoever writes last, not by whoever claimed last.
//
// So the loop does the opposite: it re-reads the mode from inside the gate and writes what it finds.
// Each pass writes the mode that was current when the gate was taken, and a pass that sees the mode
// changed while it was writing simply takes another pass. The number of passes is bounded by the number
// of switches that happened while this one held the gate, and the loop stops as soon as it has written
// a mode nothing has replaced.
//
// A superseded pass returning silently - rather than reporting success - still matters: it did not
// persist anything, and the pass that does is the one that reports.
func (m *Manager) persistMode(sequence uint64) {
	if m.modeSequence.Load() != sequence {
		// A newer switch has already claimed persistence. It will write; this call has nothing to add,
		// and reaching the backend now would be an older value landing on top of a newer one.
		return
	}
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile == nil {
		return
	}
	// The gate is taken BEFORE the ticket is re-read, and that order is the whole mechanism. With the
	// read first there is a window between the read and the call in which a newer switch can claim its
	// ticket - and a switch that is already inside the backend cannot be called back. Held here, the
	// re-read cannot go stale: any switch that claims a newer ticket must also take this lock to write,
	// so it cannot take the ticket AND write while this holder has not yet looked.
	m.persistAccess.Lock()
	defer m.persistAccess.Unlock()
	for attempt := 0; ; attempt++ {
		if m.modeSequence.Load() != sequence {
			return
		}
		// The value written is the one the gate observes, not the one this call was handed. That is what
		// makes the last write the newest value even when it is performed by an older switch.
		currentMode := m.Mode()
		err := cacheFile.StoreMode(currentMode)
		if err != nil {
			if m.logger != nil {
				m.logger.Error(E.Cause(err, "save mode"))
			}
			return
		}
		if m.modeSequence.Load() == sequence {
			// Nothing replaced the value that was just written, so the backend and the runtime agree.
			return
		}
		// A switch landed while this write was in flight. Adopt it and write again, so the backend ends
		// on the newest mode rather than on the one this pass started with.
		sequence = m.modeSequence.Load()
		if attempt > maxConvergenceAttempts {
			// Defensive: a switch storm on one goroutine's stack. Give the newest switch the job instead
			// of spinning, and let the caller see that this call stopped short.
			if m.logger != nil {
				m.logger.Error("gave up converging persisted mode after ", attempt, " attempts")
			}
			return
		}
	}
}

// maxConvergenceAttempts bounds the convergence loop in persistMode. It is not a correctness limit: a
// pass can only repeat when a switch landed while it was writing, so reaching this bound means a mode
// storm. Aborting is safe, because the switch that caused the final change performs its own write.
const maxConvergenceAttempts = 64

var _ adapter.LifecycleService = (*Manager)(nil)
