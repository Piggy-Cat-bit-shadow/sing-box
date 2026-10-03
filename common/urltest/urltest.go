package urltest

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/observable"
)

// scopedHistoryKey identifies one measurement: a node measured against a specific target.
//
// # Why the tag alone was wrong
//
// A delay belongs to a (node, target) pair. Keying by tag meant "Hong Kong to gstatic" and
// "Hong Kong to Cloudflare" were the same entry, so whichever was measured last decided what a
// URLTest group configured for the other target would select from.
type scopedHistoryKey struct {
	Tag   string
	Scope MeasurementScope
}

// displayRecord is one tag's most recent successful measurement.
type displayRecord struct {
	History adapter.URLTestHistory
	Scope   MeasurementScope
}

// HistoryStorage holds node measurements in two INDEPENDENT layers.
//
// # display
//
// One entry per tag: the most recent successful measurement of that node, whatever target produced
// it. This is what a node list, a Clash proxy entry, or a manual diagnostic reads.
//
// It is written by manual probes AND by automatic health checks, because both are legitimately "the
// last successful measurement". It is never removed by a failure: a failed probe against one URL
// does not invalidate a success against another.
//
// # health
//
// One entry per (tag, target), and the only thing selection, interval skipping and tolerance read.
// ONLY an automatic URLTest group health check may write or delete it.
//
// # Why they are separate
//
// A manual diagnostic asks "how fast is this node against the URL I typed". An automatic group asks
// "which member should carry traffic for MY configured target". Answering the second question with
// the first answer's data is wrong, and letting manual probes write selection evidence also lets a
// user grow that evidence without bound by testing arbitrary URLs.
//
// The layers were previously kept in step on every store, which is what made a manual probe against
// an arbitrary URL land in the health map.
type HistoryStorage struct {
	access sync.RWMutex
	// notifyAccess serialises notification against teardown.
	//
	// Copying the hook list removes the data race, but not the lifecycle boundary: without this, a
	// notification could take its snapshot, Close could return, and the sends would then happen
	// after the caller had already released whatever consumes them. Holding this across Close makes
	// "Close has returned" mean "no further event can be produced".
	notifyAccess sync.Mutex

	// displayHistory is the most recent successful measurement per tag, for display.
	//
	// It is maintained by BOTH manual probes and automatic health checks, because both are a
	// legitimate "last successful measurement". It is never removed by a failure: a failed probe
	// against one URL says nothing about the last success against another.
	displayHistory map[string]displayRecord

	// healthHistory is per (tag, target) and is what selection and skipping read.
	//
	// ONLY an automatic URLTest group health check may write or delete here. A manual diagnostic
	// against an arbitrary URL must never become selection evidence, and must never grow this map
	// without bound.
	healthHistory map[scopedHistoryKey]adapter.URLTestHistory

	// closed makes Close terminal. A measurement that finishes afterwards must not write.
	closed bool

	updateHooks []*observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		displayHistory: make(map[string]displayRecord),
		healthHistory:  make(map[scopedHistoryKey]adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return
	}
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.notifyUpdated()
}

// LoadURLTestHistory returns the tag's most recent successful measurement, whatever target
// produced it.
//
// This is the DISPLAY accessor: a node list and the Clash UI want "the last result for this node",
// and a result measured against any target answers that. It must not be used for selection.
func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	record, loaded := s.displayHistory[tag]
	if !loaded {
		return nil
	}
	// A copy: the caller must not be able to mutate stored state through the pointer.
	history := record.History
	return &history
}

// LoadURLTestHistoryFor returns the tag's HEALTH measurement for one specific target.
//
// Selection, interval skipping and tolerance must use this: a result against a different target
// says nothing about the target being tested.
func (s *HistoryStorage) LoadURLTestHistoryFor(tag string, scope MeasurementScope) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if s.closed {
		return nil
	}
	history, loaded := s.healthHistory[scopedHistoryKey{Tag: tag, Scope: scope}]
	if !loaded {
		return nil
	}
	result := history
	return &result
}

// StoreDisplayHistory records a manual measurement for display only.
//
// A manual probe answers "how fast is this node against the URL I asked for". That is a useful thing
// to show and must NOT become selection evidence: it was not measured against the group's target,
// and letting it accumulate would also let a user grow the health map without bound by testing
// arbitrary URLs.
//
// A failure is simply not recorded. It must never remove the previous success, because failing URL B
// does not disprove a success against URL A.
func (s *HistoryStorage) StoreDisplayHistory(tag string, scope MeasurementScope, history *adapter.URLTestHistory) {
	if s == nil || history == nil {
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	s.displayHistory[tag] = displayRecord{History: *history, Scope: scope}
	s.access.Unlock()
	s.notifyUpdated()
}

// StoreHealthHistory records an automatic health measurement, in both layers.
//
// The health layer is what the group selects from. The display layer is updated too, because the
// node has just been measured and that is by definition the most recent thing known about it.
func (s *HistoryStorage) StoreHealthHistory(tag string, scope MeasurementScope, history *adapter.URLTestHistory) {
	if s == nil || history == nil {
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	s.healthHistory[scopedHistoryKey{Tag: tag, Scope: scope}] = *history
	s.displayHistory[tag] = displayRecord{History: *history, Scope: scope}
	s.access.Unlock()
	s.notifyUpdated()
}

// DeleteHealthHistory removes one target's health measurement for a tag.
//
// It deliberately does NOT touch the display entry. The layers are independent: a failed health
// check against this group's target is not a reason to stop showing the node's last successful
// measurement, which may well have been against another target.
func (s *HistoryStorage) DeleteHealthHistory(tag string, scope MeasurementScope) {
	if s == nil {
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	delete(s.healthHistory, scopedHistoryKey{Tag: tag, Scope: scope})
	s.access.Unlock()
	s.notifyUpdated()
}

// DeleteURLTestHistory removes every measurement for a tag, in both layers.
//
// Used when the NODE is gone rather than when one target failed.
func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	if s == nil {
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	delete(s.displayHistory, tag)
	for key := range s.healthHistory {
		if key.Tag == tag {
			delete(s.healthHistory, key)
		}
	}
	s.access.Unlock()
	s.notifyUpdated()
}

// DeleteURLTestHistoryFor removes one target's HEALTH measurement.
//
// Retained as the health-layer name used by the measurement paths. The display layer is untouched:
// that is the whole point of the split, and it is what removes the need to re-point the display
// entry at some other scope when this one is deleted.
func (s *HistoryStorage) DeleteURLTestHistoryFor(tag string, scope MeasurementScope) {
	s.DeleteHealthHistory(tag, scope)
}

// StoreURLTestHistoryFor records a HEALTH measurement.
//
// Retained as the health-layer name used by the automatic group path. Use StoreDisplayHistory for a
// manual probe, which must not write selection evidence.
func (s *HistoryStorage) StoreURLTestHistoryFor(tag string, scope MeasurementScope, history *adapter.URLTestHistory) {
	s.StoreHealthHistory(tag, scope, history)
}

// StoreURLTestHistory records a health measurement against the default target.
//
// Kept for callers that measure the default target only.
func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	scope, err := NewMeasurementScope(DefaultURLTestURL, nil)
	if err != nil {
		// The default target is a compile-time constant; if it ever fails to normalise the
		// storage would silently drop results, so it is recorded rather than swallowed.
		panic(err)
	}
	s.StoreHealthHistory(tag, scope, history)
}

// HealthEntryCount reports how many health entries are stored.
//
// It exists so a test can assert that manual probes do not grow the health map, as a fact rather
// than by inference.
func (s *HistoryStorage) HealthEntryCount() int {
	if s == nil {
		return 0
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return len(s.healthHistory)
}

// DisplayEntryCount reports how many display entries are stored.
func (s *HistoryStorage) DisplayEntryCount() int {
	if s == nil {
		return 0
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return len(s.displayHistory)
}

// notifyUpdated delivers one event to every registered hook.
//
// # Synchronisation
//
// The hook list is COPIED while holding the storage lock, and the sends happen after releasing it.
// Both halves are required:
//
//   - Copying is what removes the race. The list is appended to by AddUpdateHook and dropped by
//     Close, so walking it unlocked reads a slice header and backing array that another goroutine
//     writes.
//   - Sending outside the storage lock is what keeps this callable from a context that already
//     holds it, and keeps a slow consumer from blocking every other storage operation.
//
// notifyAccess is held across both, so Close cannot return while an event is still being delivered.
func (s *HistoryStorage) notifyUpdated() {
	s.notifyAccess.Lock()
	defer s.notifyAccess.Unlock()

	s.access.RLock()
	if s.closed {
		s.access.RUnlock()
		return
	}
	hooks := make([]*observable.Subscriber[struct{}], len(s.updateHooks))
	copy(hooks, s.updateHooks)
	s.access.RUnlock()

	for _, updateHook := range hooks {
		updateHook.Emit(struct{}{})
	}
}

// Close makes the storage terminal.
//
// Every later operation becomes a no-op, including a measurement that was already in flight when
// Close ran: its result is discarded rather than written into a storage that no longer exists.
func (s *HistoryStorage) Close() error {
	// Take the notification lock first, so Close blocks until any in-flight delivery finishes and
	// no new one can start afterwards.
	s.notifyAccess.Lock()
	defer s.notifyAccess.Unlock()

	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	// Release everything. A closed storage holds no measurements and notifies nobody; keeping the
	// maps would let a late writer - or a reader that raced Close - still observe live state.
	clear(s.displayHistory)
	clear(s.healthHistory)
	s.updateHooks = nil
	return nil
}
