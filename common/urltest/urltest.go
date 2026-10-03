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

// latestHistoryRecord remembers which scope produced a tag's most recent result, so the entry can
// be re-pointed at another scope when that one is deleted instead of vanishing.
type latestHistoryRecord struct {
	History *adapter.URLTestHistory
	Scope   MeasurementScope
}

// HistoryStorage holds node measurements.
//
// It keeps two views of the same data:
//
//	latest  one entry per tag, for display - "show the most recent measurement of this node"
//	scoped  one entry per (tag, target), for decisions - selection, interval skipping, health
//
// They are maintained together on every store. The split exists because those two questions have
// different answers: a UI showing "most recent" is correct and useful, while a group selecting a
// node must only consider results measured against its own target.
type HistoryStorage struct {
	access sync.RWMutex

	// delayHistory is the most recent successful measurement per tag, for display.
	delayHistory map[string]latestHistoryRecord

	// scopedHistory is per (tag, target), and is what selection and skipping read.
	scopedHistory map[scopedHistoryKey]*adapter.URLTestHistory

	updateHooks []*observable.Subscriber[struct{}]
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory:  make(map[string]latestHistoryRecord),
		scopedHistory: make(map[scopedHistoryKey]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.access.RLock()
	defer s.access.RUnlock()
	s.notifyUpdated()
}

// LoadURLTestHistory returns the tag's most recent measurement, whatever target produced it.
//
// This is the DISPLAY accessor: the native node list and the Clash UI want "the last result for
// this node", and a result measured against any target answers that question. It must not be used
// to make selection decisions - use LoadURLTestHistoryFor for that.
func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag].History
}

// LoadURLTestHistoryFor returns the tag's measurement for one specific target.
//
// Selection, interval skipping and health checks must use this: a fresh result against a
// different target says nothing about the target being tested.
func (s *HistoryStorage) LoadURLTestHistoryFor(tag string, scope MeasurementScope) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.scopedHistory[scopedHistoryKey{Tag: tag, Scope: scope}]
}

// DeleteURLTestHistory removes every measurement for a tag, including the display entry.
//
// Used when the node itself is gone rather than when one target failed.
func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	delete(s.delayHistory, tag)
	for key := range s.scopedHistory {
		if key.Tag == tag {
			delete(s.scopedHistory, key)
		}
	}
	s.notifyUpdated()
	s.access.Unlock()
}

// DeleteURLTestHistoryFor removes one target's measurement for a tag.
//
// # Why it re-points the display entry instead of deleting it
//
// A failed test against one target is not a reason to show nothing. The node may have a perfectly
// good result against another target, and that is still the most recent thing known about it. The
// display entry therefore moves to the newest remaining measurement, and is only removed when no
// measurement remains at all.
func (s *HistoryStorage) DeleteURLTestHistoryFor(tag string, scope MeasurementScope) {
	s.access.Lock()
	delete(s.scopedHistory, scopedHistoryKey{Tag: tag, Scope: scope})

	if latest, ok := s.delayHistory[tag]; ok && latest.Scope == scope {
		if replacement, replacementScope, found := s.newestScopedLocked(tag); found {
			s.delayHistory[tag] = latestHistoryRecord{History: replacement, Scope: replacementScope}
		} else {
			delete(s.delayHistory, tag)
		}
	}
	s.notifyUpdated()
	s.access.Unlock()
}

// newestScopedLocked returns the tag's most recent remaining measurement.
// The caller must hold the write lock.
func (s *HistoryStorage) newestScopedLocked(tag string) (*adapter.URLTestHistory, MeasurementScope, bool) {
	var (
		newest      *adapter.URLTestHistory
		newestScope MeasurementScope
		found       bool
	)
	for key, history := range s.scopedHistory {
		if key.Tag != tag || history == nil {
			continue
		}
		if !found || history.Time.After(newest.Time) {
			newest = history
			newestScope = key.Scope
			found = true
		}
	}
	return newest, newestScope, found
}

// StoreURLTestHistory records a measurement against the default target.
//
// Kept for callers that measure the default target only. A caller that knows its target should
// use StoreURLTestHistoryFor so the result lands in the right scope.
func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	scope, err := NewMeasurementScope(DefaultURLTestURL, nil)
	if err != nil {
		// The default target is a compile-time constant; if it ever fails to normalise the
		// storage would silently drop results, so it is recorded rather than swallowed.
		panic(err)
	}
	s.StoreURLTestHistoryFor(tag, scope, history)
}

// StoreURLTestHistoryFor records a measurement for one target.
//
// The display entry is updated at the same time, because the caller has just measured the node and
// that is by definition the most recent thing known about it.
func (s *HistoryStorage) StoreURLTestHistoryFor(tag string, scope MeasurementScope, history *adapter.URLTestHistory) {
	s.access.Lock()
	s.scopedHistory[scopedHistoryKey{Tag: tag, Scope: scope}] = history
	s.delayHistory[tag] = latestHistoryRecord{History: history, Scope: scope}
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) notifyUpdated() {
	for _, updateHook := range s.updateHooks {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = nil
	return nil
}
