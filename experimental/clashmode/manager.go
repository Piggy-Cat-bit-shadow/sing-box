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
	// is a mode SWITCH, and the field it writes is the one routing reads.
	restored := cacheFile.LoadMode()
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	if common.Any(m.modeList, func(it string) bool {
		return strings.EqualFold(it, restored)
	}) {
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

	// Publish the switch and hand the notification to the updateHooks list as ONE step, so the
	// comparison and the store cannot be split by a second controller.
	m.updateAccess.Lock()
	if newMode == m.Mode() {
		m.updateAccess.Unlock()
		return
	}
	m.mode.Store(newMode)
	updateHooks := m.updateHooks
	m.updateAccess.Unlock()

	// Everything below runs with the control lock RELEASED.
	//
	// The hooks are third-party code that may block or re-enter, ClearCache drops the DNS caches, and
	// StoreMode may touch the disk. Holding the lock across any of them would let a slow subscriber or
	// a slow filesystem stall the next mode switch - and, before Mode() became lock-free, every
	// connection that reached a `clash_mode` rule.
	for _, hook := range updateHooks {
		hook.Emit(struct{}{})
	}
	if m.dnsRouter != nil {
		m.dnsRouter.ClearCache()
	}
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile != nil {
		err := cacheFile.StoreMode(newMode)
		if err != nil {
			if m.logger != nil {
				m.logger.Error(E.Cause(err, "save mode"))
			}
		}
	}
	if m.logger != nil {
		m.logger.Info("updated mode: ", newMode)
	}
}

var _ adapter.LifecycleService = (*Manager)(nil)
