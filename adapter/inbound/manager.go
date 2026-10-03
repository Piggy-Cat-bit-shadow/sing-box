package inbound

import (
	"context"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	logger       log.ContextLogger
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	started      bool
	stage        adapter.StartStage
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
}

func NewManager(logger log.ContextLogger, registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		logger:       logger,
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	inbounds := m.inbounds
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		done := adapter.LogElapsed(m.logger, stage, " ", name)
		err := adapter.LegacyStart(inbound, stage)
		done()
		if err != nil {
			return E.Cause(err, stage, " ", name)
		}
	}
	return nil
}

func (m *Manager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.started {
		return nil
	}
	m.started = false
	inbounds := m.inbounds
	m.inbounds = nil
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	var err error
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		done := adapter.LogElapsed(m.logger, "close ", name)
		monitor.Start("close ", name)
		err = E.Append(err, inbound.Close(), func(err error) error {
			return E.Cause(err, "close ", name)
		})
		monitor.Finish()
		done()
	}
	return nil
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return m.inbounds
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.inboundByTag, tag)
	index := common.Index(m.inbounds, func(it adapter.Inbound) bool {
		return it == inbound
	})
	if index == -1 {
		panic("invalid inbound index")
	}
	m.inbounds = append(m.inbounds[:index], m.inbounds[index+1:]...)
	started := m.started
	m.access.Unlock()
	if started {
		return inbound.Close()
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	// Reject a duplicate BEFORE constructing anything.
	//
	// Constructing first and replacing afterwards discards an object whose constructor side effects
	// cannot be undone - a bridge outbound claims a process-global slot at construction, for example
	// - and it silently runs a configuration the user did not write.
	m.access.Lock()
	if _, loaded := m.inboundByTag[tag]; loaded {
		m.access.Unlock()
		return E.New("inbound ", tag, " already exists")
	}
	m.access.Unlock()

	inbound, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			done := adapter.LogElapsed(m.logger, stage, " ", name)
			err = adapter.LegacyStart(inbound, stage)
			done()
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	// Re-check under the lock: the constructor runs outside it, so another goroutine may have
	// installed this tag meanwhile. The loser releases what it built rather than leaking it.
	if _, loaded := m.inboundByTag[tag]; loaded {
		_ = common.Close(inbound)
		return E.New("inbound ", tag, " already exists")
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	return nil
}
