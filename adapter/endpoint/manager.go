package endpoint

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.EndpointManager = (*Manager)(nil)

type Manager struct {
	logger        log.ContextLogger
	registry      adapter.EndpointRegistry
	access        sync.Mutex
	started       bool
	stage         adapter.StartStage
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
}

func NewManager(logger log.ContextLogger, registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
	}
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	if stage == adapter.StartStateStart {
		// started with outbound manager
		return nil
	}
	for _, endpoint := range m.endpoints {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		done := adapter.LogElapsed(m.logger, stage, " ", name)
		err := endpoint.Start(stage)
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
	endpoints := m.endpoints
	m.endpoints = nil
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	var err error
	for _, endpoint := range endpoints {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		done := adapter.LogElapsed(m.logger, "close ", name)
		monitor.Start("close ", name)
		err = E.Append(err, endpoint.Close(), func(err error) error {
			return E.Cause(err, "close ", name)
		})
		monitor.Finish()
		done()
	}
	return nil
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return m.endpoints
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	// Reject a duplicate BEFORE constructing anything.
	//
	// Constructing first and replacing afterwards discards an object whose constructor side effects
	// cannot be undone - a bridge outbound claims a process-global slot at construction, for example
	// - and it silently runs a configuration the user did not write.
	m.access.Lock()
	if _, loaded := m.endpointByTag[tag]; loaded {
		m.access.Unlock()
		return E.New("endpoint ", tag, " already exists")
	}
	m.access.Unlock()

	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	// Re-check under the lock: the constructor runs outside it, so another goroutine may have
	// installed this tag meanwhile. The loser releases what it built rather than leaking it.
	if _, loaded := m.endpointByTag[tag]; loaded {
		_ = common.Close(endpoint)
		return E.New("endpoint ", tag, " already exists")
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	return nil
}
