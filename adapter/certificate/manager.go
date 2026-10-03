package certificate

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ adapter.CertificateProviderManager = (*Manager)(nil)

type Manager struct {
	logger        log.ContextLogger
	registry      adapter.CertificateProviderRegistry
	access        sync.Mutex
	started       bool
	stage         adapter.StartStage
	providers     []adapter.CertificateProviderService
	providerByTag map[string]adapter.CertificateProviderService
}

func NewManager(logger log.ContextLogger, registry adapter.CertificateProviderRegistry) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		providerByTag: make(map[string]adapter.CertificateProviderService),
	}
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	providers := m.providers
	m.access.Unlock()
	for _, provider := range providers {
		name := "certificate-provider/" + provider.Type() + "[" + provider.Tag() + "]"
		m.logger.Trace(stage, " ", name)
		startTime := time.Now()
		err := provider.Start(stage)
		if err != nil {
			return E.Cause(err, stage, " ", name)
		}
		m.logger.Trace(stage, " ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
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
	providers := m.providers
	m.providers = nil
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	var err error
	for _, provider := range providers {
		name := "certificate-provider/" + provider.Type() + "[" + provider.Tag() + "]"
		m.logger.Trace("close ", name)
		startTime := time.Now()
		monitor.Start("close ", name)
		err = E.Append(err, provider.Close(), func(err error) error {
			return E.Cause(err, "close ", name)
		})
		monitor.Finish()
		m.logger.Trace("close ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
	}
	return err
}

func (m *Manager) CertificateProviders() []adapter.CertificateProviderService {
	m.access.Lock()
	defer m.access.Unlock()
	return m.providers
}

func (m *Manager) Get(tag string) (adapter.CertificateProviderService, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Create(ctx context.Context, logger log.ContextLogger, tag string, providerType string, options any) error {
	// Reject a duplicate BEFORE constructing anything.
	//
	// Constructing first and replacing afterwards discards an object whose constructor side effects
	// cannot be undone, and it silently runs a configuration the user did not write.
	m.access.Lock()
	if _, loaded := m.providerByTag[tag]; loaded {
		m.access.Unlock()
		return E.New("certificate provider ", tag, " already exists")
	}
	m.access.Unlock()

	provider, err := m.registry.Create(ctx, logger, tag, providerType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	// Re-check under the lock: the constructor runs outside it, so another goroutine may have
	// installed this tag meanwhile. The loser releases what it built rather than leaking it.
	if _, loaded := m.providerByTag[tag]; loaded {
		_ = common.Close(provider)
		return E.New("certificate provider ", tag, " already exists")
	}
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	return nil
}
