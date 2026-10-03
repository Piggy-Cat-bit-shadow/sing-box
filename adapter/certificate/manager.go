package certificate

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.CertificateProviderManager = (*Manager)(nil)

type Manager struct {
	registry      adapter.CertificateProviderRegistry
	access        sync.Mutex
	providers     []adapter.CertificateProviderService
	providerByTag map[string]adapter.CertificateProviderService
}

func NewManager(registry adapter.CertificateProviderRegistry) *Manager {
	return &Manager{
		registry:      registry,
		providerByTag: make(map[string]adapter.CertificateProviderService),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	providers := m.providers
	m.access.Unlock()
	for _, provider := range providers {
		name := "certificate-provider/" + provider.Type() + "[" + provider.Tag() + "]"
		err := scope.Start(name, provider, stage)
		if err != nil {
			return err
		}
	}
	return nil
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
