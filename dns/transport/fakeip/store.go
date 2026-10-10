package fakeip

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

const reservedAddressCount = 1024

// The two generation indices a store uses. They are constants rather than counters because a store
// serves exactly one live generation at a time and retires at most one, and the LEDGER tick - not the
// index - is what separates one store's live generation from another's. `FakeIPMetadata` carries no
// generation index at all, so a restart finds the same index again; if the index were a counter it
// would have to be persisted, which is exactly the new disk format this change must not introduce.
const (
	generationRetired = 0
	generationLive    = 1
)

var _ adapter.FakeIPStore = (*Store)(nil)

type Store struct {
	ctx        context.Context
	logger     logger.Logger
	inet4Range netip.Prefix
	inet6Range netip.Prefix
	inet4Last  netip.Addr
	inet6Last  netip.Addr
	storage    adapter.FakeIPStorage

	// ledger remembers what this store has handed out, for longer than this store lives. It is looked
	// up from the context, so it belongs to whoever owns the sequence of Boxes; when there is none,
	// nothing is recorded and the Box has no cross-Box issuance memory. See adapter.FakeIPIssuanceLedger.
	//
	// It is held as the CONCRETE adapter type, not as an interface, because that is what the registry
	// hands back: `service.MustRegisterPtr[adapter.FakeIPIssuanceLedger]` keys on
	// `common.DefaultValue[*adapter.FakeIPIssuanceLedger]()` and `service.PtrFromContext` returns
	// exactly that pointer. A pointer to an interface would be a different key, and a mismatched pair
	// returns nil rather than failing to compile - which is why the pair is pinned by a test.
	ledger *adapter.FakeIPIssuanceLedger
	// generationSequence is the ledger tick this store's ranges belong to, taken once at Start.
	// `FakeIPMetadata` carries no generation index, so a restart finds the same index again; the tick
	// is what separates the generation this store serves from the one it retired.
	generationSequence uint64

	addressAccess sync.Mutex
	inet4Current  netip.Addr
	inet6Current  netip.Addr
	reservedCount int
}

func NewStore(ctx context.Context, logger logger.Logger, inet4Range netip.Prefix, inet6Range netip.Prefix) *Store {
	store := &Store{
		ctx:        ctx,
		logger:     logger,
		inet4Range: inet4Range,
		inet6Range: inet6Range,
	}
	if inet4Range.IsValid() {
		store.inet4Last = broadcastAddress(inet4Range)
	}
	if inet6Range.IsValid() {
		store.inet6Last = broadcastAddress(inet6Range)
	}
	return store
}

func broadcastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	raw := addr.As16()
	bits := prefix.Bits()
	if addr.Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		raw[i/8] |= 1 << (7 - i%8)
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte(raw[12:]))
	}
	return netip.AddrFrom16(raw)
}

func nextAddress(addressRange netip.Prefix, last netip.Addr, current netip.Addr) netip.Addr {
	address := current.Next()
	if address == last || !addressRange.Contains(address) {
		address = addressRange.Addr().Next().Next()
	}
	return address
}

func (s *Store) Start() error {
	// The ledger, when one exists, is owned by whoever owns the sequence of Boxes rather than by this
	// Box, so it is looked up from the context exactly as the cache file is. Nothing is recorded at
	// construction: a configuration check builds a Box and closes it without ever starting it, and a
	// write from there would land in a shared ledger while a real Box is running.
	s.ledger = service.PtrFromContext[adapter.FakeIPIssuanceLedger](s.ctx)
	if s.ledger != nil {
		// The tick is taken BEFORE the retired generation is recorded, so the two do not collide.
		// `FakeIPMetadata` carries no generation index, so a restart finds the same index again and the
		// tick is the only thing separating "the generation that just handed this address out" from
		// "the generation that is replacing it".
		s.generationSequence = s.ledger.Advance()
	}
	var storage adapter.FakeIPStorage
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile != nil && cacheFile.StoreFakeIP() {
		storage = cacheFile
	}
	if storage == nil {
		storage = NewMemoryStorage()
	}
	metadata := storage.FakeIPMetadata()
	if metadata != nil && metadata.Inet4Range == s.inet4Range && metadata.Inet6Range == s.inet6Range {
		s.inet4Current = metadata.Inet4Current
		s.inet6Current = metadata.Inet6Current
	} else {
		// The persisted metadata describes a generation that is about to be DESTROYED by the reset
		// below, and it is the only surviving statement of what that generation handed out. Its ranges
		// and cursors are read here, BEFORE the reset, so the addresses a client may still be holding
		// stay attributable after the configuration that issued them is gone.
		//
		// This is the durable proof source, and it exists only when `experimental.cache_file` has
		// `store_fakeip` on: `MemoryStorage.FakeIPMetadata` returns nil, so on the default in-memory
		// path there is nothing here to read and the ledger records only what this process issues.
		if metadata != nil {
			s.recordRetired(metadata)
		}
		if s.inet4Range.IsValid() {
			s.inet4Current = s.inet4Range.Addr().Next()
		}
		if s.inet6Range.IsValid() {
			s.inet6Current = s.inet6Range.Addr().Next()
		}
		_ = storage.FakeIPReset()
	}
	s.storage = storage
	// Seed this generation at the point it starts from, which is either what the metadata restored or
	// the beginning of the configured range. The cursor can lead the true high-water mark by the
	// reservation window `Create` persists; that over-approximation is bounded and documented on
	// IssuanceLedger.RecordSeed.
	if s.ledger != nil {
		s.ledger.RecordSeed(s.generationSequence, generationLive, s.inet4Range, s.inet4Current, s.inet6Range, s.inet6Current)
	}
	return nil
}

// recordRetired records the generation whose metadata is about to be reset.
//
// The retired generation is recorded at the tick BEFORE the one this store advanced to, and under the
// retired generation index, so it cannot be overwritten by the generation replacing it: both
// identifiers take part in the record's identity, and `Store.Start` advances the tick exactly once per
// generation.
func (s *Store) recordRetired(metadata *adapter.FakeIPMetadata) {
	if s.ledger == nil {
		return
	}
	retiredSequence := s.generationSequence
	if retiredSequence > 0 {
		retiredSequence--
	}
	s.ledger.RecordSeed(retiredSequence, generationRetired, metadata.Inet4Range, metadata.Inet4Current,
		metadata.Inet6Range, metadata.Inet6Current)
}

func (s *Store) Contains(address netip.Addr) bool {
	return s.inet4Range.Contains(address) || s.inet6Range.Contains(address)
}

func (s *Store) Close() error {
	if s.storage == nil {
		return nil
	}
	s.addressAccess.Lock()
	metadata := &adapter.FakeIPMetadata{
		Inet4Range:   s.inet4Range,
		Inet6Range:   s.inet6Range,
		Inet4Current: s.inet4Current,
		Inet6Current: s.inet6Current,
	}
	s.addressAccess.Unlock()
	return s.storage.FakeIPSaveMetadata(metadata)
}

func (s *Store) Create(domain string, isIPv6 bool) (netip.Addr, error) {
	if address, loaded := s.storage.FakeIPLoadDomain(domain, isIPv6); loaded {
		return address, nil
	}

	s.addressAccess.Lock()
	defer s.addressAccess.Unlock()

	// Double-check after acquiring lock
	if address, loaded := s.storage.FakeIPLoadDomain(domain, isIPv6); loaded {
		return address, nil
	}

	if !isIPv6 && !s.inet4Current.IsValid() {
		return netip.Addr{}, E.New("missing IPv4 fakeip address range")
	} else if isIPv6 && !s.inet6Current.IsValid() {
		return netip.Addr{}, E.New("missing IPv6 fakeip address range")
	}
	// Advance and persist the cursor a whole window ahead of the addresses this
	// store is about to hand out, and then leave the metadata alone until the
	// window is exhausted. The allocation path therefore never depends on a
	// metadata write that could still be buffered when the process dies: whatever
	// point it dies at, the cursor on disk is already past every address issued in
	// this window, so a restart resumes past them instead of re-issuing addresses
	// that are still live.
	if s.reservedCount == 0 {
		metadata := &adapter.FakeIPMetadata{
			Inet4Range:   s.inet4Range,
			Inet6Range:   s.inet6Range,
			Inet4Current: s.inet4Current,
			Inet6Current: s.inet6Current,
		}
		for range reservedAddressCount {
			if metadata.Inet4Current.IsValid() {
				metadata.Inet4Current = nextAddress(s.inet4Range, s.inet4Last, metadata.Inet4Current)
			}
			if metadata.Inet6Current.IsValid() {
				metadata.Inet6Current = nextAddress(s.inet6Range, s.inet6Last, metadata.Inet6Current)
			}
		}
		err := s.storage.FakeIPSaveMetadata(metadata)
		if err != nil {
			return netip.Addr{}, E.Cause(err, "save fakeip metadata")
		}
		s.reservedCount = reservedAddressCount
	}
	s.reservedCount--
	var address netip.Addr
	if !isIPv6 {
		s.inet4Current = nextAddress(s.inet4Range, s.inet4Last, s.inet4Current)
		address = s.inet4Current
	} else {
		s.inet6Current = nextAddress(s.inet6Range, s.inet6Last, s.inet6Current)
		address = s.inet6Current
	}
	s.storage.FakeIPStoreAsync(address, domain, s.logger)
	if s.ledger != nil {
		// The exact record: this is one address the store really handed out, so the ledger narrows
		// whatever the persisted cursor over-approximated at Start. The address IS the advanced cursor -
		// `nextAddress` returns the address it moved TO, not the one it moved from.
		s.ledger.RecordIssued(s.generationSequence, generationLive, address)
	}
	return address, nil
}

func (s *Store) Lookup(address netip.Addr) (string, bool) {
	return s.storage.FakeIPLoad(address)
}

func (s *Store) Reset() error {
	return s.storage.FakeIPReset()
}
