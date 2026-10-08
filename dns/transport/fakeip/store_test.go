package fakeip

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const (
	testInet4RangeText = "198.18.0.0/15"
	testInet6RangeText = "fdfe:dcba:9876::/64"
)

// The persisted bucket and key names are unexported in experimental/cachefile;
// the test reads the raw bucket on purpose so that it observes what actually
// reached disk instead of going back through the FakeIPMetadata method under test.
var (
	testPersistedBucket = []byte("fakeip_address")
	testPersistedKey    = []byte("fakeip_metadata")
)

// newStoreWithCacheFile builds a store over a real cache file, so the reservation
// is observed through the production path: Store.Create -> FakeIPStorage.
// FakeIPSaveMetadata -> CacheFile.Flush -> bbolt, and Start reads it back the same
// way a restart would.
func newStoreWithCacheFile(t *testing.T) (*Store, *cachefile.CacheFile, context.Context) {
	t.Helper()
	baseCtx := context.Background()
	cacheFile := cachefile.New(
		baseCtx,
		logger.NOP(),
		option.CacheFileOptions{
			Enabled:     true,
			Path:        filepath.Join(t.TempDir(), "cache.db"),
			StoreFakeIP: true,
		},
	)
	scope := adapter.NewScope(baseCtx, log.NewNOPFactory().Logger())
	require.NoError(t, cacheFile.Start(adapter.StartStateInitialize, scope))
	// LIFO cleanup: the store must save its cursor before the cache file closes.
	t.Cleanup(func() {
		require.NoError(t, scope.Close())
	})
	storeCtx := service.ContextWith[adapter.CacheFile](baseCtx, cacheFile)
	store := NewStore(
		storeCtx,
		logger.NOP(),
		netip.MustParsePrefix(testInet4RangeText),
		netip.MustParsePrefix(testInet6RangeText),
	)
	require.NoError(t, store.Start())
	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})
	return store, cacheFile, storeCtx
}

func requirePersistedMetadata(t *testing.T, cacheFile *cachefile.CacheFile) *adapter.FakeIPMetadata {
	t.Helper()
	var metadataBinary []byte
	require.NoError(t, cacheFile.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(testPersistedBucket)
		if bucket == nil {
			return nil
		}
		metadataBinary = bytes.Clone(bucket.Get(testPersistedKey))
		return nil
	}))
	require.NotNil(t, metadataBinary, "the address cursor must already be on disk")
	metadata := &adapter.FakeIPMetadata{}
	require.NoError(t, metadata.UnmarshalBinary(metadataBinary))
	return metadata
}

// advance returns the address reservedAddressCount steps past the start of the
// range without going through the store's own helper, so the expectation does not
// share a bug with the code it checks. Both test ranges are far larger than one
// window, so the cursor cannot wrap around them.
func advanceForWindows(testRange netip.Prefix, windows int) netip.Addr {
	expected := testRange.Addr().Next()
	for range reservedAddressCount * windows {
		expected = expected.Next()
	}
	return expected
}

// The store must advance and persist the cursor a whole window ahead before it
// hands out the first address of that window, and must not rewrite the metadata
// per allocation. The pre-fix store kept the reserved window but also called
// FakeIPSaveMetadataAsync with the just-issued address on every Create, which both
// put the persisted cursor at (or, with the write still buffered, behind) the
// newest issued address — defeating the reservation — and obsoleted the
// once-per-window write the window exists to enable.
func TestStorePersistsCursorAheadOfIssuedAddresses(t *testing.T) {
	store, cacheFile, _ := newStoreWithCacheFile(t)
	inet4Range := netip.MustParsePrefix(testInet4RangeText)
	inet6Range := netip.MustParsePrefix(testInet6RangeText)

	var lastIssued netip.Addr
	for i := range 3 {
		address, err := store.Create(fmt.Sprintf("host-%d.example", i), false)
		require.NoError(t, err)
		require.True(t, inet4Range.Contains(address), "issued address %v is outside the range", address)
		lastIssued = address
	}

	metadata := requirePersistedMetadata(t, cacheFile)
	require.Equal(t, advanceForWindows(inet4Range, 1), metadata.Inet4Current,
		"the persisted cursor must be the range start advanced by exactly one reserved window")
	require.Equal(t, advanceForWindows(inet6Range, 1), metadata.Inet6Current,
		"the parallel IPv6 cursor must be reserved even while only IPv4 addresses are issued")
	require.Positive(t, metadata.Inet4Current.Compare(lastIssued),
		"the persisted cursor %v must lead the last issued address %v",
		metadata.Inet4Current, lastIssued)
}

// The window must actually be refilled, not just reserved once: the allocation
// that exhausts it persists the next window before issuing from it, so the cursor
// on disk is ahead of every address issued so far at every point in the run.
func TestStoreRefillsReservedWindow(t *testing.T) {
	store, cacheFile, _ := newStoreWithCacheFile(t)
	inet4Range := netip.MustParsePrefix(testInet4RangeText)

	var lastIssued netip.Addr
	for i := range reservedAddressCount + 1 {
		address, err := store.Create(fmt.Sprintf("host-%d.example", i), false)
		require.NoError(t, err)
		lastIssued = address
	}

	metadata := requirePersistedMetadata(t, cacheFile)
	require.Equal(t, advanceForWindows(inet4Range, 2), metadata.Inet4Current,
		"exhausting the first window must persist a second one ahead of the allocation that consumed it")
	require.Positive(t, metadata.Inet4Current.Compare(lastIssued))
}

// A restart that never saw Close must still start past every address the previous
// store handed out. This is the property the reservation buys: the cursor is
// already on disk ahead of the window, so the addresses queued by FakeIPStoreAsync
// and not yet flushed cannot be re-issued.
func TestStoreRestartWithoutCloseSkipsIssuedAddresses(t *testing.T) {
	store, _, storeCtx := newStoreWithCacheFile(t)

	issued := make(map[netip.Addr]struct{})
	for i := range 3 {
		address, err := store.Create(fmt.Sprintf("host-%d.example", i), false)
		require.NoError(t, err)
		issued[address] = struct{}{}
	}

	restarted := NewStore(
		storeCtx,
		logger.NOP(),
		netip.MustParsePrefix(testInet4RangeText),
		netip.MustParsePrefix(testInet6RangeText),
	)
	require.NoError(t, restarted.Start())
	address, err := restarted.Create("after-restart.example", false)
	require.NoError(t, err)
	_, reused := issued[address]
	require.False(t, reused,
		"restart re-issued %v, which the previous store had already handed out", address)
}

// countingStorage records how often the store asks for its cursor to be persisted.
type countingStorage struct {
	saves int
	last  adapter.FakeIPMetadata
}

func (s *countingStorage) FakeIPMetadata() *adapter.FakeIPMetadata {
	return nil
}

func (s *countingStorage) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	s.saves++
	s.last = *metadata
	return nil
}

func (s *countingStorage) FakeIPStore(address netip.Addr, domain string) error {
	return nil
}

func (s *countingStorage) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
}

func (s *countingStorage) FakeIPLoad(address netip.Addr) (string, bool) {
	return "", false
}

func (s *countingStorage) FakeIPLoadDomain(domain string, isIPv6 bool) (netip.Addr, bool) {
	return netip.Addr{}, false
}

func (s *countingStorage) FakeIPReset() error {
	return nil
}

var _ adapter.FakeIPStorage = (*countingStorage)(nil)

// The cursor is persisted once per reserved window and not once per allocation.
// A per-allocation write is what the pre-fix store did; besides negating the
// reservation it puts a synchronous disk write on the allocation path.
func TestStoreSavesCursorOncePerReservedWindow(t *testing.T) {
	inet4Range := netip.MustParsePrefix(testInet4RangeText)
	storage := &countingStorage{}
	store := NewStore(context.Background(), logger.NOP(), inet4Range, netip.Prefix{})
	// Start would pick the storage and set the cursor from the (empty) metadata;
	// do both directly so the test isolates Create.
	store.storage = storage
	store.inet4Current = inet4Range.Addr().Next()

	for i := range 10 {
		_, err := store.Create(fmt.Sprintf("host-%d.example", i), false)
		require.NoError(t, err)
	}
	require.Equal(t, 1, storage.saves,
		"ten allocations inside one window must persist the cursor once")

	for i := 10; i < reservedAddressCount+1; i++ {
		_, err := store.Create(fmt.Sprintf("host-%d.example", i), false)
		require.NoError(t, err)
	}
	require.Equal(t, 2, storage.saves,
		"crossing the window boundary must persist the cursor exactly once more")
}
