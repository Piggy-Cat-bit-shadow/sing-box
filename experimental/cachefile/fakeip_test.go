package cachefile

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

var (
	testFakeIPInet4Range = netip.MustParsePrefix("198.18.0.0/15")
	testFakeIPInet6Range = netip.MustParsePrefix("fdfe:dcba:9876::/64")
)

// openTestCacheFile starts a real cache file in a temp dir. These tests must not
// use a stub storage: the defects they pin are all in how the bbolt transactions
// are opened and committed.
func openTestCacheFile(t *testing.T) *CacheFile {
	t.Helper()
	cacheFile := New(
		context.Background(),
		logger.NOP(),
		option.CacheFileOptions{
			Enabled:     true,
			Path:        filepath.Join(t.TempDir(), "cache.db"),
			StoreFakeIP: true,
		},
	)
	require.NoError(t, cacheFile.start())
	t.Cleanup(func() {
		db := cacheFile.database()
		if db != nil {
			require.NoError(t, db.Close())
		}
	})
	return cacheFile
}

func testFakeIPMetadata() *adapter.FakeIPMetadata {
	return &adapter.FakeIPMetadata{
		Inet4Range:   testFakeIPInet4Range,
		Inet6Range:   testFakeIPInet6Range,
		Inet4Current: netip.MustParseAddr("198.18.4.3"),
		Inet6Current: netip.MustParseAddr("fdfe:dcba:9876::3"),
	}
}

func requirePersistedFakeIPDomain(t *testing.T, cacheFile *CacheFile, address netip.Addr, domain string) {
	t.Helper()
	var persisted string
	require.NoError(t, cacheFile.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		persisted = string(bytes.Clone(bucket.Get(address.AsSlice())))
		return nil
	}))
	require.Equal(t, domain, persisted)
}

// FakeIPMetadata runs on the FakeIP store's Start path, and the store compares the
// cursor it returns against the configured ranges to decide whether to reuse the
// persisted state or reset the whole address bucket. The pre-fix implementation
// ran it as a write batch that deleted keyMetadata, so the cursor was one-shot:
// reading it twice (two stores over one cache file, or a Start that is not
// followed by an allocation) lost it, and the next read reset the range and
// re-issued addresses that were still in the address bucket.
func TestFakeIPMetadataReadIsNotConsuming(t *testing.T) {
	cacheFile := openTestCacheFile(t)
	metadata := testFakeIPMetadata()
	require.NoError(t, cacheFile.FakeIPSaveMetadata(metadata))

	first := cacheFile.FakeIPMetadata()
	require.NotNil(t, first, "the persisted cursor must be readable back")
	require.Equal(t, metadata, first)

	second := cacheFile.FakeIPMetadata()
	require.NotNil(t, second,
		"FakeIPMetadata consumed keyMetadata: a second read lost the cursor, so the next Start "+
			"would reset to the start of the range and re-issue live addresses")
	require.Equal(t, first, second)
}

// FakeIPMetadata is a read path but must not take the write lock. A read-only
// bbolt database rejects write transactions, so this fails on any implementation
// that still goes through c.batch. Besides the pointless write transaction on
// every start, that is what made the cursor deletion asynchronous: db.Batch is
// coalesced, so the delete could commit at an arbitrary later point (or not at
// all if the process died first).
func TestFakeIPMetadataReadDoesNotNeedWriteTransaction(t *testing.T) {
	cacheFile := openTestCacheFile(t)
	require.NoError(t, cacheFile.FakeIPSaveMetadata(testFakeIPMetadata()))

	require.NoError(t, cacheFile.DB.Close())
	readOnly, err := bbolt.Open(cacheFile.path, 0o666, &bbolt.Options{
		ReadOnly: true,
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	cacheFile.DB = readOnly

	require.NotNil(t, cacheFile.FakeIPMetadata(),
		"FakeIPMetadata opened a write transaction on a read path")
	require.NotNil(t, cacheFile.FakeIPMetadata())
}

// queueFakeIP must look up the mapping being replaced through FakeIPLoad, not only
// through the pending map. An address persisted by an earlier batch still has its
// domain in the on-disk reverse bucket, and the pre-fix code never saw that entry,
// so the stale domain kept resolving to an address that now belongs to a different
// domain until the next Flush happened to repair the bucket.
func TestQueueFakeIPShadowsPersistedMapping(t *testing.T) {
	cacheFile := openTestCacheFile(t)
	address := netip.MustParseAddr("198.18.4.7")
	require.NoError(t, cacheFile.FakeIPStore(address, "old.example"))
	requirePersistedFakeIPDomain(t, cacheFile, address, "old.example")

	// Re-map the address without flushing: the on-disk reverse entry is still there.
	cacheFile.FakeIPStoreAsync(address, "new.example", logger.NOP())

	domain, loaded := cacheFile.FakeIPLoadDomain("old.example", false)
	require.False(t, loaded,
		"old.example still resolved to %v after its address was re-mapped to new.example", domain)
	require.False(t, domain.IsValid())

	cacheFile.Flush()
	requirePersistedFakeIPDomain(t, cacheFile, address, "new.example")
	_, loaded = cacheFile.FakeIPLoadDomain("old.example", false)
	require.False(t, loaded, "the replaced domain must not come back after the flush")
}

// A forward entry can outlive its reverse entry: when the same domain is mapped to
// a second address, the reverse bucket moves to that address while the first
// address's forward entry still names the domain. Re-mapping the first address
// then finds a non-nil oldDomain in the forward bucket, and deleting the reverse
// entry unconditionally tears down the mapping the second address is still using,
// leaving that address live but unreachable by domain.
func TestPutFakeIPKeepsLiveReverseEntry(t *testing.T) {
	cacheFile := openTestCacheFile(t)
	first := netip.MustParseAddr("198.18.4.11")
	second := netip.MustParseAddr("198.18.4.12")
	require.NoError(t, cacheFile.FakeIPStore(first, "shared.example"))
	require.NoError(t, cacheFile.FakeIPStore(second, "shared.example"))

	address, loaded := cacheFile.FakeIPLoadDomain("shared.example", false)
	require.True(t, loaded)
	require.Equal(t, second, address)

	require.NoError(t, cacheFile.FakeIPStore(first, "moved.example"))

	address, loaded = cacheFile.FakeIPLoadDomain("shared.example", false)
	require.True(t, loaded,
		"re-mapping the first address deleted the live reverse entry of the second address")
	require.Equal(t, second, address)

	domain, loaded := cacheFile.FakeIPLoad(first)
	require.True(t, loaded)
	require.Equal(t, "moved.example", domain)
}
