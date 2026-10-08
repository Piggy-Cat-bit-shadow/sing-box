package cachefile

import (
	"bytes"
	"net/netip"
	"os"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const fakeipBucketPrefix = "fakeip_"

var (
	bucketFakeIP        = []byte(fakeipBucketPrefix + "address")
	bucketFakeIPDomain4 = []byte(fakeipBucketPrefix + "domain4")
	bucketFakeIPDomain6 = []byte(fakeipBucketPrefix + "domain6")
	keyMetadata         = []byte(fakeipBucketPrefix + "metadata")
)

// FakeIPMetadata reads the persisted address cursor without consuming it. This runs
// on the FakeIP store's Start path, so it must stay a read-only view: the previous
// implementation used a write batch that deleted the key, which took the single
// write lock during startup and destroyed the only persisted copy of the cursor.
// The delete is committed before the call returns, so afterwards the cursor exists
// only in the caller's memory until the store saves it again (the next reserved
// window, or Close). A process that died in between left no metadata at all, and
// the next Start then takes the metadata == nil branch, resets the whole FakeIP
// bucket, and starts re-issuing from the beginning of the range — wiping every
// cached domain mapping and handing addresses to different domains while clients
// may still resolve the old ones.
func (c *CacheFile) FakeIPMetadata() *adapter.FakeIPMetadata {
	var metadata adapter.FakeIPMetadata
	err := c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return os.ErrNotExist
		}
		metadataBinary := bucket.Get(keyMetadata)
		if len(metadataBinary) == 0 {
			return os.ErrInvalid
		}
		return metadata.UnmarshalBinary(metadataBinary)
	})
	if err != nil {
		return nil
	}
	return &metadata
}

// FakeIPSaveMetadata stages the cursor and flushes immediately. Flush takes
// pendingAccess itself, so the lock is released explicitly before calling it
// (a defer would deadlock). The caller — the FakeIP store — only calls this once
// per reserved address window plus once on Close, so blocking here is cheap and
// keeps the cursor on disk ahead of the addresses issued from that window.
func (c *CacheFile) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	c.pendingAccess.Lock()
	added := c.pending.fakeIPMetadata == nil
	c.pending.fakeIPMetadata = metadata
	c.enqueueLocked(added, 0)
	c.pendingAccess.Unlock()
	c.Flush()
	return nil
}

func putFakeIPMetadata(tx *bbolt.Tx, metadata *adapter.FakeIPMetadata) error {
	bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
	if err != nil {
		return err
	}
	metadataBinary, err := metadata.MarshalBinary()
	if err != nil {
		return err
	}
	return bucket.Put(keyMetadata, metadataBinary)
}

func (c *CacheFile) FakeIPStore(address netip.Addr, domain string) error {
	c.queueFakeIP(address, domain)
	c.Flush()
	return nil
}

func (c *CacheFile) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
	c.queueFakeIP(address, domain)
}

// queueFakeIP records a new address allocation in the pending batch. The replaced
// mapping is looked up through FakeIPLoad, not just through the pending map: the
// address may already be persisted by an earlier batch, in which case the old
// domain still exists in the on-disk reverse bucket and would otherwise be handed
// out (and size-accounted) as if it were still live. The old domain's reverse
// entry is left as an explicit tombstone rather than deleted, because putFakeIP
// may legitimately keep the on-disk entry (the domain may have been re-mapped to
// another address since), and a plain delete would then let the stale on-disk
// address leak back out through FakeIPLoadDomain.
func (c *CacheFile) queueFakeIP(address netip.Addr, domain string) {
	oldDomain, loaded := c.FakeIPLoad(address)
	c.pendingAccess.Lock()
	defer c.pendingAccess.Unlock()
	if loaded {
		if address.Is4() {
			c.pending.fakeIPAddress4[oldDomain] = netip.Addr{}
		} else {
			c.pending.fakeIPAddress6[oldDomain] = netip.Addr{}
		}
	}
	pendingDomain, pendingLoaded := c.pending.fakeIPDomain[address]
	c.pending.fakeIPDomain[address] = domain
	if address.Is4() {
		c.pending.fakeIPAddress4[domain] = address
	} else {
		c.pending.fakeIPAddress6[domain] = address
	}
	c.enqueueLocked(!pendingLoaded, len(domain)-len(pendingDomain))
}

func putFakeIP(tx *bbolt.Tx, address netip.Addr, domain string) error {
	bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
	if err != nil {
		return err
	}
	addressBytes := address.AsSlice()
	oldDomain := bucket.Get(addressBytes)
	err = bucket.Put(addressBytes, []byte(domain))
	if err != nil {
		return err
	}
	if address.Is4() {
		bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain4)
	} else {
		bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain6)
	}
	if err != nil {
		return err
	}
	// A forward entry can outlive its reverse entry: the same domain may have been
	// re-mapped to another address (which overwrote the reverse bucket) while this
	// address still points at it in the forward bucket. Deleting the reverse entry
	// here unconditionally would tear down a mapping that is still live for the
	// other address, so only delete it when it still points back at this address.
	if oldDomain != nil && bytes.Equal(bucket.Get(oldDomain), addressBytes) {
		err = bucket.Delete(oldDomain)
		if err != nil {
			return err
		}
	}
	return bucket.Put([]byte(domain), addressBytes)
}

func (c *CacheFile) FakeIPLoad(address netip.Addr) (string, bool) {
	c.pendingAccess.RLock()
	domain, cached := c.pending.fakeIPDomain[address]
	if !cached && c.writing != nil {
		domain, cached = c.writing.fakeIPDomain[address]
	}
	c.pendingAccess.RUnlock()
	if cached {
		return domain, true
	}
	_ = c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		domain = string(bucket.Get(address.AsSlice()))
		return nil
	})
	return domain, domain != ""
}

func (p *pendingWrites) fakeIPAddress(domain string, isIPv6 bool) (netip.Addr, bool) {
	if isIPv6 {
		address, loaded := p.fakeIPAddress6[domain]
		return address, loaded
	}
	address, loaded := p.fakeIPAddress4[domain]
	return address, loaded
}

func (c *CacheFile) FakeIPLoadDomain(domain string, isIPv6 bool) (netip.Addr, bool) {
	c.pendingAccess.RLock()
	address, cached := c.pending.fakeIPAddress(domain, isIPv6)
	if !cached && c.writing != nil {
		address, cached = c.writing.fakeIPAddress(domain, isIPv6)
	}
	c.pendingAccess.RUnlock()
	if cached {
		// A pending entry with an invalid address is a tombstone written by
		// queueFakeIP for a domain whose mapping was replaced; report it as not
		// loaded so the caller falls through to a fresh policy evaluation instead
		// of resolving the domain to a stale on-disk address.
		return address, address.IsValid()
	}
	_ = c.view(func(tx *bbolt.Tx) error {
		var bucket *bbolt.Bucket
		if isIPv6 {
			bucket = tx.Bucket(bucketFakeIPDomain6)
		} else {
			bucket = tx.Bucket(bucketFakeIPDomain4)
		}
		if bucket == nil {
			return nil
		}
		address = M.AddrFromIP(bucket.Get([]byte(domain)))
		return nil
	})
	return address, address.IsValid()
}

func (c *CacheFile) FakeIPReset() error {
	c.flushAccess.Lock()
	defer c.flushAccess.Unlock()
	c.pendingAccess.Lock()
	for _, domain := range c.pending.fakeIPDomain {
		c.pending.count--
		c.pending.size -= len(domain)
	}
	clear(c.pending.fakeIPDomain)
	clear(c.pending.fakeIPAddress4)
	clear(c.pending.fakeIPAddress6)
	if c.pending.fakeIPMetadata != nil {
		c.pending.fakeIPMetadata = nil
		c.pending.count--
	}
	c.pendingAccess.Unlock()
	return c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIP, bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			err := tx.DeleteBucket(bucketName)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
