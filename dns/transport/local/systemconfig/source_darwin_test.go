//go:build darwin && cgo

package systemconfig

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// The Darwin DNS reader's own contract.
//
// source_darwin.go reads the platform DNS configuration through the private libSystem
// dns_configuration_copy export and watches it with a notify_register_check / notify_check token on
// dns_configuration_notify_key. Those tests drive it through the sourcePlatform seam, so they can
// say "the resolver list changed" without reconfiguring the machine they run on.
//
// What they establish, and why each one matters to the network lifecycle:
//
//   - a changed resolver list reaches Configuration(), so the next request is served by the new
//     server rather than the old one;
//   - a notification carrying the SAME information returns the SAME *Config pointer, which is the
//     identity dns/transport/local/local_shared.go compares - so a duplicate notification does not
//     rebuild the server set, does not close its scope and does not drop the resolver sockets;
//   - Close releases the registration, exactly once.
//
// They deliberately say nothing about whether a resolver change is a network transition. It is not,
// and the DNS layer's own generation is what covers it (dns/dns_environment_generation_test.go).

// fakeResolver is one dnsinfo resolver as the platform reports it.
func fakeResolver(interfaceIndex int, servers []string, search []string) dnsInfoResolver {
	resolver := dnsInfoResolver{
		interfaceIndex: interfaceIndex,
		search:         search,
	}
	for _, server := range servers {
		resolver.servers = append(resolver.servers, M.SocksaddrFrom(netip.MustParseAddr(server), 53))
	}
	return resolver
}

// scriptedPlatform is a sourcePlatform whose snapshot and notification the test drives.
type scriptedPlatform struct {
	access sync.Mutex
	// resolvers is what the next snapshot returns.
	resolvers []dnsInfoResolver
	// readable selects whether the snapshot can be read at all.
	readable bool
	// pending is the notify flag: set by post, consumed by notification.
	pending bool
	// registered and deregisteredCount make the registration lifecycle observable.
	registered        bool
	deregisterCount   int
	deregisterTokens  []int
	notificationCalls int
}

func newScriptedPlatform(resolvers ...dnsInfoResolver) *scriptedPlatform {
	return &scriptedPlatform{resolvers: resolvers, readable: true}
}

// post delivers a change notification, exactly as the notify service would.
func (p *scriptedPlatform) post() {
	p.access.Lock()
	p.pending = true
	p.access.Unlock()
}

// seed replaces the platform's resolvers WITHOUT delivering a notification, which is how a test
// proves that the notification - not the passage of time - is what makes a change visible.
func (p *scriptedPlatform) seed(resolvers ...dnsInfoResolver) {
	p.access.Lock()
	p.resolvers = resolvers
	p.access.Unlock()
}

func (p *scriptedPlatform) seam() *sourcePlatform {
	return &sourcePlatform{
		register: func() (int, bool) {
			p.access.Lock()
			defer p.access.Unlock()
			p.registered = true
			return 7, true
		},
		snapshot: func() *dnsInfoConfig {
			p.access.Lock()
			defer p.access.Unlock()
			if !p.readable {
				return nil
			}
			return &dnsInfoConfig{resolvers: append([]dnsInfoResolver(nil), p.resolvers...)}
		},
		notification: func() (bool, bool) {
			p.access.Lock()
			defer p.access.Unlock()
			p.notificationCalls++
			changed := p.pending
			// notify_check CONSUMES the flag: the first call after a change reports it, later calls
			// report no change until the next post. Reproducing that here is what makes the
			// duplicate-notification test mean anything.
			p.pending = false
			return changed, true
		},
		deregister: func(token int) {
			p.access.Lock()
			defer p.access.Unlock()
			p.deregisterCount++
			p.deregisterTokens = append(p.deregisterTokens, token)
			p.registered = false
		},
	}
}

func newScriptedSource(platform *scriptedPlatform) *Source {
	return newSource(context.Background(), platform.seam())
}

// TestSourceNewResolverServesTheNextRequest is (B) at the reader.
//
// The resolver list changes and a notification is delivered. The next Configuration() must report
// the new servers, and it must return a DIFFERENT *Config pointer: that pointer identity is what
// dns/transport/local/local_shared.go compares (serverSetFor) to decide whether the server set has
// to be rebuilt from the new addresses.
func TestSourceNewResolverServesTheNextRequest(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, nil))
	source := newScriptedSource(platform)
	defer source.Close()

	before := source.Configuration()
	if got := serverStrings(before); !equalStrings(got, []string{"1.1.1.1:53"}) {
		t.Fatalf("initial servers = %v, want [1.1.1.1:53]", got)
	}

	// The resolver list genuinely changes and the platform notifies.
	platform.seed(fakeResolver(0, []string{"9.9.9.9"}, nil))
	platform.post()

	after := source.Configuration()
	if got := serverStrings(after); !equalStrings(got, []string{"9.9.9.9:53"}) {
		t.Fatalf("servers after the change = %v, want [9.9.9.9:53]: the notification was not "+
			"consumed, so the next request would still be sent to the previous resolver", got)
	}
	if after == before {
		t.Fatal("Configuration returned the SAME *Config after the resolver list changed. " +
			"serverSetFor compares that pointer, so the cached server set would be kept and the " +
			"new resolver would never be used")
	}
}

// TestSourceWithoutNotificationKeepsServingTheOldResolver is the other half of the same rule: the
// notification is what makes the change visible, not the passage of time.
//
// This is the shape of a missed notification, and it is why the DNS layer does not rely on this
// reader being pushed to: the aggregate observation in Router.observeDNSEnvironment reads it on
// every generation read, so a missed push is a delayed observation rather than a permanent one.
func TestSourceWithoutNotificationKeepsServingTheOldResolver(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, nil))
	source := newScriptedSource(platform)
	defer source.Close()

	before := source.Configuration()
	platform.seed(fakeResolver(0, []string{"9.9.9.9"}, nil))
	// No post(): the notify flag is not set.

	after := source.Configuration()
	if after != before {
		t.Fatal("Configuration re-read the platform without a notification, so the fast path is " +
			"not being taken and every DNS query would pay a full dnsinfo copy")
	}
	if got := serverStrings(after); !equalStrings(got, []string{"1.1.1.1:53"}) {
		t.Fatalf("servers = %v, want the pinned [1.1.1.1:53]", got)
	}
}

// TestSourceDuplicateNotificationDoesNotRebuild is (D) at the reader.
//
// A notification is not a state change. notify_check documents false positives for
// notify_register_check tokens, and the platform repeats itself, so a notification whose content is
// unchanged must not produce a new *Config - which is what would make serverSetFor close the live
// resolver scope and build a new one on every repetition.
func TestSourceDuplicateNotificationDoesNotRebuild(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, []string{"corp.example."}))
	source := newScriptedSource(platform)
	defer source.Close()

	pinned := source.Configuration()

	// A burst of duplicate notifications carrying the same information.
	for range 64 {
		platform.post()
		if got := source.Configuration(); got != pinned {
			t.Fatal("a duplicate notification produced a new *Config. serverSetFor would treat it " +
				"as a new resolver set, close the live server scope and rebuild it - a churn driven " +
				"entirely by the platform repeating itself")
		}
	}
}

// TestSourceSearchDomainOnlyChangeIsObserved is (C) at the reader: equal servers, a different
// search list.
func TestSourceSearchDomainOnlyChangeIsObserved(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, []string{"a.example."}))
	source := newScriptedSource(platform)
	defer source.Close()

	before := source.Configuration()

	platform.seed(fakeResolver(0, []string{"1.1.1.1"}, []string{"b.example."}))
	platform.post()

	after := source.Configuration()
	if got := after.Search; !equalStrings(got, []string{"b.example."}) {
		t.Fatalf("search domains = %v, want [b.example.]", got)
	}
	if after == before {
		t.Fatal("a search domain change produced the same *Config, so it is invisible to every " +
			"consumer of this reader")
	}
}

// TestSourceUnreadableSnapshot pins what "no DNS at all" resolves to, in both directions.
//
// Two distinct cases, and the reader treats them differently on purpose:
//
//   - the platform cannot be read and nothing has been read before: the source publishes
//     defaultServers, the loopback stub resolvers. It does NOT publish an empty list, because an
//     empty resolver list is not something a consumer can act on;
//   - the platform cannot be read AFTER a successful read: the last known reading is retained. A
//     read failure is not a configuration change, so it must not be reported as one - and it must
//     not advance the DNS generation, which is what a spurious "no resolvers" transition would do
//     on every DHCP renewal that briefly drops the configd entry.
func TestSourceUnreadableSnapshot(t *testing.T) {
	t.Run("nothing read yet", func(t *testing.T) {
		platform := newScriptedPlatform()
		platform.readable = false
		source := newScriptedSource(platform)
		defer source.Close()
		if got := serverStrings(source.Configuration()); !equalStrings(got, []string{"127.0.0.1:53", "[::1]:53"}) {
			t.Fatalf("servers with an unreadable platform = %v, want the loopback stub resolvers", got)
		}
	})

	t.Run("a reading is retained", func(t *testing.T) {
		platform := newScriptedPlatform(fakeResolver(0, []string{"9.9.9.9"}, nil))
		source := newScriptedSource(platform)
		defer source.Close()
		if got := serverStrings(source.Configuration()); !equalStrings(got, []string{"9.9.9.9:53"}) {
			t.Fatalf("servers = %v", got)
		}

		platform.access.Lock()
		platform.readable = false
		platform.access.Unlock()
		platform.post()

		got := serverStrings(source.Configuration())
		if !equalStrings(got, []string{"9.9.9.9:53"}) {
			t.Fatalf("servers after a read failure = %v, want the last known reading [9.9.9.9:53]: "+
				"a failed read is not a configuration change, and reporting it as one would retire "+
				"every in-flight verdict on a transient failure", got)
		}
	})
}

// TestSourceCloseDeregistersTheWatcher proves the registration is released exactly once.
//
// A notify token is a finite resource and the registration is what makes the source observable, so
// a source that never released it would leak one per transport the box ever built - and a stale
// registration would keep receiving notifications for a reader nothing owns.
func TestSourceCloseDeregistersTheWatcher(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, nil))
	source := newScriptedSource(platform)

	platform.access.Lock()
	registered := platform.registered
	platform.access.Unlock()
	if !registered {
		t.Fatal("the source did not register for notifications at construction")
	}

	if err := source.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	platform.access.Lock()
	defer platform.access.Unlock()
	if platform.deregisterCount != 1 {
		t.Fatalf("deregistration count = %d, want exactly 1: Close is not idempotent, or it never "+
			"released the registration", platform.deregisterCount)
	}
	if platform.registered {
		t.Fatal("the source is still registered after Close")
	}
	if len(platform.deregisterTokens) != 1 || platform.deregisterTokens[0] != 7 {
		t.Fatalf("deregistered tokens = %v, want [7] - the token the registration returned",
			platform.deregisterTokens)
	}
}

// TestSourceResetForcesAReRead is the seam the network reset relies on.
//
// Transport.Reset calls Source.Reset, which marks the reading stale so the next Configuration
// re-reads the platform even with no notification. That is what makes a resolver change that
// arrived without a notification visible after a network transition.
func TestSourceResetForcesAReRead(t *testing.T) {
	platform := newScriptedPlatform(fakeResolver(0, []string{"1.1.1.1"}, nil))
	source := newScriptedSource(platform)
	defer source.Close()

	before := source.Configuration()
	platform.seed(fakeResolver(0, []string{"9.9.9.9"}, nil))
	// No notification. Only Reset.
	source.Reset()

	after := source.Configuration()
	if after == before {
		t.Fatal("Reset did not force a re-read, so a resolver change delivered without a " +
			"notification would never be observed at all")
	}
	if got := serverStrings(after); !equalStrings(got, []string{"9.9.9.9:53"}) {
		t.Fatalf("servers after Reset = %v, want [9.9.9.9:53]", got)
	}
}

func serverStrings(config *Config) []string {
	if config == nil {
		return nil
	}
	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		servers = append(servers, server.String())
	}
	return servers
}

func equalStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
