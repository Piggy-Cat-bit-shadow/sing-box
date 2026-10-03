//go:build linux || darwin || (windows && (amd64 || 386))

//nolint:unused
package bridge

import (
	"context"
	"net/netip"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type sysctlState struct {
	name  string
	value string
}

type backendBase struct {
	ctx            context.Context
	logger         logger.ContextLogger
	networkManager adapter.NetworkManager
	tag            string

	index      uint32
	bridgeName string
	tunName    string
	inet4Port  netip.Addr
	inet6Port  netip.Addr

	boundInterface string

	tunInterface tun.Tun

	returnAccess sync.Mutex
	returnPaths  []tun.Return

	egressAccess sync.Mutex

	session       adapter.BridgeSession
	currentEgress string

	// indexAccess guards indexAcquired and index, so claiming and releasing a global slot is
	// idempotent rather than dependent on how many times Start and Close are called.
	indexAccess   sync.Mutex
	indexAcquired bool

	// closed is the scope's context channel, and readGroup joins the read loop. Both replace the
	// fork's own closeOnce/readDone pair: the scope already owns cancellation and teardown, so a
	// second, hand-rolled mechanism would be a parallel lifecycle for the same resource.
	closed    <-chan struct{}
	readGroup sync.WaitGroup
}

// init records the configuration. It deliberately acquires NOTHING.
//
// # Why the index is not claimed here
//
// A constructor does not own a running resource, and nothing ever closes an object that failed to
// be built: when a later part of startup fails, the object is discarded and Close is never called.
// Claiming a process-global slot in the constructor therefore leaked it permanently on every
// startup failure, and enough failures made bridge creation fail with a limit error the
// configuration had never reached.
//
// The index is claimed by acquireIndex, which Start calls and whose failure path releases it.
func (b *backendBase) init(ctx context.Context, logger logger.ContextLogger, networkManager adapter.NetworkManager, tag string, options option.BridgeOutboundOptions) {
	b.ctx = ctx
	b.logger = logger
	b.networkManager = networkManager
	b.tag = tag
	b.bridgeName = options.BridgeName
	if b.bridgeName == "" {
		b.bridgeName = "bridge"
	}
	b.boundInterface = options.Interface
}

// acquireIndex claims this bridge's global slot and the addresses derived from it.
//
// It is safe to call more than once: only the first call allocates, so a repeated Start cannot
// consume a second slot. It runs under indexAccess so the "already acquired" test and the claim are
// one operation.
//
// The caller registers releaseIndex with the scope, so the slot's lifetime is owned by the same
// mechanism that owns every other resource the object starts - not by how many times Close happens
// to run.
func (b *backendBase) acquireIndex() (uint32, error) {
	b.indexAccess.Lock()
	defer b.indexAccess.Unlock()
	if b.indexAcquired {
		return b.index, nil
	}
	index, err := allocateBridgeIndex()
	if err != nil {
		return 0, err
	}
	b.index = index
	b.indexAcquired = true
	b.inet4Port = addressAt(bridgeInet4Base, index)
	b.inet6Port = addressAt(bridgeInet6Base, index)
	return index, nil
}

// allocateIndex claims the slot and registers its release with the scope, so the scope owns the
// slot exactly as it owns every other resource. Claiming is idempotent, so a repeated Start cannot
// consume a second slot, and releasing is idempotent, so a failed start followed by Close cannot
// free a slot another bridge has taken.
func (b *backendBase) allocateIndex(scope *adapter.Scope) error {
	_, err := b.acquireIndex()
	if err != nil {
		return err
	}
	scope.Add(func() error {
		b.releaseIndex()
		return nil
	})
	return nil
}

// releaseIndex returns the slot. It is safe to call more than once, so a failed Start followed by
// Close cannot release a slot twice - which would free a slot another bridge may have taken.
func (b *backendBase) releaseIndex() {
	b.indexAccess.Lock()
	defer b.indexAccess.Unlock()
	if !b.indexAcquired {
		return
	}
	b.indexAcquired = false
	releaseBridgeIndex(b.index)
}

func (b *backendBase) PortAddresses() (netip.Addr, netip.Addr) {
	return b.inet4Port, b.inet6Port
}

func (b *backendBase) AttachReturn(returnPath tun.Return) error {
	b.returnAccess.Lock()
	defer b.returnAccess.Unlock()
	if slices.Contains(b.returnPaths, returnPath) {
		return nil
	}
	b.returnPaths = append(slices.Clip(b.returnPaths), returnPath)
	return nil
}

func (b *backendBase) DetachReturn(returnPath tun.Return) error {
	b.returnAccess.Lock()
	defer b.returnAccess.Unlock()
	returnPaths := make([]tun.Return, 0, len(b.returnPaths))
	for _, existing := range b.returnPaths {
		if existing != returnPath {
			returnPaths = append(returnPaths, existing)
		}
	}
	b.returnPaths = returnPaths
	return nil
}

func (b *backendBase) registerMonitors(scope *adapter.Scope, syncFunc func()) {
	networkMonitor := b.networkManager.NetworkMonitor()
	if networkMonitor != nil {
		networkElement := networkMonitor.RegisterCallback(syncFunc)
		scope.Add(func() error {
			networkMonitor.UnregisterCallback(networkElement)
			return nil
		})
	} else if b.boundInterface != "" {
		b.logger.Debug("network monitor unavailable, pinned egress will not track interface changes")
	}
	if b.boundInterface == "" {
		interfaceMonitor := b.networkManager.InterfaceMonitor()
		if interfaceMonitor != nil {
			interfaceElement := interfaceMonitor.RegisterCallback(func(_ *control.Interface, _ int) { syncFunc() })
			scope.Add(func() error {
				interfaceMonitor.UnregisterCallback(interfaceElement)
				return nil
			})
		}
	}
}

func (b *backendBase) syncSessionEgress() {
	b.egressAccess.Lock()
	defer b.egressAccess.Unlock()
	select {
	case <-b.closed:
		return
	default:
	}
	egress := b.resolveEgress()
	if egress == b.currentEgress {
		return
	}
	err := b.session.SetEgress(egress)
	if err != nil {
		b.logger.Debug(E.Cause(err, "apply bridge egress ", egress))
		return
	}
	b.currentEgress = egress
	if egress == "" {
		b.logger.Debug("bridge egress unavailable, dropping forwarded traffic")
	} else {
		b.logger.Debug("bridge egress ", egress)
	}
}

func (b *backendBase) resolveEgress() string {
	if b.boundInterface != "" {
		return b.boundInterface
	}
	monitor := b.networkManager.InterfaceMonitor()
	if monitor == nil {
		return ""
	}
	defaultInterface := monitor.DefaultInterface()
	if defaultInterface == nil {
		return ""
	}
	return defaultInterface.Name
}

func (b *backendBase) readLoop() {
	buffer := make([]byte, tun.PacketOffset+bridgeTunMTU)
	for {
		n, err := b.tunInterface.Read(buffer)
		if err != nil {
			select {
			case <-b.closed:
			default:
				b.logger.Debug(E.Cause(err, "bridge tun read"))
			}
			return
		}
		if n <= tun.PacketOffset {
			continue
		}
		packet := buffer[tun.PacketOffset:n]
		// On checksum-offloading NICs (notably virtio) the kernel leaves the L4
		// checksum uncomputed when the forwarding path TXes to a tun; recompute it.
		fixReturnChecksum(packet)
		b.deliverReturn(packet)
	}
}

func (b *backendBase) deliverReturn(packet []byte) {
	b.returnAccess.Lock()
	returnPaths := b.returnPaths
	b.returnAccess.Unlock()
	for _, returnPath := range returnPaths {
		headroom := returnPath.ReturnHeadroom()
		buffer := make([]byte, headroom+len(packet))
		copy(buffer[headroom:], packet)
		unconsumed := returnPath.ReturnPackets([][]byte{buffer})
		if len(unconsumed) == 0 {
			return
		}
	}
}
