package dialer

import (
	"context"
	"net"
	"net/netip"
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func DialSerialNetwork(ctx context.Context, dialer N.Dialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if len(destinationAddresses) == 0 {
		if !destination.IsIP() {
			panic("invalid usage")
		}
		destinationAddresses = []netip.Addr{destination.Addr}
	}
	if parallelDialer, isParallel := dialer.(ParallelNetworkDialer); isParallel {
		return parallelDialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	var errors []error
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		for _, address := range destinationAddresses {
			conn, err := parallelDialer.DialParallelInterface(ctx, network, M.SocksaddrFrom(address, destination.Port), strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
			if err == nil {
				return conn, nil
			}
			errors = append(errors, err)
		}
	} else {
		for _, address := range destinationAddresses {
			conn, err := dialer.DialContext(ctx, network, M.SocksaddrFrom(address, destination.Port))
			if err == nil {
				return conn, nil
			}
			errors = append(errors, err)
		}
	}
	return nil, E.Errors(errors...)
}

// DialParallelNetwork races the candidate addresses for one connection.
//
// # What changed
//
// This used to split candidates into two family groups and call DialSerialNetwork on each.
// Within a family the addresses were therefore attempted one at a time, so a blackholed
// address cost the whole connect timeout before the next was tried; and because an empty
// family fell through to pure serial, a connection whose candidates were all in one family
// had no racing at all - which is the common case whenever only one family resolved.
//
// Candidates are now interleaved and scheduled by the shared candidate scheduler: the first
// starts immediately, one more starts per fallback delay, and a definite path failure
// advances the schedule at once instead of waiting out a delay for an answer already known
// to be no.
//
// The interface and strategy arguments are unchanged; they select the per-attempt dialer.
func DialParallelNetwork(ctx context.Context, dialer ParallelInterfaceDialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	return dialParallelNetwork(ctx, dialer, network, destination, destinationAddresses, preferIPv6, strategy, interfaceType, fallbackInterfaceType, fallbackDelay, nil, 0)
}

// dialParallelNetwork is the health-aware form. The exported function keeps its signature so
// existing callers are unaffected, and passes no health; callers that own family state use
// this one.
func dialParallelNetwork(ctx context.Context, dialer ParallelInterfaceDialer, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, preferIPv6 bool, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration, health *familyHealth, networkEnvironment uint64) (net.Conn, error) {
	if len(destinationAddresses) == 0 {
		if !destination.IsIP() {
			panic("invalid usage")
		}
		destinationAddresses = []netip.Addr{destination.Addr}
	}

	domainStrategy := C.DomainStrategyPreferIPv4
	if preferIPv6 {
		domainStrategy = C.DomainStrategyPreferIPv6
	}
	plan := planCandidates(destinationAddresses, netip.Addr{}, domainStrategy)

	// Health comes from the dialer that owns the underlay, so the verdict survives across
	// connections instead of being relearned every time. The parameter carries it because
	// this is a free function; the alternative - a package-level variable - would share one
	// network's verdict with every dialer in the process.
	scheduler := &candidateScheduler{
		fallbackDelay:      fallbackDelay,
		health:             health,
		networkEnvironment: networkEnvironment,
	}
	conn, _, err := scheduler.dial(ctx, plan, func(attemptCtx context.Context, address netip.Addr) (net.Conn, error) {
		// Each attempt keeps the full configuration the caller supplied: the network
		// strategy, the interface selection and the fallback interface selection. Racing
		// chooses WHICH address to try, never how to try it.
		attemptDestination := M.SocksaddrFrom(address, destination.Port)
		return dialer.DialParallelInterface(attemptCtx, network, attemptDestination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func ListenSerialNetworkPacket(ctx context.Context, dialer N.Dialer, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if len(destinationAddresses) == 0 {
		if !destination.IsIP() {
			panic("invalid usage")
		}
		destinationAddresses = []netip.Addr{destination.Addr}
	}
	if parallelDialer, isParallel := dialer.(ParallelNetworkDialer); isParallel {
		return parallelDialer.ListenSerialNetworkPacket(ctx, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	var errors []error
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		for _, address := range destinationAddresses {
			conn, err := parallelDialer.ListenSerialInterfacePacket(ctx, M.SocksaddrFrom(address, destination.Port), strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
			if err == nil {
				return conn, address, nil
			}
			errors = append(errors, err)
		}
	} else {
		for _, address := range destinationAddresses {
			conn, err := dialer.ListenPacket(ctx, M.SocksaddrFrom(address, destination.Port))
			if err == nil {
				return conn, address, nil
			}
			errors = append(errors, err)
		}
	}
	return nil, netip.Addr{}, E.Errors(errors...)
}
