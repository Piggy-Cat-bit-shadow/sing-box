package route

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.searchProcessInfo(ctx, &metadata)
	metadata.Destination = M.Socksaddr{}
	err := N.ReportConnHandshakeSuccess(conn, conn)
	if err != nil {
		return E.Cause(err, "report handshake success")
	}
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err = dnsOutbound.HandleStreamDNSRequest(ctx, r.dns, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	r.searchProcessInfo(ctx, &metadata)
	err := N.ReportPacketConnHandshakeSuccess(conn, nil)
	if err != nil {
		N.ReleaseMultiPacketBuffer(packetBuffers)
		err = E.Cause(err, "report handshake success")
	} else {
		err = dnsOutbound.NewDNSPacketConnection(ctx, r.dns, conn, packetBuffers, metadata)
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

func (r *Router) dispatchDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	var message mDNS.Msg
	err := message.Unpack(payload)
	if err != nil {
		r.logger.ErrorContext(ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	r.searchProcessInfo(ctx, &metadata)
	destination := metadata.Destination
	metadata.Destination = M.Socksaddr{}
	r.dns.ExchangeAsync(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, exchangeErr error) {
		if exchangeErr == nil {
			exchangeErr = r.writeDNSPacketResponse(&message, response, writer, destination)
		}
		if exchangeErr != nil && !R.IsRejected(exchangeErr) && !E.IsClosedOrCanceled(exchangeErr) {
			r.logger.ErrorContext(ctx, E.Cause(exchangeErr, "process DNS packet"))
		}
	})
}

// dnsHijackConcurrency bounds how many hijacked DNS packets may be resolved at once.
//
// The bound exists because the alternative to blocking the packet loop must not be an unbounded
// number of goroutines: every parked packet is holding a DNS query that may sit for the whole
// DNS timeout (C.DNSTimeout) waiting on a dial. A cap turns a pathological DNS flood against a
// dead resolver into dropped packets the client retries, instead of memory that grows until the
// device kills the process.
const dnsHijackConcurrency = 256

// HijackDNSPacket hands a hijacked DNS packet to the DNS router WITHOUT waiting for it.
//
// # Why this is not simply a call into the router
//
// The caller is the packet loop of the tun stack: sing-tun's ForwardDispatcher and the gvisor
// UDP forwarder both invoke this inline from the goroutine that dispatches every forwarded
// packet. The chain below (DNS router -> adapter.DNSClient.ExchangeAsync -> transport acquire)
// is asynchronous only in its DELIVERY; the enqueue itself waits for the transport to be
// acquired, and acquiring it dials the resolver's detour outbound.
//
// One legal configuration therefore stalls the whole tunnel: a DNS server whose `detour` points
// at an outbound the network silently drops. The dial sits until the DNS timeout - ten seconds -
// and for that whole time nothing else in the packet loop runs: other DNS servers, ICMP, packet
// forwarding, every new TCP flow. Nothing logs an error, because nothing failed; everything is
// waiting. Releasing the loop on dial timeout is also what produces the "works for a minute,
// dies for four" waves seen in the field.
//
// # Why the payload is unpacked inside the goroutine
//
// The packet buffer behind payload belongs to the stack and is only valid until this function
// returns. Moving the unpack into the goroutine would read a recycled buffer. Parsing here and
// passing the copied message keeps the payload's lifetime confined to this call.
//
// # Why a semaphore rather than one goroutine per packet
//
// Unbounded is the other half of the same bug in the opposite direction: a resolver that is dead
// for ten seconds turns a modest query rate into thousands of parked goroutines. Over the cap
// the packet is dropped, which is correct for UDP DNS - the client retries - and is logged.
func (r *Router) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	var message mDNS.Msg
	err := message.Unpack(payload)
	if err != nil {
		r.logger.ErrorContext(ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	for {
		inFlight := r.dnsHijackInFlight.Load()
		if inFlight >= dnsHijackConcurrency {
			// Over the cap: the resolver has this many queries already parked, so it is not
			// answering and another one would only add pressure. A dropped UDP query is retried
			// by the client, which is strictly better than stalling the loop that would have
			// carried the retry.
			r.logger.DebugContext(ctx, "dropping hijacked DNS packet: ", dnsHijackConcurrency, " already in flight")
			return
		}
		if r.dnsHijackInFlight.CompareAndSwap(inFlight, inFlight+1) {
			break
		}
	}
	go func() {
		defer r.dnsHijackInFlight.Add(-1)
		r.dispatchDNSPacket(ctx, payload, writer, metadata)
	}()
}

func (r *Router) writeDNSPacketResponse(message *mDNS.Msg, response *mDNS.Msg, writer N.PacketWriter, destination M.Socksaddr) error {
	responseBuffer, err := dns.TruncateDNSMessage(message, response, N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer))
	if err != nil {
		return err
	}
	return writer.WritePacket(responseBuffer, destination)
}
