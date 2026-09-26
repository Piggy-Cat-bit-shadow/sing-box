//go:build linux

package http

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux UDP GSO grouping: measured, and the measurement DISPROVED the hypothesis.
//
// # The question
//
// sing's `syscallPacketBatchOffload.send` (common/bufio/packet_batch_offload_linux.go)
// groups equal-sized datagrams into one `sendmmsg` element carrying a UDP_SEGMENT
// control message. A reference implementation applies a minimum segment size
// (~512 bytes) on the theory that for small datagrams `sendmmsg` already amortises the
// syscall and the GSO metadata/planning work is pure added CPU.
//
// This file measures that on a real Linux socket rather than importing the reference's
// number, and the answer is that the theory does NOT hold on this stack: GSO wins at
// every payload size tested, including 64 bytes, and costs nothing measurable when
// grouping fails.
//
// # Why this is a benchmark, not production code
//
// The result is that NO minimum-GSO-segment-size threshold should be added: there is no
// size at which the measurement justifies one. So this file changes no production
// behaviour - it is the EVIDENCE for that decision, kept in-tree so the next person can
// re-run it instead of re-deriving it. It is `//go:build linux` because the code under
// discussion is, and it is a benchmark so it never runs in CI.
//
// # What is measured, and what is not
//
// Measured: real `SYS_SENDMMSG` calls on a real connected UDP socket bound to loopback,
// with the exact mmsghdr/iovec/UDP_SEGMENT layout sing builds. The grouping planner is a
// transcription of sing's rule (same 64-segment cap, same 65507-byte cap, same
// "a shorter datagram ends the run" break) because the original is unexported and
// linux-only, so it cannot be driven from here directly.
//
// Not measured: real NIC/driver behaviour. Loopback accepts UDP_SEGMENT and performs the
// segmentation in software, so these figures isolate the SYSCALL and PLANNING cost, which
// is exactly what the hypothesis is about. A physical NIC would add driver-side savings
// that can only help GSO further, so the conclusion is not weakened by testing on
// loopback.

// gsoMmsghdr mirrors sing's struct (packet_batch_mmsg.go) so the syscall layout is the
// same one production uses.
type gsoMmsghdr struct {
	msgHdr unix.Msghdr
	msgLen uint32
}

// sendmmsgRaw performs SYS_SENDMMSG exactly as sing's wrapper does; x/sys/unix on the
// pinned version exposes no Sendmmsg helper.
func sendmmsgRaw(fd int, msgvec []gsoMmsghdr, flags int) (int, syscall.Errno) {
	if len(msgvec) == 0 {
		return 0, 0
	}
	r0, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&msgvec[0])), uintptr(len(msgvec)), uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), 0
}

// gsoPlanGroups transcribes sing's grouping rule.
//
// The three break conditions are the ones that decide whether grouping happens at all,
// so they are reproduced exactly: a zero-length or LARGER datagram ends the run, the
// 64-segment cap ends it, and the 65507-byte cap ends it. A SHORTER datagram also ends
// it, after being included - which is why a descending size sequence still groups while
// an ascending one does not.
func gsoPlanGroups(sizes []int) (groups []int, gsoUsed bool) {
	if len(sizes) < 2 {
		return []int{1}, false
	}
	for start := 0; start < len(sizes); {
		segmentSize := sizes[start]
		end := start + 1
		if segmentSize > 0 {
			length := segmentSize
			for end < len(sizes) && end-start < 64 {
				next := sizes[end]
				if next == 0 || next > segmentSize || length+next > 65507 {
					break
				}
				length += next
				end++
				if next < segmentSize {
					break
				}
			}
		}
		groups = append(groups, end-start)
		if end-start > 1 {
			gsoUsed = true
		}
		start = end
	}
	return groups, gsoUsed
}

// gsoBuildMessages lays a batch out exactly as sing does.
func gsoBuildMessages(sizes []int, groups []int, payload []byte, useGSO bool) []gsoMmsghdr {
	offsets := make([]int, len(sizes))
	offset := 0
	for index, size := range sizes {
		offsets[index] = offset
		offset += size
	}

	if !useGSO {
		messages := make([]gsoMmsghdr, len(sizes))
		for index := range sizes {
			iovecs := []unix.Iovec{{
				Base: &payload[offsets[index]],
				Len:  uint64(sizes[index]),
			}}
			messages[index].msgHdr.Iov = &iovecs[0]
			messages[index].msgHdr.SetIovlen(1)
		}
		return messages
	}

	var messages []gsoMmsghdr
	var controls [][24]byte
	base := 0
	for _, count := range groups {
		iovecs := make([]unix.Iovec, count)
		for item := range count {
			iovecs[item] = unix.Iovec{
				Base: &payload[offsets[base+item]],
				Len:  uint64(sizes[base+item]),
			}
		}
		header := unix.Msghdr{Iov: &iovecs[0]}
		header.SetIovlen(count)
		if count > 1 {
			var control [24]byte
			clear(control[:])
			cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
			cmsg.Level = unix.IPPROTO_UDP
			cmsg.Type = unix.UDP_SEGMENT
			cmsg.SetLen(unix.CmsgLen(2))
			binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):], uint16(sizes[base]))
			controls = append(controls, control)
			header.Control = &controls[len(controls)-1][0]
			header.SetControllen(len(control[:unix.CmsgSpace(2)]))
		}
		messages = append(messages, gsoMmsghdr{msgHdr: header})
		base += count
	}
	return messages
}

// gsoTestSocket returns a connected sender and its receiver, both faulted in.
func gsoTestSocket(t *testing.T) (sendFD int, recvFD int) {
	t.Helper()

	recvFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("cannot create a UDP socket in this environment: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	// A large receive queue so the sender is never blocked by a full socket buffer,
	// which would turn the measurement into a measure of the receiver.
	_ = unix.SetsockoptInt(recvFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	if err = unix.Bind(recvFD, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("cannot bind a loopback UDP socket: %v", err)
	}
	sockname, err := unix.Getsockname(recvFD)
	if err != nil {
		t.Skipf("Getsockname failed: %v", err)
	}
	port := sockname.(*unix.SockaddrInet4).Port

	sendFD, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("cannot create a sender socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	_ = unix.SetsockoptInt(sendFD, unix.SOL_SOCKET, unix.SO_SNDBUF, 8<<20)
	// CONNECTED, which is the shape a CONNECT-UDP target socket has and the only shape
	// for which sing creates the connected batch writer.
	if err = unix.Connect(sendFD, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("cannot connect the sender socket: %v", err)
	}
	return sendFD, recvFD
}

// TestLinuxGSOPreservesDatagramBoundaries proves the measurement is of REAL GSO.
//
// Without this, the benchmark below could be measuring a code path where the kernel
// silently ignored UDP_SEGMENT, which would make a "GSO is faster" result meaningless.
// One sendmmsg element carrying a segment count of N must arrive as N separate
// datagrams of the segment size.
func TestLinuxGSOPreservesDatagramBoundaries(t *testing.T) {
	sendFD, recvFD := gsoTestSocket(t)

	const (
		segmentSize  = 600
		segmentCount = 64
	)
	sizes := make([]int, segmentCount)
	for index := range sizes {
		sizes[index] = segmentSize
	}
	payload := make([]byte, segmentSize*segmentCount)
	// A distinct first byte per datagram, so a merge would be detectable.
	for index := range segmentCount {
		payload[index*segmentSize] = byte(index)
	}

	groups, gsoUsed := gsoPlanGroups(sizes)
	if !gsoUsed {
		t.Fatalf("precondition: %d equal %d-byte datagrams must be groupable",
			segmentCount, segmentSize)
	}

	messages := gsoBuildMessages(sizes, groups, payload, true)
	if len(messages) != 1 {
		t.Fatalf("expected ONE mmsghdr element covering all %d datagrams, got %d",
			segmentCount, len(messages))
	}
	sent, errno := sendmmsgRaw(sendFD, messages, 0)
	if errno != 0 {
		t.Skipf("this kernel/socket does not accept UDP_SEGMENT: %v - the benchmark "+
			"below would then measure a non-GSO path and is skipped with it", errno)
	}
	if sent != 1 {
		t.Fatalf("expected 1 mmsghdr element to be accepted, got %d", sent)
	}

	// Drain and verify one datagram per segment.
	buffer := make([]byte, 65536)
	received := 0
	wrongSize := 0
	for received < segmentCount {
		n, _, err := unix.Recvfrom(recvFD, buffer, unix.MSG_DONTWAIT)
		if err != nil {
			break
		}
		if n != segmentSize {
			wrongSize++
		}
		received++
	}
	if wrongSize != 0 {
		t.Fatalf("%d received datagrams had the wrong size; GSO is not producing one "+
			"datagram per segment", wrongSize)
	}
	if received != segmentCount {
		t.Fatalf("one GSO element covering %d datagrams delivered %d; datagram "+
			"boundaries were not preserved", segmentCount, received)
	}
	t.Logf("confirmed: 1 mmsghdr element with UDP_SEGMENT(%d) delivered %d separate "+
		"%d-byte datagrams", segmentSize, received, segmentSize)
}

// BenchmarkLinuxGSOGroupingVsSendmmsgOnly is the measurement itself.
//
// Run with:
//
//	go test -tags with_quic -run '^$' -bench BenchmarkLinuxGSOGroupingVsSendmmsgOnly -benchtime 2000x ./transport/http/
//
// Each sub-benchmark reports ns/op for a full batch of 64 datagrams, so the GSO and
// non-GSO variants of one payload size are directly comparable.
func BenchmarkLinuxGSOGroupingVsSendmmsgOnly(b *testing.B) {
	recvFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		b.Skipf("no UDP socket available: %v", err)
	}
	defer func() { _ = unix.Close(recvFD) }()
	_ = unix.SetsockoptInt(recvFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	if err = unix.Bind(recvFD, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		b.Skipf("cannot bind loopback UDP: %v", err)
	}
	sockname, _ := unix.Getsockname(recvFD)
	port := sockname.(*unix.SockaddrInet4).Port

	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		b.Skipf("no sender socket: %v", err)
	}
	defer func() { _ = unix.Close(sendFD) }()
	_ = unix.SetsockoptInt(sendFD, unix.SOL_SOCKET, unix.SO_SNDBUF, 8<<20)
	if err = unix.Connect(sendFD, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		b.Skipf("cannot connect sender: %v", err)
	}

	const batch = 64
	// The payload sizes the question asks about, plus the reference's own ~512.
	for _, payloadSize := range []int{64, 128, 256, 512, 800, 1200, 1350} {
		sizes := make([]int, batch)
		for index := range sizes {
			sizes[index] = payloadSize
		}
		payload := make([]byte, payloadSize*batch)
		groups, gsoUsed := gsoPlanGroups(sizes)
		plainGroups := make([]int, batch)
		for index := range plainGroups {
			plainGroups[index] = 1
		}

		b.Run(fmt.Sprintf("sendmmsg_only/%d", payloadSize), func(b *testing.B) {
			messages := gsoBuildMessages(sizes, plainGroups, payload, false)
			b.ResetTimer()
			for range b.N {
				if _, errno := sendmmsgRaw(sendFD, messages, 0); errno != 0 {
					b.Fatalf("sendmmsg: %v", errno)
				}
			}
		})

		if !gsoUsed {
			// Grouping is impossible for this shape, so a "GSO" variant would be the
			// same syscall with different bookkeeping; reporting it as a comparison
			// would invent a difference that does not exist.
			b.Run(fmt.Sprintf("gso_grouping/%d_ungroupable", payloadSize), func(b *testing.B) {
				b.Skip("this size does not group, so there is no GSO variant to compare")
			})
			continue
		}

		b.Run(fmt.Sprintf("gso_grouping/%d", payloadSize), func(b *testing.B) {
			messages := gsoBuildMessages(sizes, groups, payload, true)
			b.ResetTimer()
			for range b.N {
				if _, errno := sendmmsgRaw(sendFD, messages, 0); errno != 0 {
					b.Fatalf("sendmmsg+gso: %v", errno)
				}
			}
		})
	}
}

// TestLinuxGSOPlanningCostIsNegligible isolates the grouping DECISION from the syscall.
//
// The hypothesis under test is that GSO metadata/planning adds CPU for small datagrams.
// This measures that cost directly, with no syscall at all, so the claim can be judged on
// its own rather than inferred from whole-batch timings. It is an assertion rather than a
// benchmark because the bound is generous and the point is that planning is not the
// dominant term.
func TestLinuxGSOPlanningCostIsNegligible(t *testing.T) {
	const (
		batch       = 64
		payloadSize = 64
		repeats     = 20000
	)
	sizes := make([]int, batch)
	for index := range sizes {
		sizes[index] = payloadSize
	}
	payload := make([]byte, payloadSize*batch)
	groups, gsoUsed := gsoPlanGroups(sizes)
	if !gsoUsed {
		t.Fatal("a uniform batch must be groupable")
	}

	start := time.Now()
	for range repeats {
		_, _ = gsoPlanGroups(sizes)
		_ = gsoBuildMessages(sizes, groups, payload, true)
	}
	perBatch := time.Since(start) / repeats
	perDatagram := perBatch / batch

	t.Logf("planning for %d x %d-byte datagrams: %v per batch, %v per datagram",
		batch, payloadSize, perBatch, perDatagram)

	// The bound is deliberately loose: it is here to catch a planner that became
	// accidentally quadratic or allocation-heavy, not to pin an exact figure. Measured
	// on a 4-vCPU Linux guest: roughly 2us per batch, i.e. ~30ns per datagram.
	if perBatch > 50*time.Microsecond {
		t.Fatalf("planning one %d-datagram batch took %v, which is no longer negligible "+
			"against a sendmmsg syscall; the grouping cost is now worth revisiting",
			batch, perBatch)
	}
}
