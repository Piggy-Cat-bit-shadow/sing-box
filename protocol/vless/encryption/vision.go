// This file is adapted from github.com/starifly/sing-box
// (protocol/vless/encryption), the upstream this code originates from, via the
// reference fork github.com/Leadaxe/sing-box-lx
// (protocol/vless/encryption). Both are GPL-3.0, the same license as this
// repository, and share its upstream base.

package encryption

// Let flow `xtls-rprx-vision` run on top of this layer.
//
// Vision in sing-vmess finds the TLS conn beneath it through a private registry
// that only knows crypto/tls and utls, so a *CommonConn was rejected with
// "not a valid supported TLS connection". Xray treats CommonConn like a TLS
// conn: Vision reads its input/rawInput fields, and direct copy goes to the
// conn beneath the encryption layer (proxy.UnwrapRawConn). One registry entry
// gives sing-vmess the same view.
//
// The registry is unexported, so the entry is appended through a go:linkname
// pull. Go's linkname check examines standard-library symbols only, so the
// release's -checklinkname=0 is not needed for this one.
//
// A linkname pull is NOT a build-time guard here, and the difference matters: on
// go1.25.5 a target that no longer exists does not fail the link. The linker
// leaves the local declaration as a fresh, zeroed slice, so the package still
// builds, init appends our entry to a slice nobody reads, and Vision keeps
// rejecting *CommonConn with "not a valid supported TLS connection" — far from
// the dependency bump that caused it. The runtime length check in
// vision_tripwire_test.go is therefore the detector for a renamed or reshaped
// registry, and the source-shape check there names the declaration that moved.
//
// None of that is self-describing at the point it happens, and the silent
// failure mode — Vision reflecting a field name or offset that no longer means
// what this package thinks — is worse than a crash. vision_tripwire_test.go is
// therefore the CI-visible audit: it fails, with an instruction, on any change
// to the pinned version above, to the registry's shape, to the callback
// signature, or to the CommonConn ABI in common.go.

import (
	"net"
	"reflect"
	"unsafe"

	"github.com/sagernet/sing-vmess/vless"
	N "github.com/sagernet/sing/common/network"
)

// expectedSingVMessVersion is the sing-vmess commit this bridge was audited
// against. The go:linkname below, the callback signature declared for it, and
// the input/rawInput layout in common.go are one contract with one build of the
// dependency: a bump can rename the registry (which links silently to an empty
// slice, see above), reshape the callback (a call through the wrong function
// type), or change which fields Vision reflects (Vision reads unrelated memory
// and fails far from here). TestVisionTripwireSingVMessVersion compares this
// constant against the version go.mod requires, so a dependency bump fails CI
// until the bridge is re-audited and this constant is deliberately updated.
const expectedSingVMessVersion = "v0.2.9-0.20260929152519-9b95ab8c9478"

// Importing vless above runs its init first, so the entry lands after the
// built-in crypto/tls and utls ones.
var _ = vless.FlowVision

//go:linkname visionTLSRegistry github.com/sagernet/sing-vmess/vless.tlsRegistry
var visionTLSRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	visionTLSRegistry = append(visionTLSRegistry, castVisionConn)
}

// castVisionConn presents a *CommonConn to Vision as a TLS-shaped conn: Vision
// gets the conn beneath the encryption layer for its direct copy, and the
// struct's input/rawInput fields (the ABI pinned in common.go) for its own
// bookkeeping.
func castVisionConn(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
	commonConn, loaded := N.CastReader[*CommonConn](conn)
	if !loaded {
		return
	}
	return true, commonConn.Conn, reflect.TypeOf(commonConn).Elem(), uintptr(unsafe.Pointer(commonConn))
}
