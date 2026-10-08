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
// release's -checklinkname=0 is not needed for this one. If sing-vmess renames
// or reshapes the registry the link fails at build time; if it changes the
// callback signature, TestVisionRegistryABIStillMatchesSingVMess panics or
// fails instead of Vision silently reading the wrong memory.

import (
	"net"
	"reflect"
	"unsafe"

	"github.com/sagernet/sing-vmess/vless"
	N "github.com/sagernet/sing/common/network"
)

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
