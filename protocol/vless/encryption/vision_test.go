package encryption

import (
	"bytes"
	"crypto/tls"
	"net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-vmess/vless"

	"github.com/stretchr/testify/require"
)

// Vision over the encryption layer: sing-vmess finds the TLS conn beneath a
// flow through a private registry that only knows crypto/tls and utls, so a
// *CommonConn was rejected with "not a valid supported TLS connection" and
// `flow: xtls-rprx-vision` on an encrypted node never connected. vision.go
// appends one entry to that registry; these tests pin the view it gives Vision.
//
// The registry lookup — not the NewVisionConn wrapper — is what this port owns,
// so it is asserted here directly. NewVisionConn itself performs
// `unsafe.Pointer(uintptr + offset)` inside sing-vmess, which the race
// detector's checkptr rejects for every registered conn type (the built-in
// crypto/tls entry included); the end-to-end call is therefore compile-excluded
// under -race in vision_checkptr_test.go rather than deleted.

// The registry finds a *CommonConn, hands Vision the conn beneath the
// encryption layer, and exposes the input/rawInput fields Vision reads by name
// and offset.
func TestVisionRegistryFindsCommonConn(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	commonConn := NewCommonConn(inner, false)

	loaded, netConn, reflectType, reflectPointer := castVisionConn(commonConn)
	require.True(t, loaded, "castVisionConn did not load *CommonConn")
	require.Equal(t, net.Conn(inner), netConn, "direct copy conn must be the conn beneath the encryption layer")

	input, ok := reflectType.FieldByName("input")
	require.True(t, ok, "CommonConn.input is missing")
	require.Equal(t, reflect.TypeOf(bytes.Reader{}), input.Type, "CommonConn.input must stay bytes.Reader")

	rawInput, ok := reflectType.FieldByName("rawInput")
	require.True(t, ok, "CommonConn.rawInput is missing")
	require.Equal(t, reflect.TypeOf(bytes.Buffer{}), rawInput.Type, "CommonConn.rawInput must stay bytes.Buffer")

	require.Equal(t, reflect.ValueOf(&commonConn.input).Pointer(), reflectPointer+input.Offset,
		"input offset does not point at CommonConn.input")
	require.Equal(t, reflect.ValueOf(&commonConn.rawInput).Pointer(), reflectPointer+rawInput.Offset,
		"rawInput offset does not point at CommonConn.rawInput")

	// The reference ABI declares rawInput before input; a reorder changes the
	// offsets that Xray-compatible code assumes even though Vision itself looks
	// fields up by name.
	require.Less(t, rawInput.Offset, input.Offset, "CommonConn field order changed")
}

// A plain conn is still rejected, so the entry does not widen Vision beyond
// TLS-like conns.
func TestVisionRejectsPlainConn(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()

	_, err := vless.NewVisionConn(inner, inner, [16]byte{}, nil)
	require.Error(t, err, "NewVisionConn accepted a plain conn")
}

// The linkname target still exists with the expected shape and holds our entry.
// A sing-vmess bump that renames the registry fails the link at build time; a
// bump that reshapes the callback fails here instead of silently handing Vision
// a function value called with the wrong frame.
func TestVisionRegistryHoldsCommonConn(t *testing.T) {
	t.Parallel()

	for _, entry := range visionTLSRegistry {
		if reflect.ValueOf(entry).Pointer() == reflect.ValueOf(castVisionConn).Pointer() {
			return
		}
	}
	t.Fatal("castVisionConn is not in sing-vmess vless.tlsRegistry")
}

// TestVisionRegistryABIStillMatchesSingVMess is the sentinel for the pinned
// sing-vmess: the registry element type is declared in vision.go, so if the
// dependency changes that callback's shape our declaration would still link and
// the built-in entries would be invoked through the wrong signature. Driving
// the built-in crypto/tls entry through this package's view of the slice makes
// such a change fail loudly here.
func TestVisionRegistryABIStillMatchesSingVMess(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	// A *tls.Conn wrapper without a handshake is enough: the built-in registry
	// entry only unwraps it.
	tlsConn := tls.Client(inner, &tls.Config{InsecureSkipVerify: true})

	require.GreaterOrEqual(t, len(visionTLSRegistry), 2,
		"sing-vmess vless.tlsRegistry lost the built-in entries this package appends to")

	var loadedTLS bool
	for _, entry := range visionTLSRegistry {
		loaded, netConn, reflectType, reflectPointer := entry(tlsConn)
		if !loaded {
			continue
		}
		loadedTLS = true
		require.Equal(t, reflect.TypeOf(tlsConn).Elem(), reflectType)
		require.Equal(t, net.Conn(inner), netConn, "the built-in entry must unwrap to the conn beneath tls.Conn")
		require.Equal(t, uintptr(unsafe.Pointer(tlsConn)), reflectPointer)
	}
	require.True(t, loadedTLS,
		"no tlsRegistry entry recognised *tls.Conn any more: the callback signature this package declares "+
			"no longer matches the pinned sing-vmess")
}
