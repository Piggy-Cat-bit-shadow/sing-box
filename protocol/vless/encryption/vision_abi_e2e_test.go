//go:build !race

package encryption

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-vmess/vless"

	"github.com/stretchr/testify/require"
)

// TestVisionTripwireVisionConnAliasesCommonConnFields is the end-to-end half of
// the Vision tripwire, and it is excluded from -race for the same reason
// vision_checkptr_test.go is: NewVisionConn computes
// `unsafe.Pointer(uintptr(unsafe.Pointer(conn)) + field.Offset)`, and the uintptr
// crossed a function boundary (the registry callback's return value), so the
// race detector's checkptr aborts for EVERY registered conn type — the built-in
// crypto/tls entry included. That is a property of the pinned sing-vmess, not of
// this port.
//
// What this test adds over the registry checks in vision_tripwire_test.go is the
// dependency's own half of the ABI: after NewVisionConn has reflected on our
// *CommonConn and reinterpreted the two fields, its VisionConn.input and
// VisionConn.rawInput pointers must alias OUR fields exactly. If sing-vmess
// looked those fields up under different names, reflect.FieldByName would return
// a zero StructField with Offset 0 and the pointer would be the *CommonConn
// itself (or whatever sits at that offset) instead of the field — silently
// wrong memory, which is the failure this whole tripwire exists to make loud.
func TestVisionTripwireVisionConnAliasesCommonConnFields(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	commonConn := NewCommonConn(inner, false)

	visionConn, err := vless.NewVisionConn(commonConn, commonConn, [16]byte{}, nil)
	require.NoError(t, err, "sing-vmess NewVisionConn over *CommonConn; "+visionAuditInstruction)

	visionType := reflect.TypeOf(visionConn).Elem()
	require.Equal(t, "vless.VisionConn", visionType.String(),
		"the type NewVisionConn returns is no longer vless.VisionConn; "+visionAuditInstruction)

	inputField, inputFound := visionType.FieldByName("input")
	require.True(t, inputFound, "sing-vmess vless.VisionConn lost its \"input\" field; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf((*bytes.Reader)(nil)), inputField.Type,
		"sing-vmess vless.VisionConn.input changed type; the CommonConn field it aliases must change to match; "+visionAuditInstruction)

	rawInputField, rawInputFound := visionType.FieldByName("rawInput")
	require.True(t, rawInputFound, "sing-vmess vless.VisionConn lost its \"rawInput\" field; "+visionAuditInstruction)
	require.Equal(t, reflect.TypeOf((*bytes.Buffer)(nil)), rawInputField.Type,
		"sing-vmess vless.VisionConn.rawInput changed type; the CommonConn field it aliases must change to match; "+visionAuditInstruction)

	// Read the pointer NewVisionConn stored in each unexported field and compare
	// it with the address of the CommonConn field it is supposed to alias.
	// Value.Pointer is used rather than an unsafe.Pointer cast so the check stays
	// clean under `go vet`'s unsafeptr analysis (a uintptr is never converted
	// back to unsafe.Pointer here).
	fieldPointer := func(field reflect.StructField) uintptr {
		return reflect.ValueOf(visionConn).Elem().FieldByIndex(field.Index).Pointer()
	}
	require.Equal(t, uintptr(unsafe.Pointer(&commonConn.input)), fieldPointer(inputField),
		"sing-vmess VisionConn.input does not alias CommonConn.input: Vision is reading unrelated memory; "+visionAuditInstruction)
	require.Equal(t, uintptr(unsafe.Pointer(&commonConn.rawInput)), fieldPointer(rawInputField),
		"sing-vmess VisionConn.rawInput does not alias CommonConn.rawInput: Vision is reading unrelated memory; "+visionAuditInstruction)
}
