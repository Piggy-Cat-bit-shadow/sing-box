//go:build !race

package encryption

import (
	"net"
	"testing"

	"github.com/sagernet/sing-vmess/vless"

	"github.com/stretchr/testify/require"
)

// The reference's end-to-end assertion: vless.NewVisionConn accepts a
// *CommonConn now that vision.go registered it, where before the registry entry
// it failed with "vision: not a valid supported TLS connection".
//
// Excluded under -race on purpose. NewVisionConn reinterprets
// `uintptr(unsafe.Pointer(conn)) + field.Offset` as a pointer, and the race
// detector's checkptr looks for the original pointer in the arithmetic's
// operands; the uintptr crossed a function boundary (the registry callback's
// return value), so no operand can match and checkptr fatally aborts. That is
// true for every registered conn type — the built-in crypto/tls entry trips the
// same check — so this is a property of the pinned sing-vmess, not of this
// port. vision_test.go asserts the same registry lookup without the wrapper.
func TestVisionAcceptsCommonConn(t *testing.T) {
	t.Parallel()

	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	commonConn := NewCommonConn(inner, false)

	_, err := vless.NewVisionConn(commonConn, commonConn, [16]byte{}, nil)
	require.NoError(t, err, "NewVisionConn over *CommonConn")
}
