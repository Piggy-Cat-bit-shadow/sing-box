// This file is adapted from github.com/starifly/sing-box
// (protocol/vless/encryption), the upstream this code originates from, via the
// reference fork github.com/Leadaxe/sing-box-lx
// (protocol/vless/encryption). Both are GPL-3.0, the same license as this
// repository, and share its upstream base.
//
// It replaces the two tiny helpers the reference kept in its own
// `common/xray/{cpuid,crypto}` packages. Pulling that Xray-compat tree in for
// ~20 lines of logic would be out of proportion, so the pieces this package
// actually uses live here instead.
package encryption

import (
	"crypto/rand"
	"math/big"
	"runtime"

	"golang.org/x/sys/cpu"
)

// hasAESGCMHardware reports whether the CPU accelerates AES-GCM. The handshake
// picks AES-GCM over ChaCha20-Poly1305 when it does, matching what the peer
// expects to negotiate. Kept in sync with crypto/tls/cipher_suites.go.
var hasAESGCMHardware = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasGHASH) ||
	runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

// randBetween returns a uniform random value in [from, to). Used for the
// padding/delay ranges, which are cosmetic on the wire but must not be
// predictable, hence crypto/rand rather than math/rand.
func randBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
