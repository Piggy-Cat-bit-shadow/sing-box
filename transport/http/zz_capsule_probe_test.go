package http

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func encVarint(v uint64) []byte {
	out := make([]byte, VarintLen(v))
	PutVarint(out, v)
	return out
}

// Does the capsule size limit actually fire when the declared length alone
// exceeds it? (Correct QUIC varint encoding this time.)
func TestCapsuleLengthLimitFires(t *testing.T) {
	for _, length := range []uint64{MaxCapsuleLength, MaxCapsuleLength + 1, 1 << 40} {
		wire := append(encVarint(0x00), encVarint(length)...)
		reader := bufio.NewReader(bytes.NewReader(wire))
		buffer := buf.New()
		err := readDatagramCapsule(reader, buffer)
		buffer.Release()
		t.Logf("declared length %-14d err=%v", length, err)
	}
}
