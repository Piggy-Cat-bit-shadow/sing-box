package route

import (
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// The cached first payload must reach the writer's owned path through the REAL copy loop.
//
// # Why this is asserted against CopyWithIncreateBuffer rather than the helper
//
// A helper that works perfectly but is wired into the wrong branch, or not wired at all, would pass
// every unit test of the helper and still deliver zero benefit. This drives the function
// route/conn.go actually calls, with a CachedReader source, so the assertion covers the wiring and
// not merely the decision.
func TestCachedPayloadReachesTheOwnedPath(t *testing.T) {
	destination := &geometryRecordingWriter{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
	source := &cachedSource{}

	_, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)

	require.Equal(t, 1, destination.ownedWrites,
		"a geometry-compatible cached payload must reach WriteBuffer through the real copy loop")
	require.Zero(t, destination.plainWrites,
		"the copying path must not have been used for a compatible cached payload")
}

// geometryRecordingWriter advertises geometry and counts which path was taken.
type geometryRecordingWriter struct {
	frontHeadroom int
	rearHeadroom  int
	writerMTU     int
	ownedWrites   int
	plainWrites   int
}

func (w *geometryRecordingWriter) Write(p []byte) (int, error) {
	w.plainWrites++
	return len(p), nil
}

func (w *geometryRecordingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.ownedWrites++
	buffer.Release()
	return nil
}

func (w *geometryRecordingWriter) WriterMTU() int     { return w.writerMTU }
func (w *geometryRecordingWriter) FrontHeadroom() int { return w.frontHeadroom }
func (w *geometryRecordingWriter) RearHeadroom() int  { return w.rearHeadroom }

// cachedSource implements N.CachedReader with exactly one cached buffer, then EOF.
type cachedSource struct {
	served bool
}

func (s *cachedSource) ReadCached() *buf.Buffer {
	if s.served {
		return nil
	}
	s.served = true
	buffer := buf.NewSize(3 + 512 + 255)
	buffer.Resize(3, 0)
	for i := 0; i < 512; i++ {
		_ = buffer.WriteByte(byte(i))
	}
	return buffer
}

func (s *cachedSource) Read(p []byte) (int, error) { return 0, io.EOF }
