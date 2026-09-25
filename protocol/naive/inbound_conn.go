package naive

import (
	"bufio"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
)

const paddingCount = 8

// paddingSizeSource yields the padding length for one frame.
//
// It is a per-connection field rather than a package global so a test can drive
// every value in 0..255 without sharing mutable state between connections: a
// global would race under -race and would couple concurrently running tests.
// Production always leaves it nil and uses rand.Intn(256) directly, so the wire
// distribution is exactly what Naive specifies (0..255, uniform).
type paddingSizeSource func() int

func generatePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := range 16 {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

// paddingConn implements the Naive padding frame codec.
//
// The frame format matches klzgrad/forwardproxy exactly and must not be
// changed: a 2-byte big-endian original data size, a 1-byte padding size, the
// data, then that many zero padding bytes. Padding applies to the first
// paddingCount frames in each direction and is then dropped entirely.
//
// `enabled` records whether the client negotiated padding by sending the
// Padding header. It is NOT a validity requirement: a CONNECT without the
// header is a plain HTTP proxy request and simply uses unpadded framing, which
// is what the reference implementation does.
type paddingConn struct {
	// enabled is set from the client's Padding header. When false the connection
	// is plain I/O and no frame header is ever written or expected.
	enabled bool
	// readPadding and writePadding count frames in each direction. Padding stops
	// once both reach paddingCount.
	readPadding      int
	writePadding     int
	readRemaining    int
	paddingRemaining int
	// paddingSize, when non-nil, supplies the padding length instead of the
	// default uniform rand.Intn(256). It exists only so tests can exercise the
	// full 0..255 range deterministically; production leaves it nil.
	paddingSize paddingSizeSource
}

// nextPaddingSize returns the padding length for one frame.
//
// The default is the Naive protocol's uniform 0..255 draw. The value is NOT
// clamped to the buffer's free space: the wire format allows the whole range, so
// narrowing it would change the sender's padding distribution. A caller that
// cannot accommodate the range must supply a correctly sized buffer, which the
// production copy path always does (see the headroom check in
// writeBufferWithPadding).
func (p *paddingConn) nextPaddingSize() int {
	if p.paddingSize != nil {
		return p.paddingSize()
	}
	return rand.Intn(256)
}

func (p *paddingConn) readWithPadding(reader io.Reader, buffer []byte) (n int, err error) {
	if !p.enabled {
		return reader.Read(buffer)
	}
	if p.readRemaining > 0 {
		if len(buffer) > p.readRemaining {
			buffer = buffer[:p.readRemaining]
		}
		n, err = reader.Read(buffer)
		if err != nil {
			return
		}
		p.readRemaining -= n
		return
	}
	if p.paddingRemaining > 0 {
		err = rw.SkipN(reader, p.paddingRemaining)
		if err != nil {
			return
		}
		p.paddingRemaining = 0
	}
	if p.readPadding < paddingCount {
		var paddingHeader []byte
		if len(buffer) >= 3 {
			paddingHeader = buffer[:3]
		} else {
			paddingHeader = make([]byte, 3)
		}
		_, err = io.ReadFull(reader, paddingHeader)
		if err != nil {
			return
		}
		originalDataSize := int(binary.BigEndian.Uint16(paddingHeader[:2]))
		paddingSize := int(paddingHeader[2])
		if len(buffer) > originalDataSize {
			buffer = buffer[:originalDataSize]
		}
		n, err = io.ReadFull(reader, buffer)
		if err != nil {
			return
		}
		p.readPadding++
		p.readRemaining = originalDataSize - n
		p.paddingRemaining = paddingSize
		return
	}
	return reader.Read(buffer)
}

func (p *paddingConn) writeWithPadding(writer io.Writer, data []byte) (n int, err error) {
	if !p.enabled {
		return writeFull(writer, data)
	}
	if p.writePadding < paddingCount {
		paddingSize := p.nextPaddingSize()
		// This path allocates its own buffer, so it always has room for the full
		// 0..255 range; nothing needs clamping and nothing can fail here.
		buffer := buf.NewSize(3 + len(data) + paddingSize)
		defer buffer.Release()
		header := buffer.Extend(3)
		binary.BigEndian.PutUint16(header, uint16(len(data)))
		header[2] = byte(paddingSize)
		common.Must1(buffer.Write(data))
		common.Must(buffer.WriteZeroN(paddingSize))
		// A frame header is already on the wire once ANY byte of the frame is
		// written, so the write must complete or the stream is corrupt.
		if _, writeErr := writeFull(writer, buffer.Bytes()); writeErr != nil {
			// Deliberately do NOT advance the frame counter: the peer never
			// received a complete frame, so it must not expect the padding
			// accounting to move.
			return 0, writeErr
		}
		p.writePadding++
		return len(data), nil
	}
	return writeFull(writer, data)
}

// writeFull writes all of data and returns the byte count io.Writer reported.
//
// It exists because io.Writer's contract permits a Write to return
// n < len(data) with a NIL error, and such a result must be treated as a
// failure. The previous code checked only the error and therefore reported the
// full payload length even when bytes were dropped, which silently truncated the
// tunnel and advanced the padding frame counter past a frame the peer never
// fully received; the next write then emitted raw bytes into a stream the peer
// was still parsing as framed.
func writeFull(writer io.Writer, data []byte) (int, error) {
	written, err := writer.Write(data)
	if err != nil {
		return written, err
	}
	if written != len(data) {
		return written, io.ErrShortWrite
	}
	return written, nil
}

func (p *paddingConn) writeBufferWithPadding(writer io.Writer, buffer *buf.Buffer) error {
	framed := false
	if p.enabled && p.writePadding < paddingCount {
		bufferLen := buffer.Len()
		if bufferLen > 65535 {
			_, err := p.writeChunked(writer, buffer.Bytes())
			return err
		}
		if buffer.Start() < 3 {
			return E.New("naive padding requires 3 bytes of front headroom, buffer has ", buffer.Start())
		}
		paddingSize := p.nextPaddingSize()
		// The padding range is the protocol's full 0..255 and is deliberately
		// NOT clamped to the buffer. rearHeadroom() advertises 255 for exactly
		// this reason, and the copy path guarantees it (ReadWaitOptions.Copy
		// reallocates when RearHeadroom > FreeLen, and CopyExtendedBuffer calls
		// buffer.Reserve(rearHeadroom)). Narrowing the range here would silently
		// change the padding-size distribution Naive specifies.
		//
		// If a caller still passes a buffer that cannot hold the frame, that is a
		// programming error in the caller, not a protocol condition: report it as
		// an error. It must not be common.Must, which would turn it into a panic
		// and take the whole process down.
		if buffer.FreeLen() < paddingSize {
			return E.New("naive padding needs ", paddingSize,
				" bytes of free space for padding, buffer has ", buffer.FreeLen(),
				" (padding range 0..255 must be preserved, not clamped)")
		}
		header := buffer.ExtendHeader(3)
		binary.BigEndian.PutUint16(header, uint16(bufferLen))
		header[2] = byte(paddingSize)
		if err := buffer.WriteZeroN(paddingSize); err != nil {
			return E.Cause(err, "write naive padding")
		}
		framed = true
	}
	if _, err := writeFull(writer, buffer.Bytes()); err != nil {
		// As above: a frame that was not fully written must not advance the
		// counter, or the peer's framing and ours diverge.
		return err
	}
	if framed {
		p.writePadding++
	}
	return nil
}

func (p *paddingConn) writeChunked(writer io.Writer, data []byte) (n int, err error) {
	if !p.enabled {
		// Without padding there is no 2-byte frame length, so there is no
		// 65535-byte frame limit to respect. Write straight through.
		return writeFull(writer, data)
	}
	for len(data) > 0 {
		var chunk []byte
		if len(data) > 65535 {
			chunk = data[:65535]
			data = data[65535:]
		} else {
			chunk = data
			data = nil
		}
		var written int
		written, err = p.writeWithPadding(writer, chunk)
		n += written
		if err != nil {
			return
		}
	}
	return
}

func (p *paddingConn) frontHeadroom() int {
	if p.enabled && p.writePadding < paddingCount {
		return 3
	}
	return 0
}

func (p *paddingConn) rearHeadroom() int {
	if p.enabled && p.writePadding < paddingCount {
		return 255
	}
	return 0
}

func (p *paddingConn) writerMTU() int {
	if p.enabled && p.writePadding < paddingCount {
		return 65535
	}
	return 0
}

// readerReplaceable and writerReplaceable report that the padding layer can be
// dropped from the connection stack. Both directions must be past the padding
// window, and an unpadded connection is replaceable immediately because there is
// no frame layer at all.
func (p *paddingConn) readerReplaceable() bool {
	return !p.enabled || p.readPadding == paddingCount
}

func (p *paddingConn) writerReplaceable() bool {
	return !p.enabled || p.writePadding == paddingCount
}

type naiveConn struct {
	net.Conn
	paddingConn
}

func (c *naiveConn) Read(p []byte) (n int, err error) {
	n, err = c.readWithPadding(c.Conn, p)
	return n, wrapError(err)
}

func (c *naiveConn) Write(p []byte) (n int, err error) {
	n, err = c.writeChunked(c.Conn, p)
	return n, wrapError(err)
}

func (c *naiveConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	err := c.writeBufferWithPadding(c.Conn, buffer)
	return wrapError(err)
}

func (c *naiveConn) FrontHeadroom() int      { return c.frontHeadroom() }
func (c *naiveConn) RearHeadroom() int       { return c.rearHeadroom() }
func (c *naiveConn) WriterMTU() int          { return c.writerMTU() }
func (c *naiveConn) Upstream() any           { return c.Conn }
func (c *naiveConn) ReaderReplaceable() bool { return c.readerReplaceable() }
func (c *naiveConn) WriterReplaceable() bool { return c.writerReplaceable() }

type naiveH2Conn struct {
	reader io.Reader
	writer io.Writer
	// flusher is a ResponseController rather than the ResponseWriter's
	// http.Flusher interface, because http.Flusher.Flush() returns nothing.
	//
	// That signature is why the previous implementation could not tell a
	// successful flush from a failed one: every tunnel write called Flush() and
	// discarded the outcome, so a stream that had already failed was treated as
	// healthy and the connection kept writing into it. The reference uses
	// http.NewResponseController(w).Flush() and checks its error
	// (klzgrad/forwardproxy forwardproxy.go), and ResponseController is the
	// supported way to reach that error from a handler.
	flusher       *http.ResponseController
	remoteAddress net.Addr
	paddingConn
}

func (c *naiveH2Conn) Read(p []byte) (n int, err error) {
	n, err = c.readWithPadding(c.reader, p)
	return n, wrapError(err)
}

// flush propagates a flush failure to the caller.
//
// A failed flush means the tunnel's write side is no longer usable: the stream
// was reset, the connection went away, or the transport rejected the write. The
// caller must see that as an error on THIS write so it stops producing frames
// and tears the tunnel down, rather than reporting success and continuing to
// write into a dead stream.
func (c *naiveH2Conn) flush() error {
	return c.flusher.Flush()
}

func (c *naiveH2Conn) Write(p []byte) (n int, err error) {
	n, err = c.writeChunked(c.writer, p)
	if err != nil {
		return n, wrapError(err)
	}
	// The write reached the transport buffer but is not delivered until it is
	// flushed, so a flush failure invalidates the write that just "succeeded".
	if flushErr := c.flush(); flushErr != nil {
		return n, wrapError(flushErr)
	}
	return n, nil
}

func (c *naiveH2Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	err := c.writeBufferWithPadding(c.writer, buffer)
	if err != nil {
		return wrapError(err)
	}
	if flushErr := c.flush(); flushErr != nil {
		return wrapError(flushErr)
	}
	return nil
}

func wrapError(err error) error {
	err = baderror.WrapH2(err)
	if WrapError != nil {
		err = WrapError(err)
	}
	return err
}

func (c *naiveH2Conn) Close() error {
	return common.Close(c.reader, c.writer)
}

func (c *naiveH2Conn) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (c *naiveH2Conn) RemoteAddr() net.Addr               { return c.remoteAddress }
func (c *naiveH2Conn) SetDeadline(t time.Time) error      { return os.ErrInvalid }
func (c *naiveH2Conn) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (c *naiveH2Conn) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (c *naiveH2Conn) NeedAdditionalReadDeadline() bool   { return true }
func (c *naiveH2Conn) UpstreamReader() any                { return c.reader }
func (c *naiveH2Conn) UpstreamWriter() any                { return c.writer }
func (c *naiveH2Conn) FrontHeadroom() int                 { return c.frontHeadroom() }
func (c *naiveH2Conn) RearHeadroom() int                  { return c.rearHeadroom() }
func (c *naiveH2Conn) WriterMTU() int                     { return c.writerMTU() }
func (c *naiveH2Conn) ReaderReplaceable() bool            { return c.readerReplaceable() }
func (c *naiveH2Conn) WriterReplaceable() bool            { return c.writerReplaceable() }

// hijackedConn returns bytes buffered by the HTTP server before the tunnel
// starts, then reads from the underlying connection.
//
// When net/http hijacks a connection it hands back a *bufio.ReadWriter whose
// Reader may already contain bytes the server read past the request headers. A
// client that sends its tunnel prologue immediately after CONNECT -- which is
// what a pipelining client does -- has those bytes sitting in that buffer. If
// they are discarded the tunnel begins mid-stream: the first UoT request header
// or padding frame header is missing and every subsequent read is misaligned.
//
// The buffered bytes are consumed FIRST, exactly in order, so the tunnel sees a
// single continuous stream. Only the read side is intercepted: writes go straight
// to the socket, because the server has already flushed the response and nothing
// else is buffered on the write side.
type hijackedConn struct {
	net.Conn
	reader *bufio.Reader
	// drained is set once the buffered bytes are exhausted, after which reads
	// pass straight through with no extra bookkeeping.
	drained bool
}

func (c *hijackedConn) Read(p []byte) (int, error) {
	if !c.drained && c.reader != nil {
		if c.reader.Buffered() > 0 {
			return c.reader.Read(p)
		}
		c.drained = true
	}
	return c.Conn.Read(p)
}

// Upstream exposes the wrapped connection so wrappers that unwrap (bufio,
// deadline helpers, common.Cast) still reach the real socket rather than
// stopping at this adapter.
func (c *hijackedConn) Upstream() any { return c.Conn }
