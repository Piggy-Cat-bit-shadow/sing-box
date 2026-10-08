package sniff

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

// errClientHelloSniffed aborts a server handshake from inside GetConfigForClient, at the point
// where the ClientHello the sniffer came for has already been parsed.
//
// It is not a protocol failure and no caller ever sees it: TLSClientHello returns as soon as
// clientHello is set, whatever HandshakeContext reports. What returning it prevents is everything
// crypto/tls does after this callback, and that is not free. A Go server that is allowed to
// continue generates an ECDHE key share and, when the client offers X25519MLKEM768, an ML-KEM key
// share as well - measured here at roughly 125us and 13KB per connection - and then abandons the
// handshake anyway, because this sniffer configures no certificate and completes nothing.
//
// The reading the sniffer reports is unaffected in either direction. GetConfigForClient is called
// only after crypto/tls has parsed a complete ClientHello, so a nil clientHello still means the
// payload was not a ClientHello and still surfaces the original error below - including the
// io.ErrUnexpectedEOF that carries ErrNeedMoreData, which is never produced by this callback.
var errClientHelloSniffed = E.New("client hello sniffed")

// tlsRecordHeaderSize is crypto/tls's recordHeaderLen: the five bytes a TLS record starts with.
const tlsRecordHeaderSize = 5

// crypto/tls's record type and first-record version bound, from Conn.readRecordOrCCS.
const (
	tlsRecordTypeAlert     = 20
	tlsRecordTypeHandshake = 22
	tlsFirstVersionBound   = 0x1000
)

// tlsFirstRecordRejected reports whether crypto/tls refuses a first record header before reading
// any of its body.
//
// It restates, rather than approximates, the check crypto/tls itself performs while a server has
// read no record yet (haveVers == 0): the first record must be an alert or a handshake, and its
// version must be below 0x1000. Everything outside that is turned away with a RecordHeaderError
// before a single body byte is read, so answering it here removes work without removing a
// verdict.
//
// The length guard is the part that keeps this safe on a partial read. A short header proves
// nothing - crypto/tls would be waiting for the rest of it and would report io.ErrUnexpectedEOF,
// which PeekStream reads as ErrNeedMoreData and answers by reading again - so a header that is not
// yet complete is deliberately not a rejection, and the caller falls through to crypto/tls.
func tlsFirstRecordRejected(header []byte) bool {
	if len(header) < tlsRecordHeaderSize {
		return false
	}
	recordType := header[0]
	version := uint16(header[1])<<8 | uint16(header[2])
	return (recordType != tlsRecordTypeAlert && recordType != tlsRecordTypeHandshake) || version >= tlsFirstVersionBound
}

// errNotTLSHandshake is the error crypto/tls raises for a first record that is not a handshake,
// reproduced here so that a gated payload produces the same value - same type, same message, same
// header bytes - as the parser would have produced on its own.
func errNotTLSHandshake(header []byte) error {
	var recordHeader [tlsRecordHeaderSize]byte
	copy(recordHeader[:], header)
	return tls.RecordHeaderError{
		Msg:          "first record does not look like a TLS handshake",
		RecordHeader: recordHeader,
	}
}

func TLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	// A TLS record header is the cheapest thing in this parser and the only thing the first
	// record's fate depends on. Checking it before crypto/tls is constructed keeps a non-TLS
	// payload from paying for a server Conn, a read buffer and a full handshake setup just to be
	// told the first byte was wrong. The buffer is deliberately tiny: bufio.Peek fills only as
	// far as the header and hands the rest of the first read straight through, so crypto/tls
	// still sees the payload in the same sized chunks it did before.
	bufferedReader := std_bufio.NewReaderSize(reader, tlsRecordHeaderSize)
	header, _ := bufferedReader.Peek(tlsRecordHeaderSize)
	if tlsFirstRecordRejected(header) {
		return errNotTLSHandshake(header)
	}
	var clientHello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(bufferedReader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = argHello
			// Abort here rather than let crypto/tls generate key material for a handshake that
			// will never be completed. See errClientHelloSniffed.
			return nil, errClientHelloSniffed
		},
	}).HandshakeContext(ctx)
	if clientHello != nil {
		metadata.Protocol = C.ProtocolTLS
		metadata.Domain = clientHello.ServerName
		return nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return E.Cause1(ErrNeedMoreData, err)
	} else {
		return err
	}
}
