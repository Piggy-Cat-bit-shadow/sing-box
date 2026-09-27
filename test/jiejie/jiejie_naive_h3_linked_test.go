//go:build with_quic && !jiejie_server_minimal && !jiejie_client_macos

package jiejie_test

// naiveHTTP3Included reports whether this build links the Native Naive HTTP/3
// listener.
//
// The build constraint mirrors the two files that register protocol/naive/quic:
//
//	include/quic.go                with_quic && !jiejie_server_minimal
//	include/quic_client_macos.go   (no longer imports it)
//
// So the listener is present under with_quic with NEITHER jiejie_server_minimal
// NOR jiejie_client_macos, and absent under both narrowed profiles. Under the
// production tag set the QUIC package is absent, so a udp inbound serves TCP and
// warns that HTTP/3 is disabled.
//
// The jiejie_client_macos clause was added when that import was removed. It is
// not cosmetic: without it a macOS client test build would claim
// naiveHTTP3Included == true while the package is not linked, and the Naive ALPN
// tests that branch on this constant would assert against an H3 listener that
// does not exist -- failing, or worse, passing vacuously.
//
// This is a compile-time fact rather than a runtime probe on purpose. Asking
// whether a handshake succeeds cannot distinguish "HTTP/3 is not in this build"
// from "HTTP/3 is in this build and broken", and those two must be reported
// differently: the first is a SKIP, the second a failure.
const naiveHTTP3Included = true
