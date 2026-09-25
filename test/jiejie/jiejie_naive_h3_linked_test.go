//go:build with_quic && !jiejie_server_minimal

package jiejie_test

// naiveHTTP3Included reports whether this build links the Native Naive HTTP/3
// listener.
//
// The build constraint mirrors include/quic.go, which registers
// protocol/naive/quic only when with_quic is set WITHOUT jiejie_server_minimal.
// Under the production tag set the QUIC package is absent, so a udp inbound
// serves TCP and warns that HTTP/3 is disabled.
//
// This is a compile-time fact rather than a runtime probe on purpose. Asking
// whether a handshake succeeds cannot distinguish "HTTP/3 is not in this build"
// from "HTTP/3 is in this build and broken", and those two must be reported
// differently: the first is a SKIP, the second a failure.
const naiveHTTP3Included = true
