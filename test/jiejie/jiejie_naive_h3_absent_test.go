//go:build !with_quic || jiejie_server_minimal || jiejie_client_macos

package jiejie_test

// naiveHTTP3Included is false when the build does not link protocol/naive/quic.
//
// That is the case for a build without with_quic, for the production server tag
// set, and for the macOS client profile, whose include/quic_client_macos.go no
// longer imports the package: the Native Naive HTTP/3 listener it installs is a
// SERVER listener, and the client is outbound-only.
//
// See the linked variant for why this is a compile-time constant.
const naiveHTTP3Included = false
