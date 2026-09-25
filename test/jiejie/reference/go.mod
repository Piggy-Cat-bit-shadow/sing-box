// This module exists so the MASQUE reference implementations
// (github.com/quic-go/masque-go and github.com/quic-go/connect-ip-go) can be
// imported by interop tests WITHOUT ever entering the production dependency
// graph.
//
// It is deliberately separate from both the repository root module and the
// `test` module:
//
//   - the root module builds the shipped binary, so a reference client must
//     never be reachable from it;
//   - the `test` module is tidied as a whole, so an import there would pull the
//     references into the main test binary's module graph even though only a
//     handful of tests need them.
//
// A separate module makes "no reference dependency in the production graph" a
// property of the module layout rather than a convention someone has to
// remember. Nothing in the root or `test` module imports this one.
module github.com/sagernet/sing-box/test/jiejie/reference

go 1.26.0

require (
	github.com/quic-go/connect-ip-go v0.4.0
	github.com/quic-go/masque-go v0.6.0
	github.com/quic-go/quic-go v0.63.0
	github.com/sagernet/sing v0.9.5
	github.com/stretchr/testify v1.12.1
	github.com/yosida95/uritemplate/v3 v3.0.2
)

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/quic-go/connect-ip-go => github.com/quic-go/connect-ip-go v0.4.1-0.20260924175820-fdd945e3d600
