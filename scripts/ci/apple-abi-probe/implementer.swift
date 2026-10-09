// Artifact-level ABI check, part 2: the IMPLEMENTER side.
//
// `BridgeServiceSession` is the client's own implementation of the bound Go interface.
// The body of name() is copied verbatim from
// docs/fork/apple-bridge-session-implementer.patch. The remaining witnesses exist only
// so the class declaration is a complete conformance; the compiler derives their
// signatures from the shipped LibboxBridgeSessionProtocol.
//
// This is the half a call-site grep structurally cannot see: if the protocol still
// required a bare String, or if LibboxStringBox could not be constructed and have its
// value assigned from Swift, this file would not compile.
import Foundation
import Libbox

final class BridgeServiceSession: NSObject, LibboxBridgeSessionProtocol {
    private let tunName = "utun0"

    // Verbatim from docs/fork/apple-bridge-session-implementer.patch
    func name() -> LibboxStringBox? {
        let nameBox = LibboxStringBox()
        nameBox.value = tunName
        return nameBox
    }

    func close() throws {}

    func fileDescriptor() -> Int32 { 0 }

    func inet6Active() -> Bool { false }

    func setEgress(_ interfaceName: String?) throws {}
}

// The conformance is only meaningful if the protocol requirement really is the boxed
// type. This forces a witness of the exact required type to be accepted.
func witnessShape() -> LibboxStringBox? {
    BridgeServiceSession().name()
}
