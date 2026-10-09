// RED CHECK: the pre-migration call shapes must NOT compile against the shipped header.
//
// Every line here is what the pinned client's call sites looked like BEFORE the
// migration (a bare String result). If any of them type-checks, the migration did not
// reach the artifact and the whole ABI check is worthless.
//
// Expected: this file FAILS to compile, with "cannot assign value of type
// 'LibboxStringBox?' to type 'String'" on each line.
import Foundation
import Libbox

func oldCallSites(
    report: LibboxDeprecatedNote,
    session: any LibboxBridgeSessionProtocol,
    prefix: LibboxRoutePrefix,
    options: LibboxTunOptions
) {
    let message: String = report.message()
    let sessionName: String = session.name()
    let address: String = prefix.address()
    let mask: String = prefix.mask()
    let proxyServer: String = options.getHTTPProxyServer()
    let dnsMode: String = options.getDNSMode()

    _ = (message, sessionName, address, mask, proxyServer, dnsMode)
}

// The old implementer witness: returning String where the protocol requires the box.
final class OldBridgeServiceSession: NSObject, LibboxBridgeSessionProtocol {
    func name() -> String { "utun0" }
    func close() throws {}
    func fileDescriptor() -> Int32 { 0 }
    func inet6Active() -> Bool { false }
    func setEgress(_ interfaceName: String?) throws {}
}
