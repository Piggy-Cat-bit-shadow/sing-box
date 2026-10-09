// Artifact-level ABI check, part 1: the migrated CALL SITES.
//
// The lvalues below are copied verbatim from the right-hand sides of
// docs/fork/apple-stringbox-callsites.patch, which is the patch the Apple gitlink
// revision 2b23330d is documented to carry. They are type-checked against the
// Libbox.objc.h that the freshly built Libbox.xcframework actually ships - not
// against a source-tree reading of the core.
import Foundation
import Libbox

// GlobalChecksModifier.swift: report.message()!.value   (x3 in the patch)
// RootHelperService.swift / IOSRootHelperService.swift /
// BridgeTunTracker.swift: session.name()!.value
// ExtensionPlatformInterface.swift: ipv4Prefix.address()!.value / .mask()!.value,
//   options.getHTTPProxyServer()!.value, options.getDNSMode()!.value
func migratedCallSites(
    report: LibboxDeprecatedNote,
    session: any LibboxBridgeSessionProtocol,
    prefix: LibboxRoutePrefix,
    options: LibboxTunOptions
) {
    let message: String = report.message()!.value
    let sessionName: String = session.name()!.value
    let address: String = prefix.address()!.value
    let mask: String = prefix.mask()!.value
    let proxyServer: String = options.getHTTPProxyServer()!.value
    let dnsMode: String = options.getDNSMode()!.value

    _ = (message, sessionName, address, mask, proxyServer, dnsMode)
}

// The exact receiver shapes the patch uses, including the `as NSString` conversion
// RootHelperService.swift performs on the unboxed value.
func callSiteShapes(session: any LibboxBridgeSessionProtocol) {
    let name: NSString = session.name()!.value as NSString
    _ = name
}

// The interface whose return type the migration moved, reached the way the client
// reaches it: LibboxNewBridgeService returns id<LibboxBridgeSession>, which Swift
// imports as `any LibboxBridgeSessionProtocol` because the concrete class
// LibboxBridgeSession already owns the bare name.
func bridgeServiceFactory(options: LibboxBridgeOptions) throws {
    let service: (any LibboxBridgeSessionProtocol)? = LibboxNewBridgeService(options, nil)
    _ = try service?.name()?.value
}
