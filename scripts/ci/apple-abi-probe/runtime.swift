// Artifact-level ABI check, part 4: LINK and RUN against the shipped framework.
//
// Type-checking proves the declarations match. This proves the framework actually
// links and that the boxed-string path works at runtime: the same object the migrated
// call sites read through `.value` is constructed here, written through the generated
// `setValue:` setter and read back.
//
// It is built with the macOS slice of the framework this repository just produced, and
// it is an UNSIGNED binary: swiftc applies no signing identity, and nothing here
// contacts Apple, uses a certificate, a provisioning profile or a Team ID.
import Foundation
import Libbox

let box = LibboxStringBox()
box.value = "jiejiebox-abi-probe"
guard box.value == "jiejiebox-abi-probe" else {
    fatalError("LibboxStringBox did not round-trip its value")
}
print("LibboxStringBox round-trip OK: \(box.value)")

// The interface whose ABI moved: the factory returns the protocol type, and reaching
// the migrated accessor through it is the shape the client uses.
print("LibboxVersion(): \(LibboxVersion())")

// A second box, to be sure the first was not a singleton in disguise.
let other = LibboxStringBox()
other.value = "second"
guard other.value == "second", box.value == "jiejiebox-abi-probe" else {
    fatalError("two LibboxStringBox instances shared state")
}
print("two independent LibboxStringBox instances OK")
