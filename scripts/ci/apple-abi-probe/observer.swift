// Artifact-level ABI check, part 3: the OBSERVER itself, verbatim.
//
// This is Library/Network/ScreenStateObserver.swift exactly as
// docs/fork/apple-screen-state-observer.patch adds it, compiled against the
// Libbox.xcframework that was just built from this core. It proves three things the
// design doc asserts and nothing else checks:
//
//   1. `import notify` resolves and notify_register_dispatch / notify_get_state /
//      notify_cancel have the Swift signatures the patch assumes (Int32 token,
//      DispatchQueue, UInt64 out-state);
//   2. LibboxCommandServer really exposes recordScreenState(_: Bool) and
//      recordLockState(_: Bool) with those exact types in the shipped artifact;
//   3. the file is iOS-only, so a macOS build of this same translation unit compiles
//      it away and never reaches the private notification names.
//
// The point of the file below is that it is NOT a rewrite: it is the shipped text.
#if os(iOS)
    import Foundation
    import Libbox
    import notify

    final class ScreenStateObserver {
        private let queue = DispatchQueue(label: "io.nekohasekai.sfamt.screen-state")
        private var displayToken: Int32 = -1
        private var lockToken: Int32 = -1

        init(commandServer: LibboxCommandServer) {
            notify_register_dispatch("com.apple.iokit.hid.displayStatus", &displayToken, queue) { token in
                var state: UInt64 = 0
                notify_get_state(token, &state)
                commandServer.recordScreenState(state == 1)
            }
            notify_register_dispatch("com.apple.springboard.lockstate", &lockToken, queue) { token in
                var state: UInt64 = 0
                notify_get_state(token, &state)
                commandServer.recordLockState(state == 1)
            }
        }

        func cancel() {
            notify_cancel(displayToken)
            notify_cancel(lockToken)
        }
    }
#endif
