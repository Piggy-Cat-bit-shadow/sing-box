#!/usr/bin/env python3
"""Reduce a multi-slice Libbox.xcframework to a single device-only framework.

Why this exists: gomobile cannot build a device-only Apple framework. Its
build.go contains

    // Special case to build iossimulator if -target=ios
    if buildTarget == "ios" {
        addPlatform("iossimulator")
    }

so requesting `-platform ios` still produces an ios-arm64 AND an
ios-arm64_x86_64-simulator slice. A stock iPhone loads only the device slice, so
the simulator slice is dead weight in a shipping artifact.

Rather than patching gomobile (a vendored tool, not this repository's code), the
device slice is extracted here and Info.plist is rewritten to describe exactly
what remains. Leaving the original Info.plist in place would make Xcode look for
a simulator slice that is no longer present.

Usage:
    extract_device_slice.py <source.xcframework> <destination.xcframework>
"""

import pathlib
import plistlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    source = pathlib.Path(sys.argv[1])
    destination = pathlib.Path(sys.argv[2])

    if not source.is_dir():
        print(f"FAIL: source framework not found: {source}", file=sys.stderr)
        return 1

    # A device slice is named "ios-<arch>" (for example ios-arm64). Simulator
    # slices contain "simulator" in the identifier.
    device_slices = sorted(
        entry
        for entry in source.iterdir()
        if entry.is_dir()
        and entry.name.startswith("ios-")
        and "simulator" not in entry.name
    )
    if len(device_slices) != 1:
        print(
            f"FAIL: expected exactly one device slice, found "
            f"{[entry.name for entry in device_slices]}",
            file=sys.stderr,
        )
        return 1
    device_slice = device_slices[0]

    info_path = source / "Info.plist"
    if not info_path.is_file():
        print(f"FAIL: no Info.plist in {source}", file=sys.stderr)
        return 1
    info = plistlib.loads(info_path.read_bytes())

    kept = [
        library
        for library in info["AvailableLibraries"]
        if library["LibraryIdentifier"] == device_slice.name
    ]
    if not kept:
        print(
            f"FAIL: Info.plist does not describe {device_slice.name}",
            file=sys.stderr,
        )
        return 1

    if destination.exists():
        import shutil

        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    import shutil

    shutil.copytree(device_slice, destination / device_slice.name)

    info["AvailableLibraries"] = kept
    (destination / "Info.plist").write_bytes(plistlib.dumps(info))

    print(f"device slice:        {device_slice.name}")
    print(f"remaining libraries: {[lib['LibraryIdentifier'] for lib in kept]}")
    for library in kept:
        print(f"  architectures:     {library['SupportedArchitectures']}")
        print(f"  platform:          {library['SupportedPlatform']}")
        if "SupportedPlatformVariant" in library:
            print(f"  variant:           {library['SupportedPlatformVariant']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
