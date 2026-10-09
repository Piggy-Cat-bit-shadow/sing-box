// Runs the desktop client's own afterSign verification against a packaged app.
//
// Usage: node verify-desktop-package-integrity.cjs <clientDir> <appOutDir> <productFilename>
//
// # Why this exists
//
// scripts/afterSign.cjs is the client's packaging integrity check: it proves the
// executable embeds the CURRENT app.asar integrity hash, that there is exactly one
// Electron fuse wire, and that all nine fuses are in the state the client expects -
// including enableEmbeddedAsarIntegrityValidation and onlyLoadAppFromAsar, which are what
// stop a modified app.asar from loading.
//
// electron-builder calls that hook as part of its SIGNING step. This release is
// deliberately unsigned, so whether the hook runs at all depends on electron-builder's
// internal path for a build with no certificate. That is not something to assume either
// way: if it is skipped, the client ships without the checks and nothing says so.
//
// So the hook is invoked here explicitly, against the packaged output, regardless of
// whether electron-builder already ran it. It is read-only verification, so running it
// twice is harmless.
//
// The hook is imported from the client rather than reimplemented, so this cannot drift
// from what the client actually checks.
"use strict";

const path = require("node:path");

function fail(message) {
  console.error(`verify-desktop-package-integrity: ${message}`);
  process.exitCode = 1;
}

async function main() {
  const [clientArgument, outputArgument, productFilename] = process.argv.slice(2);
  if (!clientArgument || !outputArgument || !productFilename) {
    fail(
      "usage: verify-desktop-package-integrity.cjs <clientDir> <appOutDir> <productFilename>",
    );
    return;
  }
  const clientDir = path.resolve(clientArgument);
  const appOutDir = path.resolve(outputArgument);

  let hook;
  try {
    hook = require(path.join(clientDir, "scripts", "afterSign.cjs"));
  } catch (error) {
    fail(`could not load the client's afterSign hook: ${error.message}`);
    return;
  }
  if (typeof hook.afterSign !== "function") {
    fail(`${path.join(clientDir, "scripts", "afterSign.cjs")} exports no afterSign`);
    return;
  }

  // Only the fields the hook reads. appOutDir and the product filename are what it uses to
  // find the executable; electronPlatformName selects the ".exe" suffix.
  const context = {
    appOutDir,
    electronPlatformName: "win32",
    packager: { appInfo: { productFilename } },
  };

  try {
    await hook.afterSign(context);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
    return;
  }
  console.log(
    `PASS: ${productFilename}.exe embeds the current app.asar hash and all Electron fuses are as expected`,
  );
}

main().catch((error) => fail(error instanceof Error ? error.message : String(error)));
