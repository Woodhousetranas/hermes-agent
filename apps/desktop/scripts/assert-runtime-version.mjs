/**
 * Prevent a Desktop build from shipping with a stale Electron app version.
 *
 * Electron-builder uses apps/desktop/package.json#version for the installed
 * app identity, artifact names, and update metadata. Hermes itself exposes
 * its runtime version from hermes_cli/__init__.py. These must stay in lockstep
 * or an otherwise current Desktop build can be identified as an older app.
 */

import { readFileSync } from "fs"
import { join, resolve } from "path"
import { isMain } from "./utils.mjs"

const DESKTOP_ROOT = resolve(import.meta.dirname, "..")
const REPO_ROOT = resolve(DESKTOP_ROOT, "..", "..")
const DESKTOP_PACKAGE_PATH = join(DESKTOP_ROOT, "package.json")
const RUNTIME_INIT_PATH = join(REPO_ROOT, "hermes_cli", "__init__.py")

export function readDesktopVersion(packagePath = DESKTOP_PACKAGE_PATH) {
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"))
  return typeof packageJson.version === "string" ? packageJson.version : null
}

export function readRuntimeVersion(initPath = RUNTIME_INIT_PATH) {
  const source = readFileSync(initPath, "utf8")
  return source.match(/__version__\s*=\s*["']([^"']+)["']/)?.[1] ?? null
}

export function assertRuntimeVersion({ desktopVersion = readDesktopVersion(), runtimeVersion = readRuntimeVersion() } = {}) {
  if (!desktopVersion || !runtimeVersion) {
    throw new Error(
      `[assert-runtime-version] Could not resolve both versions (Desktop=${desktopVersion ?? "missing"}, Hermes=${runtimeVersion ?? "missing"}).`
    )
  }

  if (desktopVersion !== runtimeVersion) {
    throw new Error(
      `[assert-runtime-version] Desktop package version ${desktopVersion} does not match Hermes runtime ${runtimeVersion}. ` +
        "Update apps/desktop/package.json and the apps/desktop entry in package-lock.json before building."
    )
  }

  return { desktopVersion, runtimeVersion }
}

function main() {
  const { desktopVersion, runtimeVersion } = assertRuntimeVersion()
  console.log(`[assert-runtime-version] Desktop and Hermes are both ${desktopVersion}`)
  return runtimeVersion
}

if (process.argv[1] && isMain(import.meta.url)) {
  main()
}
