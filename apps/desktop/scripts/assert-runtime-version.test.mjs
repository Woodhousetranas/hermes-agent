import assert from 'node:assert/strict'
import { test } from 'vitest'

import { assertRuntimeVersion } from './assert-runtime-version.mjs'

test('accepts a Desktop package that matches the Hermes runtime', () => {
  assert.deepEqual(
    assertRuntimeVersion({ desktopVersion: '0.20.2', runtimeVersion: '0.20.2' }),
    { desktopVersion: '0.20.2', runtimeVersion: '0.20.2' }
  )
})

test('rejects a stale Desktop package version before packaging', () => {
  assert.throws(
    () => assertRuntimeVersion({ desktopVersion: '0.17.0', runtimeVersion: '0.20.2' }),
    /Desktop package version 0\.17\.0 does not match Hermes runtime 0\.20\.2/
  )
})
