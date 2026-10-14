/**
 * E07 pins: timing-safe hex/string, Mode A vs ait_ refuse,
 * path fold / trailing slash, health identity (no our hosting),
 * log secret redact. T21 stays OPEN (loopback is not public CA).
 * No top-level await.
 */
import assert from 'node:assert/strict'
import { MCP_RELAY_HEALTH_PLAIN_BODY, TEAM_SPACE_HEALTH_PLAIN_BODY } from '../src/constants.js'
import { isMcpRelayHealthBody, looksLikeTeamSpaceHealthBody } from '../src/identity.js'
import { logRelayInfo } from '../src/log.js'
import {
  inboundKeyFamilyPrefix,
  isInboundFamilyPublicToken,
  isLocalApiFamilyPublicToken,
  isModeAPublicToken,
  localKeyFamilyPrefix,
} from '../src/mode-a-key.js'
import { classifyRelayPath } from '../src/paths.js'
import { accessTokenStillLive, sha256Hex, timingSafeEqualHex, timingSafeEqualString } from '../src/timing-safe.js'

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
}

function captureInfo(message: string): string {
  const chunks: string[] = []
  const orig = process.stdout.write
  process.stdout.write = ((chunk: unknown) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk))
    return true
  }) as typeof process.stdout.write
  try {
    logRelayInfo(message)
  } finally {
    process.stdout.write = orig
  }
  return chunks.join('')
}

try {
  const inbound = inboundKeyFamilyPrefix()
  const local = localKeyFamilyPrefix()
  assert.equal(inbound.startsWith(local), false, 'inbound family is not ait_')
  assert.equal(isModeAPublicToken(`${inbound}deadbeefdeadbeef`), true)
  assert.equal(isModeAPublicToken(`${local}deadbeef`), true)
  assert.equal(isInboundFamilyPublicToken(`${inbound}deadbeefdeadbeef`), true)
  assert.equal(isLocalApiFamilyPublicToken(`${inbound}deadbeefdeadbeef`), false)
  assert.equal(isLocalApiFamilyPublicToken(`${local}deadbeef`), true)
  assert.equal(isInboundFamilyPublicToken(`${local}deadbeef`), false)
  assert.equal(isModeAPublicToken(`${inbound.toUpperCase()}deadbeefdeadbeef`), true)
  assert.equal(isModeAPublicToken(`${local.toUpperCase()}deadbeef`), true)
  assert.equal(isModeAPublicToken('not-a-key'), false)
  assert.equal(isModeAPublicToken(''), false)
  assert.equal(isModeAPublicToken(null), false)

  const hexA = sha256Hex('a')
  const hexB = sha256Hex('b')
  assert.equal(timingSafeEqualHex(hexA, hexA), true)
  assert.equal(timingSafeEqualHex(hexA, hexB), false)
  assert.equal(timingSafeEqualHex(hexA.toUpperCase(), hexA), true)
  assert.equal(timingSafeEqualHex(hexA, hexA.slice(0, 32)), false)
  assert.equal(timingSafeEqualHex('not-hex', hexA), false)
  assert.equal(timingSafeEqualHex('', ''), false)
  assert.equal(timingSafeEqualString('pair-secret-16ok!!', 'pair-secret-16ok!!'), true)
  assert.equal(timingSafeEqualString('pair-secret-16ok!!', 'pair-secret-16no!!'), false)
  assert.equal(timingSafeEqualString('short', 'longer-secret'), false)
  assert.equal(timingSafeEqualString('', ''), true)
  assert.equal(timingSafeEqualString(1 as unknown as string, 'x'), false)
  assert.equal(accessTokenStillLive(0, Date.now()), false)
  assert.equal(accessTokenStillLive(Date.now() + 60_000, Date.now()), true)
  assert.equal(accessTokenStillLive(Number.NaN, Date.now()), false)

  assert.equal(classifyRelayPath('/mcp'), 'mcp')
  assert.equal(classifyRelayPath('/mcp/'), 'mcp')
  assert.equal(classifyRelayPath('/mcp//'), 'mcp')
  assert.equal(classifyRelayPath('//mcp'), 'mcp')
  assert.equal(classifyRelayPath('/health///'), 'health')
  assert.equal(classifyRelayPath('//health'), 'health')
  assert.equal(classifyRelayPath('/pair/hello/'), 'pair_hello')
  assert.equal(classifyRelayPath('/pair//hello'), 'pair_hello')
  assert.equal(classifyRelayPath('/.well-known/oauth-protected-resource/mcp/'), 'well_known_prm_mcp')
  assert.equal(classifyRelayPath('/authorize/'), 'authorize')
  assert.equal(classifyRelayPath('/mcp/?x=1'), 'mcp')
  assert.equal(classifyRelayPath('/project-a/mcp'), 'prefix')
  assert.equal(classifyRelayPath('/mcp/../authorize'), 'prefix')
  assert.equal(classifyRelayPath('https://v-aid.ai/mcp'), 'prefix')
  assert.equal(classifyRelayPath('/'), 'root')

  assert.equal(looksLikeTeamSpaceHealthBody(TEAM_SPACE_HEALTH_PLAIN_BODY), true)
  assert.equal(looksLikeTeamSpaceHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY), false)
  assert.equal(isMcpRelayHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY), true)
  assert.equal(isMcpRelayHealthBody(TEAM_SPACE_HEALTH_PLAIN_BODY), false)
  assert.equal(isMcpRelayHealthBody('AItomation MCP relay on https://v-aid.ai/mcp'), false)
  assert.equal(isMcpRelayHealthBody('AItomation AI connector via cms.v-aid.ai'), false)
  assert.equal(isMcpRelayHealthBody('AItomation AI connector hosted on Coolify'), false)
  assert.equal(isMcpRelayHealthBody('AItomation AI connector backed by Directus'), false)
  assert.equal(isMcpRelayHealthBody('welcome to the team space bridge'), false)

  const inboundLine = captureInfo(`authorization Bearer ${inbound}deadbeefdeadbeef`)
  assert.match(inboundLine, /\[redacted\]/)
  assert.doesNotMatch(inboundLine, /deadbeefdeadbeef/)
  const localLine = captureInfo(`got ${local}deadbeef from pair`)
  assert.match(localLine, /\[redacted\]/)
  assert.doesNotMatch(localLine, /deadbeef/)
  const queryLine = captureInfo('open /mcp?access_token=leaksecret')
  assert.match(queryLine, /access_token=\[redacted\]/)
  assert.doesNotMatch(queryLine, /leaksecret/)
  const waitLine = captureInfo('wait_for_peer then continue')
  assert.match(waitLine, /wait_for_peer/)
  const longLine = captureInfo(`x`.repeat(800))
  assert.ok(longLine.length < 500, `info log was not capped (${longLine.length})`)

  console.log('ok identity-timing')
  console.log('SENTINEL_OK')
} catch (err) {
  fail(err instanceof Error ? err.message : String(err))
}
