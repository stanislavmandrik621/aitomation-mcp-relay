/**
 * T18 leftovers: Host-header honesty, Mode B empty resource,
 * CIMD connect lookup, DCR cannot overwrite confidential.
 * No top-level await.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import type { IncomingMessage } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { cimdSafeDnsLookup, cimdUrlAllowed, isCimdClientId } from '../src/cimd.js'
import { parseRelayConfig } from '../src/config.js'
import { inboundKeyFamilyPrefix } from '../src/mode-a-key.js'
import { resolveModeBAuth } from '../src/mode-b-auth.js'
import { createOAuthStore, writeConfidentialJsonOrAdoptWinner } from '../src/oauth-store.js'
import type { ConfidentialFile } from '../src/oauth-store.js'
import { createPairStore } from '../src/pair-store.js'
import { classifyRelayPath } from '../src/paths.js'
import {
  isBindAnyHost,
  isOurHostingHost,
  parsePublicBaseUrl,
  publicOriginFromRequest,
  safeAdvertisedOrigin,
  wwwAuthenticatePrm,
} from '../src/public-url.js'
import { isAllowedOAuthRedirect } from '../src/redirects.js'
import { accessTokenStillLive, sha256Hex, timingSafeEqualHex } from '../src/timing-safe.js'
import { wellKnownJson } from '../src/well-known.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
}

function sourceWithoutComments(raw: string): string {
  return raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
}

function src(name: string): string {
  return sourceWithoutComments(readFileSync(join(root, 'src', name), 'utf8'))
}

function asReq(partial: { headers?: IncomingMessage['headers']; url?: string }): IncomingMessage {
  return { headers: partial.headers || {}, url: partial.url || '/mcp' } as IncomingMessage
}

function lookupRefused(hostname: string): Promise<string> {
  return new Promise((resolve, reject) => {
    cimdSafeDnsLookup(hostname, {}, (err) => {
      if (!err) {
        reject(new Error(`lookup should refuse ${hostname}`))
        return
      }
      resolve(err.code || err.message)
    })
  })
}

void (async () => {
  const drifted: string[] = []
  const note = (ok: boolean, row: string): void => {
    if (!ok) drifted.push(row)
  }

  try {
    note(isOurHostingHost('v-aid.ai') === true, 'isOurHostingHost v-aid.ai')
    note(isOurHostingHost('cms.v-aid.ai') === true, 'isOurHostingHost cms')
    note(isOurHostingHost('v-aid.ai:443') === true, 'isOurHostingHost host:port')
    note(isOurHostingHost('edge.v-aid.ai') === true, 'isOurHostingHost suffix')
    note(isOurHostingHost('connector.example') === false, 'isOurHostingHost other')
    note(isBindAnyHost('0.0.0.0') === true, 'isBindAnyHost 0.0.0.0')
    note(isBindAnyHost('::') === true, 'isBindAnyHost ::')
    note(isBindAnyHost('127.0.0.1') === false, 'isBindAnyHost loopback')

    note(parsePublicBaseUrl('https://v-aid.ai') === null, 'parsePublicBaseUrl our host')
    note(parsePublicBaseUrl('https://cms.v-aid.ai/mcp') === null, 'parsePublicBaseUrl cms /mcp')
    note(parsePublicBaseUrl('https://0.0.0.0') === null, 'parsePublicBaseUrl bind-any')
    note(parsePublicBaseUrl('https://connector.example') === 'https://connector.example', 'parsePublicBaseUrl honest')

    note(safeAdvertisedOrigin('https://v-aid.ai') === 'https://127.0.0.1', 'safeAdvertisedOrigin our host')
    note(safeAdvertisedOrigin('https://0.0.0.0:8790') === 'https://127.0.0.1', 'safeAdvertisedOrigin bind-any')
    note(
      publicOriginFromRequest(asReq({ headers: { host: 'v-aid.ai' } }), null) === 'https://127.0.0.1',
      'Host v-aid.ai is not advertised',
    )
    note(
      publicOriginFromRequest(asReq({ headers: { host: 'cms.v-aid.ai:443' } }), null) === 'https://127.0.0.1',
      'Host cms:port is not advertised',
    )
    note(
      publicOriginFromRequest(asReq({ headers: { host: 'connector.example' } }), null) === 'https://connector.example',
      'Host other origin is kept',
    )
    note(
      publicOriginFromRequest(asReq({ headers: { host: 'v-aid.ai' } }), 'https://connector.example')
        === 'https://connector.example',
      'configured publicUrl wins over Host',
    )
    note(!/v-aid/.test(wwwAuthenticatePrm(publicOriginFromRequest(asReq({ headers: { host: 'v-aid.ai' } }), null))), 'PRM header no our host')

    const spoofedPrm = JSON.stringify(wellKnownJson('prm', 'https://v-aid.ai'))
    note(!/v-aid/.test(spoofedPrm), 'well-known PRM remaps our host')
    note(/https:\/\/127\.0\.0\.1\/mcp/.test(spoofedPrm), 'well-known PRM fallback resource')
    const spoofedAs = JSON.stringify(wellKnownJson('as', 'https://cms.v-aid.ai'))
    note(!/v-aid/.test(spoofedAs), 'well-known AS remaps our host')

    let hostThrew = false
    try {
      parseRelayConfig({ MCP_RELAY_HOST: 'v-aid.ai' })
    } catch {
      hostThrew = true
    }
    note(hostThrew, 'config HOST our host fail-loud')
    let urlThrew = false
    try {
      parseRelayConfig({ MCP_RELAY_PUBLIC_URL: 'https://v-aid.ai' })
    } catch {
      urlThrew = true
    }
    note(urlThrew, 'config PUBLIC_URL our host fail-loud')
    let bindUrlThrew = false
    try {
      parseRelayConfig({ MCP_RELAY_PUBLIC_URL: 'https://0.0.0.0' })
    } catch {
      bindUrlThrew = true
    }
    note(bindUrlThrew, 'config PUBLIC_URL bind-any fail-loud')
    note(parseRelayConfig({ MCP_RELAY_HOST: '0.0.0.0' }).host === '0.0.0.0', 'config HOST 0.0.0.0 still binds')

    note(cimdUrlAllowed('https://v-aid.ai/client.json').ok === false, 'CIMD our host refused')
    note(isCimdClientId('https://evil.example/x') === false, 'isCimdClientId not allowlist')
    note(isCimdClientId('https://chatgpt.com/oauth/client.json') === true, 'isCimdClientId chatgpt')
    note((await lookupRefused('127.0.0.1')) === 'EACCES', 'CIMD lookup loopback refused')
    note((await lookupRefused('169.254.169.254')) === 'EACCES', 'CIMD lookup metadata refused')
    note((await lookupRefused('v-aid.ai')) === 'EACCES', 'CIMD lookup our host refused before DNS')

    note(isAllowedOAuthRedirect('https://v-aid.ai/api/mcp/auth_callback') === false, 'redirect our host')
    note(isAllowedOAuthRedirect('http://0.0.0.0/callback') === false, 'redirect bind-any')
    note(classifyRelayPath('/project-a/mcp') === 'prefix', 'path prefix /project-a/mcp')
    note(classifyRelayPath('/mcp/../authorize') === 'prefix', 'path prefix traversal')
    note(classifyRelayPath('https://v-aid.ai/mcp') === 'prefix', 'absolute-form not /mcp')

    note(accessTokenStillLive(0, Date.now()) === false, 'expiresAt 0 is expired')
    note(timingSafeEqualHex(sha256Hex('a'), sha256Hex('a')) === true, 'hex equal')
    note(timingSafeEqualHex(sha256Hex('a'), sha256Hex('b')) === false, 'hex unequal')

    const oauth = createOAuthStore({ dataDir: null })
    const pair = createPairStore()
    oauth.putPublicClient({
      clientId: oauth.confidential.clientId,
      kind: 'public',
      secretHash: null,
      redirectUris: ['https://chatgpt.com/connector/oauth/steal'],
    })
    note(oauth.getClient(oauth.confidential.clientId)?.kind === 'confidential', 'DCR cannot overwrite confidential')

    const badDir = mkdtempSync(join(tmpdir(), 'mcp-relay-oauth-bad-'))
    try {
      writeFileSync(join(badDir, 'confidential-client.json'), '{"clientId":"host_present","secretHash":"not-hex"}\n')
      let badThrew = false
      try {
        createOAuthStore({ dataDir: badDir })
      } catch {
        badThrew = true
      }
      note(badThrew, 'present invalid confidential file fail-loud')
    } finally {
      rmSync(badDir, { recursive: true, force: true })
    }
    const reuseDir = mkdtempSync(join(tmpdir(), 'mcp-relay-oauth-ok-'))
    try {
      const first = createOAuthStore({ dataDir: reuseDir })
      const second = createOAuthStore({ dataDir: reuseDir })
      note(second.confidential.clientId === first.confidential.clientId, 'confidential reused from disk')
      note(second.confidential.created === false, 'second load is not a remint')
    } finally {
      rmSync(reuseDir, { recursive: true, force: true })
    }

    // First-boot mint race: a concurrent process on the same data dir can
    // win the exclusive-create between our own ENOENT read and our own
    // write. We must adopt what the winner persisted, not overwrite it and
    // not report our own never-written secret as real (deterministic via
    // pre-seeding the winner file - no real multi-process timing needed).
    const raceDir = mkdtempSync(join(tmpdir(), 'mcp-relay-oauth-race-'))
    try {
      const winnerSecret = 'b'.repeat(64)
      const winnerRow: ConfidentialFile = {
        clientId: 'host_racewinner00000000000',
        secretHash: winnerSecret,
        createdAt: new Date().toISOString(),
      }
      const jsonPath = join(raceDir, 'confidential-client.json')
      const loserRow: ConfidentialFile = {
        clientId: 'host_raceloser0000000000000',
        secretHash: 'c'.repeat(64),
        createdAt: new Date().toISOString(),
      }
      // Simulate the winner already having created the file via 'wx'
      // exclusive-create before we (the loser) attempt the same.
      writeFileSync(jsonPath, `${JSON.stringify(winnerRow, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
      let raceThrew = false
      let adopted: string | null = null
      try {
        adopted = writeConfidentialJsonOrAdoptWinner(jsonPath, loserRow)
      } catch {
        raceThrew = true
      }
      note(raceThrew === false, 'race loser does not throw on EEXIST')
      note(adopted === winnerRow.clientId, 'race loser adopts winner clientId, never overwrites')
      const onDisk = JSON.parse(readFileSync(jsonPath, 'utf8')) as ConfidentialFile
      note(onDisk.secretHash === winnerSecret, 'winner file on disk is untouched by the loser')
      note(onDisk.clientId !== loserRow.clientId, 'loser row never lands on disk')
    } finally {
      rmSync(raceDir, { recursive: true, force: true })
    }
    const raceBadDir = mkdtempSync(join(tmpdir(), 'mcp-relay-oauth-race-bad-'))
    try {
      const jsonPath = join(raceBadDir, 'confidential-client.json')
      writeFileSync(jsonPath, '{"clientId":"host_present","secretHash":"not-hex"}\n', { flag: 'wx' })
      let raceBadThrew = false
      try {
        writeConfidentialJsonOrAdoptWinner(jsonPath, {
          clientId: 'host_raceloserbad00000000000',
          secretHash: 'd'.repeat(64),
          createdAt: new Date().toISOString(),
        })
      } catch {
        raceBadThrew = true
      }
      note(raceBadThrew, 'race loser fails loud when the winner file is unreadable/invalid')
    } finally {
      rmSync(raceBadDir, { recursive: true, force: true })
    }

    oauth.putAccess({
      tokenHash: sha256Hex('empty-res'),
      clientId: 'x',
      resource: '',
      expiresAt: Date.now() + 60_000,
    })
    note(
      resolveModeBAuth(asReq({ headers: { authorization: 'Bearer empty-res' } }), {
        oauth,
        pair,
        publicUrl: 'https://connector.example',
        staticHeaderHash: null,
      }).kind === 'scope',
      'empty resource is insufficient_scope',
    )
    oauth.putAccess({
      tokenHash: sha256Hex('good-res'),
      clientId: 'x',
      resource: 'https://connector.example/mcp',
      expiresAt: Date.now() + 60_000,
    })
    const good = resolveModeBAuth(asReq({ headers: { authorization: 'Bearer good-res' } }), {
      oauth,
      pair,
      publicUrl: 'https://connector.example',
      staticHeaderHash: null,
    })
    note(good.kind === 'ok' && good.kind === 'ok' && good.via === 'oauth', 'matching resource is oauth ok')
    note(
      resolveModeBAuth(
        asReq({
          headers: { authorization: `Bearer ${inboundKeyFamilyPrefix()}deadbeefdeadbeef` },
        }),
        { oauth, pair, publicUrl: 'https://connector.example', staticHeaderHash: null },
      ).kind === 'mode_a',
      'Bearer Mode A is mode_a',
    )
    note(
      resolveModeBAuth(
        asReq({ headers: { authorization: `Bearer ${'a'.repeat(300)}` } }),
        { oauth, pair, publicUrl: 'https://connector.example', staticHeaderHash: null },
      ).kind === 'unauth',
      'oversize non-Mode-A Bearer is unauth',
    )
    note(
      resolveModeBAuth(
        asReq({
          headers: { 'mcp-api-key': `${inboundKeyFamilyPrefix()}deadbeefdeadbeef` },
        }),
        { oauth, pair, publicUrl: 'https://connector.example', staticHeaderHash: null },
      ).kind === 'unauth',
      'unpaired mcp-api-key is unauth not mode_a',
    )
    note(
      resolveModeBAuth(
        asReq({
          headers: { authorization: 'Bearer good-res' },
          url: '/mcp?access_token=leak',
        }),
        { oauth, pair, publicUrl: 'https://connector.example', staticHeaderHash: null },
      ).kind === 'unauth',
      'query token is unauth even with Bearer',
    )

    const publicUrlSrc = src('public-url.ts')
    note(publicUrlSrc.includes('safeAdvertisedOrigin(`https://${host}`)'), 'publicOriginFromRequest uses safeAdvertisedOrigin')
    note(!/return `https:\$\{host\}`/.test(publicUrlSrc), 'publicOriginFromRequest does not return raw Host')

    const modeBSrc = src('mode-b-auth.ts')
    const resourceGate = /if \(!row\.resource \|\| !resourceMatches\(row\.resource, origin\)\)/
    note(resourceGate.test(modeBSrc), 'Mode B empty resource fail-closed')
    const modeBCommented = modeBSrc.replace(resourceGate, '// if (!row.resource || !resourceMatches(row.resource, origin))')
    note(
      resourceGate.test(sourceWithoutComments(modeBCommented)) === false,
      'commented Mode B resource gate is not load-bearing',
    )
    note(!/row\.resource && !resourceMatches/.test(modeBSrc), 'Mode B does not skip empty resource')
    note(modeBSrc.includes('token.length > 256'), 'Mode B caps non-Mode-A Bearer length')

    const cimdSrc = src('cimd.ts')
    note(cimdSrc.includes('lookup: cimdSafeDnsLookup'), 'CIMD getOnce uses cimdSafeDnsLookup')
    note(cimdSrc.includes('res.socket.remoteAddress'), 'CIMD getOnce re-checks connected address')
    note(cimdSrc.includes("url.protocol !== 'https:'"), 'CIMD getOnce https-only')
    note(!/\? https : http/.test(cimdSrc), 'CIMD getOnce has no http fallback')
    note(!/ssrfSafeNetFetch/.test(cimdSrc), 'CIMD does not import desktop fetch')
    note(!/extractMcpInboundToken/.test(cimdSrc), 'CIMD does not copy inbound token extract')

    const storeSrc = src('oauth-store.ts')
    note(storeSrc.includes('client.clientId === confidential.clientId'), 'put/remember refuse confidential id')
    note(storeSrc.includes('existing.kind === \'confidential\'') || storeSrc.includes('existing.kind === "confidential"'), 'refuse overwrite confidential kind')
    note(/\[0-9a-f\]\{64\}/.test(storeSrc), 'confidential hash is hex')
    note(
      /throw new Error\('confidential client file is unreadable'\)/.test(storeSrc)
        && storeSrc.includes('ID_RE.test(parsed.clientId)'),
      'invalid present confidential file throws before remint',
    )
    note(storeSrc.includes("flag: 'wx'") && storeSrc.includes('writeConfidentialJsonOrAdoptWinner'), 'confidential json write is exclusive-create with race-adopt fallback')
    const raceAdoptGate = /if \(code !== 'EEXIST'\) throw err\n\s*const raw = readFileSync\(jsonPath, 'utf8'\)/
    note(raceAdoptGate.test(storeSrc), 'race loser re-throws non-EEXIST errors before adopting winner')
    const storeCommented = storeSrc.replace(raceAdoptGate, "// if (code !== 'EEXIST') throw err")
    note(
      raceAdoptGate.test(sourceWithoutComments(storeCommented)) === false,
      'commented race-adopt EEXIST gate is not load-bearing',
    )

    const oauthSrc = src('oauth.ts')
    note(/A-Za-z0-9\._~-/.test(oauthSrc), 'authorize PKCE challenge charset')
    note(oauthSrc.includes('OAUTH_STATE_MAX'), 'authorize caps state')
    note(oauthSrc.includes('temporarily_unavailable'), 'DCR cap is honest 503')
    note(!/extractMcpInboundToken/.test(oauthSrc), 'oauth does not copy inbound token extract')

    const mainSrc = src('main.ts')
    note(!/https:\$\{config\.host\}/.test(mainSrc), 'main does not advertise bind host as public URL')
    note(mainSrc.includes('safeAdvertisedOrigin'), 'main logs safeAdvertisedOrigin')

    const configSrc = src('config.ts')
    note(configSrc.includes('isOurHostingHost(raw)'), 'parseHost refuses our hosting')

    const wellKnownSrc = src('well-known.ts')
    note(wellKnownSrc.includes('safeAdvertisedOrigin(origin)'), 'well-known remaps origin')

    if (drifted.length > 0) {
      fail(drifted.join('; '))
    }
    console.log('ok oauth-source')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
