/**
 * I10 leftovers: listen epoch / stale bind, advertise trailing-dot
 * our-web, TLS files at parse, reserved desktop listen ports,
 * hang-up polarity, in-flight refuse not FIFO. T21 stays OPEN.
 * No top-level await.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseRelayConfig } from '../src/config.js'
import {
  MCP_RELAY_BANNED_PORTS,
  MCP_RELAY_DEFAULT_PORT,
  MCP_RELAY_HEALTH_PLAIN_BODY,
  MCP_RELAY_MAX_CONCURRENT,
  TEAM_SPACE_HEALTH_PLAIN_BODY,
} from '../src/constants.js'
import { createInFlightSet } from '../src/in-flight.js'
import {
  bumpRelayListenEpoch,
  createRelayServer,
  listenRelay,
} from '../src/listen.js'
import {
  isBindAnyHost,
  isLoopbackBindHost,
  isOurHostingHost,
  parsePublicBaseUrl,
  publicOriginFromRequest,
  safeAdvertisedOrigin,
} from '../src/public-url.js'
import { peekJsonRpc, relayClientHungUp } from '../src/rpc-peek.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const listenPath = join(root, 'src/listen.ts')
const publicUrlPath = join(root, 'src/public-url.ts')

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

function asReq(host: string): IncomingMessage {
  return { headers: { host } } as IncomingMessage
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = http.createServer()
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      const port = addr && typeof addr === 'object' ? addr.port : 0
      server.close((err) => (err ? reject(err) : resolve(port)))
    })
    server.on('error', reject)
  })
}

function throws(fn: () => void): boolean {
  try {
    fn()
    return false
  } catch {
    return true
  }
}

void (async () => {
  const drifted: string[] = []
  const note = (ok: boolean, row: string): void => {
    if (!ok) drifted.push(row)
  }

  try {
    note(MCP_RELAY_HEALTH_PLAIN_BODY === 'AItomation MCP relay\n', 'health plain bytes unchanged')
    note(String(MCP_RELAY_HEALTH_PLAIN_BODY) !== String(TEAM_SPACE_HEALTH_PLAIN_BODY), 'health bytes are not the team server line')
    note(MCP_RELAY_DEFAULT_PORT === 8790, 'default port 8790')
    note(MCP_RELAY_BANNED_PORTS.includes(3737), 'banned WhatsApp listen 3737')
    note(MCP_RELAY_BANNED_PORTS.includes(8765), 'banned workflow listen 8765')
    note(MCP_RELAY_BANNED_PORTS.includes(8787), 'banned Local API 8787')
    note(MCP_RELAY_BANNED_PORTS.includes(8788), 'banned team server 8788')
    note(!MCP_RELAY_BANNED_PORTS.includes(8790), '8790 is not banned')
    note(throws(() => parseRelayConfig({ MCP_RELAY_PORT: '3737' })), 'config 3737 refuse')
    note(throws(() => parseRelayConfig({ MCP_RELAY_PORT: '8765' })), 'config 8765 refuse')

    // Refuse list only. true means the relay must not bind or advertise
    // these account/CMS hosts. We never serve this door there.
    note(isOurHostingHost('v-aid.ai') === true, 'refuse our account host')
    note(isOurHostingHost('v-aid.ai.') === true, 'refuse trailing-dot FQDN')
    note(isOurHostingHost('cms.v-aid.ai.') === true, 'refuse cms trailing-dot FQDN')
    note(isOurHostingHost('V-AID.AI.') === true, 'refuse case + trailing-dot')
    note(isOurHostingHost('v-aid.ai:443.') === true, 'refuse host:port + trailing-dot')
    note(isOurHostingHost('notv-aid.ai') === false, 'substring notv-aid.ai is not our host')
    note(isOurHostingHost('v-aid.ai.evil.com') === false, 'suffix after our host is not our host')
    note(isOurHostingHost('connector.example') === false, 'customer host is not our host')
    note(!/v-aid\\.ai\/i/.test(src('public-url.ts')), 'public-url has no substring /v-aid.ai/i')

    note(safeAdvertisedOrigin('https://v-aid.ai.') === 'https://127.0.0.1', 'advertise trailing-dot our host falls back')
    note(parsePublicBaseUrl('https://v-aid.ai.') === null, 'parsePublicBaseUrl trailing-dot our host')
    note(
      publicOriginFromRequest(asReq('v-aid.ai.'), null) === 'https://127.0.0.1',
      'Host trailing-dot our host is not advertised',
    )
    note(isBindAnyHost('::0') === true, '::0 is bind-any')
    note(isBindAnyHost('0:0:0:0:0:0:0:0') === true, 'long unspecified is bind-any')
    note(isBindAnyHost('0000:0000:0000:0000:0000:0000:0000:0000') === true, 'padded unspecified is bind-any')
    note(isBindAnyHost('::ffff:0:0') === true, 'v4-mapped unspecified is bind-any')
    note(isBindAnyHost('::ffff:0000:0000') === true, 'padded v4-mapped unspecified is bind-any')
    note(isBindAnyHost('::ffff:00:00') === true, 'short-padded v4-mapped unspecified is bind-any')
    note(isBindAnyHost('0:0:0:0:0:ffff:0000:0000') === true, 'long padded v4-mapped unspecified is bind-any')
    note(parsePublicBaseUrl('https://[::ffff:0:0]') === null, 'mapped unspecified is not a public origin')
    note(isLoopbackBindHost('127.0.0.1') === true, 'loopback 127.0.0.1')
    note(isLoopbackBindHost('localhost') === true, 'loopback localhost')
    note(isLoopbackBindHost('::ffff:7f00:0001') === true, 'padded v4-mapped loopback')
    note(isLoopbackBindHost('connector.example') === false, 'named host is not loopback')

    note(!throws(() => parseRelayConfig({ MCP_RELAY_HOST: '127.0.0.1' })), 'loopback without certs ok')
    note(!throws(() => parseRelayConfig({ MCP_RELAY_HOST: '0.0.0.0' })), 'bind-any without certs ok')
    note(throws(() => parseRelayConfig({ MCP_RELAY_HOST: 'v-aid.ai.' })), 'config HOST refuse trailing-dot our host')
    note(throws(() => parseRelayConfig({ MCP_RELAY_HOST: 'v-aid.ai:443.' })), 'config HOST refuse port trailing-dot our host')
    note(
      !throws(() => parseRelayConfig({ MCP_RELAY_HOST: '0000:0000:0000:0000:0000:0000:0000:0000' })),
      'padded unspecified without certs ok',
    )
    note(
      throws(() => parseRelayConfig({ MCP_RELAY_HOST: 'connector.example' })),
      'named host without certs fail-closed',
    )
    note(
      throws(() => parseRelayConfig({
        MCP_RELAY_TLS_CERT_FILE: '/no/such/cert.pem',
        MCP_RELAY_TLS_KEY_FILE: '/no/such/key.pem',
      })),
      'missing cert files fail at parse',
    )
    const emptyDir = mkdtempSync(join(tmpdir(), 'mcp-relay-tls-'))
    try {
      const emptyCert = join(emptyDir, 'cert.pem')
      const emptyKey = join(emptyDir, 'key.pem')
      writeFileSync(emptyCert, '')
      writeFileSync(emptyKey, '')
      note(
        throws(() => parseRelayConfig({
          MCP_RELAY_TLS_CERT_FILE: emptyCert,
          MCP_RELAY_TLS_KEY_FILE: emptyKey,
        })),
        'empty cert files fail at parse',
      )
    } finally {
      rmSync(emptyDir, { recursive: true, force: true })
    }
    const bareState = {
      closing: () => false,
      inflight: createInFlightSet(),
      pairSecret: null,
    }
    note(
      throws(() => createRelayServer({
        host: 'connector.example',
        port: 18790,
        dataDir: '/tmp',
        pairSecret: null,
        publicUrl: null,
        staticHeaderHash: null,
        tlsCertFile: null,
        tlsKeyFile: null,
      }, bareState)),
      'createRelayServer named-host HTTP fail-closed',
    )
    note(
      throws(() => createRelayServer({
        host: '127.0.0.1',
        port: 3737,
        dataDir: '/tmp',
        pairSecret: null,
        publicUrl: null,
        staticHeaderHash: null,
        tlsCertFile: null,
        tlsKeyFile: null,
      }, bareState)),
      'createRelayServer refuses banned 3737',
    )
    note(
      throws(() => createRelayServer({
        host: '127.0.0.1',
        port: 8765,
        dataDir: '/tmp',
        pairSecret: null,
        publicUrl: null,
        staticHeaderHash: null,
        tlsCertFile: null,
        tlsKeyFile: null,
      }, bareState)),
      'createRelayServer refuses banned 8765',
    )
    note(
      throws(() => createRelayServer({
        host: '127.0.0.1',
        port: 18791,
        dataDir: '/tmp',
        pairSecret: null,
        publicUrl: null,
        staticHeaderHash: null,
        tlsCertFile: '/tmp/only-cert.pem',
        tlsKeyFile: null,
      }, bareState)),
      'createRelayServer refuses one-sided TLS',
    )

    note(
      relayClientHungUp(
        { aborted: false, destroyed: true, socket: { destroyed: false } } as IncomingMessage,
        { writableEnded: false } as ServerResponse,
      ) === false,
      'body-complete IncomingMessage.destroyed is not hang-up',
    )
    note(
      relayClientHungUp(
        { aborted: true, socket: { destroyed: false } } as IncomingMessage,
        { writableEnded: false } as ServerResponse,
      ) === true,
      'req.aborted is hang-up',
    )
    note(
      relayClientHungUp(
        { aborted: false, socket: { destroyed: true } } as IncomingMessage,
        { writableEnded: false } as ServerResponse,
      ) === true,
      'socket.destroyed is hang-up',
    )
    note(
      relayClientHungUp(
        { aborted: true, socket: { destroyed: true } } as IncomingMessage,
        { writableEnded: true } as ServerResponse,
      ) === false,
      'ended reply is not hang-up',
    )
    note(peekJsonRpc('{"jsonrpc":"2.0","method":"initialized"}').notification === true, 'peek notification')

    const hung = src('rpc-peek.ts')
    note(hung.includes('export function relayClientHungUp'), 'rpc-peek owns hang-up leaf')
    note(hung.includes('req.aborted === true'), 'hang-up reads req.aborted')
    note(hung.includes('sock.destroyed === true'), 'hang-up reads socket.destroyed')
    note(!/if \(req\.destroyed === true\)/.test(hung), 'hang-up does not use req.destroyed')

    const cap = createInFlightSet()
    const tokens: Array<() => void> = []
    for (let i = 0; i < MCP_RELAY_MAX_CONCURRENT; i++) {
      const t = cap.begin()
      note(Boolean(t), `in-flight slot ${i}`)
      if (t) tokens.push(t)
    }
    note(cap.begin() === null, 'in-flight refuses at cap')
    note(cap.size() === MCP_RELAY_MAX_CONCURRENT, 'in-flight size stays at cap')
    note(Boolean(tokens[0]), 'first live token still held')
    tokens[0]?.()
    const after = cap.begin()
    note(Boolean(after), 'release of live token frees a slot (not FIFO of another live)')
    after?.()
    for (const t of tokens.slice(1)) t()
    const inflightSrc = src('in-flight.ts')
    note(!/pending\.values\(\)\.next/.test(inflightSrc), 'in-flight has no FIFO values().next')
    note(!/oldestKey/.test(inflightSrc), 'in-flight has no oldestKey FIFO')
    note(!/while \(pending\.size >/.test(inflightSrc), 'in-flight has no FIFO while')

    const listenSrc = src('listen.ts')
    note(listenSrc.includes('_listenEpoch !== epoch'), 'listen checks epoch before assign')
    note(
      /createRelayServer[\s\S]{0,180}_listenEpoch !== epoch/.test(listenSrc),
      'epoch re-check after createRelayServer',
    )
    note(listenSrc.includes('bumpRelayListenEpoch()'), 'drain bumps epoch')
    note(listenSrc.includes('closeRelayServer'), 'stale/error bind closes server')
    note(listenSrc.includes('listen cancelled'), 'stale bind rejects cancelled')
    note(!/server\.listen\(\s*0\s*,/.test(listenSrc), 'listen source does not bind port 0')
    note(!/setTimeout\s*\([^)]*exit/.test(listenSrc), 'no short grace then exit')

    const mainSrc = src('main.ts')
    note(
      mainSrc.indexOf('installDrainShutdown') < mainSrc.indexOf('await listenRelay'),
      'main arms drain before listen',
    )
    note(mainSrc.includes('StartedRelayBox'), 'main uses started box')
    note(mainSrc.includes('listenRelay(config') && mainSrc.includes('startedBox'), 'listenRelay receives the started box')
    note(listenSrc.includes('if (box) box.current = started'), 'onListen stamps the box before resolve')
    note(
      listenSrc.indexOf('if (box) box.current = started')
        < listenSrc.indexOf("settleErr(new Error('listen cancelled'))"),
      'onListen stamps box before epoch re-check',
    )

    const port = await freePort()
    const cfg = parseRelayConfig({
      MCP_RELAY_PORT: String(port),
      MCP_RELAY_HOST: '127.0.0.1',
    })
    const pending = listenRelay(cfg, {
      closing: () => false,
      inflight: createInFlightSet(),
      pairSecret: null,
    })
    bumpRelayListenEpoch()
    let cancelled = false
    try {
      const started = await pending
      try { started.server.close() } catch { /* ignore */ }
      try { started.server.closeAllConnections() } catch { /* ignore */ }
    } catch (err) {
      cancelled = err instanceof Error && err.message === 'listen cancelled'
    }
    note(cancelled, 'same-tick epoch bump cancels stale bind')

    const epochBlock = [
      '      if (_listenEpoch !== epoch) {',
      '        settleErr(new Error(\'listen cancelled\'))',
      '        return',
      '      }',
    ].join('\n')
    const epochCommentedBlock = [
      '      // if (_listenEpoch !== epoch) {',
      '      //   settleErr(new Error(\'listen cancelled\'))',
      '      //   return',
      '      // }',
    ].join('\n')
    const listenRaw = readFileSync(listenPath, 'utf8')
    note(listenRaw.includes(epochBlock), 'epoch gate block present')
    const epochCommented = listenRaw.replace(epochBlock, epochCommentedBlock)
    note(
      sourceWithoutComments(epochCommented).includes(epochBlock) === false,
      'commented onListen epoch gate is not load-bearing',
    )
    writeFileSync(listenPath, epochCommented)
    let breakRed = false
    try {
      const { listenRelay: brokenListen, bumpRelayListenEpoch: brokenBump } = await import(
        `../src/listen.ts?pinbreak=${Date.now()}`
      )
      const breakPort = await freePort()
      const breakCfg = parseRelayConfig({
        MCP_RELAY_PORT: String(breakPort),
        MCP_RELAY_HOST: '127.0.0.1',
      })
      const breakPending = brokenListen(breakCfg, {
        closing: () => false,
        inflight: createInFlightSet(),
        pairSecret: null,
      })
      brokenBump()
      try {
        const started = await breakPending
        breakRed = true
        try { started.server.close() } catch { /* ignore */ }
        try { started.server.closeAllConnections() } catch { /* ignore */ }
      } catch {
        breakRed = false
      }
    } finally {
      writeFileSync(listenPath, listenRaw)
    }
    note(breakRed, 'pin-break epoch gate RED (stale bind assigned) then restore')

    const stripGate = '.replace(/\\.+$/, \'\')'
    const publicRaw = readFileSync(publicUrlPath, 'utf8')
    note(publicRaw.includes(stripGate), 'hostnameKey strips trailing dots')
    const stripCommented = publicRaw.replace(stripGate, '/* trailing-dot strip */')
    note(!sourceWithoutComments(stripCommented).includes(stripGate), 'commented trailing-dot strip is gone')
    writeFileSync(publicUrlPath, stripCommented)
    let stripRed = false
    try {
      const brokenUrl = await import(`../src/public-url.ts?pinbreak=${Date.now()}`)
      stripRed = brokenUrl.isOurHostingHost('v-aid.ai.') === false
        && brokenUrl.safeAdvertisedOrigin('https://v-aid.ai.') === 'https://v-aid.ai.'
    } finally {
      writeFileSync(publicUrlPath, publicRaw)
    }
    note(stripRed, 'pin-break trailing-dot strip RED (our host advertised) then restore')

    if (drifted.length > 0) {
      fail(drifted.join('; '))
    }
    console.log('ok listen-leftover')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
