/**
 * H10 leftovers: /pair/next dead write requeues the same requestId,
 * requeue skips a settled waiter, oauth store never FIFO-evicts live
 * rows, well-known / Mode B refuse our-web advertise, hello refuses
 * inbound-key plaintext as keyId. No top-level await.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { MCP_RELAY_OAUTH_ROW_MAX, MCP_RELAY_PAIR_ID_MAX } from '../src/constants.js'
import { inboundKeyFamilyPrefix } from '../src/mode-a-key.js'
import { resolveModeBAuth } from '../src/mode-b-auth.js'
import { createOAuthStore } from '../src/oauth-store.js'
import { handlePairRoute, pairNextClientHungUp } from '../src/pair-routes.js'
import { createPairStore } from '../src/pair-store.js'
import { sha256Hex } from '../src/timing-safe.js'
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

function pairReq(body: string, secret: string): IncomingMessage {
  const req = Readable.from([Buffer.from(body, 'utf8')]) as IncomingMessage
  req.method = 'POST'
  req.headers = { authorization: `Bearer ${secret}` }
  Object.defineProperty(req, 'aborted', { configurable: true, writable: true, value: false })
  req.socket = { destroyed: false } as IncomingMessage['socket']
  return req
}

function throwingRes(): ServerResponse {
  return {
    writableEnded: false,
    destroyed: false,
    writeHead(): ServerResponse {
      throw new Error('EPIPE')
    },
    end(): ServerResponse {
      throw new Error('EPIPE')
    },
  } as unknown as ServerResponse
}

void (async () => {
  const drifted: string[] = []
  const note = (ok: boolean, row: string): void => {
    if (!ok) drifted.push(row)
  }

  try {
    note(
      pairNextClientHungUp(
        { aborted: false, destroyed: true, socket: { destroyed: false } } as IncomingMessage,
        { writableEnded: false } as ServerResponse,
      ) === false,
      'IncomingMessage.destroyed is not hang-up',
    )
    note(
      pairNextClientHungUp(
        { aborted: true, socket: { destroyed: false } } as IncomingMessage,
        { writableEnded: false } as ServerResponse,
      ) === true,
      'req.aborted is hang-up',
    )

    const secret = 'pair-secret-16ok!!'
    const pair = createPairStore()
    pair.hello('dev-1', 'key-1')
    const enq = pair.enqueueMcp('{"jsonrpc":"2.0","id":1,"method":"initialize"}')
    await handlePairRoute(
      pairReq('{"deviceId":"dev-1","waitMs":10}', secret),
      throwingRes(),
      'next',
      secret,
      pair,
    )
    const again = await pair.next(10)
    note(!!again && again.requestId === enq.requestId, 'dead write after next requeues same requestId')
    pair.resetForTest()

    const settled = createPairStore()
    settled.hello('dev-2', 'key-2')
    const settledEnq = settled.enqueueMcp('{"jsonrpc":"2.0","id":2,"method":"ping"}')
    const taken = await settled.next(10)
    note(!!taken && taken.requestId === settledEnq.requestId, 'taken matches enqueue')
    if (taken) {
      note(settled.reply(taken.requestId, 200, { ok: true }) === true, 'reply settles waiter')
      settled.requeue(taken)
    }
    const zombie = await settled.next(5)
    note(zombie === null, 'requeue of settled waiter is a no-op')
    settled.resetForTest()

    const inboundPlain = `${inboundKeyFamilyPrefix()}deadbeefdeadbeef`
    const refuseHello = createPairStore()
    refuseHello.hello('dev-3', inboundPlain)
    note(refuseHello.paired() === false, 'hello refuses inbound-key plaintext as keyId')
    const helloRes = {
      writableEnded: false,
      destroyed: false,
      status: 0,
      body: '',
      writeHead(status: number): void {
        this.status = status
      },
      end(buf: Buffer): void {
        this.body = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf)
        this.writableEnded = true
      },
    }
    await handlePairRoute(
      pairReq(JSON.stringify({ deviceId: 'dev-3', keyId: inboundPlain }), secret),
      helloRes as unknown as ServerResponse,
      'hello',
      secret,
      refuseHello,
    )
    note(helloRes.status === 400, 'pair hello inbound-key keyId is 400')
    note(refuseHello.paired() === false, 'pair hello inbound-key keyId does not pair')

    const oversize = createPairStore()
    const tooLong = 'k'.repeat(MCP_RELAY_PAIR_ID_MAX + 1)
    note(oversize.hello('dev-4', tooLong) === false, 'hello store refuses oversize keyId')
    note(oversize.paired() === false, 'oversize keyId does not pair')
    const oversizeRes = {
      writableEnded: false,
      destroyed: false,
      status: 0,
      body: '',
      writeHead(status: number): void {
        this.status = status
      },
      end(buf: Buffer): void {
        this.body = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf)
        this.writableEnded = true
      },
    }
    await handlePairRoute(
      pairReq(JSON.stringify({ deviceId: 'dev-4', keyId: tooLong }), secret),
      oversizeRes as unknown as ServerResponse,
      'hello',
      secret,
      oversize,
    )
    note(oversizeRes.status === 400, 'pair hello oversize keyId is 400 not 200')
    note(oversize.paired() === false, 'pair hello oversize keyId does not pair')

    const nulStore = createPairStore()
    note(nulStore.hello('dev\0x', 'key-ok') === false, 'hello store refuses NUL deviceId')
    const nulRes = {
      writableEnded: false,
      destroyed: false,
      status: 0,
      writeHead(status: number): void {
        this.status = status
      },
      end(): void {
        this.writableEnded = true
      },
    }
    await handlePairRoute(
      pairReq(JSON.stringify({ deviceId: 'dev\0x', keyId: 'key-ok' }), secret),
      nulRes as unknown as ServerResponse,
      'hello',
      secret,
      nulStore,
    )
    note(nulRes.status === 400, 'pair hello NUL deviceId is 400 not 200')

    const abortPair = createPairStore()
    abortPair.hello('dev-5', 'key-5')
    const preAbort = new AbortController()
    preAbort.abort()
    const abortedWait = abortPair.next(8000, preAbort.signal)
    const lostEnq = abortPair.enqueueMcp('{"jsonrpc":"2.0","id":3,"method":"ping"}')
    const afterAbort = await Promise.race([
      abortedWait,
      new Promise<string>((resolve) => setTimeout(() => resolve('hung'), 20)),
    ])
    note(afterAbort === null, 'already-aborted next settles immediately')
    const delivered = await abortPair.next(10)
    note(!!delivered && delivered.requestId === lostEnq.requestId, 'aborted next does not swallow enqueue')
    abortPair.resetForTest()

    const attachAbort = createPairStore()
    attachAbort.hello('dev-6', 'key-6')
    const lateAc = new AbortController()
    const origAdd = lateAc.signal.addEventListener.bind(lateAc.signal)
    lateAc.signal.addEventListener = ((type: string, fn: EventListenerOrEventListenerObject, opts?: boolean | AddEventListenerOptions) => {
      origAdd(type, fn, opts)
      if (type === 'abort') lateAc.abort()
    }) as AbortSignal['addEventListener']
    const lateWait = attachAbort.next(8000, lateAc.signal)
    const lateEnq = attachAbort.enqueueMcp('{"jsonrpc":"2.0","id":4,"method":"ping"}')
    const lateSettled = await Promise.race([
      lateWait,
      new Promise<string>((resolve) => setTimeout(() => resolve('hung'), 20)),
    ])
    note(lateSettled === null, 'abort-during-attach next settles, no leftover waiter')
    const lateGot = await attachAbort.next(10)
    note(!!lateGot && lateGot.requestId === lateEnq.requestId, 'abort-during-attach does not swallow enqueue')
    attachAbort.resetForTest()

    const oauth = createOAuthStore({ dataDir: null })
    oauth.putAccess({
      tokenHash: sha256Hex('our-web-res'),
      clientId: 'x',
      resource: 'https://v-aid.ai/mcp',
      expiresAt: Date.now() + 60_000,
    })
    const ourWebAuth = resolveModeBAuth(
      { headers: { authorization: 'Bearer our-web-res' }, url: '/mcp' } as IncomingMessage,
      {
        oauth,
        pair: createPairStore(),
        publicUrl: 'https://connector.example',
        staticHeaderHash: null,
      },
    )
    note(ourWebAuth.kind === 'scope', 'Mode B token resource on our-web is scope')

    const capStore = createOAuthStore({ dataDir: null })
    const live = Date.now() + 60_000
    for (let i = 0; i < MCP_RELAY_OAUTH_ROW_MAX; i += 1) {
      capStore.putAccess({
        tokenHash: sha256Hex(`live-${i}`),
        clientId: 'cap',
        resource: 'https://connector.example/mcp',
        expiresAt: live,
      })
    }
    const first = capStore.findAccess('live-0', Date.now())
    capStore.putAccess({
      tokenHash: sha256Hex('overflow-live'),
      clientId: 'cap',
      resource: 'https://connector.example/mcp',
      expiresAt: live,
    })
    note(first !== null, 'live row at cap is not FIFO-evicted')
    note(capStore.findAccess('live-0', Date.now()) !== null, 'first live access still findable at cap')
    note(capStore.findAccess('overflow-live', Date.now()) === null, 'new live row refused at cap')

    oauth.rememberCimd({
      clientId: 'https://v-aid.ai/client.json',
      kind: 'cimd',
      secretHash: null,
      redirectUris: ['https://chatgpt.com/connector/oauth/x'],
    })
    note(oauth.getClient('https://v-aid.ai/client.json') === null, 'rememberCimd refuses our-web clientId')
    oauth.putPublicClient({
      clientId: 'https://cms.v-aid.ai/oauth/client.json',
      kind: 'cimd',
      secretHash: null,
      redirectUris: ['https://chatgpt.com/connector/oauth/x'],
    })
    note(oauth.getClient('https://cms.v-aid.ai/oauth/client.json') === null, 'putPublicClient refuses our-web CIMD')

    const spoofedPrm = JSON.stringify(wellKnownJson('prm', 'https://v-aid.ai'))
    note(!/v-aid/.test(spoofedPrm), 'well-known PRM does not advertise v-aid')
    note(/https:\/\/127\.0\.0\.1\/mcp/.test(spoofedPrm), 'well-known PRM empty/our-web uses fallback resource')
    const spoofedAs = JSON.stringify(wellKnownJson('as', 'https://cms.v-aid.ai'))
    note(!/v-aid/.test(spoofedAs), 'well-known AS does not advertise cms')
    const emptyPrm = JSON.stringify(wellKnownJson('prm', ''))
    note(/https:\/\/127\.0\.0\.1\/mcp/.test(emptyPrm), 'well-known empty origin is fallback resource')
    const customerHost = JSON.stringify(wellKnownJson('prm', 'https://notv-aid.ai'))
    note(/https:\/\/notv-aid\.ai\/mcp/.test(customerHost), 'well-known substring v-aid.ai in hostname is not remapped')
    note(!/127\.0\.0\.1/.test(customerHost), 'well-known customer host is not fallback')

    const badDir = mkdtempSync(join(tmpdir(), 'mcp-relay-oauth-h10-'))
    try {
      writeFileSync(join(badDir, 'confidential-client.json'), '{not-json')
      let threw = false
      try {
        createOAuthStore({ dataDir: badDir })
      } catch (err) {
        threw = err instanceof Error && err.message === 'confidential client file is unreadable'
      }
      note(threw, 'unreadable confidential file fail-closed with named error')
    } finally {
      rmSync(badDir, { recursive: true, force: true })
    }

    const pairRoutesSrc = src('pair-routes.ts')
    const deadWriteGate = /if \(!wrote\) pair\.requeue\(item\)/
    note(deadWriteGate.test(pairRoutesSrc), 'dead write requeues same requestId')
    const deadWriteCommented = pairRoutesSrc.replace(deadWriteGate, '// if (!wrote) pair.requeue(item)')
    note(
      deadWriteGate.test(sourceWithoutComments(deadWriteCommented)) === false,
      'commented dead-write requeue is not load-bearing (TOOL-G31-066)',
    )
    note(pairRoutesSrc.includes("if (!body.ok)"), 'failed pair body does not fall through')
    note(pairRoutesSrc.includes('isModeAPublicToken(keyId)'), 'hello refuses Mode A keyId')
    note(pairRoutesSrc.includes('if (!pair.hello('), 'pair hello store refuse is 400')
    note(pairRoutesSrc.includes('pairNextClientHungUp'), 'next hang-up uses pairNextClientHungUp')
    note(!/if \(req\.destroyed === true\)/.test(pairRoutesSrc), 'IncomingMessage.destroyed is not hang-up')

    const storeSrc = src('pair-store.ts')
    const requeueGate = /if \(!mcpWaiters\.has\(requestId\)\) return/
    note(requeueGate.test(storeSrc), 'requeue skips settled waiter')
    const requeueCommented = storeSrc.replace(requeueGate, '// if (!mcpWaiters.has(requestId)) return')
    note(
      requeueGate.test(sourceWithoutComments(requeueCommented)) === false,
      'commented requeue waiter gate is not load-bearing',
    )
    note(storeSrc.includes('isModeAPublicToken(k)'), 'pair store hello refuses inbound-key plaintext')
    note(storeSrc.includes('return false'), 'pair store hello refuse is false')
    note(storeSrc.includes('if (signal?.aborted)'), 'next re-checks aborted after attach')

    const oauthSrc = src('oauth-store.ts')
    note(oauthSrc.includes('roomForNewRow'), 'oauth store admits by room, not FIFO-evict')
    note(!/map\.keys\(\)\.next\(\)/.test(oauthSrc), 'oauth store has no FIFO first-key evict')
    note(oauthSrc.includes('clientIdIsOurWeb'), 'oauth store refuses our-web CIMD id')
    note(
      (oauthSrc.match(/throw new Error\('confidential client file is unreadable'\)/g) || []).length >= 2,
      'unreadable confidential file throws named error on load and hash',
    )

    const wellSrc = src('well-known.ts')
    note(wellSrc.includes('safeAdvertisedOrigin(origin)'), 'well-known remaps origin')
    note(wellSrc.includes('isOurHostingHost'), 'well-known refuses our-web host')
    note(wellSrc.includes('urlNamesOurWeb'), 'well-known our-web belt is hostname not substring')
    note(!/v-aid\\.ai\/i\.test\(/.test(wellSrc), 'well-known has no substring v-aid.ai test')

    const modeBSrc = src('mode-b-auth.ts')
    note(modeBSrc.includes('resourceNamesOurWeb'), 'Mode B refuses our-web resource')
    const resourceGate = /if \(!row\.resource \|\| !resourceMatches\(row\.resource, origin\)\)/
    note(resourceGate.test(modeBSrc), 'Mode B empty resource fail-closed')

    if (drifted.length > 0) {
      fail(drifted.join('; '))
    }
    console.log('ok pair-oauth-leftover')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
