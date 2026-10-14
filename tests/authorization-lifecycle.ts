import assert from 'node:assert/strict'
import test from 'node:test'
import { EventEmitter } from 'node:events'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { MCP_RELAY_MCP_FORWARD_WAIT_MS, MCP_RELAY_PAIR_QUEUE_MAX } from '../src/constants.js'
import { createPairStore } from '../src/pair-store.js'
import { createOAuthStore } from '../src/oauth-store.js'
import { showOwnerApproval, takeOwnerApproval, ownerApprovalFailure } from '../src/owner-approval.js'
import { sha256Hex } from '../src/timing-safe.js'
import { handlePairRoute } from '../src/pair-routes.js'

test('expired commands cannot execute after a late desktop poll', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const pair = createPairStore()
  pair.hello('device', 'project-a')
  const command = pair.enqueueMcp('{"method":"tools/call"}')
  t.mock.timers.tick(MCP_RELAY_MCP_FORWARD_WAIT_MS)
  assert.equal((await command.wait).status, 503)
  assert.equal(await pair.next(0), null)
  assert.equal(pair.reply(command.requestId, 200, {}), false)
})

test('client cancellation discards a queued mutation and releases its waiter', async () => {
  const pair = createPairStore()
  pair.hello('device', 'key')
  const command = pair.enqueueMcp('{"method":"tools/call"}')
  command.cancel()
  command.cancel()
  assert.equal((await command.wait).status, 503)
  assert.equal(await pair.next(0), null)
  assert.equal(pair.reply(command.requestId, 200, {}), false)
})

test('same-device project changes revoke pending work, old pollers, and static key hash', async () => {
  const pair = createPairStore()
  pair.hello('device', 'project-a', sha256Hex('old-static-secret'))
  const oldPoll = pair.next(10_000)
  pair.hello('device', 'project-b')
  assert.equal(await oldPoll, null)
  assert.equal(pair.keyHash(), null)
  const pending = pair.enqueueMcp('{"id":1}')
  const delivered = await pair.next(0)
  assert.ok(delivered)
  pair.hello('device', 'project-c')
  assert.equal((await pending.wait).status, 503)
  pair.requeue(delivered)
  assert.equal(await pair.next(0), null)
  assert.equal(pair.reply(pending.requestId, 200, {}), false)
})

test('a resolved poll cannot deliver a command withdrawn before the route resumes', async () => {
  for (const reason of ['rebind', 'cancel', 'unavailable']) {
    const pair = createPairStore()
    pair.hello('device', 'key-a')
    const pending = pair.enqueueMcp('{"method":"tools/call"}')
    const originalNext = pair.next
    pair.next = async (...args) => {
      const item = await originalNext(...args)
      if (reason === 'rebind') pair.hello('device', 'key-b')
      else if (reason === 'cancel') pending.cancel()
      else pair.markUnavailable()
      return item
    }
    const req = Object.assign(new EventEmitter(), {
      method: 'POST', headers: { authorization: 'Bearer owner-secret' },
      socket: { destroyed: false }, aborted: false,
    }) as IncomingMessage
    let status = 0
    let payload = ''
    const res = {
      writeHead(code: number) { status = code },
      end(body?: string) { payload = body || '' },
    } as unknown as ServerResponse
    const processing = handlePairRoute(req, res, 'next', 'owner-secret', pair)
    req.emit('data', Buffer.from('{"deviceId":"device","waitMs":0}'))
    req.emit('end')
    await processing
    assert.equal(status, 204, reason)
    assert.equal(payload, '', reason)
    assert.equal((await pending.wait).status, 503)
  }
})

test('unavailability discards old commands; same-binding hello resumes new work', async () => {
  const pair = createPairStore()
  pair.hello('device', 'key')
  const old = pair.enqueueMcp('{"id":1}')
  pair.markUnavailable()
  assert.equal((await old.wait).status, 503)
  assert.equal((await pair.enqueueMcp('{"id":2}').wait).status, 503)
  pair.hello('device', 'key')
  assert.equal(pair.unavailable(), false)
  assert.equal(await pair.next(0), null)
  const next = pair.enqueueMcp('{"id":3}')
  assert.equal((await pair.next(0))?.requestId, next.requestId)
  pair.reply(next.requestId, 200, { ok: true })
  assert.equal((await next.wait).status, 200)
})

test('relay caps all unresolved requests even after desktop dequeues them', async () => {
  const pair = createPairStore()
  pair.hello('device', 'key')
  const active = []
  for (let i = 0; i < MCP_RELAY_PAIR_QUEUE_MAX; i++) {
    active.push(pair.enqueueMcp('{}'))
    assert.ok(await pair.next(0))
  }
  assert.equal((await pair.enqueueMcp('{}').wait).status, 503)
  for (const row of active) row.cancel()
  await Promise.all(active.map((row) => row.wait))
})

test('owner consent requires a one-use secret check bound to request and paired project', (t) => {
  t.mock.timers.enable({ apis: ['Date'] })
  const oauth = createOAuthStore()
  const pair = createPairStore()
  pair.hello('device', 'key-a')
  const query = new Map([['client_id', '<script>bad</script>'], ['redirect_uri', 'https://claude.ai/api/mcp/auth_callback']])
  const secret = 'test-owner-pairing-secret'
  const page = () => {
    let html = ''
    const res = { writeHead() {}, end(body: string) { html = body } } as unknown as ServerResponse
    showOwnerApproval(res, oauth, pair, query)
    assert.ok(!html.includes('<script>bad</script>'))
    assert.ok(html.includes('&lt;script&gt;bad&lt;/script&gt;'))
    assert.ok(!html.includes(secret))
    const nonce = /name="approval_nonce" value="([a-f0-9]+)"/.exec(html)?.[1]
    assert.ok(nonce)
    return new Map([['approval_nonce', nonce], ['owner_secret', secret]])
  }
  const wrong = page()
  wrong.set('owner_secret', 'wrong')
  assert.equal(ownerApprovalFailure(oauth, pair, query, wrong, secret), 'incorrect_secret')
  const approved = page()
  assert.equal(takeOwnerApproval(oauth, pair, query, approved, secret), true)
  assert.equal(ownerApprovalFailure(oauth, pair, query, approved, secret), 'stale_form')
  const tampered = page()
  assert.equal(ownerApprovalFailure(oauth, pair, new Map([['client_id', 'different']]), tampered, secret), 'request_changed')
  const moved = page()
  pair.hello('device', 'key-b')
  assert.equal(ownerApprovalFailure(oauth, pair, query, moved, secret), 'pairing_changed')
  const roundTrip = page()
  pair.hello('device', 'key-c')
  pair.hello('device', 'key-b')
  assert.equal(takeOwnerApproval(oauth, pair, query, roundTrip, secret), false)
  const rotated = page()
  pair.hello('device', 'key-b', sha256Hex('new-key-secret'))
  assert.equal(takeOwnerApproval(oauth, pair, query, rotated, secret), false)
  const expired = page()
  t.mock.timers.tick(5 * 60_000)
  assert.equal(ownerApprovalFailure(oauth, pair, query, expired, secret), 'stale_form')
})

test('approval CSP permits the registered OAuth callback origin without accepting injected directives', () => {
  const pair = createPairStore()
  pair.hello('device', 'key')
  for (const [redirect, allowed] of [
    ['https://chatgpt.com/connector_platform_oauth_redirect', 'https://chatgpt.com'],
    ['http://127.0.0.1:34901/callback', 'http://127.0.0.1:34901'],
    ['http://[::1]:34901/callback', 'http://[::1]:34901'],
    ['https://custom-client.example/callback?state=unsafe;script-src%20*', 'https://custom-client.example'],
    ['https://bad;script-src.example/callback', ''],
    ['javascript:alert(1)', ''],
  ]) {
    let headers: Record<string, string> = {}
    const res = { writeHead(_code: number, value: Record<string, string>) { headers = value }, end() {} } as unknown as ServerResponse
    showOwnerApproval(res, createOAuthStore(), pair, new Map([['redirect_uri', redirect!]]))
    const formPolicy = headers['content-security-policy']!.split('; ').find(value => value.startsWith('form-action'))
    assert.equal(formPolicy, `form-action 'self'${allowed ? ` ${allowed}` : ''}`)
    assert.equal(headers['referrer-policy'], 'same-origin')
    assert.ok(!headers['content-security-policy']!.includes('script-src'))
  }
})

test('OAuth grants stay on the approved binding and all grant types expire on re-pair', () => {
  const oauth = createOAuthStore()
  const expiresAt = Date.now() + 60_000
  oauth.bindPair('device:key-a')
  oauth.putAccess({ tokenHash: sha256Hex('access'), clientId: 'client', resource: 'https://relay.example/mcp', expiresAt })
  oauth.putRefresh({ tokenHash: sha256Hex('refresh'), clientId: 'client', resource: 'https://relay.example/mcp', expiresAt, publicClient: true })
  oauth.putCode({ codeHash: sha256Hex('code'), clientId: 'client', resource: 'https://relay.example/mcp', expiresAt, challenge: 'challenge', redirectUri: 'https://claude.ai/api/mcp/auth_callback', used: false })
  oauth.bindPair('device:key-a')
  assert.ok(oauth.findAccess('access', Date.now()))
  oauth.bindPair('device:key-b')
  assert.equal(oauth.findAccess('access', Date.now()), null)
  assert.equal(oauth.takeRefresh('refresh', Date.now()), null)
  assert.equal(oauth.takeCode('code', Date.now()), null)
  assert.ok(oauth.getClient(oauth.confidential.clientId))
})
