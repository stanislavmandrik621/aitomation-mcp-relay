import assert from 'node:assert/strict'
import test from 'node:test'
import http from 'node:http'
import { once } from 'node:events'
import { createHash } from 'node:crypto'
import { parseRelayConfig } from '../src/config.js'
import { parseOAuthClientPolicy } from '../src/client-policy.js'
import { cimdUrlAllowed, resolveCimdHop, parseCimdDocument } from '../src/cimd.js'
import { isAllowedOAuthRedirect } from '../src/redirects.js'
import { createRelayListener } from '../src/handler.js'
import { createInFlightSet } from '../src/in-flight.js'
import { createPairStore } from '../src/pair-store.js'

const callback = 'https://custom-client.example/oauth/complete'
const policy = parseOAuthClientPolicy({
  MCP_RELAY_OAUTH_REDIRECT_URIS: JSON.stringify([callback, 'http://127.0.0.1:3456/oauth/callback', 'http://[::1]:3456/oauth/callback']),
  MCP_RELAY_CIMD_HOSTS: '["custom-client.example"]',
})

test('operator-configured clients do not depend on a provider name', () => {
  assert.equal(isAllowedOAuthRedirect(callback), false)
  assert.equal(isAllowedOAuthRedirect(callback, policy), true)
  assert.equal(isAllowedOAuthRedirect(callback + '/other', policy), false)
  assert.equal(isAllowedOAuthRedirect('http://127.0.0.1:3456/oauth/callback', policy), true)
  assert.equal(isAllowedOAuthRedirect('http://127.0.0.1:3457/oauth/callback', policy), false)
  assert.equal(isAllowedOAuthRedirect('http://[::1]:3456/oauth/callback', policy), true)
  assert.equal(cimdUrlAllowed('https://custom-client.example/client.json').ok, false)
  assert.equal(cimdUrlAllowed('https://custom-client.example/client.json', policy).ok, true)
  assert.equal(resolveCimdHop(new URL('https://custom-client.example/client.json'), 'https://untrusted.example/client.json', policy).ok, false)
  assert.equal(resolveCimdHop(new URL('https://custom-client.example/client.json'), 'http://127.0.0.1/secret', policy).ok, false)
  assert.ok(parseCimdDocument('https://custom-client.example/client.json', JSON.stringify({
    client_id: 'https://custom-client.example/client.json', redirect_uris: [callback], token_endpoint_auth_method: 'none',
  }), policy))
  assert.deepEqual(parseRelayConfig({ MCP_RELAY_OAUTH_REDIRECT_URIS: JSON.stringify([callback]) }).clientPolicy?.redirectUris, [callback])
})

test('invalid operator policies fail startup instead of opening arbitrary redirects or fetch hosts', () => {
  for (const uri of ['https://*.example/callback', 'http://public.example/callback', 'https://user:secret@example.com/callback',
    'https://example.com/callback#fragment', 'https://127.0.0.1/callback', 'javascript:alert(1)', 'https://cms.v-aid.ai/callback']) {
    assert.throws(() => parseOAuthClientPolicy({ MCP_RELAY_OAUTH_REDIRECT_URIS: JSON.stringify([uri]) }), uri)
  }
  for (const host of ['*', '*.example', '127.0.0.1', 'localhost', '169.254.169.254', 'foo.v-aid.ai', 'https://example.com', 'example.com:8443']) {
    assert.throws(() => parseOAuthClientPolicy({ MCP_RELAY_CIMD_HOSTS: JSON.stringify([host]) }), host)
  }
  for (const raw of ['not-json', '{}', '[42]']) assert.throws(() => parseOAuthClientPolicy({ MCP_RELAY_OAUTH_REDIRECT_URIS: raw }))
})

test('a custom MCP client completes DCR, owner approval, PKCE, refresh and authenticated forwarding over HTTP', async () => {
  const pair = createPairStore()
  pair.hello('test-device', 'test-key', null, true)
  const origin = 'https://relay.example'
  const ownerSecret = 'test-owner-secret-long-enough'
  const server = http.createServer(createRelayListener({ closing: () => false, inflight: createInFlightSet(), pairSecret: ownerSecret, publicUrl: origin, pair, clientPolicy: policy }))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const base = `http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`
  const post = (path: string, body: unknown) => fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  try {
    const rejected = await post('/register', { redirect_uris: ['https://untrusted.example/callback'] })
    assert.equal(rejected.status, 400)
    const registered = await post('/register', { redirect_uris: [callback], token_endpoint_auth_method: 'none' })
    assert.equal(registered.status, 201)
    const client = await registered.json() as { client_id: string }
    const verifier = 'v'.repeat(43)
    const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code', state: 'custom-client-state',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: `${origin}/mcp`, scope: 'offline_access' })
    const page = await fetch(`${base}/authorize?${query}`)
    assert.equal(page.status, 200)
    assert.equal(page.headers.get('referrer-policy'), 'same-origin', 'browser form submission must preserve its same-origin Origin')
    const nonce = /name="approval_nonce" value="([^"]+)"/.exec(await page.text())?.[1]
    assert.ok(nonce)
    for (const untrustedOrigin of ['null', 'https://untrusted.example']) {
      const denied: Response = await fetch(`${base}/authorize?${query}`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: untrustedOrigin },
        body: new URLSearchParams({ approval_nonce: nonce, owner_secret: ownerSecret }) })
      assert.equal(denied.status, 403, 'opaque and cross-origin submissions remain rejected even with valid credentials')
      assert.equal((await denied.json() as { error: string }).error, 'access_denied')
    }
    const consent = await fetch(`${base}/authorize?${query}`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: origin },
      body: new URLSearchParams({ approval_nonce: nonce, owner_secret: ownerSecret, connection_name: 'Generic MCP integration test' }) })
    assert.equal(consent.status, 302)
    const location = new URL(consent.headers.get('location')!)
    assert.equal(location.origin + location.pathname, callback)
    assert.equal(location.searchParams.get('iss'), origin)
    const tokenResponse = await fetch(base + '/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: location.searchParams.get('code')!, code_verifier: verifier, resource: `${origin}/mcp` }) })
    assert.equal(tokenResponse.status, 200)
    const tokens = await tokenResponse.json() as { access_token: string; refresh_token: string }
    const forwarded = fetch(base + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokens.access_token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) })
    const work = await pair.next(2000)
    assert.ok(work)
    pair.reply(work.requestId, 200, { jsonrpc: '2.0', id: 1, result: { tools: [] } })
    assert.equal((await forwarded).status, 200)
    const refresh = await fetch(base + '/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token, resource: `${origin}/mcp` }) })
    assert.equal(refresh.status, 200)
    const renewed = await refresh.json() as { access_token: string; refresh_token: string }
    assert.notEqual(renewed.refresh_token, tokens.refresh_token)
    pair.hello('test-device', 'different-project-key')
    const oldGrant = await fetch(base + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${renewed.access_token}` }, body: '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' })
    assert.equal(oldGrant.status, 401)
  } finally {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
})
