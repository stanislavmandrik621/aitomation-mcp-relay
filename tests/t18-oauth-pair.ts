/**
 * T18 pins: well-known JSON, unauthed POST 401+PRM, no 47601,
 * /pair routes, Mode A key on the public URL is 401+PRM.
 * No top-level await.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import http from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MCP_RELAY_BANNED_PORTS, MCP_RELAY_CLAUDE_REDIRECT, MCP_RELAY_GEMINI_REDIRECT } from '../src/constants.js'
import { cimdUrlAllowed, resolveCimdHop } from '../src/cimd.js'
import { createInFlightSet } from '../src/in-flight.js'
import { createRelayListener } from '../src/handler.js'
import { inboundKeyFamilyPrefix, localKeyFamilyPrefix } from '../src/mode-a-key.js'
import { createOAuthStore } from '../src/oauth-store.js'
import { createPairStore } from '../src/pair-store.js'
import { pairNextClientHungUp } from '../src/pair-routes.js'
import { classifyRelayPath } from '../src/paths.js'
import { isAllowedOAuthRedirect } from '../src/redirects.js'
import { sha256Hex } from '../src/timing-safe.js'
import { accessTokenStillLive } from '../src/timing-safe.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
}

function sourceWithoutComments(raw: string): string {
  return raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
}

function request(
  server: http.Server,
  opts: { method: string; path: string; headers?: http.OutgoingHttpHeaders; body?: string },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const addr = server.address()
    if (!addr || typeof addr === 'string') {
      reject(new Error('no listen address'))
      return
    }
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        method: opts.method,
        path: opts.path,
        headers: opts.headers,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      },
    )
    req.on('error', reject)
    if (opts.body) req.write(opts.body)
    req.end()
  })
}

function listen(listener: http.RequestListener): Promise<http.Server> {
  const server = http.createServer(listener)
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve(server))
    server.on('error', reject)
  })
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()))
  })
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = createHash('sha256').update('t18-pkce-verifier-pad-xxxxxxxx').digest('base64url')
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url')
  return { verifier, challenge }
}

async function approve(server: http.Server, path: string, secret: string) {
  const page = await request(server, { method: 'GET', path })
  assert.equal(page.status, 200, 'GET displays consent instead of granting access')
  assert.equal(page.headers.location, undefined)
  assert.equal(page.headers['x-frame-options'], 'DENY')
  assert.equal(page.headers['referrer-policy'], 'same-origin')
  assert.ok(!page.body.includes(secret))
  const nonce = /name="approval_nonce" value="([a-f0-9]+)"/.exec(page.body)?.[1]
  assert.ok(nonce)
  const headers = { 'content-type': 'application/x-www-form-urlencoded' }
  const noOwner = await request(server, {
    method: 'POST', path, headers, body: 'owner_secret=wrong',
  })
  assert.equal(noOwner.status, 403)
  const body = new URLSearchParams({ approval_nonce: nonce, owner_secret: secret }).toString()
  const approved = await request(server, { method: 'POST', path, headers, body })
  const replay = await request(server, { method: 'POST', path, headers, body })
  assert.equal(replay.status, 403, 'approval cannot be replayed')
  return approved
}

function collectSrc(): string {
  const dir = join(root, 'src')
  let joined = ''
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.ts')) continue
    joined += `\n${readFileSync(join(dir, name), 'utf8')}`
  }
  return joined
}

void (async () => {
  try {
    assert.equal(accessTokenStillLive(0, Date.now()), false)
    assert.equal(accessTokenStillLive(Date.now() + 60_000, Date.now()), true)

    assert.equal(isAllowedOAuthRedirect(MCP_RELAY_CLAUDE_REDIRECT), true)
    assert.equal(isAllowedOAuthRedirect(MCP_RELAY_GEMINI_REDIRECT), true)
    assert.equal(isAllowedOAuthRedirect('https://chatgpt.com/connector/oauth/abc'), true)
    assert.equal(isAllowedOAuthRedirect('https://chatgpt.com/connector_platform_oauth_redirect'), true)
    assert.equal(isAllowedOAuthRedirect('http://127.0.0.1:9/callback'), true)
    assert.equal(isAllowedOAuthRedirect('http://localhost:1234/callback'), true)
    assert.equal(isAllowedOAuthRedirect('http://127.0.0.1/callback'), true)
    assert.equal(isAllowedOAuthRedirect('http://127.0.0.1:9/other'), false)
    assert.equal(isAllowedOAuthRedirect('http://127.0.0.2/callback'), false)
    assert.equal(isAllowedOAuthRedirect('https://evil.example/callback'), false)
    assert.equal(isAllowedOAuthRedirect('https://chatgpt.com/'), false)

    assert.equal(cimdUrlAllowed('https://chatgpt.com/oauth/client.json').ok, true)
    assert.equal(cimdUrlAllowed('https://claude.ai/oauth/client.json').ok, true)
    assert.equal(cimdUrlAllowed('https://127.0.0.1.nip.io/x').ok, false)
    assert.equal(cimdUrlAllowed('https://localhost./x').ok, false)
    assert.equal(cimdUrlAllowed('https://[::7f00:1]/x').ok, false)
    assert.equal(cimdUrlAllowed('https://169.254.169.254/x').ok, false)
    assert.equal(cimdUrlAllowed('https://vertexaisearch.cloud.google.com/oauth-redirect').ok, false)
    const hop = resolveCimdHop(new URL('https://chatgpt.com/a'), 'https://169.254.169.254/imds')
    assert.equal(hop.ok, false)

    assert.equal(classifyRelayPath('/pair/hello'), 'pair_hello')
    assert.equal(classifyRelayPath('/pair/next'), 'pair_next')
    assert.equal(classifyRelayPath('/pair/reply'), 'pair_reply')
    assert.equal(classifyRelayPath('/pair/unavailable'), 'pair_unavailable')
    assert.equal(classifyRelayPath('/.well-known/oauth-protected-resource'), 'well_known_prm')
    assert.equal(classifyRelayPath('/.well-known/oauth-protected-resource/mcp'), 'well_known_prm_mcp')
    assert.equal(classifyRelayPath('/.well-known/oauth-authorization-server'), 'well_known_as')
    assert.equal(classifyRelayPath('/authorize'), 'authorize')
    assert.equal(classifyRelayPath('/token'), 'token')
    assert.equal(MCP_RELAY_BANNED_PORTS.includes(47601), true)
    assert.equal(MCP_RELAY_BANNED_PORTS.includes(47600), true)
    assert.equal(MCP_RELAY_BANNED_PORTS.includes(0), true)

    const src = sourceWithoutComments(collectSrc())
    assert.doesNotMatch(src, /server\.listen\(\s*0\s*,/)
    assert.doesNotMatch(src, /server\.listen\(\s*47601/)
    assert.doesNotMatch(src, /server\.listen\(\s*47600/)
    assert.doesNotMatch(src, /KEYCHAIN_SERVICE/)
    assert.doesNotMatch(src, /MCP_OAUTH_PORT/)
    assert.doesNotMatch(src, /extractMcpInboundToken/)
    assert.doesNotMatch(src, /isLoopbackHost/)
    assert.doesNotMatch(src, /ssrfSafeNetFetch/)
    assert.doesNotMatch(src, /health-page/)
    assert.doesNotMatch(src, /packages\/bridge/)
    assert.doesNotMatch(readFileSync(join(root, 'src/listen.ts'), 'utf8'), /listen\(\s*0\s*,/)

    const pair = createPairStore()
    const oauth = createOAuthStore({ dataDir: null })
    assert.match(oauth.confidential.clientId, /^host_/)
    assert.equal(isAllowedOAuthRedirect(MCP_RELAY_GEMINI_REDIRECT), true)
    const secret = 'pair-secret-16ok!!'
    const inflight = createInFlightSet()
    const server = await listen(createRelayListener({
      closing: () => false,
      inflight,
      pairSecret: secret,
      pair,
      oauth,
      publicUrl: 'https://connector.example',
    }))

    const prmPaths = [
      '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/mcp',
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-authorization-server/mcp',
    ]
    for (const path of prmPaths) {
      const htmlAccept = await request(server, {
        method: 'GET',
        path,
        headers: { accept: 'text/html' },
      })
      assert.equal(htmlAccept.status, 200, path)
      assert.match(String(htmlAccept.headers['content-type']), /application\/json/)
      assert.doesNotMatch(htmlAccept.body, /<html/i)
      const parsed = JSON.parse(htmlAccept.body) as Record<string, unknown>
      if (path.includes('protected-resource')) {
        assert.equal(parsed.resource, 'https://connector.example/mcp')
        assert.match(String(parsed.resource), /^https:\/\//)
        assert.match(String(parsed.resource), /\/mcp$/)
      } else {
        assert.equal(parsed.issuer, 'https://connector.example')
        assert.ok(Array.isArray(parsed.code_challenge_methods_supported))
        assert.equal((parsed.code_challenge_methods_supported as string[])[0], 'S256')
        assert.equal(parsed.client_id_metadata_document_supported, true)
      }
    }

    const tokenInUrl = await request(server, {
      method: 'POST',
      path: '/mcp?access_token=leak',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(tokenInUrl.status, 401)
    assert.match(String(tokenInUrl.headers['www-authenticate']), /resource_metadata=/)

    const unauthed = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_records"}}',
    })
    assert.equal(unauthed.status, 401)
    assert.notEqual(unauthed.status, 200)
    assert.match(String(unauthed.headers['www-authenticate']), /resource_metadata=/)
    assert.doesNotMatch(unauthed.body, /missing_key/)
    assert.doesNotMatch(unauthed.body, /isError|query_records/)

    const modeA = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${inboundKeyFamilyPrefix()}deadbeefdeadbeef`,
      },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(modeA.status, 401)
    assert.match(String(modeA.headers['www-authenticate']), /resource_metadata=/)
    const localA = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${localKeyFamilyPrefix()}deadbeef`,
      },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(localA.status, 401)
    assert.match(String(localA.headers['www-authenticate']), /resource_metadata=/)

    const helloUnauth = await request(server, {
      method: 'POST',
      path: '/pair/hello',
      headers: { 'content-type': 'application/json' },
      body: '{"deviceId":"d1","keyId":"k1","connectionIdentity":1}',
    })
    assert.equal(helloUnauth.status, 401)
    assert.doesNotMatch(String(helloUnauth.headers['www-authenticate'] || ''), /resource_metadata/)

    const hello = await request(server, {
      method: 'POST',
      path: '/pair/hello',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: '{"deviceId":"d1","keyId":"k1","connectionIdentity":1}',
    })
    assert.equal(hello.status, 200)

    const wrongDevice = await request(server, {
      method: 'POST',
      path: '/pair/next',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: '{"deviceId":"other-device","waitMs":10}',
    })
    assert.equal(wrongDevice.status, 401)
    assert.doesNotMatch(String(wrongDevice.headers['www-authenticate'] || ''), /resource_metadata/)

    const stillUnauthed = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}',
    })
    assert.equal(stillUnauthed.status, 401)
    assert.match(String(stillUnauthed.headers['www-authenticate']), /resource_metadata=/)

    const stillModeA = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${inboundKeyFamilyPrefix()}deadbeefdeadbeef`,
      },
      body: '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}',
    })
    assert.equal(stillModeA.status, 401)

    const reg = await request(server, {
      method: 'POST',
      path: '/register',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: [MCP_RELAY_CLAUDE_REDIRECT],
        token_endpoint_auth_method: 'none',
      }),
    })
    assert.equal(reg.status, 201)
    const regJson = JSON.parse(reg.body) as { client_id: string }
    const { verifier, challenge } = pkce()
    const authz = await approve(server,
      `/authorize?response_type=code&client_id=${encodeURIComponent(regJson.client_id)}&redirect_uri=${encodeURIComponent(MCP_RELAY_CLAUDE_REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&state=s1&resource=${encodeURIComponent('https://connector.example/mcp/')}`,
      secret)
    assert.equal(authz.status, 302)
    const loc = String(authz.headers.location || '')
    assert.match(loc, /^https:\/\/claude\.ai\/api\/mcp\/auth_callback/)
    const code = new URL(loc).searchParams.get('code') || ''
    assert.ok(code)
    assert.doesNotMatch(loc, /access_token=/)

    const badCt = await request(server, {
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ grant_type: 'authorization_code', code, code_verifier: verifier }),
    })
    assert.equal(badCt.status, 415)

    const tok = await request(server, {
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&code_verifier=${encodeURIComponent(verifier)}&client_id=${encodeURIComponent(regJson.client_id)}&redirect_uri=${encodeURIComponent(MCP_RELAY_CLAUDE_REDIRECT)}`,
    })
    assert.equal(tok.status, 200)
    const tokJson = JSON.parse(tok.body) as { access_token: string; refresh_token: string }
    assert.ok(tokJson.access_token)
    assert.ok(tokJson.refresh_token)
    assert.equal(tokJson.access_token.startsWith(inboundKeyFamilyPrefix()), false)

    const nextP = request(server, {
      method: 'POST',
      path: '/pair/next',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: '{"deviceId":"d1","waitMs":8000}',
    })
    const mcpP = request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${tokJson.access_token}`,
      },
      body: '{"jsonrpc":"2.0","id":9,"method":"initialize","params":{}}',
    })
    const next = await nextP
    assert.equal(next.status, 200)
    const nextJson = JSON.parse(next.body) as { requestId: string; jsonrpc: string }
    assert.ok(nextJson.requestId)
    const reply = await request(server, {
      method: 'POST',
      path: '/pair/reply',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: JSON.stringify({
        requestId: nextJson.requestId,
        status: 200,
        json: { jsonrpc: '2.0', id: 9, result: { forwarded: true } },
      }),
    })
    assert.equal(reply.status, 200)
    const mcp = await mcpP
    assert.equal(mcp.status, 200)
    assert.match(mcp.body, /forwarded/)
    assert.doesNotMatch(mcp.body, /executeTool|LOCAL_TOOLS/)

    // A legacy desktop can reconnect after a command was admitted. Never
    // deliver the command if it would discard the authenticated connection.
    const queuedForNewDesktop = pair.enqueueMcp('{"id":99,"method":"ping"}', { id: 'a'.repeat(64), label: 'Alex' })
    const legacyHello = await request(server, {
      method: 'POST', path: '/pair/hello',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
      body: '{"deviceId":"d1","keyId":"k1"}',
    })
    assert.equal(legacyHello.status, 200)
    assert.equal(pair.supportsConnectionIdentity(), false)
    const refusedDelivery = await request(server, {
      method: 'POST', path: '/pair/next',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
      body: '{"deviceId":"d1","waitMs":10}',
    })
    assert.equal(refusedDelivery.status, 204)
    assert.deepEqual(await queuedForNewDesktop.wait, { status: 503, json: { error: 'desktop_update_required' } })
    pair.hello('d1', 'k1', null, true)

    const refreshed = await request(server, {
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(tokJson.refresh_token)}&client_id=${encodeURIComponent(regJson.client_id)}`,
    })
    assert.equal(refreshed.status, 200)
    const refJson = JSON.parse(refreshed.body) as { refresh_token: string }
    assert.ok(refJson.refresh_token)
    assert.notEqual(refJson.refresh_token, tokJson.refresh_token)
    const deadRt = await request(server, {
      method: 'POST',
      path: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(tokJson.refresh_token)}&client_id=${encodeURIComponent(regJson.client_id)}`,
    })
    assert.equal(deadRt.status, 400)
    assert.match(deadRt.body, /invalid_grant/)

    oauth.insertExpiredAccessForTest('expired-zero', 0)
    assert.equal(oauth.findAccess('expired-zero', Date.now()), null)

    const keyPlain = `${inboundKeyFamilyPrefix()}staticheaderkey0001`
    pair.hello('d1', 'k1', sha256Hex(keyPlain), true)
    const staticNext = request(server, {
      method: 'POST',
      path: '/pair/next',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: '{"deviceId":"d1","waitMs":8000}',
    })
    const staticMcp = request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        'mcp-api-key': keyPlain,
      },
      body: '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}',
    })
    const staticItem = await staticNext
    assert.equal(staticItem.status, 200)
    const staticId = (JSON.parse(staticItem.body) as { requestId: string }).requestId
    await request(server, {
      method: 'POST',
      path: '/pair/reply',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: JSON.stringify({ requestId: staticId, status: 200, json: { ok: true, via: 'static' } }),
    })
    const staticRes = await staticMcp
    assert.equal(staticRes.status, 200)
    assert.match(staticRes.body, /static/)
    const oldGrant = await request(server, {
      method: 'POST', path: '/mcp',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tokJson.access_token}` },
      body: '{"jsonrpc":"2.0","id":4,"method":"ping"}',
    })
    assert.equal(oldGrant.status, 401, 'restamping the paired static secret revokes prior OAuth grants')

    const unavail = await request(server, {
      method: 'POST',
      path: '/pair/unavailable',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${secret}`,
      },
      body: '{"deviceId":"d1"}',
    })
    assert.equal(unavail.status, 200)
    const afterDown = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        'mcp-api-key': keyPlain,
      },
      body: '{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}',
    })
    assert.equal(afterDown.status, 503)
    assert.match(afterDown.body, /unavailable/)
    assert.doesNotMatch(afterDown.body, /project /i)

    oauth.putAccess({
      tokenHash: sha256Hex('scope-token'),
      clientId: 'x',
      resource: 'https://other.example/mcp',
      expiresAt: Date.now() + 60_000,
    })
    pair.hello('d1', 'k1', null, true)
    const scoped = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer scope-token',
      },
      body: '{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}',
    })
    assert.equal(scoped.status, 403)
    assert.match(scoped.body, /insufficient_scope/)

    const geminiAuth = await approve(server,
      `/authorize?response_type=code&client_id=${encodeURIComponent(oauth.confidential.clientId)}&redirect_uri=${encodeURIComponent(MCP_RELAY_GEMINI_REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256`,
      secret)
    assert.equal(geminiAuth.status, 302)
    assert.match(String(geminiAuth.headers.location), /vertexaisearch\.cloud\.google\.com/)

    await closeServer(server)

    const oauthOnly = createOAuthStore({ dataDir: null })
    const unpaired = await listen(createRelayListener({
      closing: () => false,
      inflight: createInFlightSet(),
      pairSecret: 'another-secret-16',
      oauth: oauthOnly,
      publicUrl: 'https://connector.example',
    }))
    oauthOnly.putAccess({
      tokenHash: sha256Hex('unpaired-at'),
      clientId: 'x',
      resource: 'https://connector.example/mcp',
      expiresAt: Date.now() + 60_000,
    })
    const authUnpaired = await request(unpaired, {
      method: 'POST',
      path: '/mcp',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer unpaired-at',
      },
      body: '{"jsonrpc":"2.0","id":8,"method":"initialize","params":{}}',
    })
    assert.equal(authUnpaired.status, 503)
    assert.match(authUnpaired.body, /not_paired/)
    await closeServer(unpaired)

    const noPair = await listen(createRelayListener({
      closing: () => false,
      inflight: createInFlightSet(),
      pairSecret: null,
    }))
    const pairMissing = await request(noPair, {
      method: 'POST',
      path: '/pair/hello',
      headers: { 'content-type': 'application/json', authorization: 'Bearer xxxxxxxxxxxxxxxx' },
      body: '{"deviceId":"d1","keyId":"k1"}',
    })
    assert.equal(pairMissing.status, 503)
    assert.match(pairMissing.body, /not_paired/)
    await closeServer(noPair)

    const hungPair = createPairStore()
    hungPair.hello('hx', 'hy', null, true)
    const hungAc = new AbortController()
    const hungNext = hungPair.next(8000, hungAc.signal)
    hungAc.abort()
    assert.equal(await hungNext, null)
    const hungEnq = hungPair.enqueueMcp('{"jsonrpc":"2.0","id":77,"method":"initialize"}')
    const hungGot = await hungPair.next(10)
    assert.ok(hungGot)
    assert.equal(hungGot.requestId, hungEnq.requestId)
    hungPair.resetForTest()

    const liveReq = { aborted: false, destroyed: true, socket: { destroyed: false } }
    const liveRes = { writableEnded: false }
    assert.equal(
      pairNextClientHungUp(liveReq as http.IncomingMessage, liveRes as http.ServerResponse),
      false,
      'body-complete IncomingMessage.destroyed is not hang-up',
    )
    assert.equal(
      pairNextClientHungUp(
        { aborted: true, socket: { destroyed: false } } as http.IncomingMessage,
        { writableEnded: false } as http.ServerResponse,
      ),
      true,
      'req.aborted is hang-up',
    )
    assert.equal(
      pairNextClientHungUp(
        { aborted: false, socket: { destroyed: true } } as http.IncomingMessage,
        { writableEnded: false } as http.ServerResponse,
      ),
      true,
      'socket.destroyed is hang-up',
    )
    assert.equal(
      pairNextClientHungUp(
        { aborted: true, socket: { destroyed: true } } as http.IncomingMessage,
        { writableEnded: true } as http.ServerResponse,
      ),
      false,
      'reply already ended is not hang-up',
    )

    const rq = createPairStore()
    rq.hello('rq', 'rk', null, true)
    const rqEnq = rq.enqueueMcp('{"jsonrpc":"2.0","id":9,"method":"ping"}')
    const rqTaken = await rq.next(10)
    assert.ok(rqTaken)
    rq.requeue(rqTaken)
    const rqAgain = await rq.next(10)
    assert.ok(rqAgain)
    assert.equal(rqAgain.requestId, rqEnq.requestId)
    rq.resetForTest()

    assert.equal(existsSync(join(root, 'src/oauth.ts')), true)
    assert.equal(existsSync(join(root, 'src/cimd.ts')), true)
    assert.equal(existsSync(join(root, 'src/pair-routes.ts')), true)
    const pairRoutesSrc = sourceWithoutComments(readFileSync(join(root, 'src/pair-routes.ts'), 'utf8'))
    assert.match(pairRoutesSrc, /req\.on\('close'/)
    assert.match(pairRoutesSrc, /req\.on\('aborted'/)
    assert.match(pairRoutesSrc, /pair\.next\(waitMs,\s*ac\.signal\)/)
    assert.match(pairRoutesSrc, /pairNextClientHungUp/)
    assert.match(pairRoutesSrc, /pair\.requeue/)
    assert.match(pairRoutesSrc, /req\.aborted === true/)
    assert.doesNotMatch(
      pairRoutesSrc,
      /if \(req\.destroyed === true\)/,
      'IncomingMessage.destroyed after body is not hang-up',
    )
    const nextAt = pairRoutesSrc.indexOf("route === 'next'")
    assert.ok(nextAt >= 0, 'next route')
    const nextSlice = pairRoutesSrc.slice(nextAt, nextAt + 1800)
    assert.match(
      nextSlice,
      /if \(!pairNextClientHungUp\(req, res\)\) return/,
      'dropIfHungUp refuses abort unless hung-up',
    )
    const nextCommented = nextSlice.replace(
      /if \(!pairNextClientHungUp\(req, res\)\) return/,
      '// if (!pairNextClientHungUp(req, res)) return',
    )
    assert.equal(
      /if \(!pairNextClientHungUp\(req, res\)\) return/.test(sourceWithoutComments(nextCommented)),
      false,
      'commented hung-up refuse is not load-bearing (TOOL-G31-066)',
    )

    console.log('ok t18-oauth-pair')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
