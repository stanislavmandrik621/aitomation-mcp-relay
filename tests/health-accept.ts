/**
 * Health Accept-negotiate + live GET/HEAD / and /health.
 * Historic bytes on missing Accept / text/plain / any-type.
 * HTML only for an exact text/html range with q>0.
 * Bodies must fail Team Space identity.
 */
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import http from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { relayWantsHealthHtml } from '../src/accept.js'
import {
  MCP_RELAY_DEFAULT_PORT,
  MCP_RELAY_HEALTH_ACCEPT,
  MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX,
  MCP_RELAY_HEALTH_PLAIN_BODY,
  MCP_RELAY_HEALTH_PROBE_MAX_BYTES,
  MCP_RELAY_MAX_CONCURRENT,
  MCP_RELAY_MAX_CONNECTIONS,
  TEAM_SPACE_HEALTH_PLAIN_BODY,
} from '../src/constants.js'
import { createInFlightSet } from '../src/in-flight.js'
import {
  createRelayListener,
  peelRelayRequestUrl,
  relayExactHost,
  relayDeclaredContentLength,
  relayHasTeAndCl,
  relayHostIsOurWeb,
  relayJsonContentType,
  relayMcpClientHungUp,
  relayRawHeadersDuped,
} from '../src/handler.js'
import { healthPageHtml } from '../src/health-html.js'
import { isMcpRelayHealthBody, looksLikeTeamSpaceHealthBody } from '../src/identity.js'
import { peekJsonRpc } from '../src/rpc-peek.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const CHROME_ACCEPT =
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
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

function sourceWithoutComments(raw: string): string {
  return raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
}

void (async () => {
  try {
    assert.equal(MCP_RELAY_HEALTH_PLAIN_BODY, 'AItomation MCP relay\n')
    assert.notEqual(MCP_RELAY_HEALTH_PLAIN_BODY, TEAM_SPACE_HEALTH_PLAIN_BODY)
    assert.equal(looksLikeTeamSpaceHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY), false)
    assert.equal(looksLikeTeamSpaceHealthBody(TEAM_SPACE_HEALTH_PLAIN_BODY), true)
    assert.equal(looksLikeTeamSpaceHealthBody('AItomation Team Space'), true)
    assert.equal(looksLikeTeamSpaceHealthBody('welcome to the team space bridge'), true)
    assert.equal(isMcpRelayHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY), true)
    assert.equal(isMcpRelayHealthBody(TEAM_SPACE_HEALTH_PLAIN_BODY), false)

    const html = healthPageHtml()
    const htmlBytes = Buffer.byteLength(html, 'utf8')
    assert.ok(htmlBytes < MCP_RELAY_HEALTH_PROBE_MAX_BYTES, `html ${htmlBytes} >= cap`)
    assert.equal(looksLikeTeamSpaceHealthBody(html), false)
    assert.equal(isMcpRelayHealthBody(html), true)
    assert.doesNotMatch(html, /team space/i)
    assert.doesNotMatch(html, /AItomation Team Space bridge/)
    assert.doesNotMatch(html, /<script/i)
    assert.doesNotMatch(html, /—|–|…/)
    assert.doesNotMatch(html, /\b(coolify|v-aid|directus|cursor|copilot|windsurf)\b/i)

    assert.equal(relayWantsHealthHtml(undefined), false)
    assert.equal(relayWantsHealthHtml(null), false)
    assert.equal(relayWantsHealthHtml(''), false)
    assert.equal(relayWantsHealthHtml('*/*'), false)
    assert.equal(relayWantsHealthHtml('text/*'), false)
    assert.equal(relayWantsHealthHtml('text/plain'), false)
    assert.equal(relayWantsHealthHtml('text/plain, */*'), false)
    assert.equal(relayWantsHealthHtml('application/json'), false)
    assert.equal(relayWantsHealthHtml(CHROME_ACCEPT), true)
    assert.equal(relayWantsHealthHtml('text/html'), true)
    assert.equal(relayWantsHealthHtml('TEXT/HTML;q=1'), true)
    assert.equal(relayWantsHealthHtml('text/html ; q=0.9'), true)
    assert.equal(relayWantsHealthHtml('application/xml, text/html;charset=utf-8'), true)
    assert.equal(relayWantsHealthHtml(['text/html', 'application/xml']), true)
    assert.equal(relayWantsHealthHtml(['*/*']), false)
    assert.equal(relayWantsHealthHtml('text/html-sandboxed'), false)
    assert.equal(relayWantsHealthHtml('application/x-text/html-preview'), false)
    assert.equal(relayWantsHealthHtml('not-text/html'), false)
    assert.equal(relayWantsHealthHtml('text/html;q=0'), false)
    assert.equal(relayWantsHealthHtml('text/html;q=0.0'), false)
    assert.equal(relayWantsHealthHtml('text/plain, text/html;q=0'), false)
    assert.equal(relayWantsHealthHtml('text/html;q=0.1, */*;q=0.9'), false)
    assert.equal(relayWantsHealthHtml('text/plain, text/html'), false)
    assert.equal(relayWantsHealthHtml('a'.repeat(MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX + 1)), false)
    assert.equal(relayWantsHealthHtml('text/html\0'), false)
    assert.equal(relayWantsHealthHtml('text/html\u0001'), false)
    assert.equal(relayWantsHealthHtml(`text/html${String.fromCharCode(0xd800)}`), false)
    assert.equal(relayWantsHealthHtml('中'.repeat(700)), false)
    assert.equal(relayWantsHealthHtml(['text/html', 'a'.repeat(MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX)]), false)

    assert.equal(MCP_RELAY_HEALTH_ACCEPT, 'text/plain')
    assert.equal(MCP_RELAY_MAX_CONCURRENT, 16)
    assert.equal(MCP_RELAY_MAX_CONNECTIONS, 32)

    assert.equal(relayJsonContentType('application/json'), true)
    assert.equal(relayJsonContentType('application/json; charset=utf-8'), true)
    assert.equal(relayJsonContentType('text/plain'), false)
    assert.equal(relayJsonContentType(undefined), false)
    assert.equal(relayHostIsOurWeb('v-aid.ai'), true)
    assert.equal(relayHostIsOurWeb('cms.v-aid.ai'), true)
    assert.equal(relayHostIsOurWeb('x.v-aid.ai'), true)
    assert.equal(relayHostIsOurWeb('connector.example'), false)
    assert.equal(relayHostIsOurWeb('127.0.0.1'), false)
    assert.equal(relayHasTeAndCl({ 'transfer-encoding': 'chunked', 'content-length': '1' }), true)
    assert.equal(relayHasTeAndCl({ 'content-length': '1' }), false)
    assert.equal(relayDeclaredContentLength({ 'content-length': '12' }), 12)
    assert.equal(relayDeclaredContentLength({ 'content-length': String(256 * 1024 + 1) }), 256 * 1024 + 1)
    assert.equal(relayDeclaredContentLength({}), null)
    assert.equal(relayRawHeadersDuped(['Host', 'a', 'Host', 'b']), true)
    assert.equal(relayRawHeadersDuped(['Host', 'a', 'Content-Length', '1', 'Content-Length', '2']), true)
    assert.equal(relayRawHeadersDuped(['Transfer-Encoding', 'gzip, chunked']), true)
    assert.equal(relayRawHeadersDuped(['Host', 'a', 'Content-Type', 'application/json']), false)
    assert.equal(relayExactHost({ headers: { host: ['a', 'b'] } } as unknown as http.IncomingMessage), null)
    assert.equal(
      peelRelayRequestUrl('/mcp', '127.0.0.1:8790'),
      '/mcp',
    )
    assert.equal(
      peelRelayRequestUrl('https://connector.example/mcp', 'connector.example'),
      '/mcp',
    )
    assert.equal(
      peelRelayRequestUrl('https://v-aid.ai/mcp', 'v-aid.ai'),
      'bad',
    )
    assert.equal(
      peelRelayRequestUrl('https://evil.example/mcp', 'connector.example'),
      'bad',
    )

    assert.equal(peekJsonRpc('{"jsonrpc":"2.0","method":"initialized"}').notification, true)
    assert.equal(peekJsonRpc('{"jsonrpc":"2.0","id":1,"method":"initialize"}').notification, false)
    assert.equal(peekJsonRpc('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}').name, 'x')

    const capSet = createInFlightSet()
    const tokens: Array<() => void> = []
    for (let i = 0; i < MCP_RELAY_MAX_CONCURRENT; i++) {
      const t = capSet.begin()
      assert.ok(t, `slot ${i}`)
      tokens.push(t)
    }
    assert.equal(capSet.begin(), null)
    assert.equal(capSet.size(), MCP_RELAY_MAX_CONCURRENT)
    tokens[0]()
    const after = capSet.begin()
    assert.ok(after)
    after()
    for (const t of tokens.slice(1)) t()
    assert.equal(capSet.size(), 0)

    assert.equal(
      relayMcpClientHungUp(
        { aborted: false, destroyed: true, socket: { destroyed: false } } as http.IncomingMessage,
        { writableEnded: false } as http.ServerResponse,
      ),
      false,
      'body-complete IncomingMessage.destroyed is not hang-up',
    )
    assert.equal(
      relayMcpClientHungUp(
        { aborted: true, socket: { destroyed: false } } as http.IncomingMessage,
        { writableEnded: false } as http.ServerResponse,
      ),
      true,
      'req.aborted is hang-up',
    )
    assert.equal(
      relayMcpClientHungUp(
        { aborted: false, socket: { destroyed: true } } as http.IncomingMessage,
        { writableEnded: false } as http.ServerResponse,
      ),
      true,
      'socket.destroyed is hang-up',
    )
    assert.equal(
      relayMcpClientHungUp(
        { aborted: true, socket: { destroyed: true } } as http.IncomingMessage,
        { writableEnded: true } as http.ServerResponse,
      ),
      false,
      'reply already ended is not hang-up',
    )

    const acceptSrc = readFileSync(join(root, 'src/accept.ts'), 'utf8')
    assert.doesNotMatch(acceptSrc, /\.includes\(\s*['"]text\/html['"]\s*\)/)

    const inflight = createInFlightSet()
    const server = http.createServer(
      createRelayListener({
        closing: () => false,
        inflight,
        pairSecret: null,
      }),
    )
    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve())
      server.on('error', reject)
    })

    const paths = ['/', '/health'] as const
    const methods = ['GET', 'HEAD'] as const
    for (const path of paths) {
      for (const method of methods) {
        const missing = await request(server, { method, path })
        assert.equal(missing.status, 200, `${method} ${path} missing Accept`)
        assert.equal(missing.headers['cache-control'], 'no-store')
        assert.equal(String(missing.headers.vary).toLowerCase(), 'accept')
        if (method === 'HEAD') {
          assert.equal(missing.body, '')
          assert.equal(Number(missing.headers['content-length']), Buffer.byteLength(MCP_RELAY_HEALTH_PLAIN_BODY))
        } else {
          assert.equal(missing.body, MCP_RELAY_HEALTH_PLAIN_BODY)
          assert.equal(looksLikeTeamSpaceHealthBody(missing.body), false)
          assert.equal(isMcpRelayHealthBody(missing.body), true)
        }

        const plain = await request(server, {
          method,
          path,
          headers: { accept: 'text/plain' },
        })
        assert.equal(plain.status, 200)
        assert.equal(plain.headers['cache-control'], 'no-store')
        assert.equal(String(plain.headers.vary).toLowerCase(), 'accept')
        if (method === 'GET') assert.equal(plain.body, MCP_RELAY_HEALTH_PLAIN_BODY)

        const anyType = await request(server, {
          method,
          path,
          headers: { accept: '*/*' },
        })
        assert.equal(anyType.status, 200)
        if (method === 'GET') assert.equal(anyType.body, MCP_RELAY_HEALTH_PLAIN_BODY)

        const browser = await request(server, {
          method,
          path,
          headers: { accept: CHROME_ACCEPT },
        })
        assert.equal(browser.status, 200)
        assert.equal(browser.headers['cache-control'], 'no-store')
        assert.equal(String(browser.headers.vary).toLowerCase(), 'accept')
        if (method === 'HEAD') {
          assert.equal(browser.body, '')
          assert.equal(Number(browser.headers['content-length']), Buffer.byteLength(html))
        } else {
          assert.equal(browser.body, html)
          assert.equal(looksLikeTeamSpaceHealthBody(browser.body), false)
          assert.equal(isMcpRelayHealthBody(browser.body), true)
        }
      }
    }

    const getMcp = await request(server, { method: 'GET', path: '/mcp' })
    assert.equal(getMcp.status, 405)
    const noCt = await request(server, {
      method: 'POST',
      path: '/mcp',
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(noCt.status, 415)
    const ourWebHost = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: { host: 'v-aid.ai', 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(ourWebHost.status, 400)
    const postMcp = await request(server, {
      method: 'POST',
      path: '/mcp',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    })
    assert.equal(postMcp.status, 401)
    assert.notEqual(postMcp.status, 200)
    const www = String(postMcp.headers['www-authenticate'] || '')
    assert.match(www, /Bearer/i)
    assert.match(www, /resource_metadata=/)
    assert.doesNotMatch(postMcp.body, /missing_key/)
    assert.doesNotMatch(postMcp.body, /project|ong solar|team /i)

    const prefix = await request(server, { method: 'GET', path: '/project-a/mcp' })
    assert.equal(prefix.status, 404)
    const prefixHealth = await request(server, { method: 'GET', path: '/acme/health' })
    assert.equal(prefixHealth.status, 404)

    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()))
    })

    const treeFiles = [
      'src/server.ts',
      'src/main.ts',
      'src/listen.ts',
      'src/handler.ts',
      'src/config.ts',
      'src/constants.ts',
      'src/accept.ts',
      'src/health-html.ts',
      'src/identity.ts',
      'src/in-flight.ts',
      'src/log.ts',
      'src/paths.ts',
      'README.md',
      'docs/SELF-HOST.md',
      'Dockerfile',
      '.github/workflows/publish-image.yml',
    ]
    let joined = ''
    for (const rel of treeFiles) {
      const abs = join(root, rel)
      assert.equal(existsSync(abs), true, `missing ${rel}`)
      joined += `\n${readFileSync(abs, 'utf8')}`
    }
    const code = sourceWithoutComments(joined)
    assert.doesNotMatch(code, /from ['"][^'"]*packages\/bridge/)
    assert.doesNotMatch(code, /@aitomation\/bridge/)
    assert.doesNotMatch(code, /TEAMSPACE_/)
    assert.doesNotMatch(code, /SIGKILL/)
    assert.doesNotMatch(code, /taskkill/i)
    assert.doesNotMatch(code, /process\.kill\s*\(\s*-/)
    assert.doesNotMatch(code, /2024-11-05/)
    assert.doesNotMatch(code, /AITOMATION_/)
    assert.doesNotMatch(code, /aitmcp_/)
    assert.doesNotMatch(joined, /[—–…]/)
    assert.doesNotMatch(joined, /\b(Coolify|v-aid\.ai|cms\.v-aid)\b/)
    assert.doesNotMatch(joined, /\b(Cursor|Copilot|Windsurf)\b/)

    const listenSrc = sourceWithoutComments(readFileSync(join(root, 'src/listen.ts'), 'utf8'))
    assert.match(listenSrc, /server\.listen\(\s*config\.port/)
    assert.doesNotMatch(listenSrc, /server\.listen\(\s*0\s*,/)
    assert.match(listenSrc, /inflight\.drain\(\)/)
    assert.match(listenSrc, /maxConnections/)
    assert.match(listenSrc, /closeAllConnections/)
    assert.doesNotMatch(listenSrc, /setTimeout\s*\([^)]*exit/)

    const handlerSrc = sourceWithoutComments(readFileSync(join(root, 'src/handler.ts'), 'utf8'))
    assert.match(handlerSrc, /relayMcpClientHungUp/)
    assert.match(handlerSrc, /concurrent_cap/)
    assert.match(handlerSrc, /declared > MCP_RELAY_POST_BODY_MAX_BYTES/)
    assert.match(handlerSrc, /req\.aborted === true/)
    assert.match(handlerSrc, /endSilentAndClose/)
    assert.doesNotMatch(handlerSrc, /isLoopbackHost/)
    assert.doesNotMatch(handlerSrc, /extractMcpInboundToken/)
    assert.doesNotMatch(handlerSrc, /if \(req\.destroyed === true\)/)
    assert.doesNotMatch(handlerSrc, /from ['"].*mcp-inbound\/http/)

    const dockerfile = readFileSync(join(root, 'Dockerfile'), 'utf8')
    assert.match(dockerfile, /COPY package\.json package-lock\.json/)
    assert.match(dockerfile, /\bnpm ci\b/)
    assert.doesNotMatch(dockerfile, /\bnpm install\b/)
    assert.equal(existsSync(join(root, 'package-lock.json')), true, 'package-lock.json missing')

    const wf = readFileSync(join(root, '.github/workflows/publish-image.yml'), 'utf8')
    assert.match(wf, /Official GHCR publisher/)
    assert.match(wf, /ghcr\.io\/stanislavmandrik621\/aitomation-mcp-relay/)
    assert.match(wf, /docker\/login-action/)
    assert.match(wf, /push:\s*true/)
    assert.doesNotMatch(wf, /aitomation-teamspace-bridge/)

    const syncPath = join(root, '../../scripts/sync-mcp-relay-public.sh')
    assert.equal(existsSync(syncPath), true, 'missing sync-mcp-relay-public.sh')
    const sync = readFileSync(syncPath, 'utf8')
    assert.match(sync, /packages\/mcp-relay/)
    assert.match(sync, /aitomation-mcp-relay/)
    assert.match(sync, /PUBLIC_IMAGE_TAG/)
    assert.equal(sync.includes('docker push'), false)
    assert.equal(sync.includes('ghcr.io'), false)
    assert.match(sync, /Do not sync packages\/bridge/)
    assert.doesNotMatch(sync, /SRC=.*packages\/bridge/)

    assert.equal(MCP_RELAY_DEFAULT_PORT, 8790)

    const readme = readFileSync(join(root, 'README.md'), 'utf8')
    assert.match(readme, /Public certificate/)
    assert.match(readme, /Three projects/)
    assert.match(readme, /We do not host this door/)

    console.log('ok health-accept')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
