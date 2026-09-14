import { DEFAULT_CLIENT_POLICY, type OAuthClientPolicy } from './client-policy.js'
import type { IncomingMessage, ServerResponse } from 'node:http'
import {
  MCP_RELAY_HEALTH_PLAIN_BODY,
  MCP_RELAY_POST_BODY_MAX_BYTES,
  MCP_RELAY_503_NOT_PAIRED,
  MCP_RELAY_503_UNAVAILABLE,
} from './constants.js'
import { relayWantsHealthHtml } from './accept.js'
import { healthPageHtml } from './health-html.js'
import type { InFlightSet } from './in-flight.js'
import { logRelay } from './log.js'
import { resolveModeBAuth } from './mode-b-auth.js'
import { handleAuthorize, handleRegister, handleToken } from './oauth.js'
import { createOAuthStore, type OAuthStore } from './oauth-store.js'
import { createPairStore, type PairStore } from './pair-store.js'
import { handlePairRoute } from './pair-routes.js'
import { classifyRelayPath, type RelayRoute } from './paths.js'
import { isOurHostingHost, publicOriginFromRequest, wwwAuthenticatePrm } from './public-url.js'
import { peekJsonRpc } from './rpc-peek.js'
import { wellKnownJson, type WellKnownKind } from './well-known.js'
import { relayProtocolHeaderAccepted } from './protocol.js'

const PLAIN_HEADERS = {
  'content-type': 'text/plain; charset=utf-8',
  'cache-control': 'no-store',
  pragma: 'no-cache',
} as const

const HTML_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  pragma: 'no-cache',
  vary: 'Accept',
} as const

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  pragma: 'no-cache',
} as const

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, HEAD, POST, OPTIONS',
  'access-control-allow-headers': 'Authorization, Content-Type, mcp-api-key, MCP-Protocol-Version',
  'access-control-max-age': '600',
} as const

const CLOSE_HDR = { connection: 'close' } as const

export type RelayHandlerState = {
  clientPolicy?: OAuthClientPolicy
  closing: () => boolean
  inflight: InFlightSet
  pairSecret: string | null
  publicUrl?: string | null
  staticHeaderHash?: string | null
  pair?: PairStore
  oauth?: OAuthStore
}

type BoundState = {
  clientPolicy: OAuthClientPolicy
  closing: () => boolean
  inflight: InFlightSet
  pairSecret: string | null
  publicUrl: string | null
  staticHeaderHash: string | null
  pair: PairStore
  oauth: OAuthStore
}

function bindState(state: RelayHandlerState): BoundState {
  return {
    clientPolicy: state.clientPolicy ?? DEFAULT_CLIENT_POLICY,
    closing: state.closing,
    inflight: state.inflight,
    pairSecret: state.pairSecret,
    publicUrl: state.publicUrl ?? null,
    staticHeaderHash: state.staticHeaderHash ?? null,
    pair: state.pair ?? createPairStore(),
    oauth: state.oauth ?? createOAuthStore({ dataDir: null }),
  }
}

function sendPlain(
  res: ServerResponse,
  status: number,
  body: string,
  extra?: Record<string, string>,
  method?: string,
): void {
  const buf = Buffer.from(body, 'utf8')
  res.writeHead(status, {
    ...PLAIN_HEADERS,
    'content-length': buf.length,
    ...extra,
  })
  res.end(method === 'HEAD' ? undefined : buf)
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: string,
  extra?: Record<string, string>,
  method?: string,
): void {
  const buf = Buffer.from(body, 'utf8')
  res.writeHead(status, {
    ...JSON_HEADERS,
    ...CORS,
    'content-length': buf.length,
    ...extra,
  })
  res.end(method === 'HEAD' ? undefined : buf)
}

function destroyReq(req: IncomingMessage): void {
  try { req.destroy() } catch { /* ignore */ }
}

function sendJsonClose(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  body: string,
  extra?: Record<string, string>,
): void {
  if (res.writableEnded === true || res.headersSent) {
    destroyReq(req)
    return
  }
  sendJson(res, status, body, { ...CLOSE_HDR, ...extra })
  destroyReq(req)
}

function sendPlainClose(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  body: string,
  extra?: Record<string, string>,
  method?: string,
): void {
  if (res.writableEnded === true || res.headersSent) {
    destroyReq(req)
    return
  }
  sendPlain(res, status, body, { ...CLOSE_HDR, ...extra }, method)
  destroyReq(req)
}

function endSilentAndClose(req: IncomingMessage, res: ServerResponse): void {
  if (res.writableEnded !== true && !res.headersSent) {
    try {
      res.writeHead(204, { ...JSON_HEADERS, ...CORS, ...CLOSE_HDR })
      res.end()
    } catch { /* EPIPE */ }
  }
  destroyReq(req)
}

function sendHealth(res: ServerResponse, method: string, accept: unknown): void {
  if (relayWantsHealthHtml(accept)) {
    const html = healthPageHtml()
    const buf = Buffer.from(html, 'utf8')
    res.writeHead(200, {
      ...HTML_HEADERS,
      'content-length': buf.length,
    })
    res.end(method === 'HEAD' ? undefined : buf)
    return
  }
  const buf = Buffer.from(MCP_RELAY_HEALTH_PLAIN_BODY, 'utf8')
  res.writeHead(200, {
    ...PLAIN_HEADERS,
    vary: 'Accept',
    'content-length': buf.length,
  })
  res.end(method === 'HEAD' ? undefined : buf)
}

function send401Prm(req: IncomingMessage, res: ServerResponse, publicUrl: string | null): void {
  const origin = publicOriginFromRequest(req, publicUrl)
  sendJsonClose(req, res, 401, '{"error":"unauthorized"}\n', {
    'www-authenticate': wwwAuthenticatePrm(origin),
  })
}

function send403Scope(req: IncomingMessage, res: ServerResponse): void {
  sendJsonClose(req, res, 403, '{"error":"insufficient_scope"}\n')
}

function headerIsArray(raw: unknown): boolean {
  return Array.isArray(raw)
}

/** Array Host is refuse (never take the first). */
export function relayExactHost(req: IncomingMessage): string | null {
  const raw = req.headers.host
  if (headerIsArray(raw) || typeof raw !== 'string') return null
  const host = raw.trim()
  if (!host || host.includes('\0') || /[\r\n]/.test(host) || host.length > 253) return null
  return host
}

function hostnameFromHostHeader(raw: string): string | null {
  const host = raw.trim()
  if (!host) return null
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    if (end < 2) return null
    return host.slice(1, end).toLowerCase()
  }
  const colon = host.lastIndexOf(':')
  if (colon > 0 && /^\d{1,5}$/.test(host.slice(colon + 1))) {
    return host.slice(0, colon).toLowerCase()
  }
  return host.toLowerCase()
}

/** Our hosting never serves this door (MCP-004). */
export function relayHostIsOurWeb(hostname: string): boolean {
  return isOurHostingHost(hostname)
}

export function relayJsonContentType(raw: unknown): boolean {
  if (typeof raw !== 'string' || !raw.trim()) return false
  const first = raw.split(',')[0] ?? ''
  const base = first.split(';')[0].trim().toLowerCase()
  return base === 'application/json'
}

export function relayHasTeAndCl(headers: IncomingMessage['headers']): boolean {
  const on = (raw: unknown): boolean => {
    if (typeof raw === 'string') return raw.trim().length > 0
    if (Array.isArray(raw)) return raw.some((x) => typeof x === 'string' && x.trim().length > 0)
    return false
  }
  return on(headers['transfer-encoding']) && on(headers['content-length'])
}

export function relayContentLengthBad(headers: IncomingMessage['headers']): boolean {
  const cl = headers['content-length']
  if (cl === undefined) return false
  if (Array.isArray(cl)) return true
  if (typeof cl !== 'string') return true
  if (!cl.trim()) return false
  const n = Number(cl.trim())
  return !Number.isFinite(n) || n < 0
}

export function relayDeclaredContentLength(headers: IncomingMessage['headers']): number | null {
  if (relayContentLengthBad(headers)) return null
  const raw = headers['content-length']
  if (typeof raw !== 'string' || !raw.trim()) return null
  const n = Number(raw.trim())
  if (!Number.isFinite(n) || n < 0) return null
  return Math.floor(n)
}

/**
 * HTTP/1 can keep the first Host / Content-Length and comma-join TE.
 * Count raw names (MCP-012).
 */
export function relayRawHeadersDuped(rawHeaders: unknown): boolean {
  if (!Array.isArray(rawHeaders)) return false
  let host = 0
  let cl = 0
  let te = 0
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i]
    if (typeof name !== 'string') continue
    const key = name.toLowerCase()
    const value = rawHeaders[i + 1]
    if (key === 'host') host += 1
    else if (key === 'content-length') cl += 1
    else if (key === 'transfer-encoding') {
      te += 1
      if (typeof value === 'string' && value.includes(',')) return true
    }
  }
  return host > 1 || cl > 1 || te > 1
}

/**
 * Relative /mcp stays. Absolute-form or //... only when the hostname
 * matches the Host header and is not our web (Mode B is user-owned HTTPS).
 */
export function peelRelayRequestUrl(rawUrl: string | undefined, hostHeader: string | null): string | 'bad' {
  const raw = typeof rawUrl === 'string' && rawUrl ? rawUrl : '/'
  if (raw.includes('\0')) return 'bad'
  const pathOnly = raw.split('?')[0] ?? raw
  if (!pathOnly.startsWith('//') && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(pathOnly)) return raw
  try {
    const parsed = new URL(raw.startsWith('//') ? `http:${raw}` : raw)
    if (relayHostIsOurWeb(parsed.hostname)) return 'bad'
    if (!hostHeader) return 'bad'
    const headerName = hostnameFromHostHeader(hostHeader)
    if (!headerName || headerName !== parsed.hostname.toLowerCase()) return 'bad'
    return `${parsed.pathname}${parsed.search}`
  } catch {
    return 'bad'
  }
}

/**
 * Client hung up while we still owe POST /mcp. Body-complete close sets
 * IncomingMessage.destroyed on current Node; that is not a hang-up
 * (MCP-013). Fetch abort often skips req.aborted and destroys the socket
 * instead. Pair hang-up lives in pair-routes (not this leaf).
 */
export function relayMcpClientHungUp(
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  if (res.writableEnded === true) return false
  if (req.aborted === true) return true
  const sock = req.socket
  return Boolean(sock && sock.destroyed === true)
}

function readBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; reason: 'oversize' | 'cancelled' }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    let total = 0
    let settled = false
    const finish = (
      result: { ok: true; text: string } | { ok: false; reason: 'oversize' | 'cancelled' },
    ): void => {
      if (settled) return
      settled = true
      req.removeListener('data', onData)
      req.removeListener('end', onEnd)
      req.removeListener('error', onError)
      req.removeListener('aborted', onAborted)
      resolve(result)
    }
    const onData = (c: Buffer | string): void => {
      const buf = typeof c === 'string' ? Buffer.from(c) : c
      total += buf.length
      if (total > maxBytes) {
        req.destroy()
        finish({ ok: false, reason: 'oversize' })
        return
      }
      chunks.push(buf)
    }
    const onEnd = (): void => {
      if (req.aborted === true) {
        finish({ ok: false, reason: 'cancelled' })
        return
      }
      finish({ ok: true, text: Buffer.concat(chunks).toString('utf8') })
    }
    const onError = (): void => {
      finish({ ok: false, reason: 'cancelled' })
    }
    const onAborted = (): void => {
      finish({ ok: false, reason: 'cancelled' })
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
    req.on('aborted', onAborted)
  })
}

function wellKnownKind(route: RelayRoute): WellKnownKind | null {
  if (route === 'well_known_prm') return 'prm'
  if (route === 'well_known_prm_mcp') return 'prm_mcp'
  if (route === 'well_known_as') return 'as'
  if (route === 'well_known_as_mcp') return 'as_mcp'
  return null
}

function sendOptions(req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(204, { ...CORS, 'cache-control': 'no-store', ...CLOSE_HDR })
  res.end()
  destroyReq(req)
}

function beginOrCap(
  req: IncomingMessage,
  res: ServerResponse,
  inflight: InFlightSet,
  logName: string,
): (() => void) | null {
  const done = inflight.begin()
  if (done) return done
  sendJsonClose(req, res, 429, '{"error":"concurrent_cap"}\n', { 'retry-after': '1' })
  logRelay((req.method || 'POST').toUpperCase(), logName, 429)
  return null
}

function mcpEnvelopeRefuse(
  req: IncomingMessage,
  res: ServerResponse,
): 'ok' | 'refuse' {
  if (relayRawHeadersDuped(req.rawHeaders)) {
    sendJsonClose(req, res, 400, '{"error":"bad_header"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  const host = relayExactHost(req)
  if (host === null) {
    sendJsonClose(req, res, 400, '{"error":"bad_host"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  const hostName = hostnameFromHostHeader(host)
  if (!hostName || relayHostIsOurWeb(hostName)) {
    sendJsonClose(req, res, 400, '{"error":"bad_host"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  if (relayHasTeAndCl(req.headers) || relayContentLengthBad(req.headers)) {
    sendJsonClose(req, res, 400, '{"error":"bad_length"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  const declared = relayDeclaredContentLength(req.headers)
  if (declared !== null && declared > MCP_RELAY_POST_BODY_MAX_BYTES) {
    sendJsonClose(req, res, 413, '{"error":"payload_too_large"}\n')
    logRelay('POST', '/mcp', 413)
    return 'refuse'
  }
  if (
    headerIsArray(req.headers['content-type'])
    || headerIsArray(req.headers.authorization)
    || headerIsArray(req.headers['mcp-api-key'])
  ) {
    sendJsonClose(req, res, 400, '{"error":"bad_header"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  if (!relayJsonContentType(req.headers['content-type'])) {
    sendJsonClose(req, res, 415, '{"error":"unsupported_media"}\n')
    logRelay('POST', '/mcp', 415)
    return 'refuse'
  }
  // The pairing queue forwards JSON-RPC only. Refuse unsupported HTTP versions
  // here, so modern clients can fall back before headers would be discarded.
  if (!relayProtocolHeaderAccepted(req.headers['mcp-protocol-version'])) {
    sendJsonClose(req, res, 400, '{"error":"unsupported_protocol_version"}\n')
    logRelay('POST', '/mcp', 400)
    return 'refuse'
  }
  return 'ok'
}

export function createRelayListener(state: RelayHandlerState) {
  const bound = bindState(state)
  const pairBinding = (): string => JSON.stringify([bound.pair.bindingVersion(), bound.pair.deviceId(), bound.pair.keyId()])
  const syncPairGrants = (): void => {
    bound.oauth.bindPair(pairBinding())
  }
  syncPairGrants()
  return function handleRelayRequest(req: IncomingMessage, res: ServerResponse): void {
    syncPairGrants()
    const method = (req.method || 'GET').toUpperCase()
    const host = relayExactHost(req)
    const peeled = peelRelayRequestUrl(req.url, host)
    const route = classifyRelayPath(peeled === 'bad' ? req.url : peeled)

    if (route === 'root' || route === 'health') {
      if (method === 'GET' || method === 'HEAD') {
        sendHealth(res, method, req.headers.accept)
        logRelay(method, route === 'health' ? '/health' : '/', 200)
        return
      }
      sendPlain(res, 405, 'Method not allowed\n', { allow: 'GET, HEAD' })
      logRelay(method, route === 'health' ? '/health' : '/', 405)
      return
    }

    const wk = wellKnownKind(route)
    if (wk) {
      if (method === 'OPTIONS') {
        sendOptions(req, res)
        return
      }
      if (method !== 'GET' && method !== 'HEAD') {
        sendPlain(res, 405, 'Method not allowed\n', { allow: 'GET, HEAD' })
        logRelay(method, 'well-known', 405)
        return
      }
      const origin = publicOriginFromRequest(req, bound.publicUrl)
      const json = `${JSON.stringify(wellKnownJson(wk, origin))}\n`
      sendJson(res, 200, json, undefined, method)
      logRelay(method, 'well-known', 200)
      return
    }

    if (route === 'authorize') {
      const done = beginOrCap(req, res, bound.inflight, 'authorize')
      if (!done) return
      void handleAuthorize(req, res, bound).finally(done)
      return
    }
    if (route === 'token') {
      const done = beginOrCap(req, res, bound.inflight, 'token')
      if (!done) return
      void handleToken(req, res, bound).finally(done)
      return
    }
    if (route === 'register') {
      const done = beginOrCap(req, res, bound.inflight, 'register')
      if (!done) return
      void handleRegister(req, res, bound).finally(done)
      return
    }

    if (
      route === 'pair_hello'
      || route === 'pair_next'
      || route === 'pair_reply'
      || route === 'pair_unavailable'
    ) {
      const name = route.slice('pair_'.length) as 'hello' | 'next' | 'reply' | 'unavailable'
      const done = beginOrCap(req, res, bound.inflight, `/pair/${name}`)
      if (!done) return
      void handlePairRoute(req, res, name, bound.pairSecret, bound.pair, syncPairGrants).finally(done)
      logRelay(method, `/pair/${name}`, 0)
      return
    }

    if (route === 'prefix') {
      sendPlain(res, 404, 'Not found\n')
      logRelay(method, 'prefix', 404)
      return
    }

    if (route === 'mcp') {
      if (method === 'OPTIONS') {
        sendOptions(req, res)
        return
      }
      if (method === 'GET' || method === 'HEAD') {
        sendPlainClose(req, res, 405, 'Method not allowed\n', { allow: 'POST' }, method)
        logRelay(method, '/mcp', 405)
        return
      }
      if (method !== 'POST') {
        sendPlainClose(req, res, 405, 'Method not allowed\n', { allow: 'POST' })
        logRelay(method, '/mcp', 405)
        return
      }
      if (peeled === 'bad') {
        sendJsonClose(req, res, 400, '{"error":"bad_url"}\n')
        logRelay('POST', '/mcp', 400)
        return
      }
      if (mcpEnvelopeRefuse(req, res) === 'refuse') return
      if (bound.closing()) {
        sendJsonClose(req, res, 503, MCP_RELAY_503_UNAVAILABLE)
        logRelay('POST', '-', 503)
        return
      }
      const done = beginOrCap(req, res, bound.inflight, '/mcp')
      if (!done) return
      void (async () => {
        try {
          const auth = resolveModeBAuth(req, bound)
          if (auth.kind === 'scope') {
            send403Scope(req, res)
            logRelay('POST', '-', 403)
            return
          }
          if (auth.kind !== 'ok') {
            send401Prm(req, res, bound.publicUrl)
            logRelay('POST', '-', 401)
            return
          }
          const requestBinding = pairBinding()
          const body = await readBody(req, MCP_RELAY_POST_BODY_MAX_BYTES)
          if (!body.ok) {
            if (body.reason === 'cancelled' || relayMcpClientHungUp(req, res)) {
              if (res.writableEnded !== true && !res.headersSent) {
                sendJsonClose(req, res, 503, MCP_RELAY_503_UNAVAILABLE)
              } else {
                destroyReq(req)
              }
              logRelay('POST', '-', 503)
              return
            }
            sendJsonClose(req, res, 413, '{"error":"payload_too_large"}\n')
            logRelay('POST', '-', 413)
            return
          }
          if (bound.closing()) {
            sendJsonClose(req, res, 503, MCP_RELAY_503_UNAVAILABLE)
            logRelay('POST', '-', 503)
            return
          }
          syncPairGrants()
          if (requestBinding !== pairBinding()
            || resolveModeBAuth(req, bound).kind !== 'ok') {
            send401Prm(req, res, bound.publicUrl)
            return
          }
          const text = body.text
          const peek = peekJsonRpc(text)
          if (bound.pair.unavailable()) {
            sendJsonClose(req, res, 503, MCP_RELAY_503_UNAVAILABLE)
            logRelay(peek.method === '-' ? 'POST' : peek.method, peek.name, 503)
            return
          }
          if (!bound.pair.paired()) {
            sendJsonClose(req, res, 503, MCP_RELAY_503_NOT_PAIRED)
            logRelay(peek.method === '-' ? 'POST' : peek.method, peek.name, 503)
            return
          }
          if (!bound.pair.supportsConnectionIdentity()) {
            sendJsonClose(req, res, 503, '{"error":"desktop_update_required","message":"Update and reconnect the paired desktop to separate connector users."}\n')
            return
          }
          // Trusted side-channel data from authentication, never params/_meta.
          const forwarded = bound.pair.enqueueMcp(text, auth.connection)
          const dropIfHungUp = (): void => {
            if (!relayMcpClientHungUp(req, res)) return
            forwarded.cancel()
            destroyReq(req)
          }
          try { req.on('aborted', dropIfHungUp) } catch { /* ignore */ }
          try { req.on('close', dropIfHungUp) } catch { /* ignore */ }
          try { req.socket?.on('close', dropIfHungUp) } catch { /* ignore */ }
          dropIfHungUp()
          let result: { status: number; json: unknown }
          try {
            result = await forwarded.wait
          } finally {
            try { req.removeListener('aborted', dropIfHungUp) } catch { /* ignore */ }
            try { req.removeListener('close', dropIfHungUp) } catch { /* ignore */ }
            try { req.socket?.removeListener('close', dropIfHungUp) } catch { /* ignore */ }
          }
          if (relayMcpClientHungUp(req, res) || res.writableEnded === true) {
            destroyReq(req)
            logRelay(peek.method === '-' ? 'POST' : peek.method, peek.name, 0)
            return
          }
          const payload = result.json == null
            ? ''
            : typeof result.json === 'string'
              ? result.json
              : `${JSON.stringify(result.json)}\n`
          if (peek.notification || result.status === 204 || payload === '') {
            endSilentAndClose(req, res)
            logRelay(peek.method === '-' ? 'POST' : peek.method, peek.name, result.status === 204 ? 204 : result.status)
            return
          }
          sendJson(res, result.status, payload.endsWith('\n') ? payload : `${payload}\n`)
          logRelay(peek.method === '-' ? 'POST' : peek.method, peek.name, result.status)
        } finally {
          done()
        }
      })()
      return
    }

    sendPlain(res, 404, 'Not found\n')
    logRelay(method, 'other', 404)
  }
}
