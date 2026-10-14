/**
 * Mode B authorization server. We verify PKCE S256. We do not mint a
 * verifier into /authorize. CIMD URL client_ids are not ID_RE grants.
 */

import { DEFAULT_CLIENT_POLICY, type OAuthClientPolicy } from './client-policy.js'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { connectionLabel } from './connection.js'
import { MCP_RELAY_OAUTH_BODY_MAX_BYTES, MCP_RELAY_SCOPE_OFFLINE } from './constants.js'
import { fetchCimdDocument, isCimdClientId } from './cimd.js'
import { ID_RE, accessTtl, authCodeTtl, mintOpaqueToken, refreshTtl, type OAuthStore } from './oauth-store.js'
import { isAllowedOAuthRedirect } from './redirects.js'
import {
  authorizeUrl,
  canonicalResource,
  publicOriginFromRequest,
  resourceMatches,
  tokenUrl,
} from './public-url.js'
import { sha256Hex, timingSafeEqualHex, timingSafeEqualString } from './timing-safe.js'
import type { PairStore } from './pair-store.js'
import { showOwnerApproval, ownerApprovalFailure } from './owner-approval.js'

const OAUTH_STATE_MAX = 512

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  pragma: 'no-cache',
} as const

export type OAuthRequestCtx = {
  clientPolicy?: OAuthClientPolicy
  oauth: OAuthStore
  publicUrl: string | null
  pairSecret?: string | null
  pair?: PairStore
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8')
  res.writeHead(status, {
    ...JSON_HEADERS,
    'content-length': payload.length,
    'access-control-allow-origin': '*',
  })
  res.end(payload)
}

function sendOauthError(res: ServerResponse, status: number, error: string, desc?: string): void {
  const body: Record<string, string> = { error }
  if (desc) body.error_description = desc
  sendJson(res, status, body)
}

function headerLine(req: IncomingMessage, name: string): string {
  const raw = req.headers[name]
  if (typeof raw === 'string') return raw
  return ''
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<{ ok: true; text: string } | { ok: false }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    let total = 0
    let settled = false
    const finish = (result: { ok: true; text: string } | { ok: false }): void => {
      if (settled) return
      settled = true
      req.removeListener('data', onData)
      req.removeListener('end', onEnd)
      req.removeListener('error', onError)
      resolve(result)
    }
    const onData = (c: Buffer | string): void => {
      const buf = typeof c === 'string' ? Buffer.from(c) : c
      total += buf.length
      if (total > maxBytes) {
        req.destroy()
        finish({ ok: false })
        return
      }
      chunks.push(buf)
    }
    const onEnd = (): void => {
      finish({ ok: true, text: Buffer.concat(chunks).toString('utf8') })
    }
    const onError = (): void => {
      finish({ ok: false })
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
  })
}

function parseForm(body: string): Map<string, string> {
  const out = new Map<string, string>()
  if (!body) return out
  for (const part of body.split('&')) {
    if (!part) continue
    const eq = part.indexOf('=')
    const rawKey = eq === -1 ? part : part.slice(0, eq)
    const rawVal = eq === -1 ? '' : part.slice(eq + 1)
    let key = ''
    let val = ''
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '))
      val = decodeURIComponent(rawVal.replace(/\+/g, ' '))
    } catch {
      continue
    }
    if (!key || key === '__proto__' || key === 'constructor' || key === 'prototype') continue
    if (!out.has(key)) out.set(key, val)
  }
  return out
}

function queryMap(urlRaw: string | undefined): Map<string, string> {
  const out = new Map<string, string>()
  const raw = typeof urlRaw === 'string' ? urlRaw : ''
  const q = raw.indexOf('?')
  if (q === -1) return out
  return parseForm(raw.slice(q + 1))
}

function verifyS256(verifier: string, challenge: string): boolean {
  if (typeof verifier !== 'string' || typeof challenge !== 'string') return false
  if (verifier.length < 43 || verifier.length > 128) return false
  if (!/^[A-Za-z0-9._~-]+$/.test(verifier)) return false
  const digest = createHash('sha256').update(verifier, 'ascii').digest()
  const computed = digest.toString('base64url')
  if (computed.length !== challenge.length) return false
  try {
    return timingSafeEqual(Buffer.from(computed), Buffer.from(challenge))
  } catch {
    return false
  }
}

function basicClientSecret(req: IncomingMessage): { clientId: string; secret: string } | null {
  const auth = headerLine(req, 'authorization')
  const m = /^Basic\s+(.+)$/i.exec(auth)
  if (!m) return null
  try {
    const decoded = Buffer.from(m[1], 'base64').toString('utf8')
    const colon = decoded.indexOf(':')
    if (colon <= 0) return null
    return { clientId: decoded.slice(0, colon), secret: decoded.slice(colon + 1) }
  } catch {
    return null
  }
}

function clientSecretMatches(store: OAuthStore, clientId: string, secret: string): boolean {
  const client = store.getClient(clientId)
  if (!client || !client.secretHash || !secret) return false
  return timingSafeEqualHex(client.secretHash, sha256Hex(secret))
}

function redirectWithParams(res: ServerResponse, redirectUri: string, params: Record<string, string>): void {
  const loc = new URL(redirectUri)
  for (const [k, v] of Object.entries(params)) {
    loc.searchParams.set(k, v)
  }
  res.writeHead(302, {
    location: loc.toString(),
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
  })
  res.end()
}

async function resolveClient(
  store: OAuthStore,
  clientId: string,
  policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY,
): Promise<{ ok: true; client: { clientId: string; redirectUris: string[]; kind: string; secretHash: string | null } } | { ok: false; error: string }> {
  const existing = store.getClient(clientId)
  if (existing) return { ok: true, client: existing }
  if (isCimdClientId(clientId, policy)) {
    const fetched = await fetchCimdDocument(clientId, policy)
    if (!fetched.ok) return { ok: false, error: 'invalid_client' }
    const client = {
      clientId,
      kind: 'cimd' as const,
      secretHash: null,
      redirectUris: fetched.doc.redirectUris,
    }
    store.rememberCimd(client)
    return { ok: true, client }
  }
  if (!ID_RE.test(clientId)) return { ok: false, error: 'invalid_client' }
  return { ok: false, error: 'invalid_client' }
}

export async function handleAuthorize(req: IncomingMessage, res: ServerResponse, ctx: OAuthRequestCtx): Promise<void> {
  const method = (req.method || 'GET').toUpperCase()
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'Authorization, Content-Type',
      'access-control-max-age': '600',
    })
    res.end()
    return
  }
  if (method !== 'GET' && method !== 'POST') {
    sendOauthError(res, 405, 'invalid_request')
    return
  }
  const q = queryMap(req.url)
  const origin = publicOriginFromRequest(req, ctx.publicUrl)
  const redirectUri = q.get('redirect_uri') || ''
  const clientId = q.get('client_id') || ''
  const state = q.get('state') || ''
  const responseType = q.get('response_type') || ''
  const challenge = q.get('code_challenge') || ''
  const methodPkce = q.get('code_challenge_method') || ''
  const resource = q.get('resource') || canonicalResource(origin)
  if (!isAllowedOAuthRedirect(redirectUri, ctx.clientPolicy)) {
    sendOauthError(res, 400, 'invalid_request', 'redirect is not allowed')
    return
  }
  if (state.length > OAUTH_STATE_MAX) {
    sendOauthError(res, 400, 'invalid_request', 'state is too long')
    return
  }
  if (responseType !== 'code') {
    redirectWithParams(res, redirectUri, { error: 'unsupported_response_type', iss: origin, ...(state ? { state } : {}) })
    return
  }
  if (
    methodPkce !== 'S256'
    || !challenge
    || challenge.length < 43
    || challenge.length > 128
    || !/^[A-Za-z0-9._~-]+$/.test(challenge)
  ) {
    redirectWithParams(res, redirectUri, { error: 'invalid_request', error_description: 'PKCE S256 is required', iss: origin, ...(state ? { state } : {}) })
    return
  }
  if (!resourceMatches(resource, origin)) {
    redirectWithParams(res, redirectUri, { error: 'invalid_target', iss: origin, ...(state ? { state } : {}) })
    return
  }
  const resolved = await resolveClient(ctx.oauth, clientId, ctx.clientPolicy)
  if (!resolved.ok) {
    redirectWithParams(res, redirectUri, { error: 'invalid_client', iss: origin, ...(state ? { state } : {}) })
    return
  }
  if (!resolved.client.redirectUris.includes(redirectUri)) {
    sendOauthError(res, 400, 'invalid_request', 'redirect is not registered')
    return
  }
  if (!ctx.pairSecret || !ctx.pair?.paired() || ctx.pair.unavailable()) {
    sendOauthError(res, 503, 'temporarily_unavailable', 'Pair an available desktop project before connecting a client')
    return
  }
  if (method === 'GET') {
    showOwnerApproval(res, ctx.oauth, ctx.pair, q)
    return
  }
  if (headerLine(req, 'content-type').split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') {
    sendOauthError(res, 415, 'invalid_request')
    return
  }
  const requestOrigin = headerLine(req, 'origin')
  if (requestOrigin && requestOrigin !== origin) {
    sendOauthError(res, 403, 'access_denied')
    return
  }
  const body = await readBody(req, MCP_RELAY_OAUTH_BODY_MAX_BYTES)
  const approvalForm = body.ok ? parseForm(body.text) : new Map<string, string>()
  const approvalFailure = !body.ok ? 'invalid_form'
    : !ctx.pair.paired() || ctx.pair.unavailable() ? 'pairing_changed'
    : ownerApprovalFailure(ctx.oauth, ctx.pair, q, approvalForm, ctx.pairSecret)
  if (approvalFailure) {
    const description = approvalFailure === 'incorrect_secret'
      ? 'The relay pairing secret did not match. Start a fresh connection attempt and paste only the value of MCP_RELAY_PAIR_SECRET, without the variable name, quotes, or spaces.'
      : approvalFailure === 'pairing_changed'
        ? 'The desktop pairing changed while this page was open. Start a fresh connection attempt from your MCP client.'
        : approvalFailure === 'stale_form'
          ? 'This approval form expired, was already submitted, or predates a relay restart. Start a fresh connection attempt from your MCP client; do not resubmit this page.'
          : 'The approval request changed or could not be read. Start a fresh connection attempt from your MCP client.'
    console.warn('[mcp-relay] owner approval rejected:', approvalFailure)
    sendOauthError(res, 403, 'access_denied', description)
    return
  }
  const now = Date.now()
  const code = mintOpaqueToken('ac_')
  ctx.oauth.putCode({
    connectionId: mintOpaqueToken('connection_'),
    connectionLabel: connectionLabel(approvalForm.get('connection_name')),
    codeHash: sha256Hex(code),
    clientId,
    redirectUri,
    challenge,
    resource: canonicalResource(origin),
    expiresAt: authCodeTtl(now),
    used: false,
  })
  const params: Record<string, string> = { code, iss: origin.replace(/\/+$/, '') }
  if (state) params.state = state
  redirectWithParams(res, redirectUri, params)
}

export async function handleToken(req: IncomingMessage, res: ServerResponse, ctx: OAuthRequestCtx): Promise<void> {
  const method = (req.method || 'GET').toUpperCase()
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'Authorization, Content-Type',
      'access-control-max-age': '600',
    })
    res.end()
    return
  }
  if (method !== 'POST') {
    sendOauthError(res, 405, 'invalid_request')
    return
  }
  const ct = headerLine(req, 'content-type').split(';')[0].trim().toLowerCase()
  if (ct !== 'application/x-www-form-urlencoded') {
    sendOauthError(res, 415, 'invalid_request', 'token is application/x-www-form-urlencoded')
    return
  }
  const body = await readBody(req, MCP_RELAY_OAUTH_BODY_MAX_BYTES)
  if (!body.ok) {
    sendOauthError(res, 400, 'invalid_request')
    return
  }
  const form = parseForm(body.text)
  const grant = form.get('grant_type') || ''
  const origin = publicOriginFromRequest(req, ctx.publicUrl)
  const now = Date.now()
  const basic = basicClientSecret(req)
  if (grant === 'authorization_code') {
    const code = form.get('code') || ''
    const verifier = form.get('code_verifier') || ''
    const redirectUri = form.get('redirect_uri') || ''
    const clientId = form.get('client_id') || basic?.clientId || ''
    const secret = form.get('client_secret') || basic?.secret || ''
    const row = ctx.oauth.takeCode(code, now)
    if (!row) {
      sendOauthError(res, 400, 'invalid_grant')
      return
    }
    if (row.clientId !== clientId || row.redirectUri !== redirectUri) {
      sendOauthError(res, 400, 'invalid_grant')
      return
    }
    if (!verifyS256(verifier, row.challenge)) {
      sendOauthError(res, 400, 'invalid_grant')
      return
    }
    const client = ctx.oauth.getClient(clientId)
    if (client && client.kind === 'confidential') {
      if (!clientSecretMatches(ctx.oauth, clientId, secret)) {
        sendOauthError(res, 401, 'invalid_client')
        return
      }
    }
    const access = mintOpaqueToken('at_')
    const refresh = mintOpaqueToken('rt_')
    const accessExp = accessTtl(now)
    const refreshExp = refreshTtl(now)
    const connectionId = row.connectionId || mintOpaqueToken('connection_')
    ctx.oauth.putAccess({
      connectionId, connectionLabel: row.connectionLabel,
      tokenHash: sha256Hex(access),
      clientId,
      resource: row.resource,
      expiresAt: accessExp,
    })
    ctx.oauth.putRefresh({
      connectionId, connectionLabel: row.connectionLabel,
      tokenHash: sha256Hex(refresh),
      clientId,
      resource: row.resource,
      expiresAt: refreshExp,
      publicClient: !client || client.kind !== 'confidential',
    })
    sendJson(res, 200, {
      access_token: access,
      token_type: 'Bearer',
      expires_in: Math.floor((accessExp - now) / 1000),
      refresh_token: refresh,
      scope: MCP_RELAY_SCOPE_OFFLINE,
      resource: row.resource,
    })
    return
  }
  if (grant === 'refresh_token') {
    const presented = form.get('refresh_token') || ''
    const clientId = form.get('client_id') || basic?.clientId || ''
    const secret = form.get('client_secret') || basic?.secret || ''
    const row = ctx.oauth.takeRefresh(presented, now)
    if (!row) {
      sendOauthError(res, 400, 'invalid_grant')
      return
    }
    if (clientId && row.clientId !== clientId) {
      sendOauthError(res, 400, 'invalid_grant')
      return
    }
    const client = ctx.oauth.getClient(row.clientId)
    if (client && client.kind === 'confidential') {
      if (!clientSecretMatches(ctx.oauth, row.clientId, secret)) {
        sendOauthError(res, 401, 'invalid_client')
        return
      }
    }
    const access = mintOpaqueToken('at_')
    const accessExp = accessTtl(now)
    const connectionId = row.connectionId || mintOpaqueToken('connection_')
    ctx.oauth.putAccess({
      connectionId, connectionLabel: row.connectionLabel,
      tokenHash: sha256Hex(access),
      clientId: row.clientId,
      resource: row.resource,
      expiresAt: accessExp,
    })
    const nextRefresh = row.publicClient ? mintOpaqueToken('rt_') : presented
    const refreshExp = refreshTtl(now)
    ctx.oauth.putRefresh({
      connectionId, connectionLabel: row.connectionLabel,
      tokenHash: sha256Hex(nextRefresh),
      clientId: row.clientId,
      resource: row.resource,
      expiresAt: refreshExp,
      publicClient: row.publicClient,
    })
    sendJson(res, 200, {
      access_token: access,
      token_type: 'Bearer',
      expires_in: Math.floor((accessExp - now) / 1000),
      refresh_token: nextRefresh,
      scope: MCP_RELAY_SCOPE_OFFLINE,
      resource: row.resource,
    })
    return
  }
  sendOauthError(res, 400, 'unsupported_grant_type')
}

export async function handleRegister(req: IncomingMessage, res: ServerResponse, ctx: OAuthRequestCtx): Promise<void> {
  const method = (req.method || 'GET').toUpperCase()
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'Content-Type',
    })
    res.end()
    return
  }
  if (method !== 'POST') {
    sendOauthError(res, 405, 'invalid_request')
    return
  }
  const ct = headerLine(req, 'content-type').split(';')[0].trim().toLowerCase()
  if (ct !== 'application/json') {
    sendOauthError(res, 415, 'invalid_request')
    return
  }
  const body = await readBody(req, MCP_RELAY_OAUTH_BODY_MAX_BYTES)
  if (!body.ok) {
    sendOauthError(res, 400, 'invalid_client_metadata')
    return
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(body.text) as unknown
  } catch {
    sendOauthError(res, 400, 'invalid_client_metadata')
    return
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    sendOauthError(res, 400, 'invalid_client_metadata')
    return
  }
  const rec = parsed as Record<string, unknown>
  const methodAuth = typeof rec.token_endpoint_auth_method === 'string'
    ? rec.token_endpoint_auth_method
    : 'none'
  if (methodAuth !== 'none') {
    sendOauthError(res, 400, 'invalid_client_metadata', 'DCR is public (none) only')
    return
  }
  const uris = rec.redirect_uris
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 16) {
    sendOauthError(res, 400, 'invalid_redirect_uri')
    return
  }
  const redirectUris: string[] = []
  for (const item of uris) {
    if (typeof item !== 'string' || !isAllowedOAuthRedirect(item, ctx.clientPolicy)) {
      sendOauthError(res, 400, 'invalid_redirect_uri')
      return
    }
    redirectUris.push(item.trim())
  }
  const clientId = mintOpaqueToken('pub_').slice(0, 36)
  ctx.oauth.putPublicClient({
    clientId,
    kind: 'public',
    secretHash: null,
    redirectUris,
  })
  if (!ctx.oauth.getClient(clientId)) {
    sendOauthError(res, 503, 'temporarily_unavailable')
    return
  }
  const origin = publicOriginFromRequest(req, ctx.publicUrl)
  sendJson(res, 201, {
    client_id: clientId,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    code_challenge_methods: ['S256'],
    authorization_endpoint: authorizeUrl(origin),
    token_endpoint: tokenUrl(origin),
  })
}

export function lookupAccessToken(store: OAuthStore, token: string, nowMs: number) {
  return store.findAccess(token, nowMs)
}

export { timingSafeEqualString }
