/**
 * Mode B auth for POST /mcp.
 * Bearer Mode A keys on the public URL are 401+PRM.
 * Claude static_headers (mcp-api-key) is the only non-OAuth remote, paired project only.
 * Do not copy extractMcpInboundToken.
 */

import type { IncomingMessage } from 'node:http'
import { isModeAPublicToken } from './mode-a-key.js'
import type { OAuthStore } from './oauth-store.js'
import type { PairStore } from './pair-store.js'
import { isOurHostingHost, publicOriginFromRequest, resourceMatches } from './public-url.js'
import { sha256Hex, timingSafeEqualHex } from './timing-safe.js'
import { relayConnection, type RelayConnection } from './connection.js'

export type ModeBAuth =
  | { kind: 'unauth' }
  | { kind: 'mode_a' }
  | { kind: 'scope' }
  | { kind: 'ok'; via: 'oauth' | 'static_headers'; connection: RelayConnection }

function headerLine(req: IncomingMessage, name: string): string {
  const raw = req.headers[name]
  return typeof raw === 'string' ? raw : ''
}

function resourceNamesOurWeb(resource: string): boolean {
  if (typeof resource !== 'string' || !resource.trim()) return false
  try {
    return isOurHostingHost(new URL(resource).hostname)
  } catch {
    return isOurHostingHost(resource)
  }
}

function queryHasToken(urlRaw: string | undefined): boolean {
  const raw = typeof urlRaw === 'string' ? urlRaw : ''
  const q = raw.indexOf('?')
  if (q === -1) return false
  const search = raw.slice(q + 1)
  return /(?:^|&)(access_token|token)=/i.test(search)
}

export function resolveModeBAuth(
  req: IncomingMessage,
  opts: {
    oauth: OAuthStore
    pair: PairStore
    publicUrl: string | null
    staticHeaderHash: string | null
    nowMs?: number
  },
): ModeBAuth {
  if (queryHasToken(req.url)) return { kind: 'unauth' }
  const now = typeof opts.nowMs === 'number' && Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now()
  const origin = publicOriginFromRequest(req, opts.publicUrl)
  const auth = headerLine(req, 'authorization')
  // Refuse ambiguous credential sources rather than silently choosing one.
  const staticKey = headerLine(req, 'mcp-api-key').trim()
  if (auth && staticKey) return { kind: 'unauth' }
  const bearer = /^Bearer\s+(.+)$/i.exec(auth)
  if (bearer) {
    const token = bearer[1].trim()
    if (isModeAPublicToken(token)) return { kind: 'mode_a' }
    if (token.length > 256) return { kind: 'unauth' }
    const row = opts.oauth.findAccess(token, now)
    if (!row) return { kind: 'unauth' }
    if (!row.resource || !resourceMatches(row.resource, origin)) {
      return { kind: 'scope' }
    }
    if (resourceNamesOurWeb(row.resource)) return { kind: 'scope' }
    return { kind: 'ok', via: 'oauth', connection: relayConnection(row.connectionId || row.tokenHash, row.connectionLabel) }
  }
  if (!staticKey) return { kind: 'unauth' }
  if (!opts.pair.paired()) return { kind: 'unauth' }
  const expected = opts.staticHeaderHash || opts.pair.keyHash()
  if (!expected) return { kind: 'unauth' }
  const presented = sha256Hex(staticKey)
  if (!timingSafeEqualHex(expected, presented)) return { kind: 'unauth' }
  return { kind: 'ok', via: 'static_headers', connection: relayConnection(`static:${expected}`, 'Shared connector key') }
}
