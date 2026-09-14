import {
  MCP_RELAY_HEALTH_PLAIN_BODY,
  MCP_RELAY_HEALTH_PROBE_MAX_BYTES,
  TEAM_SPACE_HEALTH_PLAIN_BODY,
} from './constants.js'
import { isOurHostingHost } from './public-url.js'

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length
}

function capUtf8(raw: string, maxBytes: number): string {
  if (!raw) return ''
  const bytes = new TextEncoder().encode(raw)
  if (bytes.byteLength <= maxBytes) return raw
  return new TextDecoder('utf-8').decode(bytes.subarray(0, maxBytes), { stream: true })
}

function sourceForIdentity(body: string): string {
  if (typeof body !== 'string' || !body) return ''
  if (utf8ByteLength(body) <= MCP_RELAY_HEALTH_PROBE_MAX_BYTES) return body
  return capUtf8(body, MCP_RELAY_HEALTH_PROBE_MAX_BYTES)
}

/** Our web / CMS / hosting names. This connector never is those hosts (MCP-004). */
function namesOurHosting(lower: string): boolean {
  if (!lower) return false
  if (lower.includes('coolify') || lower.includes('directus')) return true
  const found = lower.match(/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/g)
  if (!found) return false
  for (const host of found) {
    if (isOurHostingHost(host)) return true
  }
  return false
}

/**
 * Desktop Team Space probe identity (same rule as the desktop leaf).
 * True when the body is the historic Team Space line, includes
 * "team space bridge", or contains both "aitomation" and "team space".
 * This process must fail this check on every health body.
 */
export function looksLikeTeamSpaceHealthBody(body: string): boolean {
  const source = sourceForIdentity(body)
  if (!source) return false
  if (source === TEAM_SPACE_HEALTH_PLAIN_BODY) return true
  const t = source.trim().toLowerCase()
  if (!t) return false
  if (t === TEAM_SPACE_HEALTH_PLAIN_BODY.trim().toLowerCase()) return true
  if (t.includes('team space bridge')) return true
  return t.includes('aitomation') && t.includes('team space')
}

/** Own probe identity. Never uses Team Space tokens or our hosting names. */
export function isMcpRelayHealthBody(body: string): boolean {
  const source = sourceForIdentity(body)
  if (!source) return false
  if (looksLikeTeamSpaceHealthBody(source)) return false
  const t = source.trim().toLowerCase()
  if (!t) return false
  if (namesOurHosting(t)) return false
  if (source === MCP_RELAY_HEALTH_PLAIN_BODY) return true
  if (t === MCP_RELAY_HEALTH_PLAIN_BODY.trim().toLowerCase()) return true
  if (t.includes('mcp relay')) return true
  return t.includes('aitomation') && t.includes('ai connector')
}
