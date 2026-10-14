/**
 * Pasted resource URL. Absolute https. /mcp and /mcp/ are the same resource.
 */

import type { IncomingMessage } from 'node:http'

/**
 * Account + CMS hosts we refuse as a connector origin (MCP-004).
 * `isOurHostingHost === true` means do not bind, do not advertise, do not
 * parse as a public URL. We never serve this door on those hosts. Mode B is
 * the customer's own HTTPS process.
 */
const REFUSED_PUBLIC_HOSTS = new Set([
  'v-aid.ai',
  'www.v-aid.ai',
  'cms.v-aid.ai',
])

const FALLBACK_ORIGIN = 'https://127.0.0.1'

function headerHost(req: IncomingMessage): string | null {
  const raw = req.headers.host
  if (typeof raw !== 'string') return null
  const host = raw.trim()
  if (!host || host.includes('\0') || /[\r\n]/.test(host)) return null
  if (host.length > 253) return null
  return host
}

const BIND_ANY_HOSTS = new Set([
  '0.0.0.0',
  '::',
  '::0',
  '0:0:0:0:0:0:0:0',
  '::ffff:0.0.0.0',
  '::ffff:0:0',
  '0:0:0:0:0:ffff:0:0',
  '0:0:0:0:0:ffff:0.0.0.0',
])

const LOOPBACK_HOSTS = new Set([
  '127.0.0.1',
  '::1',
  'localhost',
  '::ffff:127.0.0.1',
  '::ffff:7f00:1',
])

function hostnameKey(hostnameRaw: string): string {
  return (hostnameRaw || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '')
}

function parseIpv4Octets(raw: string): [number, number, number, number] | null {
  const parts = raw.split('.')
  if (parts.length !== 4) return null
  const out: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out.push(n)
  }
  return [out[0]!, out[1]!, out[2]!, out[3]!]
}

/** Expand IPv6 (including v4-mapped and padded hextets) to 8 integers, or null. */
function parseIpv6Hextets(host: string): number[] | null {
  if (!host.includes(':')) return null
  let s = host
  const zone = s.indexOf('%')
  if (zone >= 0) s = s.slice(0, zone)
  if (!s || s.split('::').length > 2) return null

  const side = (part: string): number[] | null => {
    if (part === '') return []
    const bits = part.split(':')
    const out: number[] = []
    for (let i = 0; i < bits.length; i++) {
      const bit = bits[i] ?? ''
      if (bit.includes('.')) {
        if (i !== bits.length - 1) return null
        const oct = parseIpv4Octets(bit)
        if (!oct) return null
        out.push(((oct[0] << 8) | oct[1]) >>> 0, ((oct[2] << 8) | oct[3]) >>> 0)
        continue
      }
      if (!/^[0-9a-f]{1,4}$/.test(bit)) return null
      out.push(parseInt(bit, 16))
    }
    return out
  }

  if (!s.includes('::')) {
    const g = side(s)
    return g && g.length === 8 ? g : null
  }
  const [leftRaw, rightRaw] = s.split('::')
  const left = side(leftRaw ?? '')
  const right = side(rightRaw ?? '')
  if (!left || !right) return null
  const fill = 8 - left.length - right.length
  if (fill < 0) return null
  return [...left, ...Array<number>(fill).fill(0), ...right]
}

function ipv6AllZero(h: number[]): boolean {
  return h.length === 8 && h.every((n) => n === 0)
}

function ipv6V4MappedUnspecified(h: number[]): boolean {
  return (
    h.length === 8
    && h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0
    && h[5] === 0xffff && h[6] === 0 && h[7] === 0
  )
}

function ipv6Loopback(h: number[]): boolean {
  return (
    h.length === 8
    && h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0
    && h[5] === 0 && h[6] === 0 && h[7] === 1
  )
}

function ipv6V4MappedLoopback(h: number[]): boolean {
  return (
    h.length === 8
    && h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0
    && h[5] === 0xffff && h[6] === 0x7f00 && h[7] === 1
  )
}

function hostnameFromMaybeHostPort(hostnameRaw: string): string {
  const raw = (hostnameRaw || '').trim()
  if (!raw) return ''
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    if (end > 1) return hostnameKey(raw.slice(1, end))
  }
  if (!raw.includes('://')) {
    let colons = 0
    for (const ch of raw) {
      if (ch === ':') colons += 1
    }
    if (colons >= 2) return hostnameKey(raw)
  }
  try {
    const u = new URL(raw.includes('://') ? raw : `https://${raw}`)
    return hostnameKey(u.hostname)
  } catch {
    if (!raw.includes('://')) {
      const cut = raw.lastIndexOf(':')
      if (cut > 0 && raw.indexOf(':') === cut) return hostnameKey(raw.slice(0, cut))
    }
    return hostnameKey(raw)
  }
}

/** True = refuse this host as a connector. Never a listen target we serve. */
export function isOurHostingHost(hostnameRaw: string): boolean {
  const host = hostnameFromMaybeHostPort(hostnameRaw)
  if (!host) return false
  return REFUSED_PUBLIC_HOSTS.has(host) || host.endsWith('.v-aid.ai')
}

/** Bind-any is fine to listen on, never a public origin. */
export function isBindAnyHost(hostnameRaw: string): boolean {
  const host = hostnameFromMaybeHostPort(hostnameRaw)
  if (!host) return false
  if (BIND_ANY_HOSTS.has(host) || host === '0.0.0.0') return true
  const v6 = parseIpv6Hextets(host)
  if (!v6) return false
  return ipv6AllZero(v6) || ipv6V4MappedUnspecified(v6)
}

/** Loopback bind may stay HTTP behind the operator's own HTTPS proxy. */
export function isLoopbackBindHost(hostnameRaw: string): boolean {
  const host = hostnameFromMaybeHostPort(hostnameRaw)
  if (!host) return false
  if (LOOPBACK_HOSTS.has(host) || host.endsWith('.localhost')) return true
  const v6 = parseIpv6Hextets(host)
  if (!v6) return false
  return ipv6Loopback(v6) || ipv6V4MappedLoopback(v6)
}

export function safeAdvertisedOrigin(origin: string): string {
  if (typeof origin !== 'string' || !origin.trim()) return FALLBACK_ORIGIN
  try {
    const raw = origin.trim()
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`)
    if (u.protocol !== 'https:') return FALLBACK_ORIGIN
    if (isOurHostingHost(u.hostname) || isBindAnyHost(u.hostname)) return FALLBACK_ORIGIN
    return u.origin
  } catch {
    return FALLBACK_ORIGIN
  }
}

export function parsePublicBaseUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!trimmed || trimmed.length > 2048) return null
  if (trimmed.includes('\0') || /[\r\n]/.test(trimmed)) return null
  let u: URL
  try {
    u = new URL(trimmed)
  } catch {
    return null
  }
  if (u.username || u.password) return null
  if (u.protocol !== 'https:') return null
  const host = u.hostname.toLowerCase()
  if (!host || isOurHostingHost(host) || isBindAnyHost(host)) return null
  const path = u.pathname === '/' || u.pathname === '' || u.pathname === '/mcp' || u.pathname === '/mcp/'
    ? ''
    : null
  if (path === null) return null
  u.hash = ''
  u.search = ''
  u.pathname = ''
  return u.origin
}

export function publicOriginFromRequest(req: IncomingMessage, configured: string | null): string {
  if (configured) return safeAdvertisedOrigin(configured)
  const host = headerHost(req)
  if (!host) return FALLBACK_ORIGIN
  return safeAdvertisedOrigin(`https://${host}`)
}

export function canonicalResource(origin: string): string {
  const base = origin.replace(/\/+$/, '')
  return `${base}/mcp`
}

export function resourceMatches(presented: unknown, origin: string): boolean {
  if (typeof presented !== 'string') return false
  const want = canonicalResource(origin)
  const got = presented.trim().replace(/\/+$/, '')
  const alt = `${want}/`.replace(/\/+$/, '')
  return got === want || got === alt || presented.trim() === `${want}/`
}

export function prmMetadataUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/.well-known/oauth-protected-resource/mcp`
}

export function asMetadataUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/.well-known/oauth-authorization-server`
}

export function authorizeUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/authorize`
}

export function tokenUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/token`
}

export function registerUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/register`
}

export function wwwAuthenticatePrm(origin: string): string {
  const meta = prmMetadataUrl(origin)
  return `Bearer realm="mcp", resource_metadata="${meta}"`
}
