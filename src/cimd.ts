/**
 * CIMD fetch for Flavor 1 (ChatGPT / Claude). Not Gemini confidential.
 * Closed host allowlist AND isPrivateOrLocalFetchHost AND hop re-check.
 * Do not treat a generic public fetch as complete.
 */

import { DEFAULT_CLIENT_POLICY, type OAuthClientPolicy } from './client-policy.js'
import dns from 'node:dns'
import type { IncomingMessage } from 'node:http'
import https from 'node:https'
import {
  MCP_RELAY_CIMD_BODY_MAX_BYTES,
  MCP_RELAY_CIMD_HOSTS,
  MCP_RELAY_CIMD_MAX_HOPS,
  MCP_RELAY_CIMD_TIMEOUT_MS,
} from './constants.js'
import { isOurHostingHost } from './public-url.js'
import { isAllowedOAuthRedirect } from './redirects.js'
import { isInvalidDottedIpv4, isPrivateOrLocalFetchHost } from './ssrf-host.js'

export type CimdDocument = {
  clientId: string
  redirectUris: string[]
  tokenEndpointAuthMethod: 'none'
}

const CIMD_HOST_SET = new Set(MCP_RELAY_CIMD_HOSTS)

function stripTrailingDots(host: string): string {
  return host.replace(/\.+$/, '')
}

export function cimdHostAllowed(hostnameRaw: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): boolean {
  const raw = (hostnameRaw || '').trim().toLowerCase()
  if (!raw) return false
  if (isOurHostingHost(raw) || isPrivateOrLocalFetchHost(raw) || isInvalidDottedIpv4(raw)) return false
  const stripped = stripTrailingDots(raw)
  if (!stripped) return false
  if (isOurHostingHost(stripped) || isPrivateOrLocalFetchHost(stripped) || isInvalidDottedIpv4(stripped)) return false
  if (!CIMD_HOST_SET.has(stripped) && !policy.cimdHosts.includes(stripped)) return false
  return true
}

export function cimdUrlAllowed(raw: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): { ok: true; url: URL } | { ok: false; error: string } {
  if (typeof raw !== 'string' || !raw || raw.length > 2048) return { ok: false, error: 'bad_url' }
  if (raw.includes('\0') || /[\r\n]/.test(raw)) return { ok: false, error: 'bad_url' }
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return { ok: false, error: 'bad_url' }
  }
  if (u.username || u.password) return { ok: false, error: 'bad_url' }
  if (u.protocol !== 'https:') return { ok: false, error: 'https_only' }
  if (!cimdHostAllowed(u.hostname, policy)) return { ok: false, error: 'host_refused' }
  return { ok: true, url: u }
}

export function resolveCimdHop(current: URL, locationRaw: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): { ok: true; url: URL } | { ok: false; error: string } {
  if (typeof locationRaw !== 'string' || !locationRaw.trim()) return { ok: false, error: 'bad_location' }
  if (locationRaw.includes('\0') || /[\r\n]/.test(locationRaw)) return { ok: false, error: 'bad_location' }
  let next: URL
  try {
    next = new URL(locationRaw, current)
  } catch {
    return { ok: false, error: 'bad_location' }
  }
  return cimdUrlAllowed(next.toString(), policy)
}

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | dns.LookupAddress[],
  family?: number,
) => void

function refusedLookupError(): NodeJS.ErrnoException {
  const err = new Error('host_refused') as NodeJS.ErrnoException
  err.code = 'EACCES'
  return err
}

/**
 * Connect-time lookup for CIMD. Hostname allowlist is not enough: the
 * stack resolves again at connect. DNS errors pass through. Private
 * answers and our web hosts are refused (MCP-004 / T18).
 */
export function cimdSafeDnsLookup(
  hostname: string,
  options: dns.LookupOneOptions | dns.LookupAllOptions | number | undefined,
  callback: LookupCallback,
): void {
  if (
    typeof hostname !== 'string'
    || isOurHostingHost(hostname)
    || isPrivateOrLocalFetchHost(hostname)
    || isInvalidDottedIpv4(hostname)
  ) {
    callback(refusedLookupError(), '')
    return
  }
  const opts = typeof options === 'object' && options !== null ? options : {}
  const wantsAll = (opts as dns.LookupAllOptions).all === true
  dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
    if (err) {
      callback(err, '')
      return
    }
    const safe = (Array.isArray(addresses) ? addresses : []).filter(
      (entry) =>
        entry
        && typeof entry.address === 'string'
        && !isPrivateOrLocalFetchHost(entry.address)
        && !isOurHostingHost(entry.address),
    )
    if (safe.length === 0) {
      callback(refusedLookupError(), '')
      return
    }
    if (wantsAll) {
      callback(null, safe)
      return
    }
    callback(null, safe[0].address, safe[0].family)
  })
}

function readCapped(res: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    res.on('data', (c: Buffer | string) => {
      const buf = typeof c === 'string' ? Buffer.from(c) : c
      total += buf.length
      if (total > maxBytes) {
        res.destroy()
        reject(new Error('cimd_too_large'))
        return
      }
      chunks.push(buf)
    })
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    res.on('error', reject)
  })
}

function getOnce(url: URL, timeoutMs: number): Promise<{ status: number; location: string | null; body: string; contentType: string }> {
  return new Promise((resolve, reject) => {
    if (url.protocol !== 'https:') {
      reject(new Error('https_only'))
      return
    }
    const req = https.request(
      {
        protocol: 'https:',
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Connection: 'close',
        },
        timeout: timeoutMs,
        lookup: cimdSafeDnsLookup,
      },
      (res) => {
        const remote = res.socket && typeof res.socket.remoteAddress === 'string'
          ? res.socket.remoteAddress
          : ''
        if (remote && (isPrivateOrLocalFetchHost(remote) || isOurHostingHost(remote))) {
          res.destroy()
          reject(new Error('host_refused'))
          return
        }
        const location = typeof res.headers.location === 'string' ? res.headers.location : null
        const contentType = typeof res.headers['content-type'] === 'string' ? res.headers['content-type'] : ''
        void readCapped(res, MCP_RELAY_CIMD_BODY_MAX_BYTES).then((body) => {
          resolve({
            status: typeof res.statusCode === 'number' ? res.statusCode : 0,
            location,
            body,
            contentType,
          })
        }).catch(reject)
      },
    )
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy()
      reject(new Error('cimd_timeout'))
    })
    req.end()
  })
}

export function parseCimdDocument(clientIdUrl: string, body: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): CimdDocument | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(body) as unknown
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
  const rec = parsed as Record<string, unknown>
  if ('client_id' in rec) {
    if (typeof rec.client_id !== 'string' || rec.client_id.trim() !== clientIdUrl) return null
  }
  const redirectUris = rec.redirect_uris
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 16) return null
  const allowed: string[] = []
  for (const item of redirectUris) {
    if (typeof item !== 'string' || !isAllowedOAuthRedirect(item, policy)) return null
    allowed.push(item.trim())
  }
  // SEP-3149 clients advertise capabilities in the plural field. The legacy
  // singular field is only a preference when the plural field is present.
  // This relay implements public-client PKCE, so accept only an intersection
  // containing `none`; never silently downgrade a confidential-only client.
  if ('token_endpoint_auth_methods_supported' in rec) {
    const methods = rec.token_endpoint_auth_methods_supported
    if (!Array.isArray(methods) || !methods.length
      || !methods.every((method) => typeof method === 'string' && method.length > 0)
      || !methods.includes('none')) return null
  } else if ('token_endpoint_auth_method' in rec && rec.token_endpoint_auth_method !== 'none') {
    return null
  }
  return {
    clientId: clientIdUrl,
    redirectUris: allowed,
    tokenEndpointAuthMethod: 'none',
  }
}

export async function fetchCimdDocument(clientIdUrl: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): Promise<
  { ok: true; doc: CimdDocument } | { ok: false; error: string }
> {
  let current = cimdUrlAllowed(clientIdUrl, policy)
  if (!current.ok) return current
  let hops = 0
  try {
    while (hops <= MCP_RELAY_CIMD_MAX_HOPS) {
      const page = await getOnce(current.url, MCP_RELAY_CIMD_TIMEOUT_MS)
      if (page.status >= 300 && page.status < 400) {
        hops += 1
        if (hops > MCP_RELAY_CIMD_MAX_HOPS) return { ok: false, error: 'too_many_hops' }
        if (!page.location) return { ok: false, error: 'bad_location' }
        const hop = resolveCimdHop(current.url, page.location, policy)
        if (!hop.ok) return hop
        current = hop
        continue
      }
      if (page.status !== 200) return { ok: false, error: 'cimd_http' }
      if (!/application\/json/i.test(page.contentType)) return { ok: false, error: 'cimd_type' }
      const doc = parseCimdDocument(clientIdUrl, page.body, policy)
      if (!doc) return { ok: false, error: 'cimd_doc' }
      return { ok: true, doc }
    }
    return { ok: false, error: 'too_many_hops' }
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'cimd_fetch'
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : ''
    if (msg === 'cimd_timeout' || msg === 'cimd_too_large' || msg === 'https_only' || msg === 'host_refused') {
      return { ok: false, error: msg }
    }
    if (code === 'EACCES') return { ok: false, error: 'host_refused' }
    return { ok: false, error: 'cimd_fetch' }
  }
}

export function isCimdClientId(raw: string, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): boolean {
  if (typeof raw !== 'string') return false
  return cimdUrlAllowed(raw.trim(), policy).ok
}
