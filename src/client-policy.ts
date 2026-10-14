import { isOurHostingHost } from './public-url.js'
import { isPrivateOrLocalFetchHost } from './ssrf-host.js'

/** Operator additions are per relay; no wildcard origins or provider code changes. */
export type OAuthClientPolicy = {
  redirectUris: readonly string[]
  cimdHosts: readonly string[]
}
export const DEFAULT_CLIENT_POLICY: OAuthClientPolicy = { redirectUris: [], cimdHosts: [] }

export function validConfiguredRedirect(raw: string): boolean {
  if (!raw || raw !== raw.trim() || raw.length > 2048 || /[\s\0\\]/.test(raw)) return false
  try {
    const u = new URL(raw)
    if (u.username || u.password || u.hash || u.hostname.includes('*') || isOurHostingHost(u.hostname)) return false
    if (u.protocol === 'https:') return !isPrivateOrLocalFetchHost(u.hostname)
    return u.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(u.hostname)
  } catch { return false }
}

function jsonStrings(raw: string | undefined, name: string): string[] {
  if (!raw?.trim()) return []
  let value: unknown
  try { value = JSON.parse(raw) } catch { throw new Error(`${name} must be a JSON array of strings`) }
  if (!Array.isArray(value) || value.length > 64 || !value.every((item) => typeof item === 'string')) {
    throw new Error(`${name} must be a JSON array of at most 64 strings`)
  }
  return [...new Set(value)]
}

export function parseOAuthClientPolicy(env: Record<string, string | undefined>): OAuthClientPolicy {
  const redirectUris = jsonStrings(env.MCP_RELAY_OAUTH_REDIRECT_URIS, 'MCP_RELAY_OAUTH_REDIRECT_URIS')
  if (redirectUris.some((uri) => !validConfiguredRedirect(uri))) {
    throw new Error('MCP_RELAY_OAUTH_REDIRECT_URIS requires exact public HTTPS callbacks or HTTP loopback callbacks, without credentials or fragments')
  }
  const cimdHosts = jsonStrings(env.MCP_RELAY_CIMD_HOSTS, 'MCP_RELAY_CIMD_HOSTS')
  if (cimdHosts.some((host) => !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/i.test(host)
    || isOurHostingHost(host) || isPrivateOrLocalFetchHost(host))) {
    throw new Error('MCP_RELAY_CIMD_HOSTS requires exact public DNS hostnames, without wildcards, ports or URLs')
  }
  return { redirectUris, cimdHosts: cimdHosts.map((host) => host.toLowerCase()) }
}
