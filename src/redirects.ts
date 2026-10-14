/**
 * Closed OAuth redirect allowlist. Exact paths. Never a loopback helper.
 * ChatGPT is the connector/oauth/ prefix plus the one legacy URL.
 * Claude Code is http 127.0.0.1/callback and http localhost/callback any port.
 */

import {
  MCP_RELAY_CHATGPT_REDIRECT_LEGACY,
  MCP_RELAY_CHATGPT_REDIRECT_PREFIX,
  MCP_RELAY_CLAUDE_REDIRECT,
  MCP_RELAY_GEMINI_REDIRECT,
} from './constants.js'
import { isOurHostingHost } from './public-url.js'
import { DEFAULT_CLIENT_POLICY, type OAuthClientPolicy } from './client-policy.js'


function parseHttpUrl(raw: string): URL | null {
  if (typeof raw !== 'string' || !raw || raw.length > 2048) return null
  if (raw.includes('\0') || /[\r\n]/.test(raw)) return null
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  if (u.username || u.password) return null
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  return u
}

function isClaudeCodeLoopbackCallback(u: URL): boolean {
  if (u.protocol !== 'http:') return false
  const host = u.hostname.toLowerCase()
  if (host !== '127.0.0.1' && host !== 'localhost') return false
  const port = u.port ? Number(u.port) : 80
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false
  if (u.pathname !== '/callback') return false
  if (u.hash || u.search) return false
  return true
}

function isChatgptConnectorOauth(raw: string, u: URL): boolean {
  if (u.protocol !== 'https:') return false
  if (u.hostname.toLowerCase() !== 'chatgpt.com') return false
  if (raw === MCP_RELAY_CHATGPT_REDIRECT_LEGACY) return true
  if (!raw.startsWith(MCP_RELAY_CHATGPT_REDIRECT_PREFIX)) return false
  const rest = raw.slice(MCP_RELAY_CHATGPT_REDIRECT_PREFIX.length)
  if (!rest || rest.includes('/') || rest.includes('?') || rest.includes('#')) return false
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(rest)) return false
  return u.pathname.startsWith('/connector/oauth/') && u.pathname !== '/connector/oauth/'
}

export function isAllowedOAuthRedirect(raw: unknown, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): boolean {
  if (typeof raw !== 'string') return false
  const trimmed = raw.trim()
  if (!trimmed) return false
  const u = parseHttpUrl(trimmed)
  if (!u) return false
  if (isOurHostingHost(u.hostname)) return false
  if (policy.redirectUris.includes(trimmed)) return true
  if (trimmed === MCP_RELAY_CLAUDE_REDIRECT) {
    return u.protocol === 'https:' && u.hostname.toLowerCase() === 'claude.ai' && u.pathname === '/api/mcp/auth_callback'
  }
  if (trimmed === MCP_RELAY_GEMINI_REDIRECT) {
    return u.protocol === 'https:' && u.hostname === 'vertexaisearch.cloud.google.com' && u.pathname === '/oauth-redirect'
  }
  if (isChatgptConnectorOauth(trimmed, u)) return true
  if (isClaudeCodeLoopbackCallback(u)) return true
  return false
}

export function assertAllowedRedirects(uris: unknown, policy: OAuthClientPolicy = DEFAULT_CLIENT_POLICY): string[] | null {
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 16) return null
  const out: string[] = []
  for (const item of uris) {
    if (typeof item !== 'string' || !isAllowedOAuthRedirect(item, policy)) return null
    out.push(item.trim())
  }
  return out
}
