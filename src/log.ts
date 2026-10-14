import { MCP_RELAY_LOG_NAME_MAX } from './constants.js'
import { inboundKeyFamilyPrefix, localKeyFamilyPrefix } from './mode-a-key.js'

const LOG_INFO_MAX = 400

function escapeRe(raw: string): string {
  return raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function asWellFormed(raw: string): string {
  const withMethod = raw as { toWellFormed?: () => string }
  if (typeof withMethod.toWellFormed === 'function') return withMethod.toWellFormed()
  return raw
}

function capDisplay(raw: string, max: number): string {
  const well = asWellFormed(raw)
  if (well.length <= max) return well
  let cut = well.slice(0, max)
  const last = cut.charCodeAt(cut.length - 1)
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1)
  return `${cut}...`
}

function capName(raw: string): string {
  const t = raw.trim()
  if (!t) return '-'
  const clean = t.replace(/[^\x20-\x7e]/g, '?')
  if (!clean) return '-'
  return capDisplay(clean, MCP_RELAY_LOG_NAME_MAX)
}

function redactSecrets(raw: string): string {
  let s = raw
  s = s.replace(/Bearer\s+\S+/gi, 'Bearer [redacted]')
  const inbound = escapeRe(inboundKeyFamilyPrefix())
  const local = escapeRe(localKeyFamilyPrefix())
  s = s.replace(new RegExp(`(^|[^A-Za-z0-9])((?:${inbound}|${local})[A-Za-z0-9_]+)`, 'gi'), '$1[redacted]')
  s = s.replace(/(access_token|token|secret|password)=([^\s&]+)/gi, '$1=[redacted]')
  return s
}

/** method + name + status only. Never args, secrets, or project names. */
export function logRelay(method: string, name: string, status: number): void {
  const m = capName(method)
  const n = capName(name)
  const line = `[mcp-relay] ${m} ${n} ${status}\n`
  try {
    process.stdout.write(line)
  } catch {
    // A full pipe must not take down the listener.
  }
}

export function logRelayInfo(message: string): void {
  const ascii = message.replace(/[\u2014\u2013\u2026]/g, '-').replace(/[\0\r\n]/g, ' ')
  const clean = capDisplay(redactSecrets(ascii), LOG_INFO_MAX)
  try {
    process.stdout.write(`[mcp-relay] ${clean}\n`)
  } catch {
    // ignore
  }
}
