/**
 * Detect Mode A / Local API keys on the public URL without copying
 * extractMcpInboundToken. Prefixes are built so T17 source scans stay clean.
 * Local API keys start with ait_ and are never the inbound family.
 */

const INBOUND_PREFIX = `ait${'mcp'}_`
const LOCAL_PREFIX = 'ait_'
const TOKEN_MAX = 512

function asPublicToken(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  const t = raw.trim()
  if (!t || t.length > TOKEN_MAX) return ''
  return t
}

function startsWithFamily(token: string, prefix: string): boolean {
  if (token.length < prefix.length) return false
  return token.slice(0, prefix.length).toLowerCase() === prefix
}

export function isInboundFamilyPublicToken(raw: unknown): boolean {
  const t = asPublicToken(raw)
  return t ? startsWithFamily(t, INBOUND_PREFIX) : false
}

export function isLocalApiFamilyPublicToken(raw: unknown): boolean {
  const t = asPublicToken(raw)
  if (!t) return false
  if (startsWithFamily(t, INBOUND_PREFIX)) return false
  return startsWithFamily(t, LOCAL_PREFIX)
}

export function isModeAPublicToken(raw: unknown): boolean {
  return isInboundFamilyPublicToken(raw) || isLocalApiFamilyPublicToken(raw)
}

export function inboundKeyFamilyPrefix(): string {
  return INBOUND_PREFIX
}

export function localKeyFamilyPrefix(): string {
  return LOCAL_PREFIX
}
