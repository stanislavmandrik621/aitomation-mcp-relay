/**
 * Accept-negotiate for GET / and GET /health.
 *
 * Browsers that ask for text/html (q>0, and that type wins over text/plain
 * and any-type) get a short status card. Missing Accept, any-type Accept,
 * and text/plain stay the historic one-line body so curl monitors and the
 * 4 KiB probe cap do not break.
 *
 * Fail closed on NUL, lone surrogates, C0 (except TAB), C1, or a header
 * whose UTF-8 size is over 2048 bytes (CJK over the cap included).
 */

import {
  MCP_RELAY_ACCEPT_ARRAY_MAX,
  MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX,
} from './constants.js'

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length
}

function stringIsWellFormed(raw: string): boolean {
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = raw.charCodeAt(i + 1)
      if (n < 0xdc00 || n > 0xdfff) return false
      i++
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false
    }
  }
  return true
}

function acceptHeaderLooksSafe(raw: string): boolean {
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i)
    if (c === 0 || c === 0x7f) return false
    if (c < 0x20 && c !== 0x09) return false
    if (c >= 0x80 && c <= 0x9f) return false
  }
  return stringIsWellFormed(raw)
}

function acceptHeaderWithinCap(raw: string): boolean {
  if (raw.length === 0 || raw.length > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX) return false
  return utf8ByteLength(raw) <= MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX
}

function acceptQuality(params: string): number {
  if (!params) return 1
  const search = `;${params}`
  const namedQ = /(?:^|;)\s*q(?:\s*=|\s*;|\s*$)/i.test(search)
  const m = /(?:^|;)\s*q\s*=\s*([^;\s]*)/i.exec(search)
  if (!m) return namedQ ? 0 : 1
  const raw = m[1] ?? ''
  if (!/^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/.test(raw)) return 0
  const q = Number(raw)
  if (!Number.isFinite(q) || q <= 0) return 0
  return q
}

function acceptHeaderToString(acceptHeader: unknown): string | null {
  if (typeof acceptHeader === 'string') {
    // Cheap .length cap BEFORE the char-by-char safety scan (BRG-057 G9 twin).
    if (acceptHeader.length > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX) return null
    return acceptHeaderLooksSafe(acceptHeader) ? acceptHeader : null
  }
  if (!Array.isArray(acceptHeader) || acceptHeader.length === 0) return null
  if (acceptHeader.length > MCP_RELAY_ACCEPT_ARRAY_MAX) return null
  let totalUnits = 0
  let totalBytes = 0
  const parts: string[] = []
  for (const item of acceptHeader) {
    if (typeof item !== 'string' || item.length > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX) return null
    if (!acceptHeaderLooksSafe(item)) return null
    if (parts.length > 0) {
      totalUnits += 2
      totalBytes += 2
    }
    totalUnits += item.length
    totalBytes += utf8ByteLength(item)
    if (
      totalUnits > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX
      || totalBytes > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX
    ) {
      return null
    }
    parts.push(item)
  }
  const joined = parts.join(', ')
  return acceptHeaderWithinCap(joined) ? joined : null
}

function acceptHasHtmlType(accept: string): boolean {
  let bestHtml = 0
  let bestPlain = 0
  let bestStar = 0
  let bestTextStar = 0
  for (const range of accept.split(',')) {
    const trimmed = range.trim()
    if (!trimmed) continue
    const semi = trimmed.indexOf(';')
    const mediaType = (semi === -1 ? trimmed : trimmed.slice(0, semi)).trim().toLowerCase()
    const q = acceptQuality(semi === -1 ? '' : trimmed.slice(semi + 1))
    if (q <= 0) continue
    if (mediaType === 'text/html' && q > bestHtml) bestHtml = q
    if (mediaType === 'text/plain' && q > bestPlain) bestPlain = q
    if (mediaType === '*/*' && q > bestStar) bestStar = q
    if (mediaType === 'text/*' && q > bestTextStar) bestTextStar = q
  }
  return bestHtml > 0 && bestHtml > bestPlain && bestHtml >= bestStar && bestHtml >= bestTextStar
}

/**
 * True only when Accept has an exact text/html range with q>0 that wins
 * over text/plain and any-type. A throw here would 500 the probe, so catch.
 */
export function relayWantsHealthHtml(acceptHeader: unknown): boolean {
  try {
    const raw = acceptHeaderToString(acceptHeader)
    if (raw === null) return false
    if (!acceptHeaderWithinCap(raw)) return false
    return acceptHasHtmlType(raw)
  } catch {
    return false
  }
}
