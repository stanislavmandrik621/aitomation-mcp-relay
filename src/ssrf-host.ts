/**
 * Hostname-only private/local classifier. No dns.lookup.
 * Same algorithm as the desktop leaf, plus FQDN trailing dots,
 * IPv4-compatible / expanded mapped IPv6, and wildcard-DNS helpers
 * (nip.io / sslip.io / xip.io). CIMD still needs a closed host
 * allowlist AND hop re-check; this leaf alone is not CIMD-complete.
 *
 * Do not add isLoopbackHost here. Claude Code redirects are exact
 * 127.0.0.1/callback and localhost/callback paths, not a loopback helper.
 */

const IPV4_DOTTED_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

const REBIND_HELPER_EXACT = new Set(['nip.io', 'sslip.io', 'xip.io'])

const REBIND_HELPER_SUFFIXES = ['.nip.io', '.sslip.io', '.xip.io'] as const

export function parseIpv4Octets(host: string): [number, number, number, number] | null {
  const m = IPV4_DOTTED_RE.exec(host)
  if (!m) return null
  const raw = [m[1], m[2], m[3], m[4]]
  if (raw.some((part) => part.length > 1 && part.startsWith('0'))) return null
  const octets: [number, number, number, number] = [
    Number(raw[0]),
    Number(raw[1]),
    Number(raw[2]),
    Number(raw[3]),
  ]
  if (octets.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null
  return octets
}

function normalizeHostname(hostnameRaw: string): string {
  return (hostnameRaw || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '')
}

export function isInvalidDottedIpv4(host: string): boolean {
  const n = normalizeHostname(host)
  return IPV4_DOTTED_RE.test(n) && parseIpv4Octets(n) === null
}

function isPrivateIpv4(a: number, b: number): boolean {
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a >= 224) return true
  return false
}

function privateOrLocalFromDottedQuad(host: string): boolean {
  const octets = parseIpv4Octets(host)
  if (!octets) return true
  return isPrivateIpv4(octets[0], octets[1])
}

function isRebindHelperHost(host: string): boolean {
  if (REBIND_HELPER_EXACT.has(host)) return true
  return REBIND_HELPER_SUFFIXES.some((suffix) => host.endsWith(suffix))
}

function ipv4FromConsecutiveLabels(host: string): [number, number, number, number] | null {
  const labels = host.split('.')
  for (let i = 0; i <= labels.length - 4; i++) {
    const candidate = `${labels[i]}.${labels[i + 1]}.${labels[i + 2]}.${labels[i + 3]}`
    const octets = parseIpv4Octets(candidate)
    if (octets) return octets
  }
  return null
}

function ipv4FromHyphenLabel(host: string): [number, number, number, number] | null {
  for (const label of host.split('.')) {
    const m = /^(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$/.exec(label)
    if (!m) continue
    const octets = parseIpv4Octets(`${m[1]}.${m[2]}.${m[3]}.${m[4]}`)
    if (octets) return octets
  }
  return null
}

function parseHextetList(raw: string): number[] | null {
  if (raw === '') return []
  const out: number[] = []
  for (const part of raw.split(':')) {
    if (!part || !/^[0-9a-f]{1,4}$/i.test(part)) return null
    const n = parseInt(part, 16)
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null
    out.push(n)
  }
  return out
}

/**
 * Expand a literal IPv6 host to 8 groups. Dotted-quad tails and one
 * `::` run are accepted. Unparseable input is null (fail closed).
 */
function expandIpv6Groups(host: string): number[] | null {
  const bare = host.split('%')[0] || ''
  if (!bare.includes(':')) return null
  if ((bare.match(/::/g) || []).length > 1) return null

  let v4tail: [number, number, number, number] | null = null
  let core = bare
  const lastColon = bare.lastIndexOf(':')
  const after = lastColon >= 0 ? bare.slice(lastColon + 1) : ''
  if (IPV4_DOTTED_RE.test(after)) {
    v4tail = parseIpv4Octets(after)
    if (!v4tail) return null
    core = bare.slice(0, lastColon)
    if (core.endsWith(':') && !core.endsWith('::')) core = `${core}:`
  }

  const compressed = core.includes('::')
  const sides = compressed ? core.split('::') : [core]
  if (sides.length > 2) return null
  const left = parseHextetList(sides[0] ?? '')
  const right = compressed ? parseHextetList(sides[1] ?? '') : []
  if (!left || !right) return null

  const v4groups = v4tail ? [(v4tail[0] << 8) | v4tail[1], (v4tail[2] << 8) | v4tail[3]] : []
  const have = left.length + right.length + v4groups.length
  if (compressed) {
    if (have > 8) return null
    const fill = 8 - have
    return [...left, ...Array<number>(fill).fill(0), ...right, ...v4groups]
  }
  if (have !== 8) return null
  return [...left, ...right, ...v4groups]
}

function ipv4FromIpv6Groups(groups: number[], mapped: boolean): boolean {
  const a = (groups[6] >> 8) & 0xff
  const b = groups[6] & 0xff
  if (mapped && groups[5] !== 0xffff) return false
  return isPrivateIpv4(a, b)
}

function ipv6LiteralIsPrivate(host: string): boolean {
  if (host === '::1' || host === '::' || host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80')) {
    return true
  }
  const groups = expandIpv6Groups(host)
  if (!groups || groups.length !== 8) return true
  if (groups.every((g) => g === 0)) return true
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true
  if ((groups[0] & 0xfe00) === 0xfc00) return true
  if ((groups[0] & 0xffc0) === 0xfe80) return true
  const first5zero = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0
  if (first5zero && groups[5] === 0xffff) return ipv4FromIpv6Groups(groups, true)
  if (first5zero && groups[5] === 0) return ipv4FromIpv6Groups(groups, false)
  const first4zero = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0
  if (first4zero && groups[4] === 0xffff && groups[5] === 0) return ipv4FromIpv6Groups(groups, false)
  return false
}

/**
 * True when hostname is loopback / private / link-local / metadata /
 * local-only. Empty input fails closed (blocked).
 */
export function isPrivateOrLocalFetchHost(hostnameRaw: string): boolean {
  const host = normalizeHostname(hostnameRaw)
  if (!host) return true
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      host.endsWith('.internal') || host === 'metadata.google.internal') return true
  if (isRebindHelperHost(host)) return true
  const embedded = ipv4FromConsecutiveLabels(host) ?? ipv4FromHyphenLabel(host)
  if (embedded && isPrivateIpv4(embedded[0], embedded[1])) return true
  if (host.includes(':')) return ipv6LiteralIsPrivate(host)
  if (IPV4_DOTTED_RE.test(host)) return privateOrLocalFromDottedQuad(host)
  return false
}
