/**
 * One process serves one project. Path prefixes on one name
 * (/project-a/mcp) are refused. Well-known, OAuth, and /pair
 * are exact extra routes on the same listen port (8790).
 * Fold repeated slashes and trailing slashes. Do not resolve ..
 * (a traversal stays prefix).
 */

export type RelayRoute =
  | 'root'
  | 'health'
  | 'mcp'
  | 'prefix'
  | 'other'
  | 'well_known_prm'
  | 'well_known_prm_mcp'
  | 'well_known_as'
  | 'well_known_as_mcp'
  | 'authorize'
  | 'token'
  | 'register'
  | 'pair_hello'
  | 'pair_next'
  | 'pair_reply'
  | 'pair_unavailable'

function decodePathname(pathname: string): string | null {
  try {
    const decoded = decodeURIComponent(pathname)
    if (decoded.includes('\0')) return null
    return decoded
  } catch {
    return null
  }
}

function foldRelayPath(path: string): string {
  if (!path) return '/'
  let folded = ''
  let slash = false
  for (const ch of path) {
    if (ch === '/') {
      if (!slash) folded += '/'
      slash = true
    } else {
      folded += ch
      slash = false
    }
  }
  while (folded.length > 1 && folded.endsWith('/')) {
    folded = folded.slice(0, -1)
  }
  return folded || '/'
}

export function classifyRelayPath(urlRaw: string | undefined): RelayRoute {
  const raw = typeof urlRaw === 'string' && urlRaw ? urlRaw : '/'
  let pathname = raw
  const q = raw.indexOf('?')
  if (q !== -1) pathname = raw.slice(0, q)
  const h = pathname.indexOf('#')
  if (h !== -1) pathname = pathname.slice(0, h)
  const decoded = decodePathname(pathname)
  if (decoded === null) return 'other'
  const exact = foldRelayPath(decoded)
  if (exact === '/') return 'root'
  if (exact === '/health') return 'health'
  if (exact === '/mcp') return 'mcp'
  if (exact === '/authorize') return 'authorize'
  if (exact === '/token') return 'token'
  if (exact === '/register') return 'register'
  if (exact === '/pair/hello') return 'pair_hello'
  if (exact === '/pair/next') return 'pair_next'
  if (exact === '/pair/reply') return 'pair_reply'
  if (exact === '/pair/unavailable') return 'pair_unavailable'
  if (exact === '/.well-known/oauth-protected-resource') return 'well_known_prm'
  if (exact === '/.well-known/oauth-protected-resource/mcp') return 'well_known_prm_mcp'
  if (exact === '/.well-known/oauth-authorization-server') return 'well_known_as'
  if (exact === '/.well-known/oauth-authorization-server/mcp') return 'well_known_as_mcp'
  const parts = exact.split('/').filter((p) => p.length > 0)
  if (parts.length >= 2) return 'prefix'
  return 'other'
}
