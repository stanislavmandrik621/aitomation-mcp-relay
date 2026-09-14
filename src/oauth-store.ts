/**
 * In-memory OAuth rows plus one persisted Gemini confidential client.
 * expiresAt === 0 is expired, never forever.
 */

import { randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  MCP_RELAY_ACCESS_TTL_MS,
  MCP_RELAY_AUTH_CODE_TTL_MS,
  MCP_RELAY_GEMINI_REDIRECT,
  MCP_RELAY_OAUTH_ROW_MAX,
  MCP_RELAY_REFRESH_TTL_MS,
} from './constants.js'
import { isOurHostingHost } from './public-url.js'
import { accessTokenStillLive, sha256Hex } from './timing-safe.js'

const ID_RE = /^[A-Za-z0-9._-]{8,128}$/

export type OAuthClientKind = 'public' | 'confidential' | 'cimd'

export type OAuthClient = {
  clientId: string
  kind: OAuthClientKind
  secretHash: string | null
  redirectUris: string[]
}

export type AuthCode = {
  connectionId?: string
  connectionLabel?: string
  codeHash: string
  clientId: string
  redirectUri: string
  challenge: string
  resource: string
  expiresAt: number
  used: boolean
}

export type AccessRow = {
  connectionId?: string
  connectionLabel?: string
  tokenHash: string
  clientId: string
  resource: string
  expiresAt: number
}

export type RefreshRow = {
  connectionId?: string
  connectionLabel?: string
  tokenHash: string
  clientId: string
  resource: string
  expiresAt: number
  publicClient: boolean
}

export type ConfidentialShown = {
  clientId: string
  secret: string
  created: boolean
}

export type OAuthStore = {
  confidential: ConfidentialShown
  getClient: (clientId: string) => OAuthClient | null
  putPublicClient: (client: OAuthClient) => void
  rememberCimd: (client: OAuthClient) => void
  putCode: (row: AuthCode) => void
  takeCode: (code: string, nowMs: number) => AuthCode | null
  putAccess: (row: AccessRow) => void
  findAccess: (token: string, nowMs: number) => AccessRow | null
  putRefresh: (row: RefreshRow) => void
  takeRefresh: (token: string, nowMs: number) => RefreshRow | null
  /** A grant for one paired project must not follow a new device or key. */
  bindPair: (binding: string) => void
  insertExpiredAccessForTest: (token: string, expiresAt: number) => void
}

export type ConfidentialFile = {
  clientId: string
  secretHash: string
  createdAt: string
}

function mintId(prefix: string): string {
  return `${prefix}${randomBytes(16).toString('hex')}`
}

function validConfidentialFileRow(parsed: ConfidentialFile): boolean {
  return (
    typeof parsed.clientId === 'string'
    && ID_RE.test(parsed.clientId)
    && typeof parsed.secretHash === 'string'
    && /^[0-9a-f]{64}$/i.test(parsed.secretHash)
  )
}

/**
 * Exclusive-create the confidential-client.json file (`wx`: fail if it
 * already exists). If another process already won a first-boot mint race
 * on this same data dir, EEXIST fires and we must adopt what the winner
 * actually persisted - never silently overwrite it, and never report our
 * own (now-orphaned, never-written-to-disk) secret as real. Returns the
 * winner's clientId when we lost the race, or null when our row won.
 */
export function writeConfidentialJsonOrAdoptWinner(jsonPath: string, row: ConfidentialFile): string | null {
  try {
    writeFileSync(jsonPath, `${JSON.stringify(row, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    return null
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : ''
    if (code !== 'EEXIST') throw err
    const raw = readFileSync(jsonPath, 'utf8')
    const parsed = JSON.parse(raw) as ConfidentialFile
    if (validConfidentialFileRow(parsed)) return parsed.clientId
    throw new Error('confidential client file is unreadable')
  }
}

function loadOrMintConfidential(dataDir: string | null): ConfidentialShown {
  const secret = randomBytes(32).toString('hex')
  const clientId = mintId('host_')
  if (!dataDir) {
    return { clientId, secret, created: true }
  }
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const jsonPath = resolve(dataDir, 'confidential-client.json')
  const oncePath = resolve(dataDir, 'confidential-secret-once.txt')
  try {
    const raw = readFileSync(jsonPath, 'utf8')
    const parsed = JSON.parse(raw) as ConfidentialFile
    if (validConfidentialFileRow(parsed)) {
      return { clientId: parsed.clientId, secret: '', created: false }
    }
    throw new Error('confidential client file is unreadable')
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : ''
    if (code !== 'ENOENT') {
      throw new Error('confidential client file is unreadable')
    }
  }
  const row: ConfidentialFile = {
    clientId,
    secretHash: sha256Hex(secret),
    createdAt: new Date().toISOString(),
  }
  // Lost a first-boot mint race to another process on the same data dir:
  // our in-memory secret was never persisted, so it must never be shown.
  const winnerClientId = writeConfidentialJsonOrAdoptWinner(jsonPath, row)
  if (winnerClientId) {
    return { clientId: winnerClientId, secret: '', created: false }
  }
  try {
    writeFileSync(oncePath, `${secret}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : ''
    if (code !== 'EEXIST') throw err
  }
  return { clientId, secret, created: true }
}

function roomForNewRow<T extends { expiresAt: number }>(map: Map<string, T>, nowMs: number): boolean {
  if (map.size < MCP_RELAY_OAUTH_ROW_MAX) return true
  for (const [key, row] of map) {
    if (!accessTokenStillLive(row.expiresAt, nowMs)) map.delete(key)
    if (map.size < MCP_RELAY_OAUTH_ROW_MAX) return true
  }
  return false
}

function clientIdIsOurWeb(clientId: string): boolean {
  if (typeof clientId !== 'string' || !clientId.trim()) return false
  try {
    return isOurHostingHost(new URL(clientId).hostname)
  } catch {
    return isOurHostingHost(clientId)
  }
}

function readConfidentialHash(dataDir: string | null, shown: ConfidentialShown): string {
  if (shown.secret) return sha256Hex(shown.secret)
  if (!dataDir) return sha256Hex(shown.secret)
  const jsonPath = resolve(dataDir, 'confidential-client.json')
  try {
    const parsed = JSON.parse(readFileSync(jsonPath, 'utf8')) as ConfidentialFile
    if (typeof parsed.secretHash !== 'string' || !/^[0-9a-f]{64}$/i.test(parsed.secretHash)) {
      throw new Error('confidential client file is unreadable')
    }
    return parsed.secretHash
  } catch {
    throw new Error('confidential client file is unreadable')
  }
}

export function isMintedClientId(clientId: string): boolean {
  return ID_RE.test(clientId)
}

export function createOAuthStore(opts?: { dataDir?: string | null }): OAuthStore {
  const dataDir = opts && 'dataDir' in opts ? opts.dataDir ?? null : null
  const confidential = loadOrMintConfidential(dataDir)
  const secretHash = readConfidentialHash(dataDir, confidential)
  const clients = new Map<string, OAuthClient>()
  clients.set(confidential.clientId, {
    clientId: confidential.clientId,
    kind: 'confidential',
    secretHash,
    redirectUris: [MCP_RELAY_GEMINI_REDIRECT],
  })
  const codes = new Map<string, AuthCode>()
  const access = new Map<string, AccessRow>()
  const refresh = new Map<string, RefreshRow>()
  let pairBinding: string | null = null

  return {
    confidential,
    bindPair(binding: string): void {
      if (pairBinding !== null && pairBinding !== binding) {
        codes.clear()
        access.clear()
        refresh.clear()
      }
      pairBinding = binding
    },
    getClient(clientId: string): OAuthClient | null {
      const row = clients.get(clientId)
      return row ?? null
    },
    putPublicClient(client: OAuthClient): void {
      if (client.kind === 'confidential') return
      if (!isMintedClientId(client.clientId) && client.kind !== 'cimd') return
      if (client.clientId === confidential.clientId) return
      if (clientIdIsOurWeb(client.clientId)) return
      const existing = clients.get(client.clientId)
      if (existing && existing.kind === 'confidential') return
      if (!clients.has(client.clientId) && clients.size >= MCP_RELAY_OAUTH_ROW_MAX) return
      clients.set(client.clientId, client)
    },
    rememberCimd(client: OAuthClient): void {
      if (client.kind !== 'cimd') return
      if (client.clientId === confidential.clientId) return
      if (clientIdIsOurWeb(client.clientId)) return
      const existing = clients.get(client.clientId)
      if (existing && existing.kind === 'confidential') return
      if (!clients.has(client.clientId) && clients.size >= MCP_RELAY_OAUTH_ROW_MAX) return
      clients.set(client.clientId, client)
    },
    putCode(row: AuthCode): void {
      if (!codes.has(row.codeHash) && !roomForNewRow(codes, Date.now())) return
      codes.set(row.codeHash, row)
    },
    takeCode(code: string, nowMs: number): AuthCode | null {
      const hash = sha256Hex(code)
      const row = codes.get(hash)
      if (!row) return null
      if (row.used) return null
      if (!accessTokenStillLive(row.expiresAt, nowMs)) {
        codes.delete(hash)
        return null
      }
      row.used = true
      codes.delete(hash)
      return row
    },
    putAccess(row: AccessRow): void {
      if (!access.has(row.tokenHash) && !roomForNewRow(access, Date.now())) return
      access.set(row.tokenHash, row)
    },
    findAccess(token: string, nowMs: number): AccessRow | null {
      const row = access.get(sha256Hex(token))
      if (!row) return null
      if (!accessTokenStillLive(row.expiresAt, nowMs)) {
        access.delete(row.tokenHash)
        return null
      }
      return row
    },
    putRefresh(row: RefreshRow): void {
      if (!refresh.has(row.tokenHash) && !roomForNewRow(refresh, Date.now())) return
      refresh.set(row.tokenHash, row)
    },
    takeRefresh(token: string, nowMs: number): RefreshRow | null {
      const hash = sha256Hex(token)
      const row = refresh.get(hash)
      if (!row) return null
      refresh.delete(hash)
      if (!accessTokenStillLive(row.expiresAt, nowMs)) return null
      return row
    },
    insertExpiredAccessForTest(token: string, expiresAt: number): void {
      access.set(sha256Hex(token), {
        tokenHash: sha256Hex(token),
        clientId: 'test',
        resource: '',
        expiresAt,
      })
    },
  }
}

export function mintOpaqueToken(prefix: string): string {
  return `${prefix}${randomBytes(32).toString('hex')}`
}

export function authCodeTtl(nowMs: number): number {
  return nowMs + MCP_RELAY_AUTH_CODE_TTL_MS
}

export function accessTtl(nowMs: number): number {
  return nowMs + MCP_RELAY_ACCESS_TTL_MS
}

export function refreshTtl(nowMs: number): number {
  return nowMs + MCP_RELAY_REFRESH_TTL_MS
}

export { ID_RE }
