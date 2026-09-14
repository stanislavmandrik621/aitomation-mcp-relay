import { parseOAuthClientPolicy, type OAuthClientPolicy } from './client-policy.js'
import { mkdirSync, statSync, writeFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'
import {
  MCP_RELAY_BANNED_PORTS,
  MCP_RELAY_DEFAULT_HOST,
  MCP_RELAY_DEFAULT_PORT,
} from './constants.js'
import {
  isBindAnyHost,
  isLoopbackBindHost,
  isOurHostingHost,
  parsePublicBaseUrl,
} from './public-url.js'

export type RelayConfig = {
  clientPolicy?: OAuthClientPolicy
  host: string
  port: number
  dataDir: string
  pairSecret: string | null
  publicUrl: string | null
  staticHeaderHash: string | null
  tlsCertFile: string | null
  tlsKeyFile: string | null
}

type EnvBag = Record<string, string | undefined>

function envLine(env: EnvBag, name: string): string | undefined {
  const raw = env[name]
  if (typeof raw !== 'string') return undefined
  if (/[\0\r\n]/.test(raw)) {
    throw new Error(`${name} cannot contain a line break or a NUL`)
  }
  const t = raw.trim()
  return t ? t : undefined
}

function parsePort(raw: string | undefined): number {
  if (raw === undefined) return MCP_RELAY_DEFAULT_PORT
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error('MCP_RELAY_PORT must be a whole number')
  }
  const n = Number(raw)
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error('MCP_RELAY_PORT must be 1-65535')
  }
  if (MCP_RELAY_BANNED_PORTS.includes(n)) {
    throw new Error(
      `MCP_RELAY_PORT ${n} is reserved (Local API, Team Space, banned, or leftover). Use ${MCP_RELAY_DEFAULT_PORT}.`,
    )
  }
  return n
}

function parseHost(raw: string | undefined): string {
  if (raw === undefined) return MCP_RELAY_DEFAULT_HOST
  if (raw.length > 253) throw new Error('MCP_RELAY_HOST is too long')
  if (isOurHostingHost(raw)) {
    throw new Error('MCP_RELAY_HOST cannot be our web host')
  }
  return raw
}

function parseOptionalPath(env: EnvBag, name: string): string | null {
  const raw = envLine(env, name)
  if (!raw) return null
  const abs = isAbsolute(raw) ? raw : resolve(raw)
  if (abs.includes('\0')) throw new Error(`${name} is not a usable path`)
  return abs
}

function parsePairSecret(env: EnvBag): string | null {
  const raw = envLine(env, 'MCP_RELAY_PAIR_SECRET')
  if (!raw) return null
  if (raw.length < 16) {
    throw new Error('MCP_RELAY_PAIR_SECRET must be at least 16 characters')
  }
  if (raw.length > 2048) {
    throw new Error('MCP_RELAY_PAIR_SECRET is too long')
  }
  return raw
}

function parsePublicUrl(env: EnvBag): string | null {
  const raw = envLine(env, 'MCP_RELAY_PUBLIC_URL')
  if (!raw) return null
  const parsed = parsePublicBaseUrl(raw)
  if (!parsed) {
    throw new Error('MCP_RELAY_PUBLIC_URL must be an https origin (optional /mcp). Our web hosts are refused.')
  }
  return parsed
}

function parseStaticHeaderHash(env: EnvBag): string | null {
  const raw = envLine(env, 'MCP_RELAY_STATIC_HEADER_HASH')
  if (!raw) return null
  if (!/^[0-9a-f]{64}$/i.test(raw)) {
    throw new Error('MCP_RELAY_STATIC_HEADER_HASH must be 64 hex characters')
  }
  return raw.toLowerCase()
}

function requireTlsFile(abs: string, name: string): string {
  let st: ReturnType<typeof statSync>
  try {
    st = statSync(abs)
  } catch {
    throw new Error(`${name} is missing or unreadable`)
  }
  if (!st.isFile() || st.size < 1) {
    throw new Error(`${name} must be a non-empty file`)
  }
  return abs
}

export function parseRelayConfig(env: EnvBag = process.env): RelayConfig {
  const port = parsePort(envLine(env, 'MCP_RELAY_PORT'))
  const host = parseHost(envLine(env, 'MCP_RELAY_HOST'))
  const dataRaw = envLine(env, 'MCP_RELAY_DATA_DIR') ?? resolve('data')
  const dataDir = isAbsolute(dataRaw) ? dataRaw : resolve(dataRaw)
  const tlsCertFile = parseOptionalPath(env, 'MCP_RELAY_TLS_CERT_FILE')
  const tlsKeyFile = parseOptionalPath(env, 'MCP_RELAY_TLS_KEY_FILE')
  if ((tlsCertFile === null) !== (tlsKeyFile === null)) {
    throw new Error('Set both MCP_RELAY_TLS_CERT_FILE and MCP_RELAY_TLS_KEY_FILE, or neither')
  }
  if (tlsCertFile && tlsKeyFile) {
    requireTlsFile(tlsCertFile, 'MCP_RELAY_TLS_CERT_FILE')
    requireTlsFile(tlsKeyFile, 'MCP_RELAY_TLS_KEY_FILE')
  }
  if (!tlsCertFile && !isLoopbackBindHost(host) && !isBindAnyHost(host)) {
    throw new Error(
      'A named bind host needs MCP_RELAY_TLS_CERT_FILE and MCP_RELAY_TLS_KEY_FILE, or listen on loopback / 0.0.0.0 behind your own HTTPS proxy',
    )
  }
  return {
    host,
    port,
    clientPolicy: parseOAuthClientPolicy(env),
    dataDir,
    pairSecret: parsePairSecret(env),
    publicUrl: parsePublicUrl(env),
    staticHeaderHash: parseStaticHeaderHash(env),
    tlsCertFile,
    tlsKeyFile,
  }
}

export function ensureRelayDataDir(dataDir: string): void {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const marker = resolve(dataDir, 'mcp-relay.json')
  try {
    writeFileSync(
      marker,
      `${JSON.stringify({ kind: 'mcp-relay', createdAt: new Date().toISOString() }, null, 2)}\n`,
      { encoding: 'utf8', flag: 'wx', mode: 0o600 },
    )
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code: unknown }).code) : ''
    if (code !== 'EEXIST') throw err
  }
}
