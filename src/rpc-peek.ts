/**
 * Read JSON-RPC method + tool name for logs only.
 * Never execute. Never keep params.
 * Hang-up polarity for listen / in-flight (MCP-013): req.aborted or
 * socket destroy while a reply is owed. Body-complete IncomingMessage.destroyed
 * is not hang-up.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import { MCP_RELAY_LOG_NAME_MAX } from './constants.js'

export type RpcPeek = {
  method: string
  name: string
  notification: boolean
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

function shortToken(raw: unknown): string {
  if (typeof raw !== 'string') return '-'
  const t = raw.trim()
  if (!t) return '-'
  return t.length <= MCP_RELAY_LOG_NAME_MAX ? t : `${t.slice(0, MCP_RELAY_LOG_NAME_MAX)}...`
}

export function relayClientHungUp(
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  if (res.writableEnded === true) return false
  if (req.aborted === true) return true
  const sock = req.socket
  return Boolean(sock && sock.destroyed === true)
}

export function peekJsonRpc(body: string): RpcPeek {
  if (!body) return { method: '-', name: '-', notification: false }
  let parsed: unknown
  try {
    parsed = JSON.parse(body) as unknown
  } catch {
    return { method: '-', name: '-', notification: false }
  }
  const obj = asRecord(parsed)
  if (!obj) return { method: '-', name: '-', notification: false }
  const notification = !Object.prototype.hasOwnProperty.call(obj, 'id')
  const method = shortToken(obj.method)
  if (method === 'tools/call') {
    const params = asRecord(obj.params)
    const name = params ? shortToken(params.name) : '-'
    return { method, name, notification }
  }
  return { method, name: '-', notification }
}
