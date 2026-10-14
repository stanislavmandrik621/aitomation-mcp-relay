/**
 * Desktop pair dial routes. Pairing secret in Authorization Bearer.
 * Nameless 503 bodies. No tool execution.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import {
  MCP_RELAY_OAUTH_BODY_MAX_BYTES,
  MCP_RELAY_PAIR_REPLY_BODY_MAX_BYTES,
  MCP_RELAY_503_NOT_PAIRED,
  MCP_RELAY_PAIR_NEXT_WAIT_MAX_MS,
} from './constants.js'
import { isModeAPublicToken } from './mode-a-key.js'
import type { PairStore } from './pair-store.js'
import { timingSafeEqualString } from './timing-safe.js'

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  pragma: 'no-cache',
} as const

export type PairRouteName = 'hello' | 'next' | 'reply' | 'unavailable'

function sendJson(res: ServerResponse, status: number, body: string): boolean {
  if (res.writableEnded === true || res.destroyed === true) return false
  try {
    const payload = Buffer.from(body, 'utf8')
    res.writeHead(status, {
      ...JSON_HEADERS,
      'content-length': payload.length,
      ...(status === 413 ? { connection: 'close' } : {}),
    })
    res.end(payload)
    return true
  } catch {
    return false
  }
}

function headerLine(req: IncomingMessage, name: string): string {
  const raw = req.headers[name]
  return typeof raw === 'string' ? raw : ''
}

function bearer(req: IncomingMessage): string | null {
  const m = /^Bearer\s+(.+)$/i.exec(headerLine(req, 'authorization'))
  if (!m) return null
  const t = m[1].trim()
  return t || null
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<{ ok: true; text: string } | { ok: false; oversized?: boolean }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    let total = 0
    let settled = false
    const finish = (result: { ok: true; text: string } | { ok: false; oversized?: boolean }): void => {
      if (settled) return
      settled = true
      req.removeListener('data', onData)
      req.removeListener('end', onEnd)
      req.removeListener('error', onError)
      req.removeListener('aborted', onHangUp)
      req.removeListener('close', onHangUp)
      resolve(result)
    }
    const onData = (c: Buffer | string): void => {
      const buf = typeof c === 'string' ? Buffer.from(c) : c
      total += buf.length
      if (total > maxBytes) {
        req.pause()
        finish({ ok: false, oversized: true })
        return
      }
      chunks.push(buf)
    }
    const onEnd = (): void => finish({ ok: true, text: Buffer.concat(chunks).toString('utf8') })
    const onError = (): void => finish({ ok: false })
    const onHangUp = (): void => {
      if (req.aborted === true) {
        finish({ ok: false })
        return
      }
      const sock = req.socket
      if (sock && sock.destroyed === true) finish({ ok: false })
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
    req.on('aborted', onHangUp)
    req.on('close', onHangUp)
  })
}

function refuseOversizedBody(req: IncomingMessage, res: ServerResponse): void {
  // Send a deterministic rejection before closing the upload socket. A reset
  // alone hides the cause from the desktop and strands the original MCP call.
  res.once('finish', () => req.destroy())
  if (!sendJson(res, 413, '{"error":"payload_too_large"}\n')) req.destroy()
}

/**
 * Client hung up while we still owe /pair/next. Body-complete close sets
 * IncomingMessage.destroyed on current Node; that is not a hang-up
 * (MCP-013 / TS-OUT-044). Fetch abort often skips req.aborted and
 * destroys the socket instead. Do not import the desktop helper.
 */
export function pairNextClientHungUp(
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  if (res.writableEnded === true) return false
  if (req.aborted === true) return true
  const sock = req.socket
  return Boolean(sock && sock.destroyed === true)
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

export async function handlePairRoute(
  req: IncomingMessage,
  res: ServerResponse,
  route: PairRouteName,
  pairSecret: string | null,
  pair: PairStore,
  onPaired?: () => void,
): Promise<void> {
  const method = (req.method || 'GET').toUpperCase()
  if (method !== 'POST') {
    sendJson(res, 405, '{"error":"method_not_allowed"}\n')
    return
  }
  if (!pairSecret) {
    sendJson(res, 503, MCP_RELAY_503_NOT_PAIRED)
    return
  }
  const presented = bearer(req)
  if (!presented || !timingSafeEqualString(presented, pairSecret)) {
    sendJson(res, 401, '{"error":"unauthorized"}\n')
    return
  }
  const maxBytes = route === 'reply' ? MCP_RELAY_PAIR_REPLY_BODY_MAX_BYTES : MCP_RELAY_OAUTH_BODY_MAX_BYTES
  const declared = req.headers['content-length']
  if (typeof declared === 'string' && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
    refuseOversizedBody(req, res)
    return
  }
  const body = await readBody(req, maxBytes)
  if (!body.ok) {
    if (body.oversized) {
      refuseOversizedBody(req, res)
      return
    }
    sendJson(res, 400, '{"error":"invalid"}\n')
    return
  }
  let rec: Record<string, unknown> = {}
  if (body.text.trim()) {
    try {
      const parsed = JSON.parse(body.text) as unknown
      rec = asRecord(parsed) ?? {}
    } catch {
      sendJson(res, 400, '{"error":"invalid"}\n')
      return
    }
  }
  if (route === 'hello') {
    const deviceId = typeof rec.deviceId === 'string' ? rec.deviceId : ''
    const keyId = typeof rec.keyId === 'string' ? rec.keyId : ''
    const keyHash = typeof rec.keyHash === 'string' ? rec.keyHash : null
    if (!deviceId.trim() || !keyId.trim() || isModeAPublicToken(keyId)) {
      sendJson(res, 400, '{"error":"invalid"}\n')
      return
    }
    if (!pair.hello(deviceId, keyId, keyHash, rec.connectionIdentity === 1)) {
      sendJson(res, 400, '{"error":"invalid"}\n')
      return
    }
    onPaired?.()
    sendJson(res, 200, '{"ok":true}\n')
    return
  }
  if (route === 'unavailable') {
    const deviceId = typeof rec.deviceId === 'string' ? rec.deviceId : ''
    if (pair.paired() && !pair.matchesDevice(deviceId)) {
      sendJson(res, 401, '{"error":"unauthorized"}\n')
      return
    }
    pair.markUnavailable()
    sendJson(res, 200, '{"ok":true}\n')
    return
  }
  if (route === 'next') {
    if (!pair.paired()) {
      sendJson(res, 503, MCP_RELAY_503_NOT_PAIRED)
      return
    }
    const deviceId = typeof rec.deviceId === 'string' ? rec.deviceId : ''
    if (!pair.matchesDevice(deviceId)) {
      sendJson(res, 401, '{"error":"unauthorized"}\n')
      return
    }
    const waitRaw = rec.waitMs
    const waitMs = typeof waitRaw === 'number' && Number.isFinite(waitRaw)
      ? Math.floor(waitRaw)
      : MCP_RELAY_PAIR_NEXT_WAIT_MAX_MS
    const ac = new AbortController()
    let settled = false
    const dropIfHungUp = (): void => {
      if (settled) return
      if (!pairNextClientHungUp(req, res)) return
      ac.abort()
    }
    try { req.on('aborted', dropIfHungUp) } catch { /* ignore */ }
    try { req.on('close', dropIfHungUp) } catch { /* ignore */ }
    dropIfHungUp()
    let item: Awaited<ReturnType<PairStore['next']>>
    try {
      item = await pair.next(waitMs, ac.signal)
    } finally {
      settled = true
      try { req.removeListener('close', dropIfHungUp) } catch { /* ignore */ }
      try { req.removeListener('aborted', dropIfHungUp) } catch { /* ignore */ }
    }
    if (res.writableEnded || res.destroyed || pairNextClientHungUp(req, res)) {
      if (item) pair.requeue(item)
      return
    }
    // The promise may already have resolved when a re-pair, timeout, or
    // client cancellation withdraws the command before this continuation.
    if (item?.connection && !pair.supportsConnectionIdentity()) {
      pair.reply(item.requestId, 503, { error: 'desktop_update_required' })
      item = null
    }
    if (!item || !pair.isPending(item.requestId)) {
      try {
        res.writeHead(204, { 'cache-control': 'no-store' })
        res.end()
      } catch { /* ignore */ }
      return
    }
    const wrote = sendJson(res, 200, `${JSON.stringify(item)}\n`)
    if (!wrote) pair.requeue(item)
    return
  }
  if (route === 'reply') {
    const requestId = typeof rec.requestId === 'string' ? rec.requestId : ''
    const status = typeof rec.status === 'number' ? rec.status : 200
    const replyDevice = typeof rec.deviceId === 'string' ? rec.deviceId : ''
    if (!requestId.trim()) {
      sendJson(res, 400, '{"error":"invalid"}\n')
      return
    }
    if (replyDevice.trim() && pair.paired() && !pair.matchesDevice(replyDevice)) {
      sendJson(res, 401, '{"error":"unauthorized"}\n')
      return
    }
    const ok = pair.reply(requestId, status, rec.json ?? null)
    if (!ok) {
      sendJson(res, 404, '{"error":"not_found"}\n')
      return
    }
    sendJson(res, 200, '{"ok":true}\n')
  }
}
