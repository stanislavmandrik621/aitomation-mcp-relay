/**
 * 1:1 pair slot. Desktop dials /pair/hello then long-polls /pair/next.
 * Tools never run here. Cloud POST /mcp waits for a desktop /pair/reply.
 */

import { randomUUID } from 'node:crypto'
import {
  MCP_RELAY_MCP_FORWARD_WAIT_MS,
  MCP_RELAY_PAIR_ID_MAX,
  MCP_RELAY_PAIR_NEXT_WAIT_MAX_MS,
  MCP_RELAY_PAIR_QUEUE_MAX,
} from './constants.js'
import { isModeAPublicToken } from './mode-a-key.js'
import { timingSafeEqualString } from './timing-safe.js'
import type { RelayConnection } from './connection.js'

export type PairPending = {
  requestId: string
  jsonrpc: string
  connection?: RelayConnection
}

export type PairMcpResult = {
  status: number
  json: unknown
}

type NextWaiter = {
  resolve: (item: PairPending | null) => void
  timer: ReturnType<typeof setTimeout>
  cleanup?: () => void
}

type McpWaiter = {
  resolve: (result: PairMcpResult) => void
  timer: ReturnType<typeof setTimeout>
}

export type PairStore = {
  paired: () => boolean
  unavailable: () => boolean
  deviceId: () => string | null
  keyId: () => string | null
  keyHash: () => string | null
  bindingVersion: () => number
  supportsConnectionIdentity: () => boolean
  isPending: (requestId: string) => boolean
  matchesDevice: (deviceId: string) => boolean
  hello: (deviceId: string, keyId: string, keyHash?: string | null, connectionIdentity?: boolean) => boolean
  markUnavailable: () => void
  next: (waitMs: number, signal?: AbortSignal) => Promise<PairPending | null>
  enqueueMcp: (jsonrpc: string, connection?: RelayConnection) => { requestId: string; wait: Promise<PairMcpResult>; cancel: () => void }
  /** Put a taken item back when the poll that claimed it cannot write. */
  requeue: (item: PairPending) => void
  reply: (requestId: string, status: number, json: unknown) => boolean
  resetForTest: () => void
}

function clampId(raw: string): string | null {
  const t = raw.trim()
  if (!t || t.length > MCP_RELAY_PAIR_ID_MAX) return null
  if (t.includes('\0') || /[\r\n]/.test(t)) return null
  return t
}

export function createPairStore(): PairStore {
  let paired = false
  let unavailable = false
  let deviceId: string | null = null
  let keyId: string | null = null
  let keyHash: string | null = null
  let bindingVersion = 0
  let connectionIdentity = false
  const queue: PairPending[] = []
  const nextWaiters: NextWaiter[] = []
  const mcpWaiters = new Map<string, McpWaiter>()

  function settleNext(item: PairPending | null): boolean {
    const w = nextWaiters.shift()
    if (!w) return false
    clearTimeout(w.timer)
    try { w.cleanup?.() } catch { /* ignore */ }
    w.resolve(item)
    return true
  }

  function removeQueued(requestId: string): void {
    for (let i = queue.length - 1; i >= 0; i--) {
      if (queue[i].requestId === requestId) queue.splice(i, 1)
    }
  }

  function abandonPending(): void {
    while (nextWaiters.length) settleNext(null)
    queue.length = 0
    for (const [id, w] of mcpWaiters) {
      clearTimeout(w.timer)
      w.resolve({ status: 503, json: { error: 'unavailable' } })
      mcpWaiters.delete(id)
    }
  }

  return {
    paired: () => paired,
    unavailable: () => unavailable,
    deviceId: () => deviceId,
    keyId: () => keyId,
    keyHash: () => keyHash,
    bindingVersion: () => bindingVersion,
    supportsConnectionIdentity: () => connectionIdentity,
    isPending: (requestId: string) => paired && !unavailable && mcpWaiters.has(requestId),
    matchesDevice(presented: string): boolean {
      const got = clampId(presented)
      if (!got || !deviceId) return false
      return timingSafeEqualString(got, deviceId)
    },
    hello(nextDevice: string, nextKey: string, nextHash?: string | null, supportsIdentity?: boolean): boolean {
      const d = clampId(nextDevice)
      const k = clampId(nextKey)
      if (!d || !k || isModeAPublicToken(k)) return false
      // A different key on the same device can name a different project.
      const hash = typeof nextHash === 'string' && /^[0-9a-f]{64}$/i.test(nextHash) ? nextHash.toLowerCase() : null
      const restamp = deviceId !== null && (deviceId !== d || keyId !== k || (hash !== null && hash !== keyHash))
      if (deviceId === null || restamp) bindingVersion += 1
      if (supportsIdentity !== undefined) connectionIdentity = supportsIdentity
      else if (deviceId === null || restamp) connectionIdentity = false
      deviceId = d
      keyId = k
      if (hash !== null) {
        keyHash = hash
      } else if (restamp) {
        keyHash = null
      }
      paired = true
      unavailable = false
      if (restamp) {
        abandonPending()
      }
      return true
    },
    markUnavailable(): void {
      unavailable = true
      abandonPending()
    },
    next(waitMs: number, signal?: AbortSignal): Promise<PairPending | null> {
      if (signal?.aborted || unavailable || !paired) return Promise.resolve(null)
      const first = queue.shift()
      if (first) return Promise.resolve(first)
      const cap = Number.isFinite(waitMs) ? Math.min(Math.max(0, Math.floor(waitMs)), MCP_RELAY_PAIR_NEXT_WAIT_MAX_MS) : 0
      if (cap <= 0) return Promise.resolve(null)
      return new Promise((resolve) => {
        let settled = false
        const finish = (item: PairPending | null): void => {
          if (settled) return
          settled = true
          if (signal) {
            try { signal.removeEventListener('abort', onAbort) } catch { /* ignore */ }
          }
          const idx = nextWaiters.findIndex((w) => w.resolve === resolve)
          if (idx !== -1) nextWaiters.splice(idx, 1)
          resolve(item)
        }
        const timer = setTimeout(() => {
          finish(null)
        }, cap)
        const onAbort = (): void => {
          clearTimeout(timer)
          finish(null)
        }
        if (signal) signal.addEventListener('abort', onAbort, { once: true })
        if (signal?.aborted) {
          onAbort()
          return
        }
        nextWaiters.push({
          resolve,
          timer,
          cleanup: () => {
            if (signal) {
              try { signal.removeEventListener('abort', onAbort) } catch { /* ignore */ }
            }
          },
        })
      })
    },
    enqueueMcp(jsonrpc: string, connection?: RelayConnection): { requestId: string; wait: Promise<PairMcpResult>; cancel: () => void } {
      if (!paired || unavailable || mcpWaiters.size >= MCP_RELAY_PAIR_QUEUE_MAX) {
        return {
          requestId: randomUUID(),
          wait: Promise.resolve({ status: 503, json: { error: 'unavailable' } }),
          cancel: () => {},
        }
      }
      const requestId = randomUUID()
      const pending: PairPending = { requestId, jsonrpc, ...(connection ? { connection: { ...connection } } : {}) }
      const wait = new Promise<PairMcpResult>((resolve) => {
        const timer = setTimeout(() => {
          mcpWaiters.delete(requestId)
          // Expired commands must never execute when the desktop reconnects.
          removeQueued(requestId)
          resolve({ status: 503, json: { error: 'unavailable' } })
        }, MCP_RELAY_MCP_FORWARD_WAIT_MS)
        mcpWaiters.set(requestId, { resolve, timer })
      })
      if (!settleNext(pending)) queue.push(pending)
      const cancel = (): void => {
        removeQueued(requestId)
        const waiter = mcpWaiters.get(requestId)
        if (!waiter) return
        mcpWaiters.delete(requestId)
        clearTimeout(waiter.timer)
        waiter.resolve({ status: 503, json: { error: 'unavailable' } })
      }
      return { requestId, wait, cancel }
    },
    requeue(item: PairPending): void {
      const requestId = typeof item?.requestId === 'string' ? item.requestId.trim() : ''
      const jsonrpc = typeof item?.jsonrpc === 'string' ? item.jsonrpc : ''
      if (!requestId || !jsonrpc) return
      if (!mcpWaiters.has(requestId)) return
      const pending = { requestId, jsonrpc, ...(item.connection ? { connection: { ...item.connection } } : {}) }
      if (!settleNext(pending)) queue.unshift(pending)
    },
    reply(requestId: string, status: number, json: unknown): boolean {
      const id = typeof requestId === 'string' ? requestId.trim() : ''
      if (!id) return false
      const w = mcpWaiters.get(id)
      if (!w) return false
      mcpWaiters.delete(id)
      removeQueued(id)
      clearTimeout(w.timer)
      const raw = Number.isFinite(status) ? Math.floor(status) : 200
      const code = raw >= 100 && raw <= 599 ? raw : 200
      w.resolve({ status: code, json })
      return true
    },
    resetForTest(): void {
      connectionIdentity = false
      bindingVersion += 1
      paired = false
      unavailable = false
      deviceId = null
      keyId = null
      keyHash = null
      queue.length = 0
      while (nextWaiters.length) {
        const w = nextWaiters.shift()
        if (w) {
          clearTimeout(w.timer)
          try { w.cleanup?.() } catch { /* ignore */ }
          w.resolve(null)
        }
      }
      for (const [id, w] of mcpWaiters) {
        clearTimeout(w.timer)
        w.resolve({ status: 503, json: { error: 'unavailable' } })
        mcpWaiters.delete(id)
      }
    },
  }
}
