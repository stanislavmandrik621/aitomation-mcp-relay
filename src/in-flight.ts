/**
 * In-flight POST drain. Stop accepts no new work, waits for these
 * to finish, then exits. Do not force-kill this HTTPS process mid-POST.
 * Do not kill a process group that can include a Team Space process.
 *
 * begin() refuses at MCP_RELAY_MAX_CONCURRENT so a flood cannot
 * sit in readBody before any cap (MCP-006). Release in finally.
 */

import { MCP_RELAY_MAX_CONCURRENT } from './constants.js'

export type InFlightSet = {
  begin: () => (() => void) | null
  size: () => number
  drain: () => Promise<void>
}

export function createInFlightSet(): InFlightSet {
  const pending = new Set<() => void>()
  const waiters: Array<() => void> = []

  function flushWaiters(): void {
    if (pending.size !== 0) return
    while (waiters.length > 0) {
      const w = waiters.shift()
      if (w) w()
    }
  }

  return {
    begin(): (() => void) | null {
      // Refuse at the cap. Never FIFO-evict a live token (MCP-014 / MCP-005).
      if (pending.size >= MCP_RELAY_MAX_CONCURRENT) return null
      let done = false
      const token = (): void => {
        if (done) return
        done = true
        pending.delete(token)
        flushWaiters()
      }
      pending.add(token)
      return token
    },
    size(): number {
      return pending.size
    },
    drain(): Promise<void> {
      if (pending.size === 0) return Promise.resolve()
      return new Promise((resolve) => {
        waiters.push(resolve)
      })
    },
  }
}
