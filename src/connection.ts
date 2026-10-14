import { sha256Hex } from './timing-safe.js'

export type RelayConnection = { id: string; label: string }

export function connectionLabel(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length > 80 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(raw)
    || Buffer.from(raw, 'utf8').toString('utf8') !== raw) return ''
  return raw.trim()
}

/** Client IDs identify software, not people. Each authorization gets its own
 * connection identity, preserved through refresh and never supplied by the model. */
export function relayConnection(id: string, label?: unknown): RelayConnection {
  const digest = sha256Hex(`aitomation-connection-v1:${id}`)
  return { id: digest, label: connectionLabel(label) || `Connection ${digest.slice(0, 8)}` }
}
