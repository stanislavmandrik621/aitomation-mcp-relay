import { createHash, timingSafeEqual } from 'node:crypto'

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i
const DUMMY32 = Buffer.alloc(32)

export function sha256Hex(raw: string): string {
  return createHash('sha256').update(raw, 'utf8').digest('hex')
}

function dummyCompare(): void {
  timingSafeEqual(DUMMY32, DUMMY32)
}

export function timingSafeEqualString(left: string, right: string): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') {
    dummyCompare()
    return false
  }
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  if (a.length !== b.length) {
    const ha = createHash('sha256').update(a).digest()
    const hb = createHash('sha256').update(b).digest()
    timingSafeEqual(ha, hb)
    return false
  }
  if (a.length === 0) {
    dummyCompare()
    return true
  }
  return timingSafeEqual(a, b)
}

export function timingSafeEqualHex(left: string, right: string): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') {
    dummyCompare()
    return false
  }
  const leftOk = SHA256_HEX_RE.test(left)
  const rightOk = SHA256_HEX_RE.test(right)
  if (!leftOk || !rightOk) {
    const ha = createHash('sha256').update(left, 'utf8').digest()
    const hb = createHash('sha256').update(right, 'utf8').digest()
    timingSafeEqual(ha, hb)
    return false
  }
  const a = Buffer.from(left, 'hex')
  const b = Buffer.from(right, 'hex')
  if (a.length !== 32 || b.length !== 32) {
    dummyCompare()
    return false
  }
  return timingSafeEqual(a, b)
}

export function accessTokenStillLive(expiresAt: number, nowMs: number): boolean {
  if (!Number.isFinite(expiresAt) || expiresAt === 0) return false
  if (!Number.isFinite(nowMs)) return false
  return nowMs < expiresAt
}
