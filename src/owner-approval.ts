import { createHash, randomBytes } from 'node:crypto'
import type { ServerResponse } from 'node:http'
import type { OAuthStore } from './oauth-store.js'
import type { PairStore } from './pair-store.js'
import { timingSafeEqualString } from './timing-safe.js'

const APPROVAL_TTL_MS = 5 * 60_000
const APPROVAL_MAX = 128
type Approval = { query: string; binding: string; expiresAt: number }
const approvals = new WeakMap<OAuthStore, Map<string, Approval>>()
const PAGE_STYLE = `:root{color-scheme:dark;font:16px/1.55 system-ui,sans-serif;background:#141416;color:#f3f3f5}*{box-sizing:border-box}body{margin:0;padding:40px 20px}main{max-width:600px;margin:5vh auto;padding:32px;background:#1d1d20;border:1px solid #343438;border-radius:16px}h1{font-size:26px;line-height:1.25;margin:8px 0 24px}p{color:#b6b6c0;overflow-wrap:anywhere}strong{color:#ededf2}label{display:block;color:#ededf2;font-weight:600}input[type=password],input[type=text]{display:block;width:100%;margin-top:8px;padding:12px;border:1px solid #595963;border-radius:8px;background:#141416;color:#fff;font:inherit}button{width:100%;border:0;border-radius:8px;padding:13px 18px;background:#7455e8;color:#fff;font:600 16px system-ui;cursor:pointer}button:hover{background:#8567f2}input:focus-visible,button:focus-visible{outline:3px solid #bcaaff;outline-offset:3px}form{border-top:1px solid #343438;margin-top:24px;padding-top:12px}@media(max-width:480px){body{padding:16px}main{margin:0;padding:24px}h1{font-size:23px}}`
const STYLE_HASH = createHash('sha256').update(PAGE_STYLE).digest('base64')

function binding(pair: PairStore): string {
  return JSON.stringify([pair.bindingVersion(), pair.deviceId(), pair.keyId()])
}

function rowsFor(store: OAuthStore): Map<string, Approval> {
  let rows = approvals.get(store)
  if (!rows) {
    rows = new Map()
    approvals.set(store, rows)
  }
  const now = Date.now()
  for (const [id, row] of rows) if (row.expiresAt <= now) rows.delete(id)
  return rows
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!)
}

/** Browser consent is separate from client registration and proof of PKCE possession. */
export function showOwnerApproval(res: ServerResponse, store: OAuthStore, pair: PairStore, query: Map<string, string>): void {
  const rows = rowsFor(store)
  if (rows.size >= APPROVAL_MAX) rows.delete(rows.keys().next().value!)
  const encoded = new URLSearchParams([...query]).toString()
  const nonce = randomBytes(32).toString('hex')
  // The caller validates this registered callback before rendering. Browsers
  // also apply form-action to the redirect after POST, not just /authorize.
  let callbackOrigin = ''
  try {
    const candidate = new URL(query.get('redirect_uri') || '').origin
    if (/^https?:\/\/(?:[a-z0-9.-]+|\[[a-f0-9:]+\])(?::\d+)?$/i.test(candidate)) callbackOrigin = candidate
  } catch { /* no external form destination for an invalid callback */ }
  rows.set(nonce, { query: encoded, binding: binding(pair), expiresAt: Date.now() + APPROVAL_TTL_MS })
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect to AItomation</title><style>${PAGE_STYLE}</style>
<body><main><h1>Allow this app to use AItomation?</h1>
<p>Client: <strong>${escapeHtml(query.get('client_id') || '')}</strong></p>
<p>Paired connector key: <strong>${escapeHtml(pair.keyId() || '')}</strong></p>
<p>This grants access to the tools available to this key in its paired project.</p>
<p>Return address: ${escapeHtml(query.get('redirect_uri') || '')}</p>
<form method="post" action="/authorize?${escapeHtml(encoded)}">
<input type="hidden" name="approval_nonce" value="${nonce}">
<p><label>Connection name (optional) <input type="text" name="connection_name" maxlength="80" placeholder="Alex · ChatGPT" autocomplete="off"></label></p>
<p>This label identifies the connection in AItomation Chat. It does not change the project permissions granted by this key.</p>
<p><label>Relay pairing secret <input type="password" name="owner_secret" required autocomplete="off" maxlength="512"></label></p>
<p>Enter the secret you configured on your relay to confirm you own this connection. It stays on this relay and is never sent to the client.</p>
<button type="submit">Approve connection</button></form><p>To decline, close this page.</p></main></body></html>`
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': Buffer.byteLength(html),
    'cache-control': 'no-store',
    // Preserve Origin on same-origin form POSTs; no-referrer makes browsers
    // send Origin: null, which the authorization endpoint correctly rejects.
    // External OAuth callbacks still receive no Referer.
    'referrer-policy': 'same-origin',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'content-security-policy': `default-src 'none'; style-src 'sha256-${STYLE_HASH}'; form-action 'self'${callbackOrigin ? ` ${callbackOrigin}` : ''}; base-uri 'none'; frame-ancestors 'none'`,
  })
  res.end(html)
}

export function takeOwnerApproval(store: OAuthStore, pair: PairStore, query: Map<string, string>, form: Map<string, string>, secret: string): boolean {
  return ownerApprovalFailure(store, pair, query, form, secret) === null
}

export function ownerApprovalFailure(store: OAuthStore, pair: PairStore, query: Map<string, string>, form: Map<string, string>, secret: string): 'stale_form' | 'pairing_changed' | 'request_changed' | 'incorrect_secret' | null {
  const nonce = form.get('approval_nonce') || ''
  const rows = rowsFor(store)
  const row = rows.get(nonce)
  rows.delete(nonce)
  if (!row) return 'stale_form'
  if (row.binding !== binding(pair)) return 'pairing_changed'
  if (row.query !== new URLSearchParams([...query]).toString()) return 'request_changed'
  const presented = form.get('owner_secret') || ''
  return presented.length <= 512 && timingSafeEqualString(presented, secret) ? null : 'incorrect_secret'
}
