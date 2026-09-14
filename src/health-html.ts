/**
 * Compact status card for browsers. Built once at load.
 * Own identity tokens only. Must fail the Team Space health identity check.
 */

import { MCP_RELAY_HEALTH_PLAIN_BODY, MCP_RELAY_HEALTH_PROBE_MAX_BYTES } from './constants.js'
import { isMcpRelayHealthBody, looksLikeTeamSpaceHealthBody } from './identity.js'

const HEALTH_PAGE_CSS =
  ':root{color-scheme:dark}' +
  '*,*::before,*::after{box-sizing:border-box}' +
  'html,body{height:100%;margin:0}' +
  'body{min-height:100%;display:flex;align-items:center;justify-content:center;' +
  'background:#0b100f;color:#e8eeec;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;' +
  '-webkit-font-smoothing:antialiased;padding:24px}' +
  'body::before{content:"";position:fixed;inset:0;pointer-events:none;' +
  'background:radial-gradient(ellipse 70% 50% at 50% 40%,rgba(16,185,129,.14),transparent 68%)}' +
  '.card{position:relative;width:100%;max-width:420px;background:#121816;border:1px solid #24302b;' +
  'border-radius:12px;padding:28px 24px}' +
  '.mark{width:36px;height:36px;border-radius:10px;margin:0 0 16px;' +
  'background:linear-gradient(135deg,#10b981,#059669)}' +
  '.brand{margin:0 0 16px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#8fa39a}' +
  'h1{margin:0 0 10px;font-size:1.25rem;font-weight:600;letter-spacing:-.01em}' +
  '.row{display:flex;align-items:center;gap:8px;margin:0 0 14px}' +
  '.dot{width:8px;height:8px;border-radius:50%;background:#4ade80}' +
  '.status{color:#4ade80;font-size:.875rem;font-weight:500}' +
  'p{margin:0;color:#8fa39a;font-size:.875rem}'

const HEALTH_PAGE_HTML =
  '<!DOCTYPE html>\n' +
  '<html lang="en">\n' +
  '<head>\n' +
  '<meta charset="utf-8"/>\n' +
  '<meta name="viewport" content="width=device-width,initial-scale=1"/>\n' +
  '<meta http-equiv="Cache-Control" content="no-store"/>\n' +
  '<meta name="robots" content="noindex"/>\n' +
  '<title>AI connector</title>\n' +
  `<style>${HEALTH_PAGE_CSS}</style>\n` +
  '</head>\n' +
  '<body>\n' +
  '<div class="card">\n' +
  '<div class="mark" aria-hidden="true"></div>\n' +
  '<p class="brand">AItomation</p>\n' +
  '<h1>This connector is running</h1>\n' +
  '<div class="row"><span class="dot" aria-hidden="true"></span><span class="status">Up</span></div>\n' +
  '<p>This AI connector is up. Other apps reach it on the address you set. Pair it from the app on your computer.</p>\n' +
  '</div>\n' +
  '</body>\n' +
  '</html>\n'

{
  if (MCP_RELAY_HEALTH_PLAIN_BODY !== 'AItomation MCP relay\n') {
    throw new Error('Historic probe body must stay byte-identical')
  }
  if (looksLikeTeamSpaceHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY)) {
    throw new Error('Historic probe body must not match Team Space identity')
  }
  if (!isMcpRelayHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY)) {
    throw new Error('Historic probe body must match this connector identity')
  }
  const bytes = new TextEncoder().encode(HEALTH_PAGE_HTML).byteLength
  if (bytes >= MCP_RELAY_HEALTH_PROBE_MAX_BYTES) {
    throw new Error('Health HTML exceeds the probe byte cap')
  }
  if (looksLikeTeamSpaceHealthBody(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML must not match Team Space identity')
  }
  if (!isMcpRelayHealthBody(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML must match this connector identity')
  }
  const lower = HEALTH_PAGE_HTML.toLowerCase()
  if (lower.includes('team space') || lower.includes('team space bridge')) {
    throw new Error('Health HTML must not use Team Space tokens')
  }
  if (
    /<script/i.test(HEALTH_PAGE_HTML)
    || /\shref=|\ssrc=/i.test(HEALTH_PAGE_HTML)
    || /url\s*\(|@import/i.test(HEALTH_PAGE_HTML)
    || /<(iframe|object|embed|link|base|form)\b/i.test(HEALTH_PAGE_HTML)
    || /<meta[^>]+http-equiv\s*=\s*['"]?refresh/i.test(HEALTH_PAGE_HTML)
    || /\son[a-z]+\s*=/i.test(HEALTH_PAGE_HTML)
  ) {
    throw new Error('Health HTML must not load scripts or outside files')
  }
  if (/[\u2014\u2013\u2026]/.test(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML user copy must use ASCII hyphen and ...')
  }
  if (/[\u2018\u2019\u201c\u201d]/.test(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML user copy must use straight quotes')
  }
  if (/\b(coolify|directus|v-aid)\b/i.test(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML must not name our hosting')
  }
  if (/\b(cursor|copilot|windsurf)\b/i.test(HEALTH_PAGE_HTML)) {
    throw new Error('Health HTML must not name other editors')
  }
}

export function healthPageHtml(): string {
  return HEALTH_PAGE_HTML
}
