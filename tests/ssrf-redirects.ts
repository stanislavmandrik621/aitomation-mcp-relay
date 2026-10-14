/**
 * E08: SSRF host (nip.io, localhost., ::7f00:1), closed redirects,
 * Accept cap-before-scan (BRG-057), health HTML identity + byte cap.
 * No top-level await.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { relayWantsHealthHtml } from '../src/accept.js'
import {
  MCP_RELAY_CLAUDE_REDIRECT,
  MCP_RELAY_GEMINI_REDIRECT,
  MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX,
  MCP_RELAY_HEALTH_PLAIN_BODY,
  MCP_RELAY_HEALTH_PROBE_MAX_BYTES,
} from '../src/constants.js'
import { healthPageHtml } from '../src/health-html.js'
import { isMcpRelayHealthBody, looksLikeTeamSpaceHealthBody } from '../src/identity.js'
import { isAllowedOAuthRedirect } from '../src/redirects.js'
import {
  isInvalidDottedIpv4,
  isPrivateOrLocalFetchHost,
  parseIpv4Octets,
} from '../src/ssrf-host.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
}

function sourceWithoutComments(raw: string): string {
  return raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
}

function src(name: string): string {
  return sourceWithoutComments(readFileSync(join(root, 'src', name), 'utf8'))
}

void (async () => {
  const drifted: string[] = []
  const note = (ok: boolean, row: string): void => {
    if (!ok) drifted.push(row)
  }

  try {
    const mustBlock = [
      'localhost.',
      'localhost..',
      '127.0.0.1.',
      '127.0.0.1.nip.io',
      '169.254.169.254.nip.io',
      '10.0.0.1.sslip.io',
      '127-0-0-1.nip.io',
      'app.10.0.0.1.xip.io',
      '::7f00:1',
      '[::7f00:1]',
      '::127.0.0.1',
      '0:0:0:0:0:0:7f00:1',
      '0:0:0:0:0:ffff:127.0.0.1',
      '0:0:0:0:0:ffff:7f00:1',
      '0:0:0:0:0:0:0:1',
      '::ffff:7f00:1',
      '::ffff:127.0.0.1',
      '::ffff:0:127.0.0.1',
      '::ffff:0:7f00:1',
      '0:0:0:0:ffff:0:127.0.0.1',
      '127.0.0.1',
      'localhost',
      'foo.localhost',
      '169.254.169.254',
    ]
    for (const h of mustBlock) {
      note(isPrivateOrLocalFetchHost(h) === true, `block ${h}`)
    }

    const mustAllow = [
      'example.com',
      'chatgpt.com',
      'claude.ai',
      '8.8.8.8',
      '2606:4700:4700::1111',
      '[2606:4700:4700::1111]',
      '::ffff:8.8.8.8',
      '::ffff:0:8.8.8.8',
      'fcc.gov',
      'fda.gov',
    ]
    for (const h of mustAllow) {
      note(isPrivateOrLocalFetchHost(h) === false, `allow ${h}`)
    }

    note(isInvalidDottedIpv4('127.999.0.1') === true, 'invalid 127.999.0.1')
    note(isInvalidDottedIpv4('127.999.0.1.') === true, 'invalid 127.999.0.1. trailing dot')
    note(isInvalidDottedIpv4('8.8.8.8') === false, 'valid 8.8.8.8 not invalid')
    note(JSON.stringify(parseIpv4Octets('127.0.0.1')) === '[127,0,0,1]', 'parse 127.0.0.1')

    note(isAllowedOAuthRedirect(MCP_RELAY_CLAUDE_REDIRECT) === true, 'claude official redirect')
    note(isAllowedOAuthRedirect(MCP_RELAY_GEMINI_REDIRECT) === true, 'gemini official redirect')
    note(isAllowedOAuthRedirect('https://chatgpt.com/connector/oauth/abc') === true, 'chatgpt prefix')
    note(isAllowedOAuthRedirect('http://127.0.0.1/callback') === true, 'claude loopback')
    note(isAllowedOAuthRedirect('http://localhost:1234/callback') === true, 'claude localhost port')
    note(isAllowedOAuthRedirect('https://v-aid.ai/api/mcp/auth_callback') === false, 'our-web v-aid')
    note(isAllowedOAuthRedirect('https://cms.v-aid.ai/connector/oauth/x') === false, 'our-web cms')
    note(isAllowedOAuthRedirect('https://edge.v-aid.ai/oauth-redirect') === false, 'our-web suffix')
    note(isAllowedOAuthRedirect('http://127.0.0.1.nip.io/callback') === false, 'redirect nip.io')
    note(isAllowedOAuthRedirect('http://localhost./callback') === false, 'redirect localhost.')
    note(isAllowedOAuthRedirect('http://[::7f00:1]/callback') === false, 'redirect ::7f00:1')
    note(isAllowedOAuthRedirect('http://127.0.0.1/callback?next=https://evil.example') === false, 'loopback query open redirect')
    note(isAllowedOAuthRedirect('https://evil.example/callback') === false, 'foreign host')

    note(relayWantsHealthHtml('text/html') === true, 'accept html')
    note(relayWantsHealthHtml('text/html\0') === false, 'accept NUL')
    note(relayWantsHealthHtml(`text/html${String.fromCharCode(0xd800)}`) === false, 'accept lone surrogate')
    note(relayWantsHealthHtml('中'.repeat(700)) === false, 'accept CJK over cap')
    note(relayWantsHealthHtml('a'.repeat(MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX + 1)) === false, 'accept over cap')
    note(relayWantsHealthHtml(['text/html', 'a'.repeat(MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX)]) === false, 'accept array over cap')

    const html = healthPageHtml()
    const htmlBytes = Buffer.byteLength(html, 'utf8')
    note(htmlBytes < MCP_RELAY_HEALTH_PROBE_MAX_BYTES, `html ${htmlBytes} under cap`)
    note(looksLikeTeamSpaceHealthBody(html) === false, 'html not Team Space identity')
    note(isMcpRelayHealthBody(html) === true, 'html is connector identity')
    note(isMcpRelayHealthBody(MCP_RELAY_HEALTH_PLAIN_BODY) === true, 'plain is connector identity')
    note(!/team space/i.test(html), 'html has no Team Space token')
    note(!/\bv-aid\b/i.test(html), 'html has no our-web token')

    const ssrfSrc = src('ssrf-host.ts')
    note(!/isLoopbackHost/.test(ssrfSrc), 'ssrf-host has no isLoopbackHost')
    const trailDot = /replace\(\/\\\.\+\$\/,\s*['']{2}\)/
    note(trailDot.test(ssrfSrc), 'ssrf-host strips trailing FQDN dots')
    const trailCommented = ssrfSrc.replace(trailDot, '// replace(/\\.+$/, \'\')')
    note(
      trailDot.test(sourceWithoutComments(trailCommented)) === false,
      'commented trailing-dot strip is not load-bearing',
    )
    const rebindGate = /if \(isRebindHelperHost\(host\)\) return true/
    note(rebindGate.test(ssrfSrc), 'ssrf-host refuses nip.io helpers')
    const rebindCommented = ssrfSrc.replace(rebindGate, '// if (isRebindHelperHost(host)) return true')
    note(
      rebindGate.test(sourceWithoutComments(rebindCommented)) === false,
      'commented rebind helper gate is not load-bearing',
    )
    note(ssrfSrc.includes('7f00') || /expandIpv6Groups/.test(ssrfSrc), 'ssrf-host expands IPv6-compatible')

    const acceptSrc = src('accept.ts')
    const capBefore = /if \(acceptHeader\.length > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX\) return null/
    note(capBefore.test(acceptSrc), 'accept caps length before scan')
    const capIdx = acceptSrc.search(capBefore)
    const scanIdx = acceptSrc.indexOf('acceptHeaderLooksSafe(acceptHeader)')
    note(capIdx >= 0 && scanIdx > capIdx, 'accept cap is before looksSafe')
    const capCommented = acceptSrc.replace(capBefore, '// if (acceptHeader.length > MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX) return null')
    note(
      capBefore.test(sourceWithoutComments(capCommented)) === false,
      'commented accept cap-before-scan is not load-bearing',
    )

    const redirSrc = src('redirects.ts')
    const ourHostGate = /if \(isOurHostingHost\(u\.hostname\)\) return false/
    note(ourHostGate.test(redirSrc), 'redirects refuse our-web host')
    const ourHostCommented = redirSrc.replace(ourHostGate, '// if (isOurHostingHost(u.hostname)) return false')
    note(
      ourHostGate.test(sourceWithoutComments(ourHostCommented)) === false,
      'commented our-web redirect gate is not load-bearing',
    )
    const searchGate = /if \(u\.hash \|\| u\.search\) return false/
    note(searchGate.test(redirSrc), 'loopback callback refuses query')
    const searchCommented = redirSrc.replace(searchGate, '// if (u.hash || u.search) return false')
    note(
      searchGate.test(sourceWithoutComments(searchCommented)) === false,
      'commented loopback query refuse is not load-bearing',
    )

    const htmlSrc = src('health-html.ts')
    note(htmlSrc.includes('bytes >= MCP_RELAY_HEALTH_PROBE_MAX_BYTES'), 'health HTML boot-checks byte cap')
    note(htmlSrc.includes('looksLikeTeamSpaceHealthBody(HEALTH_PAGE_HTML)'), 'health HTML boot-checks Team Space identity')
    note(/coolify\|directus\|v-aid/.test(htmlSrc), 'health HTML boot-checks our hosting names')
    const vAidGate = /\\b\(coolify\|directus\|v-aid\)\\b/
    note(vAidGate.test(htmlSrc), 'health HTML v-aid token is in the refuse regex')
    const vAidCommented = htmlSrc.replace(/coolify\|directus\|v-aid/, '// coolify|directus|v-aid')
    note(
      vAidGate.test(sourceWithoutComments(vAidCommented)) === false,
      'commented health HTML v-aid refuse is not load-bearing',
    )

    if (drifted.length > 0) {
      fail(drifted.join('; '))
    }
    console.log('ok ssrf-redirects')
    console.log('SENTINEL_OK')
  } catch (err) {
    fail(err instanceof Error ? err.stack || err.message : String(err))
  }
})()
