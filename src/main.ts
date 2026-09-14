import { ensureRelayDataDir, parseRelayConfig } from './config.js'
import { createInFlightSet } from './in-flight.js'
import { installDrainShutdown, listenRelay, type StartedRelayBox } from './listen.js'
import { logRelayInfo } from './log.js'
import { createOAuthStore } from './oauth-store.js'
import { createPairStore } from './pair-store.js'
import { authorizeUrl, safeAdvertisedOrigin, tokenUrl } from './public-url.js'

export async function main(): Promise<void> {
  const config = parseRelayConfig()
  ensureRelayDataDir(config.dataDir)
  const oauth = createOAuthStore({ dataDir: config.dataDir })
  const pair = createPairStore()
  let closing = false
  const inflight = createInFlightSet()
  const startedBox: StartedRelayBox = { current: null }
  installDrainShutdown(startedBox, () => {
    closing = true
  })
  startedBox.current = await listenRelay(config, {
    closing: () => closing,
    inflight,
    pairSecret: config.pairSecret,
    clientPolicy: config.clientPolicy,
    publicUrl: config.publicUrl,
    staticHeaderHash: config.staticHeaderHash,
    oauth,
    pair,
  }, startedBox)
  const advertised = config.publicUrl ? safeAdvertisedOrigin(config.publicUrl) : null
  if (advertised) {
    logRelayInfo(`authorization url ${authorizeUrl(advertised)}`)
    logRelayInfo(`token url ${tokenUrl(advertised)}`)
  } else {
    logRelayInfo('public url unset - well-known uses the request Host')
  }
  logRelayInfo(`scopes include offline_access`)
  logRelayInfo(`confidential client id ${oauth.confidential.clientId}`)
  if (oauth.confidential.created && oauth.confidential.secret) {
    logRelayInfo('confidential secret written once under the data dir')
  }
  if (config.pairSecret) {
    logRelayInfo('pair secret present in env')
  } else {
    logRelayInfo('no pair yet - authenticated POST /mcp returns 503')
  }
}

export function runMain(): void {
  void main().catch((err) => {
    const message = err instanceof Error ? err.message : String(err)
    logRelayInfo(`start failed: ${message}`)
    process.exit(1)
  })
}
