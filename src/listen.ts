import { readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import {
  MCP_RELAY_BANNED_PORTS,
  MCP_RELAY_HEADERS_TIMEOUT_MS,
  MCP_RELAY_MAX_CONNECTIONS,
  MCP_RELAY_REQUEST_TIMEOUT_MS,
} from './constants.js'
import type { RelayConfig } from './config.js'
import { createRelayListener, type RelayHandlerState } from './handler.js'
import type { InFlightSet } from './in-flight.js'
import { logRelayInfo } from './log.js'
import { isBindAnyHost, isLoopbackBindHost, isOurHostingHost } from './public-url.js'

export type StartedRelay = {
  server: http.Server | https.Server
  inflight: InFlightSet
}

export type StartedRelayBox = {
  current: StartedRelay | null
}

let _listenEpoch = 0

export function relayListenEpoch(): number {
  return _listenEpoch
}

export function bumpRelayListenEpoch(): number {
  _listenEpoch += 1
  return _listenEpoch
}

function closeRelayServer(server: http.Server | https.Server): void {
  try { server.close() } catch { /* already closing */ }
  try { server.closeAllConnections() } catch { /* Node older than closeAllConnections */ }
}

function applyServerLimits(server: http.Server | https.Server): void {
  server.maxConnections = MCP_RELAY_MAX_CONNECTIONS
  server.headersTimeout = MCP_RELAY_HEADERS_TIMEOUT_MS
  server.requestTimeout = MCP_RELAY_REQUEST_TIMEOUT_MS
}

export function createRelayServer(
  config: RelayConfig,
  state: RelayHandlerState,
): http.Server | https.Server {
  if (MCP_RELAY_BANNED_PORTS.includes(config.port)) {
    throw new Error(`Refusing listen on reserved port ${config.port}`)
  }
  if (isOurHostingHost(config.host)) {
    throw new Error('Refusing listen on our web host')
  }
  if ((config.tlsCertFile === null) !== (config.tlsKeyFile === null)) {
    throw new Error('Set both TLS cert and key, or neither')
  }
  const listener = createRelayListener(state)
  if (config.tlsCertFile && config.tlsKeyFile) {
    const cert = readFileSync(config.tlsCertFile)
    const key = readFileSync(config.tlsKeyFile)
    if (cert.byteLength < 1 || key.byteLength < 1) {
      throw new Error('TLS cert and key must be non-empty files')
    }
    const server = https.createServer({ cert, key, minVersion: 'TLSv1.2' }, listener)
    applyServerLimits(server)
    return server
  }
  if (!isLoopbackBindHost(config.host) && !isBindAnyHost(config.host)) {
    throw new Error(
      'A named bind host needs TLS cert and key, or listen on loopback / 0.0.0.0 behind your own HTTPS proxy',
    )
  }
  const server = http.createServer(listener)
  applyServerLimits(server)
  return server
}

export function listenRelay(
  config: RelayConfig,
  state: RelayHandlerState,
  box?: StartedRelayBox,
): Promise<StartedRelay> {
  if (MCP_RELAY_BANNED_PORTS.includes(config.port)) {
    return Promise.reject(new Error(`Refusing listen on reserved port ${config.port}`))
  }
  const epoch = _listenEpoch
  let server: http.Server | https.Server
  try {
    server = createRelayServer(config, state)
  } catch (err) {
    return Promise.reject(err instanceof Error ? err : new Error(String(err)))
  }
  if (_listenEpoch !== epoch) {
    closeRelayServer(server)
    return Promise.reject(new Error('listen cancelled'))
  }
  return new Promise((resolve, reject) => {
    let settled = false
    const settleErr = (err: Error): void => {
      if (settled) return
      settled = true
      server.off('listening', onListen)
      server.off('error', onErr)
      if (box && box.current && box.current.server === server) {
        box.current = null
      }
      closeRelayServer(server)
      reject(err)
    }
    const onErr = (err: Error): void => {
      settleErr(err)
    }
    const onListen = (): void => {
      server.off('error', onErr)
      if (settled) return
      const started: StartedRelay = {
        server,
        inflight: state.inflight,
      }
      if (box) box.current = started
      if (_listenEpoch !== epoch) {
        settleErr(new Error('listen cancelled'))
        return
      }
      settled = true
      const scheme = config.tlsCertFile ? 'https' : 'http'
      logRelayInfo(`listen ${scheme}://${config.host}:${config.port}`)
      logRelayInfo(`data dir ${config.dataDir}`)
      resolve(started)
    }
    server.once('error', onErr)
    server.once('listening', onListen)
    server.listen(config.port, config.host)
  })
}

/**
 * Drain in-flight POSTs, then close the listener, then exit.
 * Do not force-kill this process (or a process group) mid-POST.
 * Do not use a short disconnect grace then kill.
 */
export function installDrainShutdown(started: StartedRelayBox, markClosing: () => void): void {
  let stopping = false
  const stop = (signal: string): void => {
    if (stopping) {
      logRelayInfo(`${signal} ignored (already draining)`)
      return
    }
    stopping = true
    bumpRelayListenEpoch()
    markClosing()
    const live = started.current
    if (!live) {
      logRelayInfo(`${signal} cancelled bind then exit`)
      process.exit(0)
      return
    }
    logRelayInfo(`${signal} drain then exit`)
    live.server.close()
    void live.inflight.drain().then(() => {
      try { live.server.closeAllConnections() } catch { /* ignore */ }
      process.exit(0)
    })
  }
  process.on('SIGTERM', () => stop('SIGTERM'))
  process.on('SIGINT', () => stop('SIGINT'))
}
