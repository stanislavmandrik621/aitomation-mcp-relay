import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import type { IncomingMessage, ServerResponse } from 'node:http'
import test from 'node:test'
import { createRelayListener } from '../src/handler.js'
import { createInFlightSet } from '../src/in-flight.js'
import { MCP_RELAY_PROTOCOL_VERSIONS, relayProtocolHeaderAccepted } from '../src/protocol.js'

test('relay accepts only the implemented handshake protocol versions and omitted headers', () => {
  assert.deepEqual(MCP_RELAY_PROTOCOL_VERSIONS, ['2025-11-25', '2025-06-18'])
  for (const version of [undefined, ...MCP_RELAY_PROTOCOL_VERSIONS]) assert.equal(relayProtocolHeaderAccepted(version), true)
  for (const version of ['', '2026-07-28', '2025-03-26', '2024-11-05', ['2025-11-25'], null]) {
    assert.equal(relayProtocolHeaderAccepted(version), false)
  }
})

test('relay rejects modern HTTP probes before pairing and preserves legacy authentication', async () => {
  const inflight = createInFlightSet()
  const handler = createRelayListener({ closing: () => false, inflight, pairSecret: null })
  for (const version of ['2026-07-28', '', ['2025-11-25'], undefined, ...MCP_RELAY_PROTOCOL_VERSIONS]) {
    let status = 0, payload = ''
    const req = Object.assign(new EventEmitter(), {
      method: 'POST', url: '/mcp', rawHeaders: [], socket: { destroyed: false }, destroy() {},
      headers: { host: 'mcp.fixture.example', 'content-type': 'application/json',
        ...(version !== undefined ? { 'mcp-protocol-version': version } : {}) },
    }) as unknown as IncomingMessage
    const res = Object.assign(new EventEmitter(), {
      headersSent: false, writableEnded: false,
      writeHead(code: number) { status = code; this.headersSent = true },
      end(body?: string) { payload = body || ''; this.writableEnded = true },
    }) as unknown as ServerResponse
    handler(req, res)
    await inflight.drain()
    if (relayProtocolHeaderAccepted(version)) assert.equal(status, 401, 'legacy traffic still requires authorization')
    else {
      assert.equal(status, 400)
      assert.deepEqual(JSON.parse(payload), { error: 'unsupported_protocol_version' })
    }
  }
})
