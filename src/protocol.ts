/** Keep aligned with desktop electron/mcp-inbound/protocol.ts. */
export const MCP_RELAY_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18'] as const

export function relayProtocolHeaderAccepted(value: unknown): boolean {
  return value === undefined || (typeof value === 'string'
    && (MCP_RELAY_PROTOCOL_VERSIONS as readonly string[]).includes(value))
}
