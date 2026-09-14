/**
 * RFC 9728 PRM and RFC 8414 AS metadata. JSON only. No HTML catch-all.
 * Origin and /mcp path-insertion serve the same resource URL (including path).
 */

import { MCP_RELAY_SCOPE_OFFLINE } from './constants.js'
import {
  asMetadataUrl,
  authorizeUrl,
  canonicalResource,
  isOurHostingHost,
  registerUrl,
  safeAdvertisedOrigin,
  tokenUrl,
} from './public-url.js'

export type WellKnownKind = 'prm' | 'prm_mcp' | 'as' | 'as_mcp'

function advertisedOrigin(origin: string): string {
  const safe = safeAdvertisedOrigin(origin)
  try {
    const host = new URL(safe).hostname
    if (!host || isOurHostingHost(host)) return safeAdvertisedOrigin('')
  } catch {
    return safeAdvertisedOrigin('')
  }
  return safe
}

function urlNamesOurWeb(urlRaw: string): boolean {
  if (typeof urlRaw !== 'string' || !urlRaw.trim()) return false
  try {
    return isOurHostingHost(new URL(urlRaw).hostname)
  } catch {
    return isOurHostingHost(urlRaw)
  }
}

export function buildProtectedResourceMetadata(origin: string): Record<string, unknown> {
  const safe = advertisedOrigin(origin)
  const resource = canonicalResource(safe)
  if (!resource || !/^https:\/\//i.test(resource) || urlNamesOurWeb(resource)) {
    const fallback = canonicalResource(safeAdvertisedOrigin(''))
    return {
      resource: fallback,
      authorization_servers: [safeAdvertisedOrigin('').replace(/\/+$/, '')],
      bearer_methods_supported: ['header'],
      scopes_supported: [MCP_RELAY_SCOPE_OFFLINE],
      resource_documentation: safeAdvertisedOrigin('').replace(/\/+$/, ''),
    }
  }
  return {
    resource,
    authorization_servers: [safe.replace(/\/+$/, '')],
    bearer_methods_supported: ['header'],
    scopes_supported: [MCP_RELAY_SCOPE_OFFLINE],
    resource_documentation: safe.replace(/\/+$/, ''),
  }
}

export function buildAuthorizationServerMetadata(origin: string): Record<string, unknown> {
  let iss = advertisedOrigin(origin).replace(/\/+$/, '')
  if (!iss || !/^https:\/\//i.test(iss) || urlNamesOurWeb(iss)) {
    iss = safeAdvertisedOrigin('').replace(/\/+$/, '')
  }
  return {
    issuer: iss,
    authorization_endpoint: authorizeUrl(iss),
    token_endpoint: tokenUrl(iss),
    registration_endpoint: registerUrl(iss),
    scopes_supported: [MCP_RELAY_SCOPE_OFFLINE],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  }
}

export function wellKnownJson(kind: WellKnownKind, origin: string): Record<string, unknown> {
  if (kind === 'prm' || kind === 'prm_mcp') return buildProtectedResourceMetadata(origin)
  return buildAuthorizationServerMetadata(origin)
}

export { asMetadataUrl }
