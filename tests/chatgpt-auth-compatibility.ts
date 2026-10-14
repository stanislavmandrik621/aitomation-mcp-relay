import assert from 'node:assert/strict'
import test from 'node:test'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseCimdDocument } from '../src/cimd.js'
import { handleAuthorize } from '../src/oauth.js'
import { createOAuthStore } from '../src/oauth-store.js'

const clientId = 'https://chatgpt.com/oauth/client.json'
const redirect = 'https://chatgpt.com/connector_platform_oauth_redirect'
const origin = 'https://connector.example'
const document = (extra: Record<string, unknown>) => JSON.stringify({
  client_id: clientId, redirect_uris: [redirect], ...extra,
})

test('ChatGPT plural CIMD capabilities permit public PKCE despite a JWT preference', () => {
  assert.equal(parseCimdDocument(clientId, document({
    token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
    token_endpoint_auth_method: 'private_key_jwt',
  }))?.tokenEndpointAuthMethod, 'none')
  assert.ok(parseCimdDocument(clientId, document({ token_endpoint_auth_method: 'none' })))
  assert.ok(parseCimdDocument(clientId, document({})))
})

test('CIMD never downgrades confidential-only or malformed capabilities', () => {
  for (const methods of [['private_key_jwt'], [], 'none', null, ['none', 123]]) {
    assert.equal(parseCimdDocument(clientId, document({
      token_endpoint_auth_methods_supported: methods, token_endpoint_auth_method: 'none',
    })), null)
  }
  for (const method of ['private_key_jwt', 'client_secret_basic', null, 42]) {
    assert.equal(parseCimdDocument(clientId, document({ token_endpoint_auth_method: method })), null)
  }
  assert.equal(parseCimdDocument(clientId, document({ redirect_uris: ['https://evil.example/callback'] })), null)
  assert.equal(parseCimdDocument(clientId, document({ client_id: 'https://claude.ai/different' })), null)
})

test('OAuth error callbacks include the advertised issuer and preserve state', async () => {
  for (const [patch, error] of [
    [{ response_type: 'token' }, 'unsupported_response_type'],
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ resource: 'https://other.example/mcp' }, 'invalid_target'],
    [{ client_id: 'unknown-client' }, 'invalid_client'],
  ] as const) {
    const query = new URLSearchParams({
      redirect_uri: redirect, client_id: 'unknown-client', state: 'original-state',
      response_type: 'code', code_challenge_method: 'S256', code_challenge: 'a'.repeat(43),
      resource: `${origin}/mcp`,
    })
    for (const [key, value] of Object.entries(patch)) query.set(key, value)
    let status = 0
    let location = ''
    const req = { method: 'GET', headers: {}, url: `/authorize?${query}` } as IncomingMessage
    const res = {
      writeHead(code: number, headers: Record<string, string>) { status = code; location = headers.location || '' },
      end() {},
    } as unknown as ServerResponse
    await handleAuthorize(req, res, { oauth: createOAuthStore({ dataDir: null }), publicUrl: origin })
    assert.equal(status, 302)
    const callback = new URL(location)
    assert.equal(callback.searchParams.get('error'), error)
    assert.equal(callback.searchParams.get('iss'), origin)
    assert.equal(callback.searchParams.get('state'), 'original-state')
  }
})
