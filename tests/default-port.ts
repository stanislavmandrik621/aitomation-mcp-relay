/**
 * Default listen port is 8790. Never 8787 (Local API), 8788 (Team Space),
 * or 8789 (banned).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MCP_RELAY_BANNED_PORTS,
  MCP_RELAY_DEFAULT_PORT,
  MCP_RELAY_MAX_CONCURRENT,
  MCP_RELAY_MAX_CONNECTIONS,
} from '../src/constants.js'
import { parseRelayConfig } from '../src/config.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function fail(message: string): never {
  console.log('FAIL', message)
  process.exit(1)
}

try {
  assert.equal(MCP_RELAY_DEFAULT_PORT, 8790)
  assert.equal(MCP_RELAY_BANNED_PORTS.includes(8787), true)
  assert.equal(MCP_RELAY_BANNED_PORTS.includes(8788), true)
  assert.equal(MCP_RELAY_BANNED_PORTS.includes(8789), true)
  assert.equal(MCP_RELAY_BANNED_PORTS.includes(MCP_RELAY_DEFAULT_PORT), false)
  assert.equal(MCP_RELAY_MAX_CONNECTIONS, 32)
  assert.equal(MCP_RELAY_MAX_CONCURRENT, 16)
  assert.equal(MCP_RELAY_MAX_CONCURRENT < MCP_RELAY_MAX_CONNECTIONS, true)

  const cfg = parseRelayConfig({})
  assert.equal(cfg.port, 8790)

  for (const banned of [8787, 8788, 8789, 0, 47600, 47601]) {
    assert.throws(() => parseRelayConfig({ MCP_RELAY_PORT: String(banned) }))
  }

  const dockerfile = readFileSync(join(root, 'Dockerfile'), 'utf8')
  assert.match(dockerfile, /ENV MCP_RELAY_PORT=8790/)
  assert.match(dockerfile, /EXPOSE 8790/)
  assert.doesNotMatch(dockerfile, /ENV MCP_RELAY_PORT=878[789]/)
  assert.doesNotMatch(dockerfile, /EXPOSE 878[789]/)
  assert.doesNotMatch(dockerfile, /TEAMSPACE_/)

  const compose = readFileSync(join(root, 'docker-compose.yml'), 'utf8')
  assert.match(compose, /8790:8790/)
  assert.doesNotMatch(compose, /8787|8788|8789/)

  const readme = readFileSync(join(root, 'README.md'), 'utf8')
  assert.match(readme, /8790/)
  assert.match(readme, /Do not use 8787, 8788, or 8789/)

  console.log('ok default-port')
  console.log('SENTINEL_OK')
} catch (err) {
  fail(err instanceof Error ? err.message : String(err))
}
