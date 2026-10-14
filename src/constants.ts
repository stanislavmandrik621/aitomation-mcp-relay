/**
 * Listen and identity constants for the user-hosted connector process.
 * Never reuse Local API 8787, Team Space 8788, or banned 8789.
 */

export const MCP_RELAY_DEFAULT_PORT = 8790

/** Ports this process must never bind. Desktop listen + leftover + ephemeral. */
export const MCP_RELAY_BANNED_PORTS: readonly number[] = [
  0, 3737, 8765, 8787, 8788, 8789, 47600, 47601,
]

export const MCP_RELAY_DEFAULT_HOST = '127.0.0.1'

export const MCP_RELAY_HEALTH_PLAIN_BODY = 'AItomation MCP relay\n'

/** Desktop pair probe (T19) must send this so GET /health stays the historic line. */
export const MCP_RELAY_HEALTH_ACCEPT = 'text/plain'

export const MCP_RELAY_HEALTH_PROBE_MAX_BYTES = 4096

export const MCP_RELAY_HEALTH_ACCEPT_HEADER_MAX = 2048

export const MCP_RELAY_ACCEPT_ARRAY_MAX = 16

/** Historic Team Space probe line. Our bodies must never equal or match this. */
export const TEAM_SPACE_HEALTH_PLAIN_BODY = 'AItomation Team Space bridge\n'

export const MCP_RELAY_POST_BODY_MAX_BYTES = 256 * 1024

export const MCP_RELAY_OAUTH_BODY_MAX_BYTES = 16 * 1024

/** Authenticated desktop results include tool schemas and full source documents. */
export const MCP_RELAY_PAIR_REPLY_BODY_MAX_BYTES = 4 * 1024 * 1024

export const MCP_RELAY_CIMD_BODY_MAX_BYTES = 64 * 1024

export const MCP_RELAY_CIMD_MAX_HOPS = 5

export const MCP_RELAY_CIMD_TIMEOUT_MS = 8_000

export const MCP_RELAY_LOG_NAME_MAX = 80

export const MCP_RELAY_MAX_CONNECTIONS = 32

/** Process-wide in-flight / body-read ceiling (MCP-006 / MCP-014). One pair. */
export const MCP_RELAY_MAX_CONCURRENT = 16

export const MCP_RELAY_HEADERS_TIMEOUT_MS = 10_000

export const MCP_RELAY_REQUEST_TIMEOUT_MS = 60_000

export const MCP_RELAY_ACCESS_TTL_MS = 60 * 60 * 1000

export const MCP_RELAY_REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const MCP_RELAY_AUTH_CODE_TTL_MS = 10 * 60 * 1000

export const MCP_RELAY_PAIR_NEXT_WAIT_MAX_MS = 30_000

export const MCP_RELAY_MCP_FORWARD_WAIT_MS = 55_000

export const MCP_RELAY_PAIR_QUEUE_MAX = 16

export const MCP_RELAY_OAUTH_ROW_MAX = 512

export const MCP_RELAY_PAIR_ID_MAX = 128

export const MCP_RELAY_503_NOT_PAIRED = '{"error":"not_paired"}\n'

export const MCP_RELAY_503_UNAVAILABLE = '{"error":"unavailable"}\n'

export const MCP_RELAY_503_NO_PROJECT = '{"error":"no_project_open"}\n'

export const MCP_RELAY_GEMINI_REDIRECT = 'https://vertexaisearch.cloud.google.com/oauth-redirect'

export const MCP_RELAY_CLAUDE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback'

export const MCP_RELAY_CHATGPT_REDIRECT_PREFIX = 'https://chatgpt.com/connector/oauth/'

export const MCP_RELAY_CHATGPT_REDIRECT_LEGACY = 'https://chatgpt.com/connector_platform_oauth_redirect'

export const MCP_RELAY_SCOPE_OFFLINE = 'offline_access'

/** Hosts we will fetch a CIMD client_id URL from. Gemini confidential is not CIMD. */
export const MCP_RELAY_CIMD_HOSTS: readonly string[] = [
  'chatgpt.com',
  'www.chatgpt.com',
  'claude.ai',
  'www.claude.ai',
]
