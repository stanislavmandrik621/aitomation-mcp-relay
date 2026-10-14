# AItomation MCP relay

User-hosted HTTPS edge for inbound AI connectors. Other apps call this
process on an address you own. The app on your computer pairs to it later
and runs the tools. This process never runs tools itself.

This repository is the **connector process only**. It is not the desktop
app and it is not the Team Space team server.

We do not host this door for you. Place it on a server you control. A
desktop app update does not update this process. A desktop `v*` tag does
not publish this image.

## One process, one project

One relay talks to one device and one project.

- Three projects that need a public HTTPS door need three processes.
- Path prefixes on one name (`/project-a/mcp`) are refused.
- The Team Space server on the same machine is a fourth process. Same
  machine is fine. Same process is not.

## Quick start (Docker)

```bash
docker pull ghcr.io/stanislavmandrik621/aitomation-mcp-relay:latest
docker run --rm -p 8790:8790 \
  -e MCP_RELAY_HOST=0.0.0.0 \
  -e MCP_RELAY_PORT=8790 \
  -e MCP_RELAY_DATA_DIR=/data \
  -v mcp-relay-data:/data \
  ghcr.io/stanislavmandrik621/aitomation-mcp-relay:latest
```

Default listen port is **8790**. Do not use 8787, 8788, or 8789.

`GET /` and `GET /health` answer 200. A browser shows a short status
page. `curl` and a later pair probe (`Accept: text/plain`) still get the
one-line text `AItomation MCP relay`.

`POST /mcp` without a sign-in token returns 401 plus a
`WWW-Authenticate` header that points at the well-known JSON. After
you pair the app and complete OAuth, that POST is forwarded to the
app. Tools never run on this process. Pairing uses `/pair/hello`,
`/pair/next`, `/pair/reply`, and `/pair/unavailable`.

Official images are multi-arch (`linux/amd64` and `linux/arm64`). Prefer
pinning a version tag in production.

## Public certificate on a public host

Cloud hosts that call this connector (ChatGPT, Claude, Grok, Gemini
Enterprise) need a certificate from a public certificate authority.
Do not use a self-made certificate on a public host. Put a reverse
proxy with a public certificate in front of this process, or pass
`MCP_RELAY_TLS_CERT_FILE` and `MCP_RELAY_TLS_KEY_FILE` that already
come from that authority.

## Environment

| Name | Default | Notes |
|---|---|---|
| `MCP_RELAY_HOST` | `127.0.0.1` | Docker sets `0.0.0.0`. |
| `MCP_RELAY_PORT` | `8790` | Reserved ports are refused. |
| `MCP_RELAY_DATA_DIR` | `./data` | Use an absolute path under a service manager. |
| `MCP_RELAY_PAIR_SECRET` | unset | Pair secret stays in env, never in argv. |
| `MCP_RELAY_PUBLIC_URL` | unset | Public https origin (optional `/mcp`). Used in well-known `resource`. |
| `MCP_RELAY_OAUTH_REDIRECT_URIS` | `[]` | JSON array of additional exact OAuth callback URLs for any compatible client. Public HTTPS or HTTP loopback only. |
| `MCP_RELAY_CIMD_HOSTS` | `[]` | JSON array of additional public DNS hosts from which client metadata may be fetched. No wildcards. |
| `MCP_RELAY_STATIC_HEADER_HASH` | unset | Optional SHA-256 hex of the Claude request-header key for the paired project. |
| `MCP_RELAY_TLS_CERT_FILE` | unset | Optional. Public CA for a public host. |
| `MCP_RELAY_TLS_KEY_FILE` | unset | Pair with the cert file. |

This process does not read Team Space environment names.

The MCP endpoint is provider-independent. ChatGPT, Claude, and Gemini have
built-in callback presets; other OAuth clients can use their own callbacks
through the environment settings above, without changing relay code. Clients
must support the implemented Streamable HTTP and OAuth public-client PKCE
flow, or the authenticated `mcp-api-key` header flow. This does not imply
support for every client's proprietary transport or authentication extensions.
See [client configuration](docs/SELF-HOST.md#other-mcp-clients).

OAuth stays on port **8790**. Authorization URL is `/authorize`. Token
URL is `/token`. Include `offline_access` in scopes. Gemini Enterprise
uses the confidential client id minted on first start (secret is written
once under the data dir) and redirect
`https://vertexaisearch.cloud.google.com/oauth-redirect`. Well-known
JSON is at `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp`. There is no HTML catch-all
on those paths.

## Alternate (clone + npm)

```bash
git clone https://github.com/stanislavmandrik621/aitomation-mcp-relay.git
cd aitomation-mcp-relay
npm ci
npm start
```

`npm start` is for development. For a real service, build once
(`npm run build`) and run `node dist/server.js` under a service manager.

Step-by-step service unit, three-project compose, and HTTPS proxy
snippets: [docs/SELF-HOST.md](docs/SELF-HOST.md).

## Stop

SIGTERM or SIGINT stops new work, waits for in-flight `POST /mcp`
forwards to finish, then exits. The process does not kill itself
mid-POST.

## Source of truth

Day-to-day edits live in the AItomation monorepo `packages/mcp-relay`
and are published here for customers. Official GHCR write is this
repo's `publish-image` workflow. The desktop cut does not publish
this image.

## License

MIT - see [LICENSE](LICENSE).
