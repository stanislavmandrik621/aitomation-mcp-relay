# Run the MCP relay on your own server

This process is an HTTPS edge. Other apps reach the address you paste.
The desktop app on your computer pairs to it later. Tools run on that
computer, not here.

We do not host this door. Place it on a machine you control.

## Tool discovery and execution

The desktop advertises a small initial catalog. Use `aitomation_search_app_tools`
to find an operation and `aitomation_load_app_tool` to read its complete input
schema. Execute it through `aitomation_call_app_tool` with `name` and
`arguments` matching that schema. For example:

```json
{"name":"compose_list_recipes","arguments":{"query":"business","apply_ready_only":true}}
```

This stable invocation tool supports clients that do not add callable functions
after receiving new schemas. Direct calls also work when a client refreshes its
tool catalog. Both paths enforce the same project, key permissions, input
validation, approvals and limits. Operations excluded by policy remain excluded.
If a call returns a pending handle, use `aitomation_get_app_tool_result` to wait
for completion before reporting success.

After upgrading the desktop, restart it and refresh the client's connection/tool
catalog. Existing conversations may retain the old catalog; start a new one if
`aitomation_call_app_tool` is missing. Reading a schema alone cannot install a
function into the client's runtime.

## One name, one project

Health probes hit `/` and `/health` on the origin. Extra path segments
are refused. Do not put three projects behind `/a/mcp`, `/b/mcp`, and
`/c/mcp` on one process.

Three Mode B projects means three processes (three containers, or three
service units, each with its own port or its own hostname). The Team
Space team server on the same machine is a fourth process.

## Public certificate

A public host needs a certificate from a public certificate authority.
Do not use a self-made certificate for ChatGPT, Claude, Grok, or Gemini
Enterprise. Usual spelling:

1. This process listens on loopback (`127.0.0.1:8790`) over HTTP.
2. Caddy or nginx on the same machine terminates HTTPS with a public
   certificate and forwards to that port.

If you pass `MCP_RELAY_TLS_CERT_FILE` and `MCP_RELAY_TLS_KEY_FILE`,
those files must already be a public-authority pair when the host is
on the public internet.

## Data dir

Set `MCP_RELAY_DATA_DIR` to an **absolute** path. The default is
relative to the working folder, so a service with no working folder
silently starts a new empty dir.

The pair secret stays in `MCP_RELAY_PAIR_SECRET` in the environment.
Do not put it on the command line.

## Docker

```bash
docker pull ghcr.io/stanislavmandrik621/aitomation-mcp-relay:latest
docker run -d --restart unless-stopped -p 8790:8790 \
  -e MCP_RELAY_HOST=0.0.0.0 \
  -e MCP_RELAY_PORT=8790 \
  -e MCP_RELAY_DATA_DIR=/data \
  -v mcp-relay-data:/data \
  ghcr.io/stanislavmandrik621/aitomation-mcp-relay:latest
```

Never `docker compose down -v` if you want to keep that volume.

A desktop `v*` tag does not publish this image. Pull again after a
relay release.

## Three projects on one machine

Copy `docker-compose.multi-project.example.yml`. Each service has its
own volume and its own published port (8790, 8791, 8792, ...). Give
each one its own public hostname on the reverse proxy. Do not share
a path prefix.

If you also run the Team Space team server on that machine, it stays
its own container and its own port (default 8788). Do not fold this
process into that one.

## systemd

```ini
[Unit]
Description=AItomation MCP relay
After=network.target

[Service]
Type=simple
User=mcprelay
WorkingDirectory=/var/lib/mcp-relay
Environment=MCP_RELAY_HOST=127.0.0.1
Environment=MCP_RELAY_PORT=8790
Environment=MCP_RELAY_DATA_DIR=/var/lib/mcp-relay/data
EnvironmentFile=-/etc/mcp-relay.env
ExecStart=/usr/bin/node /opt/mcp-relay/dist/server.js
Restart=on-failure
# Drain in-flight POSTs. Do not force-kill while a request is open.
TimeoutStopSec=infinity
KillSignal=SIGTERM
KillMode=process

[Install]
WantedBy=multi-user.target
```

`/etc/mcp-relay.env` may hold `MCP_RELAY_PAIR_SECRET=...`. Keep that
file owner-read-only.

`KillMode=process` is required so a stop does not kill a sibling Team
Space process in the same group.

## Reverse proxy (Caddy)

```
connector.example.com {
  reverse_proxy 127.0.0.1:8790
}
```

Caddy fetches a public certificate for that name. This process stays
on loopback HTTP.

## Other MCP clients

The relay is an inbound MCP server: it lets another MCP client call tools in
the paired AItomation project. Adding external MCP servers for AItomation to
call is a separate, outbound integration.

For an OAuth client beyond the built-in presets, add its exact callback URL
to the operator's environment file and restart the relay:

```dotenv
MCP_RELAY_OAUTH_REDIRECT_URIS='["https://my-client.example/oauth/callback","http://127.0.0.1:3456/oauth/callback"]'
MCP_RELAY_CIMD_HOSTS='["my-client.example"]'
```

Use the client's actual callback, including its port and path. DCR clients
only need the callback setting; CIMD clients also need their metadata host.
Every fetched metadata redirect must be an allowed callback. Metadata fetches
still reject local/private IPs at DNS resolution and recheck every redirect
hop. Entries are scoped to one relay process and do not change other relays.

Clients connect to the same `https://YOUR-HOST/mcp` endpoint. They can register
through `/register` using `token_endpoint_auth_method: "none"`, complete
authorization-code OAuth with S256 PKCE and owner approval, then use their
Bearer access token. Existing ChatGPT/Claude/Gemini callback presets continue
to work. Local clients may alternatively use the desktop's local HTTP endpoint
or enabled stdio helper. Header-capable remote clients can use `mcp-api-key`
with the paired project's connector key; local keys are deliberately refused
as Bearer tokens on the public relay.

Supported protocol versions are `2025-11-25` and `2025-06-18`. The remote
relay implements stateless Streamable HTTP POST/JSON responses; GET `/mcp`
returns 405. Legacy HTTP+SSE-only clients and proprietary transports are not
covered. Public-client DCR/CIMD is supported; arbitrary JWT-only confidential
clients are not. Compatibility should be tested in the target client, not
inferred from its product name.

The regression suite includes an unnamed custom client completing DCR,
consent, PKCE token exchange, forwarding, refresh rotation, and revocation on
project re-pair. Protocol reference:
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

## Health

```bash
curl -sS http://127.0.0.1:8790/health
# AItomation MCP relay

curl -sS -H 'Accept: text/html' http://127.0.0.1:8790/health | head
```

Missing Accept, `text/plain`, and any-type Accept stay the one-line
text. A browser Accept that prefers `text/html` gets the short card.

## Stop

SIGTERM waits for in-flight `POST /mcp` work, then exits. Do not
`kill -9` the process while a POST is open.

## OAuth and pairing

Unauthed `POST /mcp` is 401 with `WWW-Authenticate` pointing at the
protected-resource JSON. Serve JSON at:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-authorization-server/mcp`

Set `MCP_RELAY_PUBLIC_URL` to the https address people paste (origin,
or origin plus `/mcp`). `resource` in that JSON matches that address
including `/mcp`.

The desktop app pairs with `MCP_RELAY_PAIR_SECRET` on `/pair/hello`,
`/pair/next`, `/pair/reply`, and `/pair/unavailable`. After pair,
`POST /mcp` still needs OAuth (or the Claude request-header for the
paired project). Tools still run on the desktop.

Opening `/authorize` shows a consent page; it never issues a code on GET.
Review the client, return address, and paired key, then enter your
`MCP_RELAY_PAIR_SECRET` and choose **Approve connection**. Enter this
secret only on your own HTTPS relay page, never in the connecting client's
settings. Approval expires after five minutes and can be used once. The
relay checks the secret locally and never includes it in the callback.
Missing pairing configuration or an unavailable desktop blocks approval.

For several people, approve a separate OAuth connection for each person/app.
The approval page has an optional **Connection name** field, for example
`Alex · ChatGPT`. Chat on the executing desktop shows the name and a short
connection tag. The server creates the identity; client metadata cannot set
it. It survives token refresh, but authorization is currently kept in memory:
a relay restart requires approval again and creates a new tag. Shared static
headers or shared OAuth credentials identify one connection, not each person.

The desktop handles up to eight forwarded requests concurrently. Existing
per-key execution and per-minute limits still apply across all connections
and local calls. Chat IDs, request IDs, imported batches, result handles and
remote approvals are separated by authorization. Replies may finish out of
order. Update the desktop and relay together: older peers without connection
identity support are refused instead of merging callers' activity.

A Team Space invite does not authorize this endpoint or bind an OAuth grant
to a team member's role. Approved calls use the paired desktop account/key's
project permissions. Revoking a team invitation does not revoke that grant.
Use each member's own desktop/key where member-specific access is needed.
The project on the executing desktop stores these conversations; they are not
automatically distributed to every member's Chat. See
[connected conversations](../../../docs/mcp-connected-conversations.md#several-people-using-one-project).

Re-pairing with a different device or key clears pending commands and
revokes existing OAuth codes, access tokens, and refresh tokens. Connect
clients again after changing that binding. Reconnecting the same device
and key preserves grants. Commands that time out or are abandoned while
the desktop is unavailable are discarded rather than replayed later.

Gemini Enterprise: paste Authorization URL `/authorize`, Token URL
`/token`, scopes including `offline_access`, and the confidential
client id. The secret is written once to
`$MCP_RELAY_DATA_DIR/confidential-secret-once.txt`. Redirect they
register: `https://vertexaisearch.cloud.google.com/oauth-redirect`.

## What this process does not do

- No tool execution on this process.
- No listen on 47601, 47600, or port 0.
