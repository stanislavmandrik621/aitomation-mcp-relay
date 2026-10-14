# Publish the MCP relay image

Official GHCR write is the **public** repo workflow
`.github/workflows/publish-image.yml` after
`scripts/sync-mcp-relay-public.sh` copies this tree.

- Image: `ghcr.io/stanislavmandrik621/aitomation-mcp-relay`
- Public repo: `stanislavmandrik621/aitomation-mcp-relay`
- Desktop `v*` does **not** publish this image.
- The private monorepo must not `docker push` this package (BRG-058).

Both image install stages `COPY package-lock.json` and run `npm ci`.

When a desktop cut includes this relay, About and What's new must name
this connector as its own image, not only the Team Space team server.
That About line lives in the desktop app and ships with that cut.
