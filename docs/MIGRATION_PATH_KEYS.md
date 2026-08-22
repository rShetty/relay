# Migrating from Path-Key MCP URLs to Header Authentication

## Background

The legacy per-user MCP endpoint placed a bearer-equivalent API key directly
in the URL path:

```
GET/POST /user-mcp/{api_key}/{connector}/mcp
```

Credentials in URL paths leak in places headers do not:

- **Server & proxy access logs** — every hop typically logs the full path.
- **Browser history** and `Referer` headers on any link followed afterwards.
- **Shared screenshots / pasted configs** — keys are visible at a glance.

As of this release that route is **disabled by default**. A replacement
endpoint authenticates via the `Authorization` header:

```
GET/POST /user-mcp/{connector}/mcp
Authorization: Bearer relay_<api_key>
```

Semantics are unchanged: the key is validated, `last_used_at` is updated,
and the request is bridged to the connector's mounted MCP server with an
injected `X-User-Id` header. Only DB-backed API keys (`relay_...`) are
accepted; OAuth bearer tokens belong on `/mcp/{connector}`.

## Client configuration

### Claude Code (`~/.claude.json` or project `.mcp.json`)

```json
{
  "mcpServers": {
    "relay-github": {
      "url": "https://your-gateway.example.com/user-mcp/github/mcp",
      "headers": {
        "Authorization": "Bearer relay_your-api-key"
      }
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "relay-github": {
      "url": "https://your-gateway.example.com/user-mcp/github/mcp",
      "headers": {
        "Authorization": "Bearer relay_your-api-key"
      }
    }
  }
}
```

### Gemini CLI (`~/.gemini/settings.json`)

```json
{
  "mcpServers": {
    "relay-github": {
      "url": "https://your-gateway.example.com/user-mcp/github/mcp",
      "headers": {
        "Authorization": "Bearer relay_your-api-key"
      }
    }
  }
}
```

(Older Gemini CLI versions without `headers` support can export the key as
`RELAY_MCP_AUTHORIZATION` and use a wrapper such as
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote).)

### OpenCode

```json
{
  "mcp": {
    "relay-github": {
      "type": "remote",
      "url": "https://your-gateway.example.com/user-mcp/github/mcp",
      "headers": {
        "Authorization": "Bearer relay_your-api-key"
      }
    }
  }
}
```

### curl / plain HTTP

```bash
curl -X POST https://your-gateway.example.com/user-mcp/github/mcp \
  -H "Authorization: Bearer relay_your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

The connector detail page in the web UI (`/connectors/{name}`) shows
ready-to-copy snippets for each client.

## Migration steps for gateway operators

1. **Deploy this version.** The new header route works immediately; the old
   path-key route starts returning **404** with a JSON error pointing clients
   at the new endpoint.
2. **Notify client owners** (or find them via access logs: requests to
   `/user-mcp/*/…/mcp` now log a deprecation warning when re-enabled).
3. Clients update their configs to the header form above — no new keys are
   needed; existing `relay_...` keys keep working.
4. Once no legacy traffic remains, nothing else to do: the route stays off.

## Emergency re-enable (temporary escape hatch)

If some client cannot be migrated immediately, operators may temporarily
re-enable the legacy route:

```bash
export RELAY_LEGACY_PATH_KEYS=1
```

While enabled, every legacy request logs a deprecation warning. This flag is
meant as a short-term bridge only — plan to turn it off.

## FAQ

**Do existing API keys stop working?**
No. Keys are unchanged; only *where* they are transmitted moves from the URL
path to the Authorization header.

**What happens if I call the legacy route while it's disabled?**
You get `404` with a JSON body explaining the new endpoint. Nothing is
processed, so leaked-in-log risk stops immediately.

**Why not accept both indefinitely?**
Path-based credentials cannot be fully protected by transport security alone;
every access log, proxy, and history file becomes a credential store.
