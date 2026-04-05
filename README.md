# Relay

**OAuth-authenticated MCP proxy for connecting MCP clients to third-party services.**

An MCP Gateway acts as a middle layer between MCP clients (like Cursor, Claude Code, Windsurf, OpenCode, Gemini CLI) and third-party services. It provides:

- **Multi-User System** - Signup/login with API keys for each user
- **OAuth 2.1 Authentication** with PKCE for secure client authentication
- **Per-User Token Management** - Each user gets their own third-party tokens (GitHub, Slack, Linear, etc.)
- **Per-User MCP Endpoints** - Connect MCP clients using API key in URL path
- **Backend Aggregation** - Connect to MCP servers OR direct APIs with OAuth support
- **Dynamic Tool Discovery** - Tools auto-discovered from all connectors
- **Resources & Prompts** - MCP Resources and Prompts from connectors
- **Security Layer** - Rate limiting, input validation, audit logging

## Architecture

```
┌─────────────────┐                    ┌──────────────────┐                    ┌─────────────────┐
│   MCP Client    │                    │   MCP Gateway    │                    │    Backends     │
│ (Cursor/Claude) │                    │                  │                    │                 │
│                 │   OAuth + MCP      │                  │    MCP or API      │                 │
│  ┌───────────┐  │ ◄─────────────────►│  ┌────────────┐  │ ◄─────────────────►│  ┌───────────┐  │
│  │  MCP SDK  │  │                    │  │  FastMCP   │  │                    │  │  GitHub   │  │
│  └───────────┘  │                    │  └────────────┘  │                    │  │  Slack    │  │
│                 │                    │                  │                    │  │  OpenAI   │  │
│                 │                    │  ┌────────────┐  │                    │  │  Linear   │  │
│                 │                    │  │   OAuth    │  │                    │  └───────────┘  │
│                 │                    │  └────────────┘  │                    │                 │
│                 │                    │                  │                    │                 │
│                 │                    │  ┌────────────┐  │                    │                 │
│                 │                    │  │  Security  │  │                    │                 │
│                 │                    │  └────────────┘  │                    │                 │
└─────────────────┘                    └──────────────────┘                    └─────────────────┘
```

## Quick Start

### 1. Install

```bash
cd mcp-gateway
pip install -e .
```

### 2. Configure Environment

```bash
# Create .env file
cat > .env << EOF
# Server
MCP_GATEWAY_ENVIRONMENT=development
SERVER_PORT=8000

# OAuth (auto-generated in dev, set explicitly for production)
OAUTH_JWT_SECRET_KEY=your-secret-key-here

# Backend credentials (optional, for backend auth)
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxx
OPENAI_API_KEY=sk-xxx
SLACK_BOT_TOKEN=xoxb-xxx

# Security
SECURITY_RATE_LIMIT_REQUESTS_PER_MINUTE=60
SECURITY_AUDIT_ENABLED=true
EOF
```

### 3. Start the Server

```bash
cd relay
pip install -e .
python -m gateway.server
```

Server runs on http://localhost:8000

### 4. Create an Account

Visit http://localhost:8000/auth/register to create a user account. You'll automatically get an API key.

### 5. Connect Third-Party Services

1. Visit http://localhost:8000/connectors
2. Click "Connect" on any service (GitHub, Slack, Linear)
3. Complete OAuth flow to link your account

### 6. Connect MCP Clients

Each connector has a unique MCP endpoint using your API key:

```json
{
  "mcpServers": {
    "relay-github": {
      "url": "http://localhost:8000/user-mcp/{api_key}/github/mcp"
    }
  }
}
```

Copy the config from the connector detail page at `/connectors/{connector_name}`.

## REST API (Non-MCP Clients)

The gateway provides a complete REST API for CLIs, SDKs, and applications that don't use MCP.

### Quick Start (API Key)

```bash
# 1. Create an API key
curl -X POST http://localhost:8000/v1/api-keys \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My CLI", "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"]}'

# Response:
# {"api_key": "sk-abc123...", "client_id": "client_xyz", ...}

# 2. Discover available tools (no auth required)
curl http://localhost:8000/v1/tools

# 3. Call a tool
curl -X POST http://localhost:8000/v1/call \
  -H "Authorization: Bearer sk-abc123..." \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "github_search_repositories", "arguments": {"query": "mcp"}}'
```

### Public Discovery Endpoints

These endpoints require no authentication - useful for SDK code generation:

| Endpoint | Description |
|----------|-------------|
| `GET /v1/tools` | List all tools in OpenAI-compatible format |
| `GET /v1/tools/{name}` | Get JSON schema for a specific tool |
| `GET /v1/connectors` | List all third-party connectors |

### Authenticated Tool Execution

| Endpoint | Description |
|----------|-------------|
| `POST /v1/call` | Execute a single tool |
| `POST /v1/batch` | Execute up to 10 tools in one request |

**Note:** Batch calls are limited to 10 tools per request. Each tool in the batch is executed independently and results are returned in order.

### Authentication Options

1. **API Key** (Simplest for CLIs):
   ```bash
   curl -H "Authorization: Bearer sk-xxx" ...
   # or
   curl -H "ApiKey: sk-xxx" ...
   ```

2. **OAuth Bearer Token**:
   ```bash
   curl -H "Authorization: Bearer <access_token>" ...
   ```

### Connecting Third-Party Services (OAuth)

Users can connect their own GitHub, Slack, Linear, etc. accounts via OAuth:

```bash
# 1. Visit the web UI to connect services
open http://localhost:8000/connectors

# 2. Or use the OAuth endpoints directly
# GitHub
curl "http://localhost:8000/oauth/authorize/github?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback"

# After authorization, tokens are automatically stored
```

**Supported OAuth Connectors:**
- GitHub - Repositories, Issues, PRs, Code Search
- Slack - Messages, Channels, Users
- Linear - Issues, Projects, Cycles

**Token Storage:**
- Tokens stored per-user in SQLite database
- Each user has their own tokens (isolation)
- Fallback to "default" user for shared tokens

### Token Management API

```bash
# Store a personal token for a connector
curl -X POST http://localhost:8000/v1/tokens \
  -H "Authorization: Bearer sk-xxx" \
  -H "Content-Type: application/json" \
  -d '{"connector_name": "github", "token": "ghp_your_token"}'

# List your connected tokens
curl http://localhost:8000/v1/tokens \
  -H "Authorization: Bearer sk-xxx"

# Response:
# {"user_id": "api-key-my-cli", "connectors": ["github", "slack"]}
```

### Token Management Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `POST /v1/tokens` | POST | JWT | Store a personal token for a connector |
| `GET /v1/tokens` | GET | JWT | List your connected connectors |
| `DELETE /v1/tokens/{connector}` | DELETE | JWT | Remove a stored token |

**Token Resolution Order:**
1. User's stored token (via `POST /v1/tokens`)
2. Default user's shared token (stored under "default" user_id)
3. Environment variable shared credential (set at server startup)

### Example: Python SDK

```python
import httpx

class MCPGatewayClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    def list_tools(self):
        resp = httpx.get(f"{self.base_url}/v1/tools")
        return resp.json()["data"]
    
    def call(self, tool_name: str, arguments: dict):
        resp = httpx.post(
            f"{self.base_url}/v1/call",
            headers=self.headers,
            json={"tool_name": tool_name, "arguments": arguments}
        )
        return resp.json()

# Usage
client = MCPGatewayClient("http://localhost:8000", "sk-xxx")
tools = client.list_tools()
result = client.call("github_search_repositories", {"query": "mcp"})
```

### Example: Batch Execution

```bash
curl -X POST http://localhost:8000/v1/batch \
  -H "Authorization: Bearer sk-xxx" \
  -H "Content-Type: application/json" \
  -d '[
    {"tool_name": "github_search_repositories", "arguments": {"query": "mcp"}},
    {"tool_name": "slack_post_message", "arguments": {"channel": "C123", "text": "Hello"}}
  ]'
```

## Connecting MCP Clients

### Per-User MCP Endpoints

Each user has their own MCP endpoint with the API key in the URL path:

```
http://localhost:8000/user-mcp/{api_key}/{connector_name}/mcp
```

This allows MCP clients like Cursor, Claude Code, Gemini CLI, and OpenCode to connect without OAuth dance.

**Supported Clients:**

| Client | Configuration |
|--------|--------------|
| Claude Code | `{"url": "http://localhost:8000/user-mcp/{api_key}/github/mcp"}` |
| Cursor | `{"url": "http://localhost:8000/user-mcp/{api_key}/github/mcp"}` |
| Gemini CLI | `url: http://localhost:8000/user-mcp/{api_key}/github/mcp` |
| OpenCode | `{"url": "http://localhost:8000/user-mcp/{api_key}/github/mcp"}` |

The connector detail page (e.g., `/connectors/github`) provides ready-to-copy configurations for each client.

### MCP Resources

Each connector exposes MCP Resources for dynamic data:

| Connector | Resources |
|-----------|-----------|
| GitHub | User info, repository details, recent issues |
| Slack | Channel list, user list |
| Linear | Team info, workspace info |
| OpenAI | Available models |
| Anthropic | Available models |

### MCP Prompts

Each connector provides reusable prompts:

| Connector | Prompts |
|-----------|---------|
| GitHub | Create issue, review PR, summarize repo |
| Slack | Send daily standup, channel summary |
| Linear | Create sprint issue, weekly report |

### Legacy OAuth Authentication

For traditional OAuth flow, use the main MCP server at `/mcp` with Bearer token:

```json
{
  "mcpServers": {
    "gateway": {
      "url": "http://localhost:8001/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_ACCESS_TOKEN"
      }
    }
  }
}
```

## Security Features

### OAuth 2.1 with PKCE

The gateway implements the full OAuth 2.1 specification with PKCE for public clients:

1. **Client Registration** - Register your app with redirect URIs
2. **Authorization Code Flow** - User grants access via authorization code
3. **PKCE** - Code challenge prevents authorization code interception
4. **JWT Tokens** - Short-lived access tokens with refresh token rotation

### Rate Limiting

- **Per-minute limit**: 60 requests (configurable)
- **Per-hour limit**: 1000 requests (configurable)
- **Sliding window** algorithm for accurate limiting
- **Automatic blocking** with Retry-After headers

### Input Validation

- **SQL injection detection** - Blocks SQL-like patterns
- **Command injection detection** - Blocks shell metacharacters
- **Path traversal prevention** - Blocks `../` patterns
- **XSS prevention** - HTML sanitization
- **Size limits** - Max request size and string length

### Audit Logging

All security-relevant events are logged:

- OAuth flows (registration, authorization, token exchange)
- Rate limit violations
- Tool calls (with redacted sensitive fields)
- IP-based access control

Logs include:
- Timestamp
- Event type
- Client/user IDs
- IP address (hashed for privacy)
- Success/failure status

## Backend Configuration

### MCP Server Backends

```yaml
# In config/backends.yaml
backends:
  github:
    type: mcp
    name: GitHub
    description: GitHub API via MCP server
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-github"
    connector: github  # Maps to OAuth for per-user tokens
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_PAT}  # Fallback token
    tools:
      - create_issue
      - create_pull_request
      - search_repositories
    requires_auth: true
```

### API Backends

```yaml
backends:
  openai:
    type: api
    name: OpenAI
    base_url: https://api.openai.com/v1
    connector: openai  # Enables per-user OAuth tokens
    auth_type: bearer
    env_key: OPENAI_API_KEY  # Fallback token
    tools:
      - chat_completions
      - embeddings
    requires_auth: true
```

### How Per-User Tokens Work

1. **Backend Definition**: Each backend can specify a `connector` field
2. **Token Lookup**: Gateway checks TokenStore for user's token
3. **Fallback Chain**: 
   - First tries: `user_id` from JWT + `connector_name`
   - Then tries: `"default"` user + `connector_name`
   - Finally falls back to: env var (if configured)
4. **Token Injection**:
   - For API backends: token goes in `Authorization: Bearer` header
   - For MCP backends: token passed in tool arguments

This means users can connect their own GitHub/Slack/Linear accounts and make API calls with their own credentials!

## API Reference

### OAuth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/register` | POST | Register a new OAuth client |
| `/oauth/authorize` | GET | Authorization endpoint (consent page) |
| `/oauth/token` | POST | Token endpoint (exchange code for tokens) |
| `/oauth/revoke` | POST | Revoke an access or refresh token |

### MCP Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/mcp/backends` | GET | JWT | List all backends and their status |
| `/mcp/backends/{id}/connect` | POST | JWT | Connect to a specific backend |
| `/mcp/tools` | GET | JWT | List all available tools |
| `/mcp/call` | POST | JWT | Call a tool on a backend or connector |
| `/mcp/connectors` | GET | JWT | List all connectors and their status |
| `/mcp/connectors/{name}/health` | POST | JWT | Check health of a specific connector |

### MCP Tools (via FastMCP)

When connected via MCP, the gateway provides **dynamic tool discovery** — tools are automatically discovered from all registered connectors and MCP backends at runtime. No hardcoded tool lists needed.

**Gateway Management Tools:**

| Tool | Description |
|------|-------------|
| `gateway_list_backends` | List all backend services and their health status |
| `gateway_list_tools` | List all available tools across connectors and backends |
| `gateway_call_tool` | Call any discovered tool with proper authentication |
| `gateway_connect_backend` | Connect to a specific backend |
| `gateway_auth_status` | Check user's authentication and connected services |

**Dynamically Discovered Tools (39 total):**

| Connector | Tools | Examples |
|-----------|-------|----------|
| GitHub | 9 | `github_search_repositories`, `github_get_repository`, `github_list_issues`, `github_create_issue`, `github_list_pull_requests`, `github_create_pull_request`, `github_get_file_contents`, `github_create_or_update_file`, `github_search_code` |
| Slack | 13 | `slack_post_message`, `slack_update_message`, `slack_delete_message`, `slack_list_channels`, `slack_get_channel_info`, `slack_create_channel`, ... |
| Linear | 11 | `linear_list_issues`, `linear_create_issue`, `linear_list_projects`, `linear_get_issue`, ... |
| OpenAI | 4 | `openai_chat_completion`, `openai_embeddings`, `openai_create_image`, `openai_list_models` |
| Anthropic | 2 | `anthropic_chat_completion`, `anthropic_count_tokens` |

**MCP Discovery Pattern:**

The gateway uses a generic `gateway_call_tool` dispatcher that:
1. Discovers tools from all registered connectors and MCP backends at startup
2. Routes tool calls to the appropriate backend/connector automatically
3. Resolves per-user tokens from the TokenStore for authenticated calls
4. Falls back to shared credentials if no user token is found

This means new tools are automatically available when you add connectors or connect MCP backends — no code changes needed.

## Configuration Reference

### Environment Variables

All configuration can be set via environment variables with the `MCP_GATEWAY_` prefix:

```bash
# Server
MCP_GATEWAY_ENVIRONMENT=development|staging|production
MCP_GATEWAY_SERVER__HOST=0.0.0.0
MCP_GATEWAY_SERVER__PORT=8000
MCP_GATEWAY_DEBUG=true

# OAuth
MCP_GATEWAY_OAUTH__JWT_SECRET_KEY=your-secret-key
MCP_GATEWAY_OAUTH__ACCESS_TOKEN_EXPIRE_MINUTES=30
MCP_GATEWAY_OAUTH__REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
MCP_GATEWAY_SECURITY__RATE_LIMIT_REQUESTS_PER_MINUTE=60
MCP_GATEWAY_SECURITY__RATE_LIMIT_REQUESTS_PER_HOUR=1000
MCP_GATEWAY_SECURITY__AUDIT_ENABLED=true
MCP_GATEWAY_SECURITY__AUDIT_LOG_PATH=logs/audit.log

# Backend
MCP_GATEWAY_BACKEND__CONNECT_TIMEOUT_SECONDS=30
MCP_GATEWAY_BACKEND__TOOL_TIMEOUT_SECONDS=120
```

## Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -e .

EXPOSE 8000

CMD ["mcp-gateway", "serve", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t mcp-gateway .
docker run -p 8000:8000 \
  -e MCP_GATEWAY_OAUTH__JWT_SECRET_KEY=your-secret-key \
  -e MCP_GATEWAY_ENVIRONMENT=production \
  mcp-gateway
```

### Kubernetes

See `deploy/kubernetes/` for Helm charts and deployment manifests.

### Security Checklist

For production deployment:

- [ ] Set strong `OAUTH_JWT_SECRET_KEY` (use `openssl rand -hex 32`)
- [ ] Enable TLS/SSL (`SERVER__SSL_ENABLED=true`)
- [ ] Configure `IP_WHITELIST` if needed
- [ ] Set up audit log aggregation
- [ ] Configure rate limits appropriately
- [ ] Use Redis for distributed rate limiting
- [ ] Set up health checks and monitoring
- [ ] Rotate credentials regularly

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

```bash
black .
ruff check .
mypy .
```

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## Related Projects

- [MCP Specification](https://modelcontextprotocol.io) - The Model Context Protocol
- [Hermes Agent](https://github.com/nousresearch/hermes-agent) - The AI agent framework this is based on
- [FastMCP](https://github.com/anthropics/mcp) - The MCP SDK used

## Support

For issues and feature requests, please open a GitHub issue.
