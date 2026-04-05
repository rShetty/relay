# Relay Architecture

## Overview

**Relay** is an OAuth 2.1-authenticated MCP proxy that enables AI coding clients (OpenCode, Claude Code, Cursor, Gemini CLI) to access third-party services (GitHub, Slack, Linear, OpenAI, Anthropic) through a unified interface.

**Key Features:**
- Multi-user system with signup/login and API keys
- Per-user MCP endpoints (`/user-mcp/{api_key}/{connector}/mcp`) for direct client connections
- Per-user token isolation - each user's third-party tokens are stored separately
- Dynamic tool discovery from all connectors at startup
- MCP Resources and Prompts from each connector
- Web UI for account management and connector configuration

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    RUN LAYER                                       │
│                                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐  │
│  │ User System   │  │ Token Store   │  │ Connectors    │  │ MCP Servers       │  │
│  │               │  │               │  │               │  │                   │  │
│  │ • Signup/Login│  │ • Per-user    │  │ • GitHub      │  │ • /mcp/github     │  │
│  │ • API Keys   │  │   tokens      │  │ • Slack       │  │ • /mcp/slack     │  │
│  │ • Session    │  │ • Third-party │  │ • Linear      │  │ • /mcp/linear    │  │
│  │              │  │   tokens      │  │ • OpenAI      │  │ • /mcp/openai    │  │
│  └───────────────┘  └───────────────┘  │ • Anthropic  │  │ • /mcp/anthropic │  │
│                                          └───────────────┘  └───────────────────┘  │
│                                                                                     │
│                              ┌─────────────────────────────────┐                   │
│                              │      FastAPI Server (Port 8000) │                   │
│                              │      • Web UI                   │                   │
│                              │      • REST API                 │                   │
│                              │      • Per-user MCP:            │                   │
│                              │        /user-mcp/{key}/{conn}/mcp│                   │
│                              └─────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                    │                                                  │
                    │ Per-User MCP (API key in URL)                  │ 3rd Party Tokens
                    ▼                                                  ▼
┌─────────────────────────────┐              ┌─────────────────────────────────────┐
│      MCP Client             │              │         Third-Party APIs           │
│                             │              │                                     │
│  • OpenCode ───────────────┼──────────────┼──► GitHub API                       │
│  • Claude Code              │  /user-mcp/  │  • Slack API                       │
│  • Cursor                   │  {api_key}/  │  • Linear API                      │
│  • Gemini CLI              │  {conn}/mcp  │  • OpenAI API                      │
│                             │              │  • Anthropic API                    │
└─────────────────────────────┘              └─────────────────────────────────────┘
```

## Core Concepts

### 1. Run Layer (Gateway)

The "Run Layer" is the gateway itself - a FastAPI server that:
- Handles OAuth 2.1 authentication with clients
- Manages third-party OAuth flows (GitHub, Slack, etc.)
- Stores per-user tokens for third-party services
- Proxies tool calls to connectors and MCP backends

### 2. Connectors

Connectors are integrations with third-party services. Each connector:
- Provides a set of tools (functions) for that service
- Provides MCP Resources for dynamic data
- Provides MCP Prompts for reusable workflows
- Handles API authentication (uses stored user tokens)
- Implements the service-specific API logic

**Current Connectors:**
- `github` - Repositories, Issues, PRs, Code Search
- `slack` - Messages, Channels, Users, Reactions
- `linear` - Issues, Projects, Cycles, Teams
- `openai` - Chat completions, Embeddings, Images
- `anthropic` - Chat completions, Token counting

### 3. Per-User MCP Endpoints

Each user gets a unique MCP endpoint that includes their API key in the URL path:

```
/user-mcp/{api_key}/{connector_name}/mcp
```

This endpoint:
1. Validates the API key from the URL
2. Looks up the user ID associated with the API key
3. Forwards the request to the mounted MCP server at `/mcp/{connector}`
4. Passes the user ID via `X-User-Id` header
5. The MCP server uses the header to look up the user's token for that connector

**Benefits:**
- No OAuth dance required for MCP clients
- Each user has isolated tokens
- Easy to share/disable access (just revoke API key)
- Works with any MCP client (Cursor, Claude Code, Gemini CLI, OpenCode)

### 3. MCP Backends

MCP Backends are external MCP servers that the gateway can proxy to:
- Started dynamically based on configuration
- Tools exposed through the gateway
- **Can use OAuth tokens** via `connector` mapping (new feature!)

### 4. Backend Connector Mapping

Each backend can specify a `connector` field that maps to an OAuth provider. This enables **per-user token authentication** for MCP backends:

```python
# In config/settings.py
BACKEND_DEFINITIONS = {
    "github": {
        "type": "mcp",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "connector": "github",  # Maps to OAuth connector
        ...
    },
    "openai": {
        "type": "api",
        "base_url": "https://api.openai.com/v1",
        "connector": "openai",
        ...
    }
}
```

When a tool is called:
1. Gateway checks if backend has a `connector` mapping
2. Looks up per-user token from TokenStore
3. Passes token to the backend (for API: in headers; for MCP: in arguments)

### 5. Token Store

The token store manages two types of tokens:

| Token Type | Purpose | Storage Key |
|------------|---------|-------------|
| JWT Access Token | Authenticates MCP client to gateway | N/A (issued to client) |
| Third-Party Token | Authenticates gateway to GitHub/Slack/etc | `user_id` + `connector_name` |

### Per-User MCP Flow (API Key)

For MCP clients that don't want OAuth dance, use per-user MCP endpoints:

```
/user-mcp/{api_key}/{connector}/mcp
```

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Cursor   │     │   Gateway   │     │    GitHub   │     │  Token Store│
│   (MCP)    │     │             │     │    API      │     │             │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                  │                    │                  │
       │ 1. MCP init     │                    │                  │
       │ (URL with key)  │                    │                  │
       │────────────────>│                    │                  │
       │                  │                    │                  │
       │ 2. Validate key │                    │                  │
       │    get_api_key  │                    │                  │
       │────────────────>│                    │                  │
       │                  │                    │                  │
       │ 3. Return user_id                   │                  │
       │<───────────────│                    │                  │
       │                  │                    │                  │
       │ 4. Forward to   │                    │                  │
       │    /mcp/{conn} │                    │                  │
       │    + X-User-Id │                    │                  │
       │    header      │                    │                  │
       │────────────────>│                    │                  │
       │                  │                    │                  │
       │                  │ 5. Lookup token   │                  │
       │                  │    by user_id     │                  │
       │                  │─────────────────>│                  │
       │                  │                    │                  │
       │                  │ 6. Return token   │                  │
       │                  │<─────────────────│                  │
       │                  │                    │                  │
       │                  │ 7. Call GitHub    │                  │
       │                  │    with token    │                  │
       │                  │──────────────────>│                  │
       │                  │                    │                  │
       │                  │ 8. GitHub response                   │
       │                  │<──────────────────│                  │
       │                  │                    │                  │
       │ 9. Tool result  │                    │                  │
       │<────────────────│                    │                  │
       │                  │                    │                  │
```

## Authentication Flow

### Sequence: Client → Gateway → Third-Party

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   OpenCode  │     │   Gateway   │     │    GitHub   │     │  Token Store│
│   (MCP)     │     │             │     │    OAuth    │     │             │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                  │                    │                  │
       │ 1. Get JWT       │                    │                  │
       │─────────────────>│                    │                  │
       │                  │                    │                  │
       │ 2. JWT Response  │                    │                  │
       │<─────────────────│                    │                  │
       │                  │                    │                  │
       │ 3. Call tool     │                    │                  │
       │ (Bearer JWT)     │                    │                  │
       │─────────────────>│                    │                  │
       │                  │                    │                  │
       │                  │ 4. Lookup 3rd party │                  │
       │                  │    token            │                  │
       │                  │───────────────────>│                  │
       │                  │                    │                  │
       │                  │ 5. Return GitHub    │                  │
       │                  │    token           │                  │
       │                  │<───────────────────│                  │
       │                  │                    │                  │
       │                  │ 6. Call GitHub API │                    │
       │                  │    (with token)    │                  │
       │                  │───────────────────>│                  │
       │                  │                    │                  │
       │                  │ 7. GitHub Response │                  │
       │                  │<───────────────────│                  │
       │                  │                    │                  │
       │ 8. Tool Result  │                    │                  │
       │<─────────────────│                    │                  │
       │                  │                    │                  │
```

### Step-by-Step Details

#### Step 1-2: Client Gets JWT Access Token

```bash
# Register a client (or use API key)
curl -X POST http://localhost:8000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "my-app", "redirect_uris": ["http://localhost"]}'

# Get access token via client credentials
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=...&client_secret=..."

# Response:
# {
#   "access_token": "eyJ...",
#   "refresh_token": "eyJ...",
#   "expires_in": 1800
# }
```

#### Step 3-4: Client Calls Tool with JWT

```bash
curl -X POST http://localhost:8000/mcp/call \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "github_search_repositories", "arguments": {"query": "opencode"}}'
```

#### Step 5-6: Gateway Looks Up Third-Party Token & Calls API

```python
# In server.py: call_tool endpoint
user_token = await get_token_store().get_token(user_id, "github")
success, result = await connectors.call_tool(tool_name, args, user_token=user_token)
```

### Token Refresh Flow

When the JWT access token expires:

```python
# Client calls /oauth/token with refresh token
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=eyJ..."

# Response:
# {
#   "access_token": "eyJ...",  # New JWT
#   "refresh_token": "eyJ...",  # New refresh token
#   "expires_in": 1800
# }
```

When the third-party token expires (e.g., GitHub token):

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   OpenCode  │     │   Gateway   │     │    GitHub   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                  │                    │
       │ Tool call       │                    │
       │─────────────────>│                    │
       │                  │ GitHub API call    │
       │                  │───────────────────>│
       │                  │                    │
       │                  │ 401 Unauthorized    │
       │                  │ (token expired)    │
       │                  │<───────────────────│
       │                  │                    │
       │ 401 + hint to    │                    │
       │ re-authenticate  │                    │
       │<─────────────────│                    │
       │                  │                    │
       │ Client opens:    │                    │
       │ /oauth/authorize │                    │
       │ /github          │                    │
       ▼                  ▼                    ▼
```

## MCP Server Authentication

### FastMCP-based MCP Server

The gateway includes an MCP server implemented with `mcp.server.fastmcp.FastMCP`. This runs in stdio mode for clients like OpenCode.

**How authentication works:**

1. **Initialize**: MCP client sends initialize request with auth token
2. **Tool Call**: Each tool accepts an `authorization` parameter
3. **Validation**: Gateway validates JWT, extracts user_id
4. **Token Lookup**: Uses user_id to get third-party token
5. **Execute**: Calls connector with user's token

**MCP Tools:**

| Tool | Purpose |
|------|---------|
| `gateway_list_backends` | List available MCP backends |
| `gateway_list_tools` | List all available tools (connectors + backends) |
| `gateway_connect_backend` | Connect to a backend |
| `gateway_auth_status` | Check user's auth and connected services |
| `gateway_call_tool` | Call any tool with proper auth |

**Example MCP Tool Call:**

```python
# In OpenCode - calling gateway tools
# The MCP server runs in stdio mode, so communication is via stdin/stdout

# To use GitHub tools, first check auth status:
gateway_auth_status(authorization="Bearer <jwt_token>")

# Response shows which services are connected
# If GitHub not connected, returns hint to visit auth URL

# To call a GitHub tool:
gateway_call_tool(
    tool_name="github_search_repositories",
    arguments='{"query": "opencode"}',
    authorization="Bearer <jwt_token>"
)
```

### Client Configuration

**OpenCode (opencode.json):**

```json
{
  "mcp": {
    "gateway": {
      "type": "local",
      "command": ["bash", "/path/to/scripts/run-mcp.sh"],
      "environment": {
        "OAUTH_JWT_SECRET_KEY": "your-jwt-secret"
      }
    }
  }
}
```

**Claude Desktop (claude_desktop_config.json):**

```json
{
  "mcpServers": {
    "gateway": {
      "command": "/path/to/scripts/run-mcp.sh"
    }
  }
}
```

## API Endpoints

### OAuth Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/oauth/register` | POST | Register a new OAuth client |
| `/oauth/authorize` | GET | Start OAuth flow (redirects to service) |
| `/oauth/token` | POST | Exchange code for tokens / refresh tokens |
| `/oauth/revoke` | POST | Revoke a token |

### REST API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/tools` | GET | None | List all available tools |
| `/v1/tools/{name}` | GET | None | Get tool schema |
| `/v1/call` | POST | JWT | Call a tool |
| `/v1/connectors` | GET | None | List connectors |
| `/v1/api-keys` | POST | None | Create API key |

### MCP-Compatible Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/mcp/tools` | GET | JWT | List MCP tools |
| `/mcp/call` | POST | JWT | Call MCP tool |
| `/mcp/backends` | GET | JWT | List backends |

### Web UI

| Endpoint | Purpose |
|----------|---------|
| `/` | Gateway info and links |
| `/connectors` | Web UI to connect third-party services |
| `/docs` | OpenAPI documentation |

## Data Flow: Tool Call

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Client sends request with JWT                                           │
│    POST /v1/call                                                           │
│    Authorization: Bearer eyJ...                                            │
│    {"tool_name": "github_search_repositories", "arguments": {...}}        │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. FastAPI dependency validates JWT                                       │
│    get_current_user() extracts user_info from token                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Look up tool's connector                                                │
│    connector_name = connectors._tool_index.get(tool_name)                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Get user's third-party token                                            │
│    user_token = await token_store.get_token(user_id, connector_name)      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. Call connector with user's token                                        │
│    success, result = await connectors.call_tool(                          │
│        tool_name=tool_name,                                                │
│        arguments=args,                                                     │
│        user_token=user_token                                               │
│    )                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. Connector makes API call with token                                     │
│    GitHubConnector._search_repositories()                                  │
│    headers["Authorization"] = f"Bearer {user_token}"                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. Return result to client                                                  │
│    {"success": true, "result": [...]}                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow: Backend Tool Call (with OAuth)

For MCP backends and API backends that have a `connector` mapping:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Client sends request with JWT                                           │
│    POST /mcp/call                                                          │
│    Authorization: Bearer eyJ...                                            │
│    {"tool_name": "create_issue", "arguments": {...}}                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Look up tool's backend                                                  │
│    backend_id = backends._tool_index.get(tool_name)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Check if backend has connector mapping                                  │
│    connector_name = backends._backends[backend_id].definition.connector   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Get user's third-party token (via connector mapping)                   │
│    user_token = await token_store.get_token(user_id, connector_name)      │
│    # Falls back to "default" user if not found                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. Call backend with user_token                                            │
│    # For API backends: passes token in Authorization header                │
│    # For MCP backends: passes token in tool arguments                      │
│    success, result = await backends.call_tool(                            │
│        tool_name=tool_name,                                                │
│        arguments=args,                                                     │
│        backend_id=backend_id,                                              │
│        user_token=user_token,                                              │
│    )                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. Backend makes API call with user's token                               │
│    # MCP server receives token via env or arguments                       │
│    # API backend uses token in Authorization: Bearer header               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 7. Return result to client                                                  │
│    {"success": true, "result": [...]}                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### JWT Security
- Access tokens expire in 30 minutes (configurable)
- Refresh tokens rotate on each use
- Tokens include `jti` (JWT ID) for revocation tracking

### Token Storage
- Third-party tokens stored in SQLite database
- Encrypted at rest (recommended for production)
- Per-user isolation ensures one user can't access another's tokens

### Rate Limiting
- 60 requests per minute per client
- 1000 requests per hour per client
- Configurable in `SecuritySettings`

### Input Validation
- All tool arguments sanitized
- Maximum request size: 10MB
- Maximum string length: 100K

## Environment Variables

```bash
# Server
MCP_GATEWAY_SERVER__PORT=8000
MCP_GATEWAY_SERVER__HOST=0.0.0.0

# OAuth
MCP_GATEWAY_OAUTH__JWT_SECRET_KEY=your-secret-key

# GitHub OAuth (for user OAuth flow)
MCP_GATEWAY_GITHUB_OAUTH__CLIENT_ID=Ov23...
MCP_GATEWAY_GITHUB_OAUTH__CLIENT_SECRET=5a47...

# Slack OAuth
MCP_GATEWAY_SLACK_OAUTH__CLIENT_ID=...
MCP_GATEWAY_SLACK_OAUTH__CLIENT_SECRET=...

# Third-party API keys (for shared credentials)
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
OPENAI_API_KEY=sk-...
SLACK_BOT_TOKEN=xoxb-...
```

## Running the Gateway

### Start HTTP Server (REST + OAuth)
```bash
source venv/bin/activate
python -m gateway.server http
# Runs on http://localhost:8000
```

### Start MCP Server (stdio mode)
```bash
source venv/bin/activate
python -m gateway.server mcp
# For use with MCP clients (OpenCode, Claude Code)
```

### Start Both
```bash
# Terminal 1: HTTP server
python -m gateway.server http

# Terminal 2: MCP stdio
python -m gateway.server mcp
```

## Adding New Connectors

To add a new connector:

1. **Create connector class** in `connectors/`:
   ```python
   # connectors/new_service.py
   class NewServiceConnector(BaseConnector):
       name = "new_service"
       # Implement tools...
   ```

2. **Register in** `connectors/__init__.py`:
   ```python
   CONNECTOR_TYPES = {
       "new_service": NewServiceConnector,
   }
   ```

3. **Add OAuth config** in `config/settings.py`:
   ```python
   class NewServiceOAuthSettings(BaseSettings):
       client_id: Optional[str] = None
       client_secret: Optional[str] = None
   ```

4. **Add environment variables**:
   ```
   MCP_GATEWAY_NEWSERVICE_OAUTH__CLIENT_ID=...
   MCP_GATEWAY_NEWSERVICE_OAUTH__CLIENT_SECRET=...
   ```

## File Structure

```
relay/
├── auth/
│   ├── database.py          # SQLite database with users and api_keys tables
│   ├── db_init.py          # Database initialization
│   ├── oauth.py             # OAuth 2.1 server (JWT, PKCE)
│   ├── oauth_providers.py   # Third-party OAuth (GitHub, Slack, Linear)
│   └── token_store.py       # Token storage (per-user, per-connector)
├── backends/
│   └── manager.py           # MCP backend management
├── config/
│   └── settings.py          # Pydantic settings (all config)
├── connectors/
│   ├── __init__.py          # Connector registry with Resources & Prompts
│   ├── base.py              # BaseConnector class
│   ├── github.py            # GitHub connector
│   ├── slack.py             # Slack connector
│   ├── linear.py            # Linear connector
│   └── ai_providers.py     # OpenAI, Anthropic
├── gateway/
│   ├── server.py           # FastAPI app with per-user MCP endpoints
│   └── cli.py              # CLI commands
├── security/
│   └── middleware.py       # Rate limiting, validation
├── templates/              # Web UI Jinja2 templates
├── static/                 # CSS, JS for web UI
└── .env                    # Environment variables
```

## Glossary

| Term | Definition |
|------|------------|
| Relay | The gateway server that orchestrates connections |
| Connector | Integration with a third-party service |
| API Key | User-specific key for per-user MCP endpoints |
| JWT | JSON Web Token (OAuth 2.1 access token) |
| Third-party token | OAuth token for GitHub/Slack/etc (stored in gateway) |
| MCP | Model Context Protocol (client-server communication) |
| PKCE | Proof Key for Code Exchange (OAuth security) |
| X-User-Id | Header passed to MCP servers for per-user token lookup |

---

# Run Layer Implementation - Deep Dive

## Industry Standards (from research)

Based on analysis of **ByteBridge's "Nginx-like Proxies for MCP"** and **MCP Gateway Registry**, the Run Layer should implement:

| Feature | Purpose | Our Implementation |
|---------|---------|-------------------|
| **Request Routing** | Single endpoint for all tool calls | ✅ `/v1/call`, `/mcp/call` |
| **Tool Discovery** | Dynamic registry of available tools | ✅ `/v1/tools`, MCP tools |
| **Centralized Auth** | OAuth 2.1 JWT for client auth | ✅ Implemented |
| **Third-party Auth** | OAuth flows for GitHub/Slack/Linear | ✅ Implemented |
| **Rate Limiting** | Throttle requests per client | ✅ Sliding window algorithm |
| **Audit Logging** | Log all tool calls | ✅ AuditLogger class |
| **Protocol Mediation** | Bridge different transports | ⚠️ stdio only, need SSE |
| **Credential Vault** | Secure token storage | ✅ TokenStore (SQLite) |
| **Multi-tenant** | Isolated per-user tokens | ✅ Per-user token storage |
| **Observability** | Metrics, dashboards | ⚠️ Basic logs only |
| **Access Control** | Fine-grained permissions | ⚠️ Basic scopes |
| **Human-in-the-loop** | Approve dangerous ops | ❌ Not implemented |

## Run Layer Components

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               RUN LAYER COMPONENTS                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                        REQUEST ROUTING & PROXY                               │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │  │
│  │  │  FastAPI Server │───▶│  Tool Router    │───▶│  Connector/Backend      │   │  │
│  │  │                 │    │                 │    │  Manager                │   │  │
│  │  │  • /v1/call     │    │  • Tool lookup │    │  • Tool dispatch        │   │  │
│  │  │  • /mcp/call    │    │  • Auth check  │    │  • Response handling   │   │  │
│  │  │  • /oauth/*    │    │  • Rate limit  │    │                         │   │  │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                        AUTHENTICATION & SECURITY                             │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │  │
│  │  │  OAuth 2.1 Server│   │  Token Store    │    │  Security Middleware    │   │  │
│  │  │                 │    │                 │    │                         │   │  │
│  │  │  • JWT issuance │    │  • Per-user     │    │  • Rate limiting        │   │  │
│  │  │  • Validation   │    │   third-party   │    │  • Input validation    │   │  │
│  │  │  • Token refresh│    │   tokens        │    │  • Audit logging       │   │  │
│  │  │  • PKCE support │    │  • JWT cache    │    │  • IP restrictions     │   │  │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                        CONNECTOR REGISTRY                                    │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │  │
│  │  │  GitHub         │    │  Slack          │    │  Linear                 │   │  │
│  │  │                 │    │                 │    │                         │   │  │
│  │  │  • Search repos│    │  • Messages     │    │  • Issues               │   │  │
│  │  │  • Issues/PRs  │    │  • Channels     │    │  • Projects             │   │  │
│  │  │  • Code search │    │  • Users        │    │  • Cycles               │   │  │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────────────┘   │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │  │
│  │  │  OpenAI        │    │  Anthropic      │    │  (Extensible)           │   │  │
│  │  │                 │    │                 │    │                         │   │  │
│  │  │  • Chat complet│    │  • Chat complet│    │  • Add new connector    │   │  │
│  │  │  • Embeddings  │    │  • Token count  │    │    in connectors/       │   │  │
│  │  │  • Images      │    │                 │    │                         │   │  │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                        MCP SERVER (Client Interface)                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │  FastMCP Server (stdio mode)                                          │  │  │
│  │  │                                                                         │  │  │
│  │  │  • gateway_list_tools()     - List all available tools               │  │  │
│  │  │  • gateway_list_backends() - List MCP backends                      │  │  │
│  │  │  • gateway_auth_status()    - Check user auth status                │  │  │
│  │  │  • gateway_call_tool()      - Call tool with auth                   │  │  │
│  │  │                                                                         │  │  │
│  │  │  Auth: Each tool accepts JWT Bearer token in authorization param      │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow (Detailed)

### 1. Client-to-Gateway Authentication (OAuth 2.1)

```python
# Step 1: Register client
POST /oauth/register
{"client_name": "opencode-client", "redirect_uris": ["http://localhost"]}

# Step 2: Get access token (Client Credentials)
POST /oauth/token
grant_type=client_credentials&client_id=xxx&client_secret=yyy

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### 2. Gateway Validates JWT on Each Request

```python
# In server.py - get_current_user dependency
async def get_current_user(authorization: str = None):
    token = authorization.replace("Bearer ", "")
    user_info = state.oauth.validate_access_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user_info  # Contains user_id, client_id, scope
```

### 3. Gateway Looks Up Third-Party Token

```python
# When calling a connector tool
user_id = user_info["user_id"]  # From JWT
connector_name = "github"  # Tool maps to connector

# Get user's stored third-party token
user_token = await get_token_store().get_token(user_id, connector_name)

# Use token in API calls
headers["Authorization"] = f"Bearer {user_token}"
```

## Rate Limiting Implementation

```python
# security/middleware.py - Sliding Window Algorithm
class RateLimiter:
    def __init__(self):
        self._clients: Dict[str, List[float]] = {}
    
    def is_allowed(self, client_id: str) -> Tuple[bool, Dict]:
        now = time.time()
        window_start = now - 3600  # 1 hour window
        
        # Clean old entries
        self._clients[client_id] = [
            ts for ts in self._clients.get(client_id, [])
            if ts > window_start
        ]
        
        # Check limits
        minute_count = len([ts for ts in self._clients[client_id] if ts > now - 60])
        if minute_count >= 60:
            return False, {"reason": "rate_limit_per_minute"}
        
        # Allow and record
        self._clients[client_id].append(now)
        return True, {}
```

## Audit Logging Implementation

```python
# security/middleware.py
class AuditLogger:
    def log_tool_call(
        self,
        client_id: str,
        user_id: str,
        tool_name: str,
        arguments: Dict,
        success: bool,
        result_summary: str = None
    ):
        # Sanitize sensitive fields
        sanitized_args = self._sanitize(arguments)
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "tool_call",
            "client_id": client_id,
            "user_id": user_id,
            "tool_name": tool_name,
            "arguments": sanitized_args,
            "success": success,
            "result_summary": result_summary,
        }
        
        # Write to audit log file
        with open(self.log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
```

## Token Refresh Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Client   │     │   Gateway   │     │    OAuth   │
│  (OpenCode) │     │             │     │   Server    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                  │                    │
       │ JWT expired      │                    │
       │─────────────────>│                    │
       │                  │                    │
       │                  │ Check refresh token│
       │                  │─────────────────>│
       │                  │                    │
       │                  │ Validate & rotate │
       │                  │<─────────────────│
       │                  │                    │
       │ New JWT +        │                    │
       │ refresh token    │                    │
       │<─────────────────│                    │
       │                  │                    │
```

## What's Implemented vs Industry Standards

| Feature | Status | Notes |
|---------|--------|-------|
| **Request Routing** | ✅ Done | `/v1/call`, `/mcp/call` |
| **Tool Discovery** | ✅ Done | `/v1/tools` returns all connector tools |
| **OAuth 2.1 Server** | ✅ Done | JWT + refresh token |
| **Third-party OAuth** | ✅ Done | GitHub, Slack, Linear |
| **Per-user Token Store** | ✅ Done | SQLite-based |
| **Rate Limiting** | ✅ Done | Sliding window (60/min, 1000/hr) |
| **Audit Logging** | ✅ Done | Tool calls logged to file |
| **Input Validation** | ✅ Done | Sanitization + max sizes |
| **MCP Server (stdio)** | ✅ Done | FastMCP with auth tools |
| **Protocol Mediation** | ⚠️ Partial | stdio only, need SSE/streamable-http |
| **Credential Vault** | ⚠️ Basic | SQLite, no encryption |
| **Multi-tenant Isolation** | ✅ Done | Per-user tokens |
| **Access Control (RBAC)** | ⚠️ Basic | Client scopes |
| **Human-in-the-loop** | ❌ Missing | No approval workflow |
| **Metrics Dashboard** | ❌ Missing | No UI for stats |
| **Tool Versioning** | ❌ Missing | No version routing |

## Gaps to Address

### High Priority

1. **SSE/Streamable-HTTP for MCP** - Enable remote MCP clients
2. **Token Encryption** - Encrypt stored third-party tokens at rest
3. **Better Error Handling** - Token expiry detection and re-auth flow

### Medium Priority

1. **Access Control** - Fine-grained scopes per tool/connector
2. **Metrics** - Request counts, latency, cost tracking

### Low Priority

1. **Human-in-the-loop** - Approve dangerous operations
2. **Tool Versioning** - Run multiple versions of same tool
3. **Federation** - Connect multiple gateway instances