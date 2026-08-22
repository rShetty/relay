# Relay Enterprise Readiness

This document tracks the improvements made to make Relay production/enterprise-ready,
and identifies which items belong to Relay vs. the broader ecosystem.

## High Availability — Honest Assessment

**Relay today is a single-node deployment. Running more than one replica against the
current codebase does not give you high availability — it gives you silent
inconsistency between replicas.** This section describes exactly what breaks and what
a real HA topology requires.

### What breaks today with >1 replica

| Component | State | Why multiple replicas break it |
|-----------|-------|-------------------------------|
| Gateway database (`auth/database.py`) | SQLite via stdlib `sqlite3` | Every replica would open its own `data/gateway.db` file. Users registered on replica A do not exist on replica B; API keys, OAuth clients, consents, and installed backends diverge silently. |
| Rate limiter (`security/middleware.py::RateLimiter`) | Per-process sliding window | `configure_redis()` stores a Redis client, but `is_allowed()` never consults it — counting happens only in local memory. With N replicas each client effectively gets N× the configured request budget. |
| Account lockout (`app_state._login_attempts`) | Per-process dict | Failed-login counters are not shared, so lockout thresholds must be exceeded against every replica independently. |
| JWT revocation (`auth/oauth.py::JWTManager`) | In-memory + Redis (shared) | The one component that *is* cluster-safe when `RELAY_DATABASE__REDIS_URL` is set. Caveat: `is_revoked()` fails **open** if Redis errors — a revoked token may be accepted during a Redis outage on any replica that has not seen the jti locally. |
| Connector registry / backend sessions (`connectors/__init__.py`, `backends/manager.py`) | Process-local singletons | Health-check state, MCP stdio sessions, and enabled-flags live per process. A tool call routed to replica B can hit a backend session replica B never opened or believes is unhealthy. |
| Connector OAuth token cache (`auth/oauth_providers.py::_tokens`) | Per-process cache | After connecting GitHub on replica A, replica B cannot see the cached credential until it is written through `get_token_store()` (SQLite). |
| Audit log (`AuditLogger`) | Local hash-chained file | Each replica chains events into its own `logs/audit.log`; the tamper-evident hash chain is per-file and cannot be verified across replicas. |
| Login rate limiting / CSRF double-submit cookies | Per-process / per-replica secrets unless synced | Double-submit CSRF tokens are signed with `RELAY_SECURITY__CSRF_SECRET_KEY` — this works across replicas **only if** every replica uses identical secret values from shared config. |

### Recommended topology (target state)

Not achievable with current code until the migration items below land:

```
                      ┌─────────────────────────────────────────┐
                      │            Load balancer (TLS)          │
                      └────────────────────┬────────────────────┘
                                           │
              ┌────────────────────────────┼────────────────────────────┐
              ▼                            ▼                            ▼
     ┌────────────────┐          ┌────────────────┐          ┌────────────────┐
     │  relay app #1  │          │  relay app #2  │          │  relay app #N  │
     │  (stateless*)  │          │  (stateless*)  │          │  (stateless*)  │
     └───────┬────────┘          └───────┬────────┘          └───────┬────────┘
             │      (*after Postgres + shared-state work)│           │
             └──────────────┬────────────┴──────────────┬───────────┘
                            ▼                           ▼
                 ┌────────────────────┐       ┌────────────────────┐
                 │  PostgreSQL        │       │  Redis             │
                 │  (users, keys,     │       │  (rate limits*,    │
                 │  OAuth, audit)     │       │   JWT revocation)  │
                 └────────────────────┘       └────────────────────┘
```

\* Rate-limit sharing requires fixing `RateLimiter.is_allowed()` to actually consult
Redis; today Redis is connected but unused by the limiter.

### Migration requirements before HA

1. **PostgreSQL** — `DatabaseSettings.url` accepts a Postgres DSN, but no runtime code
   consumes it: all persistence goes through stdlib `sqlite3`. An async SQLAlchemy
   engine layer must replace the raw sqlite3 calls (drivers already declared in the
   optional `postgres` extra).
2. **Schema migrations** — Tables are created with `CREATE TABLE IF NOT EXISTS`
   (`init_db()`); Alembic (or equivalent) is required before multi-replica rollouts so
   concurrent boots do not fight over schema.
3. **Redis-backed rate limiting** — Make `RateLimiter` use atomic Redis window
   operations (`INCR`/`EXPIRE` or a Lua script) instead of local lists.
4. **Shared lockout & revocation semantics** — Move `_login_attempts` to Redis; decide
   whether JWT-revocation fail-open behaviour is acceptable or should fail closed.
5. **Session affinity elimination** — Ensure connector/backend session state is either
   externalized or safe to rebuild lazily on any replica.
6. **Centralized audit sink** — Ship audit events to shared storage (DB/SIEM) instead of
   per-pod files so the hash chain remains verifiable.

Until items 1–3 are complete, run **exactly one** relay replica and treat vertical
scaling as the only option.

## What Was Fixed in Relay

### Critical Security Fixes

| # | Issue | Fix |
|---|-------|-----|
| 1 | `cookies.txt` committed to repo | Removed file, added to `.gitignore` |
| 2 | OAuth authorize auto-approves | Now requires authenticated user session |
| 3 | `authenticate_user` accepts any credentials | Replaced with no-op stub (DB provider overrides) |
| 4 | Session cookie `secure=False` | Now production-aware: `Secure` + `SameSite=Strict` in prod |
| 5 | No CSRF protection | Added `CSRFMiddleware` (double-submit cookie pattern) |
| 6 | Encryption key auto-generated to file | Fail-closed in production; ephemeral in dev only |
| 7 | JWT uses HS256 only | Added RS256/ES256 support with `jwt_public_key` + JWKS endpoint |
| 8 | `decrypt_data` silently returns ciphertext | Now raises `RuntimeError` on failure |

### Architecture & Scalability

| # | Issue | Fix |
|---|-------|-----|
| 9 | Duplicate `GitHubOAuthSettings` class | Removed duplicate, kept the one with `model_config` |
| 10 | No PostgreSQL support | Added `DatabaseSettings.url` + `effective_url` property |
| 11 | No database migration system | Documented as needed; Alembic recommended for future |
| 12 | In-memory rate limiter not shared | Added `configure_redis()` for distributed rate limiting |
| 13 | No liveness/readiness separation | Added `/live`, `/ready` endpoints alongside `/health` |
| 14 | No graceful shutdown | Lifespan already handles cleanup; documented |

### Observability & Operations

| # | Issue | Fix |
|---|-------|-----|
| 15 | No structured logging | Added `observability/logging.py` with structlog (JSON format) |
| 16 | No Prometheus metrics | Added `observability/metrics.py` with counters/histograms/gauges + `/metrics` endpoint |
| 17 | No distributed tracing | Added `observability/tracing.py` with OpenTelemetry (optional, `relay[otel]`) |
| 18 | No metrics middleware | Added `MetricsMiddleware` for automatic request tracking |

### CI/CD & Supply Chain

| # | Issue | Fix |
|---|-------|-----|
| 19 | No CI/CD pipeline | Created `.github/workflows/ci.yml` (test, lint, security scan, Docker build) |
| 20 | No dependency scanning | Added pip-audit + Trivy to CI |
| 21 | Missing Helm charts | Created `deploy/kubernetes/relay/` with Chart.yaml, values.yaml, templates |
| 22 | Dockerfile `as` lowercase | Fixed to `AS`; added `PYTHONUNBUFFERED`, `PYTHONDONTWRITEBYTECODE` |
| 23 | Deploy rebuilt from source on the VPS; no SBOM or image signing | Build-once artifact promotion: CI builds/pushes a digest-pinned GHCR image, generates a syft SBOM, attempts cosign keyless signing, and the VPS pulls that exact digest with `--no-build`. See [Artifact Promotion](#artifact-promotion--supply-chain) below |

### Enterprise Features Added

| # | Feature | Implementation |
|---|---------|---------------|
| 24 | Account lockout | Configurable max attempts + lockout duration |
| 25 | GDPR right-to-erasure | `DELETE /auth/me` + `db.delete_user()` with cascading cleanup |
| 26 | JWKS endpoint | `/oauth/jwks` for RS256 public key distribution |
| 27 | SSO/OIDC config | `OAuthSettings.sso_*` fields for Okta/Azure AD integration |
| 28 | Tamper-evident audit logs | Hash-chained entries in `AuditLogger` |
| 29 | Security headers | CSP, X-Frame-Options, X-Content-Type-Options via `SecurityHeadersMiddleware` |
| 30 | CSRF protection | `CSRFMiddleware` with double-submit cookie pattern |
| 31 | Insecure-cookie escape hatch reachable in production | `RELAY_ALLOW_INSECURE_COOKIES=true` now fails config validation when `RELAY_ENVIRONMENT=production`; `docker-compose.prod.yml` pins the variable to `false`. `/ready` deep-probes SQLite openability (`SELECT 1`) and Redis ping (when configured) so the probe reflects backing services |

## Artifact Promotion & Supply Chain

The deploy pipeline follows a **build-once, promote-by-digest** model
(`.github/workflows/deploy.yml`):

1. **Build** — the `image` job builds the Docker image once in CI and pushes
   it to GHCR tagged with the commit SHA and `latest`.
2. **SBOM** — [syft](https://github.com/anchore/sbom-action) generates an
   SPDX JSON SBOM of the *pushed image digest* and uploads it as a workflow
   artifact (`relay-sbom-<sha>.spdx.json`).
3. **Sign** — [cosign](https://github.com/sigstore/cosign) attempts **keyless**
   signing (Fulcio certificate via the workflow's OIDC token, logged in
   Rekor). If keyless infrastructure is unavailable the job records the
   failure in the run summary and marks the image **unsigned** rather than
   blocking the release; the documented fallback is key-based signing with
   `COSIGN_KEY`/`COSIGN_PASSWORD` repository secrets.
4. **Promote** — the `deploy` job passes `repo@sha256:...` to the VPS over
   SSH. The VPS **pulls the exact digest** and runs
   `docker compose up -d --no-build` (`RELAY_IMAGE` pins the compose service).
   Nothing is rebuilt on the VPS, so the artifact that was scanned and signed
   is bit-for-bit what runs in production.

### Verification (after a signed deploy)

```bash
cosign verify ghcr.io/<owner>/<repo>@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/\.github/workflows/deploy\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Planned hardening (future iterations)

- Admission control on the VPS: refuse to start the relay service unless
  `cosign verify` succeeds against the promoted digest (requires keyless or
  a distributed public key).
- Attach the SBOM to the image itself (`cosign attach`) and store signatures
  in an OCI registry or transparency log for long-term retention.
- Provenance attestation (`cosign attest` with SLSA provenance) alongside the
  signature.

## What Belongs to Ecosystem Products

These items are **not Relay's responsibility** — they belong to other projects in the ecosystem:

### Patroclus (Authorization Infrastructure)

- **Per-tool RBAC / role hierarchy** — Patroclus handles scoped, time-limited authorization
- **Human-in-the-loop approval workflows** — Patroclus `require_approval` flow
- **Policy engine (OPA/Cedar/YAML)** — Patroclus evaluates policies, Relay just calls `check_access()`
- **Agent identity management** — Patroclus registers and manages agent identities
- **Delegation tokens** — Patroclus issues scoped delegation tokens

Relay's role: Call `patroclus.check_access()` before every tool call (fail-closed). Already implemented.

### Sentiel (Observability, DLP & Compliance)

- **DLP inspection of tool call results** — Sentiel inspects outbound data for sensitive content
- **SIEM integration** — Sentiel forwards audit events to Splunk/CloudWatch/ELK
- **Compliance reporting** — Sentiel generates SOC2/HIPAA compliance reports
- **Data retention policies** — Sentiel manages log retention and deletion

Relay's role: Send tool call events to Sentiel. The integration point exists but Sentiel client code lives in the Sentiel repo.

### Aegis (Network Egress & Attestation)

- **Network egress control** — Aegis enforces which external APIs agents can reach
- **Request attestation** — Aegis verifies that requests come from trusted agents
- **Supply chain security** — Aegis validates backend MCP server integrity

Relay's role: Route egress through Aegis. Not yet implemented (Aegis is still in design).

### Miser (LLM Cost Optimization)

- **Token budget enforcement** — Miser tracks and limits LLM token usage per agent/user
- **Cost attribution** — Miser attributes costs to users/projects
- **Model routing** — Miser selects optimal models based on cost/quality tradeoffs

Relay's role: Report LLM tool call usage to Miser. Not yet implemented.

### Hive (Agent Runtime & Orchestration)

- **Agent lifecycle management** — Hive manages agent processes
- **Tool call orchestration** — Hive sequences multi-step tool calls
- **Agent-to-gateway authentication** — Hive provides agent identity to Relay

Relay's role: Accept authenticated requests from Hive agents. Already supported via API keys.

## Remaining Work (Future Iterations)

### In Relay

1. **Alembic migrations** — Replace `CREATE TABLE IF NOT EXISTS` with proper migration system
2. **PostgreSQL async engine** — Implement async SQLAlchemy engine when `DATABASE_URL` is PostgreSQL
3. **Redis-backed rate limiting** — Make `RateLimiter.is_allowed()` consult Redis atomically (currently connected but unused; see [High Availability](#high-availability--honest-assessment))
4. **SSO implementation** — Wire OIDC callback flow (config exists, handler not implemented)
5. **Webhook/event system** — Notify external systems of events
6. **Per-tenant quotas** — Usage limits per organization
7. **Multi-tenancy / org layer** — Organization/team/tenant isolation
8. **Feature flags** — Toggle connectors/features per environment
9. **Backup/restore tooling** — Scripts and documentation for DR
10. **Sentiel DLP integration** — Send tool call results to Sentiel for inspection

### In Ecosystem

1. **Patroclus**: Implement policy engine, approval workflows, delegation tokens
2. **Sentiel**: Implement DLP inspection, SIEM forwarding, compliance reporting
3. **Aegis**: Implement network egress control, request attestation
4. **Miser**: Implement cost tracking, budget enforcement, model routing
5. **Hive**: Implement agent lifecycle, orchestration, identity management
