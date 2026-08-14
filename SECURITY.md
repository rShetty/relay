# Relay Security Architecture

## Overview

Relay implements defense-in-depth security for enterprise deployments.

## Security Controls

### Authentication

| Control | Implementation |
|---------|---------------|
| OAuth 2.1 with PKCE | Full implementation with S256 code challenges |
| JWT tokens | HS256 (dev) or RS256 (prod) with configurable expiry |
| JWKS endpoint | `/oauth/jwks` for asymmetric key verification |
| Session cookies | `HttpOnly`, `Secure` (prod), `SameSite=Strict` (prod) |
| Account lockout | Configurable max attempts + lockout duration |
| Password hashing | PBKDF2-HMAC-SHA256, 100K iterations |
| SSO/OIDC | Configurable via `RELAY_OAUTH__SSO_*` settings |

### Authorization

| Control | Implementation |
|---------|---------------|
| Per-user token isolation | Each user's third-party tokens stored separately |
| Per-connector permissions | Granular tool-level access control |
| Patroclus integration | Fail-closed per-tool policy checks |
| Admin role | Separate admin role with elevated permissions |
| Access requests | Users request access; admins approve/deny |

### Encryption

| Control | Implementation |
|---------|---------------|
| Encryption at rest | Fernet (AES-128-CBC) for stored tokens |
| Encryption in transit | TLS/SSL configurable, HSTS headers |
| Encryption key | Required in production via `RELAY_ENCRYPTION_KEY` |

### Request Security

| Control | Implementation |
|---------|---------------|
| Rate limiting | Sliding window, Redis-backed for distributed deployments |
| CSRF protection | Double-submit cookie pattern for web UI forms |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options, HSTS |
| Input validation | Pattern-based injection detection, size limits |
| IP restrictions | Whitelist/blacklist with CIDR support |

### Audit & Compliance

| Control | Implementation |
|---------|---------------|
| Audit logging | All security events logged (JSONL format) |
| Tamper-evidence | Hash-chained audit log entries |
| Sensitive field redaction | Passwords, tokens, keys redacted in logs |
| IP privacy | IP addresses SHA-256 hashed in logs |
| GDPR right-to-erasure | `DELETE /auth/me` with cascading data deletion |
| SOC2 alignment | Access controls, audit logging, encryption |

## Production Deployment Checklist

- [ ] Set `RELAY_ENVIRONMENT=production`
- [ ] Set strong `RELAY_ENCRYPTION_KEY` (Fernet key)
- [ ] Set strong `RELAY_OAUTH__JWT_SECRET_KEY`
- [ ] Set `RELAY_OAUTH__JWT_ALGORITHM=RS256` and provide public key
- [ ] Set `RELAY_SECURITY__CSRF_SECRET_KEY`
- [ ] Enable TLS (configure reverse proxy with Let's Encrypt)
- [ ] Configure Redis for distributed rate limiting
- [ ] Configure PostgreSQL for multi-instance persistence
- [ ] Set up audit log aggregation (ELK/Datadog/CloudWatch)
- [ ] Configure Prometheus scraping of `/metrics`
- [ ] Set up OpenTelemetry tracing (optional, via OTLP)
- [ ] Configure IP allowlists if needed
- [ ] Set up regular backup of encryption key and database
- [ ] Document incident response procedures
- [ ] Enable Patroclus integration for per-tool authorization

## Incident Response

### Token Compromise
1. Revoke compromised tokens: `POST /oauth/revoke`
2. Rotate JWT secret and encryption key
3. Force re-authorization for all clients
4. Review audit logs for unauthorized access

### Backend Compromise
1. Disable backend via admin UI or `DELETE /admin/backends/{id}`
2. Rotate backend credentials
3. Audit tool calls via logs
4. Notify affected users

### Rate Limit Evasion
1. Identify pattern in audit logs
2. Add IP to blacklist
3. Contact abuse team

## Security Contact

Security issues: security@example.com
