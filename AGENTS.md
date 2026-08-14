# AGENTS.md

## Build & Development Commands

```bash
# Install
pip install -e ".[dev]"

# Run server
python -m gateway.server http

# Run tests
pytest tests/ -v --cov

# Lint
ruff check .
black --check .
mypy --ignore-missing-imports gateway/ auth/ security/ config/
```

## Production Requirements

The following environment variables are **required** in production:

- `RELAY_ENVIRONMENT=production`
- `RELAY_ENCRYPTION_KEY` — Fernet key for encrypting stored tokens
- `RELAY_OAUTH__JWT_SECRET_KEY` — JWT signing secret
- `RELAY_SECURITY__CSRF_SECRET_KEY` — CSRF token signing secret

For RS256 (recommended):
- `RELAY_OAUTH__JWT_ALGORITHM=RS256`
- `RELAY_OAUTH__JWT_PUBLIC_KEY` — PEM public key

## Architecture Notes

- SQLite is used by default (development). Use PostgreSQL in production via `RELAY_DATABASE__URL`.
- Redis is optional but recommended for distributed rate limiting and JWT revocation.
- Structured JSON logging is enabled by default (`RELAY_SERVER__LOG_FORMAT=json`).
- Prometheus metrics are available at `/metrics`.
- Health endpoints: `/live` (liveness), `/ready` (readiness), `/health` (combined).
- CSRF protection is enabled by default for web UI forms.
