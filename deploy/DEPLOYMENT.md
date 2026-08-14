# Relay VPS Deployment

## Overview

Relay deploys to a VPS via GitHub Actions, matching the same pattern as Miser:

1. **CI pipeline** runs tests, lint, and security scans
2. **SSH deploy** connects to the VPS, pulls latest code, installs dependencies, and restarts the systemd service
3. **Health checks** verify the deployment succeeded
4. **Auto-retry** attempts up to 2 additional times on failure

## Required GitHub Secrets

Configure these in your repository under **Settings → Secrets and variables → Actions**:

| Secret | Description | Example |
|--------|-------------|---------|
| `VPS_HOST` | VPS IP address or hostname | `123.45.67.89` |
| `VPS_USER` | SSH user with sudo access | `deploy` |
| `VPS_SSH_KEY` | SSH private key for the VPS user | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `RELAY_ENCRYPTION_KEY` | Fernet key for encrypting stored tokens | Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `RELAY_JWT_SECRET_KEY` | JWT signing secret | Generate: `openssl rand -hex 32` |
| `RELAY_CSRF_SECRET_KEY` | CSRF token signing secret | Generate: `openssl rand -hex 32` |
| `GITHUB_PAT` | GitHub personal access token (optional, for GitHub connector) | `ghp_...` |
| `OPENAI_API_KEY` | OpenAI API key (optional, for OpenAI connector) | `sk-...` |
| `SLACK_BOT_TOKEN` | Slack bot token (optional, for Slack connector) | `xoxb-...` |
| `PATROCLUS_ENABLED` | Enable Patroclus authorization (optional) | `false` |
| `PATROCLUS_URL` | Patroclus server URL (optional) | `http://localhost:8484` |

## VPS Setup (one-time)

```bash
# Create relay user
sudo useradd --system --home-dir /var/lib/relay --create-home --shell /usr/sbin/nologin relay

# Create directories
sudo mkdir -p /var/lib/relay/data /var/lib/relay/logs /etc/relay /opt/relay
sudo chown -R relay:relay /var/lib/relay

# Install Python 3.11
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev

# Install Redis (for distributed rate limiting)
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Clone repo (will be managed by CI)
sudo git clone https://github.com/rShetty/relay.git /opt/relay
sudo chown -R relay:relay /opt/relay
```

## How It Works

```
GitHub Push (main)
       │
       ▼
┌──────────────┐     ┌──────────────┐
│   verify     │     │   security   │
│ (test, lint) │     │ (audit, scan)│
└──────┬───────┘     └──────┬───────┘
       └────────┬───────────┘
                ▼
         ┌────────────┐
         │   deploy    │
         │ (SSH to VPS)│
         └──────┬──────┘
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
   git pull   pip install  systemctl restart
                │
                ▼
         health check (/live)
                │
           ┌────┴────┐
           ▼         ▼
        success   retry (up to 2x)
```

## Files

| File | Purpose |
|------|---------|
| `.github/workflows/deploy.yml` | CI/CD pipeline: verify → security → deploy with retries |
| `deploy/relay.service` | systemd unit (hardened, non-root, auto-restart) |
| `scripts/start.sh` | Local development start script |

## Manual Deployment

```bash
# On the VPS:
cd /opt/relay
git pull origin main
source .venv/bin/activate
pip install -e ".[dev]"
sudo systemctl restart relay

# Check health
curl http://localhost:8000/live
curl http://localhost:8000/ready
curl http://localhost:8000/health
```

## Monitoring

```bash
# Service status
sudo systemctl status relay

# Logs
sudo journalctl -u relay -f

# Prometheus metrics
curl http://localhost:8000/metrics

# Audit log
tail -f /var/lib/relay/logs/audit.log
```

## Nginx Reverse Proxy (recommended)

```nginx
server {
    listen 80;
    server_name relay.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then add TLS with certbot:
```bash
sudo certbot --nginx -d relay.example.com
```
