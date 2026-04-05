# Relay Dockerfile
# Multi-stage build for optimized image size

# ---- Builder Stage ----
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /wheels -e .

# ---- Runtime Stage ----
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r relay && useradd -r -g relay relay

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Copy application code
COPY . .

# Create directories
RUN mkdir -p logs data && chown -R relay:relay logs data

# Switch to non-root user
USER relay

# Environment defaults
ENV RELAY_ENVIRONMENT=production \
    RELAY_SERVER__HOST=0.0.0.0 \
    RELAY_SERVER__PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["relay", "serve", "--host", "0.0.0.0", "--port", "8000"]
