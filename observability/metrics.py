"""
Prometheus metrics for monitoring Relay gateway.

Exposes counters, histograms, and gauges for request rate, latency,
tool calls, circuit breaker state, and backend health.
"""

from __future__ import annotations

from typing import Optional

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Use a custom registry to avoid duplicate metric registration on reload
_registry = CollectorRegistry()

REQUEST_COUNT = Counter(
    "relay_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=_registry,
)

REQUEST_LATENCY = Histogram(
    "relay_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=_registry,
)

TOOL_CALL_COUNT = Counter(
    "relay_tool_calls_total",
    "Total tool calls",
    ["tool_name", "connector", "success"],
    registry=_registry,
)

TOOL_CALL_LATENCY = Histogram(
    "relay_tool_call_duration_seconds",
    "Tool call latency",
    ["tool_name", "connector"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
    registry=_registry,
)

TOOL_CALL_ERRORS = Counter(
    "relay_tool_call_errors_total",
    "Total tool call errors",
    ["tool_name", "connector", "error_type"],
    registry=_registry,
)

CIRCUIT_BREAKER_STATE = Gauge(
    "relay_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["backend_id"],
    registry=_registry,
)

ACTIVE_BACKENDS = Gauge(
    "relay_active_backends",
    "Number of active (healthy) backends",
    registry=_registry,
)

OAUTH_TOKENS_ISSUED = Counter(
    "relay_oauth_tokens_issued_total",
    "Total OAuth tokens issued",
    ["grant_type"],
    registry=_registry,
)

RATE_LIMIT_HITS = Counter(
    "relay_rate_limit_hits_total",
    "Total rate limit rejections",
    ["limit_type"],
    registry=_registry,
)

AUTH_ATTEMPTS = Counter(
    "relay_auth_attempts_total",
    "Total authentication attempts",
    ["method", "success"],
    registry=_registry,
)

ACTIVE_USERS = Gauge(
    "relay_active_users",
    "Number of active users",
    registry=_registry,
)


class MetricsExporter:
    """Wrapper for Prometheus metrics export."""

    @property
    def registry(self) -> CollectorRegistry:
        return _registry

    def render(self) -> tuple[str, str]:
        """Return (content_type, body) for the /metrics endpoint."""
        return CONTENT_TYPE_LATEST, generate_latest(_registry).decode("utf-8")


metrics = MetricsExporter()
