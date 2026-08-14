"""
Observability module — structured logging, Prometheus metrics, and
optional OpenTelemetry tracing.
"""

from observability.logging import setup_logging, get_logger
from observability.metrics import (
    metrics,
    REQUEST_COUNT,
    REQUEST_LATENCY,
    TOOL_CALL_COUNT,
    TOOL_CALL_LATENCY,
    TOOL_CALL_ERRORS,
    CIRCUIT_BREAKER_STATE,
    ACTIVE_BACKENDS,
    OAUTH_TOKENS_ISSUED,
    RATE_LIMIT_HITS,
)

__all__ = [
    "setup_logging",
    "get_logger",
    "metrics",
    "REQUEST_COUNT",
    "REQUEST_LATENCY",
    "TOOL_CALL_COUNT",
    "TOOL_CALL_LATENCY",
    "TOOL_CALL_ERRORS",
    "CIRCUIT_BREAKER_STATE",
    "ACTIVE_BACKENDS",
    "OAUTH_TOKENS_ISSUED",
    "RATE_LIMIT_HITS",
]
