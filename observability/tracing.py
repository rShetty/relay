"""
Optional OpenTelemetry tracing integration.

When OTEL is enabled (RELAY_ENABLE_TRACING=true, RELAY_OTLP_ENDPOINT set),
spans are exported via OTLP to a collector (Jaeger, Tempo, etc.).
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def setup_tracing(
    service_name: str = "relay",
    service_version: str = "0.1.0",
    otlp_endpoint: Optional[str] = None,
) -> None:
    """
    Configure OpenTelemetry tracing.

    Gracefully no-ops if opentelemetry packages are not installed.
    """
    if not otlp_endpoint:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        resource = Resource.create({
            "service.name": service_name,
            "service.version": service_version,
        })

        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        logger.info("OpenTelemetry tracing enabled, exporting to %s", otlp_endpoint)

    except ImportError:
        logger.warning(
            "OpenTelemetry packages not installed. "
            "Install with: pip install relay[otel]"
        )
    except Exception as e:
        logger.warning("Failed to initialize OpenTelemetry tracing: %s", e)


def instrument_httpx() -> None:
    """Instrument httpx clients for distributed tracing."""
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
    except ImportError:
        pass
