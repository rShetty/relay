"""
Structured JSON logging using structlog.

In production, emits JSON logs suitable for ELK/Datadog/CloudWatch.
In development, uses pretty console output.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

import structlog


def setup_logging(
    level: str = "INFO",
    json_format: bool = True,
    service_name: str = "relay",
    service_version: str = "0.1.0",
) -> None:
    """
    Configure structured logging for the entire application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_format: If True, emit JSON logs; if False, pretty-print
        service_name: Service name for log correlation
        service_version: Service version for log correlation
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure stdlib logging to route through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.add_stats,
    ]

    if json_format:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure the formatter for stdlib logging
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    root_handler = logging.getLogger().handlers[0]
    if isinstance(root_handler, logging.StreamHandler):
        root_handler.setFormatter(formatter)

    # Add service metadata to all logs
    structlog.contextvars.bind_contextvars(
        service=service_name,
        version=service_version,
    )


def get_logger(name: str = "relay") -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)
