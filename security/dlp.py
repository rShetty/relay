"""
Result-level Data Loss Prevention (DLP) for tool call outputs.

Tool results are forwarded to LLM-powered clients, so any credential that a
backend echoes back (API keys in error messages, tokens in JSON payloads,
bearer credentials in headers-as-text) risks leaking into model context and
logs.  This module provides an opt-out-ofable inspection hook that scrubs
secret-shaped strings from tool call *results* before they leave the gateway.

Scope:
    - Inspects RESULT data only (arguments are validated by InputValidator).
    - Structural redaction: keys that look like credential field names.
    - Content redaction: value patterns for known key/token formats.

This complements the audit-log redaction already performed by
``InputValidator.redact_for_audit`` and ``AuditLogger._redact``: those
protect log sinks, this protects the caller-visible result.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ResultDLPInspector:
    """Inspect and redact sensitive content in tool call results."""

    REDACTED = "[REDACTED]"

    # Result keys whose values should always be redacted regardless of shape.
    SENSITIVE_KEY_PATTERNS = (
        r"password",
        r"passwd",
        r"secret",
        r"token",
        r"auth(?:orization)?",
        r"api[_-]?key",
        r"access[_-]?key",
        r"private[_-]?key",
        r"credential",
        r"session[_-]?id",
        r"cookie",
        r"set[_-]?cookie",
    )

    # Value-shaped patterns for well-known credential formats.
    VALUE_PATTERNS = {
        "api_key": re.compile(r"\brelay_[A-Za-z0-9_\-]{20,}\b"),
        "sk": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
        "github_pat": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"),
        "jwt": re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
        "bearer_header": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}\b"),
    }

    MAX_DEPTH = 10

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._sensitive_key_re = re.compile(
            "|".join(self.SENSITIVE_KEY_PATTERNS),
            re.IGNORECASE,
        )
        self._value_patterns = list(self.VALUE_PATTERNS.items())

    # ------------------------------------------------------------------
    # Inspection entry point
    # ------------------------------------------------------------------

    def inspect_result(self, result: Any) -> Any:
        """
        Return a copy of *result* with secret-shaped content redacted.

        Non-string scalars pass through untouched; dicts/lists are walked
        recursively; strings have credential-shaped substrings replaced.
        """
        if not self.enabled or result is None:
            return result
        return self._inspect(result, depth=0)

    # ------------------------------------------------------------------
    # Internal recursion
    # ------------------------------------------------------------------

    def _inspect(self, value: Any, depth: int, key: Optional[str] = None) -> Any:
        if depth > self.MAX_DEPTH:
            return "[truncated - max depth]"

        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for k, v in value.items():
                k_str = str(k)
                if self._sensitive_key_re.search(k_str):
                    out[k_str] = self.REDACTED
                else:
                    out[k_str] = self._inspect(v, depth + 1, key=k_str)
            return out

        if isinstance(value, (list, tuple)):
            inspected = [self._inspect(item, depth + 1, key=key) for item in value]
            return inspected if isinstance(value, list) else type(value)(inspected)

        if isinstance(value, str):
            if key is not None and self._sensitive_key_re.search(key):
                return self.REDACTED
            return self._redact_content(value)

        return value

    def _redact_content(self, text: str) -> str:
        """Redact credential-shaped substrings inside a free-form string."""
        for _name, pattern in self._value_patterns:
            text = pattern.sub(self.REDACTED, text)
        return text


_inspector: Optional[ResultDLPInspector] = None


def get_dlp_inspector() -> ResultDLPInspector:
    """Return the process-wide DLP inspector (creating it on first use)."""
    global _inspector
    if _inspector is None:
        _inspector = ResultDLPInspector()
    return _inspector


def set_dlp_inspector(inspector: Optional[ResultDLPInspector]) -> None:
    """
    Replace the process-wide DLP inspector.

    Passing ``None`` installs a permanently disabled inspector, i.e. result
    inspection becomes a no-op until a real inspector is installed again.
    """
    global _inspector
    if inspector is None:
        inspector = ResultDLPInspector(enabled=False)
    _inspector = inspector


def inspect_tool_result(result: Any) -> Any:
    """Convenience hook: run the active DLP inspector over a tool result."""
    return get_dlp_inspector().inspect_result(result)
