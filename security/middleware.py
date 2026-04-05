"""
Security Middleware for MCP Gateway

Implements:
- Rate limiting (sliding window algorithm)
- Request validation and sanitization
- Audit logging
- IP restrictions
- Input validation
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from fastapi import Request

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Rate Limiting
# -----------------------------------------------------------------------------

@dataclass
class RateLimitEntry:
    """Tracks rate limit state for a client."""
    timestamps: List[float] = field(default_factory=list)
    blocked_until: float = 0.0


class RateLimiter:
    """
    Sliding window rate limiter.

    Tracks requests per minute and per hour using a sliding window algorithm.
    Thread-safe implementation for concurrent access.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        cleanup_interval: int = 100,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.cleanup_interval = cleanup_interval
        
        # Client ID -> RateLimitEntry
        self._clients: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._request_count = 0
        self._lock = threading.Lock()

    def _cleanup_if_needed(self) -> None:
        """Remove old entries periodically to prevent memory leak."""
        self._request_count += 1
        if self._request_count % self.cleanup_interval != 0:
            return
        
        cutoff = time.time() - 3600  # 1 hour ago
        stale_clients = [
            client_id for client_id, entry in self._clients.items()
            if all(ts < cutoff for ts in entry.timestamps)
        ]
        for client_id in stale_clients:
            del self._clients[client_id]
        
        if stale_clients:
            logger.debug(f"Cleaned up {len(stale_clients)} stale rate limit entries")

    def is_allowed(self, client_id: str) -> tuple[bool, Dict[str, Any]]:
        """
        Check if a request from client_id is allowed.

        Returns:
            (is_allowed, info) tuple where info contains:
            - remaining_minute: remaining requests in current minute window
            - remaining_hour: remaining requests in current hour window
            - retry_after: seconds until unblocked (if blocked)
        """
        now = time.time()
        
        with self._lock:
            entry = self._clients[client_id]
            
            # Check if currently blocked
            if entry.blocked_until > now:
                return False, {
                    "blocked": True,
                    "retry_after": int(entry.blocked_until - now),
                    "reason": "rate_limit_exceeded",
                }
            
            # Clean old timestamps
            minute_ago = now - 60
            hour_ago = now - 3600
            entry.timestamps = [ts for ts in entry.timestamps if ts > hour_ago]
            
            # Count requests in windows
            minute_count = sum(1 for ts in entry.timestamps if ts > minute_ago)
            hour_count = len(entry.timestamps)
            
            # Check limits
            if minute_count >= self.requests_per_minute:
                # Block for remainder of minute
                entry.blocked_until = now + 60
                logger.warning(
                    f"Rate limit exceeded for client {client_id[:12]}... "
                    f"({minute_count}/{self.requests_per_minute} per minute)"
                )
                return False, {
                    "blocked": True,
                    "retry_after": 60,
                    "reason": "minute_limit_exceeded",
                }
            
            if hour_count >= self.requests_per_hour:
                # Block for remainder of hour
                entry.blocked_until = now + 3600
                logger.warning(
                    f"Rate limit exceeded for client {client_id[:12]}... "
                    f"({hour_count}/{self.requests_per_hour} per hour)"
                )
                return False, {
                    "blocked": True,
                    "retry_after": 3600,
                    "reason": "hour_limit_exceeded",
                }
            
            # Record this request
            entry.timestamps.append(now)
            self._cleanup_if_needed()
            
            return True, {
                "remaining_minute": self.requests_per_minute - minute_count - 1,
                "remaining_hour": self.requests_per_hour - hour_count - 1,
            }


# -----------------------------------------------------------------------------
# Input Validation & Sanitization
# -----------------------------------------------------------------------------

class InputValidator:
    """
    Validates and sanitizes input to prevent injection attacks.
    """

    # Inline (?i) flags inside a joined alternation are rejected by Python 3.14+.
    # Case-insensitivity is handled by passing re.IGNORECASE to re.compile below.
    DANGEROUS_PATTERNS = [
        r"\bunion\s+select\b",
        r"\bselect\s+.*\s+from\b",
        r"\bdrop\s+table\b",
        r"--\s*$",
        r"[;&|`$]\s*\w+",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"\.\./|\.\.\\",
        r"<script",
        r"javascript:",
        r"on\w+\s*=",
    ]

    SENSITIVE_PATTERNS = [
        r"password",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"credential",
        r"private[_-]?key",
    ]

    MAX_PATTERN_LENGTH = 1000

    def __init__(
        self,
        max_string_length: int = 100000,
        max_request_size: int = 10 * 1024 * 1024,
        sanitize_html: bool = True,
    ):
        self.max_string_length = max_string_length
        self.max_request_size = max_request_size
        self.sanitize_html = sanitize_html
        self._dangerous_re = re.compile(
            "|".join(self.DANGEROUS_PATTERNS), 
            re.IGNORECASE | re.DOTALL
        )
        self._sensitive_re = re.compile(
            "|".join(self.SENSITIVE_PATTERNS),
            re.IGNORECASE
        )

    def validate_string(self, value: str, field_name: str = "input") -> tuple[bool, str]:
        """
        Validate a string value.

        Returns:
            (is_valid, sanitized_value_or_error)
        """
        if len(value) > self.max_string_length:
            return False, f"{field_name} exceeds maximum length ({self.max_string_length})"
        
        if len(value) > self.MAX_PATTERN_LENGTH:
            logger.warning(f"Input too long for pattern matching in {field_name}")
            return False, f"{field_name} too long for security validation"
        
        try:
            if self._dangerous_re.search(value):
                logger.warning(f"Potential injection detected in {field_name}")
                return False, f"{field_name} contains potentially dangerous content"
        except re.error:
            logger.error(f"Regex error in validate_string")
            return False, f"{field_name} contains invalid characters"
        
        return True, value

    def redact_for_audit(self, value: Any, depth: int = 0) -> Any:
        """
        Prepare a value for safe inclusion in audit logs.

        - Redacts sensitive field names (passwords, tokens, keys, …)
        - Truncates excessively long strings
        - HTML-escapes strings when sanitize_html is True (log display only)

        NOTE: this must NOT be applied to values that will be forwarded to
        backend APIs — HTML-escaping would corrupt payloads.
        """
        if depth > 10:
            return "[truncated - max depth]"

        if isinstance(value, str):
            if len(value) > self.max_string_length:
                value = value[: self.max_string_length] + "...[truncated]"
            if self.sanitize_html:
                value = (
                    value.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#x27;")
                )
            return value

        if isinstance(value, dict):
            result = {}
            for k, v in value.items():
                if self._sensitive_re.search(str(k)):
                    result[k] = "[REDACTED]"
                else:
                    result[k] = self.redact_for_audit(v, depth + 1)
            return result

        if isinstance(value, list):
            return [self.redact_for_audit(item, depth + 1) for item in value]

        return value

    # Keep `sanitize` as an alias for backwards-compat, but redirect callers
    # to redact_for_audit explicitly at call sites.
    sanitize = redact_for_audit

    def validate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Validate tool call arguments.

        Returns validated arguments unchanged (no HTML encoding) so they can
        be forwarded as-is to backend APIs.

        Returns:
            (is_valid, validated_args_or_error_dict)
        """
        validated: Dict[str, Any] = {}
        for key, value in arguments.items():
            if isinstance(value, str):
                is_valid, result = self.validate_string(value, key)
                if not is_valid:
                    return False, {"error": result, "field": key}
                validated[key] = result
            elif isinstance(value, (dict, list)):
                # Nested structures: only check length/depth, no HTML escaping
                validated[key] = value
            else:
                validated[key] = value

        return True, validated


# -----------------------------------------------------------------------------
# Audit Logging
# -----------------------------------------------------------------------------

@dataclass
class AuditEvent:
    """Represents an auditable security event."""
    timestamp: datetime
    event_type: str
    client_id: str
    user_id: Optional[str]
    ip_address: str
    resource: str
    action: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """
    Security audit logger.

    Logs security-relevant events for compliance and forensics.
    """

    def __init__(
        self,
        log_path: str,
        enabled: bool = True,
        sensitive_fields: Optional[List[str]] = None,
    ):
        self.enabled = enabled
        self.log_path = log_path
        self.sensitive_fields = set(sensitive_fields or [])
        self._ensure_log_directory()

    def _ensure_log_directory(self) -> None:
        """Create log directory if it doesn't exist."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def _redact(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields from log data."""
        result = {}
        for key, value in data.items():
            if key.lower() in self.sensitive_fields:
                result[key] = "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = self._redact(value)
            else:
                result[key] = value
        return result

    def log(
        self,
        event_type: str,
        client_id: str,
        user_id: Optional[str],
        ip_address: str,
        resource: str,
        action: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a security event."""
        if not self.enabled:
            return
        
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            client_id=client_id,
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action=action,
            success=success,
            details=self._redact(details or {}),
        )
        
        log_entry = json.dumps({
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "client_id": event.client_id[:16] + "...",  # Truncate for privacy
            "user_id": event.user_id,
            "ip_address": self._hash_ip(event.ip_address),
            "resource": event.resource,
            "action": event.action,
            "success": event.success,
            "details": event.details,
        })
        
        # Log to file
        try:
            with open(self.log_path, "a") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
        
        # Also log to Python logger
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"AUDIT: {event.event_type} client={event.client_id[:12]}... "
            f"user={event.user_id} action={event.action} success={event.success}"
        )

    def _hash_ip(self, ip: str) -> str:
        """Hash IP address for privacy (one-way, not reversible)."""
        if not ip or ip == "unknown":
            return "unknown"
        return hashlib.sha256(ip.encode()).hexdigest()[:16]


# -----------------------------------------------------------------------------
# IP Restrictions
# -----------------------------------------------------------------------------

class IPRestrictions:
    """
    IP-based access control.

    Supports:
    - Whitelist: only allow listed IPs
    - Blacklist: block listed IPs
    - CIDR notation for ranges
    """

    def __init__(
        self,
        whitelist: Optional[List[str]] = None,
        blacklist: Optional[List[str]] = None,
    ):
        self.whitelist = set(whitelist or [])
        self.blacklist = set(blacklist or [])
        self._whitelist_networks = []
        self._blacklist_networks = []
        
        for ip in self.whitelist:
            if "/" in ip:
                self._whitelist_networks.append(ipaddress.ip_network(ip, strict=False))
        for ip in self.blacklist:
            if "/" in ip:
                self._blacklist_networks.append(ipaddress.ip_network(ip, strict=False))

    def is_allowed(self, ip: str) -> tuple[bool, str]:
        """
        Check if an IP is allowed.

        Returns:
            (is_allowed, reason)
        """
        if not ip or ip == "unknown":
            # Unknown IP: allow only when no whitelist is active; when a
            # whitelist is configured we cannot verify membership, so deny.
            if self.whitelist:
                logger.warning("Request with unknown IP rejected: whitelist is active")
                return False, "unknown_ip_whitelist_active"
            return True, "unknown_ip"

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False, "invalid_ip"

        # Check blacklist first
        if ip in self.blacklist:
            return False, "blacklisted"
        for network in self._blacklist_networks:
            if ip_obj in network:
                return False, "blacklisted_range"

        # If whitelist is non-empty, IP must be in it
        if self.whitelist:
            if ip in self.whitelist:
                return True, "whitelisted"
            for network in self._whitelist_networks:
                if ip_obj in network:
                    return True, "whitelisted_range"
            return False, "not_in_whitelist"

        return True, "allowed"


# -----------------------------------------------------------------------------
# Security Context
# -----------------------------------------------------------------------------

class SecurityContext:
    """
    Combined security middleware for MCP Gateway.

    Integrates:
    - Rate limiting
    - Input validation
    - Audit logging
    - IP restrictions
    """

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        validator: Optional[InputValidator] = None,
        audit_logger: Optional[AuditLogger] = None,
        ip_restrictions: Optional[IPRestrictions] = None,
    ):
        self.rate_limiter = rate_limiter or RateLimiter()
        self.validator = validator or InputValidator()
        self.audit = audit_logger
        self.ip = ip_restrictions or IPRestrictions()

    def check_request(
        self,
        client_id: str,
        ip_address: str,
        user_id: Optional[str] = None,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Perform all security checks for an incoming request.

        Returns:
            (is_allowed, info) - if not allowed, info contains error details
        """
        # IP check
        ip_allowed, ip_reason = self.ip.is_allowed(ip_address)
        if not ip_allowed:
            if self.audit:
                self.audit.log(
                    event_type="ip_blocked",
                    client_id=client_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    resource="gateway",
                    action="connect",
                    success=False,
                    details={"reason": ip_reason},
                )
            return False, {"error": "IP blocked", "reason": ip_reason}
        
        # Rate limit check
        allowed, rate_info = self.rate_limiter.is_allowed(client_id)
        if not allowed:
            if self.audit:
                self.audit.log(
                    event_type="rate_limited",
                    client_id=client_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    resource="gateway",
                    action="request",
                    success=False,
                    details=rate_info,
                )
            return False, {"error": "Rate limit exceeded", **rate_info}
        
        return True, rate_info

    def validate_and_sanitize(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> tuple[bool, Dict[str, Any]]:
        """Validate and sanitize tool call arguments."""
        return self.validator.validate_tool_arguments(tool_name, arguments)

    def log_tool_call(
        self,
        client_id: str,
        user_id: Optional[str],
        ip_address: str,
        tool_name: str,
        arguments: Dict[str, Any],
        success: bool,
        result_summary: Optional[str] = None,
    ) -> None:
        """Log a tool call for audit."""
        if self.audit:
            self.audit.log(
                event_type="tool_call",
                client_id=client_id,
                user_id=user_id,
                ip_address=ip_address,
                resource=tool_name,
                action="call",
                success=success,
                details={
                    "arguments": self.validator.sanitize(arguments),
                    "result_summary": result_summary,
                },
            )


class HSTSMiddleware(BaseHTTPMiddleware):
    """Add HTTP Strict-Transport-Security header to all responses."""

    def __init__(self, app, max_age: int = 31536000, include_subdomains: bool = True):
        super().__init__(app)
        self.max_age = max_age
        self.include_subdomains = include_subdomains

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        hsts_value = f"max-age={self.max_age}"
        if self.include_subdomains:
            hsts_value += "; includeSubDomains"
        response.headers["strict-transport-security"] = hsts_value
        return response
