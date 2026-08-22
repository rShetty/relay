"""
SSRF protection for admin-installed backend URLs (issue #4).

When an admin installs a remote backend (mcp_http / api_rest / api_graphql)
the gateway is instructed to make outbound requests to a URL supplied by the
client. A malicious or careless value turns the gateway into a pivot into the
internal network (Server-Side Request Forgery) — e.g. reaching cloud metadata
services, private subnets, or localhost-only admin panels.

Policy enforced by ``validate_backend_url``:

1. Scheme must be ``https``. ``http`` is tolerated only when the target host
   itself is loopback (``localhost``, ``127.0.0.0/8``, ``::1``) so local
   development backends keep working.
2. The hostname is resolved via ``socket.getaddrinfo`` and EVERY resolved
   address must be public. Any address that is private, link-local, or cloud
   metadata causes rejection:
   10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 (incl. 169.254.169.254),
   ::1, fe80::/10, fc00::/7 and 0.0.0.0.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from typing import List, Tuple, Union

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Networks that must never be reachable through user-supplied backend URLs.
BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local, incl. metadata svc
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local
)

# Cloud metadata endpoint — covered by 169.254.0.0/16 but called out
# explicitly because it is the canonical SSRF exfiltration target.
METADATA_IP = ipaddress.ip_address("169.254.169.254")


def _unwrap_address(addr: IPAddress) -> IPAddress:
    """Collapse IPv4-mapped/translated IPv6 literals to their IPv4 form."""
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped or addr.sixtofour or addr.teredo
        if isinstance(mapped, ipaddress.IPv4Address):
            return mapped
    return addr


def is_blocked_ip(addr: IPAddress) -> bool:
    """Return True if *addr* is private/link-local/metadata (never allowed)."""
    addr = _unwrap_address(addr)
    for network in BLOCKED_NETWORKS:
        if addr.version == network.version and addr in network:
            return True
    return False


def is_loopback_host(host: str) -> bool:
    """True when *host* names the local machine (localhost / loopback literal)."""
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback


def resolve_host_ips(host: str) -> List[IPAddress]:
    """Resolve *host* to every IP address DNS reports for it."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def validate_backend_url(url: str) -> Tuple[bool, str]:
    """
    Validate a backend install URL against the SSRF policy.

    Returns:
        (is_valid, reason) — reason is an empty string when valid.
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return False, "URL could not be parsed"

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()  # hostname strips [] from IPv6

    if not scheme or not host:
        return False, "URL must include both a scheme and a hostname"

    # --- Scheme check -------------------------------------------------------
    if scheme != "https":
        if scheme == "http" and is_loopback_host(host):
            # Explicit carve-out: local dev backends may use plain http.
            return True, ""
        return False, (
            f"Scheme '{scheme}' is not allowed; backend URLs must use https "
            "(http is only permitted for loopback hosts)"
        )

    # --- Target check (https only reaches here) ------------------------------
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is not None:
        if is_loopback_host(host) or is_blocked_ip(addr):
            return False, f"Backend URL points at a blocked address ({host})"
        return True, ""

    # Hostname: resolve it; every reported address must be public.
    try:
        ips = resolve_host_ips(host)
    except socket.gaierror as exc:
        logger.warning("SSRF check: failed to resolve backend host %s (%s)", host, exc)
        return False, f"Could not resolve backend host '{host}'"
    except (OSError, UnicodeError) as exc:
        logger.warning("SSRF check: error resolving backend host %s (%s)", host, exc)
        return False, f"Could not resolve backend host '{host}'"

    if not ips:
        return False, f"Backend host '{host}' did not resolve to any address"

    blocked = [str(ip) for ip in ips if is_blocked_ip(ip)]
    if blocked:
        logger.warning(
            "SSRF check: rejected backend URL for %s — resolves to blocked IP(s) %s",
            host,
            ", ".join(blocked),
        )
        return False, (
            f"Backend host '{host}' resolves to a private/blocked "
            f"address ({blocked[0]})"
        )

    return True, ""
