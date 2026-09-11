"""
SSRF (Server-Side Request Forgery) protection utilities.

If/when server-side URL fetching is enabled (e.g. for future reputation
checks), any target host MUST be validated with `is_safe_host` first.
This module intentionally blocks localhost, private/internal ranges,
link-local addresses, and common cloud metadata endpoints.
"""
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
}

# Cloud metadata endpoints
BLOCKED_IPS = {
    "169.254.169.254",  # AWS / Azure / GCP metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # if we can't parse it, treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_safe_host(url: str) -> bool:
    """
    Returns True only if the URL's host resolves to a public, non-internal
    address and uses an allowed scheme. Used to prevent SSRF if/when the
    server ever fetches a URL on the user's behalf.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    hostname_lower = hostname.lower()
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False

    if hostname_lower in BLOCKED_IPS:
        return False

    # If the hostname is itself an IP literal, check directly
    try:
        ipaddress.ip_address(hostname_lower)
        return not _is_private_ip(hostname_lower) and hostname_lower not in BLOCKED_IPS
    except ValueError:
        pass  # not an IP literal, need DNS resolution

    # Resolve DNS and check all resolved addresses
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in addr_infos:
        ip_str = info[4][0]
        if _is_private_ip(ip_str) or ip_str in BLOCKED_IPS:
            return False

    return True
