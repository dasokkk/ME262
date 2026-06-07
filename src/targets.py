"""
Target expansion and resolution.

Turns a user target spec (hostname, IPv4/IPv6 address, CIDR range, or a
comma-separated mix) into a deduplicated, ordered list of resolved IP strings
the scanner can craft packets against.
"""

import ipaddress
import socket
from typing import List


def _resolve_hostname(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def _expand_token(token: str) -> List[str]:
    token = token.strip()
    if not token:
        return []

    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return []
        if net.num_addresses > 2:
            return [str(h) for h in net.hosts()]
        return [str(h) for h in net]

    try:
        return [str(ipaddress.ip_address(token))]
    except ValueError:
        return _resolve_hostname(token)


def expand_targets(spec: str) -> List[str]:
    """Expand a target spec into an ordered, deduplicated list of IP strings."""
    result: List[str] = []
    for token in spec.split(","):
        for ip in _expand_token(token):
            if ip not in result:
                result.append(ip)
    return result


def resolve_one(host: str) -> str:
    """Resolve a single host/IP to one IP string, falling back to the input."""
    ips = _expand_token(host)
    return ips[0] if ips else host


def is_single_host(spec: str) -> bool:
    """True when the spec is one token without a CIDR range."""
    tokens = [t for t in spec.split(",") if t.strip()]
    return len(tokens) == 1 and "/" not in tokens[0]
