"""Scope guard: keep the exploit pointed at the lab by default.

The runner refuses targets that resolve to public addresses unless the operator
passes ``--allow-public``. Resolution happens once and the resulting address is
pinned by the HTTP client, so a DNS answer cannot change between the check and
the connection (no DNS-rebinding gap).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple


class ScopeError(RuntimeError):
    """Target is outside the authorised scope."""


@dataclass(frozen=True)
class Resolution:
    host: str
    port: int
    addresses: Tuple[str, ...]

    @property
    def primary(self) -> str:
        return self.addresses[0]

    @property
    def is_loopback(self) -> bool:
        try:
            return ipaddress.ip_address(_strip_zone(self.primary)).is_loopback
        except ValueError:
            return False


def _strip_zone(address: str) -> str:
    return address.split("%", 1)[0]


def classify(address: str) -> str:
    """Return a human-readable class for an IP address."""
    try:
        ip = ipaddress.ip_address(_strip_zone(address))
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "public"
    return "non-global"


def resolve(host: str, port: int = 80) -> Resolution:
    """Resolve a host to a stable, IPv4-first address list."""
    if not (1 <= port <= 65535):
        raise ScopeError("port out of range: {}".format(port))
    if not host:
        raise ScopeError("empty host")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError("cannot resolve {}: {}".format(host, exc)) from exc

    seen = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    if not seen:
        raise ScopeError("no addresses for {}".format(host))

    # The lab publishes on 127.0.0.1; prefer IPv4 when localhost resolves to
    # both ::1 and 127.0.0.1.
    seen.sort(key=lambda value: 1 if ":" in value else 0)
    return Resolution(host=host, port=port, addresses=tuple(seen))


def is_local_target(host: str, port: int = 80) -> bool:
    try:
        return resolve(host, port).is_loopback
    except ScopeError:
        return False


def assert_in_scope(
    host: str,
    port: int = 80,
    allow_public: bool = False,
    allow_hosts: Sequence[str] = (),
) -> Resolution:
    """Validate a target host, returning the pinned resolution.

    ``allow_hosts`` is an explicit operator allowlist (exact host match). It
    exists for unusual lab setups; ``allow_public`` is the broad escape hatch.
    """
    resolution = resolve(host, port)
    allowed = {value.strip().lower() for value in allow_hosts if value.strip()}
    if host.lower() in allowed:
        return resolution

    for address in resolution.addresses:
        kind = classify(address)
        if kind in ("invalid", "multicast", "unspecified"):
            raise ScopeError(
                "refusing target {} ({} resolves to {})".format(host, address, kind)
            )
        if kind == "public" and not allow_public:
            raise ScopeError(
                "refusing public target {} ({}); this PoC is lab-only. "
                "Pass --allow-public only for systems you are authorised to test."
                .format(host, address)
            )
    return resolution


def describe_target(host: str, port: int, resolution: Optional[Resolution] = None) -> str:
    resolution = resolution or resolve(host, port)
    kinds = sorted({classify(address) for address in resolution.addresses})
    return "{}:{} [{}]".format(host, port, ", ".join(kinds))


def iter_addresses(resolution: Resolution) -> Iterable[str]:
    return iter(resolution.addresses)
