"""Guards that keep server-side fetches away from internal addresses (SSRF).

An admin chooses the URL of a watch, but the *site* behind it decides where its redirects lead and which
address its name resolves to. Without a guard a hostile (or hijacked) site could point the monitor at the
server's own loopback services or at the cloud metadata endpoint and have the answer forwarded to Telegram.

The guard is applied per fetch, and only to watches that start on a public host - a target that is private
on purpose (a LAN device, a local test server) is left alone:

* every redirect hop is checked before it is followed (``ensure_public_url``);
* the plain HTTP engine also checks the addresses a name resolves to at connect time
  (``GuardedResolver``), which closes the gap between "checked" and "connected" (DNS rebinding);
* the Chrome-impersonation engine compares the address it actually connected to (``primary_ip``).
"""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 10

# True while the current fetch must not reach non-public addresses. It is set per fetch and read by the
# resolver, which runs inside the same task, so concurrent fetches of other watches are not affected.
STRICT: contextvars.ContextVar[bool] = contextvars.ContextVar("webmonitor_strict_fetch", default=False)


class UnsafeTarget(Exception):
    """A request (or one of its redirects) would end on a non-public address."""


class BlockedAddress(OSError):
    """Raised by the resolver when a name resolves to a non-public address."""


def is_public_ip(address: str) -> bool:
    """True for a globally routable address; False for loopback, private, link-local, ... or garbage."""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:127.0.0.1 is loopback, whatever the IPv6 wrapper says
    return (mapped or ip).is_global


async def is_public_host(host: str) -> bool:
    """False for loopback / private / link-local addresses (protects the server's internal network)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return True  # unresolvable: the fetch itself reports a clear error
    for info in infos:
        try:
            ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            continue
        if not is_public_ip(info[4][0]):
            return False
    return True


async def ensure_public_url(url: str) -> None:
    """Raise ``UnsafeTarget`` unless ``url`` is an http(s) URL on a public host."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTarget(f"redirect to an unsupported address ({url[:80]})")
    if not await is_public_host(parts.hostname):
        raise UnsafeTarget(f"redirect to a non-public address ({parts.hostname})")


def redirect_url(base: str, location: str) -> str:
    """The absolute URL a ``Location`` header points to."""
    return urljoin(base, location.strip())


class GuardedResolver(AbstractResolver):
    """aiohttp resolver that refuses non-public addresses while ``STRICT`` is set for the current fetch."""

    def __init__(self) -> None:
        self._inner = aiohttp.DefaultResolver()

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        infos = await self._inner.resolve(host, port, family)
        if STRICT.get():
            for info in infos:
                if not is_public_ip(info["host"]):
                    raise BlockedAddress(f"{host} resolves to a non-public address ({info['host']})")
        return infos

    async def close(self) -> None:
        await self._inner.close()
