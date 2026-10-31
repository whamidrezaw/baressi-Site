"""Fetching pages over plain HTTP (fast, light) or a stealth headless browser (robust).

* ``HttpFetcher`` — aiohttp with browser-like headers, conditional GET (ETag /
  Last-Modified), size limits and proper charset handling. A check takes ~0.2-1 s,
  so short intervals are cheap.
* ``BrowserFetcher`` — Patchright (undetected Playwright) driving real Chrome when
  installed, otherwise Chromium. Relaunches itself after crashes and periodically
  to keep memory in check, waits out bot-protection interstitials, and sends a
  User-Agent that matches the real browser version (no "HeadlessChrome").
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp

from .extract import INTERSTITIALS, detect_block
from .netguard import (
    MAX_REDIRECTS, REDIRECT_STATUSES, STRICT, BlockedAddress, GuardedResolver, UnsafeTarget, ensure_public_url,
    is_public_host, is_public_ip, redirect_url,
)
from .util import first_line

log = logging.getLogger("webmonitor")

MAX_BODY_BYTES = 15 * 1024 * 1024
MAX_FILE_BYTES = 40 * 1024 * 1024
LAUNCH_ARGS = ["--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check", "--disable-gpu"]
BLOCKED_RESOURCES = frozenset({"image", "media", "font"})
HAS_SOCKS = importlib.util.find_spec("aiohttp_socks") is not None  # SOCKS proxies for the plain HTTP engine


class FetchError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(message)
        self.kind = kind  # network | timeout | ssl | http | blocked | too_large | browser | unavailable
        self.status = status


async def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """True when something accepts TCP connections there (e.g. the Cloudflare WARP proxy)."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    text: str
    body: bytes
    engine: str
    etag: str | None = None
    last_modified: str | None = None
    content_length: int | None = None
    not_modified: bool = False
    elapsed: float = 0.0


# --------------------------------------------------------------------------- helpers

_HEADER_CHARSET = re.compile(r"charset\s*=\s*[\"']?([\w.:-]+)", re.I)
_META_CHARSET = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?\s*([\w.:-]+)", re.I)


def decode_body(body: bytes, content_type: str) -> str:
    """Decode like a browser: BOM, HTTP header, <meta charset>, then UTF-8 / Windows-1256."""
    candidates = []
    if body.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    match = _HEADER_CHARSET.search(content_type or "")
    if match:
        candidates.append(match.group(1))
    match = _META_CHARSET.search(body[:8192])
    if match:
        candidates.append(match.group(1).decode("ascii", "ignore"))
    candidates += ["utf-8", "cp1256"]  # cp1256: legacy Persian/Arabic sites
    for encoding in candidates:
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def is_textual(content_type: str, body: bytes) -> bool:
    ct = (content_type or "").lower()
    if any(t in ct for t in ("html", "xml", "text/", "json", "rss", "atom")):
        return True
    if ct:
        return False
    head = body[:512].lstrip().lower()
    return head.startswith((b"<!doctype", b"<html", b"<?xml", b"<rss", b"<feed", b"<head", b"<body"))


def browser_headers(user_agent: str, accept_language: str) -> dict:
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                  "image/apng,*/*;q=0.8",
        "Accept-Language": accept_language,
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    match = re.search(r"Chrome/(\d+)", user_agent)
    if match:
        major = match.group(1)
        platform = "Windows" if "Windows" in user_agent else "macOS" if "Mac OS X" in user_agent else "Linux"
        headers["Sec-CH-UA"] = f'"Google Chrome";v="{major}", "Chromium";v="{major}", "Not/A)Brand";v="24"'
        headers["Sec-CH-UA-Mobile"] = "?0"
        headers["Sec-CH-UA-Platform"] = f'"{platform}"'
    return headers


def build_user_agent(version: str) -> str:
    """A normal (non-headless) Chrome UA for the real browser version and host OS."""
    major = (version or "").split(".")[0] or "154"
    if sys.platform.startswith("win"):
        platform = "Windows NT 10.0; Win64; x64"
    elif sys.platform == "darwin":
        platform = "Macintosh; Intel Mac OS X 10_15_7"
    else:
        platform = "X11; Linux x86_64"
    return f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"


def _http_error(status: int, text: str) -> FetchError:
    hint = detect_block(text) if text else None
    message = f"HTTP {status}" + (f" — looks like {hint} bot protection" if hint else "")
    if hint == "Cloudflare Rate Limit":
        return FetchError("rate_limit", message + " (IP temporarily banned)", status)
    return FetchError("blocked" if hint else "http", message, status)


# --------------------------------------------------------------------------- HTTP

class HttpFetcher:
    engine = "http"
    available = True

    def __init__(self, config):
        self.config = config
        self.user_agent = config.user_agent
        self._session: aiohttp.ClientSession | None = None
        self._socks: dict[str, aiohttp.ClientSession] = {}

    def _new_session(self, connector=None) -> aiohttp.ClientSession:
        if connector is None:
            connector = aiohttp.TCPConnector(limit=self.config.max_concurrent_http, limit_per_host=4, ttl_dns_cache=300,
                                             resolver=GuardedResolver())
        return aiohttp.ClientSession(
            connector=connector,
            headers=browser_headers(self.user_agent, self.config.accept_language),
            cookie_jar=aiohttp.CookieJar(),
            timeout=aiohttp.ClientTimeout(total=120, sock_connect=20),
        )

    async def start(self) -> None:
        if self._session is None:
            self._session = self._new_session()

    async def close(self) -> None:
        for session in [self._session, *self._socks.values()]:
            if session is not None and not session.closed:
                await session.close()
        self._session = None
        self._socks.clear()

    def supports(self, watch) -> bool:
        """False for a SOCKS proxy while aiohttp-socks is missing (the other engines can still use it)."""
        proxy = watch.proxy or self.config.global_proxy
        return proxy is None or not proxy.scheme.startswith("socks") or HAS_SOCKS

    def _route(self, watch) -> tuple[aiohttp.ClientSession, str | None]:
        proxy = watch.proxy or self.config.global_proxy
        if proxy is None:
            return self._session, None
        if proxy.scheme.startswith("socks"):
            if not HAS_SOCKS:
                raise FetchError("unavailable", "SOCKS proxies need the aiohttp-socks package "
                                                "(pip install aiohttp-socks)")
            key = proxy.url_with_auth()
            if key not in self._socks:
                from aiohttp_socks import ProxyConnector
                self._socks[key] = self._new_session(ProxyConnector.from_url(key))
            return self._socks[key], None
        return self._session, proxy.url_with_auth()

    async def fetch(self, url: str, watch, *, conditional: dict | None = None, method: str = "GET",
                    max_bytes: int = MAX_BODY_BYTES) -> FetchResult:
        await self.start()
        session, proxy = self._route(watch)
        headers = dict(watch.headers)
        if conditional:
            if conditional.get("etag"):
                headers["If-None-Match"] = conditional["etag"]
            if conditional.get("last_modified"):
                headers["If-Modified-Since"] = conditional["last_modified"]
        started = time.monotonic()
        # A site decides where its redirects lead, so they are followed by hand and every hop is checked
        # (see netguard). Only watches that start on a public host are guarded: a target that is private on
        # purpose (a LAN device, a local test server) stays reachable. Through an HTTP proxy the connection
        # goes to the proxy, so the connect-time address check is skipped there.
        strict = await is_public_host(urlsplit(url).hostname or "")
        STRICT.set(strict and proxy is None)
        current = url
        try:
            for _hop in range(MAX_REDIRECTS + 1):
                remaining = watch.timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise asyncio.TimeoutError
                timeout = aiohttp.ClientTimeout(total=remaining, sock_connect=min(20.0, remaining))
                async with session.request(method, current, headers=headers, proxy=proxy, ssl=bool(watch.verify_ssl),
                                           allow_redirects=False, timeout=timeout) as resp:
                    location = resp.headers.get("Location")
                    if resp.status in REDIRECT_STATUSES and location:
                        current = redirect_url(str(resp.url), location)
                        if strict:
                            await ensure_public_url(current)
                        continue
                    status = resp.status
                    content_type = resp.headers.get("Content-Type", "")
                    etag = resp.headers.get("ETag")
                    last_modified = resp.headers.get("Last-Modified")
                    length = resp.headers.get("Content-Length")
                    length = int(length) if length and length.isdigit() else None
                    final_url = str(resp.url)
                    if status == 304:
                        return FetchResult(url, final_url, 304, content_type, "", b"", self.engine, etag, last_modified,
                                           length, not_modified=True, elapsed=time.monotonic() - started)
                    body = b"" if method == "HEAD" else await self._read(resp, max_bytes)
                break
            else:
                raise FetchError("http", "too many redirects")
        except FetchError:
            raise
        except UnsafeTarget as exc:
            raise FetchError("unsafe", str(exc)) from None
        except asyncio.TimeoutError:
            raise FetchError("timeout", f"timed out after {watch.timeout_seconds:g}s") from None
        except aiohttp.ClientSSLError as exc:
            raise FetchError("ssl", f"TLS/SSL error: {first_line(exc)}") from None
        except aiohttp.TooManyRedirects:
            raise FetchError("http", "too many redirects") from None
        except aiohttp.ClientResponseError as exc:
            raise FetchError("http", f"HTTP {exc.status} {exc.message}", exc.status) from None
        except aiohttp.ClientConnectorError as exc:
            if isinstance(getattr(exc, "os_error", None), BlockedAddress):
                raise FetchError("unsafe", str(exc.os_error)) from None
            raise FetchError("network", f"{type(exc).__name__}: {first_line(exc)}") from None
        except aiohttp.ClientError as exc:
            raise FetchError("network", f"{type(exc).__name__}: {first_line(exc)}") from None
        except ValueError as exc:
            raise FetchError("network", f"invalid request: {exc}") from None
        text = decode_body(body, content_type) if body and is_textual(content_type, body) else ""
        if status >= 400:
            raise _http_error(status, text)
        return FetchResult(url, final_url, status, content_type, text, body, self.engine, etag, last_modified,
                           length if length is not None else (len(body) if method != "HEAD" else None),
                           elapsed=time.monotonic() - started)

    @staticmethod
    async def _read(resp: aiohttp.ClientResponse, max_bytes: int) -> bytes:
        chunks, size = [], 0
        async for chunk in resp.content.iter_chunked(65536):
            size += len(chunk)
            if size > max_bytes:
                raise FetchError("too_large", f"response is larger than {max_bytes // (1024 * 1024)} MB")
            chunks.append(chunk)
        return b"".join(chunks)


# --------------------------------------------------------------------------- impersonation

def _curl_error(exc: BaseException, timeout: float) -> FetchError:
    message = first_line(exc, 250)
    lowered = message.lower()
    if "timed out" in lowered or "timeout" in lowered:
        return FetchError("timeout", f"timed out after {timeout:g}s")
    if "ssl" in lowered or "certificate" in lowered or "tls" in lowered:
        return FetchError("ssl", f"TLS/SSL error: {message}")
    return FetchError("network", message)


class ImpersonateFetcher:
    """HTTP with a real Chrome TLS/HTTP2 fingerprint (curl_cffi).

    Bot walls such as Akamai and Cloudflare reject ordinary HTTP clients by their TLS
    fingerprint; this engine looks like a current Chrome to them while staying as fast and
    light as plain HTTP (no browser). Cookies are kept per session, like a returning visitor.
    """

    engine = "impersonate"

    def __init__(self, config):
        self.config = config
        self.target = config.impersonate or "chrome"
        self._sessions: dict[str | None, object] = {}
        self.sessions_dir = config.data_dir / "sessions-impersonate"
        self.unavailable: str | None = None
        if importlib.util.find_spec("curl_cffi") is None:
            self.unavailable = "curl_cffi is not installed (pip install curl_cffi)"

    @property
    def available(self) -> bool:
        return self.unavailable is None

    def supports(self, watch) -> bool:
        return self.available

    def _session(self, watch, proxy_url: str | None):
        """Session for a watch. With persist_session=True the watch gets its own session
        and a cookie file; otherwise all watches share one session per proxy."""
        key = f"persist:{watch.id}:{proxy_url or ''}" if watch.persist_session else proxy_url
        session = self._sessions.get(key)
        if session is None:
            from curl_cffi.requests import AsyncSession
            session = AsyncSession(impersonate=self.target, proxy=proxy_url,
                                   max_clients=self.config.max_concurrent_http)
            self._sessions[key] = session
            if watch.persist_session:
                self._load_cookies(session, watch)
        return session

    def _session_file(self, watch) -> Path:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        return self.sessions_dir / f"{watch.id}.json"

    def _load_cookies(self, session, watch) -> None:
        path = self._session_file(watch)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        cookies = getattr(session, "cookies", None)
        if cookies is None:
            return
        for name, value in data.items():
            try:
                cookies[str(name)] = str(value)
            except Exception:
                log.debug("impersonate: could not restore cookie %r for %s", name, watch.id)

    def _save_cookies(self, session, watch) -> None:
        cookies = getattr(session, "cookies", None)
        if cookies is None:
            return
        data: dict = {}
        try:
            if hasattr(cookies, "items"):
                for name, value in cookies.items():
                    data[str(name)] = str(value)
            else:
                for cookie in cookies:
                    data[str(cookie.name)] = str(cookie.value)
        except Exception:
            return
        if not data:
            return
        try:
            self._session_file(watch).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            log.debug("impersonate: could not persist cookies for %s", watch.id, exc_info=True)

    async def close(self) -> None:
        for session in self._sessions.values():
            try:
                await session.close()
            except Exception:
                pass
        self._sessions.clear()

    async def fetch(self, url: str, watch, *, conditional: dict | None = None, method: str = "GET",
                    max_bytes: int = MAX_BODY_BYTES) -> FetchResult:
        if self.unavailable:
            raise FetchError("unavailable", self.unavailable)
        proxy = watch.proxy or self.config.global_proxy
        session = self._session(watch, proxy.url_with_auth() if proxy else None)
        headers = {"Accept-Language": self.config.accept_language, **watch.headers}
        if conditional:
            if conditional.get("etag"):
                headers["If-None-Match"] = conditional["etag"]
            if conditional.get("last_modified"):
                headers["If-Modified-Since"] = conditional["last_modified"]
        started = time.monotonic()
        strict = await is_public_host(urlsplit(url).hostname or "")  # see HttpFetcher.fetch / netguard
        current = url
        try:
            for _hop in range(MAX_REDIRECTS + 1):
                remaining = watch.timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise FetchError("timeout", f"timed out after {watch.timeout_seconds:g}s")
                resp = await session.request(method, current, headers=headers, timeout=remaining,
                                             allow_redirects=False, verify=bool(watch.verify_ssl))
                if strict and proxy is None:
                    peer = getattr(resp, "primary_ip", "") or ""
                    if peer and not is_public_ip(peer):
                        raise FetchError("unsafe", f"the connection ended on a non-public address ({peer})")
                location = resp.headers.get("location")
                if resp.status_code in REDIRECT_STATUSES and location:
                    current = redirect_url(str(resp.url), location)
                    if strict:
                        await ensure_public_url(current)
                    continue
                break
            else:
                raise FetchError("http", "too many redirects")
        except FetchError:
            raise
        except UnsafeTarget as exc:
            raise FetchError("unsafe", str(exc)) from None
        except Exception as exc:  # curl_cffi.requests.errors.RequestsError and friends
            raise _curl_error(exc, watch.timeout_seconds) from None
        status = resp.status_code
        content_type = resp.headers.get("content-type", "") or ""
        etag, last_modified = resp.headers.get("etag"), resp.headers.get("last-modified")
        if status == 304:
            return FetchResult(url, str(resp.url), 304, content_type, "", b"", self.engine, etag, last_modified,
                               not_modified=True, elapsed=time.monotonic() - started)
        cl = resp.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_bytes:
            raise FetchError("too_large", f"response is larger than {max_bytes // (1024 * 1024)} MB")
        body = b"" if method == "HEAD" else (resp.content or b"")
        if len(body) > max_bytes:
            raise FetchError("too_large", f"response is larger than {max_bytes // (1024 * 1024)} MB")
        text = decode_body(body, content_type) if body and is_textual(content_type, body) else ""
        if status >= 400:
            raise _http_error(status, text)
        if watch.persist_session:
            self._save_cookies(session, watch)
        return FetchResult(url, str(resp.url), status, content_type, text, body, self.engine, etag, last_modified,
                           len(body) if method != "HEAD" else None, elapsed=time.monotonic() - started)


# --------------------------------------------------------------------------- challenge browser

class ChallengeBrowser:
    """A live Playwright context for solving a bot wall by hand.

    Owned by the ChallengeManager for the duration of one challenge. Frames,
    clicks, typing and key presses are forwarded from the admin's browser to
    this context. On "done", the resulting storage_state is returned as bytes.
    """

    def __init__(self, fetcher: "BrowserFetcher", context, page, watch, url: str):
        self._fetcher = fetcher
        self._context = context
        self._page = page
        self.watch = watch
        self.url = url
        self._closed = False

    async def goto_and_settle(self) -> None:
        try:
            await self._page.goto(self.url, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            pass  # the page may be a challenge interstitial that blocks navigation
        # Let JS / CAPTCHA render before attempting auto-click and capturing first frame.
        try:
            await self._page.wait_for_timeout(1200)
            await self._fetcher._try_solve_interstitial(self._page)
            await self._page.wait_for_timeout(1000)
        except Exception:
            pass

    async def click_turnstile(self) -> bool:
        if self._closed:
            return False
        try:
            clicked = await self._fetcher._try_solve_interstitial(self._page, force_Fallback_click=True)
            await self._page.wait_for_timeout(1500)
            return clicked
        except Exception:
            return False

    async def frame(self) -> bytes:
        if self._closed:
            return b""
        try:
            return await self._page.screenshot(type="jpeg", quality=75, full_page=False)
        except Exception:
            return b""

    async def click(self, x: float, y: float) -> None:
        if self._closed:
            return
        await self._page.mouse.click(float(x), float(y))

    async def type(self, text: str) -> None:
        if self._closed:
            return
        await self._page.keyboard.type(text, delay=30)

    async def key(self, name: str) -> None:
        if self._closed:
            return
        await self._page.keyboard.press(name)

    async def done(self) -> bytes | None:
        """Save the current cookies (storage_state) as JSON bytes."""
        if self._closed:
            return None
        try:
            state = await self._context.storage_state()
        except Exception:
            return None
        import json as _json
        return _json.dumps(state, ensure_ascii=False).encode("utf-8")

    async def cancel(self) -> None:
        """Nothing to save; the caller will close the context."""

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if getattr(self._fetcher, "_active", 0) > 0:
            self._fetcher._active -= 1
        try:
            await self._context.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- browser

async def _block_heavy(route) -> None:
    try:
        if route.request.resource_type in BLOCKED_RESOURCES:
            await route.abort()
        else:
            await route.continue_()
    except Exception:  # page already closed, request already handled, ...
        pass


def _classify(exc: BaseException, timeout: float) -> FetchError:
    name = type(exc).__name__
    message = first_line(exc, 250)
    if "Timeout" in name:
        return FetchError("timeout", f"browser timed out after {timeout:g}s")
    if "ERR_CERT" in message or "SSL" in message:
        return FetchError("ssl", message)
    if "net::ERR" in message:
        return FetchError("network", message)
    return FetchError("browser", message)


class BrowserFetcher:
    engine = "browser"

    def __init__(self, config):
        self.config = config
        self.cfg = config.browser
        self.sessions_dir = config.data_dir / "sessions"
        self.user_agent: str | None = None
        self.version: str | None = None
        self.channel: str | None = None
        self.flavor = ""
        self.unavailable: str | None = None
        self._pw = None
        self._browser = None
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(self.cfg.max_pages)
        self._uses = 0
        self._active = 0

    @property
    def available(self) -> bool:
        return self.unavailable is None

    def supports(self, watch) -> bool:
        return self.available

    def _session_file(self, watch):
        return self.sessions_dir / f"{watch.id}.json"

    async def _ensure(self):
        async with self._lock:
            browser = self._browser
            if browser is not None and browser.is_connected():
                if self._uses < self.cfg.restart_every or self._active > 0:
                    return browser
                log.info("Recycling the browser after %d page loads", self._uses)
            elif browser is not None:
                log.warning("Browser connection lost; relaunching")
            await self._close_browser()
            self._browser = await self._launch()
            self._uses = 0
            return self._browser

    async def _launch(self):
        if self._pw is None:
            try:
                from patchright.async_api import async_playwright
                self.flavor = "patchright"
            except ImportError:
                try:
                    from playwright.async_api import async_playwright
                    self.flavor = "playwright"
                except ImportError:
                    self.unavailable = "patchright is not installed (pip install patchright)"
                    raise FetchError("browser", self.unavailable) from None
            self._pw = await async_playwright().start()
        channels: list[str] = []
        for channel in (self.cfg.channel, "chrome", "chromium", ""):
            if channel not in channels:
                channels.append(channel)
        errors = []
        for channel in channels:
            options = {"headless": self.cfg.headless, "args": LAUNCH_ARGS}
            if channel:
                options["channel"] = channel
            if self.config.global_proxy:
                options["proxy"] = self.config.global_proxy.for_playwright()
            try:
                browser = await self._pw.chromium.launch(**options)
            except Exception as exc:
                errors.append(f"{channel or 'bundled'}: {first_line(exc, 160)}")
                continue
            self.version = browser.version
            self.channel = channel or "bundled"
            self.user_agent = self.cfg.user_agent or build_user_agent(browser.version)
            self.unavailable = None
            log.info("Browser ready: %s %s (channel=%s, headless=%s)",
                     self.flavor, browser.version, self.channel, self.cfg.headless)
            return browser
        self.unavailable = ("no browser could be launched (" + " | ".join(errors) + "). "
                            "Install one with: patchright install chromium")
        raise FetchError("browser", self.unavailable)

    def _context_options(self, watch) -> dict:
        locale = self.config.accept_language.split(",")[0].split(";")[0].strip() or "en-US"
        options = {"locale": locale, "ignore_https_errors": not watch.verify_ssl}
        if self.cfg.headless:
            options["user_agent"] = self.user_agent
            options["viewport"] = {"width": 1366, "height": 900}
        else:
            options["no_viewport"] = True
        if watch.headers:
            options["extra_http_headers"] = dict(watch.headers)
        if watch.proxy:
            options["proxy"] = watch.proxy.for_playwright()
        if (watch.persist_session or self._session_file(watch).exists()) and self._session_file(watch).exists():
            options["storage_state"] = str(self._session_file(watch))
        return options

    async def fetch(self, url: str, watch, *, wait_for: str = "") -> FetchResult:
        async with self._sem:
            browser = await self._ensure()
            self._active += 1
            self._uses += 1
            started = time.monotonic()
            context = None
            try:
                status, content_type, text, body, final_url = await self._fetch_once(
                    browser, url, watch, wait_for=wait_for, block_resources=self.cfg.block_resources
                )
                # If resource blocking caused a Cloudflare/CAPTCHA interstitial to fail, retry once unblocked
                if self.cfg.block_resources and (status in (403, 503) or detect_block(text) is not None):
                    log.info("[%s] retrying browser fetch without resource blocking to solve interstitial", watch.id)
                    status, content_type, text, body, final_url = await self._fetch_once(
                        browser, url, watch, wait_for=wait_for, block_resources=False, persist_always=True
                    )
                if status >= 400:
                    raise _http_error(status, text)
                return FetchResult(url, final_url, status, content_type, text, body, self.engine,
                                   elapsed=time.monotonic() - started)
            except FetchError:
                raise
            except Exception as exc:
                raise _classify(exc, watch.timeout_seconds) from None
            finally:
                self._active -= 1
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def _fetch_once(self, browser, url: str, watch, *, wait_for: str = "",
                          block_resources: bool = True, persist_always: bool = False):
        context = None
        try:
            context = await browser.new_context(**self._context_options(watch))
            context.set_default_timeout(watch.timeout_seconds * 1000)
            if block_resources:
                await context.route("**/*", _block_heavy)
            page = await context.new_page()
            last: dict = {"response": None}

            def on_response(response) -> None:
                try:
                    if response.request.resource_type == "document" and response.frame == page.main_frame:
                        last["response"] = response
                except Exception:
                    pass

            page.on("response", on_response)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=watch.timeout_seconds * 1000)
            if last["response"] is None:
                last["response"] = response
            await self._settle(page, watch, wait_for)
            main = last["response"]
            status = main.status if main is not None else 200
            content_type = (main.headers.get("content-type", "") if main is not None else "") or "text/html"
            if main is not None and "html" not in content_type.lower():
                body = await main.body()
                text = decode_body(body, content_type)
            else:
                body = b""
                text = await self._content(page)
            if (watch.persist_session or persist_always) and status < 400 and detect_block(text) is None:
                self.sessions_dir.mkdir(parents=True, exist_ok=True)
                await context.storage_state(path=str(self._session_file(watch)))
            return status, content_type, text, body, page.url
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass

    async def screenshot(self, url: str, watch, *, selector: str = "", max_height: int = 3600) -> bytes:
        """JPEG of the page as this server sees it (images and fonts loaded); only the monitored
        element when ``selector`` is found. Error pages are captured too — they show what blocks us."""
        async with self._sem:
            browser = await self._ensure()
            self._active += 1
            self._uses += 1
            context = None
            try:
                options = self._context_options(watch)
                options.pop("no_viewport", None)
                options["viewport"] = {"width": 1280, "height": 900}
                options["user_agent"] = self.user_agent
                context = await browser.new_context(**options)
                context.set_default_timeout(watch.timeout_seconds * 1000)
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=watch.timeout_seconds * 1000)
                await self._settle(page, watch, selector)
                try:
                    await page.wait_for_load_state("load", timeout=8000)
                except Exception:
                    pass
                clip = None
                if selector:
                    element = await page.query_selector(selector)
                    box = await element.bounding_box() if element is not None else None
                    if box and box["width"] > 0 and box["height"] > 0:
                        clip = {"x": max(0.0, box["x"] - 8), "y": max(0.0, box["y"] - 8),
                                "width": min(1280.0, box["width"] + 16), "height": min(max_height, box["height"] + 16)}
                if clip is None:
                    height = await page.evaluate("document.documentElement.scrollHeight || document.body.scrollHeight")
                    clip = {"x": 0, "y": 0, "width": 1280, "height": max(400, min(int(height or 900), max_height))}
                return await page.screenshot(type="jpeg", quality=80, full_page=True, clip=clip)
            except FetchError:
                raise
            except Exception as exc:
                raise _classify(exc, watch.timeout_seconds) from None
            finally:
                self._active -= 1
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def open_challenge(self, url: str, watch) -> ChallengeBrowser:
        """Open a live context for the admin to solve a bot wall.

        Uses the same proxy / locale as the watch, but does *not* block resources
        (CAPTCHA images must load). storage_state is loaded if present.
        """
        browser = await self._ensure()
        self._active += 1
        self._uses += 1
        context = None
        try:
            options = self._context_options(watch)
            # Start with a fresh, interactive viewport.
            options.pop("no_viewport", None)
            options["viewport"] = {"width": 1280, "height": 900}
            options["user_agent"] = self.user_agent
            context = await browser.new_context(**options)
            context.set_default_timeout(90000)
            page = await context.new_page()
            cb = ChallengeBrowser(self, context, page, watch, url)
            await cb.goto_and_settle()
            return cb
        except Exception:
            self._active = max(0, self._active - 1)
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            raise

    def save_storage_state(self, watch, state: bytes) -> None:
        """Persist the storage_state produced by a solved challenge."""
        path = self._session_file(watch)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_bytes(state)
            tmp.replace(path)
        except OSError:
            log.debug("could not save storage_state to %s", path, exc_info=True)

    async def _try_solve_interstitial(self, page, *, force_Fallback_click: bool = False) -> bool:
        """Attempt to automatically click Cloudflare Turnstile / interstitial checkboxes."""
        clicked = False
        try:
            await page.mouse.move(220, 260, steps=4)
        except Exception:
            pass
        # 1. Check child frames for Cloudflare / Turnstile widgets
        for frame in getattr(page, "frames", ()):
            furl = (getattr(frame, "url", "") or "").lower()
            if any(k in furl for k in ("challenges.cloudflare.com", "turnstile", "cf-chl", "arkoselabs", "hcaptcha")):
                for sel in ("input[type='checkbox']", ".cb-lb", "label", "#challenge-stage", "body"):
                    try:
                        el = await frame.query_selector(sel)
                        if el is not None:
                            box = await el.bounding_box()
                            if box and box["width"] > 0 and box["height"] > 0:
                                await page.mouse.click(box["x"] + min(28.0, box["width"] / 2),
                                                       box["y"] + box["height"] / 2)
                                clicked = True
                                break
                    except Exception:
                        continue
                if not clicked and hasattr(frame, "frame_element"):
                    try:
                        el = await frame.frame_element()
                        if el is not None:
                            box = await el.bounding_box()
                            if box and box["width"] > 0 and box["height"] > 0:
                                await page.mouse.click(box["x"] + min(28.0, box["width"] / 2),
                                                       box["y"] + box["height"] / 2)
                                clicked = True
                                break
                    except Exception:
                        pass
        # 2. Check main document for Turnstile / Cloudflare containers
        if not clicked:
            for sel in (
                "iframe[src*='challenges.cloudflare.com']",
                "iframe[src*='turnstile']",
                "#turnstile-wrapper",
                "#cf-turnstile",
                ".cf-turnstile",
                "#challenge-stage",
                "button#challenge-submit",
                "input[type='button'][value*='Verify']",
            ):
                try:
                    el = await page.query_selector(sel)
                    if el is not None:
                        box = await el.bounding_box()
                        if box and box["width"] > 0 and box["height"] > 0:
                            await page.mouse.click(box["x"] + min(28.0, box["width"] / 2),
                                                   box["y"] + box["height"] / 2)
                            clicked = True
                            break
                except Exception:
                    continue
        if not clicked and force_Fallback_click:
            # Typical Cloudflare Turnstile checkbox position on 1280x900 viewport
            for cx, cy in ((210, 290), (210, 340), (510, 290)):
                try:
                    await page.mouse.click(cx, cy)
                    clicked = True
                except Exception:
                    pass
        return clicked

    async def _settle(self, page, watch, wait_for: str) -> None:
        """Wait out bot interstitials (and auto-click Turnstile), then for the monitored element."""
        deadline = time.monotonic() + watch.challenge_wait_seconds
        tried_click = False
        while time.monotonic() < deadline:
            html = await self._content(page)
            block_kind = detect_block(html, include_js=False)
            if block_kind is None:
                break
            if wait_for and await page.query_selector(wait_for) is not None:
                break
            if not tried_click or block_kind in ("Cloudflare", "CAPTCHA"):
                await self._try_solve_interstitial(page)
                tried_click = True
            if block_kind not in INTERSTITIALS and block_kind not in ("Cloudflare",):
                break
            await page.wait_for_timeout(1200)
        if wait_for:
            try:
                await page.wait_for_selector(wait_for, state="attached",
                                             timeout=min(15000, watch.timeout_seconds * 1000))
            except Exception:
                pass  # reported later as "selector matched nothing"
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass  # pages with endless background requests never become idle
        if watch.wait_ms:
            await page.wait_for_timeout(watch.wait_ms)

    @staticmethod
    async def _content(page) -> str:
        for attempt in range(6):
            try:
                return await page.content()
            except Exception:  # navigation in progress
                if attempt == 5:
                    raise
                await asyncio.sleep(0.5)
        return ""

    async def _close_browser(self) -> None:
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

    def import_cookies(self, watch, raw_text: str) -> int:
        """Import cookies from JSON (storage_state / Cookie-Editor list / dict) or 'k=v; k2=v2' header."""
        from urllib.parse import urlsplit
        raw_text = (raw_text or "").strip()
        if not raw_text:
            return 0
        host = (urlsplit(watch.url).hostname or "").lstrip(".")
        if not host:
            return 0
        pw_cookies: list[dict] = []
        flat_cookies: dict[str, str] = {}
        try:
            parsed = json.loads(raw_text)
        except Exception:
            parsed = None

        if isinstance(parsed, dict) and isinstance(parsed.get("cookies"), list):
            parsed = parsed["cookies"]

        if isinstance(parsed, list):
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                value = str(item.get("value") or "")
                if not name:
                    continue
                domain = str(item.get("domain") or f".{host}").strip()
                path = str(item.get("path") or "/").strip() or "/"
                pw_cookies.append({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": path,
                    "expires": float(item.get("expirationDate") or item.get("expires") or -1),
                    "httpOnly": bool(item.get("httpOnly", False)),
                    "secure": bool(item.get("secure", True)),
                    "sameSite": "Lax",
                })
                flat_cookies[name] = value
        elif isinstance(parsed, dict):
            for k, v in parsed.items():
                name = str(k).strip()
                if not name:
                    continue
                value = str(v)
                pw_cookies.append({
                    "name": name,
                    "value": value,
                    "domain": f".{host}",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": False,
                    "secure": True,
                    "sameSite": "Lax",
                })
                flat_cookies[name] = value
        else:
            # Parse 'Cookie: a=b; c=d' or Netscape tab-separated lines
            raw_clean = re.sub(r"(?i)^cookie\s*:\s*", "", raw_text)
            for line in raw_clean.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "\t" in line:
                    parts = line.split("\t")
                    if len(parts) >= 7:
                        name, value = parts[5].strip(), parts[6].strip()
                        if name:
                            pw_cookies.append({
                                "name": name, "value": value, "domain": parts[0].strip() or f".{host}",
                                "path": parts[2].strip() or "/", "expires": -1,
                                "httpOnly": False, "secure": True, "sameSite": "Lax",
                            })
                            flat_cookies[name] = value
                        continue
                for pair in line.split(";"):
                    if "=" not in pair:
                        continue
                    k, v = pair.split("=", 1)
                    name, value = k.strip(), v.strip()
                    if name:
                        pw_cookies.append({
                            "name": name, "value": value, "domain": f".{host}", "path": "/",
                            "expires": -1, "httpOnly": False, "secure": True, "sameSite": "Lax",
                        })
                        flat_cookies[name] = value

        if not pw_cookies:
            return 0
        state_bytes = json.dumps({"cookies": pw_cookies, "origins": []}, ensure_ascii=False).encode("utf-8")
        self.save_storage_state(watch, state_bytes)
        imp_dir = self.config.data_dir / "sessions-impersonate"
        imp_dir.mkdir(parents=True, exist_ok=True)
        try:
            (imp_dir / f"{watch.id}.json").write_text(json.dumps(flat_cookies, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
        return len(pw_cookies)

    async def close(self) -> None:
        async with self._lock:
            await self._close_browser()
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:
                pass
            self._pw = None

