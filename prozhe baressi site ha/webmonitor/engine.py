"""The monitoring engine: schedules checks, detects changes and delivers notifications."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import re
import time
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlsplit, urlunsplit

import aiohttp

from . import report
from .config import ConfigError, Proxy, Watch
from .extract import (
    ASSET_EXTENSIONS, FILE_EXTENSIONS, ExtractError, Snapshot, detect_block, document_base, extract_headlines,
    extract_items, extract_links, json_snapshot, looks_like_feed, normalize_url, page_snapshot, parse_feed,
    parse_html, parse_json_body, same_site, suggest_selector, url_extension, visible_text_length,
)
from .challenge import ChallengeManager
from .fetchers import MAX_FILE_BYTES, BrowserFetcher, FetchError, HttpFetcher, ImpersonateFetcher, port_open
from .health import build_health
from .notifier import (
    ConsoleNotifier, NotifyError, TelegramApiError, TelegramNotifier, build_parts, explain_telegram_error,
)
from .registry import WatchRegistry
from .storage import Store
from .util import (
    esc, fa_datetime, fa_digits, fa_elapsed, fa_number, find_keywords, human_duration, load_timezone, sha256_text,
    truncate,
)

log = logging.getLogger("webmonitor")

EXTRACTOR_VERSION = 2           # bump to silently re-baseline after extraction changes
DIGESTABLE = {"change", "new_page", "removed_page", "file", "new_items"}
SWITCH_STATUSES = {401, 403, 406, 429, 503}
SYSTEM = "_system"
_CRAWL_SKIP = re.compile(r"/(log-?out|sign-?out|log-?off)\b|[?&](print|share|replytocom|format)=", re.I)
# Telegram 400 errors caused by the message itself (retrying the same message cannot help)
_CONTENT_ERROR = re.compile(r"too long|parse|entit|text is empty|caption|file|document|button|markup", re.I)
TYPE_LABELS = {"page": "صفحه", "headlines": "تیترهای جدید", "items": "فهرست اطلاعیه‌ها", "feed": "خبرخوان RSS",
               "json": "داده (API)"}
TYPE_ICONS = {"page": "📄", "headlines": "📰", "items": "📌", "feed": "📡", "json": "🎓"}
ENGINE_LABELS = {"http": "سریع (HTTP)", "impersonate": "شبیه‌ساز کروم", "browser": "مرورگر"}
ALARM_ROUNDS = 6        # wake-up mode: urgent private alerts repeated until acknowledged
ALARM_INTERVAL = 45     # seconds between repeats
BACKOFF_CAP = 1800      # longest wait between checks of a failing site
HEARTBEAT_EVERY = 300           # seconds between pings of the external heartbeat URL
HEARTBEAT_OUTBOX_STALE = 1800   # no ping while a due notification has been waiting this long (alerts are stuck)
BACKUP_EVERY = 86400            # one database copy per day ...
BACKUP_KEEP = 7                 # ... and the newest seven are kept
CRASH_ALERT_EVERY = 1800        # at most one "a part crashed" message per task and half hour


async def supervise(name: str, factory, *, on_crash=None, stop: asyncio.Event | None = None,
                    min_delay: float = 2.0, max_delay: float = 120.0, stable_after: float = 60.0,
                    stats: dict | None = None) -> None:
    """Run ``factory()`` (a coroutine function) and run it again when it fails or returns early.

    The background loops (delivery, reports, the Telegram bot, one loop per site) are what keeps a monitor
    useful: if one dies silently, alerts or checks simply stop. Cancellation passes through untouched, so a
    normal shutdown still works. A task that keeps crashing is restarted with a growing delay."""
    delay = 0.0
    while True:
        started = time.monotonic()
        try:
            await factory()
            reason = "ended unexpectedly"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("[supervisor] %s crashed", name)
            reason = f"{type(exc).__name__}: {exc}"
        if stop is not None and stop.is_set():
            return
        ran = time.monotonic() - started
        delay = min_delay if (delay == 0.0 or ran >= stable_after) else min(delay * 2, max_delay)
        if stats is not None:  # read by the health report
            stats["restarts"] = stats.get("restarts", 0) + 1
            stats["last_crash"] = time.time()
            stats["last_reason"] = reason[:200]
        log.warning("[supervisor] %s %s - restarting in %.0fs", name, reason, delay,
                    extra={"task": name, "restart_in_s": delay})
        if on_crash is not None:
            try:
                on_crash(name, reason, delay)
            except Exception:
                log.debug("crash callback failed", exc_info=True)
        await asyncio.sleep(delay)
WARP_PROXY = "socks5://127.0.0.1:40000"   # Cloudflare WARP in proxy mode (see README)
NOISY_CHANGES = 6       # page changes within an hour that suggest the "new headlines" mode


def watch_fingerprint(w) -> str:
    """Hash of the settings that shape a snapshot; when it changes we re-baseline silently."""
    parts = [EXTRACTOR_VERSION, w.type, w.selector, w.item_selector, w.item_link_selector, w.exclude_selectors,
             [p.pattern for p in w.ignore_patterns], w.track_links, w.crawl.selector if w.crawl else ""]
    if w.type == "json":
        parts += [w.json_records, w.json_template, w.json_labels, w.json_filter]
    return sha256_text(json.dumps(parts, ensure_ascii=False, sort_keys=True))[:16]


def crawl_fingerprint(w) -> str:
    c = w.crawl
    parts = [w.url, c.max_pages, c.max_depth, c.same_prefix, [p.pattern for p in c.include],
             [p.pattern for p in c.exclude], c.track_files]
    return sha256_text(json.dumps(parts))[:16]


def _browser_may_help(exc: Exception) -> bool:
    if isinstance(exc, ExtractError):
        return exc.kind in ("selector", "short", "empty", "blocked")
    if isinstance(exc, FetchError):
        return exc.kind in ("blocked", "ssl", "unavailable") or (exc.kind == "http" and exc.status in SWITCH_STATUSES)
    return False


def _is_blocked(exc: Exception) -> bool:
    """The site refuses this client/IP (as opposed to being down or changed)."""
    if isinstance(exc, FetchError):
        return exc.kind in ("blocked", "rate_limit") or exc.status in SWITCH_STATUSES
    return isinstance(exc, ExtractError) and exc.kind == "blocked"


def _outcome_kind(result: str) -> str:
    """A short, stable word for the text a check returns (a field of the JSON log)."""
    text = result.lower()
    for prefix, kind in (("baseline", "baseline"), ("no change", "unchanged"), ("no new", "unchanged"),
                         ("content only", "reordered"), ("change", "changed"), ("error", "error")):
        if text.startswith(prefix):
            return kind
    return "other"


def _is_rate_limit(exc: Exception) -> bool:
    """True when the site is temporarily banning this IP (Error 1015)."""
    if isinstance(exc, FetchError):
        return exc.kind == "rate_limit"
    return "rate limit" in str(exc).lower() or "error 1015" in str(exc).lower()


def _worth_switching(exc: Exception, engine: str) -> bool:
    """Should the next engine of the escalation chain be tried after ``engine`` failed?"""
    if isinstance(exc, FetchError) and exc.kind == "unavailable":
        return True
    return _is_blocked(exc) if engine == "browser" else _browser_may_help(exc)


def route_label(route: str) -> str:
    return "the fallback proxy" if route == "fallback" else "direct"


def _cache_busted(url: str) -> str:
    parts = urlsplit(url)
    extra = urlencode({"_wm": int(time.time())})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


class Monitor:
    def __init__(self, config, *, dry_run: bool = False, watches: list | None = None):
        """``watches``: a fixed list to monitor instead of the registry (used by CLI dry runs)."""
        self.config = config
        self.tz = load_timezone(config.timezone)
        self.store = Store(config.data_dir / "monitor.db")
        self.registry = WatchRegistry(self.store, config)
        self.http = HttpFetcher(config)
        self.impersonate = ImpersonateFetcher(config)
        self.browser = BrowserFetcher(config)
        if config.telegram.enabled and not dry_run:
            self.notifier = TelegramNotifier(config.telegram)
            self.chat_ids = list(config.telegram.chat_ids)
        else:
            self.notifier = ConsoleNotifier(config.data_dir / "reports")
            self.chat_ids = ["console"]
        self._fixed_watches = watches
        self._by_id: dict[str, object] = {}
        self.started_at = time.time()
        self.bot = None
        self._running = False
        self._stop = asyncio.Event()
        self._outbox = asyncio.Event()
        self._tasks: dict[str, list[asyncio.Task]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._triggers: dict[str, asyncio.Event] = {}
        self._crawl_wake: dict[str, asyncio.Event] = {}
        self._crawl_pending: dict[str, set] = {}
        self._root_links: dict[str, list] = {}
        self._root_final: dict[str, str] = {}
        self._stats: dict[str, Counter] = defaultdict(Counter)
        self._alarms: dict[int, asyncio.Task] = {}
        self._alarm_by_watch: dict[str, int] = {}
        self._alarm_seq = 0
        self._crash_alerts: dict[str, float] = {}
        self._task_stats: dict[str, dict] = {}       # restarts per supervised task (see supervise)
        self._core_tasks: dict[str, asyncio.Task] = {}  # dispatch, housekeeping, heartbeat, bot
        self._drift: dict[str, dict] = {}            # last large-scale page change per site (for /health)
        self.db_integrity = "unchecked"
        self._warp: tuple[float, bool] | None = None  # (checked at, running) for the WARP proxy
        self.challenge = ChallengeManager(
            host=config.challenge_host,
            port=config.challenge_port,
            ttl_seconds=config.challenge_ttl_seconds,
        )
        from .miniapp import MiniApp
        self.miniapp = MiniApp(self)
        self.challenge.add_routes(self.miniapp.register_routes)
        self.challenge.health_provider = lambda: build_health(self)
        self._challenge_ready = False

    @property
    def watches(self) -> list:
        """Enabled watches."""
        return [w for w in self._by_id.values() if w.enabled]

    @property
    def all_watches(self) -> list:
        return list(self._by_id.values())

    def watch(self, watch_id: str):
        return self._by_id.get(watch_id)

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        await self.http.start()
        await self.notifier.start()
        try:
            await self.challenge.start()
            self._challenge_ready = True
        except Exception as exc:
            log.warning("Challenge server unavailable (%s); manual solving disabled", exc)
        # Sprint 4.4: log a concise self-check of all subsystems.
        try:
            info = self._self_check()
            log.info("Self-check: http=%s impersonate=%s browser=%s challenge=%s notifier=%s",
                     info["http"], info["impersonate"], info["browser"],
                     info["challenge"], info["notifier"])
        except Exception:
            log.debug("self-check failed", exc_info=True)
        verdict = self.store.quick_check()
        self.db_integrity = verdict
        if verdict != "ok":
            log.error("Database integrity check failed: %s", verdict)
            self._enqueue_info("🚨 <b>بررسی سلامت دیتابیس خطا داد</b>",
                               [f"<code>{esc(truncate(verdict, 300))}</code>",
                                "آخرین نسخهٔ پشتیبان در پوشهٔ <code>data/backups</code> است."])
        if self._fixed_watches is not None:
            watches = list(self._fixed_watches)
        else:
            for note in self.registry.sync_from_config():
                log.info("%s", note)
            records = self.registry.records()
            for record in records:
                if record.watch is None:
                    log.error("Watch %r is invalid and is skipped: %s", record.id, record.error)
            watches = [record.watch for record in records if record.watch is not None]
        self._by_id = {w.id: w for w in watches}
        stale = self.store.forget_unknown_watches(list(self._by_id))
        if stale:
            log.info("Removed stored state of watches that no longer exist: %s", ", ".join(stale))

    async def close(self) -> None:
        for task in list(self._alarms.values()):
            task.cancel()
        try:
            await self.challenge.close()
        except Exception:
            log.debug("challenge server close failed", exc_info=True)
        for closer in (self.browser.close, self.impersonate.close, self.http.close, self.notifier.close):
            try:
                await closer()
            except Exception:
                log.debug("error while closing", exc_info=True)
        await asyncio.sleep(0.25)  # let aiohttp finish closing SSL transports (avoids warnings on Windows)
        self.store.close()

    def stop(self) -> None:
        self._stop.set()

    async def run_forever(self) -> None:
        self._running = True
        if self.config.notify_startup and self.store.get_setting("startup_notify", "on") != "off":
            self._enqueue_info(*self._startup_report())
        for w in self.watches:
            self._start_watch_tasks(w)
        tasks = [self._spawn("dispatch", self._dispatch_loop), self._spawn("housekeeping", self._housekeeping_loop)]
        if self.config.heartbeat_url:
            tasks.append(self._spawn("heartbeat", self._heartbeat_loop))
        if isinstance(self.notifier, TelegramNotifier) and self.config.telegram.commands:
            from .bot import AdminBot

            self.bot = AdminBot(self)
            tasks.append(self._spawn("bot", self.bot.run))
        log.info("Monitoring %d watch(es); notifications via %s", len(self.watches), self.notifier.name)
        try:
            await self._stop.wait()
        finally:
            log.info("Shutting down…")
            self._running = False
            for watch_id in list(self._tasks):
                await self._stop_watch_tasks(watch_id)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await asyncio.wait_for(self.dispatch_pending(), timeout=15)
            except Exception:
                pass

    def _spawn(self, name: str, factory) -> asyncio.Task:
        """A background task that is restarted (and reported) instead of dying silently."""
        task = asyncio.create_task(supervise(name, factory, on_crash=self._on_task_crash, stop=self._stop,
                                             stats=self._task_stats.setdefault(name, {})), name=name)
        if not name.startswith(("watch:", "crawl:")):
            self._core_tasks[name] = task
        return task

    def _on_task_crash(self, name: str, reason: str, restart_in: float) -> None:
        """Tell the admins that a part of the monitor crashed (at most once per task and half hour)."""
        now = time.time()
        if now - self._crash_alerts.get(name, 0.0) < CRASH_ALERT_EVERY:
            return
        self._crash_alerts[name] = now
        self._enqueue_info(f"⚠️ <b>بخش «{esc(name)}» با خطا متوقف شد</b> و {fa_digits(int(restart_in))} ثانیهٔ دیگر "
                           f"خودکار دوباره اجرا می‌شود.", [f"<code>{esc(truncate(reason, 300))}</code>"])

    def _note_drift(self, w, url: str, drift) -> None:
        """Remember (for /health) and log that a page changed on a large scale."""
        self._drift[w.id] = {"level": drift.level, "ts": time.time(), "url": url, **drift.as_dict()}
        log.warning("[%s] layout change (%s): %.0f%% of the lines replaced, %.0f%% shared vocabulary, "
                    "%.0f%% of the headings kept",
                    w.id, drift.level, drift.churn * 100, drift.vocab * 100, drift.headings * 100,
                    extra={"watch": w.id, "drift": drift.level, "churn": round(drift.churn, 2),
                           "vocab": round(drift.vocab, 2), "headings": round(drift.headings, 2),
                           "size": round(drift.size, 2)})

    # ------------------------------------------------------------------ runtime watch management

    def _start_watch_tasks(self, w) -> None:
        self._triggers[w.id] = asyncio.Event()
        tasks = [self._spawn(f"watch:{w.id}", lambda: self._watch_loop(w))]
        if w.crawl:
            self._crawl_wake.setdefault(w.id, asyncio.Event())
            self._crawl_pending.setdefault(w.id, set())
            tasks.append(self._spawn(f"crawl:{w.id}", lambda: self._crawl_loop(w)))
        self._tasks[w.id] = tasks

    async def _stop_watch_tasks(self, watch_id: str) -> None:
        tasks = self._tasks.pop(watch_id, [])
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._triggers.pop(watch_id, None)

    async def apply_watch(self, w) -> None:
        """Add a new watch or replace a changed one while running (state is kept, keyed by id)."""
        await self._stop_watch_tasks(w.id)
        self._by_id[w.id] = w
        self._root_links.pop(w.id, None)
        if self._running and w.enabled:
            self._start_watch_tasks(w)

    async def remove_watch(self, watch_id: str, forget_state: bool = True) -> None:
        await self._stop_watch_tasks(watch_id)
        self._by_id.pop(watch_id, None)
        for registry in (self._crawl_wake, self._crawl_pending, self._root_links, self._root_final, self._locks):
            registry.pop(watch_id, None)
        if forget_state:
            self.store.reset_watch(watch_id)
            for subdir in ("sessions", "sessions-impersonate"):
                session_file = self.config.data_dir / subdir / f"{watch_id}.json"
                try:
                    if session_file.exists():
                        session_file.unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------ scheduling

    async def _watch_loop(self, w) -> None:
        await asyncio.sleep(random.uniform(0.5, min(8.0, max(1.0, w.interval_seconds / 2))))
        trigger = self._triggers[w.id]
        while True:
            trigger.clear()
            await self.check_watch(w)
            try:
                await asyncio.wait_for(trigger.wait(), timeout=self.next_delay(w))
            except asyncio.TimeoutError:
                pass

    def next_delay(self, w) -> float:
        """Seconds until the next check: the interval plus jitter, doubled per consecutive failure
        (from the second one) up to BACKOFF_CAP — hammering a blocking site only extends the ban."""
        delay = w.interval_seconds + random.uniform(0, w.jitter_seconds)
        state = self.store.watch_state(w.id)
        errors = state.get("consecutive_errors") or 0
        last_error = (state.get("last_error") or "").lower()
        if "rate limit" in last_error or "error 1015" in last_error:
            delay = max(delay, w.interval_seconds * 4)
        if errors >= 2:
            delay = min(delay * 2 ** min(errors - 1, 10), max(delay, BACKOFF_CAP))
        return delay

    def trigger_all(self) -> None:
        for event in self._triggers.values():
            event.set()

    def trigger(self, watch_id: str) -> None:
        """Check one watch right away (when it is running)."""
        event = self._triggers.get(watch_id)
        if event is not None:
            event.set()

    trigger_check = trigger

    async def check_watch(self, w) -> str:
        """Run one check of a watch. Never raises (except cancellation). Checks of one watch never overlap."""
        async with self._locks.setdefault(w.id, asyncio.Lock()):
            self._stats[w.id]["checks"] += 1
            started = time.monotonic()
            try:
                if w.type in ("page", "json"):
                    result = await self._check_page(w)
                elif w.type in ("items", "headlines"):
                    result = await self._check_items(w)
                else:
                    result = await self._check_feed(w)
            except (FetchError, ExtractError) as exc:
                return self._on_failure(w, exc)
            except Exception as exc:
                log.exception("[%s] unexpected error", w.id)
                return self._on_failure(w, exc)
            self._on_success(w)
            if result.startswith("baseline"):
                self._after_baseline(w)
            elapsed = time.monotonic() - started
            log.info("[%s] %s (%.1fs)", w.id, result, elapsed,
                     extra={"watch": w.id, "outcome": _outcome_kind(result), "duration_ms": int(elapsed * 1000),
                            "engine": self.engine_for(w)})
            return result

    # ------------------------------------------------------------------ rate-limit timing + exit-IP (Sprint 3.4.4)

    def _rate_limit_since(self, w) -> float | None:
        """Timestamp when this watch first saw a rate-limit ban, or None."""
        try:
            v = float(self.store.get_setting(f"rate_limit_since:{w.id}", "0") or 0)
        except (TypeError, ValueError):
            return None
        return v if v > 0 else None

    def _rate_limit_estimate_hours(self, w) -> float | None:
        """Rough hours remaining, based on the observed ban window (Cloudflare 1015 usually 2-24h)."""
        since = self._rate_limit_since(w)
        if since is None:
            return None
        # Assume the ban lasts up to 24h from the first observed hit.
        remaining = (since + 24 * 3600) - time.time()
        return max(0.0, remaining / 3600.0)

    def _record_rate_limit(self, w) -> None:
        """Called when we detect a rate-limit for the first time in this window."""
        since = self._rate_limit_since(w)
        if since is None:
            self.store.set_setting(f"rate_limit_since:{w.id}", str(time.time()))

    def _clear_rate_limit(self, w) -> None:
        """Called on any successful check."""
        key = f"rate_limit_since:{w.id}"
        if self.store.get_setting(key, "0") != "0":
            self.store.set_setting(key, "0")

    async def exit_ip(self, w) -> tuple[str, str]:
        """Fetch the public IP the watch's own route presents to a third-party site.

        Returns (ip, route_label). Raises FetchError on failure.
        """
        routed = await self._routed(w)
        probe = replace(routed, id="_ip_probe", url="https://api.ipify.org",
                        timeout_seconds=15, verify_ssl=True, headers={})
        fetcher = self.http if self.http.supports(probe) else self.impersonate
        result = await fetcher.fetch("https://api.ipify.org", probe)
        ip = (result.text or "").strip()
        if routed.proxy is None:
            route = "direct"
        elif "127.0.0.1:40000" in (routed.proxy.server or ""):
            route = "warp"
        else:
            route = "custom-proxy"
        return ip, route

    def _cached_exit_ip(self, w) -> str:
        try:
            v = self.store.get_setting(f"exit_ip:{w.id}", "")
        except Exception:
            return ""
        return v

    def _cache_exit_ip(self, w, ip: str, route: str) -> None:
        self.store.set_setting(f"exit_ip:{w.id}", f"{ip}|{route}|{int(time.time())}")

    # ------------------------------------------------------------------ adaptive timeout (Sprint 3.4.2)

    def _effective_timeout(self, w) -> float:
        """Timeout for this watch; grows on repeated timeouts."""
        try:
            val = float(self.store.get_setting(f"timeout:{w.id}", "0") or 0)
        except (TypeError, ValueError):
            val = 0.0
        return val if val > 0 else w.timeout_seconds

    def _prepare_watch(self, w):
        """Return w with the effective timeout applied (used by every fetch path)."""
        eff = self._effective_timeout(w)
        if eff > 0 and eff != w.timeout_seconds:
            return replace(w, timeout_seconds=eff)
        return w

    def _record_timeout_hit(self, w) -> None:
        """Called when a check times out. Raises effective timeout on >=2 hits."""
        key_hits = f"timeout_hits:{w.id}"
        try:
            hits = int(self.store.get_setting(key_hits, "0") or 0)
        except (TypeError, ValueError):
            hits = 0
        hits += 1
        self.store.set_setting(key_hits, str(hits))
        if hits >= 2:
            current = self._effective_timeout(w)
            new_timeout = min(current * 2, 120.0)
            if new_timeout > current:
                self.store.set_setting(f"timeout:{w.id}", str(new_timeout))
                log.info("[%s] adaptive timeout raised to %.0fs (repeated timeouts)", w.id, new_timeout)

    def _reset_timeout_hits(self, w) -> None:
        """Called on any successful check."""
        self.store.set_setting(f"timeout_hits:{w.id}", "0")

    def _key(self, w) -> int | None:
        """The registry key of a watch (used in panel buttons), None outside the service."""
        if self._fixed_watches is not None:
            return None
        record = self.registry.get(watch_id=w.id)
        return record.key if record is not None else None

    def _on_failure(self, w, exc: Exception) -> str:
        message = str(exc) or type(exc).__name__
        if isinstance(exc, FetchError) and exc.kind == "timeout":
            self._record_timeout_hit(w)
        if _is_rate_limit(exc):
            self._record_rate_limit(w)
        state = self.store.record_check_error(w.id, message)
        count = state.get("consecutive_errors", 1)
        self._stats[w.id]["errors"] += 1
        log.warning("[%s] check failed (%d in a row): %s", w.id, count, message,
                    extra={"watch": w.id, "outcome": "error", "consecutive": count,
                           "error_kind": getattr(exc, "kind", type(exc).__name__)})
        if count >= w.error_threshold and not state.get("alerted"):
            payload, summary = report.error_event(w, message, count, self._error_hint(exc), time.time(), self.tz,
                                                  key=self._key(w))
            self.store.add_event(w.id, w.url, "error", summary, payload)
            self.store.update_watch(w.id, alerted=1)
            self._outbox.set()
        return f"error: {message}"

    def _on_success(self, w) -> None:
        self._reset_timeout_hits(w)
        self._clear_rate_limit(w)
        previous = self.store.record_check_ok(w.id)
        if previous.get("alerted"):
            down = time.time() - (previous.get("first_error_at") or time.time())
            payload, summary = report.recovered_event(w, down, time.time(), self.tz)
            self.store.add_event(w.id, w.url, "recovered", summary, payload)
            self._outbox.set()
        elif previous.get("consecutive_errors"):
            log.info("[%s] recovered after %d failed check(s)", w.id, previous["consecutive_errors"])

    @staticmethod
    def _error_hint(exc: Exception) -> str:
        if _is_rate_limit(exc):
            return ("سایت موقتاً IP سرور را مسدود کرده (Cloudflare Error 1015)؛ این ban با CAPTCHA حل نمی‌شود. فاصلهٔ بررسی را بیشتر کنید و چند ساعت تا دو روز صبر کنید.")
        if _is_blocked(exc):
            return ("سایت IP این سرور را مسدود کرده است (معمولاً موقت). اگر پروکسی WARP روی سرور فعال باشد، "
                    "سیستم خودکار از آن استفاده می‌کند؛ «🧪 تست دسترسی» نشان می‌دهد کدام روش و مسیر جواب می‌دهد.")
        if isinstance(exc, ExtractError) and exc.kind in ("selector", "short"):
            hint = ("احتمالاً ساختار صفحه عوض شده است؛ در کارت سایت «✏️ ویرایش ← 🎯 حالت پایش» را بزنید تا صفحه "
                    "دوباره بررسی و بخش درست انتخاب شود.")
            if getattr(exc, "suggestion", ""):
                hint += (f"\n💡 نزدیک‌ترین بخش به محتوای قبلی: <code>{esc(exc.suggestion)}</code> "
                         f"({fa_digits(round(exc.cover * 100))}٪ هم‌پوشانی)؛ همان را به‌عنوان انتخابگر بگذارید.")
            return hint
        if isinstance(exc, FetchError):
            if exc.kind == "timeout":
                return "سایت کند یا از دسترس خارج است؛ اگر ادامه داشت، فاصلهٔ بررسی را بیشتر کنید."
            if exc.kind == "ssl":
                return "مشکل گواهی امنیتی (SSL) سایت؛ روش دریافت را «مرورگر» بگذارید."
            if exc.kind == "browser":
                return "مرورگر روی سرور اجرا نشد؛ اسکریپت نصب را دوباره اجرا کنید."
            if exc.kind == "unavailable":
                return "این روش دریافت روی سرور نصب نیست؛ اسکریپت نصب را دوباره اجرا کنید."
            if exc.status in (404, 410):
                return "این آدرس دیگر وجود ندارد؛ آدرس صفحه را بررسی کنید."
        return ""

    # ------------------------------------------------------------------ fetching

    def engine_for(self, w) -> str:
        if w.engine != "auto":
            return w.engine
        return self.store.watch_state(w.id).get("engine") or "http"

    def _fetcher(self, engine: str):
        return {"browser": self.browser, "impersonate": self.impersonate}.get(engine, self.http)

    async def _fetch(self, w, url: str, engine: str, *, conditional=None, wait_for: str = ""):
        if engine == "browser":
            return await self.browser.fetch(url, w, wait_for=wait_for)
        return await self._fetcher(engine).fetch(url, w, conditional=conditional)

    # ------------------------------------------------------------------ fallback proxy (blocked server IP)

    async def fallback_proxy(self) -> Proxy | None:
        """The proxy used when a site blocks this server's own IP: Cloudflare WARP on this machine when
        it runs (setting "auto", the default), a proxy chosen in the panel, or none ("off")."""
        setting = self.store.get_setting("fallback_proxy", "auto")
        if setting == "off":
            return None
        if setting != "auto":
            try:
                return Proxy.parse_url(setting)
            except ConfigError:
                log.warning("ignoring the invalid fallback proxy setting %r", setting)
                return None
        now = time.monotonic()
        if self._warp is None or now - self._warp[0] > 120:
            self._warp = (now, await port_open("127.0.0.1", 40000))
        return Proxy.parse(WARP_PROXY, "warp") if self._warp[1] else None

    def _may_reroute(self, w) -> bool:
        """Sites with their own proxy (or a global one) always use it."""
        return w.proxy is None and self.config.global_proxy is None

    def route_of(self, w) -> str:
        return self.store.watch_state(w.id).get("route") or "direct"

    async def _routed(self, w):
        """``w`` as it is fetched now: through the fallback proxy once its site has blocked us."""
        if self._may_reroute(w) and self.route_of(w) == "fallback":
            proxy = await self.fallback_proxy()
            if proxy is not None:
                return replace(w, proxy=proxy)
        return w

    # ------------------------------------------------------------------ fetching

    async def _engine_chain(self, w, url: str, parse, *, conditional, wait_for: str, allow_switch: bool,
                            remember: bool):
        engine = self.engine_for(w)
        chain = [engine]
        if allow_switch and w.engine == "auto":
            # escalate to stronger engines; a blocked browser falls back to the lighter Chrome impersonation
            chain += {"http": ["impersonate", "browser"], "impersonate": ["browser"],
                      "browser": ["impersonate"]}.get(engine, [])
        usable = [name for name in chain if self._fetcher(name).supports(w)]
        if not usable and w.engine == "auto":  # e.g. a SOCKS proxy while aiohttp-socks is missing
            usable = [name for name in ("impersonate", "browser") if self._fetcher(name).supports(w)]
        chain = usable or chain[:1]
        for index, candidate in enumerate(chain):
            try:
                result = await self._fetch(w, url, candidate, conditional=conditional if index == 0 else None,
                                           wait_for=wait_for)
                if result.not_modified:
                    return result, None
                # parsing and text extraction are CPU-bound (seconds for a multi-MB page): keep the loop free
                parsed = await asyncio.to_thread(parse, result)
            except (FetchError, ExtractError) as exc:
                if index + 1 < len(chain) and _worth_switching(exc, candidate):
                    log.info("[%s] %s engine was not enough (%s); trying %s", w.id, candidate, exc, chain[index + 1])
                    continue
                raise
            if candidate != engine and remember:
                self.store.update_watch(w.id, engine=candidate)
                log.info("[%s] switched to the %s engine for future checks", w.id, candidate)
            return result, parsed
        raise FetchError("network", "no fetch engine is available")

    async def _fetch_parse(self, w, url: str, parse, *, conditional=None, wait_for: str = "",
                           allow_switch: bool = True, remember: bool = True):
        """Fetch and parse. In auto mode, escalate http → impersonate → browser when a site blocks or
        hides its content, and stick with the first engine that works. When a site blocks this server's
        IP itself, retry through the fallback proxy (Cloudflare WARP) and keep using the route that works."""
        w = self._prepare_watch(w)
        fallback = await self.fallback_proxy() if self._may_reroute(w) else None
        current = self.route_of(w)
        routes = ["direct"]
        if fallback is not None:
            routes = ["fallback", "direct"] if current == "fallback" else ["direct", "fallback"]
        tried_challenge = False
        for index, route in enumerate(routes):
            target = replace(w, proxy=fallback) if route == "fallback" else w
            try:
                outcome = await self._engine_chain(target, url, parse, conditional=conditional if index == 0 else None,
                                                   wait_for=wait_for, allow_switch=allow_switch, remember=remember)
            except (FetchError, ExtractError) as exc:
                # Sprint 3.3: try to solve a bot wall by hand (once per check).
                if (not tried_challenge and allow_switch and _is_blocked(exc)
                        and self._challenge_ready and w.engine in ("auto", "browser")):
                    tried_challenge = True
                    solved = await self._maybe_solve_challenge(target, url, exc)
                    if solved:
                        retry_target = replace(target, persist_session=True)
                        try:
                            outcome = await self._engine_chain(retry_target, url, parse,
                                                               wait_for=wait_for, allow_switch=False,
                                                               remember=remember)
                        except (FetchError, ExtractError) as exc2:
                            log.info("[%s] still failing after challenge: %s", w.id, exc2)
                        else:
                            if remember and route != current:
                                self.store.update_watch(w.id, route=None if route == "direct" else route)
                            return outcome
                if index + 1 < len(routes) and allow_switch and _is_blocked(exc):
                    log.info("[%s] %s access is blocked (%s); trying %s", w.id, route_label(route), exc,
                             route_label(routes[index + 1]))
                    continue
                raise
            if remember and route != current:
                self.store.update_watch(w.id, route=None if route == "direct" else route)
                log.info("[%s] from now on checked via %s", w.id, route_label(route))
            return outcome
        raise FetchError("network", "no route to the site")

    async def _maybe_solve_challenge(self, w, url: str, exc: Exception | None = None) -> bool:
        """Open a challenge, notify admins, wait for them to solve it. Returns True if solved.

        Rate-limited to once per watch per 30 minutes so repeated blocked checks do
        not spam the admins. The admin needs the SSH tunnel open (see README).
        """
        if not self._challenge_ready or not self.browser.available:
            return False
        if exc is not None and _is_rate_limit(exc):
            await self._notify_rate_limit(w)
            return False
        if not w.proxy and self.config.global_proxy is not None:
            # A watch with its own proxy cannot use the fallback WARP tunnel anyway.
            pass
        # Rate limit per watch.
        ck = f"challenge_cooldown:{w.id}"
        try:
            last = float(self.store.get_setting(ck, "0") or 0)
        except (TypeError, ValueError):
            last = 0.0
        if time.time() - last < 1800:
            log.info("[%s] challenge skipped (rate-limited)", w.id)
            return False
        self.store.set_setting(ck, str(time.time()))

        # Open a live browser context for the admin.
        try:
            cb = await self.browser.open_challenge(url, replace(w, persist_session=True))
        except Exception as exc:
            log.warning("[%s] could not open challenge browser: %s", w.id, exc)
            return False

        session = self.challenge.create(watch_id=w.id, watch_label=w.label, url=w.page_url)
        session.frame_fn = cb.frame
        session.click_fn = cb.click
        session.type_fn = cb.type
        session.key_fn = cb.key
        session.click_turnstile_fn = cb.click_turnstile

        saved: dict = {"state": None}

        async def on_done():
            try:
                saved["state"] = await cb.done()
            except Exception:
                log.debug("challenge save state failed", exc_info=True)

        async def on_cancel():
            pass  # context is closed below

        session.done_fn = on_done
        session.cancel_fn = on_cancel

        # Notify admins now (before waiting).
        try:
            await self._notify_challenge(session, w)
        except Exception:
            log.exception("[%s] challenge notify failed", w.id)

        # Wait for a result or TTL.
        future = self.challenge.await_result(session.token)
        try:
            kind, _ = await asyncio.wait_for(future, timeout=self.config.challenge_ttl_seconds)
        except asyncio.TimeoutError:
            kind = "timeout"
            self.challenge._sessions.pop(session.token, None)

        # Always close the context.
        try:
            await cb.close()
        except Exception:
            log.debug("[%s] challenge close failed", w.id, exc_info=True)

        if kind == "done" and saved["state"]:
            self.browser.save_storage_state(w, saved["state"])
            log.info("[%s] challenge solved; storage_state saved", w.id)
            return True
        log.info("[%s] challenge %s", w.id, kind)
        return False

    async def _notify_rate_limit(self, w) -> None:
        """One notice per watch per 12 h when the site bans this IP temporarily."""
        key = f"rate_limit_notified:{w.id}"
        try:
            last = float(self.store.get_setting(key, "0") or 0)
        except (TypeError, ValueError):
            last = 0.0
        if time.time() - last < 12 * 3600:
            return
        self.store.set_setting(key, str(time.time()))
        since = self._rate_limit_since(w)
        hours_left = self._rate_limit_estimate_hours(w)
        header = f"🚫 <b>«{esc(w.label)}» موقتاً IP سرور را بلاک کرده</b>"
        if since and hours_left is not None:
            elapsed_h = (time.time() - since) / 3600.0
            header += (f"\n⏱ {fa_digits(f'{elapsed_h:.1f}')} ساعت پیش شروع شد — "
                       f"تخمین رفع: {fa_digits(f'{hours_left:.1f}')} ساعت دیگر")
        blocks = [
            "<b>این ban با CAPTCHA حل نمی‌شود</b> — سایت IP سرور را برای چند ساعت تا دو روز کاملاً مسدود کرده (Cloudflare Error 1015).",
            "🔁 <b>راه حل:</b> فاصلهٔ بررسی این سایت را زیاد کنید و بگذارید ban خودش تمام شود. تلاش پیاپی، ban را طولانی‌تر می‌کند.",
        ]
        buttons = [[{"text": "📄 کارت سایت", "callback_data": f"+c:{self._key(w)}"}]] \
            if self._key(w) is not None else None
        self._enqueue_info(header, blocks, silent=False, buttons=buttons)

    async def _notify_challenge(self, session, w) -> None:
        """Send interactive Telegram challenge controls (+ live screenshot & optional SSH tunnel URL) to admins."""
        port = self.config.challenge_port
        tunnel_url = f"http://{self.config.challenge_host}:{port}/c/{session.token}"
        ssh_cmd = getattr(self.config, "challenge_ssh_command", "") or \
            f"ssh -L {port}:127.0.0.1:{port} ubuntu@<server-ip>"
        ttl_min = max(1, int(self.config.challenge_ttl_seconds / 60))
        header = (f"🛡 <b>چالش محافظ (Cloudflare / CAPTCHA) در «{esc(w.label)}»</b>\n"
                  f"🔗 {esc(w.page_url)}")
        body = [
            "سایت یک صفحهٔ محافظ نشان می‌دهد. می‌توانید <b>مستقیماً با دکمه‌های زیر در همین چت تلگرام</b> "
            "روی چک‌باکس کلودفلر کلیک کنید، عکس جدید بگیرید و کوکی‌ها را ذخیره کنید:",
            "",
            "1️⃣ دکمهٔ <b>«🖱 کلیک خودکار چک‌باکس کلودفلر»</b> را بزنید.",
            "2️⃣ با <b>«📸 دریافت عکس لحظه‌ای صفحه»</b> بررسی کنید که صفحه باز شده باشد.",
            "3️⃣ دکمهٔ <b>«✅ حل شد (ذخیره کوکی)»</b> را بزنید.",
            "",
            "💻 <i>روش جایگزین (پنل وب کامل از طریق تونل SSH):</i>",
            f"<code>{esc(ssh_cmd)}</code>",
            f"<code>{esc(tunnel_url)}</code>",
            "",
            f"⏱ اعتبار: {fa_digits(ttl_min)} دقیقه",
        ]
        payload = report.info_event(header, ["\n".join(body)], silent=False)
        payload["buttons"] = [
            [{"text": "🖱 کلیک خودکار چک‌باکس کلودفلر", "callback_data": f"+ck:{session.token}:cf"}],
            [{"text": "📸 دریافت عکس لحظه‌ای صفحه", "callback_data": f"+ck:{session.token}:rf"}],
            [{"text": "✅ حل شد (ذخیره کوکی)", "callback_data": f"+ck:{session.token}:ok"},
             {"text": "❌ لغو چالش", "callback_data": f"+cc:{session.token}"}],
            [{"text": "🛡 باز کردن لینک چالش", "url": tunnel_url}],
        ]
        payload["deliver_mode"] = "text"
        targets = self._targets("info")
        parts = [content for kind, content in build_parts(payload) if kind == "text"]
        frame = b""
        if session.frame_fn is not None:
            try:
                frame = await session.frame_fn()
            except Exception:
                frame = b""
        for chat_id in targets:
            if frame:
                try:
                    await self.notifier.send_photo(
                        chat_id, f"challenge-{w.id}.jpg", frame,
                        f"📸 تصویر فعلی مرورگر سرور برای «{esc(w.label)}»"
                    )
                except Exception:
                    pass
            for index, text in enumerate(parts):
                try:
                    await self.notifier.send_text(
                        chat_id, text,
                        reply_markup={"inline_keyboard": payload["buttons"]} if index == len(parts) - 1 else None,
                    )
                except NotifyError as exc:
                    log.warning("[%s] challenge message to %s failed: %s", w.id, chat_id, exc)

    def _parser(self, w):
        return {"page": self._parse_content, "json": self._parse_content, "items": self._parse_items,
                "headlines": self._parse_headlines, "feed": self._parse_feed}[w.type]

    async def preview_watch(self, w, limit: int = 40) -> tuple[str, list[str]]:
        """Fetch a watch right now (nothing is stored) and return a summary plus what it monitors."""
        parse = self._parser(w)
        result, parsed = await self._fetch_parse(w, w.url, lambda r: parse(w, r), wait_for=w.wait_selector,
                                                 remember=False)
        if w.type in ("page", "json"):
            snap = parsed[0]
            info = f"{fa_number(len(snap.lines))} خط، {fa_number(snap.text_length)} حرف"
            if w.track_links:
                info += f"، {fa_number(len(snap.links))} لینک"
            lines = snap.lines[:limit]
        else:
            info = f"{fa_number(len(parsed))} مورد"
            lines = [f"• {item.title}" for item in parsed[:limit]]
        via = " · 🛡 از طریق پروکسی" if result.engine and self.route_of(w) == "fallback" and self._may_reroute(w) else ""
        engine = ENGINE_LABELS.get(result.engine, result.engine)
        return f"⚙️ {engine} · HTTP {result.status} · {fa_elapsed(result.elapsed)} · {info}{via}", lines

    # ------------------------------------------------------------------ page watches

    def _root(self, w) -> str:
        return normalize_url(w.url) or w.url

    def _parse_page(self, w, result, *, subpage: bool = False, prev_json: str | None = None):
        if not result.text:
            raise ExtractError(f"not an HTML page (Content-Type: {result.content_type or 'unknown'})", kind="type")
        doc = parse_html(result.text, result.final_url)
        base = document_base(doc, result.final_url)
        discovered = extract_links([doc], base) if w.crawl else []
        selector = (w.crawl.selector or w.selector) if subpage else w.selector
        try:
            snap = page_snapshot(doc, base, selector=selector, exclude_selectors=w.exclude_selectors,
                                 ignore_patterns=w.ignore_patterns, track_links=w.track_links, fallback=subpage)
        except ExtractError as exc:
            hint = detect_block(result.text)
            if hint:
                raise ExtractError(f"{exc} — the page looks like {hint}", kind="blocked") from None
            if exc.kind == "selector" and prev_json:
                # the selector stopped matching: look for the element that holds the text it used to select
                try:
                    found = suggest_selector(doc, base, Snapshot.from_json(prev_json).lines,
                                             exclude_selectors=w.exclude_selectors, ignore_patterns=w.ignore_patterns,
                                             track_links=w.track_links)
                except Exception:
                    found = None
                if found:
                    exc.suggestion, exc.cover = found
                    exc.args = (f"{exc.args[0]} — closest match for the previous content: {found[0]} "
                                f"({round(found[1] * 100)}% of it)",)
            raise
        minimum = 1 if subpage else w.min_content_length
        if snap.text_length < minimum:
            hint = detect_block(result.text)
            raise ExtractError(
                f"content too short ({snap.text_length} chars, expected at least {minimum})"
                + (f" — the page looks like {hint}" if hint else ""), kind="blocked" if hint else "short")
        return snap, discovered

    def _parse_json(self, w, result):
        if not result.text:
            raise ExtractError(f"empty response (Content-Type: {result.content_type or 'unknown'})", kind="empty")
        try:
            data = parse_json_body(result.text)
        except ExtractError:
            hint = detect_block(result.text)
            raise ExtractError("the response is not JSON" + (f" — the page looks like {hint}" if hint else ""),
                               kind="blocked" if hint else "type") from None
        return json_snapshot(data, w.json_records, w.json_template, w.json_labels, w.json_filter), []

    def _parse_content(self, w, result, prev_json: str | None = None):
        return self._parse_json(w, result) if w.type == "json" else self._parse_page(w, result, prev_json=prev_json)

    async def _check_page(self, w) -> str:
        root = self._root(w)
        prev = self.store.get_page(w.id, root)
        conditional = None
        if prev is not None and prev["snapshot"] and prev["fingerprint"] == watch_fingerprint(w) and not w.cache_bust:
            conditional = {"etag": prev["etag"], "last_modified": prev["last_modified"]}
        url = _cache_busted(w.url) if w.cache_bust else w.url
        result, parsed = await self._fetch_parse(w, url, lambda r: self._parse_content(w, r, prev["snapshot"] if prev else None),
                                                 conditional=conditional, wait_for=w.wait_selector)
        if result.not_modified:
            self.store.touch_page(w.id, root)
            return "no change (HTTP 304)"
        snap, discovered = parsed
        if w.crawl:
            final = normalize_url(result.final_url)
            if final and not w.cache_bust:
                self._root_final[w.id] = final
            self._root_links[w.id] = discovered
            self._queue_unknown_links(w, discovered)
        return await self._apply_snapshot(w, root, prev, snap, result)

    async def _apply_snapshot(self, w, url: str, prev, snap: Snapshot, result) -> str:
        fields = dict(kind="page", digest=snap.digest, snapshot=snap.to_json(), title=snap.title,
                      engine=result.engine, fingerprint=watch_fingerprint(w), etag=result.etag,
                      last_modified=result.last_modified)
        reason = None
        if prev is None or not prev["snapshot"]:
            reason = "first check"
        elif prev["fingerprint"] != fields["fingerprint"]:
            reason = "settings changed"
        elif prev["engine"] and prev["engine"] != result.engine:
            reason = f"engine is now {result.engine}"
        if reason:
            self.store.record_page(w.id, url, **fields)
            links = f", {len(snap.links)} links" if w.track_links else ""
            return f"baseline saved ({reason}): {len(snap.lines)} lines, {snap.text_length} chars{links}"
        if prev["digest"] == fields["digest"]:
            self.store.touch_page(w.id, url, etag=result.etag, last_modified=result.last_modified)
            return "no change"
        old = Snapshot.from_json(prev["snapshot"])
        hunks = report.diff_lines(old.lines, snap.lines, w.ignore_reorder,
                                   new_headings=snap.headings, new_anchors=snap.anchors)
        added, removed = report.diff_links(old.links, snap.links) if w.track_links else ([], [])
        if not hunks and not added and not removed:
            self.store.record_page(w.id, url, **fields)
            return "content only re-ordered (ignored)"
        eff_style = getattr(w, "report_style", "inline")
        if eff_style == "inline" and self.store.get_setting("default_report_style", "inline") == "before_after":
            eff_style = "before_after"
        drift = None
        if getattr(self.config, "drift_detection", True):
            drift = report.assess_drift(old.lines, snap.lines, old.headings, snap.headings,
                                        old.text_length, snap.text_length)
        payload, summary, hits = report.change_event(
            w, url, hunks, added, removed, time.time(), self.tz, snap.title,
            total_chars=snap.text_length,
            style=eff_style,
            drift=drift,
        )
        if drift is not None and drift.level != "normal":
            payload["drift"] = drift.as_dict()
            self._note_drift(w, url, drift)
        status = "filtered" if w.only_keywords and not hits else "pending"
        # Sprint 2.1: capture a screenshot if this watch or global auto_screenshot asks for one.
        deliver_mode = "text"
        eff_notify = getattr(w, "notify_mode", "text")
        if eff_notify == "text" and self.store.get_setting("auto_screenshot", "off") == "on":
            eff_notify = "both"
        if status == "pending" and eff_notify in ("screenshot", "both"):
            deliver_mode = eff_notify
            try:
                image = await self.screenshot(w, url=url)
            except Exception as exc:
                log.warning("[%s] screenshot failed: %s", w.id, exc)
                payload["header"] = (payload.get("header") or "") + (
                    f"\n⚠️ <i>عکس گرفته نشد: {esc(truncate(str(exc), 200))}</i>"
                )
            else:
                digest = self._save_shot(w.id, image)
                payload["shots"] = [{"digest": digest, "filename": f"{w.id}.jpg"}]
                payload["screenshot_audience"] = getattr(w, "screenshot_audience", "channel")
        payload["deliver_mode"] = deliver_mode
        self.store.record_page(w.id, url, changed=True, event=("change", summary, payload, status), **fields)
        self._stats[w.id]["changes"] += 1
        self._outbox.set()
        if status == "pending":
            changed = [h.new for h in hunks if h.kind in ("add", "modify")]
            detail = next((line for line in changed if find_keywords(w.keywords, line)), changed[0] if changed else "")
            self._maybe_alarm(w, detail or summary, hits)
            if url == self._root(w):
                self._maybe_suggest_headlines(w)
        note = f" [keywords: {', '.join(hits)}]" if hits else ""
        if status == "filtered":
            note += " [not sent: no keyword]"
        return f"CHANGE detected: {summary}{note}"

    # ------------------------------------------------------------------ items & feeds

    def _parse_items(self, w, result):
        if not result.text:
            raise ExtractError(f"not an HTML page (Content-Type: {result.content_type or 'unknown'})", kind="type")
        doc = parse_html(result.text, result.final_url)
        items = extract_items(doc, document_base(doc, result.final_url), w.item_selector, w.item_link_selector,
                              w.exclude_selectors, w.ignore_patterns)
        if not items:
            hint = detect_block(result.text)
            raise ExtractError(f"item_selector {w.item_selector!r} matched no items"
                               + (f" — the page looks like {hint}" if hint else ""),
                               kind="blocked" if hint else "selector")
        return items

    def _parse_headlines(self, w, result):
        if not result.text:
            raise ExtractError(f"not an HTML page (Content-Type: {result.content_type or 'unknown'})", kind="type")
        doc = parse_html(result.text, result.final_url)
        items = extract_headlines(doc, document_base(doc, result.final_url), w.selector, w.exclude_selectors,
                                  w.ignore_patterns)
        if not items:
            hint = detect_block(result.text)
            raise ExtractError("no headlines (links with a title) were found on the page"
                               + (f" — the page looks like {hint}" if hint else ""),
                               kind="blocked" if hint else "short")
        return items

    def _parse_feed(self, w, result):
        body = result.body or result.text.encode("utf-8")
        if not looks_like_feed(result.content_type, body):
            raise ExtractError(f"not an RSS/Atom feed (Content-Type: {result.content_type or 'unknown'})", kind="type")
        items = parse_feed(body, result.final_url)
        if not items:
            raise ExtractError("the feed contains no items", kind="empty")
        return items

    async def _check_items(self, w) -> str:
        parse = self._parse_headlines if w.type == "headlines" else self._parse_items
        _, items = await self._fetch_parse(w, w.url, lambda r: parse(w, r), wait_for=w.wait_selector)
        return self._apply_items(w, items)

    async def _check_feed(self, w) -> str:
        _, items = await self._fetch_parse(w, w.url, lambda r: self._parse_feed(w, r))
        return self._apply_items(w, items)

    def _apply_items(self, w, items: list) -> str:
        fingerprint = watch_fingerprint(w)
        ids = [item.id for item in items]
        if self.store.watch_state(w.id).get("fingerprint") != fingerprint or not self.store.has_items(w.id):
            self.store.record_items(w.id, ids, reset=True, fingerprint=fingerprint)
            return f"baseline saved: {len(items)} items"
        seen = self.store.seen_ids(w.id)
        new = [item for item in items if item.id not in seen]
        if not new:
            self.store.record_items(w.id, ids)
            return f"no new items ({len(items)} listed)"
        if w.type == "headlines" and len(items) >= 20 and len(new) > max(30, len(items) // 2):
            # Dozens of "new" stories at once means a redesign or another variant of the page, not news.
            self.store.record_items(w.id, ids)
            return f"baseline refreshed: {len(new)} of {len(items)} headlines changed at once (page layout changed?)"
        matching = [item for item in new if find_keywords(w.keywords, item.title, item.text)]
        hits = find_keywords(w.keywords, *(f"{item.title}\n{item.text}" for item in new))
        shown = matching if w.only_keywords else new
        status = "pending" if shown else "filtered"
        payload, summary = report.new_items_event(w, shown or new, time.time(), self.tz, hits)
        self.store.record_items(w.id, ids, event=("new_items", summary, payload, status))
        self._stats[w.id]["changes"] += 1
        if status == "pending":
            self._outbox.set()
            self._maybe_alarm(w, (matching or shown)[0].title, hits)
        note = " [not sent: no keyword]" if status == "filtered" else ""
        return f"NEW: {summary}{note}"

    # ------------------------------------------------------------------ crawling

    def _crawl_kind(self, w, url: str) -> str | None:
        """'page' or 'file' when ``url`` is inside the crawl scope of ``w``."""
        parts, root = urlsplit(url), urlsplit(w.url)
        if not same_site(parts.hostname, root.hostname) or _CRAWL_SKIP.search(url):
            return None
        extension = url_extension(url)
        if extension in ASSET_EXTENSIONS or any(p.search(url) for p in w.crawl.exclude):
            return None
        if extension in FILE_EXTENSIONS:
            return "file" if w.crawl.track_files else None
        if w.crawl.include:
            return "page" if any(p.search(url) for p in w.crawl.include) else None
        if w.crawl.same_prefix:
            prefix = root.path.rsplit("/", 1)[0] + "/"
            if not (parts.path or "/").startswith(prefix):
                return None
        return "page"

    def _root_aliases(self, w) -> set[str]:
        aliases = {self._root(w)}
        if w.id in self._root_final:
            aliases.add(self._root_final[w.id])
        return aliases

    def _scoped(self, w, links: list, visited: set) -> list[tuple[str, str]]:
        result = []
        for _, url in links:
            if url in visited:
                continue
            visited.add(url)
            kind = self._crawl_kind(w, url)
            if kind:
                result.append((url, kind))
        return result

    def _queue_unknown_links(self, w, links: list) -> None:
        state = self.store.watch_state(w.id)
        if not state.get("last_crawl") or state.get("crawl_fingerprint") != crawl_fingerprint(w):
            return  # the first full crawl will pick everything up
        known = self.store.page_urls(w.id) | self._root_aliases(w)
        fresh = {url for url, _ in self._scoped(w, links, set(known))}
        pending = self._crawl_pending.setdefault(w.id, set())
        if fresh - pending:
            pending |= fresh
            self._crawl_wake.setdefault(w.id, asyncio.Event()).set()

    async def _crawl_loop(self, w) -> None:
        wake, pending = self._crawl_wake[w.id], self._crawl_pending[w.id]
        await asyncio.sleep(random.uniform(10, 20))  # let the start page get its baseline first
        while True:
            state = self.store.watch_state(w.id)
            last = state.get("last_crawl") or 0
            stale = state.get("crawl_fingerprint") != crawl_fingerprint(w)
            crawl_interval = max(w.crawl.interval_seconds, w.interval_seconds)
            due = last + crawl_interval
            if time.time() < due and not pending and not stale:
                wake.clear()
                try:
                    await asyncio.wait_for(wake.wait(), timeout=due - time.time())
                except asyncio.TimeoutError:
                    pass
                continue
            try:
                if time.time() >= due or stale:
                    pending.clear()
                    await self.crawl(w)
                else:
                    urls = sorted(pending)
                    pending.clear()
                    await self._crawl_new_urls(w, urls)
            except Exception:
                log.exception("[%s] crawl failed", w.id)
                await asyncio.sleep(60)

    async def crawl(self, w) -> str:
        """Full crawl: check every tracked page/file and discover new ones within the scope."""
        started = time.time()
        state = self.store.watch_state(w.id)
        fingerprint = crawl_fingerprint(w)
        baseline = not state.get("last_crawl") or state.get("crawl_fingerprint") != fingerprint
        aliases = self._root_aliases(w)
        known = {url: row for url, row in self.store.page_rows(w.id).items() if url not in aliases}
        for url in [u for u in known if not self._crawl_kind(w, u)]:
            self.store.delete_page(w.id, url)  # outside the (possibly changed) crawl scope
            del known[url]
        links = self._root_links.get(w.id)
        if links is None:
            try:
                _, (_, links) = await self._fetch_parse(w, w.url, lambda r: self._parse_page(w, r),
                                                        wait_for=w.selector, allow_switch=False)
            except (FetchError, ExtractError) as exc:
                log.warning("[%s] crawl skipped, start page failed: %s", w.id, exc)
                return "crawl skipped (start page failed)"
        visited = set(aliases)
        frontier = self._scoped(w, links, visited)
        tracked = set(known)
        sem = asyncio.Semaphore(w.crawl.concurrency)
        stats: Counter = Counter()
        depth = 1
        while frontier and depth <= w.crawl.max_depth:
            batch = []
            for url, kind in frontier:
                if url not in tracked:
                    if len(tracked) >= w.crawl.max_pages:
                        stats["over_limit"] += 1
                        continue
                    tracked.add(url)
                batch.append((url, kind))
            found = await asyncio.gather(*(self._crawl_visit(w, url, kind, known.get(url), baseline, sem, stats)
                                           for url, kind in batch))
            frontier = []
            if depth < w.crawl.max_depth:
                for page_links in found:
                    frontier += self._scoped(w, page_links, visited)
            depth += 1
        leftovers = [(url, row["kind"]) for url, row in known.items() if url not in visited]
        if leftovers:
            await asyncio.gather(*(self._crawl_visit(w, url, kind, known.get(url), baseline, sem, stats, discover=False)
                                   for url, kind in leftovers))
        self.store.update_watch(w.id, last_crawl=time.time(), crawl_fingerprint=fingerprint)
        summary = (f"{stats['checked']} checked, {stats['new']} new, {stats['changed']} changed, "
                   f"{stats['removed']} removed, {stats['errors']} errors")
        if stats["over_limit"]:
            summary += f", {stats['over_limit']} skipped (max_pages={w.crawl.max_pages})"
        log.info("[%s] crawl %s in %.0fs: %s", w.id, "baseline" if baseline else "done", time.time() - started, summary)
        return f"crawl: {summary}"

    async def _crawl_new_urls(self, w, urls: list[str]) -> None:
        """Pages that just appeared in the start page's links: check them right away."""
        known = self.store.page_urls(w.id)
        sem = asyncio.Semaphore(w.crawl.concurrency)
        stats: Counter = Counter()
        todo = []
        for url in urls:
            kind = self._crawl_kind(w, url)
            if url in known or not kind:
                continue
            if len(known) >= w.crawl.max_pages + 1:
                log.warning("[%s] max_pages=%d reached; new page not tracked: %s", w.id, w.crawl.max_pages, url)
                continue
            known.add(url)
            todo.append((url, kind))
        if todo:
            log.info("[%s] %d new link(s) on the start page; checking them now", w.id, len(todo))
            await asyncio.gather(*(self._crawl_visit(w, url, kind, None, False, sem, stats, discover=False)
                                   for url, kind in todo))

    def _usable_engine(self, w) -> str:
        """The watch's engine, or the next one able to use its proxy (SOCKS without aiohttp-socks)."""
        engine = self.engine_for(w)
        if self._fetcher(engine).supports(w):
            return engine
        return next((name for name in ("impersonate", "browser") if self._fetcher(name).supports(w)), engine)

    async def _crawl_visit(self, w, url: str, kind: str, prev, baseline: bool, sem, stats: Counter,
                           discover: bool = True) -> list:
        async with sem:
            stats["checked"] += 1
            try:
                target = self._prepare_watch(await self._routed(w))
                if kind == "file":
                    await self._check_file(target, url, prev, baseline, stats)
                    return []
                conditional = None
                if prev is not None and prev["snapshot"] and prev["fingerprint"] == watch_fingerprint(w):
                    conditional = {"etag": prev["etag"], "last_modified": prev["last_modified"]}
                result = await self._fetch(target, url, self._usable_engine(target), conditional=conditional)
            except FetchError as exc:
                self._crawl_failure(w, url, prev, exc, stats)
                return []
            if result.not_modified:
                self.store.touch_page(w.id, url)
                return []
            if not result.text and result.body:  # a document served without a file extension
                self._apply_file(w, url, prev, result, baseline, stats)
                return []
            try:
                snap, links = await asyncio.to_thread(self._parse_page, w, result, subpage=True)
            except ExtractError as exc:
                log.debug("[%s] skipped %s: %s", w.id, url, exc)
                return []
            if prev is None or not prev["snapshot"]:
                event = None
                if not baseline:
                    payload, summary, hits = report.new_page_event(w, url, snap, time.time(), self.tz)
                    event = ("new_page", summary, payload, "filtered" if w.only_keywords and not hits else "pending")
                    stats["new"] += 1
                    self._outbox.set()
                    log.info("[%s] NEW page: %s", w.id, url)
                    if event[3] == "pending":
                        self._maybe_alarm(w, f"صفحهٔ جدید: {snap.title or url}", hits, url)
                self.store.record_page(w.id, url, kind="page", digest=snap.digest, snapshot=snap.to_json(),
                                       title=snap.title, engine=result.engine, fingerprint=watch_fingerprint(w),
                                       etag=result.etag, last_modified=result.last_modified, event=event)
            else:
                outcome = await self._apply_snapshot(w, url, prev, snap, result)
                if outcome.startswith("CHANGE"):
                    stats["changed"] += 1
                    log.info("[%s] %s on %s", w.id, outcome, url)
            return links if discover else []

    def _crawl_failure(self, w, url: str, prev, exc: FetchError, stats: Counter) -> None:
        stats["errors"] += 1
        if prev is None:
            log.debug("[%s] cannot fetch %s: %s", w.id, url, exc)
            return
        failures = self.store.page_failed(w.id, url)
        if exc.status in (404, 410) and failures >= 2:
            payload, summary = report.removed_page_event(w, url, prev["title"] or "", time.time(), self.tz)
            self.store.delete_page(w.id, url, event=("removed_page", summary, payload, "pending"))
            stats["removed"] += 1
            self._outbox.set()
            log.info("[%s] page REMOVED: %s", w.id, url)
        else:
            log.info("[%s] cannot fetch %s (%d in a row): %s", w.id, url, failures, exc)

    async def _check_file(self, w, url: str, prev, baseline: bool, stats: Counter) -> None:
        conditional = {"etag": prev["etag"], "last_modified": prev["last_modified"]} if prev is not None else None
        # files of protected sites need the Chrome-fingerprinted client too
        use_impersonate = self.engine_for(w) != "http" or not self.http.supports(w)
        fetcher = self.impersonate if use_impersonate and self.impersonate.available else self.http
        result = await fetcher.fetch(url, w, conditional=conditional, max_bytes=MAX_FILE_BYTES)
        if result.not_modified:
            self.store.touch_page(w.id, url)
            return
        self._apply_file(w, url, prev, result, baseline, stats)

    def _apply_file(self, w, url: str, prev, result, baseline: bool, stats: Counter) -> None:
        content = result.body or result.text.encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        fields = dict(kind="file", digest=digest, title=url.rsplit("/", 1)[-1], engine="http", fingerprint="file",
                      etag=result.etag, last_modified=result.last_modified, size=len(content))
        info = {"size": len(content), "content_type": result.content_type.split(";")[0].strip()}
        if prev is None or prev["kind"] != "file":
            event = None
            if not baseline:
                payload, summary = report.file_event(w, url, "new", info, time.time(), self.tz)
                event = ("file", summary, payload, "pending")
                stats["new"] += 1
                self._outbox.set()
                log.info("[%s] NEW file: %s", w.id, url)
            self.store.record_page(w.id, url, event=event, **fields)
        elif prev["digest"] != digest:
            info["old_size"] = prev["size"]
            payload, summary = report.file_event(w, url, "changed", info, time.time(), self.tz)
            self.store.record_page(w.id, url, changed=True, event=("file", summary, payload, "pending"), **fields)
            stats["changed"] += 1
            self._outbox.set()
            log.info("[%s] file CHANGED: %s", w.id, url)
        else:
            self.store.touch_page(w.id, url, etag=result.etag, last_modified=result.last_modified)

    # ------------------------------------------------------------------ wake-up alarms & diagnostics

    def _maybe_alarm(self, w, detail: str, hits: list, url: str | None = None) -> None:
        """Wake-up mode: repeat an urgent private alert until an admin presses "seen"."""
        if not w.alarm or not isinstance(self.notifier, TelegramNotifier):
            return
        if w.keywords and not hits:
            return  # with keywords set, only matching changes are urgent
        admins = self.store.admin_ids()
        if not admins:
            log.warning("[%s] wake-up alarm skipped: no admin has opened the bot yet", w.id)
            return
        previous = self._alarm_by_watch.pop(w.id, None)
        if previous in self._alarms:
            self._alarms.pop(previous).cancel()
        self._alarm_seq += 1
        alarm_id = self._alarm_seq
        self._alarm_by_watch[w.id] = alarm_id
        self._alarms[alarm_id] = asyncio.create_task(
            self._alarm_loop(alarm_id, w, detail, url or w.page_url, admins), name=f"alarm:{w.id}")

    async def _alarm_loop(self, alarm_id: int, w, detail: str, url: str, admins: list[str]) -> None:
        markup = {"inline_keyboard": [[{"text": "✅ دیدم — قطع هشدار", "callback_data": f"ak:{alarm_id}"}],
                                      [{"text": report.OPEN_PAGE, "url": url}]]}
        try:
            for round_number in range(1, ALARM_ROUNDS + 1):
                text = (f"🚨🚨🚨 <b>هشدار فوری</b> ({fa_digits(round_number)} از {fa_digits(ALARM_ROUNDS)})\n"
                        f"<b>«{esc(w.label)}»</b>\n\n"
                        f"<blockquote>{esc(truncate(detail, 500))}</blockquote>\n\n"
                        "👉 همین حالا صفحه را باز کنید و اقدام کنید.\n"
                        "🔕 برای قطع هشدار، «✅ دیدم» را بزنید.")
                for chat_id in admins:
                    try:
                        await self.notifier.send_text(chat_id, text, reply_markup=markup)
                    except NotifyError as exc:
                        log.warning("[%s] alarm to %s failed: %s", w.id, chat_id, exc)
                await asyncio.sleep(ALARM_INTERVAL)
        finally:
            self._alarms.pop(alarm_id, None)
            if self._alarm_by_watch.get(w.id) == alarm_id:
                self._alarm_by_watch.pop(w.id, None)

    def ack_alarm(self, alarm_id: int) -> bool:
        task = self._alarms.pop(alarm_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    async def diagnose(self, url: str, base=None) -> list[tuple[str, str, bool, str]]:
        """Try every fetch engine on ``url`` from this machine — directly and through the fallback proxy —
        and report what works: rows of (route, engine, ok, detail). Nothing is stored."""
        probe = replace(base, id="_diagnose", engine="auto") if base is not None else \
            Watch(id="_diagnose", url=url, timeout_seconds=30, challenge_wait_seconds=20)
        routes = [("direct", probe)]
        if self._may_reroute(probe):
            proxy = await self.fallback_proxy()
            if proxy is not None:
                routes.append(("fallback", replace(probe, proxy=proxy)))
        results = []
        for route, target in routes:
            for engine in ("http", "impersonate", "browser"):
                fetcher = self._fetcher(engine)
                if not fetcher.supports(target):
                    reason = fetcher.unavailable if not fetcher.available else "needs the aiohttp-socks package"
                    results.append((route, engine, False, reason or "not available"))
                    continue
                started = time.monotonic()
                try:
                    result = await self._fetch(target, url, engine, wait_for=target.wait_selector)
                except FetchError as exc:
                    results.append((route, engine, False, truncate(str(exc), 160)))
                    continue
                html = "html" in result.content_type.lower() or not result.content_type
                size = visible_text_length(result.text) if html else len(result.body or result.text.encode("utf-8"))
                hint = detect_block(result.text) if html else None
                ok = hint is None and size > (150 if html else 0)
                results.append((route, engine, ok,
                                f"HTTP {result.status} · {fa_number(size)} حرف · {fa_elapsed(time.monotonic() - started)}"
                                + (f" · {hint}" if hint else "")))
        return results

    async def screenshot(self, w, url: str | None = None) -> bytes:
        """JPEG of what this watch looks at (or a specific URL), fetched the way the watch is."""
        target = await self._routed(w)
        page_url = url or w.page_url
        # Priority: subpage → whole page; region='page' → whole page; else use the watch selector.
        if url is not None and url != w.page_url:
            selector = ""
        elif getattr(w, "screenshot_region", "watch") == "page":
            selector = ""
        else:
            selector = w.selector if w.type in ("page", "headlines") else ""
        return await self.browser.screenshot(page_url, target, selector=selector)

    # ------------------------------------------------------------------ screenshots (Sprint 2.1)

    def _shots_dir(self):
        return self.config.data_dir / "shots"

    def _save_shot(self, watch_id: str, data: bytes) -> str:
        """Content-addressed screenshot storage; returns the sha256 digest.

        The same screenshot (same bytes) shares a single file on disk (D3 for free).
        """
        digest = hashlib.sha256(data).hexdigest()
        path = self._shots_dir() / watch_id / digest[:2] / f"{digest}.jpg"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            try:
                tmp.write_bytes(data)
                tmp.replace(path)
            except OSError:
                log.debug("could not save screenshot to %s", path, exc_info=True)
        return digest

    def _shot_path(self, watch_id: str, digest: str):
        if not digest:
            return None
        path = self._shots_dir() / watch_id / digest[:2] / f"{digest}.jpg"
        return path if path.exists() else None

    @staticmethod
    def _shot_caption(w, payload: dict) -> str:
        label = getattr(w, "label", "") or "سایت"
        header = payload.get("header", "") or ""
        return f"📸 «{esc(label)}»\n{truncate(header, 900)}"

    def _prune_shots(self, max_age_days: int = 90) -> int:
        """Delete screenshot files older than max_age_days (Sprint 2.3). Returns the count."""
        root = self._shots_dir()
        if not root.exists():
            return 0
        cutoff = time.time() - max_age_days * 86400
        deleted = 0
        for path in root.rglob("*.jpg"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    deleted += 1
            except OSError:
                continue
        for directory in sorted(root.rglob("*"), reverse=True):
            if directory.is_dir():
                try:
                    directory.rmdir()
                except OSError:
                    pass
        return deleted

    async def _enqueue_daily_screenshots(self) -> int:
        """Queue one fresh screenshot per watch with screenshot_daily=True (Sprint 2.3)."""
        count = 0
        for w in self.watches:
            if not getattr(w, "screenshot_daily", False):
                continue
            try:
                image = await self.screenshot(w)
            except Exception as exc:
                log.debug("[%s] daily screenshot failed: %s", w.id, exc)
                continue
            digest = self._save_shot(w.id, image)
            header = (f"📸 <b>{esc(w.label)}</b> — عکس روزانه\n"
                      f"🕒 {fa_datetime(time.time(), self.tz)}\n"
                      f"{truncate(self.kind_label(w), 100)}")
            payload = report.info_event(header, [], silent=True)
            payload["shots"] = [{"digest": digest, "filename": f"{w.id}.jpg"}]
            payload["screenshot_audience"] = getattr(w, "screenshot_audience", "channel")
            payload["deliver_mode"] = "screenshot"
            self.store.add_event(w.id, w.page_url, "info", f"عکس روزانه {w.label}", payload)
            count += 1
        if count:
            self._outbox.set()
        return count

    # ------------------------------------------------------------------ tips for the admins

    def _tip_due(self, name: str, watch_id: str, every: float = 7 * 86400) -> bool:
        """At most one tip of a kind per watch per week; never again once dismissed ("off")."""
        key = f"tip:{name}:{watch_id}"
        value = self.store.get_setting(key, "")
        if value == "off":
            return False
        try:
            last = float(value or 0)
        except ValueError:
            last = 0.0
        if time.time() - last < every:
            return False
        self.store.set_setting(key, str(time.time()))
        return True

    def _maybe_suggest_headlines(self, w) -> None:
        """A page that changes all the time is usually a news front page: offer the headlines mode."""
        if w.type != "page" or w.crawl or not isinstance(self.notifier, TelegramNotifier):
            return
        recent = self.store.count_events(w.id, ("change",), time.time() - 3600)
        key = self._key(w) if recent >= NOISY_CHANGES else None
        if key is None or not self._tip_due("noisy", w.id):
            return
        header = (f"💡 <b>پیشنهاد برای «{esc(w.label)}»</b>\n"
                  f"این صفحه در یک ساعت گذشته <b>{fa_digits(recent)} بار</b> تغییر کرده است.")
        blocks = ["احتمالاً سایت خبری است: تیترها، زمان‌ها و ترتیب مطالبش مدام عوض می‌شود و پیام‌های زیادی می‌سازد.",
                  "📰 در حالت <b>«تیترهای جدید»</b> فقط خبرهای تازه (تیتر + لینک) گزارش می‌شوند؛ جابه‌جایی مطالب و "
                  "تغییر زمان‌ها نادیده گرفته می‌شود."]
        buttons = [[{"text": "📰 تبدیل به «تیترهای جدید»", "callback_data": f"+hl:{key}"}],
                   [{"text": "🔕 فقط بی‌صدا شود", "callback_data": f"+sl:{key}"},
                    {"text": "نه، همین خوب است", "callback_data": f"+nt:{key}"}]]
        self._enqueue_info(header, blocks, silent=True, buttons=buttons)

    def _after_baseline(self, w) -> None:
        """A site added while it could not be opened is reachable now: offer the precise set-up."""
        if self._fixed_watches is not None:
            return
        record = self.registry.get(watch_id=w.id)
        if record is None or not record.spec.get("_review"):
            return
        self.registry.update(record.key, {k: v for k, v in record.spec.items() if k != "_review"})
        header = f"✅ <b>«{esc(w.label)}» حالا باز می‌شود</b>"
        blocks = ["این سایت هنگام افزودن باز نمی‌شد، برای همین «کل صفحه» زیر نظر گرفته شد و نسخهٔ مرجع آن الان "
                  "ذخیره شد. حالا می‌توانید حالت دقیق پایش را انتخاب کنید — مثلاً «🎓 آزمون‌های گوته: ظرفیت و "
                  "ثبت‌نام» یا «📰 تیترهای جدید»."]
        buttons = [[{"text": "🎯 انتخاب حالت دقیق پایش", "callback_data": f"+er:{record.key}"}]]
        self._enqueue_info(header, blocks, silent=False, buttons=buttons)

    # ------------------------------------------------------------------ delivery

    def _enqueue_info(self, header: str, blocks: list[str] | None = None, silent: bool = True,
                      buttons: list | None = None) -> None:
        summary = re.sub(r"<[^>]+>", "", header.split("\n", 1)[0])
        self.store.add_event(SYSTEM, None, "info", summary, report.info_event(header, blocks, silent, buttons))
        self._outbox.set()

    async def _dispatch_loop(self) -> None:
        while True:
            self._outbox.clear()
            try:
                await self.dispatch_pending()
            except Exception:
                log.exception("notification dispatcher failed")
            try:
                await asyncio.wait_for(self._outbox.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass

    async def dispatch_pending(self) -> int:
        """Deliver due events in order (per watch); cooldown watches get one digest per window."""
        now = time.time()
        groups: dict[str, list] = {}
        for row in self.store.pending_events(now):
            groups.setdefault(row["watch_id"], []).append(row)
        delivered = 0
        for watch_id, events in groups.items():
            w = self._by_id.get(watch_id)
            cooldown = w.cooldown_minutes * 60 if w else 0
            if cooldown <= 0:
                for event in events:
                    if not await self._deliver([event], w):
                        break
                    delivered += 1
                continue
            for event in [e for e in events if e["kind"] not in DIGESTABLE]:
                if not await self._deliver([event], w):
                    break
                delivered += 1
            batch = [e for e in events if e["kind"] in DIGESTABLE]
            last = self.store.watch_state(watch_id).get("last_notified") or 0
            if batch and now - last >= cooldown and await self._deliver(batch, w):
                delivered += len(batch)
        return delivered

    def _targets(self, kind: str) -> list[str]:
        """Site changes go to the configured chats; operational messages to the panel admins (if any)."""
        if (isinstance(self.notifier, TelegramNotifier) and kind in ("info", "error", "recovered")
                and self.store.get_setting("system_messages", "admins") == "admins"):
            admins = self.store.admin_ids()
            if admins:
                return admins
        return self.chat_ids

    async def _deliver(self, events: list, w, targets: list[str] | None = None) -> bool:
        payloads = [json.loads(event["payload"]) for event in events]
        payload = payloads[0] if len(events) == 1 else report.digest_payload(
            w, payloads, events[0]["created"], events[-1]["created"])
        parts = build_parts(payload)
        markup = {"inline_keyboard": payload["buttons"]} if payload.get("buttons") else None
        last_text = max((index for index, (kind, _) in enumerate(parts) if kind == "text"), default=-1)
        single = len(events) == 1
        targets = targets or self._targets(events[0]["kind"])
        progress = set(json.loads(events[0]["progress"] or "[]")) if single else set()
        failures: dict[str, NotifyError] = {}

        # Sprint 2.1: how to deliver this event (text / screenshot / both) and who gets the photo.
        deliver_mode = payload.get("deliver_mode") or "text"
        shots = [s for s in (payload.get("shots") or []) if isinstance(s, dict) and s.get("digest")]
        if deliver_mode == "screenshot" and not shots:
            deliver_mode = "text"  # capture failed earlier; keep the text report so nothing is lost
        text_targets = list(targets)
        shot_targets: list[str] = []
        if shots:
            # Sprint 2.3: use self.chat_ids as the canonical "channel" target. For "info"
            # events the text targets may be admins only, so we must not derive shots from them.
            audience = payload.get("screenshot_audience") or "channel"
            if audience == "channel":
                shot_targets = list(self.chat_ids)
            elif audience == "admins":
                shot_targets = list(self.store.admin_ids())
                if not shot_targets:
                    shot_targets = list(self.chat_ids)  # no admin registered yet
            elif audience == "both":
                seen = set()
                for t in [*self.chat_ids, *self.store.admin_ids()]:
                    if t not in seen:
                        shot_targets.append(t)
                        seen.add(t)

        # --- text parts (skipped in "screenshot"-only mode)
        is_silent = bool(payload.get("silent"))
        if not is_silent and self.store.get_setting("quiet_hours", "off") == "on":
            now_hour = datetime.now(self.tz).hour
            if now_hour >= 23 or now_hour < 7:
                is_silent = True
        if deliver_mode != "screenshot":
            for chat_id in text_targets:
                try:
                    for index, part in enumerate(parts):
                        key = f"{chat_id}:{index}"
                        if key in progress:
                            continue
                        await self.notifier.send_part(chat_id, part, is_silent,
                                                      markup if index == last_text else None)
                        progress.add(key)
                        if single:
                            self.store.set_event_progress(events[0]["id"], sorted(progress))
                except NotifyError as exc:
                    failures[chat_id] = exc

        # --- photos
        for chat_id in shot_targets:
            try:
                for shot in shots:
                    digest = shot.get("digest") or ""
                    if not digest:
                        continue
                    key = f"{chat_id}:shot:{digest}"
                    if key in progress:
                        continue
                    path = self._shot_path(events[0]["watch_id"], digest)
                    if path is None:
                        continue
                    try:
                        data = path.read_bytes()
                    except OSError:
                        continue
                    # In screenshot-only mode the buttons ride on the photo; in "both" they are already on the text.
                    markup_for_photo = markup if deliver_mode == "screenshot" else None
                    await self.notifier.send_photo(chat_id, shot.get("filename", "shot.jpg"), data,
                                                   self._shot_caption(w, payload),
                                                   reply_markup=markup_for_photo)
                    progress.add(key)
                    if single:
                        self.store.set_event_progress(events[0]["id"], sorted(progress))
            except NotifyError as exc:
                failures[chat_id] = exc
        ids = [event["id"] for event in events]
        if not failures:
            self.store.mark_events_sent(ids)
            if w is not None:
                self.store.update_watch(w.id, last_notified=time.time())
            return True

        attempts = max(event["attempts"] for event in events) + 1
        details = "; ".join(f"chat {chat}: {exc}" for chat, exc in failures.items())
        advice = " ".join(filter(None, {explain_telegram_error(exc) for exc in failures.values()}))
        rejected = all(isinstance(exc, TelegramApiError) and exc.code in (400, 403) for exc in failures.values())
        bad_message = all(isinstance(exc, TelegramApiError) and exc.code == 400
                          and _CONTENT_ERROR.search(exc.description) for exc in failures.values())
        delivered_somewhere = len(failures) < len(targets)
        if rejected and not delivered_somewhere and targets != self.chat_ids and not bad_message:
            log.warning("Admins cannot be reached (%s); sending to the configured chats instead", details)
            return await self._deliver(events, w, targets=self.chat_ids)
        if (rejected and delivered_somewhere) or (bad_message and attempts >= 3):
            # Retrying a message Telegram rejects (bad chat id, invalid content) would block every
            # later notification of this watch, so close it and move on.
            self.store.finish_events(ids, "sent" if delivered_somewhere else "failed", details)
            log.error("Notification #%s could not be delivered everywhere: %s %s", ids[0], details, advice)
            if w is not None and delivered_somewhere:
                self.store.update_watch(w.id, last_notified=time.time())
            return True
        retry_after = max((exc.retry_after or 0) for exc in failures.values())
        delay = max(retry_after, min(900, 10 * 2 ** min(attempts - 1, 7)))
        for event in events:
            self.store.mark_event_retry(event["id"], attempts, time.time() + delay, details)
        log.error("Notification not delivered (attempt %d, next try in %ds): %s %s", attempts, delay, details, advice)
        return False

    # ------------------------------------------------------------------ reports & commands

    def kind_label(self, w) -> str:
        """e.g. "📄 صفحه + خزش کل بخش", "🎓 آزمون‌های گوته"."""
        if w.type == "json" and "examfinder" in w.url:
            return "🎓 آزمون‌های گوته"
        if w.type == "items" and "t.me/s/" in w.url:
            return "📢 کانال تلگرام"
        return f"{TYPE_ICONS[w.type]} {TYPE_LABELS[w.type]}" + (" + خزش کل بخش" if w.crawl else "")

    def _self_check(self) -> dict:
        """Report the availability of all critical subsystems (Sprint 4.4).

        Called once at start; the summary is logged and appears in the startup
        message, so an admin sees at a glance whether anything is missing.
        """
        return {
            "http": bool(getattr(self.http, "available", True)),
            "impersonate": bool(getattr(self.impersonate, "available", False)),
            "impersonate_reason": getattr(self.impersonate, "unavailable", "") or "",
            "browser": bool(getattr(self.browser, "available", False)),
            "browser_reason": getattr(self.browser, "unavailable", "") or "",
            "challenge": bool(getattr(self, "_challenge_ready", False)),
            "notifier": self.notifier.name if self.notifier else "none",
        }

    def _self_check_lines(self) -> list[str]:
        info = self._self_check()
        lines = ["🩺 <b>بررسی وضعیت موتورها</b>"]
        lines.append(f"  🌐 HTTP سریع: {'✅' if info['http'] else '❌'}")
        lines.append(f"  🛡 شبیه‌ساز کروم: {'✅' if info['impersonate'] else '❌'}"
                     + (f" — {esc(info['impersonate_reason'])}" if info.get("impersonate_reason") else ""))
        lines.append(f"  🌐 مرورگر: {'✅' if info['browser'] else '❌'}"
                     + (f" — {esc(info['browser_reason'])}" if info.get("browser_reason") else ""))
        lines.append(f"  🛡 challenge server: {'✅' if info['challenge'] else '❌'}")
        lines.append(f"  📨 notifier: {esc(info['notifier'])}")
        return lines

    def _startup_report(self) -> tuple[str, list[str]]:
        header = (f"🟢 <b>مانیتور شروع به کار کرد</b>\n🕒 {fa_datetime(time.time(), self.tz)}\n"
                  f"👁 <b>{fa_digits(len(self.watches))}</b> سایت زیر نظر است\n{report.RULE}")
        lines = [f"• <b>{esc(w.label)}</b>\n   {self.kind_label(w)} · هر {human_duration(w.interval_seconds)}"
                 for w in self.watches[:40]]
        if len(self.watches) > 40:
            lines.append(f"… و {fa_digits(len(self.watches) - 40)} سایت دیگر")
        blocks = ["\n".join(lines[i:i + 10]) for i in range(0, len(lines), 10)]
        try:
            blocks.append("\n".join(self._self_check_lines()))
        except Exception:
            log.debug("could not append self-check to startup report", exc_info=True)
        if isinstance(self.notifier, TelegramNotifier) and self.config.telegram.commands:
            blocks.append("🛠 برای مدیریت سایت‌ها، ربات را در چت خصوصی باز کنید (/panel).")
        return header, blocks

    def status_report(self, daily: bool = False) -> tuple[str, list[str]]:
        now = time.time()
        counts = self.store.event_counts_since(now - 86400)
        groups: dict[str, list[str]] = {"failing": [], "ok": [], "waiting": [], "paused": []}
        total = 0
        for w in self.all_watches:
            state = self.store.watch_state(w.id)
            changes = sum(counts.get(w.id, Counter())[k] for k in DIGESTABLE)
            total += changes
            head = f"• <b>{esc(w.label)}</b> — {self.kind_label(w)}"
            route = " · 🛡 از طریق پروکسی" if self._may_reroute(w) and self.route_of(w) == "fallback" else ""
            if not w.enabled:
                groups["paused"].append(head)
            elif state.get("consecutive_errors"):
                since = human_duration(now - (state.get("first_error_at") or now))
                groups["failing"].append(
                    f"{head}\n   ❌ {fa_digits(state['consecutive_errors'])} خطای پیاپی (از {since} پیش): "
                    f"<code>{esc(truncate(state.get('last_error') or '', 90))}</code>{route}")
            elif state.get("last_ok"):
                groups["ok"].append(
                    f"{head}\n   🕒 آخرین بررسی: {human_duration(now - state['last_ok'])} پیش · "
                    f"هر {human_duration(w.interval_seconds)} · 🔔 ۲۴ ساعت: {fa_digits(changes)}{route}")
            else:
                groups["waiting"].append(f"{head}\n   ⏳ هنوز بررسی نشده")
        title = "🗓 <b>گزارش روزانهٔ مانیتور</b>" if daily else "📊 <b>وضعیت مانیتور</b>"
        summary = [f"✅ {fa_digits(len(groups['ok']))} سالم"]
        if groups["failing"]:
            summary.append(f"⚠️ {fa_digits(len(groups['failing']))} خطا")
        if groups["paused"]:
            summary.append(f"⏸ {fa_digits(len(groups['paused']))} متوقف")
        lines = [title, f"🕒 {fa_datetime(now, self.tz)}", f"⏱ روشن از {human_duration(now - self.started_at)} پیش",
                 f"👁 {fa_digits(len(self.all_watches))} سایت: " + " · ".join(summary),
                 f"🔔 تغییرات و خبرهای ۲۴ ساعت اخیر: <b>{fa_digits(total)}</b>"]
        pending = self.store.pending_count()
        if pending:
            lines.append(f"📮 {fa_digits(pending)} پیام در صف ارسال")
        lines.append(report.RULE)
        blocks = []
        for key, heading in (("failing", "⚠️ <b>نیازمند توجه</b>"), ("ok", "✅ <b>سالم</b>"),
                             ("waiting", "⏳ <b>در انتظار اولین بررسی</b>"), ("paused", "⏸ <b>متوقف</b>")):
            entries = groups[key]
            for index in range(0, len(entries), 8):
                chunk = "\n\n".join(entries[index:index + 8])
                blocks.append(f"{heading} ({fa_digits(len(entries))})\n\n{chunk}" if index == 0 else chunk)
        if not self.all_watches:
            blocks.append("هنوز سایتی اضافه نشده است.")
        return "\n".join(lines), blocks

    async def _housekeeping_loop(self) -> None:
        next_report = self._next_report_time()
        last_prune = 0.0
        while True:
            now = time.time()
            if now - last_prune > 6 * 3600:
                try:
                    self.store.prune(self.config.history_days)
                except Exception:
                    log.exception("pruning the database failed")
                try:
                    deleted = self._prune_shots()
                    if deleted:
                        log.info("Pruned %d old screenshot file(s)", deleted)
                except Exception:
                    log.exception("pruning screenshots failed")
                last_prune = now
            await self._maybe_backup(now)
            if next_report and now >= next_report:
                try:
                    if self.store.get_setting("daily_report", "on") == "on":
                        self._enqueue_info(*self.status_report(daily=True))
                        await self._enqueue_daily_screenshots()
                except Exception:
                    log.exception("daily report failed")
                next_report = self._next_report_time()
            await asyncio.sleep(30)

    def _next_report_time(self) -> float | None:
        hour = self.config.daily_report_hour
        if hour is None:
            return None
        now = datetime.now(self.tz)
        target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target.timestamp()

    async def _maybe_backup(self, now: float) -> None:
        """One copy of monitor.db per day: sites added from the Telegram panel exist only in that file."""
        try:
            last = float(self.store.get_setting("last_backup", "0") or 0)
        except ValueError:
            last = 0.0
        if now - last < BACKUP_EVERY:
            return
        self.store.set_setting("last_backup", str(now))  # a failing backup is retried tomorrow, not every 30 s
        try:
            target = await asyncio.to_thread(self.store.backup, self.config.data_dir / "backups", BACKUP_KEEP)
            problem = "" if target is not None else "the copy failed its integrity check"
        except Exception as exc:
            log.exception("database backup failed")
            target, problem = None, f"{type(exc).__name__}: {exc}"
        if target is not None:
            log.info("Database backup written: %s", target.name)
        else:
            self._enqueue_info("⚠️ <b>پشتیبان‌گیری از دیتابیس ناموفق بود</b>", [f"<code>{esc(truncate(problem, 300))}</code>"])

    async def _heartbeat_once(self) -> bool:
        """Ping the heartbeat URL, but only while alerts can still get out; True when a ping was sent."""
        stale = self.store.overdue_outbox_age()
        if stale >= HEARTBEAT_OUTBOX_STALE:
            log.warning("Heartbeat withheld: a notification has been waiting for %d min", int(stale // 60))
            return False
        return await self._ping(self.config.heartbeat_url)

    async def _heartbeat_loop(self) -> None:
        """Dead-man's switch: an outside service (healthchecks.io, Uptime Kuma, ...) raises the alarm when
        these pings stop - server down, process stuck, or notifications piling up undelivered."""
        while True:
            await self._heartbeat_once()
            await asyncio.sleep(HEARTBEAT_EVERY)

    @staticmethod
    async def _ping(url: str) -> bool:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(url) as resp:
                    return resp.status < 400
        except Exception as exc:  # never log the URL: it usually contains a secret
            log.warning("Heartbeat ping failed (%s)", type(exc).__name__)
            return False

    # ------------------------------------------------------------------ one-shot (CLI)

    async def run_once(self, watches: list) -> list[tuple[object, str]]:
        results = []
        for w in watches:
            outcome = await self.check_watch(w)
            if w.crawl and not outcome.startswith("error"):
                outcome += " | " + await self.crawl(w)
            results.append((w, outcome))
        await self.dispatch_pending()
        return results
