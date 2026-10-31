"""Tests for the foundation fixes ("Welle 1"): Mini App login, SSRF guard, regex time limit, supervised
background tasks, database backup and heartbeat, and parsing off the event loop.

Run from the project folder:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from importlib.util import find_spec
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlencode

from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webmonitor import config as config_module  # noqa: E402
from webmonitor import netguard  # noqa: E402
from webmonitor.bot import AdminBot  # noqa: E402
from webmonitor.config import ConfigError, SafePattern, parse_config, parse_watch  # noqa: E402
from webmonitor.engine import Monitor, supervise  # noqa: E402
from webmonitor.extract import page_snapshot, parse_html  # noqa: E402
from webmonitor.fetchers import FetchError, HttpFetcher, ImpersonateFetcher  # noqa: E402
from webmonitor.miniapp import MiniApp, make_admin_token, miniapp_secret, verify_admin_token  # noqa: E402
from webmonitor.storage import Store  # noqa: E402

BOT_TOKEN = "123456:" + "A" * 35
HAS_CURL = find_spec("curl_cffi") is not None


def make_config(tmp: Path, **top):
    raw = {"data_dir": str(tmp / "data"), "notify_startup": False, "daily_report_hour": None, "watches": [], **top}
    return parse_config(raw, tmp / "cfg.json")


def make_watch(url: str, **extra):
    return parse_watch({"id": "w", "url": url, "engine": "http", "timeout_seconds": 10, "min_content_length": 1,
                        **extra})


async def serve(routes: dict) -> tuple[web.AppRunner, int]:
    app = web.Application()
    for path, handler in routes.items():
        app.router.add_get(path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


def init_data(bot_token: str, user_id: int, now: float | None = None) -> str:
    """Launch data signed the way Telegram signs it for a Web App."""
    pairs = {"auth_date": str(int(now or time.time())), "query_id": "AAH",
             "user": json.dumps({"id": user_id, "first_name": "Test"})}
    check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    return urlencode({**pairs, "hash": hmac.new(key, check.encode(), hashlib.sha256).hexdigest()})


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w1-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


# =========================================================================== Mini App login

class FakeRequest:
    def __init__(self, headers=None, query=None):
        self.headers = headers or {}
        self.query = query or {}


class MiniAppAuthTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.store = Store(self.tmp / "t.db")
        self.addCleanup(self.store.close)
        self.telegram = SimpleNamespace(token=BOT_TOKEN, admin_ids=[], chat_ids=["-1001"])
        self.app = MiniApp(SimpleNamespace(config=SimpleNamespace(telegram=self.telegram), store=self.store))

    def auth(self, **headers):
        return self.app._authenticate(FakeRequest(headers))[0]

    def test_token_signed_with_the_bot_token_is_rejected(self):
        self.store.touch_admin("555", "Admin")
        for uid in ("admin", "555"):
            forged = make_admin_token(BOT_TOKEN, uid)
            self.assertFalse(self.auth(**{"X-Admin-Token": forged}), uid)

    def test_signed_token_works_for_a_known_admin_only(self):
        secret = miniapp_secret(self.store)
        self.store.touch_admin("555", "Admin")
        self.assertTrue(self.auth(**{"X-Admin-Token": make_admin_token(secret, "555")}))
        self.assertFalse(self.auth(**{"X-Admin-Token": make_admin_token(secret, "777")}))
        self.assertFalse(self.auth(**{"X-Admin-Token": make_admin_token(secret, "admin")}))

    def test_secret_is_random_and_stable(self):
        first = miniapp_secret(self.store)
        self.assertGreaterEqual(len(first), 64)
        self.assertEqual(first, miniapp_secret(self.store))
        self.assertNotIn(BOT_TOKEN, first)

    def test_token_is_bound_to_its_user_and_expires(self):
        secret = miniapp_secret(self.store)
        token = make_admin_token(secret, "555", ttl=300, now=1000.0)
        self.assertEqual(verify_admin_token(token, secret, now=1100.0), "555")
        self.assertIsNone(verify_admin_token(token, secret, now=2000.0))
        self.assertIsNone(verify_admin_token(token, "another-secret", now=1100.0))
        self.assertEqual(make_admin_token(secret, ""), "")

    def test_without_any_known_admin_nobody_gets_in(self):
        self.assertFalse(self.auth(**{"X-Telegram-Init-Data": init_data(BOT_TOKEN, 999)}))

    def test_known_admins_get_in_through_telegram_launch_data(self):
        self.store.touch_admin("555", "Admin")
        self.assertTrue(self.auth(**{"X-Telegram-Init-Data": init_data(BOT_TOKEN, 555)}))
        self.assertFalse(self.auth(**{"X-Telegram-Init-Data": init_data(BOT_TOKEN, 556)}))
        self.assertFalse(self.auth(**{"X-Telegram-Init-Data": init_data("999999:" + "B" * 35, 555)}))

    def test_configured_admins_and_private_chats_count(self):
        self.telegram.admin_ids = ["321"]
        self.telegram.chat_ids = ["-1001", "654"]
        for uid in (321, 654):
            self.assertTrue(self.auth(**{"X-Telegram-Init-Data": init_data(BOT_TOKEN, uid)}), uid)

    def test_credentials_in_the_query_string_are_ignored(self):
        self.store.touch_admin("555", "Admin")
        query = {"t": make_admin_token(miniapp_secret(self.store), "555"), "initData": init_data(BOT_TOKEN, 555)}
        self.assertFalse(self.app._authenticate(FakeRequest(query=query))[0])

    def test_local_console_mode_without_token_stays_open(self):
        self.telegram.token = ""
        self.assertEqual(self.app._authenticate(FakeRequest()), (True, "local"))


class MiniAppLinkTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.store = Store(self.tmp / "t.db")
        self.addCleanup(self.store.close)
        self.config = SimpleNamespace(miniapp_url="https://app.example", telegram=SimpleNamespace(token=BOT_TOKEN))
        self.bot = AdminBot.__new__(AdminBot)
        self.bot.m = SimpleNamespace(config=self.config, store=self.store)
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        os.environ.pop("WEBMONITOR_MINIAPP_URL", None)
        self.addCleanup(patcher.stop)

    def test_web_app_button_carries_no_token(self):
        (label, target), = self.bot._miniapp_row("123")
        self.assertEqual(target, "webapp:https://app.example/app")
        self.assertEqual(self.bot._miniapp_row("123", 5)[0][1], "webapp:https://app.example/app?site=5")

    def test_plain_link_carries_a_user_bound_token_in_the_fragment(self):
        self.config.miniapp_url = "http://app.example"
        (label, target), = self.bot._miniapp_row("123")
        base, fragment = target.split("#", 1)
        self.assertEqual(base, "http://app.example/app")
        token = fragment.removeprefix("t=")
        self.assertEqual(verify_admin_token(token, miniapp_secret(self.store)), "123")

    def test_no_link_is_ever_posted_into_a_group_or_channel(self):
        self.assertEqual(self.bot._miniapp_row("-1001234"), [])

    def test_the_link_can_be_switched_off(self):
        self.config.miniapp_url = "off"
        self.assertEqual(self.bot._miniapp_row("123"), [])


# =========================================================================== SSRF guard

class NetguardTests(unittest.IsolatedAsyncioTestCase):
    def test_classification_of_addresses(self):
        for address in ("127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.5.5", "169.254.169.254", "::1",
                        "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1", "not-an-ip"):
            self.assertFalse(netguard.is_public_ip(address), address)
        for address in ("8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"):
            self.assertTrue(netguard.is_public_ip(address), address)

    async def test_hosts(self):
        self.assertFalse(await netguard.is_public_host("127.0.0.1"))
        self.assertFalse(await netguard.is_public_host("localhost"))
        self.assertTrue(await netguard.is_public_host("93.184.216.34"))
        self.assertTrue(await netguard.is_public_host("no-such-host.invalid"))  # unresolvable: the fetch reports it

    async def test_redirect_targets(self):
        await netguard.ensure_public_url("http://93.184.216.34/page")
        for url in ("http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                    "ftp://93.184.216.34/x", "http:///nohost"):
            with self.assertRaises(netguard.UnsafeTarget, msg=url):
                await netguard.ensure_public_url(url)

    def test_relative_locations_are_resolved(self):
        self.assertEqual(netguard.redirect_url("https://a.example/x/y", "/z"), "https://a.example/z")
        self.assertEqual(netguard.redirect_url("https://a.example/x/y", "https://b.example/"), "https://b.example/")


class FetchGuardCase(unittest.IsolatedAsyncioTestCase):
    """A site on a public host must not be able to send the monitor to an internal address."""

    fetcher_class = HttpFetcher

    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w1-"))
        self.secret_hits = Counter()

        async def secret(request):
            self.secret_hits["secret"] += 1
            return web.Response(text="<html><body><p>INTERNAL-SECRET</p></body></html>", content_type="text/html")

        async def ok(request):
            return web.Response(text="<html><body><p>hello</p></body></html>", content_type="text/html")

        self.secret_runner, self.secret_port = await serve({"/secret": secret})

        async def to_internal(request):
            raise web.HTTPFound(f"http://127.0.0.1:{self.secret_port}/secret")

        async def to_relative(request):
            raise web.HTTPFound("/ok")

        async def forever(request):
            raise web.HTTPFound("/loop")

        self.runner, self.port = await serve({"/ok": ok, "/to-internal": to_internal, "/to-relative": to_relative,
                                              "/loop": forever})
        self.config = make_config(self.tmp)
        self.fetcher = self.fetcher_class(self.config)

    async def asyncTearDown(self):
        await self.fetcher.close()
        await self.runner.cleanup()
        await self.secret_runner.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    async def fetch(self, path: str):
        return await self.fetcher.fetch(self.url(path), make_watch(self.url(path)))

    def pretend_public(self, peer_check: bool = False):
        """Treat the (local) test host as public, so that the guard is active."""
        patches = [mock.patch("webmonitor.fetchers.is_public_host", new=mock.AsyncMock(return_value=True))]
        if not peer_check:
            patches.append(mock.patch("webmonitor.fetchers.is_public_ip", new=mock.Mock(return_value=True)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)


class HttpFetchGuardTests(FetchGuardCase):
    async def test_private_targets_stay_reachable_and_redirects_are_followed(self):
        result = await self.fetch("/to-relative")
        self.assertIn("hello", result.text)
        self.assertTrue(result.final_url.endswith("/ok"))
        self.assertIn("INTERNAL-SECRET", (await self.fetch("/to-internal")).text)  # deliberately private: allowed

    async def test_redirect_from_a_public_host_to_an_internal_address_is_refused(self):
        self.pretend_public()
        with self.assertRaises(FetchError) as caught:
            await self.fetch("/to-internal")
        self.assertEqual(caught.exception.kind, "unsafe")
        self.assertEqual(self.secret_hits["secret"], 0)

    async def test_a_public_name_that_resolves_to_a_private_address_is_refused(self):
        self.pretend_public()
        with self.assertRaises(FetchError) as caught:
            await self.fetcher.fetch(f"http://localhost:{self.port}/ok", make_watch(f"http://localhost:{self.port}/ok"))
        self.assertEqual(caught.exception.kind, "unsafe")

    async def test_redirect_loops_end_with_an_error(self):
        with self.assertRaises(FetchError) as caught:
            await self.fetch("/loop")
        self.assertIn("redirect", str(caught.exception))

    async def test_an_unsafe_error_never_escalates_to_another_engine(self):
        from webmonitor.engine import _worth_switching
        error = FetchError("unsafe", "redirect to a non-public address (127.0.0.1)")
        for engine in ("http", "impersonate", "browser"):
            self.assertFalse(_worth_switching(error, engine), engine)


@unittest.skipUnless(HAS_CURL, "curl_cffi is not installed")
class ImpersonateFetchGuardTests(FetchGuardCase):
    fetcher_class = ImpersonateFetcher

    async def test_private_targets_stay_reachable_and_redirects_are_followed(self):
        result = await self.fetch("/to-relative")
        self.assertIn("hello", result.text)
        self.assertIn("INTERNAL-SECRET", (await self.fetch("/to-internal")).text)

    async def test_redirect_from_a_public_host_to_an_internal_address_is_refused(self):
        self.pretend_public()
        with self.assertRaises(FetchError) as caught:
            await self.fetch("/to-internal")
        self.assertEqual(caught.exception.kind, "unsafe")
        self.assertEqual(self.secret_hits["secret"], 0)

    async def test_the_address_curl_really_connected_to_is_checked(self):
        self.pretend_public(peer_check=True)
        with self.assertRaises(FetchError) as caught:
            await self.fetch("/ok")
        self.assertEqual(caught.exception.kind, "unsafe")
        self.assertIn("non-public address", str(caught.exception))

    async def test_redirect_loops_end_with_an_error(self):
        with self.assertRaises(FetchError) as caught:
            await self.fetch("/loop")
        self.assertIn("redirect", str(caught.exception))


# =========================================================================== regular expressions

class SafePatternTests(unittest.TestCase):
    def test_behaves_like_a_case_insensitive_regex(self):
        pattern = SafePattern(r"cookie\w*")
        self.assertTrue(pattern.search("Accept all Cookies"))
        self.assertIsNone(pattern.search("nothing here"))
        self.assertEqual(pattern.sub(" ", "a Cookie-Banner b"), "a  -Banner b")
        self.assertEqual(pattern.pattern, r"cookie\w*")

    def test_persian_text_works(self):
        self.assertEqual(SafePattern(r"آخرین به‌روزرسانی.*").sub(" ", "متن آخرین به‌روزرسانی: ۱۴۰۵"), "متن  ")

    @unittest.skipUnless(config_module._regex is not None, "the regex package is not installed")
    def test_a_catastrophic_pattern_cannot_freeze_the_monitor(self):
        text = "a" * 40 + "!"
        with mock.patch.object(config_module, "PATTERN_TIMEOUT", 0.2):
            pattern = SafePattern(r"(a|aa)+$")
            started = time.monotonic()
            self.assertIsNone(pattern.search(text))
            self.assertEqual(pattern.sub(" ", text), text)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_equal_patterns_compare_equal_and_copy_cleanly(self):
        a, b = SafePattern("x+"), SafePattern("x+")
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertIs(copy.deepcopy(a), a)
        self.assertNotEqual(a, SafePattern("y+"))

    def test_invalid_patterns_are_reported_with_their_location(self):
        with self.assertRaises(ConfigError) as caught:
            config_module._compile_patterns(["("], "watch.ignore_patterns")
        self.assertIn("invalid regular expression", str(caught.exception))
        self.assertIn("watch.ignore_patterns", str(caught.exception))

    def test_ignore_patterns_reach_the_text_extraction(self):
        watch = parse_watch({"id": "a", "url": "https://e.example", "ignore_patterns": [r"visitors: \d+"]})
        self.assertIsInstance(watch.ignore_patterns[0], SafePattern)
        doc = parse_html("<html><body><main><p>Termine frei</p><p>Visitors: 4711</p></main></body></html>", "https://e.example/")
        snapshot = page_snapshot(doc, "https://e.example/", selector="main", ignore_patterns=watch.ignore_patterns)
        self.assertEqual([line.strip() for line in snapshot.lines if line.strip()], ["Termine frei"])


class ConfigSettingsTests(TempDirCase):
    def test_new_settings_are_parsed(self):
        cfg = make_config(self.tmp, miniapp_url="https://app.example/", heartbeat_url="https://hc.example/ping/x")
        self.assertEqual(cfg.miniapp_url, "https://app.example")
        self.assertEqual(cfg.heartbeat_url, "https://hc.example/ping/x")
        self.assertEqual(cfg.warnings, [])

    def test_defaults_are_empty(self):
        cfg = make_config(self.tmp)
        self.assertEqual((cfg.miniapp_url, cfg.heartbeat_url), ("", ""))

    def test_the_environment_wins_and_urls_are_validated(self):
        with mock.patch.dict(os.environ, {"WEBMONITOR_HEARTBEAT_URL": "https://hc.example/env"}):
            self.assertEqual(make_config(self.tmp, heartbeat_url="https://hc.example/file").heartbeat_url,
                             "https://hc.example/env")
        with self.assertRaises(ConfigError):
            make_config(self.tmp, heartbeat_url="ftp://nope")
        self.assertEqual(make_config(self.tmp, miniapp_url="off").miniapp_url, "off")


# =========================================================================== parsing in threads

class ThreadedParsingTests(unittest.TestCase):
    def test_parallel_parsing_matches_the_serial_result(self):
        def page(i: int) -> str:
            rows = "".join(f"<p>Termin {i}-{n} frei</p>" for n in range(300))
            return f"<html><body><nav>menu</nav><div id='main'>{rows}</div></body></html>"

        def work(i: int):
            doc = parse_html(page(i), "https://x.example/")
            snapshot = page_snapshot(doc, "https://x.example/", selector="#main", exclude_selectors=["nav"])
            return snapshot.digest, len(snapshot.lines)

        serial = [work(i) for i in range(6)]
        with ThreadPoolExecutor(8) as pool:
            parallel = list(pool.map(work, list(range(6)) * 12))
        self.assertEqual(parallel, serial * 12)


# =========================================================================== supervisor

class SupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_crashing_task_is_restarted_and_reported(self):
        calls, crashes, stop = [], [], asyncio.Event()

        async def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("boom")
            stop.set()

        await asyncio.wait_for(supervise("t", flaky, on_crash=lambda *a: crashes.append(a), stop=stop,
                                         min_delay=0.01, max_delay=0.05), timeout=5)
        self.assertEqual(len(calls), 3)
        self.assertEqual([c[0] for c in crashes], ["t", "t"])
        self.assertIn("boom", crashes[0][1])

    async def test_the_delay_grows_while_a_task_keeps_failing(self):
        delays, stop, calls = [], asyncio.Event(), []

        async def always():
            calls.append(1)
            if len(calls) == 5:
                stop.set()
            raise RuntimeError("again")

        await supervise("t", always, on_crash=lambda name, reason, delay: delays.append(delay), stop=stop,
                        min_delay=0.01, max_delay=0.05, stable_after=60)
        self.assertEqual(delays[0], 0.01)
        self.assertEqual(delays[1], 0.02)
        self.assertEqual(delays[-1], 0.05)

    async def test_cancellation_is_not_swallowed(self):
        calls = []

        async def idle():
            calls.append(1)
            await asyncio.sleep(60)

        task = asyncio.create_task(supervise("t", idle, min_delay=0.01))
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(calls), 1)

    async def test_a_task_that_returns_is_started_again_until_the_monitor_stops(self):
        calls, stop = [], asyncio.Event()

        async def short():
            calls.append(1)
            if len(calls) == 2:
                stop.set()

        await asyncio.wait_for(supervise("t", short, stop=stop, min_delay=0.01), timeout=5)
        self.assertEqual(len(calls), 2)


# =========================================================================== database health

class StoreHealthTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.store = Store(self.tmp / "monitor.db")
        self.addCleanup(self.store.close)
        self.store.touch_admin("555", "Admin")
        self.store.set_setting("k", "v")

    def test_quick_check_is_ok(self):
        self.assertEqual(self.store.quick_check(), "ok")

    def test_backup_is_a_usable_copy_and_old_copies_are_dropped(self):
        folder = self.tmp / "backups"
        made = [self.store.backup(folder, keep=3) for _ in range(5)]
        self.assertTrue(all(path is not None for path in made))
        self.assertEqual(len(list(folder.glob("monitor-*.db"))), 3)
        copy_ = Store(made[-1])
        try:
            self.assertEqual(copy_.admin_ids(), ["555"])
            self.assertEqual(copy_.get_setting("k", ""), "v")
        finally:
            copy_.close()

    def test_backup_works_from_a_worker_thread(self):
        with ThreadPoolExecutor(1) as pool:
            target = pool.submit(self.store.backup, self.tmp / "b", 7).result()
        self.assertTrue(target.exists())

    def test_overdue_outbox_age(self):
        now = time.time()
        self.assertEqual(self.store.overdue_outbox_age(now), 0.0)
        self.store.add_event("sys", None, "info", "x", {})
        self.assertLess(self.store.overdue_outbox_age(time.time()), 5)
        self.store.conn.execute("UPDATE events SET created = ?", (now - 4000,))
        self.assertGreater(self.store.overdue_outbox_age(now), 3900)
        self.store.conn.execute("UPDATE events SET next_attempt = ?", (now + 3600,))  # waiting on purpose
        self.assertEqual(self.store.overdue_outbox_age(now), 0.0)


# =========================================================================== monitor: backup, heartbeat, loops

class MonitorOpsCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w1-"))

    async def asyncTearDown(self):
        for monitor in getattr(self, "monitors", []):
            await monitor.http.close()
            monitor.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def monitor(self, **top) -> Monitor:
        monitor = Monitor(make_config(self.tmp, **top), dry_run=True)
        self.monitors = getattr(self, "monitors", []) + [monitor]
        return monitor


class MonitorBackupAndHeartbeatTests(MonitorOpsCase):
    async def test_a_backup_is_written_once_a_day(self):
        monitor = self.monitor()
        folder = self.tmp / "data" / "backups"
        now = time.time()
        await monitor._maybe_backup(now)
        await monitor._maybe_backup(now + 60)
        self.assertEqual(len(list(folder.glob("monitor-*.db"))), 1)
        await monitor._maybe_backup(now + 86401)
        self.assertEqual(len(list(folder.glob("monitor-*.db"))), 2)

    async def test_a_failing_backup_is_reported_but_never_raises(self):
        monitor = self.monitor()
        with mock.patch.object(Store, "backup", side_effect=OSError("disk full")):
            await monitor._maybe_backup(time.time())
        self.assertEqual(monitor.store.pending_count(), 1)

    async def test_the_heartbeat_pings_while_alerts_can_get_out(self):
        monitor = self.monitor(heartbeat_url="https://hc.example/ping/abc")
        ping = mock.AsyncMock(return_value=True)
        with mock.patch.object(Monitor, "_ping", new=ping):
            self.assertTrue(await monitor._heartbeat_once())
            ping.assert_awaited_once_with("https://hc.example/ping/abc")

    async def test_the_heartbeat_is_withheld_while_notifications_are_stuck(self):
        monitor = self.monitor(heartbeat_url="https://hc.example/ping/abc")
        monitor.store.add_event("sys", None, "info", "stuck", {})
        monitor.store.conn.execute("UPDATE events SET created = ?", (time.time() - 4000,))
        ping = mock.AsyncMock(return_value=True)
        with mock.patch.object(Monitor, "_ping", new=ping):
            self.assertFalse(await monitor._heartbeat_once())
        ping.assert_not_awaited()

    async def test_a_failed_ping_is_not_an_error(self):
        with mock.patch("webmonitor.engine.aiohttp.ClientSession", side_effect=OSError("offline")):
            self.assertFalse(await Monitor._ping("https://hc.example/ping/abc"))

    async def test_crash_alerts_are_rate_limited(self):
        monitor = self.monitor()
        monitor._on_task_crash("bot", "ValueError: x", 5)
        monitor._on_task_crash("bot", "ValueError: x", 10)
        self.assertEqual(monitor.store.pending_count(), 1)
        monitor._on_task_crash("dispatch", "KeyError: y", 5)
        self.assertEqual(monitor.store.pending_count(), 2)

    async def test_start_reports_a_damaged_database(self):
        monitor = self.monitor()
        with mock.patch.object(Store, "quick_check", return_value="database disk image is malformed"):
            with mock.patch.object(monitor.challenge, "start", new=mock.AsyncMock()):
                await monitor.start()
        self.assertEqual(monitor.store.pending_count(), 1)


class MonitorLoopTests(MonitorOpsCase):
    async def test_a_failing_daily_report_does_not_end_the_housekeeping_loop(self):
        monitor = self.monitor()
        monitor._next_report_time = lambda: time.time() - 1
        task = asyncio.create_task(monitor._housekeeping_loop())
        with mock.patch.object(monitor, "status_report", side_effect=RuntimeError("report broke")):
            await asyncio.sleep(0.4)
        self.assertFalse(task.done(), "the loop must survive a failing report")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_parsing_a_large_page_keeps_the_event_loop_responsive(self):
        rows = "".join(f"<tr><td>Termin {n}</td><td>frei</td><td>Visa national</td></tr>" for n in range(40000))
        body = f"<html><body><main><table>{rows}</table></main></body></html>"

        async def big(request):
            return web.Response(text=body, content_type="text/html")

        runner, port = await serve({"/big": big})
        self.addCleanup(runner.cleanup)
        monitor = self.monitor()
        watch = make_watch(f"http://127.0.0.1:{port}/big", selector="main", timeout_seconds=60)
        gaps, stop = [], asyncio.Event()

        async def ticker():
            last = time.perf_counter()
            while not stop.is_set():
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                gaps.append(now - last - 0.01)
                last = now

        tick = asyncio.create_task(ticker())
        await asyncio.sleep(0.05)
        outcome = await monitor.check_watch(watch)
        stop.set()
        await tick
        self.assertFalse(outcome.startswith("error"), outcome)
        self.assertLess(max(gaps), 0.5, f"the loop was blocked for {max(gaps):.2f}s while a page was parsed")


if __name__ == "__main__":
    unittest.main()
