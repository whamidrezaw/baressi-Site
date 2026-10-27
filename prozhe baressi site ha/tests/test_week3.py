"""Week 3 feature tests: rate-limit detection, challenge server, adaptive timeout.

Run:
    cd /opt/monitor && ./venv/bin/python -m unittest tests.test_week3 -v
"""
from __future__ import annotations

import asyncio
import unittest

from webmonitor.challenge import ChallengeManager, ChallengeSession
from webmonitor.engine import Monitor, _is_blocked, _is_rate_limit
from webmonitor.extract import detect_block, is_rate_limit_page
from webmonitor.fetchers import FetchError


class RateLimitDetectionTests(unittest.TestCase):
    def test_error_1015_is_rate_limit(self):
        page = ("<html><body><h1>Error 1015</h1>"
                "<p>You are being rate limited. The owner of this website "
                "has banned you temporarily from accessing this website.</p></body></html>")
        self.assertEqual(detect_block(page), "Cloudflare Rate Limit")
        self.assertTrue(is_rate_limit_page(page))

    def test_js_challenge_is_not_rate_limit(self):
        page = ("<html><head><title>Just a moment...</title></head>"
                "<body><div id='cf-browser-verification'></div></body></html>")
        self.assertEqual(detect_block(page), "Cloudflare")
        self.assertFalse(is_rate_limit_page(page))

    def test_akamai_block_is_not_rate_limit(self):
        page = '<html><head><title>Access Denied</title></head><body>errors.edgesuite.net</body></html>'
        self.assertEqual(detect_block(page), "Akamai")
        self.assertFalse(is_rate_limit_page(page))

    def test_empty_html(self):
        self.assertFalse(is_rate_limit_page(""))
        self.assertIsNone(detect_block(""))

    def test_fetch_error_kind_helpers(self):
        rate = FetchError("rate_limit", "HTTP 429", 429)
        blocked = FetchError("blocked", "HTTP 403", 403)
        timeout = FetchError("timeout", "slow", None)
        self.assertTrue(_is_rate_limit(rate))
        self.assertFalse(_is_rate_limit(blocked))
        self.assertFalse(_is_rate_limit(timeout))
        self.assertTrue(_is_blocked(rate))
        self.assertTrue(_is_blocked(blocked))
        self.assertFalse(_is_blocked(timeout))


class ChallengeManagerTests(unittest.IsolatedAsyncioTestCase):
    def _manager(self, ttl: float = 60) -> ChallengeManager:
        return ChallengeManager(host="127.0.0.1", port=0, ttl_seconds=ttl)

    async def test_create_returns_unique_tokens(self):
        mgr = self._manager()
        a = mgr.create(watch_id="w1", watch_label="A", url="https://x/")
        b = mgr.create(watch_id="w1", watch_label="A", url="https://x/")
        self.assertNotEqual(a.token, b.token)
        self.assertGreaterEqual(len(a.token), 16)
        self.assertEqual(mgr.count(), 2)

    async def test_get_returns_session(self):
        mgr = self._manager()
        s = mgr.create(watch_id="w", watch_label="L", url="https://y/")
        self.assertIs(mgr.get(s.token), s)
        self.assertIsNone(mgr.get("nonexistent"))

    async def test_ttl_expiry(self):
        mgr = self._manager(ttl=0.15)
        s = mgr.create(watch_id="w", watch_label="L", url="https://y/")
        self.assertIsNotNone(mgr.get(s.token))
        await asyncio.sleep(0.25)
        self.assertIsNone(mgr.get(s.token))
        self.assertEqual(mgr.count(), 0)

    async def test_complete_invokes_done_fn(self):
        mgr = self._manager()
        called = {"done": False}

        async def done(): called["done"] = True

        s = mgr.create(watch_id="w", watch_label="L", url="https://z/")
        s.done_fn = done
        self.assertTrue(await mgr.complete(s.token))
        self.assertTrue(called["done"])
        self.assertEqual(mgr.count(), 0)

    async def test_cancel_invokes_cancel_fn(self):
        mgr = self._manager()
        called = {"cancel": False}

        async def cancel(): called["cancel"] = True

        s = mgr.create(watch_id="w", watch_label="L", url="https://z/")
        s.cancel_fn = cancel
        self.assertTrue(await mgr.cancel(s.token))
        self.assertTrue(called["cancel"])
        self.assertEqual(mgr.count(), 0)
        self.assertFalse(await mgr.cancel(s.token))

    async def test_await_result_resolves_on_complete(self):
        mgr = self._manager()
        s = mgr.create(watch_id="w", watch_label="L", url="https://q/")
        fut = mgr.await_result(s.token)

        async def finish_soon():
            await asyncio.sleep(0.05)
            await mgr.complete(s.token)

        asyncio.create_task(finish_soon())
        kind, _ = await asyncio.wait_for(fut, timeout=2)
        self.assertEqual(kind, "done")

    async def test_await_result_resolves_on_cancel(self):
        mgr = self._manager()
        s = mgr.create(watch_id="w", watch_label="L", url="https://q/")
        fut = mgr.await_result(s.token)

        async def cancel_soon():
            await asyncio.sleep(0.05)
            await mgr.cancel(s.token)

        asyncio.create_task(cancel_soon())
        kind, _ = await asyncio.wait_for(fut, timeout=2)
        self.assertEqual(kind, "cancelled")

    async def test_complete_unknown_token_returns_false(self):
        mgr = self._manager()
        self.assertFalse(await mgr.complete("deadbeef"))
        self.assertFalse(await mgr.cancel("deadbeef"))


class MonitorHelpersPresenceTests(unittest.TestCase):
    def test_expected_methods_exist(self):
        expected = [
            "_effective_timeout",
            "_prepare_watch",
            "_record_timeout_hit",
            "_reset_timeout_hits",
            "_rate_limit_since",
            "_rate_limit_estimate_hours",
            "_record_rate_limit",
            "_clear_rate_limit",
            "exit_ip",
            "_maybe_solve_challenge",
            "_notify_challenge",
            "_notify_rate_limit",
        ]
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue(hasattr(Monitor, name), f"Monitor is missing {name}")

    def test_challenge_session_fields(self):
        s = ChallengeSession(token="t", watch_id="w", watch_label="L", url="https://x/")
        self.assertEqual(s.token, "t")
        self.assertFalse(s.expired)
        for attr in ("frame_fn", "click_fn", "type_fn", "key_fn", "done_fn", "cancel_fn"):
            self.assertIsNone(getattr(s, attr))


class AuditRegressionTests(unittest.IsolatedAsyncioTestCase):
    def test_version_matches_release(self):
        import webmonitor
        self.assertEqual(webmonitor.__version__, "2.2.0")

    def test_config_validates_challenge_port_and_ttl(self):
        from pathlib import Path
        from webmonitor.config import ConfigError, parse_config
        base = {
            "watches": [{"id": "w1", "url": "https://example.org"}],
        }
        with self.assertRaises(ConfigError):
            parse_config({**base, "challenge_port": 70000}, Path("cfg.json"))
        with self.assertRaises(ConfigError):
            parse_config({**base, "challenge_ttl_seconds": 3}, Path("cfg.json"))

    def test_report_change_event_resolves_fragment_links(self):
        from pathlib import Path
        from webmonitor import report
        from webmonitor.config import parse_config
        from webmonitor.util import load_timezone
        cfg = parse_config({"watches": [{"id": "w1", "url": "https://example.org/visa"}]}, Path("cfg.json"))
        watch = cfg.watches[0]
        hunks = [
            report.Hunk(
                kind="add",
                old=[],
                new=["نوبت جدید باز شد"],
                context="بخش روادید",
                anchor="visa-sec",
            )
        ]
        payload, _, _ = report.change_event(
            watch,
            "https://example.org/visa",
            hunks,
            [],
            [],
            1700000000.0,
            load_timezone(cfg.timezone),
        )
        full_text = payload.get("header", "") + "\n" + "\n".join(payload.get("blocks", []))
        self.assertIn('href="https://example.org/visa#visa-sec"', full_text)
        self.assertNotIn('href="#visa-sec"', full_text)

    async def test_challenge_browser_decrements_active_on_close(self):
        from webmonitor.fetchers import ChallengeBrowser

        class DummyContext:
            closed = False
            async def close(self):
                self.closed = True

        class DummyFetcher:
            _active = 1

        fetcher = DummyFetcher()
        ctx = DummyContext()
        cb = ChallengeBrowser(fetcher, ctx, None, None, "https://example.org")
        await cb.close()
        self.assertEqual(fetcher._active, 0)
        self.assertTrue(ctx.closed)
        # Closing a second time must be idempotent
        await cb.close()
        self.assertEqual(fetcher._active, 0)

    async def test_remove_watch_deletes_session_files(self):
        import tempfile
        from pathlib import Path
        from webmonitor.config import parse_config
        from webmonitor.engine import Monitor
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = parse_config(
                {"data_dir": str(root / "data"), "watches": [{"id": "w1", "url": "https://example.org"}]},
                root / "cfg.json",
            )
            for subdir in ("sessions", "sessions-impersonate"):
                d = cfg.data_dir / subdir
                d.mkdir(parents=True, exist_ok=True)
                (d / "w1.json").write_text("{}", encoding="utf-8")
            mon = Monitor(cfg)
            try:
                await mon.remove_watch("w1", forget_state=True)
                self.assertFalse((cfg.data_dir / "sessions" / "w1.json").exists())
                self.assertFalse((cfg.data_dir / "sessions-impersonate" / "w1.json").exists())
            finally:
                await mon.close()

    def test_import_cookies_parses_json_and_header_string(self):
        import json
        import tempfile
        from pathlib import Path
        from webmonitor.config import parse_config
        from webmonitor.fetchers import BrowserFetcher

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = parse_config(
                {"data_dir": str(root / "data"), "watches": [{"id": "w1", "url": "https://visa.example.org/book"}]},
                root / "cfg.json",
            )
            bf = BrowserFetcher(cfg)
            watch = cfg.watches[0]
            count = bf.import_cookies(watch, "Cookie: cf_clearance=abc123xyz; session_id=9876")
            self.assertEqual(count, 2)
            state = json.loads((cfg.data_dir / "sessions" / "w1.json").read_text(encoding="utf-8"))
            self.assertEqual(len(state["cookies"]), 2)
            imp = json.loads((cfg.data_dir / "sessions-impersonate" / "w1.json").read_text(encoding="utf-8"))
            self.assertEqual(imp["cf_clearance"], "abc123xyz")

    async def test_try_solve_interstitial_clicks_turnstile(self):
        from webmonitor.fetchers import BrowserFetcher

        clicked_coords = []

        class DummyMouse:
            async def move(self, x, y, steps=1):
                pass
            async def click(self, x, y):
                clicked_coords.append((x, y))

        class DummyElement:
            async def bounding_box(self):
                return {"x": 100.0, "y": 200.0, "width": 300.0, "height": 65.0}

        class DummyFrame:
            url = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile"
            async def frame_element(self):
                return DummyElement()

        class DummyPage:
            mouse = DummyMouse()
            frames = [DummyFrame()]
            async def query_selector(self, sel):
                return None

        ok = await BrowserFetcher._try_solve_interstitial(None, DummyPage())
        self.assertTrue(ok)
        self.assertEqual(len(clicked_coords), 1)
        self.assertAlmostEqual(clicked_coords[0][0], 128.0)
        self.assertAlmostEqual(clicked_coords[0][1], 232.5)

    def test_before_after_report_style_and_spacing(self):
        from pathlib import Path
        from webmonitor import report
        from webmonitor.config import parse_config
        from webmonitor.util import load_timezone

        cfg = parse_config(
            {"watches": [{"id": "w1", "url": "https://example.org/appointments", "report_style": "before_after"}]},
            Path("cfg.json"),
        )
        watch = cfg.watches[0]
        hunks = [
            report.Hunk(kind="modify", old="ظرفیت تکمیل است", new="ظرفیت باز شد (۵ نفر)", context="جدول نوبت"),
            report.Hunk(kind="add", new="ثبت‌نام فوری فعال شد", context="جدول نوبت"),
        ]
        payload, _, _ = report.change_event(
            watch, "https://example.org/appointments", hunks, [], [], 1700000000.0, load_timezone(cfg.timezone)
        )
        block = payload["blocks"][0]
        self.assertIn("🔴 <i>قبل:</i>", block)
        self.assertIn("🟢 <i>بعد:</i>", block)
        self.assertIn("🔍 <i>کلمه‌به‌کلمه:</i>", block)
        self.assertIn("\n\n🟢 ثبت‌نام فوری فعال شد", block)
        self.assertIn("https://example.org/appointments", payload["header"])

    async def test_bot_global_settings_and_challenge_callback(self):
        import tempfile
        from pathlib import Path
        from webmonitor.config import parse_config
        from webmonitor.engine import Monitor
        from webmonitor.bot import AdminBot

        class DummyTG:
            def __init__(self):
                self.texts = []
                self.photos = []
            async def send_text(self, chat_id, text, reply_markup=None):
                self.texts.append(text)
                return {"message_id": len(self.texts)}
            async def send_photo(self, chat_id, filename, data, caption="", reply_markup=None):
                self.photos.append((filename, caption))
                return {"message_id": 99}
            async def call(self, method, data):
                if method == "sendMessage":
                    self.texts.append(data.get("text", ""))
                return {"message_id": 1}
            async def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = parse_config(
                {
                    "data_dir": str(root / "data"),
                    "telegram": {"bot_token": "123:ABC", "chat_ids": ["100"], "admin_user_ids": [100]},
                    "watches": [{"id": "w1", "url": "https://example.org"}],
                },
                root / "cfg.json",
            )
            mon = Monitor(cfg)
            tg = DummyTG()
            mon.notifier = tg
            bot = AdminBot(mon)
            try:
                await bot.toggle_setting("100", "ststyle")
                self.assertEqual(mon.store.get_setting("default_report_style", "inline"), "before_after")
                await bot.toggle_setting("100", "stshot")
                self.assertEqual(mon.store.get_setting("auto_screenshot", "off"), "on")
                await bot.toggle_setting("100", "stquiet")
                self.assertEqual(mon.store.get_setting("quiet_hours", "off"), "on")

                # Test interactive challenge solve via Telegram button
                sess = mon.challenge.create(watch_id="w1", watch_label="S1", url="https://example.org")
                fut = mon.challenge.await_result(sess.token)
                async def fake_click():
                    return True
                async def fake_shot():
                    return b"PNGDATA"
                sess.click_turnstile_fn = fake_click
                sess.frame_fn = fake_shot

                class DummyCtx:
                    acked = []
                    async def ack(self, text="", alert=False):
                        self.acked.append(text)

                ctx = DummyCtx()
                await bot.handle_challenge_action(ctx, "100", f"{sess.token}:cf")
                self.assertEqual(len(tg.photos), 1)
                await bot.handle_challenge_action(ctx, "100", f"{sess.token}:ok")
                self.assertTrue(fut.done())
                self.assertEqual(fut.result()[0], "done")
            finally:
                await mon.close()

    async def test_miniapp_auth_and_api(self):
        import hashlib
        import hmac
        import json
        import tempfile
        import time
        from pathlib import Path
        from urllib.parse import urlencode
        import aiohttp
        from webmonitor.config import parse_config
        from webmonitor.engine import Monitor
        from webmonitor.miniapp import make_admin_token, validate_init_data, verify_admin_token

        bot_token = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        tok = make_admin_token(bot_token, "100", ttl=300, now=1000.0)
        self.assertEqual(verify_admin_token(tok, bot_token, now=1100.0), "100")
        self.assertIsNone(verify_admin_token(tok, bot_token, now=2000.0))
        self.assertIsNone(verify_admin_token(tok + "x", bot_token, now=1100.0))

        # Build valid Telegram WebApp initData
        now_ts = int(time.time())
        pairs = {"auth_date": str(now_ts), "user": json.dumps({"id": 100, "first_name": "Hamid"})}
        check_str = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
        sig = hmac.new(secret_key, check_str.encode(), hashlib.sha256).hexdigest()
        init_data = urlencode({**pairs, "hash": sig})
        user = validate_init_data(init_data, bot_token, now=now_ts)
        self.assertIsNotNone(user)
        self.assertEqual(user["id"], 100)
        self.assertIsNone(validate_init_data(init_data + "tamper", bot_token, now=now_ts))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = parse_config(
                {
                    "data_dir": str(root / "data"),
                    "challenge_port": 0,
                    "telegram": {"token": bot_token, "chat_ids": ["100"], "admin_ids": ["100"]},
                    "watches": [{"id": "w1", "name": "Embassy", "url": "https://example.org"}],
                },
                root / "cfg.json",
            )
            mon = Monitor(cfg, dry_run=True)
            await mon.start()
            try:
                # Find the bound port of ChallengeManager
                sockets = mon.challenge._site._server.sockets
                port = sockets[0].getsockname()[1]
                base = f"http://127.0.0.1:{port}"
                async with aiohttp.ClientSession() as client:
                    # 1. /app HTML loads
                    async with client.get(f"{base}/app") as r:
                        self.assertEqual(r.status, 200)
                        html = await r.text()
                        self.assertIn("داشبورد هوشمند مانیتور", html)
                    # 2. Unauthenticated /api/app/state is rejected (403)
                    async with client.get(f"{base}/api/app/state") as r:
                        self.assertEqual(r.status, 403)
                    # 3. Authenticated with X-Telegram-Init-Data succeeds
                    headers = {"X-Telegram-Init-Data": init_data}
                    async with client.get(f"{base}/api/app/state", headers=headers) as r:
                        self.assertEqual(r.status, 200)
                        st = await r.json()
                        self.assertTrue(st["ok"])
                        self.assertEqual(len(st["sites"]), 1)
                        site_key = st["sites"][0]["key"]
                    # 4. Per-site detail and settings update
                    async with client.post(
                        f"{base}/api/app/site/{site_key}/update",
                        headers=headers,
                        json={"report_style": "before_after", "ignore_reorder": False},
                    ) as r:
                        self.assertEqual(r.status, 200)
                    async with client.get(f"{base}/api/app/site/{site_key}", headers=headers) as r:
                        detail = await r.json()
                        self.assertEqual(detail["site"]["report_style"], "before_after")
                        self.assertFalse(detail["site"]["ignore_reorder"])
                    # 5. Boundary validation: non-integer key returns 400 instead of 500
                    for suffix in ("", "/check", "/screenshot", "/update", "/reset", "/cookies", "/delete"):
                        method = client.get if suffix == "" else client.post
                        async with method(f"{base}/api/app/site/not-an-int{suffix}", headers=headers) as r:
                            self.assertEqual(r.status, 400)
                    # 6. SSRF protection blocks loopback/private URLs on add and update
                    async with client.post(
                        f"{base}/api/app/add",
                        headers=headers,
                        json={"url": "http://127.0.0.1:8899/health", "name": "Loopback"},
                    ) as r:
                        self.assertEqual(r.status, 400)
                    async with client.post(
                        f"{base}/api/app/site/{site_key}/update",
                        headers=headers,
                        json={"url": "http://169.254.169.254/latest/meta-data/"},
                    ) as r:
                        self.assertEqual(r.status, 400)
                    # 7. Reset, cookies, and check-all trigger without AttributeError
                    async with client.post(
                        f"{base}/api/app/site/{site_key}/cookies",
                        headers=headers,
                        json={"cookies": "cf_clearance=xyz987; session=abc"},
                    ) as r:
                        self.assertEqual(r.status, 200)
                        c_res = await r.json()
                        self.assertEqual(c_res["count"], 2)
                    async with client.post(f"{base}/api/app/site/{site_key}/reset", headers=headers) as r:
                        self.assertEqual(r.status, 200)
                    async with client.post(f"{base}/api/app/check-all", headers=headers) as r:
                        self.assertEqual(r.status, 200)
                    # 8. Challenge turnstile action invokes click_turnstile_fn
                    sess = mon.challenge.create(watch_id="w1", watch_label="Embassy", url="https://example.org")
                    clicked = {"turnstile": False}
                    async def fake_turnstile():
                        clicked["turnstile"] = True
                    sess.click_turnstile_fn = fake_turnstile
                    async with client.post(
                        f"{base}/api/app/challenge/{sess.token}/action",
                        headers=headers,
                        json={"action": "turnstile"},
                    ) as r:
                        self.assertEqual(r.status, 200)
                    # 9. Interval update syncs crawl.interval_seconds and clear-outbox flushes pending events
                    await client.post(
                        f"{base}/api/app/site/{site_key}/update",
                        headers=headers,
                        json={"crawl_enabled": True, "interval_seconds": 10800},
                    )
                    updated_rec = mon.registry.get(key=site_key)
                    self.assertEqual(updated_rec.watch.interval_seconds, 10800)
                    self.assertEqual(updated_rec.watch.crawl.interval_seconds, 10800)

                    mon.store.add_event("w1", "https://example.org", "change", "test", {}, status="pending")
                    self.assertEqual(mon.store.pending_count(), 1)
                    async with client.post(f"{base}/api/app/clear-outbox", headers=headers, json={}) as r:
                        self.assertEqual(r.status, 200)
                        clr = await r.json()
                        self.assertEqual(clr["cleared"], 1)
                    self.assertEqual(mon.store.pending_count(), 0)
            finally:
                await mon.close()

    def test_bot_interval_parsing_supports_hours_and_minutes(self):
        from webmonitor.bot import AdminBot
        self.assertEqual(AdminBot._parse_field("interval", "10800"), 10800)
        self.assertEqual(AdminBot._parse_field("interval", "۳ ساعت"), 10800)
        self.assertEqual(AdminBot._parse_field("interval", "3h"), 10800)
        self.assertEqual(AdminBot._parse_field("interval", "45 دقیقه"), 2700)
        self.assertEqual(AdminBot._parse_field("interval", "30m"), 1800)
        self.assertIsNone(AdminBot._parse_field("interval", "5"))


if __name__ == "__main__":
    unittest.main()

