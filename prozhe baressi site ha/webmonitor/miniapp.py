"""Telegram Mini App (TWA) dashboard and REST API for WebMonitor.

Provides:
* Cryptographic validation of Telegram WebApp ``initData`` (HMAC-SHA256 per Telegram spec)
  plus HMAC-signed admin URL tokens for seamless multi-device access.
* Rich RTL Persian Single-Page Application (``/app``) with:
  - Per-site dedicated profile pages (Overview, Visual Diff History, Live Screenshot,
    Interactive Settings switches, Cookie importer, Subpages inspector)
  - Global search across all historical diffs
  - Add-site wizard modal and global bot settings drawer
  - Live interactive CAPTCHA / Cloudflare challenge solver inside the Mini App
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from aiohttp import web

from .config import ConfigError
from .engine import DIGESTABLE, ENGINE_LABELS
from .fetchers import FetchError
from .registry import default_crawl
from .util import esc, fa_datetime, fa_digits, fa_number, format_short, human_duration, truncate

log = logging.getLogger("webmonitor")

TOKEN_TTL = 86400  # a signed link stays valid for one day


def miniapp_secret(store) -> str:
    """Key that signs admin links: random, kept in the database and independent of the bot token, so a
    leaked bot token alone cannot be used to forge a Mini App login."""
    secret = store.get_setting("miniapp_secret", "")
    if len(secret) < 32:
        secret = secrets.token_hex(32)
        store.set_setting("miniapp_secret", secret)
    return secret


def make_admin_token(secret: str, user_id: str, ttl: int = TOKEN_TTL, now: float | None = None) -> str:
    """Create an HMAC-SHA256 signed token ``<exp>.<uid>.<sig>`` that is bound to one Telegram user id."""
    uid = str(user_id or "").strip()
    if not secret or not uid:
        return ""
    exp = int((now if now is not None else time.time()) + ttl)
    payload = f"{exp}.{uid}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def verify_admin_token(token: str, secret: str, now: float | None = None) -> str | None:
    """Verify a token produced by ``make_admin_token``; returns ``user_id`` or ``None``."""
    if not token or not secret:
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    exp_s, uid, sig = parts
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    cur = now if now is not None else time.time()
    if cur > exp:
        return None
    payload = f"{exp}.{uid}"
    expected = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    return uid


def validate_init_data(init_data: str, bot_token: str, max_age: int = 86400,
                       now: float | None = None) -> dict | None:
    """Validate Telegram WebApp ``initData`` query string using HMAC-SHA256.

    Returns the parsed ``user`` dict if valid, or ``None`` if tampered/expired.
    """
    if not init_data or not bot_token:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    except Exception:
        return None
    received_hash = pairs.pop("hash", "")
    if not received_hash:
        return None
    auth_date_s = pairs.get("auth_date", "0")
    try:
        auth_date = int(auth_date_s)
    except ValueError:
        return None
    cur = now if now is not None else time.time()
    if max_age > 0 and abs(cur - auth_date) > max_age:
        return None
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated_hash, received_hash):
        return None
    user_raw = pairs.get("user")
    if not user_raw:
        return None
    try:
        user = json.loads(user_raw)
        if not isinstance(user, dict) or not user.get("id"):
            return None
        return user
    except Exception:
        return None


class MiniApp:
    """Serves the Telegram Mini App UI and JSON API on the ChallengeManager aiohttp server."""

    def __init__(self, monitor):
        self.m = monitor

    def register_routes(self, app: web.Application) -> None:
        app.router.add_get("/app", self.handle_app_page)
        app.router.add_get("/api/app/state", self.handle_state)
        app.router.add_get("/api/app/site/{key}", self.handle_site_detail)
        app.router.add_post("/api/app/site/{key}/check", self.handle_site_check)
        app.router.add_post("/api/app/site/{key}/screenshot", self.handle_site_screenshot)
        app.router.add_post("/api/app/site/{key}/update", self.handle_site_update)
        app.router.add_post("/api/app/site/{key}/reset", self.handle_site_reset)
        app.router.add_post("/api/app/site/{key}/cookies", self.handle_site_cookies)
        app.router.add_post("/api/app/site/{key}/delete", self.handle_site_delete)
        app.router.add_post("/api/app/add", self.handle_add_site)
        app.router.add_post("/api/app/check-all", self.handle_check_all)
        app.router.add_post("/api/app/clear-outbox", self.handle_clear_outbox)
        app.router.add_post("/api/app/settings", self.handle_settings)
        app.router.add_get("/api/app/search", self.handle_search)
        app.router.add_get("/api/app/challenge/{token}/frame", self.handle_challenge_frame)
        app.router.add_post("/api/app/challenge/{token}/action", self.handle_challenge_action)

    # ------------------------------------------------------------------ auth & validation helpers

    @staticmethod
    def _parse_key(request: web.Request) -> int | None:
        try:
            return int(request.match_info["key"])
        except (KeyError, TypeError, ValueError):
            return None

    def _is_authorized_user(self, uid: str) -> bool:
        """Only people the bot knows as admins (configured, or seen using the panel) may use the Mini App."""
        uid = str(uid or "").strip()
        if not uid:
            return False
        cfg_admins = {str(x) for x in (self.m.config.telegram.admin_ids or [])}
        cfg_chats = {str(x) for x in (self.m.config.telegram.chat_ids or []) if not str(x).startswith("-")}
        db_admins = set(self.m.store.admin_ids())
        return uid in (cfg_admins | cfg_chats | db_admins)

    def _authenticate(self, request: web.Request) -> tuple[bool, str]:
        bot_token = self.m.config.telegram.token
        if not bot_token:
            # Local dry-run / console mode without Telegram token
            return True, "local"
        # Credentials travel in headers only: a query string would end up in access logs.
        init_data = request.headers.get("X-Telegram-Init-Data", "")
        if init_data:
            user = validate_init_data(init_data, bot_token)
            if user is not None:
                uid = str(user.get("id", "")).strip()
                if self._is_authorized_user(uid):
                    if uid.isdigit():
                        name = " ".join(filter(None, [user.get("first_name"), user.get("last_name")])) or uid
                        self.m.store.touch_admin(uid, name)
                    return True, uid
                return False, "این اکانت تلگرام دسترسی ادمین ندارد."
        token = request.headers.get("X-Admin-Token", "")
        if token:
            uid = verify_admin_token(token, miniapp_secret(self.m.store))
            if uid and self._is_authorized_user(uid):
                return True, uid
        return False, "نشست منقضی شده یا دسترسی غیرمجاز است. لطفاً دوباره از داخل ربات دکمهٔ «🚀 مینی‌اپ» را بزنید."

    def _require_auth(self, request: web.Request) -> web.Response | None:
        ok, info = self._authenticate(request)
        if not ok:
            return web.json_response({"ok": False, "error": info}, status=403)
        return None

    # ------------------------------------------------------------------ serialization helpers

    def _serialize_site(self, record, now: float, counts_24h: dict,
                        page_counts: dict[str, int] | None = None,
                        watch_states: dict[str, dict] | None = None) -> dict:
        w = record.watch
        store = self.m.store
        if w:
            state = watch_states.get(record.id, {}) if watch_states is not None else store.watch_state(record.id)
            subpages_count = page_counts.get(record.id, 0) if page_counts is not None else store.page_counts().get(record.id, 0)
            last_ev = store.last_event(record.id, DIGESTABLE)
        else:
            state = {}
            subpages_count = 0
            last_ev = None
        changes_24h = sum(counts_24h.get(record.id, Counter())[k] for k in DIGESTABLE)
        has_cookies = (self.m.config.data_dir / "sessions" / f"{record.id}.json").exists()
        if w is None:
            status = "broken"
            status_label = "❌ خطای تنظیمات"
        elif not w.enabled:
            status = "paused"
            status_label = "⏸ متوقف"
        elif state.get("consecutive_errors", 0) > 0:
            status = "error"
            status_label = f"⚠️ خطا ({fa_digits(state['consecutive_errors'])} بار)"
        elif state.get("last_ok"):
            status = "ok"
            status_label = "🟢 فعال و سالم"
        else:
            status = "pending"
            status_label = "⏳ در انتظار بررسی"

        active_engine = (w.engine if w.engine != "auto" else (state.get("engine") or "http")) if w else "http"
        return {
            "key": record.key,
            "id": record.id,
            "label": record.label,
            "url": w.url if w else record.spec.get("url", ""),
            "page_url": w.page_url if w else record.spec.get("url", ""),
            "origin": record.origin,
            "status": status,
            "status_label": status_label,
            "enabled": bool(w.enabled) if w else False,
            "type": w.type if w else record.spec.get("type", "page"),
            "type_label": self.m.kind_label(w) if w else "نامعتبر",
            "engine": w.engine if w else "auto",
            "active_engine": active_engine,
            "engine_label": ENGINE_LABELS.get(active_engine, active_engine),
            "interval_seconds": int(w.interval_seconds) if w else 120,
            "interval_human": human_duration(w.interval_seconds) if w else "—",
            "consecutive_errors": state.get("consecutive_errors", 0),
            "last_error": state.get("last_error") or record.error or "",
            "last_ok_ago": human_duration(now - state["last_ok"]) + " پیش" if state.get("last_ok") else "هنوز نه",
            "last_check_ago": human_duration(now - state["last_check"]) + " پیش" if state.get("last_check") else "هنوز نه",
            "last_change_ago": (human_duration(now - last_ev["created"]) + " پیش" if last_ev else "بدون تغییر"),
            "last_change_summary": (last_ev["summary"] or "") if last_ev else "",
            "changes_24h": changes_24h,
            "subpages_count": subpages_count,
            "crawl_enabled": bool(w and w.crawl),
            "crawl_max_pages": w.crawl.max_pages if (w and w.crawl) else 0,
            "has_cookies": has_cookies,
            "keywords": list(w.keywords) if w else [],
            "only_keywords": bool(w.only_keywords) if w else False,
            "track_links": bool(w.track_links) if w else True,
            "silent": bool(w.silent) if w else False,
            "alarm": bool(w.alarm) if w else False,
            "selector": w.selector if w else "",
            "report_style": getattr(w, "report_style", "inline") if w else "inline",
            "ignore_reorder": bool(getattr(w, "ignore_reorder", True)) if w else True,
            "notify_mode": getattr(w, "notify_mode", "text") if w else "text",
            "route": (state.get("route") or "direct") if w else "direct",
        }

    def _serialize_event(self, row) -> dict:
        try:
            payload = json.loads(row["payload"])
        except Exception:
            payload = {}
        blocks = payload.get("full_blocks") or payload.get("blocks") or []
        return {
            "id": row["id"],
            "watch_id": row["watch_id"],
            "url": row["url"] or "",
            "kind": row["kind"],
            "created": row["created"],
            "created_human": fa_datetime(row["created"], self.m.tz),
            "created_short": format_short(row["created"], self.m.tz),
            "summary": row["summary"] or "",
            "status": row["status"],
            "header_html": payload.get("header", ""),
            "blocks_html": blocks[:40],
        }

    # ------------------------------------------------------------------ HTTP handlers

    async def handle_app_page(self, request: web.Request) -> web.Response:
        return web.Response(
            text=_MINIAPP_HTML,
            content_type="text/html",
            charset="utf-8",
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    async def handle_state(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        now = time.time()
        store = self.m.store
        records = self.m.registry.records()
        counts_24h = store.event_counts_since(now - 86400)
        page_counts = store.page_counts()
        watch_states = store.all_watch_states()
        sites = [self._serialize_site(r, now, counts_24h, page_counts, watch_states) for r in records]

        challenges = []
        if getattr(self.m, "challenge", None):
            for tok, sess in list(self.m.challenge._sessions.items()):
                if not sess.expired:
                    challenges.append({
                        "token": tok,
                        "watch_id": sess.watch_id,
                        "watch_label": sess.watch_label,
                        "url": sess.url,
                        "remaining": max(0, int(sess.expires_at - now)),
                    })

        return web.json_response({
            "ok": True,
            "uptime_human": human_duration(now - self.m.started_at),
            "pending_outbox": store.pending_count(),
            "sites": sites,
            "challenges": challenges,
            "settings": {
                "report_style": store.get_setting("default_report_style", "inline"),
                "auto_screenshot": store.get_setting("auto_screenshot", "off") == "on",
                "quiet_hours": store.get_setting("quiet_hours", "off") == "on",
                "daily_digest": store.get_setting("daily_report", "on") != "off",
                "startup_notify": store.get_setting("startup_notify", "on") != "off",
                "fallback_proxy": store.get_setting("fallback_proxy", "auto"),
            },
        })

    async def handle_site_detail(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None:
            return web.json_response({"ok": False, "error": "سایت پیدا نشد"}, status=404)
        now = time.time()
        counts_24h = self.m.store.event_counts_since(now - 86400)
        page_counts = self.m.store.page_counts()
        site = self._serialize_site(record, now, counts_24h, page_counts)
        events = [self._serialize_event(r) for r in self.m.store.recent_events(record.id, 25)]
        subpages = []
        for row in self.m.store.page_summaries(record.id, 80):
            url = row["url"]
            subpages.append({
                "url": url,
                "title": row["title"] or url,
                "engine": row["engine"] or "",
                "last_seen": human_duration(now - row["last_seen"]) + " پیش" if row["last_seen"] else "—",
                "last_changed": human_duration(now - row["last_changed"]) + " پیش" if row["last_changed"] else "—",
            })
        active_challenge = None
        if getattr(self.m, "challenge", None):
            for tok, sess in list(self.m.challenge._sessions.items()):
                if not sess.expired and sess.watch_id == record.id:
                    active_challenge = {
                        "token": tok,
                        "url": sess.url,
                        "remaining": max(0, int(sess.expires_at - now)),
                    }
                    break
        return web.json_response({
            "ok": True,
            "site": site,
            "events": events,
            "subpages": subpages,
            "challenge": active_challenge,
        })

    async def handle_site_check(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None or record.watch is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        started = time.monotonic()
        outcome = await self.m.check_watch(record.watch)
        elapsed = round(time.monotonic() - started, 1)
        return web.json_response({"ok": True, "outcome": outcome, "elapsed": elapsed})

    async def handle_site_screenshot(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None or record.watch is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        try:
            image_bytes = await self.m.screenshot(record.watch)
        except Exception as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=500)
        b64 = base64.b64encode(image_bytes).decode("ascii")
        return web.json_response({
            "ok": True,
            "image_data_url": f"data:image/jpeg;base64,{b64}",
            "taken_at": fa_datetime(time.time(), self.m.tz),
        })

    async def handle_site_update(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return web.json_response({"ok": False, "error": "دادهٔ نامعتبر"}, status=400)
        if "url" in data:
            from .netguard import is_public_host
            host = urlsplit(str(data["url"]).strip()).hostname or ""
            if not host or not await is_public_host(host):
                return web.json_response(
                    {"ok": False, "error": "آدرس‌های داخلی یا خصوصی سرور قابل پایش نیستند"},
                    status=400,
                )
        spec = dict(record.spec)
        allowed = {
            "name", "url", "type", "engine", "selector", "interval_seconds",
            "enabled", "silent", "alarm", "only_keywords", "track_links",
            "ignore_reorder", "report_style", "notify_mode", "keywords",
        }
        for k, v in data.items():
            if k in allowed:
                spec[k] = v
        if "keywords" in data and not spec.get("keywords"):
            spec.pop("only_keywords", None)
        if "crawl_enabled" in data:
            if data["crawl_enabled"] and not spec.get("crawl"):
                spec["crawl"] = default_crawl(spec.get("url", ""))
            elif not data["crawl_enabled"]:
                spec.pop("crawl", None)
        if "interval_seconds" in spec and isinstance(spec.get("crawl"), dict):
            try:
                spec["crawl"] = dict(spec["crawl"], interval_seconds=max(900, int(spec["interval_seconds"])))
            except (TypeError, ValueError):
                pass
        try:
            updated = self.m.registry.update(key, spec)
        except ConfigError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=400)
        await self.m.apply_watch(updated.watch)
        return web.json_response({"ok": True})

    async def handle_site_reset(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None or record.watch is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        self.m.store.reset_watch(record.id)
        for subdir in ("sessions", "sessions-impersonate"):
            f = self.m.config.data_dir / subdir / f"{record.id}.json"
            if f.exists():
                try:
                    f.unlink()
                except OSError:
                    pass
        self.m.trigger(record.id)
        return web.json_response({"ok": True})

    async def handle_site_cookies(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        record = self.m.registry.get(key=key)
        if record is None or record.watch is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return web.json_response({"ok": False, "error": "دادهٔ نامعتبر"}, status=400)
        raw = str(data.get("cookies", "")).strip()
        session_file = self.m.config.data_dir / "sessions" / f"{record.id}.json"
        if raw in ("", "-"):
            if session_file.exists():
                session_file.unlink()
            return web.json_response({"ok": True, "cleared": True})
        host = (urlsplit(record.watch.url).hostname or "").lstrip(".")
        cookies = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "cookies" in parsed:
                parsed = parsed["cookies"]
            if isinstance(parsed, list):
                for c in parsed:
                    if isinstance(c, dict) and c.get("name") and "value" in c:
                        cookies.append({
                            "name": str(c["name"]),
                            "value": str(c["value"]),
                            "domain": str(c.get("domain") or host),
                            "path": str(c.get("path") or "/"),
                        })
        except Exception:
            for pair in raw.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k.strip():
                        cookies.append({"name": k.strip(), "value": v.strip(), "domain": host, "path": "/"})
        if not cookies:
            return web.json_response({"ok": False, "error": "هیچ کوکی معتبری در متن ارسالی پیدا نشد"}, status=400)
        session_file.parent.mkdir(parents=True, exist_ok=True)
        session_file.write_text(json.dumps({"cookies": cookies, "origins": []}, ensure_ascii=False), encoding="utf-8")
        self.m.trigger(record.id)
        return web.json_response({"ok": True, "count": len(cookies)})

    async def handle_site_delete(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        key = self._parse_key(request)
        if key is None:
            return web.json_response({"ok": False, "error": "کلید نامعتبر"}, status=400)
        removed = self.m.registry.delete(key)
        if removed is None:
            return web.json_response({"ok": False, "error": "سایت یافت نشد"}, status=404)
        await self.m.remove_watch(removed.id)
        return web.json_response({"ok": True})

    async def handle_add_site(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError
            interval = int(data.get("interval_seconds", 120))
        except Exception:
            return web.json_response({"ok": False, "error": "دادهٔ نامعتبر"}, status=400)
        url = str(data.get("url", "")).strip()
        if not url:
            return web.json_response({"ok": False, "error": "لطفاً آدرس سایت را وارد کنید"}, status=400)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        from .netguard import is_public_host
        host = urlsplit(url).hostname or ""
        if not host or not await is_public_host(host):
            return web.json_response(
                {"ok": False, "error": "آدرس‌های داخلی یا خصوصی سرور قابل پایش نیستند"},
                status=400,
            )
        spec: dict = {
            "url": url,
            "name": str(data.get("name", "")).strip(),
            "type": str(data.get("type", "page")),
            "engine": str(data.get("engine", "auto")),
            "interval_seconds": interval,
            "report_style": str(data.get("report_style", "before_after")),
            "ignore_reorder": bool(data.get("ignore_reorder", False)),
            "track_links": True,
        }
        kws = data.get("keywords")
        if isinstance(kws, list):
            spec["keywords"] = [str(k).strip() for k in kws if str(k).strip()]
        elif isinstance(kws, str) and kws.strip():
            spec["keywords"] = [k.strip() for k in kws.replace("،", ",").split(",") if k.strip()]
        if data.get("crawl_enabled") and spec["type"] == "page":
            crawl_cfg = default_crawl(url)
            crawl_cfg["interval_seconds"] = max(900, interval)
            spec["crawl"] = crawl_cfg
        try:
            record = self.m.registry.add(spec, created_by="miniapp")
        except ConfigError as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=400)
        await self.m.apply_watch(record.watch)
        self.m.trigger(record.id)
        return web.json_response({"ok": True, "key": record.key})

    async def handle_check_all(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        self.m.trigger_all()
        return web.json_response({"ok": True, "count": len(self.m.watches)})

    async def handle_clear_outbox(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        watch_id = None
        try:
            data = await request.json()
            if isinstance(data, dict) and data.get("watch_id"):
                watch_id = str(data["watch_id"]).strip()
        except Exception:
            pass
        cleared = self.m.store.clear_pending_events(watch_id)
        return web.json_response({"ok": True, "cleared": cleared})

    async def handle_settings(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return web.json_response({"ok": False, "error": "دادهٔ نامعتبر"}, status=400)
        store = self.m.store
        if "report_style" in data and data["report_style"] in ("inline", "before_after"):
            store.set_setting("default_report_style", data["report_style"])
        if "auto_screenshot" in data:
            store.set_setting("auto_screenshot", "on" if data["auto_screenshot"] else "off")
        if "quiet_hours" in data:
            store.set_setting("quiet_hours", "on" if data["quiet_hours"] else "off")
        if "daily_digest" in data:
            store.set_setting("daily_report", "on" if data["daily_digest"] else "off")
        if "startup_notify" in data:
            store.set_setting("startup_notify", "on" if data["startup_notify"] else "off")
        return web.json_response({"ok": True})

    async def handle_search(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        q = (request.query.get("q") or "").strip()
        if not q:
            return web.json_response({"ok": True, "results": []})
        rows = self.m.store.conn.execute(
            "SELECT * FROM events WHERE summary LIKE ? OR payload LIKE ? ORDER BY id DESC LIMIT 30",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
        return web.json_response({"ok": True, "results": [self._serialize_event(r) for r in rows]})

    async def handle_challenge_frame(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        token = request.match_info["token"]
        sess = self.m.challenge.get(token) if getattr(self.m, "challenge", None) else None
        if sess is None or sess.frame_fn is None:
            return web.json_response({"ok": False, "error": "چالش منقضی یا بسته شده است"}, status=404)
        try:
            frame = await sess.frame_fn()
        except Exception as exc:
            return web.json_response({"ok": False, "error": str(exc)}, status=500)
        b64 = base64.b64encode(frame).decode("ascii")
        return web.json_response({
            "ok": True,
            "image_data_url": f"data:image/jpeg;base64,{b64}",
            "remaining": max(0, int(sess.expires_at - time.time())),
        })

    async def handle_challenge_action(self, request: web.Request) -> web.Response:
        err = self._require_auth(request)
        if err is not None:
            return err
        token = request.match_info["token"]
        sess = self.m.challenge.get(token) if getattr(self.m, "challenge", None) else None
        if sess is None:
            return web.json_response({"ok": False, "error": "چالش منقضی شده است"}, status=404)
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return web.json_response({"ok": False, "error": "دادهٔ نامعتبر"}, status=400)
        act = data.get("action")
        if act == "click" and sess.click_fn:
            try:
                x = float(data.get("x", 640))
                y = float(data.get("y", 400))
            except (TypeError, ValueError):
                return web.json_response({"ok": False, "error": "مختصات نامعتبر"}, status=400)
            async with sess.solving_lock:
                await sess.click_fn(x, y)
            return web.json_response({"ok": True})
        if act == "turnstile":
            turnstile_fn = getattr(sess, "click_turnstile_fn", None)
            async with sess.solving_lock:
                if turnstile_fn is not None:
                    await turnstile_fn()
                elif sess.click_fn is not None:
                    await sess.click_fn(255.0, 290.0)
            return web.json_response({"ok": True})
        if act == "type" and sess.type_fn:
            async with sess.solving_lock:
                await sess.type_fn(str(data.get("text", "")))
            return web.json_response({"ok": True})
        if act == "done":
            await self.m.challenge.complete(token)
            return web.json_response({"ok": True, "completed": True})
        if act == "cancel":
            await self.m.challenge.cancel(token)
            return web.json_response({"ok": True, "cancelled": True})
        return web.json_response({"ok": False, "error": "عملیات نامعتبر"}, status=400)


# --------------------------------------------------------------------------- Mini App SPA HTML
_MINIAPP_HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>داشبورد هوشمند مانیتور</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
:root {
  --bg: var(--tg-theme-secondary-bg-color, #0b0f17);
  --card: var(--tg-theme-bg-color, #151c28);
  --card-hover: #1c2536;
  --border: rgba(148, 163, 184, 0.16);
  --text: var(--tg-theme-text-color, #f1f5f9);
  --muted: var(--tg-theme-hint-color, #94a3b8);
  --primary: var(--tg-theme-button-color, #3b82f6);
  --primary-fg: var(--tg-theme-button-text-color, #ffffff);
  --success: #10b981;
  --success-bg: rgba(16, 185, 129, 0.14);
  --danger: #ef4444;
  --danger-bg: rgba(239, 68, 68, 0.14);
  --warn: #f59e0b;
  --warn-bg: rgba(245, 158, 11, 0.14);
  --radius: 14px;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
  margin: 0; padding: 0 0 80px;
  font-family: Vazirmatn, system-ui, -apple-system, 'Segoe UI', Tahoma, sans-serif;
  background: var(--bg); color: var(--text);
  line-height: 1.65; font-size: 14px;
}
.container { max-width: 780px; margin: 0 auto; padding: 12px; }
header.top {
  position: sticky; top: 0; z-index: 30;
  background: var(--card); border-bottom: 1px solid var(--border);
  padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; gap: 10px;
  backdrop-filter: blur(10px);
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand-icon {
  width: 38px; height: 38px; border-radius: 11px;
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  display: flex; align-items: center; justify-content: center; font-size: 20px; color: #fff;
}
.brand h1 { font-size: 16px; margin: 0; font-weight: 700; }
.brand small { font-size: 11px; color: var(--muted); display: block; }
.top-actions { display: flex; gap: 6px; }
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  padding: 8px 13px; border-radius: 10px; border: 1px solid var(--border);
  background: var(--card); color: var(--text); font-family: inherit; font-size: 13px;
  font-weight: 600; cursor: pointer; min-height: 40px; transition: .15s ease;
}
.btn:active { transform: scale(0.97); }
.btn.primary { background: var(--primary); color: var(--primary-fg); border-color: transparent; }
.btn.success { background: var(--success-bg); color: var(--success); border-color: rgba(16,185,129,.3); }
.btn.danger { background: var(--danger-bg); color: var(--danger); border-color: rgba(239,68,68,.3); }
.btn.sm { padding: 5px 10px; font-size: 12px; min-height: 34px; border-radius: 8px; }
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 12px 0; }
@media (max-width: 480px) { .kpi-grid { grid-template-columns: repeat(2, 1fr); } }
.kpi {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 10px 12px; display: flex; flex-direction: column; gap: 2px; cursor: pointer;
}
.kpi.active { border-color: var(--primary); box-shadow: 0 0 0 1px var(--primary); }
.kpi .num { font-size: 20px; font-weight: 800; }
.kpi .lbl { font-size: 11px; color: var(--muted); }
.search-bar {
  display: flex; gap: 8px; margin-bottom: 12px;
}
.search-bar input {
  flex: 1; padding: 10px 14px; border-radius: 12px; border: 1px solid var(--border);
  background: var(--card); color: var(--text); font-family: inherit; font-size: 14px;
}
.site-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 14px; margin-bottom: 10px; transition: .15s; cursor: pointer;
}
.site-card:hover { border-color: rgba(59, 130, 246, 0.45); }
.site-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 6px; }
.site-title { font-size: 15px; font-weight: 700; margin: 0; }
.site-url { font-size: 12px; color: var(--muted); direction: ltr; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; display: block; margin-bottom: 8px; }
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap;
}
.badge.ok { background: var(--success-bg); color: var(--success); }
.badge.error, .badge.broken { background: var(--danger-bg); color: var(--danger); }
.badge.paused, .badge.pending { background: var(--warn-bg); color: var(--warn); }
.badge.neutral { background: rgba(148,163,184,0.13); color: var(--muted); }
.meta-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.card-actions {
  display: flex; gap: 6px; margin-top: 12px; padding-top: 10px;
  border-top: 1px solid var(--border); flex-wrap: wrap;
}
.tabs {
  display: flex; gap: 6px; overflow-x: auto; padding-bottom: 6px; margin: 12px 0;
  border-bottom: 1px solid var(--border);
}
.tab {
  padding: 8px 14px; border-radius: 10px; font-size: 13px; font-weight: 600;
  background: transparent; color: var(--muted); border: none; cursor: pointer; white-space: nowrap;
  font-family: inherit;
}
.tab.active { background: var(--primary); color: var(--primary-fg); }
.panel-box {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 14px; margin-bottom: 12px;
}
.setting-row {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 11px 0; border-bottom: 1px solid var(--border);
}
.setting-row:last-child { border-bottom: none; }
.setting-info b { display: block; font-size: 14px; }
.setting-info small { color: var(--muted); font-size: 12px; }
.switch {
  position: relative; width: 48px; height: 28px; background: rgba(148,163,184,0.3);
  border-radius: 99px; cursor: pointer; transition: .2s; flex-shrink: 0; border: none;
}
.switch::after {
  content: ""; position: absolute; top: 3px; right: 3px; width: 22px; height: 22px;
  background: #fff; border-radius: 50%; transition: .2s;
}
.switch.on { background: var(--success); }
.switch.on::after { transform: translateX(-20px); }
select.input, input.input, textarea.input {
  width: 100%; padding: 9px 12px; border-radius: 10px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text); font-family: inherit; font-size: 13px;
}
.diff-block {
  background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
  padding: 10px 12px; margin-top: 8px; white-space: pre-wrap; unicode-bidi: plaintext;
  overflow-wrap: anywhere; font-size: 13px; line-height: 1.85;
}
.diff-block blockquote {
  margin: 6px 0; padding: 6px 10px; border-inline-start: 3px solid var(--primary);
  background: rgba(59,130,246,0.06); border-radius: 6px;
}
.diff-block s { color: #ff7b72; background: rgba(239,68,68,0.18); padding: 0 3px; border-radius: 4px; }
.diff-block b u { color: #3fb950; background: rgba(16,185,129,0.18); text-decoration: none; padding: 0 3px; border-radius: 4px; }
.diff-block a { color: var(--primary); }
.toast {
  position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%);
  background: #1e293b; color: #fff; padding: 10px 18px; border-radius: 999px;
  font-size: 13px; font-weight: 600; box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  z-index: 100; display: none; white-space: nowrap;
}
.modal-backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.65); z-index: 60;
  display: none; align-items: center; justify-content: center; padding: 14px;
}
.modal {
  background: var(--card); border: 1px solid var(--border); border-radius: 16px;
  max-width: 520px; width: 100%; max-height: 90vh; overflow-y: auto; padding: 18px;
}
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 99px; background: rgba(59,130,246,0.15);
  color: var(--primary); font-size: 12px; margin: 3px;
}
.chip button { background: none; border: none; color: inherit; cursor: pointer; padding: 0; font-size: 14px; }
img.live-shot { width: 100%; border-radius: 10px; border: 1px solid var(--border); margin-top: 8px; }
</style>
</head>
<body>
<header class="top">
  <div class="brand" onclick="showHome()" style="cursor:pointer">
    <div class="brand-icon">🛰</div>
    <div>
      <h1 id="nav-title">داشبورد هوشمند مانیتور</h1>
      <small id="nav-sub">در حال اتصال به سرور…</small>
    </div>
  </div>
  <div class="top-actions">
    <button class="btn sm" onclick="openSettingsModal()" title="تنظیمات کلی">⚙️</button>
    <button class="btn sm primary" onclick="openAddModal()">➕ سایت جدید</button>
  </div>
</header>

<div class="container">
  <!-- VIEW 1: HOME DASHBOARD -->
  <div id="view-home">
    <div id="challenge-banner"></div>
    <div class="kpi-grid">
      <div class="kpi active" id="kpi-all" onclick="setFilter('all')">
        <span class="num" id="stat-total">-</span>
        <span class="lbl">📋 همهٔ سایت‌ها</span>
      </div>
      <div class="kpi" id="kpi-ok" onclick="setFilter('ok')">
        <span class="num" style="color:var(--success)" id="stat-ok">-</span>
        <span class="lbl">🟢 سالم و فعال</span>
      </div>
      <div class="kpi" id="kpi-err" onclick="setFilter('error')">
        <span class="num" style="color:var(--danger)" id="stat-err">-</span>
        <span class="lbl">⚠️ دارای خطا</span>
      </div>
      <div class="kpi" onclick="checkAllSites()">
        <span class="num" style="color:var(--primary)" id="stat-24h">-</span>
        <span class="lbl">🔔 تغییر ۲۴ساعت (🔄 بررسی همه)</span>
      </div>
    </div>

    <div class="search-bar">
      <input id="site-q" type="search" placeholder="🔍 فیلتر نام سایت یا جستجوی کلمه در تاریخچهٔ تغییرات…" oninput="onSearchInput()">
      <button class="btn" onclick="runHistorySearch()">جستجوی تغییرات</button>
    </div>

    <div id="search-results"></div>
    <div id="sites-list"></div>
  </div>

  <!-- VIEW 2: DEDICATED PER-SITE PROFILE -->
  <div id="view-site" style="display:none">
    <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
      <button class="btn sm" onclick="showHome()">➡️ بازگشت به لیست سایت‌ها</button>
      <div id="site-top-badges"></div>
    </div>
    <div class="panel-box" id="site-header-card"></div>

    <div class="tabs">
      <button class="tab active" id="tab-btn-overview" onclick="switchSiteTab('overview')">📊 وضعیت و نمای زنده</button>
      <button class="tab" id="tab-btn-diffs" onclick="switchSiteTab('diffs')">🔍 تغییرات کلمه‌به‌کلمه</button>
      <button class="tab" id="tab-btn-settings" onclick="switchSiteTab('settings')">⚙️ تنظیمات اختصاصی</button>
      <button class="tab" id="tab-btn-subpages" onclick="switchSiteTab('subpages')">📂 زیرصفحه‌ها و کوکی</button>
    </div>

    <div id="site-tab-overview"></div>
    <div id="site-tab-diffs" style="display:none"></div>
    <div id="site-tab-settings" style="display:none"></div>
    <div id="site-tab-subpages" style="display:none"></div>
  </div>
</div>

<!-- MODAL: ADD NEW SITE -->
<div class="modal-backdrop" id="modal-add">
  <div class="modal">
    <h3 style="margin:0 0 12px">➕ افزودن سایت جدید به مانیتور</h3>
    <div style="display:flex;flex-direction:column;gap:10px">
      <div>
        <label style="font-size:12px;color:var(--muted)">🔗 آدرس صفحه (URL)</label>
        <input class="input" id="add-url" dir="ltr" placeholder="https://teheran.diplo.de/ir-fa">
      </div>
      <div>
        <label style="font-size:12px;color:var(--muted)">📝 نام دلخواه سایت</label>
        <input class="input" id="add-name" placeholder="مثلاً: سفارت آلمان — بخش ویزا">
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div>
          <label style="font-size:12px;color:var(--muted)">🧭 نوع پایش</label>
          <select class="input" id="add-type">
            <option value="page">📄 کل صفحه (کلمه‌به‌کلمه)</option>
            <option value="headlines">📰 تیترهای خبری جدید</option>
            <option value="feed">📡 خبرخوان RSS/Atom</option>
          </select>
        </div>
        <div>
          <label style="font-size:12px;color:var(--muted)">⏱ فاصلهٔ بررسی</label>
          <select class="input" id="add-interval">
            <option value="60">هر ۱ دقیقه</option>
            <option value="180">هر ۳ دقیقه</option>
            <option value="300">هر ۵ دقیقه</option>
            <option value="900" selected>هر ۱۵ دقیقه</option>
            <option value="1800">هر ۳۰ دقیقه</option>
            <option value="3600">هر ۱ ساعت</option>
            <option value="7200">هر ۲ ساعت</option>
            <option value="10800">هر ۳ ساعت</option>
            <option value="21600">هر ۶ ساعت</option>
            <option value="43200">هر ۱۲ ساعت</option>
            <option value="86400">هر ۲۴ ساعت</option>
          </select>
        </div>
      </div>
      <div>
        <label style="font-size:12px;color:var(--muted)">🔑 کلمات کلیدی مهم (با ویرگول جدا کنید)</label>
        <input class="input" id="add-keywords" placeholder="نوبت, ویزا, Termin, appointment">
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🕷 خزش خودکار زیرصفحه‌ها</b>
          <small>پایش خودکار لینک‌ها و زیرصفحه‌های داخلی این بخش</small>
        </div>
        <button class="switch on" id="add-crawl" onclick="this.classList.toggle('on')"></button>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
        <button class="btn" onclick="closeModals()">انصراف</button>
        <button class="btn primary" onclick="submitAddSite()">✅ ذخیره و شروع پایش</button>
      </div>
    </div>
  </div>
</div>

<!-- MODAL: GLOBAL SETTINGS -->
<div class="modal-backdrop" id="modal-settings">
  <div class="modal">
    <h3 style="margin:0 0 12px">⚙️ تنظیمات سراسری ربات</h3>
    <div id="global-settings-body"></div>
    <div style="display:flex;justify-content:flex-end;margin-top:14px">
      <button class="btn primary" onclick="closeModals()">بستن</button>
    </div>
  </div>
</div>

<!-- MODAL: LIVE CAPTCHA / CHALLENGE SOLVER -->
<div class="modal-backdrop" id="modal-challenge">
  <div class="modal" style="max-width:680px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <h3 style="margin:0" id="ch-title">🛡 حل زندهٔ کپچا</h3>
      <span class="badge neutral" id="ch-timer">--:--</span>
    </div>
    <p style="font-size:12px;color:var(--muted);margin:0 0 8px">
      روی مربع تیک کپچا یا دکمهٔ داخل تصویر زیر لمس/کلیک کنید تا کلیک شما مستقیماً در مرورگر سرور اعمال شود:
    </p>
    <div style="position:relative;background:#000;border-radius:10px;overflow:hidden;border:1px solid var(--border)">
      <img id="ch-img" style="width:100%;display:block;cursor:crosshair" alt="صفحه چالش" onclick="onChallengeImageClick(event)">
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;justify-content:space-between">
      <div style="display:flex;gap:6px">
        <button class="btn sm" onclick="refreshChallengeFrame()">🔄 بروزرسانی تصویر</button>
        <button class="btn sm" onclick="clickTurnstileCenter()">🎯 کلیک خودکار روی مربع کپچا</button>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn sm danger" onclick="finishChallenge('cancel')">❌ لغو</button>
        <button class="btn sm success" onclick="finishChallenge('done')">✅ حل شد (ذخیره کوکی)</button>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
if (tg) {
  tg.ready();
  tg.expand();
  if (tg.BackButton) {
    tg.BackButton.onClick(() => showHome());
  }
}

const params = new URLSearchParams(window.location.search);
// the admin token (only used outside a Telegram Web App button) arrives in the URL fragment, which is never
// sent to the server; it is read once and removed from the address bar
const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
const urlToken = hashParams.get("t") || "";
if (urlToken && window.history && history.replaceState) {
  history.replaceState(null, "", window.location.pathname + window.location.search);
}
const initialSiteKey = params.get("site") ? parseInt(params.get("site"), 10) : null;

let appState = null;
let curFilter = "all";
let currentSiteKey = null;
let currentSiteData = null;
let currentSiteTab = "overview";

const INTERVAL_PRESETS = [
  [30, "هر ۳۰ ثانیه"],
  [60, "هر ۱ دقیقه"],
  [90, "هر ۹۰ ثانیه"],
  [120, "هر ۲ دقیقه"],
  [180, "هر ۳ دقیقه"],
  [300, "هر ۵ دقیقه"],
  [600, "هر ۱۰ دقیقه"],
  [900, "هر ۱۵ دقیقه"],
  [1800, "هر ۳۰ دقیقه"],
  [3600, "هر ۱ ساعت"],
  [7200, "هر ۲ ساعت"],
  [10800, "هر ۳ ساعت"],
  [14400, "هر ۴ ساعت"],
  [21600, "هر ۶ ساعت"],
  [43200, "هر ۱۲ ساعت"],
  [86400, "هر ۲۴ ساعت"],
];

function buildIntervalOptions(currentSec, currentHuman) {
  const seen = new Set(INTERVAL_PRESETS.map(p => p[0]));
  let html = "";
  if (currentSec && !seen.has(currentSec)) {
    html += `<option value="${currentSec}" selected>هر ${escHtml(currentHuman || (currentSec + " ثانیه"))} (سفارشی)</option>`;
  }
  html += INTERVAL_PRESETS.map(([sec, label]) =>
    `<option value="${sec}" ${currentSec === sec ? "selected" : ""}>${label}</option>`
  ).join("");
  return html;
}

function haptic(kind = "light") {
  try {
    if (tg && tg.HapticFeedback) {
      if (kind === "success" || kind === "error") tg.HapticFeedback.notificationOccurred(kind);
      else tg.HapticFeedback.impactOccurred(kind);
    }
  } catch (_) {}
}

function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { el.style.display = "none"; }, 2800);
}

function escHtml(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function api(path, opts = {}) {
  const headers = Object.assign({"Content-Type": "application/json"}, opts.headers || {});
  if (tg && tg.initData) headers["X-Telegram-Init-Data"] = tg.initData;
  if (urlToken) headers["X-Admin-Token"] = urlToken;
  const res = await fetch(path, Object.assign({}, opts, {headers}));
  const data = await res.json().catch(() => ({ok: false, error: "خطای ارتباط با سرور"}));
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function loadState(silent = false) {
  try {
    appState = await api("/api/app/state");
    document.getElementById("nav-sub").textContent = `روشن از ${appState.uptime_human} پیش · ${appState.sites.length} سایت`;
    renderHome();
    if (initialSiteKey && !currentSiteKey && !window._initialOpened) {
      window._initialOpened = true;
      openSite(initialSiteKey);
    }
  } catch (err) {
    if (!silent) toast("❌ " + err.message);
    document.getElementById("nav-sub").textContent = err.message;
  }
}

function setFilter(f) {
  haptic("light");
  curFilter = f;
  document.querySelectorAll(".kpi").forEach(el => el.classList.remove("active"));
  const map = {all: "kpi-all", ok: "kpi-ok", error: "kpi-err"};
  if (map[f]) document.getElementById(map[f]).classList.add("active");
  renderHome();
}

function renderHome() {
  if (!appState) return;
  const sites = appState.sites || [];
  const okCount = sites.filter(s => s.status === "ok").length;
  const errCount = sites.filter(s => s.status === "error" || s.status === "broken").length;
  const chgCount = sites.reduce((a, s) => a + (s.changes_24h || 0), 0);

  document.getElementById("stat-total").textContent = sites.length;
  document.getElementById("stat-ok").textContent = okCount;
  document.getElementById("stat-err").textContent = errCount;
  document.getElementById("stat-24h").textContent = chgCount;

  // Challenge banner + Outbox banner
  const chBanner = document.getElementById("challenge-banner");
  let banners = "";
  if (appState.pending_outbox && appState.pending_outbox > 0) {
    banners += `
      <div class="panel-box" style="border-color:var(--warn);background:var(--warn-bg);display:flex;justify-content:space-between;align-items:center;gap:10px">
        <div>
          <b>📨 ${appState.pending_outbox} پیام در صف ارسال به تلگرام است</b>
          <div style="font-size:12px;color:var(--muted)">اگر حجم پیام‌ها زیاد است، می‌توانید صف ارسال را پاک کنید</div>
        </div>
        <button class="btn sm danger" onclick="clearPendingOutbox()">🧹 توقف و پاکسازی صف</button>
      </div>
    `;
  }
  if (appState.challenges && appState.challenges.length > 0) {
    banners += appState.challenges.map(c => `
      <div class="panel-box" style="border-color:var(--warn);background:var(--warn-bg);display:flex;justify-content:space-between;align-items:center;gap:10px">
        <div>
          <b>🛡 کپچا / چالش فعال برای «${escHtml(c.watch_label)}»</b>
          <div style="font-size:12px;color:var(--muted)">یک لمس برای مشاهده و حل زنده داخل مینی‌اپ</div>
        </div>
        <button class="btn sm primary" onclick="openChallengeModal('${escHtml(c.token)}', '${escHtml(c.watch_label)}')">🔓 حل کپچا</button>
      </div>
    `).join("");
  }
  chBanner.innerHTML = banners;

  const q = (document.getElementById("site-q").value || "").trim().toLowerCase();
  const filtered = sites.filter(s => {
    if (curFilter === "ok" && s.status !== "ok") return false;
    if (curFilter === "error" && s.status !== "error" && s.status !== "broken") return false;
    if (q && !s.label.toLowerCase().includes(q) && !s.url.toLowerCase().includes(q)) return false;
    return true;
  });

  const listEl = document.getElementById("sites-list");
  if (!filtered.length) {
    listEl.innerHTML = `<div class="panel-box" style="text-align:center;color:var(--muted)">هیچ سایتی با این فیلتر پیدا نشد.</div>`;
    return;
  }

  listEl.innerHTML = filtered.map(s => `
    <div class="site-card" onclick="openSite(${s.key})">
      <div class="site-head">
        <div>
          <h3 class="site-title">${escHtml(s.label)}</h3>
        </div>
        <span class="badge ${s.status}">${escHtml(s.status_label)}</span>
      </div>
      <span class="site-url">${escHtml(s.page_url)}</span>
      <div class="meta-row">
        <span class="badge neutral">🧭 ${escHtml(s.type_label)}</span>
        <span class="badge neutral">⏱ هر ${escHtml(s.interval_human)}</span>
        <span class="badge neutral">⚙️ ${escHtml(s.engine_label)}</span>
        ${s.crawl_enabled ? `<span class="badge neutral">📂 ${s.subpages_count} زیرصفحه</span>` : ""}
        ${s.only_keywords ? `<span class="badge ok">🎯 فقط کلیدی</span>` : ""}
        ${s.changes_24h ? `<span class="badge ok">🔔 ${s.changes_24h} تغییر در ۲۴ساعت</span>` : ""}
        ${s.has_cookies ? `<span class="badge neutral">🍪 دارای کوکی</span>` : ""}
      </div>
      ${s.last_error && s.status === "error" ? `<div style="margin-top:8px;font-size:12px;color:var(--danger)">❌ ${escHtml(s.last_error)}</div>` : ""}
      <div class="card-actions" onclick="event.stopPropagation()">
        <button class="btn sm primary" onclick="openSite(${s.key})">📊 پروفایل و تنظیمات سایت</button>
        <button class="btn sm" onclick="quickCheck(${s.key}, this)">🔄 بررسی فوری</button>
        <a class="btn sm" href="${escHtml(s.page_url)}" target="_blank" rel="noopener" style="text-decoration:none">🌐 باز کردن سایت</a>
      </div>
    </div>
  `).join("");
}

function onSearchInput() {
  document.getElementById("search-results").innerHTML = "";
  renderHome();
}

async function runHistorySearch() {
  const q = (document.getElementById("site-q").value || "").trim();
  if (!q) { toast("عبارتی برای جستجو بنویسید"); return; }
  haptic("light");
  const box = document.getElementById("search-results");
  box.innerHTML = `<div class="panel-box">⏳ در حال جستجوی «${escHtml(q)}» در کل تاریخچه…</div>`;
  try {
    const res = await api(`/api/app/search?q=${encodeURIComponent(q)}`);
    if (!res.results.length) {
      box.innerHTML = `<div class="panel-box">نتیجه‌ای برای «${escHtml(q)}» یافت نشد.</div>`;
      return;
    }
    box.innerHTML = `<div class="panel-box">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <b>🔍 نتایج جستجو در تاریخچه (${res.results.length} مورد)</b>
        <button class="btn sm" onclick="document.getElementById('search-results').innerHTML=''">بستن</button>
      </div>
      ${res.results.map(ev => `
        <div class="diff-block">
          <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted)">
            <span>🕒 ${escHtml(ev.created_human)}</span>
            ${ev.url ? `<a href="${escHtml(ev.url)}" target="_blank">🔗 لینک صفحه</a>` : ""}
          </div>
          <div>${ev.header_html}</div>
          ${(ev.blocks_html || []).slice(0, 3).map(b => `<div style="margin-top:6px">${b}</div>`).join("")}
        </div>
      `).join("")}
    </div>`;
  } catch (e) {
    box.innerHTML = "";
    toast("❌ " + e.message);
  }
}

async function quickCheck(key, btn) {
  haptic("light");
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = "⏳ در حال بررسی…";
  try {
    const r = await api(`/api/app/site/${key}/check`, {method: "POST"});
    haptic("success");
    toast(`✅ بررسی انجام شد (${r.elapsed}s): ${r.outcome}`);
    await loadState(true);
    if (currentSiteKey === key) await openSite(key, true);
  } catch (e) {
    haptic("error");
    toast("❌ " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

async function checkAllSites() {
  haptic("medium");
  toast("🔄 درخواست بررسی فوری برای همهٔ سایت‌ها ارسال شد");
  try {
    await api("/api/app/check-all", {method: "POST"});
    setTimeout(() => loadState(true), 2500);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function clearPendingOutbox(watchId = null) {
  haptic("medium");
  try {
    const res = await api("/api/app/clear-outbox", {
      method: "POST",
      body: JSON.stringify(watchId ? {watch_id: watchId} : {}),
    });
    haptic("success");
    toast(`🧹 ${res.cleared} پیام در صف ارسال لغو و پاکسازی شد`);
    await loadState(true);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

// ================================================================= PER-SITE PROFILE
async function openSite(key, keepTab = false) {
  haptic("light");
  currentSiteKey = key;
  if (!keepTab) currentSiteTab = "overview";
  document.getElementById("view-home").style.display = "none";
  document.getElementById("view-site").style.display = "block";
  if (tg && tg.BackButton) tg.BackButton.show();
  document.getElementById("site-header-card").innerHTML = "⏳ در حال بارگذاری پروفایل سایت…";
  try {
    currentSiteData = await api(`/api/app/site/${key}`);
    renderSiteProfile();
  } catch (e) {
    toast("❌ " + e.message);
    showHome();
  }
}

function showHome() {
  currentSiteKey = null;
  document.getElementById("view-site").style.display = "none";
  document.getElementById("view-home").style.display = "block";
  if (tg && tg.BackButton) tg.BackButton.hide();
  loadState(true);
}

function switchSiteTab(tab) {
  haptic("light");
  currentSiteTab = tab;
  ["overview", "diffs", "settings", "subpages"].forEach(t => {
    document.getElementById(`tab-btn-${t}`).classList.toggle("active", t === tab);
    document.getElementById(`site-tab-${t}`).style.display = t === tab ? "block" : "none";
  });
}

function renderSiteProfile() {
  if (!currentSiteData) return;
  const s = currentSiteData.site;
  const ch = currentSiteData.challenge;
  document.getElementById("site-top-badges").innerHTML = `<span class="badge ${s.status}">${escHtml(s.status_label)}</span>`;
  document.getElementById("site-header-card").innerHTML = `
    ${ch ? `
      <div style="margin-bottom:10px;padding:10px;border-radius:10px;border:1px solid var(--warn);background:var(--warn-bg);display:flex;justify-content:space-between;align-items:center;gap:8px">
        <div>
          <b>🛡 این سایت در انتظار حل کپچا / کلودفلر است</b>
          <div style="font-size:11px;color:var(--muted)">زمان باقی‌مانده: ${ch.remaining} ثانیه</div>
        </div>
        <button class="btn sm primary" onclick="openChallengeModal('${escHtml(ch.token)}', '${escHtml(s.label)}')">🔓 حل زندهٔ کپچا</button>
      </div>
    ` : ""}
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap">
      <div>
        <h2 style="margin:0 0 4px;font-size:18px">${escHtml(s.label)}</h2>
        <a href="${escHtml(s.page_url)}" target="_blank" rel="noopener" style="color:var(--primary);font-size:12px;direction:ltr;display:inline-block;word-break:break-all">🔗 ${escHtml(s.page_url)}</a>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn sm primary" onclick="quickCheck(${s.key}, this)">🔄 بررسی الان</button>
        <button class="btn sm" onclick="captureSiteScreenshot(${s.key}, this)">📸 عکس زنده</button>
      </div>
    </div>
    <div class="meta-row" style="margin-top:10px">
      <span class="badge neutral">⏱ هر ${escHtml(s.interval_human)}</span>
      <span class="badge neutral">✅ آخرین بررسی موفق: ${escHtml(s.last_ok_ago)}</span>
      <span class="badge neutral">🔔 آخرین تغییر: ${escHtml(s.last_change_ago)}</span>
      <span class="badge neutral">⚙️ موتور فعال: ${escHtml(s.engine_label)}</span>
      <span class="badge neutral">📂 زیرصفحه‌ها: ${s.subpages_count}</span>
    </div>
  `;

  // TAB 1: OVERVIEW & LIVE SCREENSHOT
  document.getElementById("site-tab-overview").innerHTML = `
    <div class="panel-box">
      <h4 style="margin:0 0 10px">⚡ عملیات سریع روی «${escHtml(s.label)}»</h4>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <button class="btn primary" onclick="quickCheck(${s.key}, this)">🔄 بررسی فوری صفحه</button>
        <button class="btn" onclick="captureSiteScreenshot(${s.key}, this)">📸 گرفتن اسکرین‌شات زنده</button>
        <button class="btn" onclick="toggleSiteField('enabled', ${!s.enabled})">${s.enabled ? "⏸ توقف موقت پایش" : "▶️ فعال‌سازی مجدد پایش"}</button>
        <button class="btn danger" onclick="resetSiteMemory(${s.key})">🧹 ریست حافظه (شروع از صفر)</button>
      </div>
      <div id="live-shot-box" style="margin-top:12px"></div>
    </div>
    <div class="panel-box">
      <h4 style="margin:0 0 8px">📌 خلاصهٔ وضعیت فنی</h4>
      <div style="font-size:13px;color:var(--muted);line-height:1.9">
        • <b>شناسهٔ یکتا:</b> <code>${escHtml(s.id)}</code><br>
        • <b>نوع پایش:</b> ${escHtml(s.type_label)}<br>
        • <b>فاصلهٔ بررسی:</b> هر ${escHtml(s.interval_human)} (${s.interval_seconds} ثانیه)<br>
        • <b>حالت گزارش:</b> ${s.report_style === "before_after" ? "قبل و بعد (۳ خطی کامل)" : "کلمه‌به‌کلمه داخل متن"}<br>
        • <b>فیلتر ارسال به کانال:</b> ${s.only_keywords ? "🎯 فقط تغییرات دارای کلمهٔ کلیدی" : "ارسال همهٔ تغییرات"}<br>
        • <b>کلمات کلیدی:</b> ${s.keywords.length ? escHtml(s.keywords.join("، ")) : "بدون محدودیت (همهٔ تغییرات)"}
      </div>
    </div>
  `;

  // TAB 2: VISUAL DIFF VIEWER
  const evs = currentSiteData.events || [];
  document.getElementById("site-tab-diffs").innerHTML = `
    <div class="panel-box">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
        <h4 style="margin:0">🔍 تاریخچهٔ تغییرات و گزارش‌ها (${evs.length})</h4>
        <input class="input" style="max-width:240px" placeholder="جستجو در تغییرات همین سایت…" oninput="filterSiteDiffs(this.value)">
      </div>
      ${evs.length === 0 ? `<div style="color:var(--muted);text-align:center;padding:20px">هنوز تغییری برای این سایت ثبت نشده است.</div>` :
        evs.map(ev => `
          <div class="diff-block site-diff-item">
            <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--muted);margin-bottom:6px">
              <span>🕒 ${escHtml(ev.created_human)} · <b>#${ev.id}</b></span>
              ${ev.url ? `<a href="${escHtml(ev.url)}" target="_blank" rel="noopener">🔗 باز کردن صفحهٔ تغییرکرده</a>` : ""}
            </div>
            <div>${ev.header_html}</div>
            ${(ev.blocks_html || []).map(b => `<div style="margin-top:8px">${b}</div>`).join("")}
          </div>
        `).join("")}
    </div>
  `;

  // TAB 3: INTERACTIVE SETTINGS
  document.getElementById("site-tab-settings").innerHTML = `
    <div class="panel-box">
      <div class="setting-row">
        <div class="setting-info">
          <b>🟢 پایش فعال</b>
          <small>روشن یا متوقف کردن بررسی خودکار این سایت</small>
        </div>
        <button class="switch ${s.enabled ? "on" : ""}" onclick="toggleSiteField('enabled', ${!s.enabled})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>⏱ فاصلهٔ زمانی بررسی</b>
          <small>فعلی: <b>هر ${escHtml(s.interval_human)}</b> (شامل صفحهٔ اصلی و زیرصفحه‌ها)</small>
        </div>
        <select class="input" style="max-width:175px" onchange="toggleSiteField('interval_seconds', parseInt(this.value,10))">
          ${buildIntervalOptions(s.interval_seconds, s.interval_human)}
        </select>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>✍️ زمان دلخواه (دقیقه یا ساعت)</b>
          <small>هر عددی بین ۱ دقیقه تا ۲۴ ساعت</small>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <input class="input" id="custom-interval-val" type="number" min="1" max="1440" style="width:74px" placeholder="مثلاً 3">
          <select class="input" id="custom-interval-unit" style="width:82px">
            <option value="3600" selected>ساعت</option>
            <option value="60">دقیقه</option>
          </select>
          <button class="btn sm primary" onclick="saveCustomInterval()">ثبت</button>
        </div>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🎯 فقط تغییرات دارای کلمهٔ کلیدی ارسال شود</b>
          <small>جلوگیری از ارسال پیام‌های اضافی؛ فقط وقتی کلمات کلیدی شما در تغییر بود پیام بفرستد</small>
        </div>
        <button class="switch ${s.only_keywords ? "on" : ""}" onclick="toggleOnlyKeywords(${!s.only_keywords})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🕷 خزش خودکار زیرصفحه‌ها (${s.subpages_count} صفحه)</b>
          <small>پایش خودکار لینک‌های داخلی زیرمجموعهٔ این صفحه (خاموش کردن = کاهش شدید پیام‌ها)</small>
        </div>
        <button class="switch ${s.crawl_enabled ? "on" : ""}" onclick="toggleSiteField('crawl_enabled', ${!s.crawl_enabled})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🔗 گزارش تغییر آدرس لینک‌ها</b>
          <small>اگر خاموش باشد، فقط تغییر متن گزارش می‌شود و تغییر لینک‌ها نادیده گرفته می‌شود</small>
        </div>
        <button class="switch ${s.track_links ? "on" : ""}" onclick="toggleSiteField('track_links', ${!s.track_links})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>📝 نمایش ۳ خطی کامل (قبل / بعد / کلمه‌به‌کلمه)</b>
          <small>نمایش جداگانهٔ خط قبلی، خط جدید و مقایسهٔ کلمه‌به‌کلمه با فاصلهٔ خوانا</small>
        </div>
        <button class="switch ${s.report_style === "before_after" ? "on" : ""}" onclick="toggleSiteField('report_style', '${s.report_style === "before_after" ? "inline" : "before_after"}')"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🔍 حساسیت حداکثری (حتی جابه‌جایی خطوط)</b>
          <small>گزارش کوچک‌ترین تغییرات و جابه‌جایی پاراگراف‌ها</small>
        </div>
        <button class="switch ${!s.ignore_reorder ? "on" : ""}" onclick="toggleSiteField('ignore_reorder', ${!s.ignore_reorder})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>📸 ارسال اسکرین‌شات همراه با گزارش تغییر</b>
          <small>وقتی تغییری رخ دهد، عکس صفحه هم در تلگرام فرستاده شود</small>
        </div>
        <button class="switch ${s.notify_mode === "both" ? "on" : ""}" onclick="toggleSiteField('notify_mode', '${s.notify_mode === "both" ? "text" : "both"}')"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>⏰ حالت بیدارباش (Alarm)</b>
          <small>تکرار هشدار در پی‌وی تا زمانی که دکمهٔ «دیدم» را بزنید</small>
        </div>
        <button class="switch ${s.alarm ? "on" : ""}" onclick="toggleSiteField('alarm', ${!s.alarm})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>🔕 ارسال بی‌صدا (Silent)</b>
          <small>پیام‌ها بدون صدای نوتیفیکیشن ارسال شوند (مگر کلمهٔ کلیدی داشته باشند)</small>
        </div>
        <button class="switch ${s.silent ? "on" : ""}" onclick="toggleSiteField('silent', ${!s.silent})"></button>
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <b>⚙️ موتور دریافت صفحه</b>
          <small>پیشنهاد: خودکار (در صورت مسدودی به شبیه‌ساز کروم و مرورگر می‌رود)</small>
        </div>
        <select class="input" style="max-width:175px" onchange="toggleSiteField('engine', this.value)">
          <option value="auto" ${s.engine === "auto" ? "selected" : ""}>خودکار (پیشنهادی)</option>
          <option value="http" ${s.engine === "http" ? "selected" : ""}>سریع (HTTP)</option>
          <option value="impersonate" ${s.engine === "impersonate" ? "selected" : ""}>شبیه‌ساز کروم (ضدکلودفلر)</option>
          <option value="browser" ${s.engine === "browser" ? "selected" : ""}>مرورگر کامل (Playwright)</option>
        </select>
      </div>
      <div style="margin-top:12px">
        <label style="font-size:12px;color:var(--muted)">🔑 کلمات کلیدی (با ویرگول جدا کنید)</label>
        <div style="display:flex;gap:8px;margin-top:4px">
          <input class="input" id="edit-kw" value="${escHtml(s.keywords.join(', '))}" placeholder="نوبت, ویزا, Termin">
          <button class="btn primary sm" onclick="saveKeywords()">ذخیره کلمات</button>
        </div>
      </div>
      <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
        <span style="font-size:12px;color:var(--muted)">حذف کامل این سایت از مانیتور</span>
        <button class="btn sm danger" onclick="deleteSite(${s.key})">🗑 حذف سایت</button>
      </div>
    </div>
  `;

  // TAB 4: SUBPAGES & COOKIE IMPORT
  const subs = currentSiteData.subpages || [];
  document.getElementById("site-tab-subpages").innerHTML = `
    <div class="panel-box">
      <h4 style="margin:0 0 8px">🍪 وارد کردن کوکی (دور زدن کلودفلر / لاگین)</h4>
      <p style="font-size:12px;color:var(--muted);margin:0 0 8px">
        اگر سایت نیاز به لاگین یا کوکی <code>cf_clearance</code> دارد، خروجی JSON افزونهٔ Cookie-Editor یا رشتهٔ کوکی را اینجا بچسبانید:
      </p>
      <textarea class="input" id="cookie-input" rows="3" dir="ltr" placeholder='[{"name":"cf_clearance","value":"..."}] یا cf_clearance=...;'></textarea>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn sm primary" onclick="submitCookies(${s.key})">🍪 ذخیره کوکی برای این سایت</button>
        ${s.has_cookies ? `<button class="btn sm danger" onclick="clearCookies(${s.key})">پاک کردن کوکی فعلی</button>` : ""}
      </div>
    </div>
    <div class="panel-box">
      <h4 style="margin:0 0 8px">📂 صفحات و زیرصفحه‌های کشف‌شده (${subs.length})</h4>
      ${subs.map(p => `
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:12px">
          <div style="font-weight:700">${escHtml(p.title)}</div>
          <a href="${escHtml(p.url)}" target="_blank" rel="noopener" style="color:var(--primary);direction:ltr;display:inline-block;word-break:break-all">${escHtml(p.url)}</a>
          <div style="color:var(--muted);margin-top:2px">آخرین بازدید: ${escHtml(p.last_seen)} · آخرین تغییر: ${escHtml(p.last_changed)}</div>
        </div>
      `).join("")}
    </div>
  `;

  switchSiteTab(currentSiteTab);
}

function filterSiteDiffs(q) {
  q = (q || "").toLowerCase();
  document.querySelectorAll(".site-diff-item").forEach(el => {
    el.style.display = (!q || el.textContent.toLowerCase().includes(q)) ? "" : "none";
  });
}

async function captureSiteScreenshot(key, btn) {
  haptic("light");
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = "📸 در حال عکس‌برداری…";
  try {
    const res = await api(`/api/app/site/${key}/screenshot`, {method: "POST"});
    haptic("success");
    switchSiteTab("overview");
    const box = document.getElementById("live-shot-box");
    box.innerHTML = `
      <div style="font-size:12px;color:var(--muted)">📸 تصویر زنده ثبت‌شده در ${escHtml(res.taken_at)}:</div>
      <img class="live-shot" src="${res.image_data_url}" alt="Screenshot">
    `;
  } catch (e) {
    haptic("error");
    toast("❌ " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

async function toggleSiteField(field, value) {
  if (!currentSiteKey) return;
  haptic("light");
  try {
    await api(`/api/app/site/${currentSiteKey}/update`, {
      method: "POST",
      body: JSON.stringify({[field]: value}),
    });
    haptic("success");
    toast("✅ تنظیمات ذخیره شد");
    await openSite(currentSiteKey, true);
  } catch (e) {
    haptic("error");
    toast("❌ " + e.message);
  }
}

async function toggleOnlyKeywords(enable) {
  if (!currentSiteData || !currentSiteData.site) return;
  if (enable && (!currentSiteData.site.keywords || !currentSiteData.site.keywords.length)) {
    toast("⚠️ ابتدا کلمات کلیدی را در پایین همین صفحه وارد و ذخیره کنید");
    return;
  }
  await toggleSiteField("only_keywords", enable);
}

async function saveCustomInterval() {
  const val = parseFloat(document.getElementById("custom-interval-val").value || "0");
  const unit = parseInt(document.getElementById("custom-interval-unit").value || "3600", 10);
  if (!val || val <= 0) {
    toast("لطفاً یک عدد معتبر وارد کنید");
    return;
  }
  const sec = Math.max(15, Math.min(86400, Math.round(val * unit)));
  await toggleSiteField("interval_seconds", sec);
}

async function saveKeywords() {
  const raw = document.getElementById("edit-kw").value || "";
  const kws = raw.replace(/،/g, ",").split(",").map(s => s.trim()).filter(Boolean);
  await toggleSiteField("keywords", kws);
}

async function resetSiteMemory(key) {
  if (!confirm("حافظه و اسنپ‌شات‌های قبلی این سایت پاک شود و از نو شروع کند؟")) return;
  haptic("medium");
  try {
    await api(`/api/app/site/${key}/reset`, {method: "POST"});
    toast("🧹 حافظهٔ سایت پاک شد و بررسی مجدد آغاز شد");
    await openSite(key, true);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function submitCookies(key) {
  const val = document.getElementById("cookie-input").value.trim();
  if (!val) { toast("متن کوکی را وارد کنید"); return; }
  try {
    const r = await api(`/api/app/site/${key}/cookies`, {method: "POST", body: JSON.stringify({cookies: val})});
    haptic("success");
    toast(`✅ ${r.count} کوکی ذخیره شد`);
    await openSite(key, true);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function clearCookies(key) {
  await api(`/api/app/site/${key}/cookies`, {method: "POST", body: JSON.stringify({cookies: "-"})});
  toast("🗑 کوکی‌های سایت پاک شد");
  await openSite(key, true);
}

async function deleteSite(key) {
  if (!confirm("آیا از حذف کامل این سایت مطمئن هستید؟")) return;
  try {
    await api(`/api/app/site/${key}/delete`, {method: "POST"});
    toast("🗑 سایت حذف شد");
    showHome();
  } catch (e) {
    toast("❌ " + e.message);
  }
}

// ================================================================= MODALS
function openAddModal() {
  haptic("light");
  document.getElementById("modal-add").style.display = "flex";
}

function openSettingsModal() {
  haptic("light");
  if (!appState) return;
  const st = appState.settings;
  document.getElementById("global-settings-body").innerHTML = `
    <div class="setting-row">
      <div class="setting-info">
        <b>📝 سبک گزارش پیش‌فرض: قبل و بعد (۳ خطی)</b>
        <small>نمایش جداگانهٔ خط قدیم، خط جدید و کلمه‌به‌کلمه برای همهٔ سایت‌ها</small>
      </div>
      <button class="switch ${st.report_style === "before_after" ? "on" : ""}" onclick="saveGlobalSetting('report_style', '${st.report_style === "before_after" ? "inline" : "before_after"}')"></button>
    </div>
    <div class="setting-row">
      <div class="setting-info">
        <b>📸 اسکرین‌شات خودکار روی همهٔ تغییرات</b>
        <small>ارسال عکس صفحه همراه با هر گزارش تغییر</small>
      </div>
      <button class="switch ${st.auto_screenshot ? "on" : ""}" onclick="saveGlobalSetting('auto_screenshot', ${!st.auto_screenshot})"></button>
    </div>
    <div class="setting-row">
      <div class="setting-info">
        <b>🌙 ساعت سکوت شبانه (۲۳:۰۰ تا ۰۷:۰۰)</b>
        <small>ارسال بی‌صدای تغییرات عادی در شب (بیدارباش‌ها همچنان با صدا می‌آیند)</small>
      </div>
      <button class="switch ${st.quiet_hours ? "on" : ""}" onclick="saveGlobalSetting('quiet_hours', ${!st.quiet_hours})"></button>
    </div>
    <div class="setting-row">
      <div class="setting-info">
        <b>📊 گزارش خلاصهٔ روزانه</b>
        <small>ارسال آمار سلامت پایش هر روز صبح</small>
      </div>
      <button class="switch ${st.daily_digest ? "on" : ""}" onclick="saveGlobalSetting('daily_digest', ${!st.daily_digest})"></button>
    </div>
    <div class="setting-row">
      <div class="setting-info">
        <b>🚀 پیام شروع‌به‌کار سرویس</b>
        <small>ارسال پیام «مانیتور راه‌اندازی شد» هنگام ری‌استارت سرور</small>
      </div>
      <button class="switch ${st.startup_notify ? "on" : ""}" onclick="saveGlobalSetting('startup_notify', ${!st.startup_notify})"></button>
    </div>
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <div>
        <b style="font-size:13px">🧹 پاکسازی صف پیام‌های در انتظار ارسال</b>
        <div style="font-size:11px;color:var(--muted)">در انتظار ارسال: ${appState.pending_outbox || 0} پیام</div>
      </div>
      <button class="btn sm danger" onclick="clearPendingOutbox()">پاکسازی صف</button>
    </div>
  `;
  document.getElementById("modal-settings").style.display = "flex";
}

async function saveGlobalSetting(k, v) {
  haptic("light");
  try {
    await api("/api/app/settings", {method: "POST", body: JSON.stringify({[k]: v})});
    await loadState(true);
    openSettingsModal();
    toast("✅ تنظیمات کلی بروز شد");
  } catch (e) {
    toast("❌ " + e.message);
  }
}

function closeModals() {
  document.querySelectorAll(".modal-backdrop").forEach(el => el.style.display = "none");
}

async function submitAddSite() {
  const url = document.getElementById("add-url").value.trim();
  if (!url) { toast("لطفاً آدرس سایت را وارد کنید"); return; }
  haptic("medium");
  try {
    const res = await api("/api/app/add", {
      method: "POST",
      body: JSON.stringify({
        url,
        name: document.getElementById("add-name").value.trim(),
        type: document.getElementById("add-type").value,
        interval_seconds: parseInt(document.getElementById("add-interval").value, 10),
        keywords: document.getElementById("add-keywords").value,
        crawl_enabled: document.getElementById("add-crawl").classList.contains("on"),
      }),
    });
    closeModals();
    toast("✅ سایت جدید اضافه شد و پایش آغاز گردید");
    await loadState(true);
    openSite(res.key);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

let activeChallengeToken = null;
async function openChallengeModal(token, label) {
  haptic("light");
  activeChallengeToken = token;
  document.getElementById("ch-title").textContent = `🛡 حل زندهٔ کپچا — «${label}»`;
  document.getElementById("modal-challenge").style.display = "flex";
  await refreshChallengeFrame();
}

async function refreshChallengeFrame() {
  if (!activeChallengeToken) return;
  try {
    const res = await api(`/api/app/challenge/${activeChallengeToken}/frame`);
    document.getElementById("ch-img").src = res.image_data_url;
    document.getElementById("ch-timer").textContent = `${res.remaining}s`;
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function onChallengeImageClick(ev) {
  if (!activeChallengeToken) return;
  const img = document.getElementById("ch-img");
  const rect = img.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const x = Math.round((ev.clientX - rect.left) * ((img.naturalWidth || 1280) / rect.width));
  const y = Math.round((ev.clientY - rect.top) * ((img.naturalHeight || 800) / rect.height));
  haptic("light");
  toast(`🖱 کلیک در (${x}, ${y}) ارسال شد…`);
  try {
    await api(`/api/app/challenge/${activeChallengeToken}/action`, {
      method: "POST",
      body: JSON.stringify({action: "click", x, y}),
    });
    setTimeout(() => refreshChallengeFrame(), 1800);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function clickTurnstileCenter() {
  if (!activeChallengeToken) return;
  haptic("medium");
  toast("🎯 کلیک هوشمند روی چک‌باکس کپچا ارسال شد…");
  try {
    await api(`/api/app/challenge/${activeChallengeToken}/action`, {
      method: "POST",
      body: JSON.stringify({action: "turnstile"}),
    });
    setTimeout(() => refreshChallengeFrame(), 2000);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

async function finishChallenge(mode) {
  if (!activeChallengeToken) return;
  haptic("success");
  try {
    await api(`/api/app/challenge/${activeChallengeToken}/action`, {
      method: "POST",
      body: JSON.stringify({action: mode}),
    });
    activeChallengeToken = null;
    closeModals();
    toast(mode === "done" ? "✅ چالش ثبت شد و کوکی ذخیره گردید" : "❌ چالش لغو شد");
    await loadState(true);
  } catch (e) {
    toast("❌ " + e.message);
  }
}

loadState();
setInterval(() => { if (!currentSiteKey) loadState(true); }, 15000);
</script>
</body>
</html>
"""
