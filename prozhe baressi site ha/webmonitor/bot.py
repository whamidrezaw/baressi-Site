"""Telegram admin panel: add, edit, pause and delete sites from a private chat with the bot.

Admins are recognised automatically — the creator/admins of every channel or group in
telegram.chat_ids, private chat ids listed there, and telegram.admin_ids — so nobody has to
edit monitor-config.json. Site definitions live in the database (see registry.py).

The interface works like a small app:

* a persistent keyboard at the bottom of the chat (📋 sites, ➕ add, 📊 status, …) that is always
  one tap away and never gets lost in the history;
* *panel* messages (dashboard, site list, site card, wizard) that are edited in place while
  navigating;
* *report* messages (status, check results, previews, access tests) that are never overwritten:
  their buttons carry a "+" prefix and open a new message instead.

Every button carries a short callback such as "c:12" (card of site 12). Free-text answers (names,
keywords, URLs) are collected through a small per-admin session.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import report
from .analyzer import GOETHE, Analysis, analyze, choice_filter_values, preview_choice, smart_name, suggest_choices
from .config import ConfigError, Proxy, Watch, check_selector
from .engine import DIGESTABLE, ENGINE_LABELS
from .extract import ExtractError, normalize_url, parse_feed
from .fetchers import FetchError
from .netguard import is_public_host  # noqa: F401 - also imported from here by older code
from .notifier import NotifyError, TelegramApiError, build_parts
from .registry import default_crawl
from .util import (
    esc, esc_attr, fa_datetime, fa_digits, fa_elapsed, fa_number, format_short, format_ts, human_duration, truncate,
)

log = logging.getLogger("webmonitor")

PAGE_SIZE = 8
SESSION_TTL = 1800
PROMPT_TTL = 900          # an unanswered question expires after 15 minutes
INTERVALS = (60, 180, 300, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
RULE = report.RULE
ENGINE_NAMES = {"auto": "خودکار", "http": "سریع (HTTP)", "impersonate": "شبیه‌ساز کروم (ضدمسدودی)",
                "browser": "مرورگر"}
ENGINE_ORDER = ["auto", "http", "impersonate", "browser"]
KIND_NAMES = {"change": "🔔 تغییر", "new_page": "🆕 صفحهٔ جدید", "removed_page": "🗑 حذف صفحه", "file": "📎 فایل",
              "new_items": "📰 مورد تازه", "error": "⚠️ خطا", "recovered": "✅ رفع خطا", "info": "ℹ️ اطلاع"}
STATUS_MARKS = {"pending": "⏳", "filtered": "🔇", "failed": "❌"}
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
DOMAIN_RE = re.compile(r"^[\w-]+(\.[\w-]+)*\.[a-z]{2,}(/\S*)?$", re.I)
KEYCAPS = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")

# --- the persistent keyboard at the bottom of the private chat
BTN_SITES, BTN_ADD, BTN_STATUS = "📋 سایت‌ها", "➕ افزودن سایت", "📊 وضعیت"
BTN_CHECK, BTN_SETTINGS, BTN_HELP = "🔄 بررسی همه", "⚙️ تنظیمات", "❓ راهنما"
KEYBOARD_VERSION = "3"
MAIN_KEYBOARD = {
    "keyboard": [[{"text": BTN_SITES}, {"text": BTN_ADD}],
                 [{"text": BTN_STATUS}, {"text": BTN_CHECK}],
                 [{"text": BTN_SETTINGS}, {"text": BTN_HELP}]],
    "resize_keyboard": True, "is_persistent": True,
    "input_field_placeholder": "لینک سایت را بفرستید یا یک دکمه را بزنید",
}
BOT_COMMANDS = [
    {"command": "panel", "description": "داشبورد مدیریت"},
    {"command": "add", "description": "افزودن سایت جدید"},
    {"command": "list", "description": "فهرست سایت‌ها"},
    {"command": "status", "description": "وضعیت همهٔ سایت‌ها"},
    {"command": "check", "description": "بررسی فوری همه"},
    {"command": "search", "description": "جستجو در تاریخچهٔ تغییرات"},
    {"command": "export", "description": "پشتیبان فهرست سایت‌ها"},
    {"command": "help", "description": "راهنما"},
]
PROMPTS = {
    "name": "📝 <b>نام دلخواه را بفرستید</b>\nدر گزارش‌ها و فهرست سایت‌ها همین نام نمایش داده می‌شود.",
    "keywords": ("🔑 <b>کلمات کلیدی را با ویرگول جدا کنید</b>، مثلاً:\n<code>نوبت, ویزا, appointment, Termin</code>\n\n"
                 "تغییراتی که یکی از این کلمات را داشته باشند با 🚨 مشخص می‌شوند (و با «فقط کلیدی» فقط همان‌ها "
                 "ارسال می‌شوند).\nبرای حذف همه، یک خط تیره (-) بفرستید."),
    "interval": ("⏱ <b>فاصلهٔ بررسی را بفرستید</b>:\n"
                 "• به ساعت: مثلاً <code>3 ساعت</code> یا <code>3h</code>\n"
                 "• به دقیقه: مثلاً <code>30 دقیقه</code> یا <code>30m</code>\n"
                 "• یا به ثانیه (عددی بین ۱۵ تا ۸۶۴۰۰): مثلاً <code>10800</code>"),
    "selector": ("✍️ <b>CSS selector بخش موردنظر را بفرستید</b>، مثلاً <code>#main</code> یا <code>.content</code>\n"
                 "(اگر نمی‌دانید، از گزینه‌های پیشنهادی استفاده کنید.)"),
    "url": "🔗 <b>آدرس جدید صفحه را بفرستید:</b>",
    "proxy": ("🌐 <b>پروکسی اختصاصی این سایت را بفرستید</b>، مثلاً:\n"
              "<code>socks5://127.0.0.1:40000</code> (Cloudflare WARP روی همین سرور)\n"
              "<code>http://user:pass@host:port</code> (پروکسی خانگی/موبایل)\n\n"
              "معمولاً لازم نیست: برای سایت‌هایی که IP سرور را مسدود کنند، پروکسی پشتیبان (⚙️ تنظیمات) خودکار "
              "استفاده می‌شود.\nبرای حذف، یک خط تیره (-) بفرستید."),
    "fallback": ("🛡 <b>آدرس پروکسی پشتیبان را بفرستید</b>\nبرای همهٔ سایت‌هایی که IP سرور را مسدود می‌کنند استفاده "
                 "می‌شود، مثلاً:\n<code>socks5://127.0.0.1:40000</code> (WARP)\n<code>http://user:pass@host:port</code> "
                 "(پروکسی خانگی/موبایل)\n\nبرای برگشت به حالت خودکار (WARP)، یک خط تیره (-) بفرستید."),
    "cookies": ("🍪 <b>ارسال کوکی برای دور زدن لاگین یا کلودفلر</b>\n\n"
                "می‌توانید کوکی‌های سایت را از مرورگر خود (با افزونهٔ Cookie-Editor در قالب JSON یا به‌صورت "
                "<code>cf_clearance=...; session=...</code>) کپی و همین‌جا ارسال کنید تا ربات با نشست شما وارد شود.\n"
                "برای پاک کردن کوکی‌های قبلی، یک خط تیره (-) بفرستید."),
    "search": ("🔍 <b>عبارت موردنظر برای جستجو در تاریخچهٔ تغییرات را بفرستید:</b>\n"
               "مثلاً: <code>نوبت</code>، <code>ویزا</code>، یا نام یک شهر/بخش."),
}
HELP = (
    "❓ <b>راهنمای ربات مانیتور</b>\n" + RULE + "\n"
    "<b>➕ افزودن سایت</b>\n"
    "لینک صفحه را بفرستید (یا «➕ افزودن سایت»). ربات صفحه را بررسی می‌کند، بهترین حالت پایش را با ⭐ پیشنهاد "
    "می‌دهد و پیش‌نمایش نشان می‌دهد؛ با «✅ ذخیره و شروع» پایش شروع می‌شود.\n\n"
    "<b>🧭 حالت‌های پایش</b>\n"
    "📰 <b>تیترهای جدید</b> — سایت خبری: فقط خبرهای تازه، بدون پیام‌های بیهوده\n"
    "📄 <b>بخش / کل صفحه</b> — سفارت و دانشگاه: هر تغییر متن، کلمه‌به‌کلمه\n"
    "🎓 <b>آزمون‌های گوته</b> — ظرفیت و زمان ثبت‌نام هر آزمون (با فیلتر شهر)\n"
    "📢 <b>کانال تلگرام</b> — @نام_کانال را بفرستید\n"
    "📡 <b>RSS</b> — خبرخوان رسمی سایت\n\n"
    "<b>⏰ بیدارباش</b>\n"
    "برای سایت‌های ظرفیتی روشن کنید: هشدار خصوصی تا زدن «دیدم» تکرار می‌شود — حتی ساعت ۳ نیمه‌شب. "
    "اعلان‌های این ربات را در گوشی بی‌صدا نکنید.\n\n"
    "<b>🛡 سایت‌هایی که مسدود می‌کنند</b>\n"
    "اگر سایتی IP سرور را مسدود کند (مثل خطای 403 گوته)، ربات خودکار از پروکسی پشتیبان (WARP) استفاده می‌کند. "
    "«🧪 تست دسترسی» در کارت سایت همهٔ روش‌ها و مسیرها را امتحان می‌کند. حتی اگر سایتی هنگام افزودن باز نشود، "
    "«➕ افزودن به‌هرحال» آن را ثبت می‌کند و به محض باز شدن خبرتان می‌کند.\n\n"
    "<b>📋 مدیریت هر سایت</b>\n"
    "در «📋 سایت‌ها» روی سایت بزنید: 🔄 بررسی فوری · 👁 پیش‌نمایش · 📸 عکس صفحه · 🧪 تست دسترسی · "
    "📜 تاریخچه · ✏️ ویرایش · ⏸ توقف · 🗑 حذف\n\n"
    "<b>📖 خواندن گزارش‌ها</b>\n"
    "🟢 متن جدید · 🔴 <s>متن حذف‌شده</s> · 🟡 ویرایش (<s>قبلی</s> <b><u>جدید</u></b>)\n"
    "📍 بخشی از صفحه که تغییر در آن است · 🚨 دارای کلمهٔ کلیدی\n\n"
    "<b>👥 در گروه/کانال اطلاع‌رسانی</b>\n"
    "/status وضعیت · /list فهرست · /check بررسی فوری (فقط مدیران)\n\n"
    "💾 /export فایل پشتیبان · 📥 برای بازگردانی، همان فایل را برای ربات بفرستید."
)


def _button(text: str, data: str) -> dict:
    if data.startswith("webapp:"):
        return {"text": text, "web_app": {"url": data[7:]}}
    if data.startswith(("http://", "https://")):
        return {"text": text, "url": data}
    return {"text": text, "callback_data": data}


def kb(*rows) -> dict:
    """Inline keyboard from rows of (text, callback data or URL); empty rows are skipped."""
    return {"inline_keyboard": [[_button(text, data) for text, data in row] for row in rows if row]}


def kbn(*rows) -> dict:
    """Keyboard of a report/result message: its buttons open a new message instead of replacing it."""
    return kb(*[[(text, data if data.startswith(("http://", "https://", "webapp:", "+")) else "+" + data)
                 for text, data in row] for row in rows if row])


def onoff(flag: bool) -> str:
    return "روشن" if flag else "خاموش"


def number_icon(index: int) -> str:
    return KEYCAPS[index - 1] if 0 < index <= len(KEYCAPS) else f"{fa_digits(index)}."


def parse_keywords(text: str) -> list[str]:
    if text.strip() in ("-", "—", "حذف", "هیچ"):
        return []
    result: list[str] = []
    for part in re.split(r"[,،؛;\n]+", text):
        part = part.strip()[:60]
        if part and part not in result:
            result.append(part)
    return result[:30]


def normalize_input_url(text: str) -> str | None:
    """A monitorable URL from what an admin typed (bare domains, @channel and t.me links included)."""
    text = (text or "").strip()
    handle = re.fullmatch(r"@([A-Za-z][A-Za-z0-9_]{3,})", text)
    if handle:
        return f"https://t.me/s/{handle.group(1)}"
    match = URL_RE.search(text)
    if match:
        url = match.group(0)
    elif DOMAIN_RE.match(text):
        url = "https://" + text
    else:
        return None
    url = url.rstrip(".,،؛)»\"'")
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if parts.hostname.lower() in ("t.me", "telegram.me"):
        segments = [s for s in parts.path.split("/") if s]
        if segments and segments[0] not in ("s", "joinchat") and not segments[0].startswith("+"):
            return f"https://t.me/s/{segments[0]}"
    return url


def looks_like_site(text: str) -> bool:
    """A web page address (not a proxy address): http(s) with a path or without a port, or t.me."""
    match = URL_RE.search(text or "")
    if not match:
        return bool(re.match(r"@[A-Za-z]", (text or "").strip()))
    try:
        parts = urlsplit(match.group(0))
        port = parts.port
    except ValueError:
        return False
    return parts.path not in ("", "/") or port is None


def describe_result(result: str) -> str:
    if result.startswith("error"):
        return f"⚠️ <b>بررسی ناموفق بود:</b>\n<code>{esc(truncate(result[6:].strip(' :'), 300))}</code>"
    if result.startswith("baseline"):
        return "📌 نسخهٔ مرجع ذخیره شد؛ از این به بعد هر تغییری گزارش می‌شود."
    if result.startswith(("CHANGE", "NEW")):
        if "not sent" in result:
            return "🔇 تغییری پیدا شد ولی کلمهٔ کلیدی نداشت (طبق تنظیمات ارسال نشد)."
        return "🔔 تغییر پیدا شد و گزارش آن ارسال شد."
    return "✅ بدون تغییر — همه‌چیز مثل بررسی قبلی است."


def _error_kind(text: str) -> str:
    if re.search(r"\b(401|403|406|429|503)\b|bot protection|looks like", text, re.I):
        return "blocked"
    if re.search(r"timed? ?out|timeout", text, re.I):
        return "timeout"
    if re.search(r"network|connect|resolve|dns|refused|reset", text, re.I):
        return "network"
    return "other"


@dataclass
class Draft:
    input_url: str
    analysis: Analysis
    choices: list
    name: str
    interval: int
    keywords: list = field(default_factory=list)
    crawl: bool = False
    url: str = ""
    choice: dict | None = None
    preview: list = field(default_factory=list)
    preview_total: int = 0
    edit_key: int | None = None
    base_spec: dict | None = None
    json_filter: dict = field(default_factory=dict)
    alarm: bool = False
    route: str = ""          # "fallback": the page only opened through the fallback proxy


@dataclass
class Session:
    draft: Draft | None = None
    awaiting: str = ""
    asked: float = 0.0
    pending_import: list | None = None
    pending_url: str = ""
    touched: float = field(default_factory=time.time)

    def ask(self, what: str) -> None:
        self.awaiting, self.asked = what, time.time()


class _Callback:
    """Answers a button press exactly once (early for slow actions, otherwise at the end)."""

    def __init__(self, tg, query_id: str):
        self.tg, self.id, self.done = tg, query_id, False

    async def ack(self, text: str = "", alert: bool = False) -> None:
        if self.done or not self.id:
            return
        self.done = True
        await self.tg.answer_callback(self.id, text, alert)


class AdminBot:
    def __init__(self, monitor):
        self.m = monitor
        self.tg = monitor.notifier
        self.cfg = monitor.config.telegram
        self.allow_private_urls = False
        self.started = time.time()
        self.username: str | None = None
        self._sessions: dict[str, Session] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._admin_cache: dict[str, tuple[bool, float]] = {}
        self._denied: dict[str, float] = {}
        self._tasks: set[asyncio.Task] = set()
        self._keyboard_actions = {
            BTN_SITES: lambda chat, uid: self.show_list(chat),
            BTN_ADD: lambda chat, uid: self.ask_url(chat, uid),
            BTN_STATUS: lambda chat, uid: self.show_status(chat),
            BTN_CHECK: lambda chat, uid: self.check_all(chat),
            BTN_SETTINGS: lambda chat, uid: self.show_settings(chat),
            BTN_HELP: lambda chat, uid: self.show_help(chat),
        }

    # ================================================================= update loop

    async def run(self) -> None:
        try:
            me = await self.tg.call("getMe") or {}
            self.username = me.get("username") or None
        except NotifyError as exc:
            log.debug("getMe failed: %s", exc)
        try:
            await self.tg.call("setMyCommands", {"commands": BOT_COMMANDS})
        except NotifyError as exc:
            log.debug("setMyCommands failed: %s", exc)
        await self._announce_keyboard()
        log.info("Telegram admin panel ready: open the bot in a private chat and send /panel")
        offset = None
        try:
            while True:
                try:
                    updates = await self.tg.get_updates(offset)
                except asyncio.CancelledError:
                    raise
                except TelegramApiError as exc:
                    if exc.code == 409:
                        log.warning("Telegram panel paused: another program is reading this bot's updates "
                                    "(a second monitor instance or a webhook)")
                    else:
                        log.warning("Telegram panel: getUpdates failed: %s", exc)
                    await asyncio.sleep(60)
                    continue
                except NotifyError as exc:
                    log.debug("getUpdates failed: %s", exc)
                    await asyncio.sleep(15)
                    continue
                for update in updates:
                    offset = update["update_id"] + 1
                    task = asyncio.create_task(self.handle_update(update))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        finally:
            pending = list(self._tasks)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            self._tasks.clear()

    async def _announce_keyboard(self) -> None:
        """After an update, give every known admin the new bottom keyboard (once per version)."""
        store = self.m.store
        for uid in store.admin_ids():
            if store.get_setting(f"kb:{uid}", "") == KEYBOARD_VERSION:
                continue
            try:
                await self.tg.send_text(
                    uid, "🆕 <b>ربات به‌روز شد</b>\n\n"
                         "⌨️ منوی ثابت پایین صفحه فعال شد: 📋 سایت‌ها · ➕ افزودن · 📊 وضعیت · 🔄 بررسی همه · "
                         "⚙️ تنظیمات · ❓ راهنما\n"
                         "📰 حالت جدید «تیترهای جدید» برای سایت‌های خبری (بدون پیام‌های بیهوده)\n"
                         "🛡 استفادهٔ خودکار از پروکسی WARP برای سایت‌هایی که IP سرور را مسدود می‌کنند\n"
                         "📸 عکس صفحه و گزارش‌های مرتب‌تر",
                    reply_markup=MAIN_KEYBOARD)
            except NotifyError as exc:
                log.debug("could not send the keyboard to %s: %s", uid, exc)
                continue
            store.set_setting(f"kb:{uid}", KEYBOARD_VERSION)

    async def handle_update(self, update: dict) -> None:
        try:
            if "callback_query" in update:
                await self._on_callback(update["callback_query"])
            elif "message" in update:
                await self._on_message(update["message"])
            elif "channel_post" in update:
                await self._on_channel_post(update["channel_post"])
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Telegram panel: handling an update failed")

    # ================================================================= access control

    def _static_admins(self) -> set[str]:
        admins = {str(a) for a in self.cfg.admin_ids}
        admins.update(chat for chat in self.cfg.chat_ids if chat.isdigit())  # private chats
        return admins

    async def is_admin(self, uid: str) -> bool:
        if not uid:
            return False
        if uid in self._static_admins():
            return True
        cached = self._admin_cache.get(uid)
        if cached and cached[1] > time.time():
            return cached[0]
        ok = False
        for chat in self.cfg.chat_ids:
            if not chat.startswith(("-", "@")):
                continue
            try:
                member = await self.tg.call("getChatMember", {"chat_id": chat, "user_id": int(uid)}, timeout=15)
            except (NotifyError, ValueError):
                continue
            if (member or {}).get("status") in ("creator", "administrator"):
                ok = True
                break
        self._admin_cache[uid] = (ok, time.time() + (900 if ok else 60))
        return ok

    async def _deny(self, chat_id: str, uid: str) -> None:
        now = time.time()
        if now - self._denied.get(uid, 0) < 600:
            return
        self._denied[uid] = now
        log.warning("Telegram panel: ignored a message from non-admin user %s", uid)
        try:
            await self.tg.send_text(chat_id, "⛔ این ربات خصوصی است و فقط مدیران کانال اطلاع‌رسانی "
                                             "می‌توانند از آن استفاده کنند.")
        except NotifyError:
            pass

    def _session(self, uid: str) -> Session:
        session = self._sessions.get(uid)
        if session is None or time.time() - session.touched > SESSION_TTL:
            session = self._sessions[uid] = Session()
        session.touched = time.time()
        return session

    def _lock(self, uid: str) -> asyncio.Lock:
        return self._locks.setdefault(uid, asyncio.Lock())

    # ================================================================= incoming

    async def _on_message(self, message: dict) -> None:
        chat = message.get("chat") or {}
        if message.get("date", 0) < self.started - 120:
            return
        user = message.get("from") or {}
        uid, chat_id = str(user.get("id", "")), str(chat.get("id"))
        if chat.get("type") in ("group", "supergroup"):
            await self._on_group_message(message, chat_id, uid)
            return
        if chat.get("type") != "private":
            return
        if not await self.is_admin(uid):
            await self._deny(chat_id, uid)
            return
        self.m.store.touch_admin(uid, user.get("first_name") or user.get("username") or "")
        async with self._lock(uid):
            await self._handle_message(chat_id, uid, message)

    def _command(self, text: str) -> tuple[str, str] | None:
        """("/status", argument) for a command meant for this bot, else None."""
        if not text.startswith("/"):
            return None
        command, _, argument = text.partition(" ")
        name, _, target = command.partition("@")
        if target and self.username and target.lower() != self.username.lower():
            return None
        return name.lower(), argument.strip()

    def _private_button(self) -> dict | None:
        if not self.username:
            return None
        return kb([("🛠 باز کردن پنل در چت خصوصی", f"https://t.me/{self.username}?start=panel")])

    async def _on_group_message(self, message: dict, chat_id: str, uid: str) -> None:
        """Commands in the notification group: /status, /list, /check (admins), /help."""
        parsed = self._command((message.get("text") or "").strip())
        if parsed is None:
            return
        sender_chat = str((message.get("sender_chat") or {}).get("id", ""))
        admin = sender_chat == chat_id or await self.is_admin(uid)  # anonymous admins post as the group
        if chat_id not in self.cfg.chat_ids and not admin:
            return
        await self._group_command(chat_id, parsed[0], admin)

    async def _group_command(self, chat_id: str, command: str, admin: bool) -> None:
        if command == "/status":
            await self._send_long(chat_id, *self.m.status_report(), markup=self._private_button())
        elif command == "/list":
            await self.tg.send_text(chat_id, self._public_list(), reply_markup=self._private_button())
        elif command == "/check":
            if not admin:
                await self.tg.send_text(chat_id, "⛔ بررسی فوری فقط برای مدیران است.")
                return
            self.m.trigger_all()
            await self.tg.send_text(chat_id, f"⏳ بررسی فوری {fa_digits(len(self.m.watches))} سایت شروع شد؛ "
                                             "هر تغییری همین‌جا اعلام می‌شود.")
        elif command in ("/help", "/start", "/panel", "/menu", "/add"):
            await self.tg.send_text(
                chat_id, "🤖 <b>ربات مانیتور</b>\nتغییرات سایت‌ها همین‌جا اعلام می‌شود.\n\n"
                         "دستورات این گروه: /status وضعیت · /list فهرست سایت‌ها · /check بررسی فوری (مدیران)\n"
                         "🛠 برای افزودن، حذف و ویرایش سایت‌ها ربات را در چت خصوصی باز کنید.",
                reply_markup=self._private_button())

    async def _on_channel_post(self, post: dict) -> None:
        chat_id = str((post.get("chat") or {}).get("id", ""))
        parsed = self._command((post.get("text") or "").strip())
        if chat_id not in self.cfg.chat_ids or parsed is None or post.get("date", 0) < self.started - 120:
            return
        await self._group_command(chat_id, parsed[0], admin=True)  # only channel admins can post

    async def _handle_message(self, chat_id: str, uid: str, message: dict) -> None:
        session = self._session(uid)
        text = (message.get("text") or "").strip()
        if message.get("document"):
            if session.awaiting.startswith("cookies:"):
                try:
                    raw_bytes = await self.tg.download_file(message["document"]["file_id"])
                    text = raw_bytes.decode("utf-8-sig", errors="replace")
                except Exception as exc:
                    await self.tg.send_text(chat_id, f"❌ فایل کوکی دریافت نشد: {esc(str(exc))}")
                    return
                await self._handle_input(chat_id, uid, session, text)
                return
            await self._receive_import(chat_id, uid, message["document"])
            return
        action = self._keyboard_actions.get(text)
        if action is not None:
            session.awaiting = ""
            await action(chat_id, uid)
            return
        parsed = self._command(text)
        if parsed is not None:
            session.awaiting = ""
            await self._private_command(chat_id, uid, session, *parsed)
            return
        if session.awaiting and time.time() - session.asked > PROMPT_TTL:
            session.awaiting = ""  # an old question must not swallow a new message
        if session.awaiting and self._is_new_site(session.awaiting, text):
            session.awaiting = ""
            await self.start_analysis(chat_id, uid, text, note="ℹ️ ویرایش قبلی لغو شد و این لینک بررسی می‌شود.")
        elif session.awaiting:
            await self._handle_input(chat_id, uid, session, text)
        elif normalize_input_url(text):
            await self.start_analysis(chat_id, uid, text)
        else:
            await self.show_menu(chat_id, note="💡 برای افزودن سایت، لینک صفحه را بفرستید یا از دکمه‌ها استفاده کنید.")

    @staticmethod
    def _is_new_site(awaiting: str, text: str) -> bool:
        """A page link sent while another question is open is a new site, not the answer."""
        field_name = awaiting.rsplit(":", 1)[-1]
        if awaiting in ("url", "search") or awaiting.startswith("cookies:") or field_name == "url":
            return False
        return looks_like_site(text) and bool(normalize_input_url(text))

    async def _private_command(self, chat_id: str, uid: str, session: Session, command: str, argument: str) -> None:
        if command == "/start":
            await self.welcome(chat_id, uid)
        elif command in ("/panel", "/menu"):
            await self._ensure_keyboard(chat_id, uid)
            await self.show_menu(chat_id)
        elif command == "/add":
            if argument:
                await self.start_analysis(chat_id, uid, argument)
            else:
                await self.ask_url(chat_id, uid)
        elif command == "/list":
            await self.show_list(chat_id)
        elif command == "/status":
            await self.show_status(chat_id)
        elif command == "/check":
            await self.check_all(chat_id)
        elif command == "/export":
            await self.export(chat_id)
        elif command == "/search":
            if argument:
                await self.run_search(chat_id, argument)
            else:
                await self.ask_search(chat_id, uid)
        elif command == "/cancel":
            session.draft = None
            await self.show_menu(chat_id, note="لغو شد.")
        else:
            await self.show_help(chat_id)

    async def _on_callback(self, query: dict) -> None:
        user = query.get("from") or {}
        uid = str(user.get("id", ""))
        message = query.get("message") or {}
        chat = message.get("chat") or {}
        chat_id, mid = str(chat.get("id") or uid), message.get("message_id")
        data = query.get("data") or ""
        ctx = _Callback(self.tg, query.get("id", ""))
        if not await self.is_admin(uid):
            await ctx.ack("⛔ دسترسی ندارید", alert=True)
            return
        if chat.get("type", "private") != "private":
            # buttons under reports in the channel/group: the panel answers privately, never in public
            chat_id, mid = uid, None
            data = data if data.startswith("+") else "+" + data
        self.m.store.touch_admin(uid, user.get("first_name") or user.get("username") or "")
        async with self._lock(uid):
            try:
                await self._handle_callback(ctx, chat_id, mid, uid, data)
            except NotifyError as exc:
                log.warning("Telegram panel: button %r could not be answered: %s", data, exc)
                await ctx.ack("ابتدا ربات را در چت خصوصی باز کنید و /start را بزنید.", alert=True)
            except Exception:
                log.exception("Telegram panel: button %r failed", data)
                await ctx.ack("❌ خطای داخلی؛ جزئیات در لاگ سرور", alert=True)
        await ctx.ack()

    async def _handle_callback(self, ctx: _Callback, chat_id: str, mid: int | None, uid: str, data: str) -> None:
        session = self._session(uid)
        session.awaiting = ""
        if data.startswith("+"):  # a button under a report: answer in a new message, keep the report
            data, mid = data[1:], None
        action, *args = data.split(":")
        key = int(args[0]) if args and args[0].isdigit() else None
        if action == "m":
            await self.show_menu(chat_id, edit=mid)
        elif action == "hp":
            await self.show_help(chat_id, edit=mid)
        elif action == "l":
            await self.show_list(chat_id, page=key or 0, edit=mid)
        elif action == "c":
            await self.show_card(chat_id, key, edit=mid)
        elif action == "t":
            await self.toggle_pause(ctx, chat_id, key, mid)
        elif action == "k":
            await ctx.ack("⏳ در حال بررسی…")
            await self.check_now(chat_id, key)
        elif action == "v":
            await ctx.ack("⏳ در حال دریافت صفحه…")
            await self.preview(chat_id, key)
        elif action == "ss":
            await ctx.ack("📸 در حال گرفتن عکس صفحه…")
            await self.screenshot(chat_id, key)
        elif action == "enm":
            await self.cycle_notify_mode(chat_id, key, edit=mid)
        elif action == "esr":
            await self.cycle_screenshot_region(chat_id, key, edit=mid)
        elif action == "esa":
            await self.cycle_screenshot_audience(chat_id, key, edit=mid)
        elif action == "esd":
            await self.toggle_screenshot_daily(chat_id, key, edit=mid)
        elif action == "ers":
            await self.cycle_report_style(chat_id, key, edit=mid)
        elif action == "esn":
            await self.cycle_sensitivity(chat_id, key, edit=mid)
        elif action == "rs":
            await self.reset_site(ctx, chat_id, key, edit=mid)
        elif action == "cku":
            await self.ask_cookies(chat_id, uid, key)
        elif action == "sh":
            await self.ask_search(chat_id, uid)
        elif action == "h":
            await self.show_history(chat_id, key, edit=mid)
        elif action == "r":
            await ctx.ack()
            await self.send_event_report(chat_id, key)
        elif action == "fd":
            await ctx.ack("📋 در حال ساخت فایل کامل…")
            await self.send_full_report(chat_id, key)
        elif action == "e":
            await self.show_edit(chat_id, key, edit=mid)
        elif action == "ep":
            await self.show_interval_picker(chat_id, f"ei:{key}", f"e:{key}", f"ef:{key}:interval", edit=mid)
        elif action == "ei":
            await self.set_watch_field(chat_id, key, "interval", int(args[1]), edit=mid)
        elif action == "ef":
            await self.ask_watch_field(chat_id, uid, key, args[1])
        elif action == "eb":
            await self.toggle_flag(ctx, chat_id, key, args[1], edit=mid)
        elif action == "ee":
            await self.cycle_engine(chat_id, key, edit=mid)
        elif action == "er":
            await ctx.ack("⏳ در حال بررسی صفحه…")
            await self.reanalyse(chat_id, uid, key)
        elif action == "d":
            await self.confirm_delete(chat_id, key, edit=mid)
        elif action == "dy":
            await self.delete(chat_id, key, edit=mid)
        elif action == "s":
            await ctx.ack()
            await self.show_status(chat_id)
        elif action == "ca":
            await self.check_all(chat_id)
        elif action == "x":
            await ctx.ack()
            await self.export(chat_id)
        elif action == "st":
            await self.show_settings(chat_id, edit=mid)
        elif action in ("sts", "std", "sfp", "ststyle", "stshot", "stquiet"):
            await self.toggle_setting(chat_id, action, edit=mid)
        elif action == "sfx":
            session.ask("fallback")
            await self.tg.send_text(chat_id, PROMPTS["fallback"], reply_markup=kb([("❌ انصراف", "st")]))
        elif action == "a":
            await self.ask_url(chat_id, uid)
        elif action == "im":
            await self.confirm_import(chat_id, uid, args[0] == "y", edit=mid)
        elif action == "dg":
            await ctx.ack("⏳ در حال امتحان همهٔ روش‌ها…")
            await self.diagnose(chat_id, key)
        elif action == "eip":
            await ctx.ack("🌐 در حال گرفتن IP خروجی…")
            await self.show_exit_ip(chat_id, key)
        elif action == "ck":
            token = args[0] if args else ""
            sub_op = args[1] if len(args) > 1 else "rf"
            await self.handle_challenge_action(ctx, chat_id, token, sub_op, edit=mid)
        elif action == "cc":
            token = args[0] if args else ""
            manager = getattr(self.m, "challenge", None)
            ok_cancel = await manager.cancel(token) if (manager and token) else False
            await ctx.ack("✅ لغو شد" if ok_cancel else "⌛ منقضی شده", alert=not ok_cancel)
            if ok_cancel:
                await self._show(chat_id, "❌ <b>چالش لغو شد.</b> پایش در نوبت بعدی دوباره تلاش می‌کند.", None, mid)
        elif action == "se" and len(args) > 1 and args[1] in ENGINE_ORDER:
            await self.set_engine(chat_id, key, args[1], edit=mid)
        elif action == "rp":
            await self.set_route(chat_id, key, "fallback", args[1] if len(args) > 1 else "", edit=mid)
        elif action == "rd":
            await self.set_route(chat_id, key, "direct", "", edit=mid)
        elif action == "hl":
            await self.convert_to_headlines(chat_id, key, edit=mid)
        elif action == "sl":
            await self.make_silent(chat_id, key, edit=mid)
        elif action == "nt":
            record = self._record(key)
            if record is not None:
                self.m.store.set_setting(f"tip:noisy:{record.id}", "off")
            await ctx.ack("👌 باشد؛ برای این سایت دیگر پیشنهاد داده نمی‌شود.")
        elif action == "ak":
            stopped = self.m.ack_alarm(key) if key is not None else False
            await ctx.ack("✅ هشدار قطع شد" if stopped else "هشدار قبلاً تمام شده بود")
            await self._show(chat_id, "✅ <b>هشدار قطع شد.</b> موفق باشید!", None, mid)
        elif action == "an":
            await self._analysis_action(ctx, chat_id, mid, uid, args[0] if args else "")
        elif action in ("as", "ar", "ap", "ai", "ab", "af", "ac", "ay", "aq", "aw", "ax", "al"):
            await self._draft_action(ctx, chat_id, mid, uid, action, args)

    # ================================================================= output helpers

    async def _show(self, chat_id: str, text: str, markup: dict | None = None, edit: int | None = None) -> int | None:
        """Edit the panel message in place when possible, otherwise send a new one."""
        if edit:
            try:
                await self.tg.edit_text(chat_id, edit, text, markup if markup is not None else {"inline_keyboard": []})
                return edit
            except TelegramApiError as exc:
                if "not modified" in exc.description:
                    return edit
                log.debug("editing the panel message failed (%s); sending a new one", exc.description)
        message = await self.tg.send_text(chat_id, text, reply_markup=markup)
        return (message or {}).get("message_id")

    async def _send_long(self, chat_id: str, header: str, blocks: list[str], markup: dict | None = None) -> None:
        parts = [content for kind, content in build_parts(report.info_event(header, blocks)) if kind == "text"]
        for index, text in enumerate(parts):
            await self.tg.send_text(chat_id, text, reply_markup=markup if index == len(parts) - 1 else None)

    def _icon(self, w) -> str:
        if w is None:
            return "❌"
        if not w.enabled:
            return "⏸"
        state = self.m.store.watch_state(w.id)
        if state.get("consecutive_errors"):
            return "⚠️"
        return "✅" if state.get("last_ok") else "⏳"

    def _record(self, key: int | None):
        return self.m.registry.get(key=key) if key is not None else None

    async def _save(self, chat_id: str, key: int, spec: dict):
        """Validate + store a changed definition and restart its monitoring."""
        try:
            record = self.m.registry.update(key, spec)
        except ConfigError as exc:
            await self.tg.send_text(chat_id, f"❌ ذخیره نشد: {esc(str(exc))}")
            return None
        await self.m.apply_watch(record.watch)
        return record

    def _routed(self, w) -> bool:
        return self.m._may_reroute(w) and self.m.route_of(w) == "fallback"

    async def _fallback_text(self) -> str:
        setting = self.m.store.get_setting("fallback_proxy", "auto")
        if setting == "off":
            return "خاموش"
        proxy = await self.m.fallback_proxy()
        if setting != "auto":
            return f"دلخواه ✅ (<code>{esc(proxy.server if proxy else setting)}</code>)"
        return "✅ WARP فعال (خودکار)" if proxy else "خودکار — WARP روی سرور پیدا نشد"

    # ================================================================= welcome, dashboard, list, card

    async def _ensure_keyboard(self, chat_id: str, uid: str) -> None:
        if self.m.store.get_setting(f"kb:{uid}", "") != KEYBOARD_VERSION:
            await self.tg.send_text(chat_id, "⌨️ منوی ثابت پایین صفحه فعال شد.", reply_markup=MAIN_KEYBOARD)
            self.m.store.set_setting(f"kb:{uid}", KEYBOARD_VERSION)

    async def welcome(self, chat_id: str, uid: str) -> None:
        await self.tg.send_text(
            chat_id, "👋 <b>به ربات مانیتور خوش آمدید!</b>\n\n"
                     "این ربات سایت‌های موردنظر شما را شبانه‌روز زیر نظر دارد و هر تغییری را فوراً گزارش می‌دهد — "
                     "از اطلاعیه‌های سفارت و ظرفیت آزمون‌ها تا تازه‌ترین خبرها.\n\n"
                     "⌨️ دکمه‌های پایین صفحه همیشه در دسترس‌اند.\n"
                     "➕ برای افزودن سایت، کافی است لینکش را بفرستید.",
            reply_markup=MAIN_KEYBOARD)
        self.m.store.set_setting(f"kb:{uid}", KEYBOARD_VERSION)
        await self.show_menu(chat_id)

    def _miniapp_row(self, chat_id: str, site_key: int | None = None) -> list[tuple[str, str]]:
        import os
        from .miniapp import make_admin_token, miniapp_secret
        base = (os.environ.get("WEBMONITOR_MINIAPP_URL") or getattr(self.m.config, "miniapp_url", "")
                or self.m.store.get_setting("miniapp_url", "https://deutschelager.duckdns.org")).strip().rstrip("/")
        if not base or base == "off":
            return []
        if str(chat_id).startswith("-"):
            return []  # an admin link must never be posted into a group or channel
        url = f"{base}/app" + (f"?site={site_key}" if site_key is not None else "")
        label = "🚀 پروفایل گرافیکی این سایت (مینی‌اپ)" if site_key is not None else "🚀 باز کردن مینی‌اپ (داشبورد گرافیکی)"
        if url.startswith("https://"):
            return [(label, f"webapp:{url}")]  # Telegram signs the launch data itself (initData): no token needed
        if url.startswith("http://"):
            # outside a Web App button there is no initData: carry a signed token bound to this admin, in the
            # URL fragment (it is never sent to the server, so it stays out of access logs and Referer headers)
            token = make_admin_token(miniapp_secret(self.m.store), str(chat_id))
            return [(label, f"{url}#t={token}")]
        return []

    async def show_menu(self, chat_id: str, edit: int | None = None, note: str = "") -> None:
        records = self.m.registry.records()
        store, now = self.m.store, time.time()
        health = Counter()
        for r in records:
            if r.watch is None:
                health["broken"] += 1
            elif not r.watch.enabled:
                health["paused"] += 1
            elif store.watch_state(r.id).get("consecutive_errors"):
                health["failing"] += 1
            else:
                health["ok"] += 1
        changes = sum(counts[kind] for counts in store.event_counts_since(now - 86400).values() for kind in DIGESTABLE)
        status = [f"✅ {fa_digits(health['ok'])} سالم"]
        if health["failing"] or health["broken"]:
            status.append(f"⚠️ {fa_digits(health['failing'] + health['broken'])} خطا")
        if health["paused"]:
            status.append(f"⏸ {fa_digits(health['paused'])} متوقف")
        lines = [note, ""] if note else []
        lines += ["🛰 <b>پنل مدیریت مانیتور</b>", RULE,
                  f"👁 <b>{fa_digits(len(records))}</b> سایت زیر نظر — " + " · ".join(status),
                  f"🔔 تغییرات و خبرهای ۲۴ ساعت اخیر: <b>{fa_digits(changes)}</b>",
                  f"🛡 پروکسی پشتیبان: {await self._fallback_text()}",
                  f"⏱ روشن از {human_duration(now - self.m.started_at)} پیش"]
        pending = store.pending_count()
        if pending:
            lines.append(f"📮 {fa_digits(pending)} پیام در صف ارسال")
        lines += [RULE, "➕ برای افزودن سایت، کافی است لینکش را همین‌جا بفرستید."]
        markup = kb(self._miniapp_row(chat_id),
                    [("➕ افزودن سایت", "a"), (f"📋 سایت‌ها ({fa_digits(len(records))})", "l:0")],
                    [("📊 وضعیت کامل", "s"), ("🔄 بررسی همه", "ca")],
                    [("🔍 جستجو در تغییرات", "sh"), ("⚙️ تنظیمات", "st")],
                    [("❓ راهنما", "hp")])
        await self._show(chat_id, "\n".join(lines), markup, edit)

    async def show_help(self, chat_id: str, edit: int | None = None) -> None:
        await self._show(chat_id, HELP, kb([("➕ افزودن سایت", "a"), ("🏠 داشبورد", "m")]), edit)

    def _list_detail(self, record) -> str:
        w = record.watch
        if w is None:
            return "❌ تعریف نامعتبر"
        kind = self.m.kind_label(w)
        if not w.enabled:
            return f"{kind} · ⏸ متوقف"
        state = self.m.store.watch_state(w.id)
        if state.get("consecutive_errors"):
            return (f"{kind} · ❌ {esc(truncate(state.get('last_error') or '', 40))} "
                    f"({fa_digits(state['consecutive_errors'])} بار)")
        last = self.m.store.last_event(w.id, DIGESTABLE)
        latest = f"آخرین تغییر {human_duration(time.time() - last['created'])} پیش" if last else "هنوز تغییری نبوده"
        return f"{kind} · هر {human_duration(w.interval_seconds)} · 🔔 {latest}"

    async def show_list(self, chat_id: str, page: int = 0, edit: int | None = None, note: str = "") -> None:
        records = self.m.registry.records()
        pages = max(1, math.ceil(len(records) / PAGE_SIZE))
        page = min(max(page, 0), pages - 1)
        lines = [note, ""] if note else []
        title = f"📋 <b>سایت‌های تحت نظر</b> ({fa_digits(len(records))})"
        if pages > 1:
            title += f" — صفحهٔ {fa_digits(page + 1)} از {fa_digits(pages)}"
        lines += [title, RULE]
        rows = []
        entries = []
        for index, record in enumerate(records[page * PAGE_SIZE:(page + 1) * PAGE_SIZE], page * PAGE_SIZE + 1):
            icon = self._icon(record.watch)
            entries.append(f"{number_icon(index)} {icon} <b>{esc(truncate(record.label, 50))}</b>\n"
                           f"      {self._list_detail(record)}")
            rows.append([(f"{number_icon(index)} {icon} {truncate(record.label, 36)}", f"c:{record.key}")])
        if entries:
            lines += ["\n\n".join(entries), RULE, "روی هر سایت بزنید تا جزئیات و مدیریت آن باز شود."]
        else:
            lines.append("هنوز سایتی اضافه نشده؛ لینک یک صفحه را بفرستید تا شروع کنیم.")
        nav = []
        if page > 0:
            nav.append(("◀️ قبلی", f"l:{page - 1}"))
        if page < pages - 1:
            nav.append(("بعدی ▶️", f"l:{page + 1}"))
        rows += [nav, [("➕ افزودن سایت", "a"), ("🏠 داشبورد", "m")]]
        await self._show(chat_id, "\n".join(lines), kb(*rows), edit)

    def _public_list(self) -> str:
        records = self.m.registry.records()
        lines = [f"📋 <b>سایت‌های تحت نظر</b> ({fa_digits(len(records))})", RULE]
        for index, record in enumerate(records[:40], 1):
            w = record.watch
            detail = self.m.kind_label(w) + f" · هر {human_duration(w.interval_seconds)}" if w else "❌ نامعتبر"
            lines.append(f"{number_icon(index)} {self._icon(w)} <b>{esc(truncate(record.label, 50))}</b>\n      {detail}")
        if not records:
            lines.append("هنوز سایتی اضافه نشده است.")
        return "\n".join(lines)

    def _what(self, w) -> str:
        if w.type == "page":
            what = f"بخش <code>{esc(truncate(w.selector, 60))}</code>" if w.selector else "کل صفحه"
            return f"📄 صفحه — {what}" + (" + خزش همهٔ صفحات این بخش" if w.crawl else "")
        if w.type == "headlines":
            where = f" (در بخش <code>{esc(truncate(w.selector, 40))}</code>)" if w.selector else ""
            return f"📰 تیترهای جدید{where} — فقط خبرهای تازه"
        if w.type == "items":
            if "t.me/s/" in w.url:
                return "📢 پست‌های جدید کانال تلگرام"
            return f"📌 موارد تازهٔ فهرست <code>{esc(truncate(w.item_selector, 50))}</code>"
        if w.type == "json":
            if w.json_template == GOETHE["template"]:
                where = "، ".join(esc(v) for v in w.json_filter.values())
                return "🎓 آزمون‌های گوته — ظرفیت و زمان ثبت‌نام" + (f" · 📍 فقط {where}" if where else "")
            return "🧩 داده (API)"
        return "📡 خبرخوان RSS — خبرهای تازه"

    def _card_text(self, record) -> str:
        w = record.watch
        if w is None:
            return (f"❌ <b>{esc(record.label)}</b>\nتعریف این سایت نامعتبر است:\n"
                    f"<code>{esc(truncate(record.error, 300))}</code>")
        store, now = self.m.store, time.time()
        state = store.watch_state(w.id)
        lines = [f"{self._icon(w)} <b>{esc(record.label)}</b>",
                 f'🔗 <a href="{esc_attr(w.page_url)}">{esc(truncate(w.page_url, 90))}</a>',
                 RULE, "<b>📌 چه چیزی پایش می‌شود</b>", self._what(w)]
        if w.type == "page" and w.track_links:
            lines.append("🔗 لینک‌های تازه/حذف‌شده هم گزارش می‌شود")
        lines += ["", "<b>⚙️ تنظیمات</b>"]
        engine = ENGINE_NAMES.get(w.engine, w.engine)
        if w.engine == "auto":
            engine += f" ← {ENGINE_LABELS.get(self.m.engine_for(w), '')}"
        lines.append(f"⏱ هر {human_duration(w.interval_seconds)} · ⚙️ {engine}")
        cached = self.m._cached_exit_ip(w)
        if cached:
            try:
                ip, route, ts = cached.split("|", 2)
                when = fa_elapsed(time.time() - int(ts)) + " پیش"
                route_label = {"direct": "مستقیم", "warp": "WARP", "custom-proxy": "پروکسی"}.get(route, route)
                lines.append(f"🌐 IP فعلی: <code>{esc(ip)}</code> ({route_label}، {when})")
            except Exception:
                pass
        try:
            eff = self.m._effective_timeout(w)
            if eff > w.timeout_seconds:
                lines.append(f"🐢 timeout خودکار: {fa_digits(int(eff))}s (سایت کند است)")
        except Exception:
            pass
        if w.proxy:
            lines.append(f"🌐 پروکسی اختصاصی: <code>{esc(w.proxy.server)}</code>")
        elif self._routed(w):
            lines.append("🛡 از طریق پروکسی پشتیبان (سایت IP سرور را مسدود کرده بود)")
        if getattr(w, "report_style", "inline") == "before_after":
            lines.append("📝 نمایش تغییرات: قبل/بعد (کامل)")
        if not getattr(w, "ignore_reorder", True):
            lines.append("🔍 حساسیت: حداکثر (حتی جابه‌جایی خطوط)")
        if (self.m.config.data_dir / "sessions" / f"{w.id}.json").exists():
            lines.append("🍪 نشست/کوکی ذخیره‌شده: دارد")
        keywords = "، ".join(w.keywords) if w.keywords else "—"
        lines.append(f"🔑 کلمات کلیدی: {esc(truncate(keywords, 200))}"
                     + (" · فقط همین‌ها ارسال می‌شود" if w.only_keywords else ""))
        if w.alarm:
            lines.append("⏰ بیدارباش: روشن — " + ("فقط تغییرات دارای کلمهٔ کلیدی" if w.keywords else "برای هر تغییر"))
        if w.silent:
            lines.append("🔕 اعلان‌ها بی‌صدا")
        nm = getattr(w, "notify_mode", "text")
        if nm != "text":
            nm_label = {"screenshot": "📸 فقط عکس", "both": "📸 متن + عکس"}.get(nm, nm)
            sr = getattr(w, "screenshot_region", "watch")
            sr_label = {"watch": "بخش زیر نظر", "page": "کل صفحه"}.get(sr, sr)
            sa = getattr(w, "screenshot_audience", "channel")
            sa_label = {"channel": "کانال/گروه", "admins": "خصوصی مدیران", "both": "هر دو"}.get(sa, sa)
            daily = " · 🗓 روزانه" if getattr(w, "screenshot_daily", False) else ""
            lines.append(f"{nm_label} · ناحیه: {sr_label} · مخاطب: {sa_label}{daily}")
        lines += ["", "<b>📈 وضعیت</b>"]
        if not w.enabled:
            lines.append("⏸ پایش متوقف است")
        elif state.get("consecutive_errors"):
            lines.append(f"⚠️ {fa_digits(state['consecutive_errors'])} خطای پیاپی: "
                         f"<code>{esc(truncate(state.get('last_error') or '', 200))}</code>")
        elif state.get("last_ok"):
            lines.append(f"✅ آخرین بررسی موفق: {human_duration(now - state['last_ok'])} پیش")
        else:
            lines.append("⏳ هنوز بررسی نشده")
        last = store.last_event(w.id, DIGESTABLE)
        if last is not None:
            lines.append(f"🔔 آخرین تغییر: {human_duration(now - last['created'])} پیش — "
                         f"{esc(truncate(last['summary'] or '', 60))}")
        day = store.count_events(w.id, DIGESTABLE, now - 86400)
        if day:
            lines.append(f"📊 رویدادهای ۲۴ ساعت اخیر: {fa_digits(day)}")
        origin = "از فایل تنظیمات" if record.origin == "config" else "افزوده‌شده با ربات"
        lines += ["", f"🆔 <code>{esc(w.id)}</code> · {origin}"]
        return "\n".join(lines)

    async def show_card(self, chat_id: str, key: int | None, edit: int | None = None, note: str = "") -> None:
        record = self._record(key)
        if record is None:
            await self.show_list(chat_id, edit=edit, note="این سایت دیگر وجود ندارد.")
            return
        text = (f"{note}\n\n" if note else "") + self._card_text(record)
        rows = []
        if record.watch is not None:
            rows.append(self._miniapp_row(chat_id, key))
            rows += [[("🔄 بررسی الان", f"k:{key}"), ("👁 پیش‌نمایش", f"v:{key}")],
                     [("📸 عکس صفحه", f"ss:{key}"), ("🧪 تست دسترسی", f"dg:{key}")],
                     [("🍪 ارسال کوکی", f"cku:{key}"), ("🌐 تست IP خروجی", f"eip:{key}")],
                     [("📜 تاریخچه", f"h:{key}"), ("✏️ ویرایش", f"e:{key}")],
                     [("🧹 ریست حافظه", f"rs:{key}"),
                      ("▶️ ادامهٔ پایش" if not record.watch.enabled else "⏸ توقف", f"t:{key}")],
                     [("🗑 حذف", f"d:{key}")]]
        else:
            rows.append([("🗑 حذف", f"d:{key}")])
        rows.append([("⬅️ فهرست", "l:0"), ("🏠 داشبورد", "m")])
        await self._show(chat_id, text, kb(*rows), edit)

    # ================================================================= site actions

    async def toggle_pause(self, ctx: _Callback, chat_id: str, key: int | None, mid: int | None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            await self.show_list(chat_id, edit=mid)
            return
        saved = await self._save(chat_id, key, dict(record.spec, enabled=not record.watch.enabled))
        if saved is not None:
            await ctx.ack("▶️ پایش ادامه دارد" if saved.watch.enabled else "⏸ پایش متوقف شد")
            await self.show_card(chat_id, key, edit=mid)

    async def check_now(self, chat_id: str, key: int | None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        message = await self.tg.send_text(chat_id, f"⏳ در حال بررسی «{esc(record.label)}»…")
        started = time.monotonic()
        result = await self.m.check_watch(record.watch)
        text = (f"🔄 <b>نتیجهٔ بررسی «{esc(record.label)}»</b>\n🕒 {fa_datetime(time.time(), self.m.tz)} · "
                f"{fa_elapsed(time.monotonic() - started)}\n\n{describe_result(result)}")
        await self._show(chat_id, text, kbn([("📄 کارت سایت", f"c:{key}"), ("👁 پیش‌نمایش", f"v:{key}")]),
                         edit=message.get("message_id"))

    async def preview(self, chat_id: str, key: int | None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        message = await self.tg.send_text(chat_id, "⏳ در حال دریافت صفحه…")
        try:
            summary, lines = await self.m.preview_watch(record.watch, limit=60)
        except (FetchError, ExtractError) as exc:
            text = f"⚠️ <b>پیش‌نمایش ناموفق بود:</b>\n<code>{esc(truncate(str(exc), 300))}</code>"
        else:
            shown, size = [], 0
            for line in lines:
                line = esc(truncate(line, 160))
                if size + len(line) > 3000:
                    shown.append("…")
                    break
                shown.append(line)
                size += len(line) + 1
            text = (f"👁 <b>آنچه در «{esc(record.label)}» زیر نظر است</b>\n{summary}\n{RULE}\n"
                    + (report.quote(shown) if shown else "(متنی پیدا نشد)"))
        await self._show(chat_id, text, kbn([("📄 کارت سایت", f"c:{key}"), ("📸 عکس صفحه", f"ss:{key}")]),
                         edit=message.get("message_id"))

    async def screenshot(self, chat_id: str, key: int | None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        w = record.watch
        message = await self.tg.send_text(chat_id, f"📸 در حال گرفتن عکس «{esc(record.label)}»… (تا یک دقیقه)")
        mid = message.get("message_id")
        try:
            image = await self.m.screenshot(w)
        except FetchError as exc:
            await self._show(chat_id, f"⚠️ <b>عکس گرفته نشد:</b>\n<code>{esc(truncate(str(exc), 300))}</code>",
                             kbn([("📄 کارت سایت", f"c:{key}")]), edit=mid)
            return
        caption = (f"📸 <b>{esc(truncate(record.label, 80))}</b>\n🕒 {fa_datetime(time.time(), self.m.tz)}\n"
                   "همان‌طور که سرور این صفحه را می‌بیند" + (" (از طریق پروکسی)" if self._routed(w) else "")
                   + (" — فقط بخش زیر نظر" if w.selector and w.type in ("page", "headlines") else ""))
        try:
            await self.tg.send_photo(chat_id, f"{w.id}.jpg", image, caption,
                                     reply_markup=kbn([("📄 کارت سایت", f"c:{key}"), ("🔗 صفحه", w.page_url)]))
        except NotifyError as exc:
            await self._show(chat_id, f"⚠️ ارسال عکس ناموفق بود: {esc(str(exc))}", None, edit=mid)
            return
        try:
            await self.tg.call("deleteMessage", {"chat_id": chat_id, "message_id": mid})
        except NotifyError:
            pass

    async def show_history(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None:
            await self.show_list(chat_id, edit=edit)
            return
        rows = self.m.store.recent_events(record.id, 12)
        lines = [f"📜 <b>تاریخچهٔ «{esc(record.label)}»</b>", RULE]
        if not rows:
            lines.append("هنوز رویدادی ثبت نشده است.")
        buttons = []
        full_buttons = []
        for row in rows:
            mark = STATUS_MARKS.get(row["status"], "")
            lines.append(f"• {format_short(row['created'], self.m.tz)} — {KIND_NAMES.get(row['kind'], row['kind'])}: "
                         f"{esc(truncate(row['summary'] or '', 60))} {mark} <i>#{fa_digits(row['id'])}</i>")
            if row["kind"] in DIGESTABLE and len(buttons) < 6:
                buttons.append((f"📄 #{fa_digits(row['id'])}", f"+r:{row['id']}"))
            if row["kind"] in DIGESTABLE and len(full_buttons) < 3:
                full_buttons.append((f"📋 #{fa_digits(row['id'])}", f"+fd:{row['id']}"))
        if buttons:
            lines += ["", "برای دیدن گزارش کامل هر رویداد، دکمه‌اش را بزنید."]
        if full_buttons:
            lines.append("📋 دکمه‌های پایین = diff کامل (فایل HTML).")
        if any(row["status"] == "filtered" for row in rows):
            lines.append("🔇 = به خاطر نداشتن کلمهٔ کلیدی ارسال نشد")
        markup_rows = [buttons[i:i + 3] for i in range(0, len(buttons), 3)]
        if full_buttons:
            markup_rows += [full_buttons[i:i + 3] for i in range(0, len(full_buttons), 3)]
        markup_rows.append([("⬅️ بازگشت به کارت", f"c:{key}")])
        await self._show(chat_id, "\n".join(lines), kb(*markup_rows), edit)

    async def send_event_report(self, chat_id: str, event_id: int | None) -> None:
        row = self.m.store.get_event(event_id) if event_id is not None else None
        if row is None:
            await self.tg.send_text(chat_id, "این گزارش پیدا نشد (ممکن است قدیمی و پاک شده باشد).")
            return
        payload = json.loads(row["payload"])
        parts = build_parts(payload)
        markup = {"inline_keyboard": payload["buttons"]} if payload.get("buttons") else None
        last_text = max((index for index, (kind, _) in enumerate(parts) if kind == "text"), default=-1)
        for index, part in enumerate(parts):
            await self.tg.send_part(chat_id, part, reply_markup=markup if index == last_text else None)

    async def send_full_report(self, chat_id: str, event_id: int | None) -> None:
        """Send the complete HTML report of one event (Sprint 4.3)."""
        row = self.m.store.get_event(event_id) if event_id is not None else None
        if row is None:
            await self.tg.send_text(chat_id, "این رویداد پیدا نشد (ممکن است قدیمی و پاک شده باشد).")
            return
        try:
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            await self.tg.send_text(chat_id, "❌ payload این رویداد قابل خواندن نیست.")
            return
        blocks = payload.get("full_blocks") or payload.get("blocks") or []
        if not blocks:
            await self.tg.send_text(chat_id, "این رویداد هیچ محتوای قابل نمایشی ندارد.")
            return
        doc_title = payload.get("doc_title") or f"گزارش رویداد #{event_id}"
        from .report import render_document
        html_doc = render_document(doc_title, payload.get("header") or "", blocks)
        filename = f"event-{event_id}-{time.strftime('%Y%m%d-%H%M')}.html"
        try:
            await self.tg.send_document(
                chat_id, filename, html_doc.encode("utf-8"),
                f"📋 گزارش کامل رویداد #{fa_digits(event_id)}\n\n{esc(truncate(row['summary'] or '', 200))}",
                content_type="text/html")
        except Exception as exc:
            await self.tg.send_text(chat_id, f"❌ ارسال فایل ناموفق: {esc(str(exc))[:200]}")

    async def show_edit(self, chat_id: str, key: int | None, edit: int | None = None, note: str = "") -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            await self.show_card(chat_id, key, edit=edit)
            return
        w = record.watch
        text = ((f"{note}\n\n" if note else "") + f"✏️ <b>ویرایش «{esc(record.label)}»</b>\n{RULE}\n"
                "روی هر گزینه بزنید تا تغییر کند؛ وضعیت فعلی روی خود دکمه نوشته شده است.")
        keywords = f" ({fa_digits(len(w.keywords))})" if w.keywords else ""
        rows = [[("📝 نام", f"ef:{key}:name"), (f"⏱ فاصله: {human_duration(w.interval_seconds)}", f"ep:{key}")],
                [(f"🔑 کلمات کلیدی{keywords}", f"ef:{key}:keywords"), ("🎯 حالت پایش", f"er:{key}")],
                [(f"⏰ بیدارباش: {onoff(w.alarm)}", f"eb:{key}:alarm"), (f"🔕 بی‌صدا: {onoff(w.silent)}", f"eb:{key}:silent")],
                [(f"🎯 فقط کلیدی: {onoff(w.only_keywords)}", f"eb:{key}:onlykw")]]
        if w.type == "page":
            rows[-1].append((f"🔗 لینک‌ها: {onoff(w.track_links)}", f"eb:{key}:links"))
            rows.append([(f"🕸 خزش کل بخش: {onoff(bool(w.crawl))}", f"eb:{key}:crawl")])
        # Sprint 2.2: screenshot / notify settings
        nm = getattr(w, "notify_mode", "text")
        nm_label = {"text": "فقط متن", "screenshot": "فقط عکس", "both": "متن + عکس"}.get(nm, nm)
        rows.append([(f"📨 اعلان: {nm_label}", f"enm:{key}")])
        if nm in ("screenshot", "both"):
            sr = getattr(w, "screenshot_region", "watch")
            sr_label = {"watch": "بخش زیر نظر", "page": "کل صفحه"}.get(sr, sr)
            sa = getattr(w, "screenshot_audience", "channel")
            sa_label = {"channel": "کانال/گروه", "admins": "مدیران", "both": "هر دو"}.get(sa, sa)
            sd = onoff(getattr(w, "screenshot_daily", False))
            rows.append([(f"📐 ناحیه: {sr_label}", f"esr:{key}")])
            rows.append([(f"👥 مخاطب: {sa_label}", f"esa:{key}")])
            rows.append([(f"🗓 روزانه: {sd}", f"esd:{key}")])
        rs = getattr(w, "report_style", "inline")
        rs_label = {"inline": "درون‌خطی", "before_after": "قبل/بعد (کامل)"}.get(rs, rs)
        sens_label = "عادی (نادیده گرفتن جابه‌جایی)" if getattr(w, "ignore_reorder", True) else "حداکثر (تک‌تک خطوط)"
        rows.append([(f"📝 نمایش: {rs_label}", f"ers:{key}"), (f"🔍 حساسیت: {sens_label}", f"esn:{key}")])
        rows.append([(f"🌐 پروکسی: {'دارد' if w.proxy else 'ندارد'}", f"ef:{key}:proxy"),
                     (f"⚙️ روش: {ENGINE_NAMES.get(w.engine, w.engine).split(' (')[0]}", f"ee:{key}")])
        rows.append([("🍪 ارسال/حذف کوکی ورود", f"cku:{key}"), ("🧹 ریست حافظهٔ سایت", f"rs:{key}")])
        if self._routed(w):
            rows.append([("🔌 برگشت از پروکسی پشتیبان به مسیر مستقیم", f"rd:{key}")])
        rows.append([("🔗 تغییر آدرس", f"ef:{key}:url")])
        rows.append([("⬅️ بازگشت به کارت", f"c:{key}")])
        await self._show(chat_id, text, kb(*rows), edit)

    async def show_interval_picker(self, chat_id: str, prefix: str, back: str, custom: str,
                                   edit: int | None = None) -> None:
        buttons = [(human_duration(seconds), f"{prefix}:{seconds}") for seconds in INTERVALS]
        rows = [buttons[i:i + 3] for i in range(0, len(buttons), 3)]
        text = ("⏱ <b>هر چند وقت یک‌بار بررسی شود؟</b>\n" + RULE + "\n"
                "فاصلهٔ کمتر یعنی خبر سریع‌تر.\n"
                "• صفحات نوبت‌دهی و ظرفیت: ۱ تا ۳ دقیقه\n"
                "• سایت‌های محافظت‌شده یا کم‌تغییر: ۱۵ دقیقه تا چند ساعت\n"
                "• در صورت زدن «عدد دلخواه» می‌توانید مثلاً <code>3 ساعت</code> یا <code>45 دقیقه</code> هم بنویسید.")
        await self._show(chat_id, text, kb(*rows, [("✍️ زمان دلخواه (ساعت / دقیقه / ثانیه)", custom)],
                                           [("⬅️ بازگشت", back)]), edit)

    async def ask_watch_field(self, chat_id: str, uid: str, key: int | None, field_name: str) -> None:
        if self._record(key) is None or field_name not in PROMPTS:
            return
        self._session(uid).ask(f"watch:{key}:{field_name}")
        await self.tg.send_text(chat_id, PROMPTS[field_name], reply_markup=kb([("❌ انصراف", f"e:{key}")]))

    async def set_watch_field(self, chat_id: str, key: int | None, field_name: str, value,
                              edit: int | None = None) -> None:
        record = self._record(key)
        if record is None:
            return
        spec = dict(record.spec)
        if field_name == "name":
            spec["name"] = value
        elif field_name == "keywords":
            spec["keywords"] = value
            if not value:
                spec.pop("only_keywords", None)
        elif field_name == "interval":
            spec["interval_seconds"] = int(value)
            if isinstance(spec.get("crawl"), dict):
                spec["crawl"] = dict(spec["crawl"], interval_seconds=max(900, int(value)))
        elif field_name == "proxy":
            if value:
                spec["proxy"] = value
            else:
                spec.pop("proxy", None)
        saved = await self._save(chat_id, key, spec)
        if saved is not None:
            await self.show_edit(chat_id, key, edit=edit, note="✅ ذخیره شد.")

    async def toggle_flag(self, ctx: _Callback, chat_id: str, key: int | None, flag: str,
                          edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        w, spec = record.watch, dict(record.spec)
        if flag == "crawl":
            if spec.get("crawl"):
                spec.pop("crawl")
            else:
                spec["crawl"] = default_crawl(spec["url"])
        elif flag == "links":
            spec["track_links"] = not w.track_links
        elif flag == "silent":
            spec["silent"] = not w.silent
        elif flag == "alarm":
            spec["alarm"] = not w.alarm
        elif flag == "onlykw":
            if not w.keywords and not w.only_keywords:
                await ctx.ack("اول «کلمات کلیدی» را تعیین کنید.", alert=True)
                return
            spec["only_keywords"] = not w.only_keywords
        if await self._save(chat_id, key, spec) is not None:
            if flag == "crawl" and spec.get("crawl"):
                await ctx.ack("🕸 خزش روشن شد؛ اولین خزش (بدون پیام) تا یک دقیقهٔ دیگر انجام می‌شود.", alert=True)
            if flag == "alarm" and spec.get("alarm"):
                await ctx.ack("⏰ بیدارباش روشن شد: با هر تغییر مهم، هشدار خصوصی تا ۶ بار تکرار می‌شود تا «دیدم» "
                              "را بزنید." + (" فقط تغییرات دارای کلمهٔ کلیدی." if w.keywords else ""), alert=True)
            await self.show_edit(chat_id, key, edit=edit)

    async def cycle_engine(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        engine = ENGINE_ORDER[(ENGINE_ORDER.index(record.watch.engine) + 1) % len(ENGINE_ORDER)]
        if await self._save(chat_id, key, dict(record.spec, engine=engine)) is not None:
            self.m.store.update_watch(record.id, engine=None)  # forget what "auto" picked before
            await self.show_edit(chat_id, key, edit=edit, note=f"⚙️ روش دریافت: {ENGINE_NAMES[engine]}")

    async def diagnose(self, chat_id: str, key: int | None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        w = record.watch
        message = await self.tg.send_text(chat_id, f"🧪 در حال امتحان همهٔ روش‌ها برای «{esc(record.label)}»…\n"
                                                   "(تا یک دقیقه)")
        results = await self.m.diagnose(w.url, base=w)
        direct_name = "🌐 <b>با پروکسی اختصاصی این سایت</b>" if w.proxy else "🔌 <b>مستقیم (IP سرور)</b>"
        lines = [f"🧪 <b>تست دسترسی «{esc(record.label)}»</b>", "همهٔ روش‌ها از روی همین سرور امتحان شد:", RULE]
        working: dict[str, list[str]] = {"direct": [], "fallback": []}
        for route in ("direct", "fallback"):
            rows = [row for row in results if row[0] == route]
            if not rows:
                continue
            lines.append(direct_name if route == "direct" else "🛡 <b>از طریق پروکسی پشتیبان</b>")
            for _, engine, ok, detail in rows:
                lines.append(f"{'✅' if ok else '❌'} {ENGINE_NAMES[engine]}: {esc(detail)}")
                if ok:
                    working[route].append(engine)
            lines.append("")
        buttons = []
        if working["direct"]:
            best = working["direct"][0]
            lines.append(f"👉 <b>نتیجه:</b> دسترسی برقرار است. روش پیشنهادی: <b>{ENGINE_NAMES[best]}</b> "
                         "(سریع‌ترین روشی که جواب داد).")
            buttons += [[(f"⚙️ استفاده از {ENGINE_NAMES[engine].split(' (')[0]}", f"se:{key}:{engine}")]
                        for engine in working["direct"][:2]]
            if self._routed(w):
                buttons.append([("🔌 برگشت به مسیر مستقیم", f"rd:{key}")])
        elif working["fallback"]:
            best = working["fallback"][0]
            lines.append("👉 <b>نتیجه:</b> سایت IP سرور را مسدود کرده ولی از طریق پروکسی پشتیبان باز می‌شود. "
                         "دکمهٔ زیر پایش را به این مسیر می‌برد (ربات بعد از اولین خطای مسدودی هم خودکار همین کار را "
                         "می‌کند).")
            buttons.append([(f"🛡 پایش از طریق پروکسی ({ENGINE_NAMES[best].split(' (')[0]})", f"rp:{key}:{best}")])
        else:
            blocked = any(_error_kind(detail) == "blocked" for *_, detail in results)
            if blocked:
                tried = any(row[0] == "fallback" for row in results)
                lines.append("👉 <b>نتیجه:</b> سایت این سرور" + (" و پروکسی پشتیبان" if tried else "")
                             + " را موقتاً مسدود کرده است. این معمولاً بعد از چند ساعت تا یک روز رفع می‌شود؛ سیستم "
                               "با فاصلهٔ امن به تلاش ادامه می‌دهد و بعد از رفع مشکل خبر می‌دهد."
                             + ("" if tried else " پیشنهاد: Cloudflare WARP را روی سرور فعال کنید (README).")
                             + " اگر طولانی شد، یک پروکسی خانگی/موبایل در ⚙️ تنظیمات ← پروکسی پشتیبان بگذارید.")
            else:
                lines.append("👉 <b>نتیجه:</b> هیچ روشی جواب نداد؛ ممکن است سایت از دسترس خارج باشد. "
                             "سیستم به تلاش ادامه می‌دهد.")
        buttons.append([("📄 کارت سایت", f"c:{key}")])
        await self._show(chat_id, "\n".join(lines), kbn(*buttons), edit=message.get("message_id"))

    async def set_engine(self, chat_id: str, key: int | None, engine: str, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        if await self._save(chat_id, key, dict(record.spec, engine=engine)) is not None:
            self.m.store.update_watch(record.id, engine=None if engine == "auto" else engine)
            await self.show_card(chat_id, key, edit=edit, note=f"✅ روش دریافت: {ENGINE_NAMES[engine]}")

    async def set_route(self, chat_id: str, key: int | None, route: str, engine: str,
                        edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        fields = {"route": "fallback" if route == "fallback" else None}
        if engine in ENGINE_ORDER and record.watch.engine == "auto":
            fields["engine"] = engine
        self.m.store.update_watch(record.id, **fields)
        self.m.trigger(record.id)
        note = ("✅ از این به بعد از طریق پروکسی پشتیبان بررسی می‌شود؛ اولین بررسی همین الان انجام می‌شود."
                if route == "fallback" else "✅ از این به بعد مستقیم (بدون پروکسی) بررسی می‌شود.")
        await self.show_card(chat_id, key, edit=edit, note=note)

    async def convert_to_headlines(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        spec = {k: v for k, v in record.spec.items() if k not in ("track_links", "crawl", "min_content_length")}
        spec["type"] = "headlines"
        if await self._save(chat_id, key, spec) is not None:
            await self.show_card(chat_id, key, edit=edit,
                                 note="✅ حالت «📰 تیترهای جدید» فعال شد: از این به بعد فقط خبرهای تازه (تیتر + لینک) "
                                      "گزارش می‌شود. اولین بررسی فقط فهرست فعلی را به خاطر می‌سپارد.")

    async def make_silent(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            return
        if await self._save(chat_id, key, dict(record.spec, silent=True)) is not None:
            await self.show_card(chat_id, key, edit=edit, note="🔕 اعلان‌های این سایت بی‌صدا شد.")

    async def cycle_notify_mode(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """📨 Cycle between text → screenshot → both."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        modes = ("text", "screenshot", "both")
        current = getattr(record.watch, "notify_mode", "text")
        next_mode = modes[(modes.index(current) + 1) % len(modes)] if current in modes else "text"
        if await self._save(chat_id, key, dict(record.spec, notify_mode=next_mode)) is not None:
            label = {"text": "فقط متن", "screenshot": "فقط عکس", "both": "متن + عکس"}[next_mode]
            await self.show_edit(chat_id, key, edit=edit, note=f"📨 حالت اعلان: {label}")

    async def cycle_screenshot_region(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """📐 Cycle between watch region and whole page."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        regions = ("watch", "page")
        current = getattr(record.watch, "screenshot_region", "watch")
        next_region = regions[(regions.index(current) + 1) % len(regions)] if current in regions else "watch"
        if await self._save(chat_id, key, dict(record.spec, screenshot_region=next_region)) is not None:
            label = {"watch": "فقط بخش زیر نظر", "page": "کل صفحه"}[next_region]
            await self.show_edit(chat_id, key, edit=edit, note=f"📐 ناحیهٔ عکس: {label}")

    async def cycle_screenshot_audience(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """👥 Cycle between channel, admins and both."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        audiences = ("channel", "admins", "both")
        current = getattr(record.watch, "screenshot_audience", "channel")
        next_aud = audiences[(audiences.index(current) + 1) % len(audiences)] if current in audiences else "channel"
        if await self._save(chat_id, key, dict(record.spec, screenshot_audience=next_aud)) is not None:
            label = {"channel": "کانال/گروه", "admins": "خصوصی برای مدیران", "both": "هر دو"}[next_aud]
            await self.show_edit(chat_id, key, edit=edit, note=f"👥 مخاطب عکس: {label}")

    async def toggle_screenshot_daily(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """🗓 Toggle whether a combined screenshot goes into the daily report."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        current = bool(getattr(record.watch, "screenshot_daily", False))
        if await self._save(chat_id, key, dict(record.spec, screenshot_daily=not current)) is not None:
            await self.show_edit(chat_id, key, edit=edit,
                                 note=f"🗓 عکس در گزارش روزانه: {onoff(not current)}")

    async def show_exit_ip(self, chat_id: str, key: int | None) -> None:
        """Fetch and display the public IP the watch presents to the site (Sprint 3.4.4)."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        w = record.watch
        message = await self.tg.send_text(chat_id, f"🌐 در حال گرفتن IP خروجی «{esc(record.label)}»…")
        mid = message.get("message_id")
        try:
            ip, route = await self.m.exit_ip(w)
        except Exception as exc:
            await self._show(chat_id, f"⚠️ گرفتن IP ناموفق: {esc(str(exc))[:300]}",
                             kbn([("📄 کارت سایت", f"c:{key}")]), edit=mid)
            return
        self.m._cache_exit_ip(w, ip, route)
        route_label = {"direct": "🔌 مستقیم (IP سرور)", "warp": "🛡 WARP (Cloudflare)",
                       "custom-proxy": "🌐 پروکسی اختصاصی"}.get(route, route)
        text = (f"🌐 <b>IP خروجی «{esc(record.label)}»</b>\n"
                f"<code>{esc(ip)}</code>\n"
                f"مسیر: {route_label}\n"
                f"این همان IPای است که سایت می‌بیند.")
        await self._show(chat_id, text, kbn([("📄 کارت سایت", f"c:{key}")]), edit=mid)

    async def cycle_report_style(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """📝 Cycle between inline word-diff and before/after view."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        styles = ("inline", "before_after")
        current = getattr(record.watch, "report_style", "inline")
        next_style = styles[(styles.index(current) + 1) % len(styles)] if current in styles else "inline"
        if await self._save(chat_id, key, dict(record.spec, report_style=next_style)) is not None:
            label = {"inline": "درون‌خطی (فشرده)", "before_after": "قبل/بعد (کامل)"}[next_style]
            await self.show_edit(chat_id, key, edit=edit, note=f"📝 نمایش تغییرات: {label}")

    async def cycle_sensitivity(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """🔍 Toggle ignore_reorder between True (standard) and False (maximum line-by-line sensitivity)."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        current = bool(getattr(record.watch, "ignore_reorder", True))
        next_val = not current
        if await self._save(chat_id, key, dict(record.spec, ignore_reorder=next_val)) is not None:
            label = "عادی (نادیده گرفتن جابه‌جایی)" if next_val else "حداکثر (تک‌تک خطوط و جابه‌جایی‌ها)"
            await self.show_edit(chat_id, key, edit=edit, note=f"🔍 حساسیت تشخیص تغییر: {label}")

    async def reset_site(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        """🧹 Reset baseline snapshot and cached sessions for a site, then trigger a fresh check."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        w = record.watch
        self.m.store.clear_watch_state(w.id)
        for sub in ("sessions", "sessions-impersonate"):
            try:
                (self.m.config.data_dir / sub / f"{w.id}.json").unlink(missing_ok=True)
            except OSError:
                pass
        self.m.trigger(w.id)
        await self.show_card(chat_id, key, edit=edit,
                             note="🧹 حافظه و نشست این سایت پاک شد؛ بررسی مجدد و ثبت نسخهٔ مرجع جدید شروع شد.")

    async def ask_cookies(self, chat_id: str, uid: str, key: int | None) -> None:
        """🍪 Ask admin to paste cookies or JSON storage state for this watch."""
        record = self._record(key)
        if record is None or record.watch is None:
            return
        self._session(uid).ask(f"cookies:{key}")
        await self.tg.send_text(chat_id, PROMPTS["cookies"], reply_markup=kb([("❌ انصراف", f"c:{key}")]))

    async def ask_search(self, chat_id: str, uid: str) -> None:
        """🔍 Ask admin for a search query across all recorded change events."""
        self._session(uid).ask("search")
        await self.tg.send_text(chat_id, PROMPTS["search"], reply_markup=kb([("❌ انصراف", "m")]))

    async def run_search(self, chat_id: str, query: str) -> None:
        """🔍 Search across recent events for matching text in summary or payload."""
        q = query.strip()
        if not q:
            await self.show_menu(chat_id, note="⚠️ عبارت جستجو خالی بود.")
            return
        q_low = q.lower()
        rows = self.m.store.conn.execute(
            "SELECT id, watch_id, kind, created, summary, payload, status FROM events "
            "WHERE kind IN ('changed', 'items', 'crawl') ORDER BY id DESC LIMIT 250"
        ).fetchall()
        matches = []
        labels = {r.id: r.label for r in self.m.registry.records()}
        for row in rows:
            summary = row["summary"] or ""
            payload_text = row["payload"] or ""
            if q_low in summary.lower() or q_low in payload_text.lower():
                matches.append(row)
                if len(matches) >= 12:
                    break
        lines = [f"🔍 <b>نتایج جستجو برای «{esc(truncate(q, 50))}»</b>", RULE]
        buttons = []
        if not matches:
            lines.append("موردی در تاریخچهٔ تغییرات پیدا نشد.")
        else:
            for row in matches:
                w_label = labels.get(row["watch_id"], row["watch_id"])
                lines.append(
                    f"• <b>{esc(truncate(w_label, 35))}</b> ({format_short(row['created'], self.m.tz)})\n"
                    f"  {esc(truncate(row['summary'] or '', 75))} <i>#{fa_digits(row['id'])}</i>"
                )
                if len(buttons) < 6:
                    buttons.append((f"📄 #{fa_digits(row['id'])}", f"+r:{row['id']}"))
        markup_rows = [buttons[i:i + 3] for i in range(0, len(buttons), 3)]
        markup_rows.append([("🔍 جستجوی جدید", "sh"), ("🏠 داشبورد", "m")])
        await self._show(chat_id, "\n".join(lines), kb(*markup_rows))

    async def handle_challenge_action(self, ctx: _Callback, chat_id: str, rest: str) -> None:
        """Handle 1-tap interactive challenge actions in Telegram (+ck:<token>:<op>)."""
        token, _, op = rest.partition(":")
        mgr = getattr(self.m, "challenge", None) or getattr(self.m, "challenges", None)
        session = mgr.get(token) if mgr is not None else None
        if session is None:
            await ctx.ack("⌛ این چالش دیگر فعال نیست یا قبلاً بسته شده است.", alert=True)
            return
        if op == "cf":
            await ctx.ack("🖱 در حال کلیک خودکار روی چک‌باکس کلودفلر…")
            fn = getattr(session, "click_turnstile_fn", None)
            clicked = False
            if callable(fn):
                try:
                    clicked = await fn()
                except Exception:
                    clicked = False
            sfn = getattr(session, "frame_fn", None) or getattr(session, "screenshot_fn", None)
            if callable(sfn):
                try:
                    img = await sfn()
                    if img:
                        status_txt = "✅ کلیک انجام شد؛ وضعیت فعلی صفحه:" if clicked else "📸 وضعیت فعلی صفحه:"
                        await self.tg.send_photo(
                            chat_id, "challenge-after-click.jpg", img,
                            f"{status_txt}\nاگر صفحه باز شده است دکمهٔ «✅ حل شد (ذخیره کوکی)» را بزنید."
                        )
                        return
                except Exception:
                    pass
            await self.tg.send_text(
                chat_id,
                "✅ کلیک خودکار امتحان شد. اگر صفحه باز شده است دکمهٔ «✅ حل شد» را بزنید."
            )
        elif op == "rf":
            await ctx.ack("📸 در حال گرفتن عکس لحظه‌ای…")
            sfn = getattr(session, "frame_fn", None) or getattr(session, "screenshot_fn", None)
            if callable(sfn):
                try:
                    img = await sfn()
                    if img:
                        await self.tg.send_photo(chat_id, "challenge-live.jpg", img, "📸 تصویر لحظه‌ای صفحهٔ چالش")
                        return
                except Exception:
                    pass
            await self.tg.send_text(chat_id, "⚠️ امکان گرفتن عکس لحظه‌ای در حال حاضر وجود ندارد.")
        elif op == "ok":
            await mgr.complete(token)
            await ctx.ack("✅ تایید شد؛ در حال ذخیرهٔ کوکی‌ها…", alert=True)
            await self.tg.send_text(chat_id, "✅ حل چالش تایید شد و کوکی‌های نشست برای مراجعات بعدی ذخیره می‌شود.")

    async def confirm_delete(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self._record(key)
        if record is None:
            await self.show_list(chat_id, edit=edit)
            return
        text = (f"🗑 <b>«{esc(record.label)}» حذف شود؟</b>\n"
                "پایش آن متوقف و نسخهٔ مرجعش پاک می‌شود (پیام‌های قبلی در کانال می‌مانند).")
        await self._show(chat_id, text, kb([("✅ بله، حذف شود", f"dy:{key}"), ("❌ خیر", f"c:{key}")]), edit)

    async def delete(self, chat_id: str, key: int | None, edit: int | None = None) -> None:
        record = self.m.registry.delete(key) if key is not None else None
        if record is None:
            await self.show_list(chat_id, edit=edit)
            return
        await self.m.remove_watch(record.id)
        await self._show(chat_id, f"🗑 «{esc(record.label)}» حذف شد.",
                         kb([("📋 سایت‌ها", "l:0"), ("🏠 داشبورد", "m")]), edit)

    # ================================================================= global actions

    async def show_status(self, chat_id: str) -> None:
        header, blocks = self.m.status_report()
        await self._send_long(chat_id, header, blocks, kbn([("🔄 بررسی همه", "ca"), ("📋 سایت‌ها", "l:0")]))

    async def check_all(self, chat_id: str) -> None:
        self.m.trigger_all()
        await self.tg.send_text(chat_id, f"⏳ <b>بررسی فوری {fa_digits(len(self.m.watches))} سایت شروع شد.</b>\n"
                                         "هر تغییری مثل همیشه در کانال/گروه اعلام می‌شود.",
                                reply_markup=kbn([("📊 وضعیت", "s")]))

    async def show_settings(self, chat_id: str, edit: int | None = None) -> None:
        store = self.m.store
        system = store.get_setting("system_messages", "admins")
        daily = store.get_setting("daily_report", "on") == "on"
        hour = self.m.config.daily_report_hour
        daily_text = f"{onoff(daily)} (ساعت {fa_digits(hour)})" if hour is not None else "در فایل تنظیمات خاموش است"
        fallback = store.get_setting("fallback_proxy", "auto")
        def_style = store.get_setting("default_report_style", "inline")
        style_label = "قبل/بعد + کلمه‌به‌کلمه (کامل)" if def_style == "before_after" else "درون‌خطی (فشرده)"
        auto_shot = store.get_setting("auto_screenshot", "off") == "on"
        quiet = store.get_setting("quiet_hours", "off") == "on"
        text = ("⚙️ <b>تنظیمات</b>\n" + RULE + "\n"
                "📨 <b>پیام‌های سیستمی</b> (خطا، رفع خطا، گزارش روزانه، پیشنهادها):\n"
                f"      {'خصوصی برای مدیران' if system == 'admins' else 'در کانال/گروه'}\n"
                f"📝 <b>سبک پیش‌فرض گزارش تغییرات:</b> {style_label}\n"
                f"📸 <b>ارسال خودکار اسکرین‌شات با هر تغییر:</b> {onoff(auto_shot)}\n"
                f"🌙 <b>ساعات سکوت شبانه (۰۰:۰۰ تا ۰۷:۰۰ بدون صدا):</b> {onoff(quiet)}\n"
                f"🗓 <b>گزارش روزانه:</b> {daily_text}\n"
                f"🛡 <b>پروکسی پشتیبان:</b> {await self._fallback_text()}\n"
                "      وقتی سایتی IP سرور را مسدود کند، خودکار از این مسیر بررسی می‌شود.\n"
                f"👤 مدیرانی که از ربات استفاده کرده‌اند: {fa_digits(len(store.admin_ids()))}\n\n"
                "ℹ️ تغییرات سایت‌ها همیشه در کانال/گروه اعلام می‌شوند.")
        mode = {"auto": "خودکار (WARP)", "off": "خاموش"}.get(fallback, "دلخواه")
        rows = [[(f"📨 پیام‌های سیستمی: {'خصوصی' if system == 'admins' else 'کانال'}", "sts")],
                [(f"📝 سبک گزارش: {'قبل/بعد کامل' if def_style == 'before_after' else 'درون‌خطی'}", "ststyle"),
                 (f"📸 عکس خودکار: {onoff(auto_shot)}", "stshot")],
                [(f"🌙 سکوت شبانه: {onoff(quiet)}", "stquiet")]]
        if hour is not None:
            rows[-1].append((f"🗓 گزارش روزانه: {onoff(daily)}", "std"))
        rows.append([(f"🛡 پروکسی پشتیبان: {mode}", "sfp"), ("✍️ پروکسی دلخواه", "sfx")])
        rows.append([("💾 فایل پشتیبان سایت‌ها", "x"), ("🏠 داشبورد", "m")])
        await self._show(chat_id, text, kb(*rows), edit)

    async def toggle_setting(self, chat_id: str, action: str, edit: int | None = None) -> None:
        store = self.m.store
        if action == "sts":
            current = store.get_setting("system_messages", "admins")
            store.set_setting("system_messages", "channels" if current == "admins" else "admins")
        elif action == "std":
            current = store.get_setting("daily_report", "on")
            store.set_setting("daily_report", "off" if current == "on" else "on")
        elif action == "ststyle":
            current = store.get_setting("default_report_style", "inline")
            store.set_setting("default_report_style", "before_after" if current == "inline" else "inline")
        elif action == "stshot":
            current = store.get_setting("auto_screenshot", "off")
            store.set_setting("auto_screenshot", "on" if current == "off" else "off")
        elif action == "stquiet":
            current = store.get_setting("quiet_hours", "off")
            store.set_setting("quiet_hours", "on" if current == "off" else "off")
        else:
            current = store.get_setting("fallback_proxy", "auto")
            store.set_setting("fallback_proxy", "off" if current == "auto" else "auto")
        await self.show_settings(chat_id, edit=edit)

    async def export(self, chat_id: str) -> None:
        specs = [record.spec for record in self.m.registry.records()]
        data = json.dumps({"exported": format_ts(time.time(), self.m.tz), "watches": specs}, ensure_ascii=False,
                          indent=2)
        await self.tg.send_document(
            chat_id, f"watches-{time.strftime('%Y%m%d-%H%M')}.json", data.encode("utf-8"),
            f"💾 پشتیبان {fa_digits(len(specs))} سایت. برای بازگردانی یا انتقال، همین فایل را برای ربات بفرستید.",
            content_type="application/json")

    async def _receive_import(self, chat_id: str, uid: str, document: dict) -> None:
        if not (document.get("file_name") or "").lower().endswith(".json"):
            await self.tg.send_text(chat_id, "فقط فایل پشتیبان با پسوند json پذیرفته می‌شود (از /export).")
            return
        try:
            raw = json.loads((await self.tg.download_file(document["file_id"])).decode("utf-8-sig"))
        except NotifyError as exc:
            await self.tg.send_text(chat_id, f"❌ فایل دریافت نشد: {esc(str(exc))}")
            return
        except (ValueError, UnicodeDecodeError):
            await self.tg.send_text(chat_id, "❌ این فایل json معتبر نیست.")
            return
        specs = raw.get("watches") if isinstance(raw, dict) else raw
        if not isinstance(specs, list):
            await self.tg.send_text(chat_id, "❌ در این فایل فهرست سایتی پیدا نشد.")
            return
        records = self.m.registry.records()
        known_ids = {r.id for r in records}
        known = {(r.spec.get("url"), r.spec.get("selector"), r.spec.get("item_selector")) for r in records}
        new, duplicates, invalid = [], 0, 0
        for spec in specs:
            if not isinstance(spec, dict) or not spec.get("url"):
                invalid += 1
                continue
            if spec.get("id") in known_ids or (spec.get("url"), spec.get("selector"), spec.get("item_selector")) in known:
                duplicates += 1
                continue
            try:
                self.m.registry.validate(dict(spec, id=spec.get("id") or "import-check"))
            except ConfigError:
                invalid += 1
                continue
            new.append(spec)
        self._session(uid).pending_import = new
        text = (f"📥 <b>فایل پشتیبان</b>\n{fa_digits(len(new))} سایت جدید · {fa_digits(duplicates)} تکراری (رد می‌شود)"
                f" · {fa_digits(invalid)} نامعتبر")
        markup = kb([("✅ افزودن", "im:y"), ("❌ انصراف", "im:n")]) if new else kb([("🏠 داشبورد", "m")])
        await self.tg.send_text(chat_id, text, reply_markup=markup)

    async def confirm_import(self, chat_id: str, uid: str, accepted: bool, edit: int | None = None) -> None:
        session = self._session(uid)
        specs, session.pending_import = session.pending_import or [], None
        if not accepted or not specs:
            await self.show_menu(chat_id, edit=edit, note="انصراف داده شد.")
            return
        added, errors = 0, []
        for spec in specs:
            try:
                record = self.m.registry.add(spec, created_by=uid)
            except ConfigError as exc:
                errors.append(str(exc))
                continue
            await self.m.apply_watch(record.watch)
            added += 1
        note = (f"✅ {fa_digits(added)} سایت اضافه شد."
                + (f"\n⚠️ {fa_digits(len(errors))} مورد اضافه نشد: {esc(errors[0])}" if errors else ""))
        await self.show_list(chat_id, edit=edit, note=note)

    # ================================================================= add / re-analyse wizard

    async def ask_url(self, chat_id: str, uid: str) -> None:
        self._session(uid).ask("url")
        await self.tg.send_text(
            chat_id, "🔗 <b>لینک صفحه‌ای را که می‌خواهید زیر نظر بگیرید بفرستید.</b>\n\n"
                     "نمونه‌ها:\n• سفارت: <code>https://teheran.diplo.de/ir-fa</code>\n"
                     "• آزمون گوته: <code>https://www.goethe.de/ins/tr/de/spr/prf/gzb2.cfm</code>\n"
                     "• سایت خبری: <code>https://www.bbc.com/persian</code>\n"
                     "• کانال تلگرام: <code>@نام_کانال</code>",
            reply_markup=kb([("❌ انصراف", "m")]))

    async def reanalyse(self, chat_id: str, uid: str, key: int | None) -> None:
        record = self._record(key)
        if record is not None and record.watch is not None:
            await self.start_analysis(chat_id, uid, record.watch.page_url, edit_key=key)

    def _duplicates(self, url: str, exclude_key: int | None = None) -> list:
        target = normalize_url(url) or url
        result = []
        for record in self.m.registry.records():
            if record.key == exclude_key:
                continue
            urls = {normalize_url(u) or u for u in (record.spec.get("url"), record.spec.get("link")) if u}
            if target in urls:
                result.append(record)
        return result

    async def _analyze(self, url: str, proxy=None) -> Analysis:
        try:
            return await asyncio.wait_for(
                analyze(self.m.config, url, http=self.m.http, browser=self.m.browser, impersonate=self.m.impersonate,
                        proxy=proxy), timeout=150)
        except asyncio.TimeoutError:
            return Analysis(url=url, error="بررسی صفحه بیش از حد طول کشید")

    @staticmethod
    def _usable(analysis: Analysis) -> bool:
        return bool(analysis.final_url) and not analysis.error and not analysis.blocked

    async def start_analysis(self, chat_id: str, uid: str, text: str, edit_key: int | None = None,
                             force: bool = False, note: str = "", edit: int | None = None) -> None:
        session = self._session(uid)
        url = normalize_input_url(text)
        if url is None:
            session.ask(f"watch:{edit_key}:url" if edit_key else "url")
            await self.tg.send_text(chat_id, "❌ این لینک معتبر نیست. یک آدرس کامل بفرستید، مثلاً "
                                             "<code>https://example.com/page</code>", reply_markup=kb([("❌ انصراف", "m")]))
            return
        if not self.allow_private_urls and not await is_public_host(urlsplit(url).hostname or ""):
            await self.tg.send_text(chat_id, "⛔ آدرس‌های شبکهٔ داخلی یا محلی مجاز نیستند.")
            return
        session.pending_url = url
        if edit_key is None and not force:
            duplicates = self._duplicates(url)
            if duplicates:
                await self._show_duplicate(chat_id, duplicates, edit=edit)
                return
        progress = (f"{note}\n\n" if note else "") + (f"⏳ <b>در حال بررسی صفحه…</b>\n🔗 {esc(truncate(url, 90))}\n"
                                                    "معمولاً چند ثانیه؛ اگر مرورگر لازم باشد تا یک دقیقه.")
        mid = await self._show(chat_id, progress, None, edit)
        record = self._record(edit_key) if edit_key is not None else None
        own_proxy = record.watch.proxy if record is not None and record.watch is not None else None
        analysis = await self._analyze(url, own_proxy)
        direct = analysis
        if not self._usable(analysis) and own_proxy is None and self.m.config.global_proxy is None:
            fallback = await self.m.fallback_proxy()
            if fallback is not None:
                reason = "مسدود است" if analysis.blocked or _error_kind(analysis.error) == "blocked" else "ناموفق بود"
                await self._show(chat_id, f"🛡 <b>دسترسی مستقیم {reason}</b>\nتلاش از طریق پروکسی پشتیبان…\n"
                                          f"🔗 {esc(truncate(url, 90))}", None, mid)
                proxied = await self._analyze(url, fallback)
                if self._usable(proxied):
                    analysis = proxied
                else:
                    analysis.notes.append(f"via proxy: {proxied.error or proxied.block_hint or 'blocked'}")
                    analysis.via_proxy = fallback.server
        choices = suggest_choices(analysis) if analysis.final_url and not analysis.error else []
        if not choices or (analysis.blocked and not analysis.regions):
            await self._show_failure(chat_id, url, direct, analysis, edit=mid)
            return
        base = record.spec if record is not None else None
        host = (urlsplit(url).hostname or "").removeprefix("www.")
        route = "fallback" if analysis is not direct else ""
        quick = analysis.is_feed or choices[0]["type"] in ("items", "json", "headlines", "feed")
        default_interval = 180 if analysis.protected or route else (60 if quick and not analysis.newsy else 120)
        session.draft = Draft(
            input_url=url, analysis=analysis, choices=choices,
            name=(base or {}).get("name") or smart_name(analysis.title or host, url),
            interval=int((base or {}).get("interval_seconds") or default_interval),
            keywords=list((base or {}).get("keywords") or []),
            crawl=bool((base or {}).get("crawl")), edit_key=edit_key, base_spec=base,
            json_filter=dict((base or {}).get("json_filter") or {}), alarm=bool((base or {}).get("alarm")),
            route=route)
        await self._show_options(chat_id, session.draft, edit=mid)

    async def _show_duplicate(self, chat_id: str, records: list, edit: int | None = None) -> None:
        lines = ["⚠️ <b>این آدرس قبلاً اضافه شده است</b>", RULE]
        lines += [f"• <b>{esc(r.label)}</b> — {self.m.kind_label(r.watch) if r.watch else '❌'}" for r in records[:3]]
        lines += ["", "اگر می‌خواهید همین صفحه را با حالت دیگری هم زیر نظر بگیرید (مثلاً یکی «تیترهای جدید» و "
                      "یکی «کل صفحه»)، «ادامه» را بزنید؛ وگرنه همان سایت را باز کنید."]
        rows = [[(f"📄 {truncate(r.label, 30)}", f"c:{r.key}")] for r in records[:3]]
        rows += [[("➕ ادامه و افزودن دوباره", "an:f")], [("❌ انصراف", "an:q")]]
        await self._show(chat_id, "\n".join(lines), kb(*rows), edit)

    async def _show_failure(self, chat_id: str, url: str, direct: Analysis, last: Analysis,
                            edit: int | None = None) -> None:
        reason = direct.error or (f"صفحهٔ محافظ {direct.block_hint}" if direct.block_hint else "نامشخص")
        lines = ["❌ <b>این صفحه از روی سرور باز نشد</b>", f"🔗 {esc(truncate(url, 90))}", RULE,
                 f"🔌 مستقیم: <code>{esc(truncate(reason, 200))}</code>"]
        proxy_note = next((note for note in last.notes if note.startswith("via proxy:")), "")
        if proxy_note:
            lines.append(f"🛡 از طریق پروکسی: <code>{esc(truncate(proxy_note[10:].strip(), 200))}</code>")
        kind = "blocked" if direct.blocked else _error_kind(reason)
        if kind == "blocked":
            explain = ("سایت IP سرور را مسدود کرده است. این معمولاً موقت است (چند ساعت تا یک روز)، مخصوصاً اگر قبلاً "
                       "پشت‌سرهم بررسی شده باشد.")
            if proxy_note:
                explain += " پروکسی پشتیبان هم فعلاً مسدود است."
            elif self.m.store.get_setting("fallback_proxy", "auto") != "off":
                explain += " پروکسی WARP روی سرور پیدا نشد (راهنمای نصب در README)."
        elif kind == "timeout":
            explain = "سایت در زمان مجاز جواب نداد؛ ممکن است کند یا موقتاً از دسترس خارج باشد."
        elif kind == "network":
            explain = "اتصال به سایت برقرار نشد؛ آدرس را بررسی کنید یا کمی بعد دوباره امتحان کنید."
        else:
            explain = "محتوای قابل پایشی در این صفحه پیدا نشد."
        lines += ["", f"💡 <b>یعنی چه؟</b> {explain}", "", "<b>چه می‌توانید بکنید؟</b>",
                  "➕ <b>افزودن به‌هرحال</b>: سایت ثبت می‌شود و با فاصلهٔ امن مدام امتحان می‌شود؛ به محض باز شدن "
                  "خبرتان می‌کنیم تا حالت دقیق پایش (مثلاً ظرفیت آزمون‌های گوته) را انتخاب کنید.",
                  "🔁 <b>تلاش دوباره</b>: چند دقیقهٔ دیگر."]
        await self._show(chat_id, "\n".join(lines),
                         kb([("🔁 تلاش دوباره", "an:r"), ("➕ افزودن به‌هرحال", "an:a")], [("❌ انصراف", "an:q")]),
                         edit)

    async def _analysis_action(self, ctx: _Callback, chat_id: str, mid: int | None, uid: str, what: str) -> None:
        session = self._session(uid)
        url = session.pending_url
        if what == "q" or not url:
            session.pending_url = ""
            await self.show_menu(chat_id, edit=mid, note="لغو شد." if what == "q" else
                                 "⌛ این فرم منقضی شده است؛ لینک را دوباره بفرستید.")
        elif what in ("r", "f"):
            await ctx.ack("⏳ در حال بررسی صفحه…")
            await self.start_analysis(chat_id, uid, url, force=True, edit=mid)
        elif what == "a":
            await ctx.ack("⏳ در حال افزودن…")
            await self.add_anyway(chat_id, uid, url, edit=mid)

    async def add_anyway(self, chat_id: str, uid: str, url: str, edit: int | None = None) -> None:
        """Register a site that cannot be opened right now; it is set up precisely once it opens."""
        parts = urlsplit(url)
        host = (parts.hostname or "site").removeprefix("www.")
        last = [segment for segment in parts.path.split("/") if segment]
        spec = {"name": f"{host} — {last[-1]}" if last else host, "url": url, "type": "page",
                "interval_seconds": 300, "track_links": True, "_review": True}
        try:
            record = self.m.registry.add(spec, created_by=uid)
        except ConfigError as exc:
            await self._show(chat_id, f"❌ ذخیره نشد: {esc(str(exc))}", None, edit)
            return
        self._session(uid).pending_url = ""
        fields = {"engine": "impersonate"} if self.m.impersonate.available else {}
        if await self.m.fallback_proxy() is not None:
            fields["route"] = "fallback"
        if fields:
            self.m.store.update_watch(record.id, **fields)
        await self.m.apply_watch(record.watch)
        text = (f"✅ <b>«{esc(record.label)}» ثبت شد</b> — در انتظار باز شدن سایت\n{RULE}\n"
                f"⏱ هر {human_duration(300)} با فاصلهٔ امن امتحان می‌شود (پشت‌سرهم بررسی کردن مسدودی را طولانی‌تر "
                "می‌کند).\n🔔 به محض باز شدن، پیامی با دکمهٔ «🎯 انتخاب حالت دقیق پایش» برایتان می‌فرستیم.\n"
                "✏️ نام را می‌توانید از کارت سایت ← ویرایش عوض کنید.")
        await self._show(chat_id, text, kbn([("📄 کارت سایت", f"c:{record.key}"), ("🏠 داشبورد", "m")]), edit)

    async def _show_options(self, chat_id: str, draft: Draft, edit: int | None = None, note: str = "") -> None:
        a = draft.analysis
        lines = [note, ""] if note else []
        lines += ["🔎 <b>نتیجهٔ بررسی صفحه</b>", RULE]
        if a.title:
            lines.append(f"📄 <b>{esc(truncate(a.title, 100))}</b>")
        lines.append(f"🔗 {esc(truncate(a.final_url or a.url, 90))}")
        lines.append(f"⚙️ دریافت با: {ENGINE_NAMES.get(a.engine, a.engine)} · {fa_elapsed(a.elapsed)}")
        if draft.route:
            lines.append("🛡 دسترسی مستقیم مسدود بود؛ صفحه از طریق پروکسی پشتیبان باز شد و پایش هم از همین مسیر "
                         "انجام می‌شود.")
        if a.block_hint:
            lines.append(f"⚠️ صفحه شبیه صفحهٔ محافظ {esc(a.block_hint)} است؛ ممکن است محتوای اصلی نباشد.")
        if a.protected:
            lines.append("🛡 این سایت محافظ ضدربات دارد (مثل Akamai/Cloudflare): فاصلهٔ بررسی ۲ دقیقه یا بیشتر "
                         "پیشنهاد می‌شود تا IP سرور مسدود نشود.")
        if a.exam_api:
            lines.append("🎓 این صفحهٔ آزمون گوته است: گزینهٔ ⭐ ظرفیت و زمان ثبت‌نام هر آزمون را دقیق زیر نظر می‌گیرد.")
        elif a.newsy:
            lines.append("📰 این صفحه سایت خبری است: «تیترهای جدید» فقط خبرهای تازه را می‌فرستد (بدون پیام‌های "
                         "بیهوده برای تغییر زمان‌ها و جابه‌جایی مطالب).")
        elif a.js_app:
            lines.append("ℹ️ بخشی از این صفحه با جاوااسکریپت ساخته می‌شود؛ اگر محتوای موردنظر در پیش‌نمایش نبود، "
                         "بعد از ذخیره روش دریافت را «مرورگر» بگذارید.")
        duplicates = self._duplicates(draft.input_url, exclude_key=draft.edit_key)
        if duplicates:
            lines.append(f"ℹ️ این آدرس قبلاً با نام «{esc(duplicates[0].label)}» هم اضافه شده است.")
        lines += ["", "<b>کدام حالت پایش؟</b>"]
        rows = []
        for index, choice in enumerate(draft.choices):
            star = "⭐ " if choice.get("recommended") else ""
            lines.append(f"{star}<b>{esc(choice['label'])}</b>")
            if choice.get("desc"):
                lines.append(f"      <i>{esc(choice['desc'])}</i>")
            rows.append([(f"{star}{choice['label']}", f"as:{index}")])
        rows += [[("✍️ selector دلخواه", "af:selector"), ("❌ انصراف", "aq")]]
        await self._show(chat_id, "\n".join(lines), kb(*rows), edit)

    async def _choose(self, chat_id: str, draft: Draft, choice: dict, edit: int | None = None) -> None:
        if choice["type"] == "feed" and "items" not in choice and choice.get("url") != draft.analysis.final_url:
            try:  # an RSS feed advertised by the page: fetch it once to show a preview
                proxy = await self.m.fallback_proxy() if draft.route else None
                probe = Watch(id="_preview", url=choice["url"], proxy=proxy)
                fetcher = self.m.http if self.m.http.supports(probe) else self.m.impersonate
                result = await fetcher.fetch(choice["url"], probe)
                choice = dict(choice, items=parse_feed(result.body or result.text.encode("utf-8"), result.final_url))
            except (FetchError, ExtractError) as exc:
                await self._show_options(chat_id, draft, edit=edit,
                                         note=f"⚠️ این خبرخوان باز نشد: {esc(truncate(str(exc), 150))}")
                return
        new_preset = choice.get("preset") == "goethe" and (draft.choice or {}).get("preset") != "goethe"
        if new_preset and draft.edit_key is None:  # sensible defaults for exam-seat monitoring
            draft.keywords = draft.keywords or list(GOETHE["keywords"])
            draft.alarm = True
            draft.interval = 120 if draft.analysis.protected or draft.route else 60
        if choice["type"] != "json":
            draft.json_filter = {}
        try:
            lines, total = preview_choice(draft.analysis, choice, json_filter=draft.json_filter or None)
        except ExtractError as exc:
            await self._show_options(chat_id, draft, edit=edit,
                                     note=f"⚠️ این بخش در صفحه پیدا نشد: {esc(truncate(str(exc), 150))}")
            return
        if not lines and choice["type"] != "json":
            await self._show_options(chat_id, draft, edit=edit,
                                     note="⚠️ این گزینه متنی برای پایش ندارد؛ گزینهٔ دیگری انتخاب کنید.")
            return
        draft.choice, draft.preview, draft.preview_total = choice, lines, total
        if choice["type"] in ("feed", "json"):
            draft.url = choice.get("url") or draft.input_url
        else:
            draft.url = draft.input_url
        if choice["type"] != "page":
            draft.crawl = False
        await self._show_review(chat_id, draft, edit=edit)

    async def _show_review(self, chat_id: str, draft: Draft, edit: int | None = None) -> None:
        choice = draft.choice
        kind = choice["type"]
        if kind == "page":
            what = f"بخش <code>{esc(truncate(choice['selector'], 60))}</code>" if choice.get("selector") else "کل صفحه"
            mode, size = f"📄 صفحه — {what}", f"{fa_number(draft.preview_total)} حرف"
            outcome = "هر تغییر متن (🟢 جدید · 🔴 حذف · 🟡 ویرایش کلمه‌به‌کلمه) در کانال اعلام می‌شود."
        elif kind == "headlines":
            mode, size = "📰 تیترهای جدید — فقط خبرهای تازه", f"{fa_digits(draft.preview_total)} تیتر"
            outcome = "هر خبر تازه با تیتر و لینک اعلام می‌شود؛ تغییر زمان‌ها و جابه‌جایی مطالب نادیده گرفته می‌شود."
        elif kind == "items":
            mode = "📢 پست‌های جدید کانال" if "tgme" in choice.get("selector", "") else "📌 موارد تازهٔ فهرست"
            size = f"{fa_digits(draft.preview_total)} مورد"
            outcome = "هر مورد تازه با متن و لینک اعلام می‌شود."
        elif kind == "json":
            mode, size = "🎓 ظرفیت و زمان ثبت‌نام هر آزمون", f"{fa_digits(draft.preview_total)} آزمون"
            outcome = ("هر تغییر ظرفیت یا زمان ثبت‌نام اعلام می‌شود؛ باز شدن ظرفیت با 🚨"
                       + (" و هشدار تکراری خصوصی (بیدارباش)." if draft.alarm else "."))
        else:
            mode, size = "📡 خبرخوان RSS — فقط خبرهای تازه", f"{fa_digits(draft.preview_total)} خبر"
            outcome = "هر خبر تازهٔ خبرخوان با تیتر و لینک اعلام می‌شود."
        title = "✏️ <b>ویرایش سایت — مرور نهایی</b>" if draft.edit_key else "🆕 <b>افزودن سایت — مرور نهایی</b>"
        page = choice.get("page") or draft.url
        lines = [title, RULE, f"📝 نام: <b>{esc(draft.name)}</b>", f"🔗 {esc(truncate(page, 90))}",
                 f"📌 حالت: {mode}", f"⏱ بررسی: هر {human_duration(draft.interval)}"]
        if kind == "page":
            lines.append(f"🕸 خزش کل بخش: {onoff(draft.crawl)}"
                         + (" (همهٔ صفحات این بخش + صفحه/فایل جدید)" if draft.crawl else ""))
        if kind == "json" and choice_filter_values(draft.analysis, choice):
            lines.append(f"📍 شهر: {esc('، '.join(draft.json_filter.values())) if draft.json_filter else 'همه'}")
        lines.append(f"🔑 کلمات کلیدی: {esc('، '.join(draft.keywords)) if draft.keywords else '—'}")
        lines.append(f"⏰ بیدارباش: {onoff(draft.alarm)}"
                     + (" (هشدار تکراری خصوصی تا زدن «دیدم»)" if draft.alarm else ""))
        if draft.route:
            lines.append("🛡 مسیر: از طریق پروکسی پشتیبان")
        preview = [esc(truncate(line, 140)) for line in draft.preview[:12]] or ["(فعلاً موردی نیست)"]
        lines += ["", f"👁 <b>پیش‌نمایش ({size}):</b>", report.quote(preview), "", f"ℹ️ {outcome}"]
        rows = [[("📝 نام", "af:name"), (f"⏱ فاصله: {human_duration(draft.interval)}", "ap")],
                [("🔑 کلمات کلیدی", "af:keywords"), (f"⏰ بیدارباش: {onoff(draft.alarm)}", "al")]]
        if kind == "page":
            rows.append([(f"🕸 خزش: {onoff(draft.crawl)}", "ac")])
        if kind == "json" and choice_filter_values(draft.analysis, choice):
            rows.append([("📍 انتخاب شهر", "aw")])
        rows += [[("⬅️ انتخاب حالت دیگر", "ar")], [("✅ ذخیره و شروع", "ay"), ("❌ انصراف", "aq")]]
        await self._show(chat_id, "\n".join(lines), kb(*rows), edit)

    async def _draft_action(self, ctx: _Callback, chat_id: str, mid: int | None, uid: str, action: str,
                            args: list[str]) -> None:
        session = self._session(uid)
        draft = session.draft
        if draft is None:
            await self.show_menu(chat_id, edit=mid, note="⌛ این فرم منقضی شده است؛ لینک را دوباره بفرستید.")
            return
        if action == "as":
            index = int(args[0]) if args and args[0].isdigit() else -1
            if not 0 <= index < len(draft.choices):
                return
            await ctx.ack()
            await self._choose(chat_id, draft, draft.choices[index], edit=mid)
        elif action == "ar":
            await self._show_options(chat_id, draft, edit=mid)
        elif action == "ab" and draft.choice is not None:
            await self._show_review(chat_id, draft, edit=mid)
        elif action == "ap":
            await self.show_interval_picker(chat_id, "ai", "ab", "af:interval", edit=mid)
        elif action == "ai" and draft.choice is not None:
            draft.interval = int(args[0])
            await self._show_review(chat_id, draft, edit=mid)
        elif action == "ac" and draft.choice is not None:
            draft.crawl = not draft.crawl
            await self._show_review(chat_id, draft, edit=mid)
        elif action == "al" and draft.choice is not None:
            draft.alarm = not draft.alarm
            await self._show_review(chat_id, draft, edit=mid)
        elif action == "aw" and draft.choice is not None:
            cities = choice_filter_values(draft.analysis, draft.choice)
            buttons = [(city, f"ax:{index}") for index, city in enumerate(cities[:24])]
            rows = [buttons[i:i + 3] for i in range(0, len(buttons), 3)]
            rows += [[("🌍 همهٔ شهرها", "ax:all")], [("⬅️ بازگشت", "ab")]]
            await self._show(chat_id, "📍 <b>کدام شهر زیر نظر باشد؟</b>\nفقط آزمون‌های همین شهر گزارش می‌شود.",
                             kb(*rows), mid)
        elif action == "ax" and draft.choice is not None:
            cities = choice_filter_values(draft.analysis, draft.choice)
            if args and args[0].isdigit() and int(args[0]) < len(cities):
                draft.json_filter = {GOETHE["filter_field"]: cities[int(args[0])]}
            else:
                draft.json_filter = {}
            await self._choose(chat_id, draft, draft.choice, edit=mid)
        elif action == "af" and args and args[0] in PROMPTS:
            session.ask(f"draft:{args[0]}")
            back = "ar" if args[0] == "selector" or draft.choice is None else "ab"
            await self.tg.send_text(chat_id, PROMPTS[args[0]], reply_markup=kb([("⬅️ بازگشت", back)]))
        elif action == "ay" and draft.choice is not None:
            await ctx.ack("⏳ در حال ذخیره…")
            await self._save_draft(chat_id, uid, draft, edit=mid)
        elif action == "aq":
            session.draft = None
            await self.show_menu(chat_id, edit=mid, note="لغو شد.")

    def _build_spec(self, draft: Draft) -> dict:
        base = dict(draft.base_spec or {})
        choice = draft.choice
        same_type = base.get("type", "page") == choice["type"]
        for name in ("type", "selector", "item_selector", "item_link_selector", "crawl", "min_content_length",
                     "json_records", "json_template", "json_labels", "json_filter", "link", "_review"):
            base.pop(name, None)
        if not same_type or choice.get("exclude"):
            base.pop("exclude_selectors", None)
        spec = {**base, "name": draft.name, "url": draft.url, "interval_seconds": draft.interval,
                "keywords": draft.keywords, "alarm": draft.alarm}
        if not draft.keywords:
            spec.pop("only_keywords", None)
        if choice["type"] == "json":
            spec.update(type="json", link=choice.get("page") or draft.input_url, json_records=GOETHE["records"],
                        json_template=GOETHE["template"], json_labels=GOETHE["labels"])
            if draft.json_filter:
                spec["json_filter"] = dict(draft.json_filter)
            spec.pop("track_links", None)
        elif choice["type"] == "feed":
            spec["type"] = "feed"
            spec.pop("track_links", None)
        elif choice["type"] == "headlines":
            spec["type"] = "headlines"
            if choice.get("selector"):
                spec["selector"] = choice["selector"]
            spec.pop("track_links", None)
        elif choice["type"] == "items":
            spec["type"] = "items"
            spec["item_selector"] = choice["selector"]
            if choice.get("link_selector"):
                spec["item_link_selector"] = choice["link_selector"]
            if choice.get("exclude"):
                spec["exclude_selectors"] = list(choice["exclude"])
            spec.pop("track_links", None)
        else:
            spec["type"] = "page"
            if choice.get("selector"):
                spec["selector"] = choice["selector"]
            spec.setdefault("track_links", True)
            if draft.crawl:
                old = (draft.base_spec or {}).get("crawl")
                same_url = (draft.base_spec or {}).get("url") == draft.url
                spec["crawl"] = old if old and same_url else default_crawl(draft.url)
            if 0 < draft.preview_total < 90:  # small region: don't treat a short text as an error
                spec["min_content_length"] = max(1, draft.preview_total // 3)
        return spec

    async def _save_draft(self, chat_id: str, uid: str, draft: Draft, edit: int | None = None) -> None:
        spec = self._build_spec(draft)
        try:
            if draft.edit_key is not None:
                record = self.m.registry.update(draft.edit_key, spec)
            else:
                record = self.m.registry.add(spec, created_by=uid)
        except ConfigError as exc:
            await self._show(chat_id, f"❌ ذخیره نشد: {esc(str(exc))}", kb([("⬅️ بازگشت", "ab")]), edit)
            return
        self._session(uid).draft = None
        fields = {}
        if record.watch.engine == "auto":  # start with whatever worked during the analysis
            fields["engine"] = draft.analysis.engine if draft.analysis.engine in ("impersonate", "browser") else None
        if draft.route:
            fields["route"] = "fallback"
        if fields:
            self.m.store.update_watch(record.id, **fields)
        await self.m.apply_watch(record.watch)
        await self._show(chat_id, f"✅ «{esc(record.label)}» ذخیره شد.\n⏳ اولین بررسی…", None, edit)
        result = await self.m.check_watch(record.watch)
        verb = "به‌روز شد" if draft.edit_key is not None else "اضافه شد و از همین حالا زیر نظر است"
        lines = [f"✅ <b>«{esc(record.label)}» {verb}.</b>", RULE, describe_result(result),
                 f"⏱ بررسی هر {human_duration(record.watch.interval_seconds)} · {self.m.kind_label(record.watch)}"]
        if self._routed(record.watch):
            lines.append("🛡 از طریق پروکسی پشتیبان")
        if record.watch.alarm:
            lines.append("⏰ بیدارباش روشن است؛ اعلان‌های این ربات را در گوشی بی‌صدا نکنید.")
        lines.append("📢 تغییرات در کانال/گروه اطلاع‌رسانی اعلام می‌شود.")
        await self._show(chat_id, "\n".join(lines),
                         kbn([("📄 کارت سایت", f"c:{record.key}"), ("➕ سایت بعدی", "a")], [("📋 سایت‌ها", "l:0")]),
                         edit)

    # ================================================================= free-text answers

    async def _handle_input(self, chat_id: str, uid: str, session: Session, text: str) -> None:
        awaiting, session.awaiting = session.awaiting, ""
        if awaiting == "url":
            await self.start_analysis(chat_id, uid, text)
            return
        if awaiting == "fallback":
            await self._set_fallback(chat_id, session, text)
            return
        if awaiting == "search":
            await self.run_search(chat_id, text)
            return
        kind, _, rest = awaiting.partition(":")
        if kind == "draft":
            await self._draft_input(chat_id, uid, session, rest, text)
            return
        if kind == "cookies":
            key = int(rest) if rest.isdigit() else None
            await self._set_cookies(chat_id, session, key, text)
            return
        if kind != "watch":
            return
        key_text, _, field_name = rest.partition(":")
        key = int(key_text) if key_text.isdigit() else None
        if field_name == "url":
            await self.start_analysis(chat_id, uid, text, edit_key=key)
            return
        value = self._parse_field(field_name, text)
        if value is None:
            session.ask(awaiting)
            hint = " (نمونه: <code>socks5://127.0.0.1:40000</code>)" if field_name == "proxy" else ""
            await self.tg.send_text(chat_id, f"❌ مقدار معتبر نیست{hint}؛ دوباره بفرستید.",
                                    reply_markup=kb([("❌ انصراف", f"e:{key}")]))
            return
        await self.set_watch_field(chat_id, key, field_name, value)

    async def _set_cookies(self, chat_id: str, session: Session, key: int | None, text: str) -> None:
        record = self._record(key)
        if record is None or record.watch is None:
            await self.show_list(chat_id)
            return
        w = record.watch
        raw = text.strip()
        if raw in ("-", "—", "حذف"):
            for sub in ("sessions", "sessions-impersonate"):
                try:
                    (self.m.config.data_dir / sub / f"{w.id}.json").unlink(missing_ok=True)
                except OSError:
                    pass
            await self.show_card(chat_id, key, note="🧹 کوکی‌ها و نشست ذخیره‌شدهٔ این سایت پاک شد.")
            return
        if self.m.browser is None:
            await self.show_card(chat_id, key, note="⚠️ موتور مرورگر برای ذخیرهٔ کوکی در دسترس نیست.")
            return
        count = self.m.browser.import_cookies(w, raw)
        if count <= 0:
            session.ask(f"cookies:{key}")
            await self.tg.send_text(
                chat_id,
                "❌ کوکی معتبری در متن ارسالی پیدا نشد.\n"
                "می‌توانید خروجی افزونهٔ Cookie-Editor (JSON)، فرمت Netscape یا رشتهٔ <code>name=value; name2=value2</code> "
                "را بفرستید:",
                reply_markup=kb([("❌ انصراف", f"c:{key}")])
            )
            return
        self.m.store.update_watch(w.id, consecutive_errors=0, last_error=None)
        self.m.trigger(w.id)
        await self.show_card(
            chat_id, key,
            note=f"🍪 {fa_digits(count)} کوکی با موفقیت ذخیره شد و بررسی مجدد سایت با نشست جدید شروع شد."
        )

    async def _set_fallback(self, chat_id: str, session: Session, text: str) -> None:
        text = text.strip()
        if text in ("-", "—", "حذف"):
            self.m.store.set_setting("fallback_proxy", "auto")
        else:
            try:
                Proxy.parse_url(text)
            except ConfigError:
                session.ask("fallback")
                await self.tg.send_text(chat_id, "❌ آدرس پروکسی معتبر نیست (نمونه: <code>socks5://127.0.0.1:40000</code>)"
                                                 "؛ دوباره بفرستید.", reply_markup=kb([("❌ انصراف", "st")]))
                return
            self.m.store.set_setting("fallback_proxy", text)
        await self.show_settings(chat_id)

    @staticmethod
    def _parse_field(field_name: str, text: str):
        if field_name == "name":
            return truncate(text.strip(), 80) or None
        if field_name == "keywords":
            return parse_keywords(text)
        if field_name == "interval":
            norm = text.strip().translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")).lower()
            m = re.match(r"^(\d+(?:\.\d+)?)\s*(ساعت|hour|hours|hr|hrs|h|دقیقه|دقيقه|min|mins|minute|minutes|m|ثانیه|ثانيه|sec|secs|second|seconds|s)?$", norm)
            if m:
                val = float(m.group(1))
                unit = (m.group(2) or "s").strip()
                if unit in ("ساعت", "hour", "hours", "hr", "hrs", "h"):
                    sec = int(round(val * 3600))
                elif unit in ("دقیقه", "دقيقه", "min", "mins", "minute", "minutes", "m"):
                    sec = int(round(val * 60))
                else:
                    sec = int(round(val))
                if 15 <= sec <= 86400:
                    return sec
        if field_name == "proxy":
            text = text.strip()
            if text in ("-", "—", "حذف"):
                return ""
            try:
                Proxy.parse_url(text)
            except ConfigError:
                return None
            return text
        return None

    async def _draft_input(self, chat_id: str, uid: str, session: Session, field_name: str, text: str) -> None:
        draft = session.draft
        if draft is None:
            await self.show_menu(chat_id, note="⌛ فرم منقضی شده است؛ لینک را دوباره بفرستید.")
            return
        if field_name == "selector":
            selector = text.strip()
            try:
                check_selector(selector, "selector")
            except ConfigError as exc:
                session.ask("draft:selector")
                await self.tg.send_text(chat_id, f"❌ {esc(str(exc))}\nدوباره بفرستید:",
                                        reply_markup=kb([("⬅️ بازگشت", "ar")]))
                return
            await self._choose(chat_id, draft, {"type": "page", "selector": selector, "label": selector})
            return
        value = self._parse_field(field_name, text)
        if value is None:
            session.ask(f"draft:{field_name}")
            await self.tg.send_text(chat_id, "❌ مقدار معتبر نیست؛ دوباره بفرستید.",
                                    reply_markup=kb([("⬅️ بازگشت", "ab")]))
            return
        if field_name == "name":
            draft.name = value
        elif field_name == "keywords":
            draft.keywords = value
        elif field_name == "interval":
            draft.interval = value
        if draft.choice is not None:
            await self._show_review(chat_id, draft)
        else:
            await self._show_options(chat_id, draft)
