"""Delivering reports: Telegram Bot API, or the console when no bot is configured (dry-run)."""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import re
import time
from pathlib import Path

import aiohttp

from .report import render_document
from .util import first_line, truncate

log = logging.getLogger("webmonitor")

TEXT_LIMIT = 3900       # Telegram allows 4096 chars after entity parsing; keep headroom
MAX_MESSAGES = 4        # per event; the rest goes into the attached full report
CAPTION = "📎 گزارش کامل (فایل HTML — در مرورگر باز کنید)"


class NotifyError(Exception):
    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class TelegramApiError(NotifyError):
    def __init__(self, code: int, description: str):
        super().__init__(f"Telegram API error {code}: {description}")
        self.code = code
        self.description = description


_MARKUP_ERROR = re.compile(r"button|reply.?markup|keyboard", re.I)
_A_RE = re.compile(r'<a href="([^"]*)">(.*?)</a>', re.S)
_S_RE = re.compile(r"<s>(.*?)</s>", re.S)
_INS_RE = re.compile(r"<b><u>(.*?)</u></b>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(text: str) -> str:
    """Plain-text rendering of our Telegram HTML (diff markers stay visible)."""
    def link(match: re.Match) -> str:
        url, label = match.group(1), match.group(2)
        plain = html.unescape(_TAG_RE.sub("", label)).rstrip("…")
        full = html.unescape(url)
        if full in plain:
            return label
        if plain and plain in full:  # label is the shortened URL itself
            return url
        return f"{label} ({url})"
    text = _A_RE.sub(link, text)
    text = _S_RE.sub(r"[-\1-]", text)
    text = _INS_RE.sub(r"{+\1+}", text)
    text = _TAG_RE.sub("", text)
    return html.unescape(text)


def _fit(piece: str, limit: int) -> str:
    """Last-resort guard for a block that is too long to fit in one message."""
    if len(piece) <= limit:
        return piece
    return html.escape(truncate(html_to_text(piece), limit - 100), quote=False)


def build_parts(payload: dict, limit: int = TEXT_LIMIT, max_messages: int = MAX_MESSAGES) -> list[tuple[str, object]]:
    """Split a report payload into Telegram messages (+ an optional full-report document).

    Blocks are never cut in the middle, so the HTML of every message stays valid.
    The result is deterministic, which lets delivery resume after a partial failure.
    """
    cont = payload.get("cont") or ""
    pieces = [_fit(p, limit) for p in [payload["header"], *(payload.get("blocks") or [])] if p]
    messages: list[str] = []
    current = ""
    truncated = False
    for piece in pieces:
        candidate = f"{current}\n\n{piece}" if current else piece
        if len(candidate) <= limit:
            current = candidate
            continue
        messages.append(current)
        if len(messages) >= max_messages:
            truncated = True
            current = ""
            break
        current = f"{cont}\n\n{piece}" if cont and len(cont) + 2 + len(piece) <= limit else piece
    if current:
        messages.append(current)
    has_doc = bool(payload.get("doc_title"))
    if truncated:
        note = ("<i>… بقیهٔ موارد در فایل گزارش کامل (پیوست بعدی)</i>" if has_doc
                else "<i>… بقیهٔ موارد نمایش داده نشد</i>")
        if len(messages[-1]) + len(note) + 2 <= limit:
            messages[-1] += "\n\n" + note
        else:
            messages.append(note)
    parts: list[tuple[str, object]] = [("text", m) for m in messages]
    if has_doc and (truncated or payload.get("attach")):
        document = render_document(payload["doc_title"], payload["header"],
                                   payload.get("full_blocks") or payload.get("blocks") or [])
        name = f"report-{time.strftime('%Y%m%d-%H%M%S')}-{hashlib.sha1(document.encode()).hexdigest()[:6]}.html"
        parts.append(("doc", {"filename": name, "content": document, "caption": CAPTION}))
    return parts


class ConsoleNotifier:
    """Prints messages instead of sending them (no bot configured, or --dry-run)."""

    name = "console"

    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir

    async def start(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def send_text(self, chat_id: str, text: str, silent: bool = False, reply_markup: dict | None = None) -> dict:
        bar = "─" * 60
        buttons = " ".join(f"[{button['text']}]" for row in (reply_markup or {}).get("inline_keyboard", [])
                           for button in row)
        print(f"\n{bar}\n📨 Telegram message{' (silent)' if silent else ''}:\n{html_to_text(text)}"
              + (f"\n{buttons}" if buttons else "") + f"\n{bar}", flush=True)
        return {}

    async def send_photo(self, chat_id: str, filename: str, content: bytes, caption: str,
                         reply_markup: dict | None = None) -> None:
        """Dry-run: write the JPEG to the reports folder and print a note."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        path = self.reports_dir / filename
        try:
            path.write_bytes(content)
        except OSError:
            pass
        bar = "─" * 60
        print(f"\n{bar}\n📸 [dry-run] screenshot: {path} ({len(content)} bytes)\n"
              f"{html_to_text(caption)}\n{bar}", flush=True)

    async def send_part(self, chat_id: str, part: tuple[str, object], silent: bool = False,
                        reply_markup: dict | None = None) -> None:
        kind, content = part
        if kind == "text":
            await self.send_text(chat_id, content, silent, reply_markup)
            return
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        path = self.reports_dir / content["filename"]
        path.write_text(content["content"], encoding="utf-8")
        print(f"📎 full report saved: {path}", flush=True)


class TelegramNotifier:
    name = "telegram"

    def __init__(self, cfg):
        self.cfg = cfg
        self.retry_delay = 1.0  # multiplier for back-off sleeps (tests make it tiny)
        self._session: aiohttp.ClientSession | None = None
        self._http_proxy: str | None = None

    async def start(self) -> None:
        if self._session is not None:
            return
        connector = None
        proxy = self.cfg.proxy
        if proxy and proxy.lower().startswith("socks"):
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError:
                raise NotifyError("telegram.proxy is a SOCKS proxy: install it with  pip install aiohttp-socks") from None
            connector = ProxyConnector.from_url(proxy)
        elif proxy:
            self._http_proxy = proxy
        self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=120))

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    def _scrub(self, text: object) -> str:
        text = str(text)
        return text.replace(self.cfg.token, "<token>") if self.cfg.token else text

    async def call(self, method: str, payload: dict | None = None, *, files: dict | None = None,
                   timeout: float = 30) -> object:
        """Call a Bot API method. Retries network/5xx errors and short 429 waits."""
        await self.start()
        url = f"{self.cfg.api_base}/bot{self.cfg.token}/{method}"
        last_error: NotifyError | None = None
        for attempt in range(3):
            if files:
                data = aiohttp.FormData()
                for key, value in (payload or {}).items():
                    data.add_field(key, value if isinstance(value, str) else json.dumps(value))
                for field, (filename, content, content_type) in files.items():
                    data.add_field(field, content, filename=filename, content_type=content_type)
                kwargs = {"data": data}
            else:
                kwargs = {"json": payload or {}}
            try:
                async with self._session.post(url, proxy=self._http_proxy,
                                              timeout=aiohttp.ClientTimeout(total=timeout), **kwargs) as resp:
                    status = resp.status
                    try:
                        body = await resp.json(content_type=None)
                    except (ValueError, aiohttp.ContentTypeError):
                        body = {"ok": False, "description": (await resp.text())[:300]}
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_error = NotifyError(f"cannot reach Telegram: {self._scrub(first_line(exc) or type(exc).__name__)}")
                await asyncio.sleep(2 * (attempt + 1) * self.retry_delay)
                continue
            if not isinstance(body, dict):
                body = {"ok": False, "description": str(body)[:300]}
            if body.get("ok"):
                return body.get("result")
            code = int(body.get("error_code") or status)
            description = self._scrub(body.get("description") or f"HTTP {status}")
            if code == 429:
                retry_after = float((body.get("parameters") or {}).get("retry_after") or 5)
                if retry_after <= 30 and attempt < 2:
                    await asyncio.sleep((retry_after + 0.5) * self.retry_delay)
                    continue
                raise NotifyError(f"Telegram rate limit, retry after {retry_after:g}s", retry_after=retry_after)
            if code >= 500:
                last_error = NotifyError(f"Telegram server error {code}: {description}")
                await asyncio.sleep(3 * (attempt + 1) * self.retry_delay)
                continue
            raise TelegramApiError(code, description)
        raise last_error or NotifyError("Telegram request failed")

    async def send_text(self, chat_id: str, text: str, silent: bool = False, reply_markup: dict | None = None) -> dict:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                   "link_preview_options": {"is_disabled": True}, "disable_notification": silent}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            return await self.call("sendMessage", payload) or {}
        except TelegramApiError as exc:
            description = exc.description.lower()
            if exc.code == 400 and "reply_markup" in payload and _MARKUP_ERROR.search(description):
                log.warning("Telegram rejected the buttons (%s); sending the message without them", exc.description)
                payload.pop("reply_markup")
                return await self.call("sendMessage", payload) or {}
            if exc.code != 400 or "parse" not in description:
                raise
            log.warning("Telegram rejected the HTML formatting (%s); resending as plain text", exc.description)
            payload.pop("parse_mode")
            payload["text"] = truncate(html_to_text(text), 4000)
            return await self.call("sendMessage", payload) or {}

    async def edit_text(self, chat_id: str, message_id: int, text: str, reply_markup: dict | None = None) -> None:
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML",
                   "link_preview_options": {"is_disabled": True}}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        await self.call("editMessageText", payload)

    async def answer_callback(self, callback_id: str, text: str = "", alert: bool = False) -> None:
        payload: dict = {"callback_query_id": callback_id}
        if text:
            payload.update(text=truncate(text, 190), show_alert=alert)
        try:
            await self.call("answerCallbackQuery", payload, timeout=10)
        except NotifyError:
            pass  # the button spinner simply times out

    async def download_file(self, file_id: str, max_bytes: int = 2_000_000) -> bytes:
        info = await self.call("getFile", {"file_id": file_id}) or {}
        path = info.get("file_path")
        if not path:
            raise NotifyError("Telegram did not return the file")
        if (info.get("file_size") or 0) > max_bytes:
            raise NotifyError("the file is too large")
        url = f"{self.cfg.api_base}/file/bot{self.cfg.token}/{path}"
        try:
            async with self._session.get(url, proxy=self._http_proxy, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status != 200:
                    raise NotifyError(f"file download failed: HTTP {resp.status}")
                data = await resp.content.read(max_bytes + 1)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise NotifyError(f"file download failed: {self._scrub(first_line(exc))}") from None
        if len(data) > max_bytes:
            raise NotifyError("the file is too large")
        return data

    async def send_document(self, chat_id: str, filename: str, content: bytes, caption: str,
                            silent: bool = False, content_type: str = "text/html") -> None:
        payload = {"chat_id": str(chat_id), "caption": caption, "parse_mode": "HTML",
                   "disable_notification": silent}
        await self.call("sendDocument", payload, files={"document": (filename, content, content_type)}, timeout=120)

    async def send_photo(self, chat_id: str, filename: str, content: bytes, caption: str,
                         reply_markup: dict | None = None) -> None:
        """A screenshot; pages too tall for a photo are sent as an image file instead."""
        payload = {"chat_id": str(chat_id), "caption": caption, "parse_mode": "HTML"}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            await self.call("sendPhoto", payload, files={"photo": (filename, content, "image/jpeg")}, timeout=120)
        except TelegramApiError as exc:
            if exc.code != 400:
                raise
            log.info("Telegram refused the photo (%s); sending it as a file", exc.description)
            await self.call("sendDocument", payload, files={"document": (filename, content, "image/jpeg")},
                            timeout=120)

    async def send_part(self, chat_id: str, part: tuple[str, object], silent: bool = False,
                        reply_markup: dict | None = None) -> None:
        kind, content = part
        if kind == "text":
            await self.send_text(chat_id, content, silent, reply_markup)
        else:
            await self.send_document(chat_id, content["filename"], content["content"].encode("utf-8"),
                                     content["caption"], silent)

    async def get_updates(self, offset: int | None, timeout: int = 50) -> list:
        payload = {"timeout": timeout, "allowed_updates": ["message", "callback_query", "channel_post"]}
        if offset is not None:
            payload["offset"] = offset
        return await self.call("getUpdates", payload, timeout=timeout + 20) or []


def explain_telegram_error(exc: Exception) -> str:
    """Actionable advice for common Telegram misconfigurations."""
    if isinstance(exc, TelegramApiError):
        description = exc.description.lower()
        if exc.code == 401:
            return "The bot token is wrong (copy it again from @BotFather)."
        if "chat not found" in description:
            return "chat_id is wrong, or you have not pressed Start in the bot yet (run: monitor_system.py chat-id)."
        if exc.code == 403:
            return "The bot is blocked or is not a member/admin of that group/channel."
    return ""
