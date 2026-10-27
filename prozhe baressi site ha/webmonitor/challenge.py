"""Challenge server (Sprint 3.2) — solves bot walls by hand through a private tunnel.

Design
------
* Binds to 127.0.0.1 by default: nothing is exposed to the internet.
* The admin opens an SSH tunnel:
    ssh -L 8899:127.0.0.1:8899 user@server
  then loads the URL the bot sent (e.g. http://127.0.0.1:8899/c/<token>).
* Every challenge gets a random single-use token, valid for a few minutes.

This module is *infrastructure only*: it exposes a small HTTP API and an
in-memory session registry. It does not drive Playwright itself; that is wired
in Sprint 3.3 (engine.py) so the two pieces can be tested independently.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from aiohttp import web

log = logging.getLogger("webmonitor")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8899
DEFAULT_TTL_SECONDS = 10 * 60      # 10 minutes
FRAME_INTERVAL = 1.2               # seconds between MJPEG frames
MAX_FRAME_BYTES = 4 * 1024 * 1024  # guard against runaway pages

# Injection hooks — Sprint 3.3 fills these in with Playwright calls.
ClickFn = Callable[[float, float], Awaitable[None]]
TypeFn = Callable[[str], Awaitable[None]]
KeyFn = Callable[[str], Awaitable[None]]
FrameFn = Callable[[], Awaitable[bytes]]
DoneFn = Callable[[], Awaitable[None]]      # save storage_state / close context
CancelFn = Callable[[], Awaitable[None]]    # close without saving


@dataclass
class ChallengeSession:
    """One in-flight challenge awaiting a human."""
    token: str
    watch_id: str
    watch_label: str
    url: str
    created_at: float = field(default_factory=time.time)
    ttl: float = DEFAULT_TTL_SECONDS
    last_frame: bytes = b""
    last_frame_at: float = 0.0
    solving_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # These are filled by the owner (Sprint 3.3).
    frame_fn: FrameFn | None = None
    click_fn: ClickFn | None = None
    type_fn: TypeFn | None = None
    key_fn: KeyFn | None = None
    done_fn: DoneFn | None = None
    cancel_fn: CancelFn | None = None

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at


class ChallengeManager:
    """Owns the HTTP server and the token → session map."""

    def __init__(self, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.host = host
        self.port = port
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, ChallengeSession] = {}
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._purge_task: asyncio.Task | None = None
        self._public_base: str | None = None  # set by engine when known
        self._pending_watchers: dict[str, asyncio.Future] = {}
        self._route_installers: list[Callable[[web.Application], None]] = []

    def add_routes(self, installer: Callable[[web.Application], None]) -> None:
        self._route_installers.append(installer)

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        if self._runner is not None:
            return
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/c/{token}", self._handle_page)
        app.router.add_get("/c/{token}/frame.mjpg", self._handle_frame)
        app.router.add_post("/c/{token}/click", self._handle_click)
        app.router.add_post("/c/{token}/type", self._handle_type)
        app.router.add_post("/c/{token}/key", self._handle_key)
        app.router.add_post("/c/{token}/done", self._handle_done)
        app.router.add_post("/c/{token}/cancel", self._handle_cancel)
        for installer in self._route_installers:
            installer(app)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        try:
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
        except OSError as exc:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            raise RuntimeError(f"challenge server could not bind to {self.host}:{self.port}: {exc}") from exc
        self._purge_task = asyncio.create_task(self._purge_loop())
        log.info("Challenge server listening on http://%s:%d (admin tunnel)", self.host, self.port)

    async def close(self) -> None:
        if self._purge_task is not None:
            self._purge_task.cancel()
            try:
                await self._purge_task
            except (asyncio.CancelledError, Exception):
                pass
            self._purge_task = None
        # Cancel any live sessions cleanly.
        for token in list(self._sessions):
            await self.cancel(token, notify=False)
        if self._runner is not None:
            await self._runner.cleanup()
        self._runner = None
        self._site = None

    # ------------------------------------------------------------------ sessions

    def new_token(self) -> str:
        return secrets.token_hex(16)  # 32 hex chars

    def create(self, *, watch_id: str, watch_label: str, url: str) -> ChallengeSession:
        token = self.new_token()
        session = ChallengeSession(token=token, watch_id=watch_id, watch_label=watch_label, url=url,
                                   ttl=self.ttl_seconds)
        self._sessions[token] = session
        return session

    def get(self, token: str) -> ChallengeSession | None:
        session = self._sessions.get(token)
        if session is None or session.expired:
            if session is not None:
                self._sessions.pop(token, None)
            return None
        return session

    def count(self) -> int:
        return len(self._sessions)

    async def cancel(self, token: str, notify: bool = True) -> bool:
        session = self._sessions.pop(token, None)
        if session is None:
            return False
        if session.cancel_fn is not None:
            try:
                await session.cancel_fn()
            except Exception:
                log.debug("challenge cancel_fn failed", exc_info=True)
        if notify:
            fut = self._pending_watchers.pop(token, None)
            if fut is not None and not fut.done():
                fut.set_result(("cancelled", None))
        return True

    async def complete(self, token: str) -> bool:
        session = self._sessions.pop(token, None)
        if session is None:
            return False
        if session.done_fn is not None:
            try:
                await session.done_fn()
            except Exception:
                log.debug("challenge done_fn failed", exc_info=True)
        fut = self._pending_watchers.pop(token, None)
        if fut is not None and not fut.done():
            fut.set_result(("done", None))
        return True

    def await_result(self, token: str) -> asyncio.Future:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending_watchers[token] = fut
        return fut

    # ------------------------------------------------------------------ housekeeping

    async def _purge_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(30)
                now = time.time()
                for token, session in list(self._sessions.items()):
                    if session.expires_at < now:
                        log.info("Challenge session %s… expired", token[:8])
                        await self.cancel(token)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("challenge purge failed")

    # ------------------------------------------------------------------ HTTP handlers

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "sessions": self.count(), "host": self.host, "port": self.port})

    async def _handle_page(self, request: web.Request) -> web.Response:
        token = request.match_info["token"]
        session = self.get(token)
        if session is None:
            return web.Response(status=404, text="link expired or invalid", content_type="text/plain")
        remaining = max(0, int(session.expires_at - time.time()))
        html = (_PAGE_HTML
                .replace("__TOKEN__", _escape(token))
                .replace("__LABEL__", _escape(session.watch_label))
                .replace("__URL__", _escape(session.url))
                .replace("__TTL__", str(remaining)))
        return web.Response(
            text=html,
            content_type="text/html",
            charset="utf-8",
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    async def _handle_frame(self, request: web.Request) -> web.StreamResponse:
        token = request.match_info["token"]
        session = self.get(token)
        if session is None or session.frame_fn is None:
            return web.Response(status=404, text="not found", content_type="text/plain")
        boundary = "frame"
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": f"multipart/x-mixed-replace; boundary={boundary}",
                "Cache-Control": "no-store",
            },
        )
        await response.prepare(request)
        try:
            while True:
                session = self.get(token)
                if session is None:
                    break
                try:
                    frame = await session.frame_fn()
                except Exception:
                    frame = b""
                if frame:
                    session.last_frame = frame
                    session.last_frame_at = time.time()
                if frame and len(frame) <= MAX_FRAME_BYTES:
                    header = (f"--{boundary}\r\n"
                              f"Content-Type: image/jpeg\r\n"
                              f"Content-Length: {len(frame)}\r\n\r\n").encode("ascii")
                    await response.write(header + frame + b"\r\n")
                await asyncio.sleep(FRAME_INTERVAL)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            try:
                await response.write_eof()
            except Exception:
                pass
        return response

    async def _handle_click(self, request: web.Request) -> web.Response:
        session, error = await self._require(request)
        if session is None:
            return error
        try:
            data = await request.json()
            x = float(data.get("x", -1))
            y = float(data.get("y", -1))
        except Exception:
            return web.json_response({"ok": False, "error": "invalid body"}, status=400)
        if x < 0 or y < 0 or session.click_fn is None:
            return web.json_response({"ok": False, "error": "no click handler or bad coords"}, status=400)
        async with session.solving_lock:
            try:
                await session.click_fn(x, y)
            except Exception as exc:
                log.warning("challenge click failed: %s", exc)
                return web.json_response({"ok": False, "error": str(exc)[:200]}, status=500)
        return web.json_response({"ok": True})

    async def _handle_type(self, request: web.Request) -> web.Response:
        session, error = await self._require(request)
        if session is None:
            return error
        try:
            data = await request.json()
            text = str(data.get("text", ""))[:2000]
        except Exception:
            return web.json_response({"ok": False, "error": "invalid body"}, status=400)
        if not text or session.type_fn is None:
            return web.json_response({"ok": False, "error": "no type handler"}, status=400)
        async with session.solving_lock:
            try:
                await session.type_fn(text)
            except Exception as exc:
                return web.json_response({"ok": False, "error": str(exc)[:200]}, status=500)
        return web.json_response({"ok": True})

    async def _handle_key(self, request: web.Request) -> web.Response:
        session, error = await self._require(request)
        if session is None:
            return error
        try:
            data = await request.json()
            key = str(data.get("key", ""))[:20]
        except Exception:
            return web.json_response({"ok": False, "error": "invalid body"}, status=400)
        if not key or session.key_fn is None:
            return web.json_response({"ok": False, "error": "no key handler"}, status=400)
        async with session.solving_lock:
            try:
                await session.key_fn(key)
            except Exception as exc:
                return web.json_response({"ok": False, "error": str(exc)[:200]}, status=500)
        return web.json_response({"ok": True})

    async def _handle_done(self, request: web.Request) -> web.Response:
        session, error = await self._require(request)
        if session is None:
            return error
        await self.complete(session.token)
        return web.json_response({"ok": True, "message": "done"})

    async def _handle_cancel(self, request: web.Request) -> web.Response:
        session, error = await self._require(request)
        if session is None:
            return error
        await self.cancel(session.token)
        return web.json_response({"ok": True, "message": "cancelled"})

    async def _require(self, request: web.Request):
        token = request.match_info["token"]
        session = self.get(token)
        if session is None:
            return None, web.json_response({"ok": False, "error": "link expired"}, status=404)
        return session, None


def _escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# --------------------------------------------------------------------------- page

_PAGE_HTML = """<!doctype html>
<html lang="fa" dir="rtl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>حل چالش — __LABEL__</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: Vazirmatn, Tahoma, sans-serif; margin: 0; background: #0f1115; color: #eaecef; }
  header { padding: 10px 14px; background: #171a21; border-bottom: 1px solid #262a35; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
  header h1 { font-size: 16px; margin: 0 0 4px; }
  header .url { font-size: 12px; color: #98a1b3; word-break: break-all; }
  main { display: grid; grid-template-columns: 1fr 340px; gap: 0; height: calc(100vh - 64px); }
  @media (max-width: 900px) { main { grid-template-columns: 1fr; height: auto; } }
  #stage { position: relative; background: #000; overflow: auto; }
  #frame { display: block; max-width: 100%; cursor: crosshair; }
  .ripple { position: absolute; width: 18px; height: 18px; border-radius: 50%; border: 2px solid #3b82f6; transform: translate(-50%, -50%); pointer-events: none; animation: pop .5s ease-out forwards; }
  @keyframes pop { from { opacity: 1; transform: translate(-50%, -50%) scale(0.5); } to { opacity: 0; transform: translate(-50%, -50%) scale(2.2); } }
  aside { padding: 14px; background: #12161d; border-inline-start: 1px solid #262a35; overflow: auto; }
  aside h2 { font-size: 13px; color: #98a1b3; margin: 0 0 8px; text-transform: uppercase; letter-spacing: .5px; }
  aside p { font-size: 12px; color: #b1b8c5; line-height: 1.7; margin: 0 0 10px; }
  .row { display: flex; gap: 8px; margin-bottom: 8px; }
  input[type=text] { flex: 1; padding: 8px 10px; background: #0d1015; border: 1px solid #2a3140; border-radius: 6px; color: #eaecef; font-size: 14px; }
  button { padding: 9px 14px; border: 1px solid #2a3140; background: #1c2130; color: #eaecef; border-radius: 6px; cursor: pointer; font-size: 13px; }
  button:hover:not(:disabled) { background: #242b3c; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.primary { background: #2563eb; border-color: #2563eb; }
  button.primary:hover:not(:disabled) { background: #1d4ed8; }
  button.danger  { background: #7f1d1d; border-color: #7f1d1d; }
  button.danger:hover:not(:disabled)  { background: #991b1b; }
  .keys button { flex: 1; }
  #status { margin-top: 12px; font-size: 12px; color: #8fbf8f; min-height: 20px; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; background: #1f2937; font-size: 11px; color: #98a1b3; }
  #timer { font-variant-numeric: tabular-nums; color: #fbbf24; }
</style>
</head><body>
<header>
  <div>
    <h1>🛡 حل چالش «__LABEL__»</h1>
    <div class="url">🔗 <span dir="ltr">__URL__</span> · <span class="badge">token: __TOKEN__</span></div>
  </div>
  <div class="badge" aria-live="off">⏱ زمان باقی‌مانده: <span id="timer" dir="ltr">--:--</span></div>
</header>
<main>
  <section id="stage" aria-label="نمایش زنده مرورگر سرور">
    <img id="frame" src="/c/__TOKEN__/frame.mjpg" alt="تصویر زنده صفحه چالش در مرورگر سرور">
  </section>
  <aside>
    <h2>چطور کار می‌کند؟</h2>
    <p>روی تصویر کلیک کنید تا در همان نقطه در مرورگر سرور کلیک شود. اگر کادر متنی است، متن را در کادر زیر بنویسید و Enter بزنید.</p>
    <h2>تایپ متن</h2>
    <div class="row">
      <input id="text" type="text" placeholder="متن برای تایپ…" aria-label="متن برای تایپ در مرورگر" autocomplete="off">
      <button onclick="sendType()" aria-label="ارسال متن">بنویس</button>
    </div>
    <h2>کلیدها</h2>
    <div class="row keys">
      <button onclick="sendKey('Enter')">Enter</button>
      <button onclick="sendKey('Tab')">Tab</button>
      <button onclick="sendKey('Backspace')">⌫</button>
      <button onclick="sendKey('Escape')">Esc</button>
    </div>
    <h2>اکشن نهایی</h2>
    <div class="row">
      <button class="primary" onclick="done()">✅ حل شد (ذخیره کوکی)</button>
      <button class="danger" onclick="cancel()">❌ انصراف</button>
    </div>
    <div id="status" role="status" aria-live="polite"></div>
  </aside>
</main>
<script>
const TOKEN = "__TOKEN__";
let remaining = parseInt("__TTL__", 10) || 600;
const timerEl = document.getElementById("timer");
function renderTimer() {
  const m = String(Math.floor(remaining / 60)).padStart(2, "0");
  const s = String(remaining % 60).padStart(2, "0");
  timerEl.textContent = `${m}:${s}`;
  if (remaining <= 0) {
    document.getElementById("status").textContent = "⛔ مهلت این لینک به پایان رسید.";
  }
}
renderTimer();
setInterval(() => { if (remaining > 0) { remaining--; renderTimer(); } }, 1000);

const stage = document.getElementById("stage");
const frame = document.getElementById("frame");
frame.addEventListener("click", async (ev) => {
  const rect = frame.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const x = (ev.clientX - rect.left) * ((frame.naturalWidth || rect.width) / rect.width);
  const y = (ev.clientY - rect.top)  * ((frame.naturalHeight || rect.height) / rect.height);
  const dot = document.createElement("div");
  dot.className = "ripple";
  dot.style.left = `${ev.clientX - stage.getBoundingClientRect().left + stage.scrollLeft}px`;
  dot.style.top  = `${ev.clientY - stage.getBoundingClientRect().top  + stage.scrollTop}px`;
  stage.appendChild(dot);
  setTimeout(() => dot.remove(), 550);
  await post(`/c/${TOKEN}/click`, {x: Math.round(x), y: Math.round(y)});
});
document.getElementById("text").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") { ev.preventDefault(); sendType(); }
});
async function sendType() {
  const input = document.getElementById("text");
  const text = input.value; if (!text) return;
  await post(`/c/${TOKEN}/type`, {text});
  input.value = "";
  await sendKey("Enter");
}
async function sendKey(key) { await post(`/c/${TOKEN}/key`, {key}); }
async function done() {
  if (!confirm("مطمئنید چالش حل شد؟ کوکی‌های نشست ذخیره می‌شود.")) return;
  const ok = await post(`/c/${TOKEN}/done`, {});
  if (ok) lockUi("✅ چالش با موفقیت ثبت شد. می‌توانید این تب را ببندید.");
}
async function cancel() {
  if (!confirm("انصراف از حل چالش؟")) return;
  const ok = await post(`/c/${TOKEN}/cancel`, {});
  if (ok) lockUi("❌ عملیات لغو شد.");
}
function lockUi(msg) {
  document.querySelectorAll("button, input").forEach(el => el.disabled = true);
  document.getElementById("status").textContent = msg;
}
async function post(path, body) {
  const status = document.getElementById("status");
  status.textContent = "⏳ در حال ارسال…";
  try {
    const r = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body||{})});
    const j = await r.json().catch(() => ({}));
    status.textContent = r.ok ? "✅ انجام شد" : ("❌ " + (j.error || r.status));
    return r.ok;
  } catch (e) { status.textContent = "❌ خطای ارتباط با سرور"; return false; }
}
</script>
</body></html>
"""
