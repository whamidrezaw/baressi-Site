"""Tests: unit tests plus end-to-end runs against a local fake website and a fake Telegram API.

Run from the project folder:
    python -m unittest discover -s tests -v
Set WEBMONITOR_SKIP_BROWSER=1 to skip the (slower) real-browser test.
"""

from __future__ import annotations

import asyncio
import html
import io
import json
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import unittest
import zipfile
from collections import Counter
from pathlib import Path
from unittest import mock

from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webmonitor import report  # noqa: E402
from webmonitor.config import ConfigError, parse_config  # noqa: E402
from webmonitor.engine import Monitor  # noqa: E402
from webmonitor.extract import (  # noqa: E402
    ExtractError, detect_block, extract_headlines, extract_items, normalize_url, page_snapshot, parse_feed,
    parse_html,
)
from webmonitor.notifier import TEXT_LIMIT, build_parts, html_to_text  # noqa: E402
from webmonitor.storage import Store  # noqa: E402
from webmonitor.util import (  # noqa: E402
    clean_text, fa_datetime, find_keywords, gregorian_to_jalali, human_duration, load_timezone,
)

CFG_PATH = Path(tempfile.gettempdir()) / "webmonitor-test.json"


def page_html(lines: list[str], title: str = "Test page") -> str:
    body = "".join(f"<p>{html.escape(line)}</p>" for line in lines)
    return f"<html><head><title>{title}</title></head><body><nav>menu</nav><div id='main'>{body}</div></body></html>"


def section_html(links: list[str]) -> str:
    items = "".join(f"<li><a href='{link}'>Link {link}</a></li>" for link in links)
    return f"<html><body><div id='main'><h1>Section</h1><ul>{items}</ul></div></body></html>"


def news_html(entries: list[tuple[str, str]]) -> str:
    items = "".join(f"<li><h3><a href='{href}'>{title}</a></h3><p>Summary of {title}</p></li>" for href, title in entries)
    return f"<html><body><ul class='news'>{items}</ul></body></html>"


def rss(entries: list[tuple[str, str]]) -> bytes:
    items = "".join(f"<item><title>{t}</title><link>https://n.example/{g}</link><guid>{g}</guid>"
                    f"<description>About {t}</description></item>" for g, t in entries)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>C</title>{items}</channel></rss>'.encode()


# =========================================================================== unit tests

class UtilTests(unittest.TestCase):
    def test_jalali_conversion(self):
        self.assertEqual(gregorian_to_jalali(2026, 10, 4), (1405, 7, 12))
        self.assertEqual(gregorian_to_jalali(2026, 3, 21), (1405, 1, 1))
        self.assertEqual(gregorian_to_jalali(2026, 3, 20), (1404, 12, 29))
        self.assertEqual(gregorian_to_jalali(2025, 3, 21), (1404, 1, 1))
        self.assertEqual(gregorian_to_jalali(2024, 3, 20), (1403, 1, 1))

    def test_clean_text_keeps_zwnj(self):
        self.assertEqual(clean_text("  می‌خواهم ​\n\tویزا‏  "), "می‌خواهم ویزا")

    def test_keywords_normalisation(self):
        self.assertEqual(find_keywords(["نوبت", "visa"], "نوبتدهي VISA"), ["نوبت", "visa"])
        self.assertEqual(find_keywords(["کیک"], "كيك"), ["کیک"])
        self.assertEqual(find_keywords(["1405"], "سال ۱۴۰۵"), ["1405"])
        self.assertEqual(find_keywords(["termin"], "nothing here"), [])

    def test_persian_dates_and_durations(self):
        from datetime import datetime

        tz = load_timezone("Asia/Tehran")
        ts = datetime(2026, 10, 5, 15, 46, tzinfo=tz).timestamp()
        self.assertEqual(fa_datetime(ts, tz), "دوشنبه ۱۳ مهر ۱۴۰۵ — ساعت ۱۵:۴۶")
        self.assertEqual(human_duration(150), "۲ دقیقه و ۳۰ ثانیه")
        self.assertEqual(human_duration(3 * 3600 + 120), "۳ ساعت و ۲ دقیقه")

    def test_default_names_are_short(self):
        from webmonitor.analyzer import smart_name

        self.assertEqual(smart_name("BBC News - Breaking news, video and the latest top stories from the U.S. and "
                                    "around the world", "https://www.bbc.com/news"), "BBC News")
        self.assertEqual(smart_name("Fox News - Breaking News Updates | Latest News Headlines | Photos & News Videos",
                                    "https://www.foxnews.com/"), "Fox News - Breaking News Updates")
        self.assertEqual(smart_name("آخرین خبر – Telegram", "https://t.me/s/akharinkhabar"), "آخرین خبر")
        self.assertEqual(smart_name("", "https://www.example.com/a"), "example.com")

    def test_proxy_addresses_are_validated(self):
        from webmonitor.config import Proxy

        self.assertEqual(Proxy.parse_url("socks5://127.0.0.1:40000").server, "socks5://127.0.0.1:40000")
        self.assertEqual(Proxy.parse_url("http://user:pass@1.2.3.4:8080").username, "user")
        for wrong in ("https://www.goethe.de/ins/tr/de/sta/izm.html", "socks5://127.0.0.1", "ftp://1.2.3.4:21", "x"):
            with self.subTest(wrong=wrong), self.assertRaises(ConfigError):
                Proxy.parse_url(wrong)


PAGE = """<html><head><title>T</title><script>var secret = 1;</script><style>.a{}</style></head><body>
<nav><a href="/menu">Menu</a></nav>
<div id="main">
  <h1>Visa   information</h1>
  <p>First <b>bold</b> paragraph.<br>Second line</p>
  <div class="accordion" style="display:none"><p>Hidden detail</p></div>
  <table><tr><th>Type</th><th>Fee</th></tr><tr><td>Schengen</td><td>90 EUR</td></tr></table>
  <ul><li><a href="docs/form.pdf?utm_source=x#top">Form</a></li><li><a href="https://other.example/x">Other</a></li></ul>
  <div class="ads">Buy now</div>
  <pre>line one
line two</pre>
</div>
<div class="cc-window">We use cookies</div>
</body></html>"""
BASE = "https://site.example/visa/index.html"


class ExtractTests(unittest.TestCase):
    def snap(self, **kwargs):
        return page_snapshot(parse_html(PAGE, BASE), BASE, **kwargs)

    def test_lines_blocks_tables_hidden_and_excludes(self):
        snap = self.snap(selector="#main", exclude_selectors=[".ads"])
        self.assertEqual(snap.lines, ["Visa information", "First bold paragraph.", "Second line", "Hidden detail",
                                      "Type | Fee", "Schengen | 90 EUR", "Form", "Other", "line one", "line two"])
        self.assertEqual(snap.title, "T")

    def test_links_are_absolute_and_clean(self):
        snap = self.snap(selector="#main", track_links=True)
        self.assertIn(("Form", "https://site.example/visa/docs/form.pdf"), snap.links)
        self.assertIn(("Other", "https://other.example/x"), snap.links)

    def test_missing_selector_raises(self):
        with self.assertRaises(ExtractError) as ctx:
            self.snap(selector="#nope")
        self.assertEqual(ctx.exception.kind, "selector")

    def test_ignore_patterns(self):
        snap = self.snap(selector="#main", ignore_patterns=[re.compile(r"\d+ EUR")])
        self.assertIn("Schengen", snap.lines)

    def test_whole_body_skips_scripts_and_cookie_banners(self):
        text = " ".join(self.snap().lines)
        self.assertIn("Menu", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("cookies", text)

    def test_nested_matches_are_not_duplicated(self):
        doc = parse_html("<div class='c'>A<div class='c'>B</div></div>", "https://x.example/")
        self.assertEqual(page_snapshot(doc, "https://x.example/", selector=".c").lines, ["A", "B"])

    def test_normalize_url(self):
        self.assertEqual(normalize_url("HTTPS://Site.Example:443/a b/ص?utm_medium=x&id=3#frag"),
                         "https://site.example/a%20b/%D8%B5?id=3")
        self.assertIsNone(normalize_url("mailto:someone@example.com"))

    def test_items(self):
        # the extra list must sit INSIDE the document: current parsers (lxml >= 6) drop whatever follows </html>
        html = news_html([("/n/1", "First headline here"), ("/n/2", "Second headline here")]).replace(
            "</body>", "<ul class='news'><li><p>An item without any link at all</p></li></ul></body>")
        doc = parse_html(html, "https://n.example/list")
        items = extract_items(doc, "https://n.example/list", "ul.news > li")
        self.assertEqual([i.id for i in items[:2]], ["https://n.example/n/1", "https://n.example/n/2"])
        self.assertEqual(items[0].title, "First headline here")
        self.assertEqual(items[0].text, "Summary of First headline here")
        self.assertTrue(items[2].id.startswith("h:"))

    def test_rss_and_atom(self):
        feed = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>C</title>'
                b'<item><title>A &amp; B</title><link>https://n.example/a</link><guid>id-a</guid>'
                b'<description><![CDATA[<p>Hello <b>world</b></p>]]></description>'
                b'<pubDate>Sun, 04 Oct 2026 13:41:33 GMT</pubDate></item>'
                b'<item><title>Second</title><link>/b</link><description>plain</description></item>'
                b'</channel></rss>')
        items = parse_feed(feed, "https://n.example/feed")
        self.assertEqual((items[0].id, items[0].title, items[0].text), ("id-a", "A & B", "Hello world"))
        self.assertEqual(items[1].url, "https://n.example/b")
        atom = (b'<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>F</title>'
                b'<entry><title>Atom one</title><link rel="alternate" href="https://a.example/1"/><id>tag:a,1</id>'
                b'<summary>S1</summary><updated>2026-10-04T10:00:00Z</updated></entry></feed>')
        entry = parse_feed(atom, "https://a.example/")[0]
        self.assertEqual((entry.id, entry.url, entry.text), ("tag:a,1", "https://a.example/1", "S1"))
        with self.assertRaises(ExtractError):
            parse_feed(b"<html><body>not a feed</body></html>", "https://a.example/")

    def test_self_changing_text_is_ignored(self):
        doc = parse_html("<html><body><div id='main'><p>Visa news</p><p>5 mins ago</p><p>Updated 2 hrs ago</p>"
                         "<p>SCREENCAPS 6 min read</p><p>Video Playing 3:40</p><p>۵ دقیقه پیش</p><p>لحظاتی پیش</p>"
                         "<p>vor 3 Stunden</p><p>Termin am 12.10.2026 um 10:00</p><p>یک پیش‌نمایش مهم</p>"
                         "<p>مدارک را دو روز قبل از مصاحبه بفرستید</p></div></body></html>", BASE)
        self.assertEqual(page_snapshot(doc, BASE, selector="#main").lines,
                         ["Visa news", "Updated", "SCREENCAPS", "Termin am 12.10.2026 um 10:00", "یک پیش‌نمایش مهم",
                          "مدارک را دو روز قبل از مصاحبه بفرستید"])

    def test_link_labels_use_the_headline_not_the_whole_card(self):
        page = ("<html><body><div id='main'><a href='/a1'><img src='x.jpg' alt='Watch live'></a>"
                "<a href='/a1'><div><h2>Bombers withdrawn from the base</h2><p>US media reported a new threat.</p>"
                "<span>9 mins ago</span></div></a></div></body></html>")
        snap = page_snapshot(parse_html(page, BASE), BASE, selector="#main", track_links=True)
        self.assertEqual(snap.links, [("Bombers withdrawn from the base", "https://site.example/a1")])

    def test_headlines(self):
        page = ("<html><body><nav><a href='/'>Home</a><a href='/sport'>Sport</a></nav>"
                "<a href='/news/1?at_medium=x'><h3>First big story of the day here</h3><p>A short teaser of the story</p><p>8</p>"
                "<span>5 mins ago</span></a><a href='/news/1'>First big story of the day here</a>"
                "<a href='/category/police'>POLICE AND LAW</a>"
                "<a href='https://ads.example/x'>You will not believe this amazing trick</a>"
                "<a href='/news/2' aria-label='Second story told in many words'><img src='i.jpg'></a></body></html>")
        items = extract_headlines(parse_html(page, "https://news.example/"), "https://news.example/")
        self.assertEqual([(i.id, i.title, i.text) for i in items], [
            ("https://news.example/news/1", "First big story of the day here", "A short teaser of the story"),
            ("https://news.example/news/2", "Second story told in many words", "")])

    def test_telegram_posts_without_footer_and_signature(self):
        post = ("<div class='tgme_widget_message_wrap'><div class='tgme_widget_message_text'>Headline number {n} of "
                "the channel<br>Details {n}<br>@Channel | channel.ir</div><div class='tgme_widget_message_footer'>"
                "<span class='tgme_widget_message_from_author'>M.B</span><a class='tgme_widget_message_date' "
                "href='https://t.me/chan/{n}'><time datetime='2026-10-05T12:22:21+00:00'>12:22</time></a></div></div>")
        page = "<html><body>" + "".join(post.format(n=n) for n in range(1, 6)) + "</body></html>"
        items = extract_items(parse_html(page, "https://t.me/s/chan"), "https://t.me/s/chan",
                              ".tgme_widget_message_wrap", "a.tgme_widget_message_date")
        first = items[0]
        self.assertEqual((first.id, first.title, first.text, first.published),
                         ("https://t.me/chan/1", "Headline number 1 of the channel", "Details 1",
                          "2026-10-05T12:22:21+00:00"))

    def test_detect_block(self):
        challenge = ("<html><head><title>Just a moment...</title></head><body><div id='cf-browser-verification'>"
                     "</div><script src='/cdn-cgi/challenge-platform/x.js'></script></body></html>")
        self.assertEqual(detect_block(challenge), "Cloudflare")
        normal = ("<html><body>" + "<p>Real content paragraph here.</p>" * 200
                  + "<div class='g-recaptcha'></div></body></html>")
        self.assertIsNone(detect_block(normal))


class ReportTests(unittest.TestCase):
    def test_diff_kinds_and_context(self):
        old = ["Title", "Appointments from 15 October", "Fee 80 EUR", "Old notice"]
        new = ["Title", "Appointments from 20 October", "Fee 80 EUR", "New announcement"]
        hunks = report.diff_lines(old, new)
        self.assertEqual([h.kind for h in hunks], ["modify", "remove", "add"])
        self.assertEqual(hunks[0].context, "Title")
        self.assertEqual(hunks[1].context, "Fee 80 EUR")

    def test_moves_are_ignored(self):
        self.assertEqual(report.diff_lines(["a", "b", "c"], ["c", "a", "b"]), [])
        self.assertEqual(len(report.diff_lines(["a", "b", "c"], ["c", "a", "b"], ignore_reorder=False)), 2)

    def test_word_diff_escapes_html(self):
        out = report.word_diff_html("Fee <b> & 10 EUR", "Fee <b> & 20 EUR")
        self.assertIn("&lt;b&gt; &amp;", out)
        self.assertIn("<s>10</s> <b><u>20</u></b>", out)

    def test_long_reports_are_split_with_valid_html(self):
        blocks = [f"🟢 <b>line {i}</b> " + "x" * 300 for i in range(60)]
        payload = report._payload("<b>Header</b>", "<i>continued</i>", blocks, silent=False, doc_title="t")
        parts = build_parts(payload)
        texts = [content for kind, content in parts if kind == "text"]
        self.assertLessEqual(len(texts), 5)
        self.assertTrue(all(len(t) <= TEXT_LIMIT for t in texts))
        self.assertTrue(all(t.count("<b>") == t.count("</b>") for t in texts))
        self.assertTrue(texts[1].startswith("<i>continued</i>"))
        self.assertEqual(parts[-1][0], "doc")
        self.assertIn("line 59", parts[-1][1]["content"])

    def test_short_reports_have_no_attachment(self):
        payload = report._payload("<b>H</b>", "", ["a", "b"], silent=False, doc_title="t")
        self.assertEqual([kind for kind, _ in build_parts(payload)], ["text"])

    def test_report_groups_changes_by_place_with_a_page_button(self):
        old = ["Most read", "1", "Old story about visas", "2", "Other story"]
        new = ["Most read", "1", "New story about visas", "2", "Other story", "Appointments open"]
        hunks = report.diff_lines(old, new)
        self.assertEqual(hunks[0].context, "Most read")  # a bare counter ("1") never serves as context

        class W:
            label, url, page_url, keywords, silent, type = "Embassy", "https://e.example/", "https://e.example/", \
                ["appointments"], False, "page"

        payload, summary, hits = report.change_event(W, W.url, hunks, [("New form", "https://e.example/f")], [],
                                                     time.time(), load_timezone("Asia/Tehran"))
        self.assertEqual(hits, ["appointments"])
        self.assertIn("📊 <b>خلاصه:</b> 🟢 ۱ جدید · 🟡 ۱ ویرایش · 🔗 ۱ لینک تازه", payload["header"])
        self.assertTrue(payload["blocks"][0].startswith("📍 <b>Most read</b>\n<blockquote>🟡"))
        self.assertIn("📍 <b>Other story</b>\n<blockquote>🟢 Appointments open</blockquote>", payload["blocks"])
        self.assertEqual(payload["buttons"], [[{"text": report.OPEN_PAGE, "url": "https://e.example/"}]])
        for kind, text in build_parts(payload):
            self.assertEqual(text.count("<blockquote"), text.count("</blockquote>"))

    def test_html_to_text(self):
        self.assertEqual(
            html_to_text('A <s>x</s> <b><u>y</u></b> <a href="https://e.x/?a=1&amp;b=2">L</a> &lt;'),
            "A [-x-] {+y+} L (https://e.x/?a=1&b=2) <")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        os.environ.pop("TELEGRAM_CHAT_ID", None)

    def test_old_flat_format_still_works(self):
        raw = {"telegram_token": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "telegram_chat_id": "42",
               "max_concurrent_tasks": 3, "global_proxy": None,
               "sites": [{"id": "s1", "url": "https://e.example/p", "selector": ".content-section",
                          "check_interval_seconds": 300, "jitter_seconds": 45,
                          "notification_cooldown_minutes": 30, "persist_session": False, "proxy": None,
                          "min_content_length": 100}]}
        cfg = parse_config(raw, CFG_PATH)
        w = cfg.watches[0]
        self.assertEqual((w.interval_seconds, w.cooldown_minutes, w.min_content_length), (300, 30, 100))
        self.assertEqual((cfg.telegram.chat_ids, cfg.telegram.enabled, cfg.browser.max_pages), (["42"], True, 3))
        self.assertEqual(cfg.warnings, [])

    def test_placeholders_disable_telegram(self):
        cfg = parse_config({"telegram": {"token": "YOUR_TELEGRAM_BOT_TOKEN", "chat_ids": ["YOUR_CHAT_ID"]},
                            "watches": [{"id": "a", "url": "https://e.example"}]}, CFG_PATH)
        self.assertFalse(cfg.telegram.enabled)

    def test_environment_overrides_token(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = "999:ZYXWVUTSRQPONMLKJIHGFEDCBA"
        cfg = parse_config({"telegram": {"chat_ids": [1]}, "watches": [{"id": "a", "url": "https://e.example"}]},
                           CFG_PATH)
        self.assertEqual((cfg.telegram.token, cfg.telegram.chat_ids), ("999:ZYXWVUTSRQPONMLKJIHGFEDCBA", ["1"]))

    def test_invalid_configs_are_rejected(self):
        ok = {"id": "a", "url": "https://e.example"}
        bad = [
            {"watches": [{"id": "a", "url": "ftp://x"}]},
            {"watches": [{"id": "a b", "url": "https://e.example"}]},
            {"watches": [{**ok, "selector": "div[["}]},
            {"watches": [{**ok, "ignore_patterns": ["("]}]},
            {"watches": [ok, ok]},
            {"watches": [{**ok, "type": "items"}]},
            {"watches": [{**ok, "interval_seconds": 1}]},
            {"watches": [{**ok, "track_links": "yes"}]},
            {"watches": {"id": "a"}},
            {"telegram": {"token": "not-a-token"}, "watches": [ok]},
        ]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ConfigError):
                parse_config(raw, CFG_PATH)

    def test_unknown_keys_warn(self):
        cfg = parse_config({"watches": [{"id": "a", "url": "https://e.example", "selecter": "#x"}]}, CFG_PATH)
        self.assertTrue(any("selecter" in warning for warning in cfg.warnings))


# =========================================================================== end-to-end

class FakeSite:
    def __init__(self):
        self.routes: dict[str, dict] = {}
        self.hits: Counter = Counter()

    def set(self, path: str, body, status: int = 200, ctype: str = "text/html; charset=utf-8", etag=None):
        self.routes[path] = {"body": body.encode() if isinstance(body, str) else body, "status": status,
                             "ctype": ctype, "etag": etag}

    def remove(self, path: str) -> None:
        self.routes.pop(path, None)

    async def handle(self, request: web.Request) -> web.Response:
        self.hits[request.path] += 1
        route = self.routes.get(request.path)
        if route is None:
            return web.Response(status=404, text="not found")
        headers = {"Content-Type": route["ctype"]}
        if route["etag"]:
            headers["ETag"] = route["etag"]
            if request.headers.get("If-None-Match") == route["etag"]:
                return web.Response(status=304, headers={"ETag": route["etag"]})
        return web.Response(status=route["status"], body=route["body"], headers=headers)


class FakeTelegram:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.failures: list[tuple[int, dict]] = []
        self.bad_chats: set[str] = set()
        self.members: dict[tuple[str, str], str] = {}  # (chat_id, user_id) -> status
        self.files: dict[str, bytes] = {}
        self.updates: list[dict] = []
        self.next_message_id = 100

    async def handle_file(self, request: web.Request) -> web.Response:
        file_id = request.match_info["path"].rsplit("/", 1)[-1].removesuffix(".json")
        return web.Response(body=self.files[file_id])

    async def handle(self, request: web.Request) -> web.Response:
        method = request.match_info["method"]
        if request.content_type.startswith("multipart"):
            form = await request.post()
            data = {k: (v if isinstance(v, str) else v.file.read()) for k, v in form.items()}
        else:
            data = await request.json()
        if method.startswith("send") and str(data.get("chat_id")) in self.bad_chats:
            return web.json_response({"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
                                     status=400)
        if method.startswith("send") and self.failures:
            status, body = self.failures.pop(0)
            return web.json_response(body, status=status)
        self.calls.append((method, data))
        if method == "getChatMember":
            status = self.members.get((str(data["chat_id"]), str(data["user_id"])), "left")
            return web.json_response({"ok": True, "result": {"status": status}})
        if method == "getFile":
            path = f"documents/{data['file_id']}.json"
            return web.json_response({"ok": True, "result": {"file_path": path,
                                                             "file_size": len(self.files[data["file_id"]])}})
        if method == "getUpdates":
            updates, self.updates = self.updates, []
            if not updates:
                await asyncio.sleep(0.05)  # stand-in for Telegram's long polling
            return web.json_response({"ok": True, "result": updates})
        self.next_message_id += 1
        return web.json_response({"ok": True, "result": {"message_id": self.next_message_id}})

    @property
    def texts(self) -> list[str]:
        return [data["text"] for method, data in self.calls if method in ("sendMessage", "editMessageText")]

    def button(self, label_part: str) -> str:
        """callback_data of the newest button whose label contains ``label_part``."""
        for method, data in reversed(self.calls):
            for row in (data.get("reply_markup") or {}).get("inline_keyboard", []):
                for button in row:
                    if label_part in button["text"]:
                        return button["callback_data"]
        raise AssertionError(f"no button containing {label_part!r}")

    @property
    def messages(self) -> list[dict]:
        return [data for method, data in self.calls if method == "sendMessage"]

    @property
    def documents(self) -> list[dict]:
        return [data for method, data in self.calls if method == "sendDocument"]


async def serve(handler, route: str = "/{tail:.*}", extra: dict | None = None):
    app = web.Application()
    app.router.add_route("*", route, handler)
    for extra_route, extra_handler in (extra or {}).items():
        app.router.add_route("GET", extra_route, extra_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


class EngineTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-test-"))
        self.site, self.tg = FakeSite(), FakeTelegram()
        self.site_runner, self.site_port = await serve(self.site.handle)
        self.tg_runner, self.tg_port = await serve(self.tg.handle, "/bot{token}/{method}",
                                                   {"/file/bot{token}/{path:.*}": self.tg.handle_file})
        self.monitors: list[Monitor] = []

    async def asyncTearDown(self):
        for monitor in self.monitors:
            await monitor.close()
        await self.site_runner.cleanup()
        await self.tg_runner.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.site_port}{path}"

    async def monitor(self, watches: list[dict], **top) -> Monitor:
        raw = {
            "data_dir": str(self.tmp / "data"), "notify_startup": False, "daily_report_hour": None,
            "telegram": {"token": "123456:" + "A" * 35, "chat_ids": ["42"],
                         "api_base": f"http://127.0.0.1:{self.tg_port}", "commands": False},
            "defaults": {"engine": "http", "timeout_seconds": 10, "min_content_length": 1},
            "watches": watches, **top,
        }
        monitor = Monitor(parse_config(raw, self.tmp / "cfg.json"))
        monitor.notifier.retry_delay = 0.01
        await monitor.start()
        self.monitors.append(monitor)
        return monitor

    def page_watch(self, **extra) -> dict:
        return {"id": "p", "name": "Embassy", "url": self.url("/page"), "selector": "#main", **extra}


class PageFlowTests(EngineTestCase):
    async def test_change_is_reported_with_word_diff_and_escaping(self):
        self.site.set("/page", page_html(["Appointments from 15 October", "Fee: 80 EUR"]))
        m = await self.monitor([self.page_watch(keywords=["appointment"])])
        w = m.watches[0]
        self.assertTrue((await m.check_watch(w)).startswith("baseline"))
        self.assertEqual(await m.check_watch(w), "no change")
        self.site.set("/page", page_html(["Appointments from 20 October", "Fee: 80 EUR",
                                          "New rule: <b>bring</b> passport & photo"]))
        self.assertTrue((await m.check_watch(w)).startswith("CHANGE"))
        self.assertEqual(await m.dispatch_pending(), 1)
        message = self.tg.messages[-1]
        self.assertEqual((message["parse_mode"], message["chat_id"]), ("HTML", "42"))
        self.assertIn("<s>15</s> <b><u>20</u></b>", message["text"])
        self.assertIn("New rule: &lt;b&gt;bring&lt;/b&gt; passport &amp; photo", message["text"])
        self.assertTrue(message["text"].startswith("🚨"))
        self.assertFalse(message["disable_notification"])

    async def test_nothing_is_lost_while_telegram_is_down(self):
        self.site.set("/page", page_html(["version one"]))
        m = await self.monitor([self.page_watch()])
        await m.check_watch(m.watches[0])
        self.site.set("/page", page_html(["version two"]))
        await m.check_watch(m.watches[0])
        self.tg.failures = [(500, {"ok": False, "error_code": 500, "description": "Internal"})] * 3
        self.assertEqual(await m.dispatch_pending(), 0)
        self.assertEqual(m.store.pending_count(), 1)
        await m.close()  # simulate a restart: the queued notification must survive
        self.monitors.remove(m)
        m2 = await self.monitor([self.page_watch()])
        with m2.store.conn:
            m2.store.conn.execute("UPDATE events SET next_attempt = 0")
        self.assertEqual(await m2.dispatch_pending(), 1)
        self.assertIn("two", self.tg.messages[-1]["text"])
        self.assertEqual(m2.store.pending_count(), 0)

    async def test_rate_limit_and_html_rejection_fallback(self):
        self.site.set("/page", page_html(["alpha beta"]))
        m = await self.monitor([self.page_watch()])
        await m.check_watch(m.watches[0])
        self.site.set("/page", page_html(["alpha gamma"]))
        await m.check_watch(m.watches[0])
        self.tg.failures = [
            (429, {"ok": False, "error_code": 429, "description": "Too Many Requests", "parameters": {"retry_after": 1}}),
            (400, {"ok": False, "error_code": 400, "description": "Bad Request: can't parse entities"}),
        ]
        self.assertEqual(await m.dispatch_pending(), 1)
        last = self.tg.messages[-1]
        self.assertNotIn("parse_mode", last)
        self.assertIn("[-beta-] {+gamma+}", last["text"])

    async def test_one_wrong_chat_id_does_not_block_the_others(self):
        self.site.set("/page", page_html(["first"]))
        m = await self.monitor([self.page_watch()])
        m.chat_ids = ["42", "999"]
        self.tg.bad_chats = {"999"}
        w = m.watches[0]
        await m.check_watch(w)
        for text in ("second", "third"):
            self.site.set("/page", page_html([text]))
            await m.check_watch(w)
        self.assertEqual(await m.dispatch_pending(), 2)
        self.assertEqual([msg["chat_id"] for msg in self.tg.messages], ["42", "42"])
        self.assertEqual(m.store.pending_count(), 0)

    async def test_errors_alert_once_then_recovery_without_false_change(self):
        self.site.set("/page", page_html(["stable text"]))
        m = await self.monitor([self.page_watch(error_threshold=2)])
        w = m.watches[0]
        await m.check_watch(w)
        self.site.set("/page", "<html><body>Service Unavailable</body></html>", status=503)
        for _ in range(4):
            self.assertTrue((await m.check_watch(w)).startswith("error"))
        self.site.set("/page", page_html(["stable text"]))
        self.assertEqual(await m.check_watch(w), "no change")  # the error page never replaced the baseline
        await m.dispatch_pending()
        texts = [message["text"] for message in self.tg.messages]
        self.assertEqual(sum("مشکل در بررسی" in t for t in texts), 1)
        self.assertEqual(sum("دوباره با موفقیت" in t for t in texts), 1)

    async def test_broken_selector_is_an_error_not_a_change(self):
        self.site.set("/page", page_html(["content here"]))
        m = await self.monitor([self.page_watch()])
        await m.check_watch(m.watches[0])
        self.site.set("/page", "<html><body><div id='redesigned'>new layout</div></body></html>")
        self.assertIn("matched nothing", await m.check_watch(m.watches[0]))
        self.assertEqual(m.store.pending_count(), 0)

    async def test_cooldown_batches_changes_without_losing_any(self):
        self.site.set("/page", page_html(["version v0"]))
        m = await self.monitor([self.page_watch(cooldown_minutes=10)])
        w = m.watches[0]
        await m.check_watch(w)
        for version in ("v1", "v2", "v3"):
            self.site.set("/page", page_html([f"version {version}"]))
            await m.check_watch(w)
            await m.dispatch_pending()
        self.assertEqual(len(self.tg.messages), 1)  # v1 sent at once, v2+v3 wait for the cooldown
        self.assertEqual(m.store.pending_count(), 2)
        m.store.update_watch(w.id, last_notified=time.time() - 11 * 60)
        self.assertEqual(await m.dispatch_pending(), 2)
        digest = self.tg.messages[-1]["text"]
        self.assertIn("۲ رویداد", digest)
        self.assertIn("v2", digest)
        self.assertIn("v3", digest)

    async def test_conditional_get_and_silent_rebaseline_on_settings_change(self):
        self.site.set("/page", page_html(["etag text"]), etag='"v1"')
        m = await self.monitor([self.page_watch()])
        await m.check_watch(m.watches[0])
        self.assertEqual(await m.check_watch(m.watches[0]), "no change (HTTP 304)")
        await m.close()
        self.monitors.remove(m)
        m2 = await self.monitor([self.page_watch(selector="body")])
        self.assertIn("settings changed", await m2.check_watch(m2.watches[0]))
        self.assertEqual(m2.store.pending_count(), 0)

    async def test_only_keywords_filters_but_keeps_history(self):
        self.site.set("/page", page_html(["nothing important"]))
        m = await self.monitor([self.page_watch(keywords=["visa"], only_keywords=True)])
        w = m.watches[0]
        await m.check_watch(w)
        self.site.set("/page", page_html(["still nothing important"]))
        self.assertIn("not sent", await m.check_watch(w))
        self.site.set("/page", page_html(["VISA appointments open"]))
        await m.check_watch(w)
        self.assertEqual(await m.dispatch_pending(), 1)
        self.assertIn("VISA appointments", self.tg.messages[-1]["text"])
        statuses = [row["status"] for row in m.store.recent_events("p")]
        self.assertEqual(sorted(statuses), ["filtered", "sent"])

    async def test_status_command_and_run_forever_lifecycle(self):
        self.site.set("/page", page_html(["hello world"]))
        m = await self.monitor([self.page_watch(interval_seconds=5)], notify_startup=True)
        task = asyncio.create_task(m.run_forever())
        for _ in range(150):
            await asyncio.sleep(0.1)
            if m.store.get_page("p", m._root(m.watches[0])) is not None and self.tg.messages:
                break
        m.stop()
        await asyncio.wait_for(task, 20)
        self.assertIn("شروع به کار", self.tg.messages[0]["text"])
        from webmonitor.bot import AdminBot

        await AdminBot(m).show_status("42")
        self.assertIn("وضعیت مانیتور", self.tg.messages[-1]["text"])
        self.assertIn("Embassy", self.tg.messages[-1]["text"])


class AccessTests(EngineTestCase):
    async def test_blocked_http_falls_back_to_impersonate_and_sticks(self):
        from webmonitor.fetchers import FetchError

        self.site.set("/page", page_html(["content only a real-looking client may see"]))
        m = await self.monitor([self.page_watch(engine="auto")])
        if not m.impersonate.available:
            self.skipTest("curl_cffi is not installed")

        async def blocked(*args, **kwargs):
            raise FetchError("http", "HTTP 403", 403)

        m.http.fetch = blocked
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.assertEqual(m.engine_for(w), "impersonate")
        self.assertEqual(await m.check_watch(w), "no change")

    async def test_blocked_browser_falls_back_to_impersonate(self):
        from webmonitor.fetchers import FetchError

        self.site.set("/page", page_html(["content behind a bot wall"]))
        m = await self.monitor([self.page_watch(engine="auto")])
        if not m.impersonate.available:
            self.skipTest("curl_cffi is not installed")
        w = m.watches[0]
        m.store.update_watch(w.id, engine="browser")  # chosen by an older version

        async def blocked(*args, **kwargs):
            raise FetchError("http", "HTTP 403", 403)

        m.browser.fetch = blocked
        self.assertIn("baseline", await m.check_watch(w))
        self.assertEqual(m.engine_for(w), "impersonate")

    async def test_backoff_after_repeated_failures(self):
        m = await self.monitor([self.page_watch(interval_seconds=60, jitter_seconds=0)])
        w = m.watches[0]
        self.assertEqual(m.next_delay(w), 60)
        for _ in range(3):
            m.store.record_check_error(w.id, "HTTP 403")
        self.assertEqual(m.next_delay(w), 240)
        for _ in range(10):
            m.store.record_check_error(w.id, "HTTP 403")
        self.assertEqual(m.next_delay(w), 1800)
        m.store.record_check_ok(w.id)
        self.assertEqual(m.next_delay(w), 60)


class ItemsAndFeedTests(EngineTestCase):
    async def test_new_list_items_are_reported(self):
        self.site.set("/news", news_html([("/n/1", "First headline here")]))
        m = await self.monitor([{"id": "n", "type": "items", "url": self.url("/news"), "item_selector": "ul.news > li"}])
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.site.set("/news", news_html([("/n/2", "Brand new headline"), ("/n/1", "First headline here")]))
        self.assertIn("NEW", await m.check_watch(w))
        await m.dispatch_pending()
        text = self.tg.messages[-1]["text"]
        self.assertIn("Brand new headline", text)
        self.assertNotIn("First headline", text)
        self.assertIn(self.url("/n/2"), text)

    async def test_new_feed_entries_are_reported(self):
        self.site.set("/feed.xml", rss([("a", "Old story")]), ctype="application/rss+xml")
        m = await self.monitor([{"id": "f", "type": "feed", "url": self.url("/feed.xml")}])
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.site.set("/feed.xml", rss([("b", "Breaking story"), ("a", "Old story")]), ctype="application/rss+xml")
        self.assertIn("NEW", await m.check_watch(w))
        await m.dispatch_pending()
        self.assertIn("Breaking story", self.tg.messages[-1]["text"])


class NewsTests(EngineTestCase):
    @staticmethod
    def front(stories: list[tuple[int, str, int]]) -> str:
        cards = "".join(f"<a href='/news/{i}'><h3>{title}</h3><span>{minutes} mins ago</span></a>"
                        for i, title, minutes in stories)
        return f"<html><body><nav><a href='/'>Home</a></nav><main>{cards}</main></body></html>"

    async def test_headlines_report_only_new_stories(self):
        self.site.set("/", self.front([(1, "Parliament votes on the new budget", 5),
                                       (2, "Storm hits the northern coast tonight", 9)]))
        m = await self.monitor([{"id": "h", "name": "News", "type": "headlines", "url": self.url("/")}])
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.site.set("/", self.front([(2, "Storm hits the northern coast tonight", 12),
                                       (1, "Parliament votes on the new budget", 8)]))
        self.assertIn("no new items", await m.check_watch(w))  # times and order changed: nothing to report
        self.site.set("/", self.front([(3, "Central bank raises interest rates again", 1),
                                       (1, "Parliament votes on the new budget", 9)]))
        self.assertIn("NEW", await m.check_watch(w))
        await m.dispatch_pending()
        message = self.tg.messages[-1]
        self.assertIn("Central bank raises interest rates again", message["text"])
        self.assertNotIn("Parliament", message["text"])
        self.assertEqual(message["reply_markup"]["inline_keyboard"][0][0]["url"], self.url("/"))

    async def test_relative_times_never_count_as_changes(self):
        self.site.set("/page", page_html(["Visa appointments update", "Published 5 mins ago"]))
        m = await self.monitor([self.page_watch()])
        w = m.watches[0]
        await m.check_watch(w)
        self.site.set("/page", page_html(["Visa appointments update", "Published 7 mins ago"]))
        self.assertEqual(await m.check_watch(w), "no change")


class Socks5Redirector:
    """A minimal SOCKS5 proxy (CONNECT, no auth) that forwards traffic for one port to another — a stand-in
    for a proxy whose IP the blocked site still accepts."""

    def __init__(self, redirect: dict[int, int]):
        self.redirect = redirect
        self.connections = 0

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        self.server.close()

    @staticmethod
    async def pipe(source, target) -> None:
        try:
            while data := await source.read(65536):
                target.write(data)
                await target.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            target.close()

    async def handle(self, reader, writer) -> None:
        try:
            greeting = await reader.readexactly(2)
            await reader.readexactly(greeting[1])
            writer.write(b"\x05\x00")
            _, _, _, address_type = await reader.readexactly(4)
            if address_type == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif address_type == 3:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            port = int.from_bytes(await reader.readexactly(2), "big")
            upstream_reader, upstream_writer = await asyncio.open_connection(host, self.redirect.get(port, port))
            self.connections += 1
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"))
            await writer.drain()
            await asyncio.gather(self.pipe(reader, upstream_writer), self.pipe(upstream_reader, writer))
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            writer.close()


class FallbackProxyTests(EngineTestCase):
    async def test_blocked_site_is_checked_through_the_fallback_proxy(self):
        m = await self.monitor([self.page_watch(engine="auto")])
        if not m.impersonate.available:
            self.skipTest("curl_cffi is not installed")
        m.browser.unavailable = "disabled in this test"  # keep it fast: http + Chrome impersonation only
        open_site = FakeSite()
        runner, open_port = await serve(open_site.handle)
        self.addAsyncCleanup(runner.cleanup)
        proxy = Socks5Redirector({self.site_port: open_port})
        proxy_port = await proxy.start()
        self.addAsyncCleanup(proxy.close)
        self.site.set("/page", "<html><body>Access Denied</body></html>", status=403)  # the server's IP is blocked
        open_site.set("/page", page_html(["Exam seats: none available"]))
        m.store.set_setting("fallback_proxy", f"socks5://127.0.0.1:{proxy_port}")
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.assertEqual(m.route_of(w), "fallback")
        self.assertGreater(proxy.connections, 0)
        direct_hits = self.site.hits["/page"]
        open_site.set("/page", page_html(["Exam seats: 2 available"] + ["Exam rules and dates."] * 10))
        self.assertIn("CHANGE", await m.check_watch(w))
        self.assertEqual(self.site.hits["/page"], direct_hits)  # the blocked route is not hammered any more
        rows = await m.diagnose(w.url, base=w)
        self.assertTrue(any(route == "fallback" and ok for route, _, ok, _ in rows))
        self.assertFalse(any(route == "direct" and ok for route, _, ok, _ in rows))


class CrawlTests(EngineTestCase):
    async def test_new_changed_removed_pages_and_files(self):
        s = self.site
        s.set("/sec/", section_html(["/sec/a", "/sec/b", "/sec/doc.pdf", "/other/x"]))
        s.set("/sec/a", page_html(["Page A"]))
        s.set("/sec/b", page_html(["Page B"]))
        s.set("/sec/doc.pdf", b"%PDF-1.4 version 1", ctype="application/pdf")
        s.set("/other/x", page_html(["out of scope"]))
        m = await self.monitor([{"id": "c", "url": self.url("/sec/"), "selector": "#main",
                                 "crawl": {"max_pages": 10, "max_depth": 2, "interval_seconds": 60}}])
        w = m.watches[0]
        await m.check_watch(w)
        self.assertIn("3 checked", await m.crawl(w))
        self.assertEqual(m.store.pending_count(), 0)  # the first crawl is a silent baseline
        self.assertEqual(s.hits["/other/x"], 0)

        s.set("/sec/c", page_html(["Brand new visa page"], title="New page"))
        s.set("/sec/", section_html(["/sec/a", "/sec/b", "/sec/doc.pdf", "/sec/c"]))
        await m.check_watch(w)  # the start page shows a new link -> queued for an immediate check
        self.assertIn(self.url("/sec/c"), m._crawl_pending[w.id])
        await m._crawl_new_urls(w, sorted(m._crawl_pending[w.id]))

        s.set("/sec/a", page_html(["Page A updated"]))
        s.set("/sec/doc.pdf", b"%PDF-1.4 version 2", ctype="application/pdf")
        s.remove("/sec/b")
        await m.crawl(w)
        await m.crawl(w)  # removal is confirmed after two consecutive 404s
        kinds = Counter(row["kind"] for row in m.store.conn.execute("SELECT kind FROM events"))
        self.assertEqual(kinds, Counter({"change": 2, "new_page": 1, "file": 1, "removed_page": 1}))
        await m.dispatch_pending()
        texts = "\n".join(message["text"] for message in self.tg.messages)
        self.assertIn("Brand new visa page", texts)
        self.assertIn("doc.pdf", texts)
        self.assertIn("حذف شد", texts)


GOETHE_RECORDS = [
    {"oid": "o1", "locationName": "Izmir", "startDate": "02.11.2026", "isDigital": False, "availability": 2,
     "price": " TRY 17.860,00", "bookFrom": "29.09.2026", "bookFromTime": "11:00:00.000"},
    {"oid": "o2", "locationName": "Ankara", "startDate": "21.10.2026", "isDigital": True, "availability": 11,
     "price": " TRY 17.860,00", "bookFrom": "20.10.2026", "bookFromTime": "09:30:00.000"},
]


def goethe_page(api_path: str = "/rest/examfinderv3/exams/institute/") -> str:
    settings = {"sortField": "startDate", "hasJUGroup": True, "countryIsoCode": "tr", "count": "7",
                "category": "E007", "defaults": {"frontendmode": True}, "type": "ER", "apipath": api_path}
    body = "".join(f"<p>Information paragraph {i} about the Goethe-Zertifikat B2 exam.</p>" for i in range(12))
    return (f"<html><head><title>Goethe-Zertifikat B2</title></head><body><div id='content'>{body}</div>"
            f"<script>window['examfinderv3DataCF'] = {json.dumps(settings)} window['configData'] = "
            f"{{\"pageId\": \"1\"}}</script><template id='exam-list'><li v-if=\"exam.availability != 12\">"
            f"</li></template></body></html>")


class JsonAndGoetheTests(unittest.TestCase):
    def test_json_snapshot_renders_goethe_records(self):
        from webmonitor.analyzer import GOETHE
        from webmonitor.extract import json_snapshot

        snap = json_snapshot({"DATA": GOETHE_RECORDS}, "DATA", GOETHE["template"], GOETHE["labels"])
        self.assertEqual(snap.lines, [
            "📍 Izmir · 🗓 02.11.2026 · 📝 کاغذی · ⛔ ظرفیت تکمیل · 💶 TRY 17.860,00",
            "📍 Ankara · 🗓 21.10.2026 · 💻 لپ‌تاپ · ⏳ رزرو از 20.10.2026 ساعت 09:30 · 💶 TRY 17.860,00",
        ])
        izmir = json_snapshot({"DATA": GOETHE_RECORDS}, "DATA", GOETHE["template"], GOETHE["labels"],
                              {"locationName": "izmir"})
        self.assertEqual(len(izmir.lines), 1)
        with self.assertRaises(ExtractError):
            json_snapshot({"OTHER": []}, "DATA")

    def test_goethe_api_is_found_whatever_the_variable_name(self):
        from webmonitor.analyzer import goethe_exam_api

        api = goethe_exam_api(goethe_page(), "https://www.goethe.de/ins/tr/de/spr/prf/gzb2.cfm")
        self.assertTrue(api.startswith("https://www.goethe.de/rest/examfinderv3/exams/institute/?"))
        self.assertIn("countryIsoCode=tr", api)
        self.assertIn("hasJUGroup=true", api)
        self.assertIn("count=100", api)
        self.assertNotIn("defaults", api)
        self.assertIsNone(goethe_exam_api("<html><script>window['x'] = {\"a\": 1}</script></html>", "https://a.b/"))


class PanelHelperTests(unittest.TestCase):
    def test_input_url_normalisation(self):
        from webmonitor.bot import normalize_input_url, parse_keywords

        self.assertEqual(normalize_input_url("@bbcpersian"), "https://t.me/s/bbcpersian")
        self.assertEqual(normalize_input_url("https://t.me/bbcpersian/123"), "https://t.me/s/bbcpersian")
        self.assertEqual(normalize_input_url("teheran.diplo.de/ir-fa"), "https://teheran.diplo.de/ir-fa")
        self.assertEqual(normalize_input_url("see https://example.com/a?b=1, thanks"), "https://example.com/a?b=1")
        self.assertIsNone(normalize_input_url("salam"))
        self.assertEqual(parse_keywords("نوبت، visa ,Termin\nvisa"), ["نوبت", "visa", "Termin"])
        self.assertEqual(parse_keywords("-"), [])

    def test_default_crawl_scope_is_the_url_section(self):
        from webmonitor.registry import default_crawl

        pattern = re.compile(default_crawl("https://teheran.diplo.de/ir-de")["include"][0])
        self.assertTrue(pattern.search("https://teheran.diplo.de/ir-de/2752046-2752046"))
        self.assertFalse(pattern.search("https://teheran.diplo.de/ir-fa/2466032-2466032"))
        self.assertTrue(re.search(default_crawl("https://example.com/")["include"][0], "https://example.com/x"))


class RegistryTests(EngineTestCase):
    async def test_config_watches_are_imported_once_and_follow_file_changes(self):
        m = await self.monitor([self.page_watch()])
        record = m.registry.records()[0]
        self.assertEqual((record.origin, record.id), ("config", "p"))
        m.registry.update(record.key, dict(record.spec, name="Renamed in bot"))
        await m.close()
        self.monitors.remove(m)
        m2 = await self.monitor([self.page_watch()])  # file unchanged: the bot's edit is kept
        self.assertEqual(m2.registry.records()[0].watch.name, "Renamed in bot")
        await m2.close()
        self.monitors.remove(m2)
        m3 = await self.monitor([self.page_watch(name="Changed in file")])  # file changed: the file wins
        self.assertEqual(m3.registry.records()[0].watch.name, "Changed in file")


class BotTests(EngineTestCase):
    ADMIN, STRANGER, CHANNEL = "777", "555", "-100123"

    async def make_bot(self, watches=()):
        from webmonitor.bot import AdminBot

        m = await self.monitor(list(watches), telegram={
            "token": "123456:" + "A" * 35, "chat_ids": [self.CHANNEL],
            "api_base": f"http://127.0.0.1:{self.tg_port}", "commands": True})
        self.tg.members[(self.CHANNEL, self.ADMIN)] = "creator"
        bot = AdminBot(m)
        bot.allow_private_urls = True  # the fake sites run on 127.0.0.1
        return m, bot

    def message(self, text: str = "", user: str = ADMIN, document: dict | None = None) -> dict:
        message = {"message_id": 1, "date": int(time.time()), "chat": {"id": int(user), "type": "private"},
                   "from": {"id": int(user), "first_name": "Tester"}}
        if document:
            message["document"] = document
        else:
            message["text"] = text
        return {"update_id": 1, "message": message}

    def press(self, data: str, user: str = ADMIN) -> dict:
        return {"update_id": 2, "callback_query": {
            "id": "cb", "from": {"id": int(user)}, "data": data,
            "message": {"message_id": 50, "chat": {"id": int(user), "type": "private"}}}}

    async def test_strangers_are_refused(self):
        m, bot = await self.make_bot()
        await bot.handle_update(self.message("/start", user=self.STRANGER))
        self.assertIn("خصوصی", self.tg.texts[-1])
        self.assertFalse(any("پنل مدیریت" in text for text in self.tg.texts))
        await bot.handle_update(self.press("a", user=self.STRANGER))
        self.assertTrue(any(method == "answerCallbackQuery" and data.get("show_alert")
                            for method, data in self.tg.calls))
        self.assertEqual(m.store.admin_ids(), [])

    async def test_channel_creator_gets_the_panel(self):
        m, bot = await self.make_bot()
        await bot.handle_update(self.message("/start"))
        self.assertIn("پنل مدیریت", self.tg.texts[-1])
        self.assertEqual(self.tg.button("افزودن سایت"), "a")
        self.assertEqual(m.store.admin_ids(), [self.ADMIN])

    async def test_add_site_wizard_end_to_end(self):
        body = "".join(f"<p>Paragraph {i}: appointments and documents for visa applicants.</p>" for i in range(10))
        self.site.set("/embassy", f"<html><head><title>Embassy Visa</title></head><body><nav>menu</nav>"
                                  f"<div id='main'><h1>Visa information</h1>{body}</div></body></html>")
        m, bot = await self.make_bot()
        await bot.handle_update(self.message(self.url("/embassy")))
        self.assertIn("نتیجهٔ بررسی صفحه", self.tg.texts[-1])
        await bot.handle_update(self.press(self.tg.button("#main")))
        self.assertIn("Paragraph 0", self.tg.texts[-1])
        await bot.handle_update(self.press("ap"))
        await bot.handle_update(self.press("ai:60"))
        await bot.handle_update(self.press(self.tg.button("کلمات کلیدی")))
        await bot.handle_update(self.message("visa، نوبت"))
        self.assertIn("visa، نوبت", self.tg.texts[-1])
        await bot.handle_update(self.press("ay"))
        self.assertIn("اضافه شد", self.tg.texts[-1])
        self.assertIn("نسخهٔ مرجع", self.tg.texts[-1])
        (record,) = m.registry.records()
        w = record.watch
        self.assertEqual((w.selector, w.interval_seconds, w.keywords, w.name, record.origin),
                         ("#main", 60, ["visa", "نوبت"], "Embassy Visa", "bot"))
        self.assertIn(w.id, [x.id for x in m.watches])
        self.site.set("/embassy", f"<html><body><div id='main'><h1>Visa information</h1>{body}"
                                  "<p>New: visa appointments open on Monday</p></div></body></html>")
        self.assertTrue((await m.check_watch(w)).startswith("CHANGE"))
        await m.dispatch_pending()
        self.assertEqual(self.tg.messages[-1]["chat_id"], self.CHANNEL)
        self.assertIn("appointments open on Monday", self.tg.messages[-1]["text"])

    async def test_manage_pause_rename_crawl_check_and_delete(self):
        self.site.set("/page", page_html(["hello world, this is the embassy page"]))
        m, bot = await self.make_bot([self.page_watch()])
        (record,) = m.registry.records()
        key = record.key
        await bot.handle_update(self.press(f"c:{key}"))
        self.assertIn("Embassy", self.tg.texts[-1])
        await bot.handle_update(self.press(f"t:{key}"))
        self.assertFalse(m.registry.get(key=key).watch.enabled)
        self.assertEqual(m.watches, [])
        await bot.handle_update(self.press(f"t:{key}"))
        self.assertTrue(m.registry.get(key=key).watch.enabled)
        await bot.handle_update(self.press(f"ef:{key}:name"))
        await bot.handle_update(self.message("سفارت جدید"))
        self.assertEqual(m.registry.get(key=key).watch.name, "سفارت جدید")
        await bot.handle_update(self.press(f"eb:{key}:crawl"))
        self.assertIsNotNone(m.registry.get(key=key).watch.crawl)
        await bot.handle_update(self.press(f"k:{key}"))
        self.assertIn("نسخهٔ مرجع", self.tg.texts[-1])
        await bot.handle_update(self.press(f"d:{key}"))
        await bot.handle_update(self.press(f"dy:{key}"))
        self.assertEqual(m.registry.records(), [])
        self.assertEqual(m.all_watches, [])
        await m.close()  # a deleted config watch stays deleted after a restart
        self.monitors.remove(m)
        m2 = await self.monitor([self.page_watch()])
        self.assertEqual(m2.registry.records(), [])

    async def test_export_and_import(self):
        m, bot = await self.make_bot([self.page_watch()])
        await bot.handle_update(self.press("x"))
        exported = json.loads(self.tg.documents[-1]["document"])
        self.assertEqual(exported["watches"][0]["url"], self.url("/page"))
        news = {"name": "News", "url": self.url("/news"), "type": "items", "item_selector": "ul.news > li"}
        self.tg.files["F1"] = json.dumps({"watches": [exported["watches"][0], news]}).encode()
        await bot.handle_update(self.message(document={"file_id": "F1", "file_name": "backup.json"}))
        self.assertIn("۱ سایت جدید", self.tg.texts[-1])
        self.assertIn("۱ تکراری", self.tg.texts[-1])
        await bot.handle_update(self.press("im:y"))
        self.assertEqual(sorted(r.spec["url"] for r in m.registry.records()), [self.url("/news"), self.url("/page")])

    async def test_system_messages_go_to_admins_privately(self):
        self.site.set("/page", "<html><body>down</body></html>", status=503)
        m, bot = await self.make_bot([self.page_watch(error_threshold=1)])
        await bot.handle_update(self.message("/start"))  # registers the admin
        await m.check_watch(m.watches[0])
        await m.dispatch_pending()
        alerts = [data for data in self.tg.messages if "مشکل در بررسی" in data["text"]]
        self.assertEqual([data["chat_id"] for data in alerts], [self.ADMIN])
        await bot.handle_update(self.press("sts"))
        self.assertEqual(m.store.get_setting("system_messages", "admins"), "channels")

    async def test_panel_runs_inside_the_service(self):
        m, _ = await self.make_bot()
        self.tg.updates = [self.message("/start")]
        task = asyncio.create_task(m.run_forever())
        for _ in range(200):
            await asyncio.sleep(0.05)
            if any("پنل مدیریت" in text for text in self.tg.texts):
                break
        m.stop()
        await asyncio.wait_for(task, 20)
        self.assertTrue(any(method == "setMyCommands" for method, _ in self.tg.calls))
        self.assertTrue(any("پنل مدیریت" in text for text in self.tg.texts))

    def serve_goethe(self, records) -> None:
        self.site.set("/gzb2.cfm", goethe_page())
        self.site.set("/rest/examfinderv3/exams/institute/", json.dumps({"DATA": records, "SUCCESS": True}),
                      ctype="application/json;charset=UTF-8")

    async def test_goethe_wizard_with_city_filter(self):
        self.serve_goethe(GOETHE_RECORDS)
        m, bot = await self.make_bot()
        await bot.handle_update(self.message(self.url("/gzb2.cfm")))
        self.assertIn("آزمون گوته", self.tg.texts[-1])
        await bot.handle_update(self.press(self.tg.button("آزمون‌های گوته")))
        self.assertIn("Izmir", self.tg.texts[-1])
        self.assertIn("بیدارباش: روشن", self.tg.texts[-1])
        await bot.handle_update(self.press("aw"))
        await bot.handle_update(self.press(self.tg.button("Izmir")))
        self.assertIn("📍 شهر: Izmir", self.tg.texts[-1])
        self.assertNotIn("Ankara", self.tg.texts[-1])
        await bot.handle_update(self.press("ay"))
        self.assertIn("اضافه شد", self.tg.texts[-1])
        (record,) = m.registry.records()
        w = record.watch
        self.assertEqual((w.type, w.json_filter, w.alarm, w.link, w.keywords),
                         ("json", {"locationName": "Izmir"}, True, self.url("/gzb2.cfm"), ["قابل رزرو", "جای خالی"]))

    async def test_free_seat_is_reported_and_wakes_the_admin_until_acknowledged(self):
        from webmonitor.analyzer import GOETHE

        self.serve_goethe(GOETHE_RECORDS)
        m, bot = await self.make_bot([{
            "id": "g", "name": "Goethe B2", "type": "json", "url": self.url("/rest/examfinderv3/exams/institute/"),
            "link": self.url("/gzb2.cfm"), "json_records": "DATA", "json_template": GOETHE["template"],
            "json_labels": GOETHE["labels"], "keywords": GOETHE["keywords"], "alarm": True}])
        await bot.handle_update(self.message("/start"))  # registers the admin for private alarms
        w = m.watches[0]
        self.assertIn("baseline", await m.check_watch(w))
        self.serve_goethe([dict(GOETHE_RECORDS[0], availability=1), GOETHE_RECORDS[1]])
        self.assertIn("CHANGE", await m.check_watch(w))
        await asyncio.sleep(0.2)  # let the alarm task send its first round
        await m.dispatch_pending()
        channel = [d for d in self.tg.messages if d["chat_id"] == self.CHANNEL]
        self.assertTrue(channel[-1]["text"].startswith("🚨"))
        self.assertIn("<s>⛔ ظرفیت تکمیل</s> <b><u>✅ قابل رزرو</u></b>", channel[-1]["text"])
        self.assertIn(self.url("/gzb2.cfm"), channel[-1]["text"])
        alarms = [d for d in self.tg.messages if d["chat_id"] == self.ADMIN and "هشدار فوری" in d["text"]]
        self.assertEqual(len(alarms), 1)
        self.assertIn("Izmir", alarms[0]["text"])
        ack = alarms[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        await bot.handle_update(self.press(ack))
        self.assertEqual(m._alarms, {})
        self.assertIn("هشدار قطع شد", self.tg.texts[-1])

    async def test_access_test_button_and_proxy_setting(self):
        self.site.set("/page", page_html(["some visible text for the access test " * 8]))
        m, bot = await self.make_bot([self.page_watch()])
        key = m.registry.records()[0].key
        await bot.handle_update(self.press(f"dg:{key}"))
        self.assertIn("تست دسترسی", self.tg.texts[-1])
        self.assertIn("✅ سریع (HTTP)", self.tg.texts[-1])
        await bot.handle_update(self.press(f"ef:{key}:proxy"))
        await bot.handle_update(self.message("socks5://127.0.0.1:40000"))
        self.assertEqual(m.registry.get(key=key).watch.proxy.server, "socks5://127.0.0.1:40000")
        await bot.handle_update(self.press(f"ef:{key}:proxy"))
        await bot.handle_update(self.message("-"))
        self.assertIsNone(m.registry.get(key=key).watch.proxy)

    def last_panel_call(self) -> str:
        return next(method for method, _ in reversed(self.tg.calls) if method in ("sendMessage", "editMessageText"))

    async def test_start_gives_the_keyboard_and_its_buttons_work(self):
        m, bot = await self.make_bot([self.page_watch()])
        await bot.handle_update(self.message("/start"))
        keyboards = [d["reply_markup"] for d in self.tg.messages if "keyboard" in (d.get("reply_markup") or {})]
        self.assertTrue(keyboards and keyboards[0]["is_persistent"])
        await bot.handle_update(self.message("📋 سایت‌ها"))
        self.assertIn("سایت‌های تحت نظر", self.tg.texts[-1])
        self.assertIn("Embassy", self.tg.texts[-1])
        await bot.handle_update(self.message("📊 وضعیت"))
        self.assertIn("وضعیت مانیتور", self.tg.texts[-1])

    async def test_buttons_under_reports_open_new_messages(self):
        m, bot = await self.make_bot([self.page_watch()])
        key = m.registry.records()[0].key
        await bot.handle_update(self.press(f"+c:{key}"))
        self.assertEqual(self.last_panel_call(), "sendMessage")  # the report above stays untouched
        await bot.handle_update(self.press(f"c:{key}"))
        self.assertEqual(self.last_panel_call(), "editMessageText")  # panel navigation edits in place

    async def test_group_commands_answer_in_the_group(self):
        m, bot = await self.make_bot([self.page_watch()])
        bot.username = "monitor_bot"
        group = {"id": int(self.CHANNEL), "type": "supergroup"}

        def group_message(text: str, user: str = self.ADMIN) -> dict:
            return {"update_id": 3, "message": {"message_id": 7, "date": int(time.time()), "chat": group,
                                                 "from": {"id": int(user)}, "text": text}}

        await bot.handle_update(group_message("/status@monitor_bot"))
        self.assertEqual(self.tg.messages[-1]["chat_id"], self.CHANNEL)
        self.assertIn("وضعیت مانیتور", self.tg.messages[-1]["text"])
        await bot.handle_update(group_message("/list@monitor_bot"))
        self.assertIn("Embassy", self.tg.messages[-1]["text"])
        count = len(self.tg.messages)
        await bot.handle_update(group_message("/status@other_bot"))
        await bot.handle_update(group_message("hello everyone"))
        self.assertEqual(len(self.tg.messages), count)
        await bot.handle_update(group_message("/check", user=self.STRANGER))
        self.assertIn("فقط برای مدیران", self.tg.messages[-1]["text"])

    async def test_a_link_sent_during_another_question_starts_a_new_site(self):
        self.site.set("/other", page_html(["Another embassy page with enough text to monitor " * 3]))
        m, bot = await self.make_bot([self.page_watch()])
        key = m.registry.records()[0].key
        await bot.handle_update(self.press(f"ef:{key}:proxy"))
        await bot.handle_update(self.message(self.url("/other")))
        self.assertIsNone(m.registry.get(key=key).watch.proxy)  # never taken for a proxy address
        self.assertIn("نتیجهٔ بررسی صفحه", self.tg.texts[-1])

    async def test_duplicate_sites_are_flagged(self):
        self.site.set("/page", page_html(["embassy text " * 20]))
        m, bot = await self.make_bot([self.page_watch()])
        await bot.handle_update(self.message(self.url("/page")))
        self.assertIn("قبلاً اضافه شده", self.tg.texts[-1])
        await bot.handle_update(self.press("an:f"))
        self.assertIn("نتیجهٔ بررسی صفحه", self.tg.texts[-1])

    async def test_blocked_site_can_be_added_and_is_set_up_once_it_opens(self):
        self.site.set("/exam", "<html><body>Access Denied</body></html>", status=403)
        m, bot = await self.make_bot()
        m.browser.unavailable = "disabled in this test"
        await bot.handle_update(self.message("/start"))
        await bot.handle_update(self.message(self.url("/exam")))
        self.assertIn("از روی سرور باز نشد", self.tg.texts[-1])
        await bot.handle_update(self.press("an:a"))
        self.assertIn("در انتظار باز شدن", self.tg.texts[-1])
        (record,) = m.registry.records()
        self.assertTrue(record.spec.get("_review"))
        self.site.set("/exam", page_html(["Exam dates will be published soon"]))
        self.assertIn("baseline", await m.check_watch(record.watch))
        await m.dispatch_pending()
        tip = self.tg.messages[-1]
        self.assertIn("حالا باز می‌شود", tip["text"])
        self.assertEqual(tip["chat_id"], self.ADMIN)
        self.assertEqual(tip["reply_markup"]["inline_keyboard"][0][0]["callback_data"], f"+er:{record.key}")
        self.assertNotIn("_review", m.registry.records()[0].spec)

    async def test_noisy_page_gets_a_headlines_tip(self):
        self.site.set("/page", page_html(["story 0"]))
        m, bot = await self.make_bot([self.page_watch()])
        await bot.handle_update(self.message("/start"))
        w = m.watches[0]
        await m.check_watch(w)
        for n in range(1, 8):
            self.site.set("/page", page_html([f"story {n}"]))
            await m.check_watch(w)
        await m.dispatch_pending()
        tips = [d for d in self.tg.messages if "پیشنهاد برای" in d["text"]]
        self.assertEqual(len(tips), 1)
        await bot.handle_update(self.press(tips[0]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]))
        self.assertEqual(m.registry.records()[0].watch.type, "headlines")
        self.assertIn("تیترهای جدید", self.tg.texts[-1])

    async def test_private_network_addresses_are_refused(self):
        m, bot = await self.make_bot()
        bot.allow_private_urls = False
        await bot.handle_update(self.message(self.url("/page")))
        self.assertIn("مجاز نیستند", self.tg.texts[-1])
        self.assertEqual(m.registry.records(), [])


class CliTests(unittest.TestCase):
    """The CLI runs its own event loop, so the fake site is served from a thread here."""

    def setUp(self):
        import http.server
        import threading

        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-cli-"))
        body = page_html(["cli test content"]).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.config_path = self.tmp / "cfg.json"
        self.config_path.write_text(json.dumps({
            "data_dir": str(self.tmp / "data"), "notify_startup": False,
            "watches": [{"id": "p", "url": f"http://127.0.0.1:{self.server.server_port}/", "selector": "#main",
                         "engine": "http", "min_content_length": 1}],
        }), encoding="utf-8")

    def tearDown(self):
        self.server.shutdown()
        logging.getLogger().handlers.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args) -> int:
        from webmonitor.cli import main
        with mock.patch("sys.stdout", new=io.StringIO()):
            return main(["-c", str(self.config_path), *args])

    def test_dry_run_never_touches_the_live_state(self):
        self.assertEqual(self.run_cli("once", "--dry-run"), 0)
        live = Store(self.tmp / "data" / "monitor.db")  # the site list is read from here…
        try:
            self.assertEqual([r["watch_id"] for r in live.list_specs()], ["p"])
            self.assertEqual(live.page_urls("p"), set())  # …but no snapshot or notification is written
            self.assertEqual(live.recent_events(), [])
        finally:
            live.close()
        dry = Store(self.tmp / "data" / "dry-run" / "monitor.db")
        try:
            self.assertEqual(len(dry.page_urls("p")), 1)
        finally:
            dry.close()

    def test_package_contains_only_what_the_server_needs(self):
        target = self.tmp / "deploy.zip"
        self.assertEqual(self.run_cli("package", "-o", str(target)), 0)
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
        self.assertIn("webmonitor/engine.py", names)
        self.assertIn("deploy/install_service.sh", names)
        self.assertIn("monitor-config.json", names)
        self.assertFalse([n for n in names if n.startswith((".venv", "data/")) or "__pycache__" in n or "\\" in n])


class BrowserTests(EngineTestCase):
    async def test_auto_engine_switches_to_browser_for_javascript_pages(self):
        if os.environ.get("WEBMONITOR_SKIP_BROWSER"):
            self.skipTest("browser tests disabled")
        self.site.set("/app", "<html><body><div id='main'></div><noscript>Please enable JavaScript</noscript>"
                              "<script>document.getElementById('main').innerHTML ="
                              " '<p>Rendered by JavaScript: appointments open</p>';</script></body></html>")
        m = await self.monitor([{"id": "js", "url": self.url("/app"), "selector": "#main", "engine": "auto",
                                 "min_content_length": 10}])
        w = m.watches[0]
        result = await m.check_watch(w)
        if m.browser.unavailable:
            self.skipTest(f"no browser available: {m.browser.unavailable}")
        self.assertTrue(result.startswith("baseline"), result)
        self.assertEqual(m.engine_for(w), "browser")
        self.assertIn("Rendered by JavaScript", m.store.get_page("js", m._root(w))["snapshot"])
        self.assertEqual(await m.check_watch(w), "no change")

    async def test_screenshot_of_the_monitored_part(self):
        if os.environ.get("WEBMONITOR_SKIP_BROWSER"):
            self.skipTest("browser tests disabled")
        from webmonitor.fetchers import FetchError

        self.site.set("/page", page_html(["Visible text for the screenshot test"]))
        m = await self.monitor([self.page_watch()])
        try:
            image = await m.screenshot(m.watches[0])
        except FetchError as exc:
            self.skipTest(f"no browser available: {exc}")
        self.assertTrue(image.startswith(b"\xff\xd8"))  # JPEG


if __name__ == "__main__":
    unittest.main()
