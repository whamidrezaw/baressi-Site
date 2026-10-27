"""Analyse a URL and suggest how to monitor it (used by `inspect` and by the Telegram panel).

It reports whether plain HTTP is enough or a browser is needed, suggests stable
CSS selectors (scored by amount of real text and low link density), finds
repeated news/announcement lists for "items" watches, and lists RSS/Atom feeds.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from .config import Watch
from .extract import (
    SKIP_TAGS, ExtractError, _compiled, detect_block, document_base, document_title, extract_headlines,
    extract_items, extract_lines, feed_links, json_snapshot, looks_like_feed, page_snapshot, parse_feed, parse_html,
    parse_json_body, visible_text_length,
)
from .fetchers import BrowserFetcher, FetchError, HttpFetcher, ImpersonateFetcher
from .util import clean_text, fa_digits, fa_number, truncate

_DYNAMIC = re.compile(r"\d{3,}|^(css|jsx|sc|svelte|emotion|chakra|tw)-|^_|__[a-z0-9]{4,}$|[a-z]+\d[a-z0-9]{4,}$", re.I)
_STATE_CLASSES = {"active", "selected", "open", "opened", "show", "shown", "hidden", "visible", "current",
                  "collapsed", "expanded", "in", "fade", "disabled", "focus", "hover", "first", "last", "odd", "even"}
_SAFE_IDENT = re.compile(r"^[A-Za-z_-][A-Za-z0-9_-]*$")
_CONTENT_HINT = re.compile(r"content|main|article|body|post|entry|text|news|page|story|detail|inner", re.I)
_CHROME_HINT = re.compile(r"header|nav|menu|footer|sidebar|breadcrumb|cookie|banner|social|share|search", re.I)
_NEWSY = re.compile(r"news|nachrichten|haber|خبر|اخبار|akhbar|khabar", re.I)
_BLOCK_NOTE = re.compile(r"\b(401|403|406|429|503)\b|bot protection|looks like", re.I)
_TITLE_SPLIT = re.compile(r"\s+[-|–—:·•»]\s+")

# Public Telegram channels (t.me/s/<name>): one item per post, identified by the post's own link.
TELEGRAM_POSTS = {
    "type": "items", "selector": ".tgme_widget_message_wrap", "link_selector": "a.tgme_widget_message_date",
    "exclude": [".tgme_widget_message_author", ".tgme_widget_message_views", ".copyonly",
                ".message_media_not_supported_wrap", ".message_video_duration", ".tgme_widget_message_reply"],
}

# Goethe-Institut exam pages load their dates from the "examfinder" JSON API; monitoring the API
# gives exact seat/registration status per exam. Codes come from Goethe's own front-end:
# 1/3 bookable, 4 few places left, 2 fully booked, 11 "bookable from <date>", 12 hidden.
GOETHE = {
    "records": "DATA",
    "template": "📍 {locationName} · 🗓 {startDate} · {isDigital} · {availability} · 💶 {price}",
    "labels": {
        "availability": {"1": "✅ قابل رزرو", "3": "✅ قابل رزرو", "4": "🟢 جای خالی محدود",
                         "2": "⛔ ظرفیت تکمیل", "11": "⏳ رزرو از {bookFrom} ساعت {bookFromTime}",
                         "12": "🚫 غیرفعال"},
        "isDigital": {"true": "💻 لپ‌تاپ", "false": "📝 کاغذی"},
    },
    "keywords": ["قابل رزرو", "جای خالی"],
    "filter_field": "locationName",
}
_JS_APP = re.compile(r"<template[\s>]|\sv-(if|for|bind)=|\sng-app|data-reactroot|__NEXT_DATA__|"
                     r"<div id=\"(app|root)\">\s*</div>", re.I)


_WINDOW_ASSIGNMENT = re.compile(r"window\[['\"]([\w.-]+)['\"]\]\s*=\s*(?=\{)")


def goethe_exam_api(html: str, page_url: str) -> str | None:
    """The examfinder API URL configured on a Goethe exam page (all exams, not just the first 7).

    The page assigns its settings to ``window['<something>DataCF']``; rather than relying on the exact
    variable name, take the first window-level object whose "apipath" points at the examfinder API.
    """
    if "examfinder" not in html:
        return None
    decoder = json.JSONDecoder()
    settings = None
    for match in _WINDOW_ASSIGNMENT.finditer(html):
        try:
            candidate, _ = decoder.raw_decode(html, match.end())
        except ValueError:
            continue
        if isinstance(candidate, dict) and "examfinder" in str(candidate.get("apipath", "")):
            settings = candidate
            break
    if settings is None or not str(settings["apipath"]).startswith("/"):
        return None
    params = {}
    for key, value in settings.items():
        if isinstance(value, (dict, list)):
            continue
        params[key] = ("true" if value else "false") if isinstance(value, bool) else str(value)
    params.update(count="100", start="1", page="1")
    parts = urlsplit(page_url)
    return f"{parts.scheme}://{parts.netloc}{settings['apipath']}?{urlencode(params)}"


# --------------------------------------------------------------------------- selectors

def _stable_classes(el) -> list[str]:
    result = []
    for cls in (el.get("class") or "").split():
        low = cls.lower()
        if (low in _STATE_CLASSES or low.startswith(("is-", "has-", "js-")) or _DYNAMIC.search(cls)
                or not _SAFE_IDENT.match(cls)):
            continue
        result.append(cls)
    return result[:3]


def _simple_selector(el) -> str:
    el_id = el.get("id") or ""
    if el_id and _SAFE_IDENT.match(el_id) and not _DYNAMIC.search(el_id):
        return f"#{el_id}"
    return el.tag.lower() + "".join(f".{c}" for c in _stable_classes(el))


def css_selector_for(doc, el, max_depth: int = 5) -> str | None:
    """A short, stable CSS selector for ``el`` (unique when possible)."""
    parts: list[str] = []
    node = el
    while node is not None and isinstance(node.tag, str) and node.tag.lower() not in ("html", "body"):
        parts.insert(0, _simple_selector(node))
        selector = " > ".join(parts)
        try:
            matches = _compiled(selector)(doc)
        except Exception:
            return None
        if len(matches) == 1 and matches[0] is el:
            return selector
        if len(parts) >= max_depth or parts[0].startswith("#"):
            break  # ancestors above an #id cannot make the selector more specific
        node = node.getparent()
    return " > ".join(parts) if parts else None


def _region_weight(el) -> float:
    """Prefer real content containers over page chrome (header, menus, footer)."""
    tag = el.tag.lower()
    names = f"{el.get('id') or ''} {el.get('class') or ''}"
    if tag in ("header", "nav", "footer", "aside") or _CHROME_HINT.search(names):
        return 0.2
    if tag in ("main", "article") or el.get("role") == "main" or re.search(r"\b(main|content)\b", names, re.I):
        return 1.5
    return 1.0


def content_candidates(doc, limit: int = 12) -> list[dict]:
    elements = []
    for el in doc.iter():
        if not isinstance(el.tag, str):
            continue
        tag = el.tag.lower()
        if tag in SKIP_TAGS or tag in ("html", "head", "body", "a", "span", "li", "p"):
            continue
        if (tag in ("main", "article") or el.get("role") == "main" or el.get("id")
                or _CONTENT_HINT.search(el.get("class") or "")):
            elements.append(el)
        if len(elements) >= 400:
            break
    seen: set[str] = set()
    best_by_text: dict[tuple, dict] = {}
    for el in elements:
        selector = css_selector_for(doc, el)
        if not selector or selector in seen:
            continue
        seen.add(selector)
        lines = extract_lines([el], limit=4000)
        length = sum(map(len, lines))
        if length < 120:
            continue
        link_text = sum(len(clean_text(a.text_content())) for a in el.iter("a"))
        density = min(1.0, link_text / max(1, length))
        candidate = {
            "selector": selector, "length": length, "lines": len(lines), "link_density": density,
            "matches": len(_compiled(selector)(doc)), "score": length * (1 - density) ** 2 * _region_weight(el),
            "preview": truncate(" ".join(lines), 110),
        }
        key = (length, candidate["preview"])  # wrappers with identical text: keep the best/shortest selector
        current = best_by_text.get(key)
        if current is None or (candidate["score"], -len(selector)) > (current["score"], -len(current["selector"])):
            best_by_text[key] = candidate
    results = sorted(best_by_text.values(), key=lambda c: c["score"], reverse=True)
    return results[:limit]


def _signature(el) -> tuple[str, str]:
    classes = _stable_classes(el)
    return el.tag.lower(), classes[0] if classes else ""


def item_candidates(doc, limit: int = 8) -> list[dict]:
    groups: dict[str, dict] = {}
    for parent in doc.iter():
        if not isinstance(parent.tag, str) or parent.tag.lower() in SKIP_TAGS:
            continue
        children = [c for c in parent if isinstance(c.tag, str)]
        if len(children) < 3:
            continue
        for signature, count in Counter(_signature(c) for c in children).items():
            if count < 3:
                continue
            members = [c for c in children if _signature(c) == signature]
            linked = [m for m in members
                      if any((a.get("href") or "").strip() not in ("", "#") for a in m.iter("a"))]
            if len(linked) < 3:
                continue
            texts = [clean_text(m.text_content()) for m in linked]
            average = sum(map(len, texts)) / len(texts)
            if average < 15 or average > 2000:
                continue
            parent_selector = css_selector_for(doc, parent)
            tag, cls = signature
            child = tag + (f".{cls}" if cls else "")
            selector = f"{parent_selector} > {child}" if parent_selector else child
            groups[selector] = {"selector": selector, "count": len(linked), "average": average,
                                "samples": [truncate(t, 90) for t in texts[:3]],
                                "score": len(linked) * min(average, 220)}
    return sorted(groups.values(), key=lambda g: g["score"], reverse=True)[:limit]


# --------------------------------------------------------------------------- analysis

@dataclass
class Analysis:
    url: str
    final_url: str = ""
    engine: str = ""
    status: int = 0
    elapsed: float = 0.0
    content_type: str = ""
    title: str = ""
    html: str = ""
    body: bytes = b""
    error: str = ""
    notes: list = field(default_factory=list)
    block_hint: str = ""
    protected: bool = False      # plain HTTP was refused: a bot wall (poll gently)
    js_app: bool = False         # content is (partly) rendered by JavaScript
    is_feed: bool = False
    feed_items: list = field(default_factory=list)
    feeds: list = field(default_factory=list)
    regions: list = field(default_factory=list)
    lists: list = field(default_factory=list)
    visible: dict = field(default_factory=dict)  # engine -> visible text length
    body_length: int = 0
    exam_api: str = ""           # Goethe examfinder API behind the page
    exam_data: object = None     # its JSON (for the preview)
    blocked: bool = False        # the site refused us (403/429/bot wall): worth retrying through a proxy
    via_proxy: str = ""          # proxy server the page was loaded through
    headlines: int = 0           # links that read like news headlines
    newsy: bool = False          # looks like a news front page (headlines mode is the best fit)


def smart_name(title: str, url: str, limit: int = 45) -> str:
    """A short default name: the page title without long site taglines, else the host name.

    "BBC News - Breaking news, video and …" -> "BBC News"; "آخرین خبر – Telegram" -> "آخرین خبر".
    """
    host = (urlsplit(url).hostname or "").removeprefix("www.")
    parts = [part for part in _TITLE_SPLIT.split(clean_text(title)) if part and part.lower() != "telegram"]
    if not parts:
        return host or url
    name = parts[0]
    for part in parts[1:]:
        if len(name) + 3 + len(part) > limit:
            break
        name = f"{name} - {part}"
    return truncate(name, limit + 15)


def _needs_more(result) -> bool:
    """True when an HTML response is too small or looks like a bot wall."""
    if (not result.text or looks_like_feed(result.content_type, result.body)
            or "json" in result.content_type.lower()):
        return False
    visible = visible_text_length(result.text)
    return visible < 300 or detect_block(result.text, visible) is not None


async def fetch_for_analysis(url: str, http, browser, impersonate=None, *, use_browser: bool = False,
                             wait_for: str = "", proxy=None):
    """Plain HTTP first, then a Chrome-fingerprinted client, then a real browser — whatever works."""
    watch = Watch(id="inspect", url=url, timeout_seconds=45, challenge_wait_seconds=25, proxy=proxy)
    results, notes = {}, []
    if not use_browser:
        for name, fetcher in (("http", http), ("impersonate", impersonate)):
            if fetcher is None or not getattr(fetcher, "available", True):
                continue
            if hasattr(fetcher, "supports") and not fetcher.supports(watch):
                notes.append(f"{name}: cannot use this proxy")
                continue
            try:
                result = await fetcher.fetch(url, watch)
            except FetchError as exc:
                notes.append(f"{name}: {exc}")
                continue
            results[name] = result
            if not _needs_more(result):
                break
            notes.append(f"{name}: little usable text ({visible_text_length(result.text)} chars)")
    if use_browser or not any(not _needs_more(r) for r in results.values()):
        if browser is None or not getattr(browser, "available", True):
            notes.append(f"browser: {getattr(browser, 'unavailable', None) or 'not available'}")
            return results, notes
        try:
            results["browser"] = await browser.fetch(url, watch, wait_for=wait_for)
        except FetchError as exc:
            notes.append(f"browser: {exc}")
    return results, notes


def build_analysis(url: str, results: dict, notes: list) -> Analysis:
    analysis = Analysis(url=url, notes=list(notes))
    if not results:
        blocked = [note for note in notes if _BLOCK_NOTE.search(note)]
        analysis.error = (blocked or notes or ["could not load the page"])[-1]
        analysis.blocked = bool(blocked)
        return analysis
    order = ("browser", "impersonate", "http")
    usable = [name for name in order if name in results and not _needs_more(results[name])]
    engine = usable[0] if usable else next(name for name in order if name in results)
    res = results[engine]
    analysis.protected = engine != "http" and any(
        note.startswith("http:") and re.search(r"\b(403|429|503)\b|bot protection", note) for note in notes)
    analysis.engine, analysis.final_url, analysis.status = engine, res.final_url, res.status
    analysis.elapsed, analysis.content_type = res.elapsed, res.content_type
    analysis.html, analysis.body = res.text or "", res.body or b""
    for name, result in results.items():
        if result.text:
            analysis.visible[name] = visible_text_length(result.text)
    raw = analysis.body or analysis.html.encode("utf-8")
    try:
        if looks_like_feed(res.content_type, raw):
            analysis.feed_items = parse_feed(raw, res.final_url)
            analysis.is_feed = True
            return analysis
        if not analysis.html:
            analysis.error = f"not an HTML page (Content-Type: {res.content_type or 'unknown'})"
            return analysis
        doc = parse_html(analysis.html, res.final_url)
        base = document_base(doc, res.final_url)
        analysis.title = document_title(doc)
        analysis.block_hint = detect_block(analysis.html) or ""
        analysis.blocked = bool(analysis.block_hint) and analysis.block_hint != "JavaScript required"
        analysis.js_app = engine != "browser" and bool(_JS_APP.search(analysis.html))
        analysis.exam_api = goethe_exam_api(analysis.html, res.final_url) or ""
        analysis.feeds = feed_links(doc, base)
        analysis.regions = content_candidates(doc)
        analysis.lists = item_candidates(doc)
        analysis.body_length = page_snapshot(parse_html(analysis.html, res.final_url), base).text_length
        headlines = extract_headlines(parse_html(analysis.html, res.final_url), base)
        analysis.headlines = len(headlines)
        title_chars = sum(len(item.title) for item in headlines)
        analysis.newsy = analysis.headlines >= 15 and (
            bool(_NEWSY.search(f"{urlsplit(res.final_url).hostname} {urlsplit(res.final_url).path} {analysis.title}"))
            or title_chars >= 0.3 * max(1, analysis.body_length))
    except ExtractError as exc:
        analysis.error = str(exc)
    return analysis


async def _load_exam_data(analysis: Analysis, fetchers: list, proxy=None) -> None:
    watch = Watch(id="inspect", url=analysis.exam_api, timeout_seconds=30, proxy=proxy)
    for fetcher in fetchers:
        if fetcher is None or not getattr(fetcher, "available", True):
            continue
        if hasattr(fetcher, "supports") and not fetcher.supports(watch):
            continue
        try:
            result = await fetcher.fetch(analysis.exam_api, watch)
            analysis.exam_data = parse_json_body(result.text)
            return
        except (FetchError, ExtractError) as exc:
            analysis.notes.append(f"exam API via {fetcher.engine}: {exc}")


async def analyze(config, url: str, *, http=None, browser=None, impersonate=None, use_browser: bool = False,
                  wait_for: str = "", proxy=None) -> Analysis:
    """Fetch and analyse a URL (through ``proxy`` when given). Pass the running monitor's fetchers to
    reuse its sessions/browser."""
    owned = []
    if http is None:
        http = HttpFetcher(config)
        owned.append(http)
    if impersonate is None:
        impersonate = ImpersonateFetcher(config)
        owned.append(impersonate)
    if browser is None:
        browser = BrowserFetcher(config)
        owned.append(browser)
    try:
        results, notes = await fetch_for_analysis(url, http, browser, impersonate, use_browser=use_browser,
                                                  wait_for=wait_for, proxy=proxy)
        analysis = await asyncio.to_thread(build_analysis, url, results, notes)
        if proxy is not None:
            analysis.via_proxy = proxy.server
        if analysis.exam_api:
            first = impersonate if analysis.engine in ("impersonate", "browser") else http
            await _load_exam_data(analysis, [first, impersonate, browser], proxy)
    finally:
        for fetcher in owned:
            await fetcher.close()
    return analysis


def _short(text: str, limit: int) -> str:
    return truncate(text.split("://", 1)[-1], limit)


def _exam_records(analysis: Analysis) -> list:
    data = analysis.exam_data
    records = data.get(GOETHE["records"]) if isinstance(data, dict) else None
    return records if isinstance(records, list) else []


def suggest_choices(analysis: Analysis, max_regions: int = 3, max_lists: int = 2) -> list[dict]:
    """What could be monitored on this page, best first (each becomes a button in the panel).

    Every choice has a short button ``label`` and a one-line ``desc`` that explains what will be
    reported; the first one is marked ``recommended``.
    """
    if analysis.is_feed:
        return [{"type": "feed", "url": analysis.final_url, "recommended": True,
                 "label": f"📡 خبرخوان RSS ({fa_digits(len(analysis.feed_items))} خبر)",
                 "desc": "هر خبر تازهٔ این خبرخوان با تیتر و لینک گزارش می‌شود."}]
    parts = urlsplit(analysis.final_url or analysis.url)
    if parts.hostname in ("t.me", "telegram.me") and parts.path.startswith("/s/"):
        return [{**TELEGRAM_POSTS, "recommended": True, "label": "📢 پست‌های جدید کانال",
                 "desc": "هر پست تازهٔ کانال با متن کامل و لینک گزارش می‌شود."}]
    choices = []
    if analysis.exam_api and analysis.exam_data is not None:
        choices.append({"type": "json", "url": analysis.exam_api, "page": analysis.final_url, "preset": "goethe",
                        "label": f"🎓 آزمون‌های گوته ({fa_digits(len(_exam_records(analysis)))} آزمون)",
                        "desc": "ظرفیت و زمان ثبت‌نام هر آزمون؛ باز شدن ظرفیت یا شروع ثبت‌نام فوراً خبر داده می‌شود."})
    headlines = {"type": "headlines", "selector": "",
                 "label": f"📰 تیترهای جدید ({fa_digits(analysis.headlines)} تیتر)",
                 "desc": "فقط خبرهای تازه با تیتر و لینک؛ جابه‌جایی مطالب و تغییر زمان‌ها نادیده گرفته می‌شود."}
    if analysis.newsy:
        choices.append(headlines)
    choices += [{"type": "feed", "url": feed, "label": f"📡 RSS: {_short(feed, 28)}",
                 "desc": "خبرخوان رسمی سایت؛ دقیق و سبک."} for feed in analysis.feeds[:2]]
    # Menus and headers (mostly links) make poor monitoring targets; keep them out of the buttons.
    regions = [r for r in analysis.regions if r["link_density"] <= 0.5] or analysis.regions[:1]
    for region in regions[:max_regions]:
        choices.append({"type": "page", "selector": region["selector"],
                        "label": f"📄 بخش {_short(region['selector'], 24)} ({fa_number(region['length'])} حرف)",
                        "desc": "هر تغییر متن این بخش (اضافه، حذف، ویرایش) با جزئیات کلمه‌به‌کلمه."})
    choices.append({"type": "page", "selector": "", "label": f"🌐 کل صفحه ({fa_number(analysis.body_length)} حرف)",
                    "desc": "همه‌چیز حتی منو و پاورقی؛ کامل‌ترین حالت ولی پرپیام‌تر."})
    if not analysis.newsy and analysis.headlines >= 5:
        choices.append(headlines)
    lists = [g for g in analysis.lists if not _CHROME_HINT.search(g["selector"])]
    for group in lists[:max_lists]:
        choices.append({"type": "items", "selector": group["selector"],
                        "label": f"📌 فهرست {fa_digits(group['count'])} موردی ({_short(group['selector'], 18)})",
                        "desc": "فقط موارد تازهٔ یک فهرست مشخص (مثلاً اطلاعیه‌ها یا اخبار یک ستون)."})
    if choices:
        choices[0]["recommended"] = True
    return choices


def choice_filter_values(analysis: Analysis, choice: dict) -> list[str]:
    """Distinct values a JSON preset can be filtered by (e.g. the Goethe exam cities)."""
    if choice.get("preset") != "goethe":
        return []
    return sorted({str(r.get(GOETHE["filter_field"]) or "").strip() for r in _exam_records(analysis)} - {""})


def preview_choice(analysis: Analysis, choice: dict, limit: int = 12,
                   json_filter: dict | None = None) -> tuple[list[str], int]:
    """(first lines, total size) that a watch built from ``choice`` would see. Raises ExtractError."""
    if choice["type"] == "json":
        snap = json_snapshot(analysis.exam_data, GOETHE["records"], GOETHE["template"], GOETHE["labels"],
                             json_filter)
        return snap.lines[:limit], len(snap.lines)
    if choice["type"] == "feed":
        items = choice.get("items")
        if items is None:
            items = analysis.feed_items
        return [f"• {item.title}" for item in items[:limit]], len(items)
    doc = parse_html(analysis.html, analysis.final_url)
    base = document_base(doc, analysis.final_url)
    if choice["type"] == "headlines":
        items = extract_headlines(doc, base, choice.get("selector", ""))
        return [f"• {item.title}" for item in items[:limit]], len(items)
    if choice["type"] == "items":
        items = extract_items(doc, base, choice["selector"], choice.get("link_selector", ""),
                              choice.get("exclude", []))
        return [f"• {item.title}" for item in items[:limit]], len(items)
    snap = page_snapshot(doc, base, selector=choice.get("selector", ""), exclude_selectors=choice.get("exclude", []))
    return snap.lines[:limit], snap.text_length


# --------------------------------------------------------------------------- CLI `inspect`

def _print_header(title: str) -> None:
    print(f"\n=== {title} ===")


async def inspect(config, url: str, *, use_browser: bool = False, selector: str = "", items: str = "") -> int:
    analysis = await analyze(config, url, use_browser=use_browser, wait_for=selector or items)
    for note in analysis.notes:
        print(note)
    if not analysis.final_url:
        print(f"\nCould not load the page: {analysis.error}")
        return 1
    _print_header("Fetch")
    print(f"{analysis.engine:>8}: HTTP {analysis.status}  {analysis.elapsed:.1f}s  final URL: {analysis.final_url}")
    if len(analysis.visible) > 1:
        print("visible text — " + ", ".join(f"{k}: {v:,} chars" for k, v in analysis.visible.items()))

    if analysis.is_feed:
        _print_header(f"RSS/Atom feed — {len(analysis.feed_items)} items")
        for item in analysis.feed_items[:10]:
            print(f" • {item.title}\n   {item.url or ''}")
        snippet = {"id": "my_feed", "name": "...", "type": "feed", "url": url, "interval_seconds": 60}
        _print_header("Suggested watch (copy into \"watches\")")
        print(json.dumps(snippet, ensure_ascii=False, indent=2))
        return 0
    if analysis.error:
        print(f"\n{analysis.error}")
        return 1

    print(f"title: {analysis.title}")
    if analysis.block_hint:
        print(f"WARNING: the page looks like {analysis.block_hint} — content may be incomplete.")
    if analysis.js_app:
        print("NOTE: parts of this page are rendered by JavaScript; if what you need is missing below, "
              "use engine \"browser\" (or monitor the page's data API).")
    if analysis.exam_api:
        lines, count = (preview_choice(analysis, {"type": "json"}, limit=10) if analysis.exam_data is not None
                        else ([], 0))
        _print_header(f"Goethe exam API (seat availability) — {count} exams")
        for line in lines:
            print(f"  {line}")
        snippet = {"id": "goethe_exams", "name": analysis.title[:60], "type": "json", "url": analysis.exam_api,
                   "link": analysis.final_url, "json_records": GOETHE["records"], "json_template": GOETHE["template"],
                   "json_labels": GOETHE["labels"], "keywords": GOETHE["keywords"], "alarm": True,
                   "interval_seconds": 60}
        print("Suggested watch:\n" + json.dumps(snippet, ensure_ascii=False, indent=2))
    if analysis.feeds:
        _print_header("RSS/Atom feeds advertised by this page (best for news sites)")
        for feed in analysis.feeds:
            print(f" • {feed}")

    if selector:
        try:
            doc = parse_html(analysis.html, analysis.final_url)
            snap = page_snapshot(doc, document_base(doc, analysis.final_url), selector=selector, track_links=True)
        except ExtractError as exc:
            print(f"\n{exc}")
            return 1
        _print_header(f"Text monitored by selector {selector!r}: {len(snap.lines)} lines, "
                      f"{snap.text_length:,} chars, {len(snap.links)} links")
        for line in snap.lines[:80]:
            print(f"  {truncate(line, 160)}")
        if len(snap.lines) > 80:
            print(f"  … {len(snap.lines) - 80} more lines")
        print(f"\nTip: set \"min_content_length\" to about {max(30, snap.text_length // 2)} for this selector.")
        return 0

    if items:
        try:
            found_lines, count = preview_choice(analysis, {"type": "items", "selector": items}, limit=20)
        except ExtractError as exc:
            print(f"\n{exc}")
            return 1
        _print_header(f"Items matched by {items!r}: {count}")
        for line in found_lines:
            print(f" {truncate(line, 140)}")
        return 0 if count else 1

    _print_header("Content regions (best first) — use as \"selector\"")
    for c in analysis.regions:
        multi = f"  [{c['matches']} matches]" if c["matches"] > 1 else ""
        print(f"  {c['length']:>7,} chars  links {c['link_density']:>4.0%}  {c['selector']}{multi}")
        print(f"           {c['preview']}")
    if analysis.lists:
        _print_header("Repeated lists (news/announcements) — use as \"item_selector\" with type \"items\"")
        for g in analysis.lists:
            print(f"  {g['count']:>3} items  ~{g['average']:.0f} chars  {g['selector']}")
            for sample in g["samples"]:
                print(f"           · {sample}")

    best = analysis.regions[0]["selector"] if analysis.regions else ""
    snippet = {"id": "my_site", "name": analysis.title[:60] or "...", "url": url, "selector": best,
               "engine": analysis.engine, "interval_seconds": 120, "track_links": True}
    _print_header("Suggested watch (copy into \"watches\" and adjust)")
    print(json.dumps(snippet, ensure_ascii=False, indent=2))
    print("\nNext: preview exactly what will be monitored with\n"
          f"  python monitor_system.py inspect \"{url}\" --selector \"{best}\"")
    return 0
