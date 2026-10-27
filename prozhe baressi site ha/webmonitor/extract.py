"""Turn fetched HTML / feeds into normalised, comparable content.

The same Python extractor is used for both engines (raw HTTP HTML and the
browser-rendered DOM), so switching engines never changes how text is read.
Hidden elements (accordions, tabs) are included on purpose: embassy pages often
keep important details in collapsed sections.
"""

from __future__ import annotations

import copy
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import lxml.html
from lxml import etree
from lxml.cssselect import CSSSelector

from .util import clean_text, has_alnum, sha256_text, truncate, word_count

SKIP_TAGS = frozenset({
    "script", "style", "noscript", "template", "svg", "math", "canvas", "head", "title",
    "meta", "link", "iframe", "object", "embed", "audio", "video", "picture", "source",
    "track", "map",
})
BLOCK_TAGS = frozenset({
    "address", "article", "aside", "blockquote", "body", "caption", "center", "dd", "details",
    "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "html", "legend", "li", "main",
    "menu", "nav", "ol", "optgroup", "option", "p", "section", "summary", "table", "tbody",
    "tfoot", "thead", "tr", "ul",
})
CELL_TAGS = frozenset({"td", "th"})
_HEADING_TAGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
# Cookie/consent overlays injected by well-known consent managers.
DEFAULT_EXCLUDES = (
    "#onetrust-consent-sdk", "#CybotCookiebotDialog", "#usercentrics-root", ".cc-window",
    "#cookie-law-info-bar", "#cmplz-cookiebanner-container",
)
# Used for crawled sub-pages when the configured selector is missing there.
FALLBACK_SELECTORS = ("main", "[role=main]", "article", "#content", "#main", ".content")
FILE_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".zip",
})
ASSET_EXTENSIONS = frozenset({
    ".css", ".js", ".mjs", ".json", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".webm", ".ogg", ".wav", ".avi", ".mov", ".mkv", ".m4a", ".exe", ".msi", ".dmg", ".apk",
    ".rar", ".7z", ".gz", ".tar", ".xml", ".rss", ".atom",
})
MAX_LINES = 20000
MAX_DEPTH = 400
_CELL = ""
_TRACKING_PARAM = re.compile(
    r"^(utm_\w+|fbclid|gclid|dclid|gbraid|wbraid|msclkid|mc_cid|mc_eid|yclid|igshid|_ga|_gl|ref_src)$", re.I
)
# Extra click-tracking parameters news sites add to article links (only ignored when identifying headlines).
_HEADLINE_TRACKING = re.compile(r"^(at_\w+|ns_\w+|itm_\w+|intcmp|cmpid|xtor|ocid|s_cid|spm|mkt_tok|trk\w*)$", re.I)
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_EMPTY_CELLS = re.compile(r"(?:\s*\|\s*)+")
_UNSAFE_PATH_RE = re.compile(r"[^\x21-\x7e]|[\"<>\\^`{|}]")

# Text that changes by itself — relative times ("5 mins ago", "۳ ساعت پیش"), reading times, video
# players — is never a real change, so it is removed before pages are compared. Absolute dates stay.
_UNITS_EN = r"(?:s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?|w|wks?|weeks?|mos?|months?|y|yrs?|years?)"
NOISE_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in (
    rf"\b\d+\s*{_UNITS_EN}\s+ago\b",
    r"\b(?:an?|one|a few)\s+(?:seconds?|minutes?|hours?|days?|weeks?|months?|years?)\s+ago\b",
    r"\b(?:just now|moments? ago)\b",
    r"\b\d+\s*-?\s*(?:min|mins|minute|minutes)\s+read\b",
    r"\bvideo playing\s+\d{1,2}:\d{2}(?::\d{2})?",
    r"\d+\s*(?:ثانیه|دقیقه|ساعت|روز|هفته|ماه|سال)\s*(?:پیش|قبل(?!\s*از))(?![\w‌])",
    r"(?<![\w‌])(?:(?:یک|دو|سه|چند)\s*(?:ثانیه|دقیقه|ساعت|روز|هفته|ماه|سال)|لحظاتی|لحظه‌ای|دقایقی|ساعاتی"
    r"|ساعتی|دقیقه‌ای)\s*پیش(?![\w‌])",
    r"\bvor\s+(?:\d+|einer?|einem|wenigen)\s+(?:Sekunden?|Minuten?|Stunden?|Tag(?:en)?|Wochen?|Monat(?:en)?|Jahr(?:en)?)\b",
    r"\bgerade eben\b",
    r"\b\d+\s*(?:saniye|dakika|saat|gün|hafta|ay|yıl)\s+önce\b",
    r"\bil y a\s+\d+\s*(?:s|sec|secondes?|min|minutes?|h|heures?|jours?)\b",
    r"منذ\s+\d+\s*(?:ثانية|ثوان|دقيقة|دقائق|ساعة|ساعات|يوم|أيام)",
))
# Parts of an item that describe the post rather than being its content (Telegram: author, views, time).
_ITEM_META = (".tgme_widget_message_footer",)
HEADLINE_MIN_WORDS = 4


class ExtractError(Exception):
    """The fetched document does not contain usable content."""

    def __init__(self, message: str, kind: str = "content"):
        super().__init__(message)
        self.kind = kind  # selector | short | type | parse | empty


@dataclass
class Snapshot:
    lines: list
    links: list = field(default_factory=list)  # [(text, url)]
    title: str = ""
    headings: list = field(default_factory=list)  # parallel to lines; "" when no heading applies
    anchors: list = field(default_factory=list)   # parallel to lines; the DOM id near that line

    @property
    def digest(self) -> str:
        return sha256_text(json.dumps([self.lines, self.links], ensure_ascii=False))

    @property
    def text_length(self) -> int:
        return sum(len(line) for line in self.lines)

    def to_json(self) -> str:
        return json.dumps({"v": 3, "title": self.title, "lines": self.lines, "links": self.links,
                          "headings": self.headings, "anchors": self.anchors}, ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> Snapshot:
        data = json.loads(raw)
        lines = list(data.get("lines", []))
        links = [tuple(x) for x in data.get("links", [])]
        headings = list(data.get("headings", []))
        if len(headings) < len(lines):
            headings += [""] * (len(lines) - len(headings))
        elif len(headings) > len(lines):
            headings = headings[:len(lines)]
        anchors = list(data.get("anchors", []))
        if len(anchors) < len(lines):
            anchors += [""] * (len(lines) - len(anchors))
        elif len(anchors) > len(lines):
            anchors = anchors[:len(lines)]
        return cls(lines, links, data.get("title", ""), headings, anchors)


@dataclass
class Item:
    id: str
    title: str
    url: str | None
    text: str
    published: str = ""


# --------------------------------------------------------------------------- URLs

def normalize_url(url: str) -> str | None:
    """Canonical absolute http(s) URL without fragment or tracking parameters."""
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        netloc = parts.netloc.lower()
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        path = parts.path or "/"
        path = _UNSAFE_PATH_RE.sub(lambda m: quote(m.group()), path)
        path = _PCT_RE.sub(lambda m: m.group().upper(), path)
        query = parts.query
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            kept = [(k, v) for k, v in pairs if not _TRACKING_PARAM.match(k)]
            if len(kept) != len(pairs):
                query = urlencode(kept)
        return urlunsplit((scheme, netloc, path, query, ""))
    except ValueError:
        return None


def url_extension(url: str) -> str:
    path = urlsplit(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    return name[name.rfind("."):] if "." in name else ""


def same_site(host_a: str | None, host_b: str | None) -> bool:
    strip = lambda h: (h or "").lower().removeprefix("www.")
    return strip(host_a) == strip(host_b)


# --------------------------------------------------------------------------- HTML

def parse_html(text: str, url: str) -> lxml.html.HtmlElement:
    if not text or not text.strip():
        raise ExtractError("empty document", kind="empty")
    parser = lxml.html.HTMLParser(encoding="utf-8", remove_comments=True, remove_pis=True)
    try:
        doc = lxml.html.document_fromstring(text.encode("utf-8", "replace"), parser=parser, base_url=url)
    except (etree.ParserError, ValueError) as exc:
        raise ExtractError(f"could not parse HTML: {exc}", kind="parse") from None
    return doc


def document_base(doc, url: str) -> str:
    base = doc.find(".//base[@href]")
    if base is not None:
        try:
            return urljoin(url, base.get("href", "").strip())
        except ValueError:
            pass
    return url


def document_title(doc) -> str:
    return clean_text(doc.findtext(".//title") or "")


@lru_cache(maxsize=512)
def _compiled(selector: str) -> CSSSelector:
    return CSSSelector(selector, translator="html")


def select_all(doc, selector: str) -> list:
    """All matches of a CSS selector, without matches nested inside other matches."""
    found = _compiled(selector)(doc)
    if len(found) < 2:
        return found
    matched = set(found)
    return [el for el in found if not any(a in matched for a in el.iterancestors())]


def drop_selectors(doc, selectors) -> None:
    for selector in selectors:
        for el in _compiled(selector)(doc):
            if el.getparent() is not None:
                el.drop_tree()


class _Lines:
    __slots__ = ("lines", "headings", "anchors", "_buf", "_limit", "_stack", "_id_stack")

    def __init__(self, limit: int):
        self.lines: list[str] = []
        self.headings: list[str] = []  # parallel to lines; the DOM heading at that point
        self.anchors: list[str] = []   # parallel to lines; nearest DOM id
        self._buf: list[str] = []
        self._limit = limit
        self._stack: list[str] = []  # current heading stack
        self._id_stack: list[str] = []  # current element-id stack

    def push_heading(self, text: str | None) -> None:
        if text:
            self._stack.append(text)

    def pop_heading(self) -> None:
        if self._stack:
            self._stack.pop()

    def push_anchor(self, el_id: str | None) -> None:
        if el_id:
            self._id_stack.append(el_id)

    def pop_anchor(self) -> None:
        if self._id_stack:
            self._id_stack.pop()

    def _current_anchor(self) -> str:
        return self._id_stack[-1] if self._id_stack else ""

    def _current(self) -> str:
        # Two levels are enough: h1 · h2. Longer stacks would just eat space.
        if not self._stack:
            return ""
        return " · ".join(self._stack[-2:])

    def text(self, value: str | None) -> None:
        if value:
            self._buf.append(value)

    def cell(self) -> None:
        self._buf.append(_CELL)

    def br(self) -> None:
        if not self._buf:
            return
        raw = "".join(self._buf)
        self._buf.clear()
        if _CELL in raw:
            line = " | ".join(p for p in (clean_text(part) for part in raw.split(_CELL)) if p)
        else:
            line = clean_text(raw)
        if line and has_alnum(line) and len(self.lines) < self._limit:
            self.lines.append(line)
            self.headings.append(self._current())
            self.anchors.append(self._current_anchor())


def _walk(el, out: _Lines, depth: int) -> None:
    tag = el.tag
    if not isinstance(tag, str):  # comment / processing instruction
        return
    tag = tag.lower()
    if tag in SKIP_TAGS or depth > MAX_DEPTH:
        return
    if tag == "br":
        out.br()
        return
    if tag == "pre":
        out.br()
        for line in el.text_content().splitlines():
            out.text(line)
            out.br()
        return
    is_heading = tag in _HEADING_TAGS
    el_id = el.get("id") or ""
    if is_heading:
        out.push_heading(clean_text(el.text_content()))
    if el_id:
        out.push_anchor(el_id)
    try:
        block = tag in BLOCK_TAGS
        if block:
            out.br()
        out.text(el.text)
        for child in el:
            _walk(child, out, depth + 1)
            out.text(child.tail)
        if tag in CELL_TAGS:
            out.cell()
        elif block:
            out.br()
    finally:
        if el_id:
            out.pop_anchor()
        if is_heading:
            out.pop_heading()


def extract_lines(roots, limit: int = MAX_LINES, return_headings: bool = False):
    out = _Lines(limit)
    for root in roots:
        out.br()
        _walk(root, out, 0)
        out.br()
    if return_headings:
        headings = out.headings[:]
        if len(headings) < len(out.lines):
            headings += [""] * (len(out.lines) - len(headings))
        anchors = out.anchors[:]
        if len(anchors) < len(out.lines):
            anchors += [""] * (len(out.lines) - len(anchors))
        return out.lines, headings, anchors
    return out.lines


def apply_ignore(lines: list[str], patterns=(), noise: bool = True) -> list[str]:
    """Remove self-changing noise (see NOISE_PATTERNS) and the watch's own ignore patterns."""
    patterns = (*NOISE_PATTERNS, *patterns) if noise else tuple(patterns)
    if not patterns:
        return lines
    result = []
    for line in lines:
        cleaned = line
        for pattern in patterns:
            cleaned = pattern.sub(" ", cleaned)
        if cleaned != line:
            cleaned = _EMPTY_CELLS.sub(" | ", clean_text(cleaned)).strip(" |")  # tidy cells emptied by a pattern
        if cleaned and has_alnum(cleaned):
            result.append(cleaned)
    return result


def apply_ignore_keep_headings(lines: list[str], headings: list[str], patterns=(), noise: bool = True,
                              anchors: list[str] | None = None):
    """Same as apply_ignore, but filters ``headings`` in parallel so they stay aligned."""
    patterns = (*NOISE_PATTERNS, *patterns) if noise else tuple(patterns)
    anchors = anchors or [""] * len(lines)
    if not patterns:
        return lines, headings, anchors
    result_lines: list[str] = []
    result_headings: list[str] = []
    result_anchors: list[str] = []
    for idx, line in enumerate(lines):
        cleaned = line
        for pattern in patterns:
            cleaned = pattern.sub(" ", cleaned)
        if cleaned != line:
            cleaned = _EMPTY_CELLS.sub(" | ", clean_text(cleaned)).strip(" |")
        if cleaned and has_alnum(cleaned):
            result_lines.append(cleaned)
            result_headings.append(headings[idx] if idx < len(headings) else "")
            result_anchors.append(anchors[idx] if idx < len(anchors) else "")
    return result_lines, result_headings, result_anchors


def _link_url(a, base_url: str) -> str | None:
    href = (a.get("href") or "").strip()
    if not href or href.startswith("#"):
        return None
    if href[:11].lower().startswith(("javascript:", "mailto:", "tel:", "data:", "sms:")):
        return None
    try:
        return normalize_url(urljoin(base_url, href))
    except ValueError:
        return None


def _link_label(a) -> str:
    """Readable text of a link: its first real line (a card link holds headline, teaser, time, …)."""
    lines = apply_ignore(extract_lines([a], limit=20))
    if lines:
        return next((line for line in lines if word_count(line) >= 3), max(lines, key=len))
    image = a.find(".//img[@alt]")
    return clean_text(a.get("aria-label") or a.get("title") or (image.get("alt") if image is not None else ""))


def _label_score(label: str) -> tuple:
    return word_count(label) >= 3, min(len(label), 200)


def extract_links(roots, base_url: str) -> list[tuple[str, str]]:
    """(label, url) of every link; when a URL is linked several times (image + headline), the most
    descriptive label wins."""
    labels: dict[str, str] = {}
    for root in roots:
        for a in root.iter("a", "area"):
            url = _link_url(a, base_url)
            if not url:
                continue
            label = _link_label(a)
            current = labels.get(url)
            if current is None or _label_score(label) > _label_score(current):
                labels[url] = label
    return [(truncate(label, 300), url) for url, label in labels.items()]


def page_snapshot(doc, base_url: str, *, selector: str = "", exclude_selectors=(), ignore_patterns=(),
                  track_links: bool = False, fallback: bool = False) -> Snapshot:
    """Extract the monitored region of a page. Mutates ``doc`` (drops excluded elements)."""
    title = document_title(doc)
    drop_selectors(doc, DEFAULT_EXCLUDES)
    drop_selectors(doc, exclude_selectors)
    roots = select_all(doc, selector) if selector else []
    if selector and not roots and fallback:
        for candidate in FALLBACK_SELECTORS:
            roots = select_all(doc, candidate)
            if roots:
                break
    if selector and not roots and not fallback:
        raise ExtractError(f"selector {selector!r} matched nothing on the page", kind="selector")
    if not roots:
        body = doc.find("body")
        roots = [body if body is not None else doc]
    raw_lines, raw_headings, raw_anchors = extract_lines(roots, return_headings=True)
    lines, headings, anchors = apply_ignore_keep_headings(raw_lines, raw_headings, ignore_patterns,
                                                          anchors=raw_anchors)
    links = extract_links(roots, base_url) if track_links else []
    return Snapshot(lines, links, title, headings, anchors)


def _item_anchor(el, link_selector: str):
    if link_selector:
        found = _compiled(link_selector)(el)
        return found[0] if found else None
    if el.tag == "a" and el.get("href"):
        return el
    for candidate in el.iter("a"):
        href = (candidate.get("href") or "").strip()
        if href and not href.startswith(("#", "javascript:")):
            return candidate
    return None


def extract_items(doc, base_url: str, item_selector: str, link_selector: str = "",
                  exclude_selectors=(), ignore_patterns=()) -> list[Item]:
    """List entries (news headlines, announcements, posts) identified by their link.

    Lines repeated in most entries (a channel's signature, "Read more") are boilerplate and left out
    of the text; a ``<time datetime>`` inside an entry becomes its publication time.
    """
    drop_selectors(doc, exclude_selectors)
    raw: list[tuple] = []
    for el in select_all(doc, item_selector):
        anchor = _item_anchor(el, link_selector)
        url = _link_url(anchor, base_url) if anchor is not None else None
        stamp = el.find(".//time[@datetime]")
        published = clean_text(stamp.get("datetime")) if stamp is not None else ""
        text_root = el
        if published or any(_compiled(selector)(el) for selector in _ITEM_META):
            text_root = copy.deepcopy(el)  # describe the entry without its meta data (author, views, time)
            drop_selectors(text_root, _ITEM_META)
            if published:
                drop_selectors(text_root, ("time",))
        lines = apply_ignore(extract_lines([text_root], limit=300), ignore_patterns)
        if lines:
            # The headline is usually the entry's first link; with an explicit link selector (e.g. the date
            # link of a Telegram post) or a very short link text, the first substantial line is used.
            link_text = clean_text(anchor.text_content()) if anchor is not None and not link_selector else ""
            raw.append((url, lines, link_text, published))
    common: set[str] = set()
    if len(raw) >= 4:
        counts = Counter(line for _, lines, _, _ in raw for line in set(lines))
        common = {line for line, n in counts.items() if n >= max(3, math.ceil(0.6 * len(raw)))}
    items: list[Item] = []
    seen: set[str] = set()
    for url, lines, link_text, published in raw:
        lines = [line for line in lines if line not in common] or lines
        title = link_text if len(link_text) >= 3 else next((line for line in lines if len(line) >= 20), lines[0])
        body = [line for line in lines if line != title]
        text = "\n".join(lines)
        item_id = url or "h:" + sha256_text(text)[:20]
        if item_id in seen:
            item_id += "#" + sha256_text(text)[:10]
            if item_id in seen:
                continue
        seen.add(item_id)
        items.append(Item(item_id, truncate(title, 300), url, truncate("\n".join(body), 3000), published))
    return items


def headline_id(url: str) -> str:
    """A story's identity: its URL without the click-tracking parameters news sites rotate."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _HEADLINE_TRACKING.match(k)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))


_CHROME_ROLES = frozenset({"navigation", "menu", "menubar", "banner", "contentinfo"})


def _in_page_chrome(el) -> bool:
    """Inside the site's menus, header bar or footer (not a news list)."""
    for ancestor in el.iterancestors():
        tag = ancestor.tag.lower() if isinstance(ancestor.tag, str) else ""
        if tag in ("nav", "footer") or (ancestor.get("role") or "").lower() in _CHROME_ROLES:
            return True
    return False


def site_brand(host: str | None) -> str:
    """'bbc' for www.bbc.com and news.bbc.co.uk: tells a site's own links from ads and other sites."""
    labels = (host or "").lower().removeprefix("www.").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def extract_headlines(doc, base_url: str, selector: str = "", exclude_selectors=(), ignore_patterns=(),
                      min_words: int = HEADLINE_MIN_WORDS, limit: int = 400) -> list[Item]:
    """News headlines: every link of the site (on the page, or inside ``selector``) whose text reads
    like a title.

    A story is identified by its link, so it is reported once — when it first appears — however its
    teaser, time stamp or position on the page change afterwards. Menu and category links are too
    short to count as headlines, and links to other sites (ads, "recommended for you") are skipped.
    """
    drop_selectors(doc, DEFAULT_EXCLUDES)
    drop_selectors(doc, exclude_selectors)
    roots = select_all(doc, selector) if selector else []
    if selector and not roots:
        raise ExtractError(f"selector {selector!r} matched nothing on the page", kind="selector")
    if not roots:
        body = doc.find("body")
        roots = [body if body is not None else doc]
    brand = site_brand(urlsplit(base_url).hostname)
    found: dict[str, Item] = {}
    for root in roots:
        for a in root.iter("a"):
            url = _link_url(a, base_url)
            if not url or site_brand(urlsplit(url).hostname) != brand or _in_page_chrome(a):
                continue
            lines = apply_ignore(extract_lines([a], limit=40), ignore_patterns)
            title = next((line for line in lines if word_count(line) >= min_words), "")
            if not title:
                label = "" if lines else clean_text(a.get("aria-label") or a.get("title") or "")  # image links
                if word_count(label) < min_words:
                    continue
                title = label
            # the teaser; counters, categories and other fragments are left out
            summary = "\n".join(line for line in lines if line != title and word_count(line) >= 3)
            key = headline_id(url)
            current = found.get(key)
            if current is None:
                found[key] = Item(key, truncate(title, 300), url, truncate(summary, 1000))
                if len(found) >= limit:
                    return list(found.values())
            elif not current.text and summary:
                current.text = truncate(summary, 1000)
    return list(found.values())


# --------------------------------------------------------------------------- feeds

def looks_like_feed(content_type: str, body: bytes) -> bool:
    ct = (content_type or "").lower()
    if any(t in ct for t in ("rss", "atom", "/xml", "+xml")) and "html" not in ct:
        return True
    head = body[:1024].lstrip().lower()
    return head.startswith(b"<?xml") or b"<rss" in head or b"<feed" in head or b"<rdf:rdf" in head


def _localname(el) -> str:
    return etree.QName(el).localname.lower() if isinstance(el.tag, str) else ""


def _feed_text(el) -> str:
    if el is None:
        return ""
    if len(el):  # inline XHTML content
        return clean_text(" ".join(el.itertext()))
    raw = el.text or ""
    if "<" in raw and ">" in raw:
        try:
            return clean_text(lxml.html.fragment_fromstring(raw, create_parent="div").text_content())
        except (etree.ParserError, ValueError):
            pass
    return clean_text(raw)


def parse_feed(data: bytes, base_url: str) -> list[Item]:
    parser = etree.XMLParser(recover=True, resolve_entities=False, no_network=True, remove_comments=True)
    try:
        root = etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise ExtractError(f"invalid RSS/Atom XML: {exc}", kind="parse") from None
    if root is None or _localname(root) not in ("rss", "feed", "rdf", "channel"):
        raise ExtractError("the response is not an RSS/Atom feed", kind="type")
    items: list[Item] = []
    seen: set[str] = set()
    for el in root.iter():
        if _localname(el) not in ("item", "entry"):
            continue
        fields: dict[str, object] = {}
        link = None
        for child in el:
            name = _localname(child)
            if not name:
                continue
            if name == "link":
                href = child.get("href")
                rel = (child.get("rel") or "alternate").lower()
                if href and rel == "alternate" and link is None:
                    link = href.strip()
                elif not href and (child.text or "").strip() and link is None:
                    link = child.text.strip()
            elif name not in fields:
                fields[name] = child
        title = _feed_text(fields.get("title"))
        summary = ""
        for name in ("description", "summary", "content", "encoded"):
            if fields.get(name) is not None:
                summary = _feed_text(fields[name])
                break
        guid = ""
        for name in ("guid", "id"):
            if fields.get(name) is not None:
                guid = clean_text(fields[name].text)
                break
        published = ""
        for name in ("pubdate", "published", "updated", "date"):
            if fields.get(name) is not None:
                published = clean_text(fields[name].text)
                break
        url = None
        if link:
            try:
                url = normalize_url(urljoin(base_url, link))
            except ValueError:
                url = None
        item_id = guid or url or "h:" + sha256_text(title + summary)[:20]
        if not (title or summary) or item_id in seen:
            continue
        seen.add(item_id)
        items.append(Item(item_id, truncate(title or summary, 300), url, truncate(summary, 3000), published))
    return items


def feed_links(doc, base_url: str) -> list[str]:
    """RSS/Atom feeds advertised by an HTML page."""
    result = []
    for link in doc.iter("link"):
        kind = (link.get("type") or "").lower()
        if "rss" in kind or "atom" in kind:
            href = (link.get("href") or "").strip()
            if href:
                url = normalize_url(urljoin(base_url, href))
                if url and url not in result:
                    result.append(url)
    return result


# --------------------------------------------------------------------------- JSON APIs

_PLACEHOLDER = re.compile(r"\{([\w.-]+)\}")
_CLOCK = re.compile(r"(\d{2}:\d{2}):\d{2}(\.\d+)?")


def json_lookup(data, path: str):
    """Value at a dotted path ("DATA", "result.items", "modules.0.date"); None when missing."""
    current = data
    for part in (p for p in path.split(".") if p):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def json_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)[:300]
    text = clean_text(str(value))
    clock = _CLOCK.fullmatch(text)
    return clock.group(1) if clock else text  # 11:00:00.000 -> 11:00


def render_record(record, template: str, labels: dict) -> str:
    """Fill ``{field}`` placeholders; a label may itself contain placeholders (one level deep)."""
    def resolve(name: str, depth: int = 0) -> str:
        raw = json_text(json_lookup(record, name))
        label = (labels.get(name) or {}).get(raw)
        if label is None:
            return raw
        return _PLACEHOLDER.sub(lambda m: resolve(m.group(1), depth + 1) if depth < 2 else "", label)
    return clean_text(_PLACEHOLDER.sub(lambda m: resolve(m.group(1)), template))


def json_snapshot(data, records_path: str = "", template: str = "", labels: dict | None = None,
                  filters: dict | None = None) -> Snapshot:
    """One readable line per record, so the normal line/word diff shows exactly what changed."""
    records = json_lookup(data, records_path) if records_path else data
    if records is None:
        raise ExtractError(f"the JSON response has no {records_path!r}", kind="selector")
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise ExtractError(f"{records_path or 'the JSON response'} is not a list of records", kind="type")
    lines = []
    for record in records:
        if filters and not all(str(expected).lower() in json_text(json_lookup(record, field)).lower()
                               for field, expected in filters.items()):
            continue
        if template:
            line = render_record(record, template, labels or {})
        elif isinstance(record, dict):
            line = " · ".join(f"{key}: {json_text(value)}" for key, value in record.items()
                              if not isinstance(value, (dict, list)))
        else:
            line = json_text(record)
        if line and has_alnum(line):
            lines.append(truncate(line, 1500))
    return Snapshot(lines, [], "", [], [])


def parse_json_body(text: str):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        raise ExtractError("the response is not valid JSON", kind="type") from None


# --------------------------------------------------------------------------- bot walls

_BLOCK_PATTERNS = (
    ("Cloudflare Rate Limit", re.compile(
        r"Error\s+1015|You are being rate limited|has banned you temporarily|"
        r"banned you temporarily from accessing", re.I)),
    ("Cloudflare", re.compile(
        r"cf-browser-verification|cf_chl_opt|/cdn-cgi/challenge-platform|<title>\s*Just a moment\.\.\.|"
        r"Attention Required! \| Cloudflare|cf-error-details", re.I)),
    ("Akamai", re.compile(r"errors\.edgesuite\.net|<title>\s*Access Denied\s*</title>", re.I)),
    ("Imperva/Incapsula", re.compile(r"Incapsula incident ID|_Incapsula_Resource", re.I)),
    ("DDoS-Guard", re.compile(r"ddos-guard\.net|<title>\s*DDoS-Guard", re.I)),
    ("Sucuri", re.compile(r"Sucuri WebSite Firewall|sucuri\.net/privacy-policy", re.I)),
    ("DataDome", re.compile(r"captcha-delivery\.com|geo\.captcha", re.I)),
    ("PerimeterX", re.compile(r"_pxCaptcha|px-captcha", re.I)),
    ("AWS WAF", re.compile(r"awswaf|aws-waf-token", re.I)),
    ("CAPTCHA", re.compile(r"g-recaptcha|h-captcha|hcaptcha\.com|challenges\.cloudflare\.com/turnstile", re.I)),
)
_JS_REQUIRED = re.compile(
    r"(enable|turn on|activate)\s+javascript|javascript\s+(is\s+)?(required|disabled|needed)|"
    r"requires\s+javascript|جاوا\s*اسکریپت", re.I)
# Bot walls that a real browser can usually pass by simply waiting a few seconds.
INTERSTITIALS = frozenset({"Cloudflare", "DDoS-Guard", "Imperva/Incapsula", "Sucuri", "AWS WAF", "DataDome",
                           "PerimeterX"})
_MARKUP_RE = re.compile(r"<(script|style|noscript|template)\b.*?</\1\s*>|<!--.*?-->|<[^>]+>", re.S | re.I)


def visible_text_length(html: str) -> int:
    """Rough length of the human-visible text of an HTML document."""
    if not html:
        return 0
    return len(clean_text(_MARKUP_RE.sub(" ", html[:3_000_000])))


def detect_block(html: str, visible_length: int | None = None, *, include_js: bool = True) -> str | None:
    """Name of the bot protection a (small) page looks like, if any."""
    if not html:
        return None
    if visible_length is None:
        visible_length = visible_text_length(html)
    if visible_length > 3000:
        return None
    head = html[:300_000]
    for name, pattern in _BLOCK_PATTERNS:
        if pattern.search(head):
            return name
    if include_js and _JS_REQUIRED.search(head):
        return "JavaScript required"
    return None


def is_rate_limit_page(html: str) -> bool:
    """True when the page is a Cloudflare/Akamai-style rate-limit ban (Error 1015 etc.)."""
    if not html:
        return False
    return detect_block(html) == "Cloudflare Rate Limit"
