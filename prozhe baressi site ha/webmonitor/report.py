"""Diffing snapshots and rendering Telegram-ready (HTML) reports.

A report payload is a JSON-serialisable dict::

    {"header": str, "cont": str, "blocks": [str], "full_blocks": [str] | None,
     "doc_title": str | None, "attach": bool, "silent": bool, "buttons": [[button]] | None}

Every block is a self-contained, tag-balanced HTML snippet, so messages can be
split between blocks without ever producing invalid Telegram HTML. ``blocks``
are shortened for chat; ``full_blocks`` (when different) hold the complete text
and are sent as an HTML file attachment. ``buttons`` (an inline keyboard, e.g.
"open the page") go under the last message.

Layout of a report: a header (what happened, where, when, a one-line summary),
then the details grouped by the part of the page they belong to ("📍 …"), each
group inside a quote block — long groups are collapsible.
"""

from __future__ import annotations

import difflib
import re
from collections import Counter
from dataclasses import dataclass
from datetime import tzinfo
from urllib.parse import urlsplit

from .util import esc, esc_attr, fa_datetime, fa_digits, fa_number, find_keywords, human_duration, truncate

MSG_LINE_LIMIT = 1800     # max chars of one changed line inside a Telegram message
EXCERPT_LINES = 35        # lines shown for a newly discovered page
SECTION_CHARS = 2800      # max size of one quoted group (a Telegram message holds ~3900)
EXPAND_LINES = 12         # longer groups are collapsible ("expandable" quote)
EXPAND_CHARS = 1200
RULE = "━━━━━━━━━━━━━━"
SEPARATOR = "┈┈┈┈"
OPEN_PAGE = "🌐 باز کردن صفحه"
_KEYCAPS = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")


@dataclass
class Hunk:
    kind: str          # add | remove | modify
    old: str = ""
    new: str = ""
    context: str = ""  # nearest meaningful unchanged line before this change
    anchor: str = ""   # DOM id near this change (used for a jump link)


# --------------------------------------------------------------------------- diffing

def _similarity(a: str, b: str) -> float:
    sm = difflib.SequenceMatcher(None, a.split(), b.split(), autojunk=False)
    if sm.real_quick_ratio() < 0.45 or sm.quick_ratio() < 0.45:
        return 0.0
    return sm.ratio()


def _pair_replace(olds: list[str], news: list[str]) -> list[Hunk]:
    """Pair similar old/new lines of a replaced block (in order) to show word-level edits."""
    if len(olds) * len(news) > 3000:
        return [Hunk("remove", old=o) for o in olds] + [Hunk("add", new=n) for n in news]
    pairs: dict[int, int] = {}
    start = 0
    for i, old in enumerate(olds):
        best, best_ratio = None, 0.0
        for j in range(start, len(news)):
            ratio = _similarity(old, news[j])
            if ratio > best_ratio:
                best, best_ratio = j, ratio
        if best is not None and best_ratio >= 0.35:
            pairs[i] = best
            start = best + 1
    hunks: list[Hunk] = []
    j = 0
    for i, old in enumerate(olds):
        if i in pairs:
            while j < pairs[i]:
                hunks.append(Hunk("add", new=news[j]))
                j += 1
            hunks.append(Hunk("modify", old=old, new=news[j]))
            j += 1
        else:
            hunks.append(Hunk("remove", old=old))
    hunks.extend(Hunk("add", new=n) for n in news[j:])
    return hunks


def _drop_moves(hunks: list[Hunk]) -> list[Hunk]:
    """Lines that were only moved (removed here, added there unchanged) are not real changes."""
    moved = Counter(h.old for h in hunks if h.kind == "remove") & Counter(h.new for h in hunks if h.kind == "add")
    if not moved:
        return hunks
    removed_budget, added_budget = moved.copy(), moved.copy()
    result: list[Hunk] = []
    carry = ""
    for h in hunks:
        if h.kind == "remove" and removed_budget[h.old] > 0:
            removed_budget[h.old] -= 1
            carry = carry or h.context
            continue
        if h.kind == "add" and added_budget[h.new] > 0:
            added_budget[h.new] -= 1
            carry = carry or h.context
            continue
        if carry and not h.context:
            h.context = carry
        carry = ""
        result.append(h)
    return result


def _meaningful(line: str) -> bool:
    """Good enough to tell the reader *where* a change is (not a counter, a time or an icon)."""
    return sum(ch.isalpha() for ch in line) >= 4


def diff_lines(old: list[str], new: list[str], ignore_reorder: bool = True,
               new_headings: list[str] | None = None,
               new_anchors: list[str] | None = None) -> list[Hunk]:
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    hunks: list[Hunk] = []
    last_equal = ""
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            last_equal = next((line for line in reversed(new[j1:j2]) if _meaningful(line)), last_equal)
            continue
        if tag == "delete":
            group = [Hunk("remove", old=line) for line in old[i1:i2]]
        elif tag == "insert":
            group = [Hunk("add", new=line) for line in new[j1:j2]]
        else:
            group = _pair_replace(old[i1:i2], new[j1:j2])
        if group:
            heading = ""
            if new_headings:
                if j1 < len(new_headings):
                    heading = new_headings[j1] or ""
                if not heading and j1 > 0 and (j1 - 1) < len(new_headings):
                    heading = new_headings[j1 - 1] or ""
            group[0].context = heading or last_equal
            if new_anchors:
                anchor = ""
                if j1 < len(new_anchors):
                    anchor = (new_anchors[j1] or "").strip()
                if not anchor and j1 > 0 and (j1 - 1) < len(new_anchors):
                    anchor = (new_anchors[j1 - 1] or "").strip()
                if anchor:
                    group[0].anchor = anchor
        hunks.extend(group)
    return _drop_moves(hunks) if ignore_reorder else hunks


def diff_links(old: list, new: list) -> tuple[list, list]:
    old_urls = {url for _, url in old}
    new_urls = {url for _, url in new}
    added = [(text, url) for text, url in new if url not in old_urls]
    removed = [(text, url) for text, url in old if url not in new_urls]
    return added, removed


# --------------------------------------------------------------------------- building blocks

def word_diff_html(old: str, new: str, budget: int | None = MSG_LINE_LIMIT, context_words: int | None = 45) -> str:
    """Inline word diff: removed words struck through, inserted words bold+underlined.

    With ``budget``/``context_words`` set to None the full line is rendered.
    """
    a, b = old.split(" "), new.split(" ")
    ops = difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
    parts: list[str] = []
    used = 0
    n = context_words
    for index, (tag, i1, i2, j1, j2) in enumerate(ops):
        if tag == "equal":
            words = a[i1:i2]
            first, last = index == 0, index == len(ops) - 1
            if n is None:
                text = " ".join(words)
            elif first and not last and len(words) > n:
                text = "… " + " ".join(words[-n:])
            elif last and not first and len(words) > n:
                text = " ".join(words[:n]) + " …"
            elif not first and not last and len(words) > 2 * n:
                text = " ".join(words[:n]) + " … " + " ".join(words[-n:])
            else:
                text = " ".join(words)
            part = esc(text)
        else:
            cut = (lambda s: truncate(s, 600)) if budget else (lambda s: s)
            removed = cut(" ".join(a[i1:i2])) if tag in ("delete", "replace") else ""
            added = cut(" ".join(b[j1:j2])) if tag in ("insert", "replace") else ""
            segments = []
            if removed:
                segments.append(f"<s>{esc(removed)}</s>")
            if added:
                segments.append(f"<b><u>{esc(added)}</u></b>")
            part = " ".join(segments)
        if budget and used + len(part) > budget and parts:
            parts.append("…")
            break
        parts.append(part)
        used += len(part) + 1
    return " ".join(parts)


def render_hunk(h: Hunk, full: bool = False, style: str = "inline") -> str:
    """One changed line: 🟢 added · 🔴 removed · 🟡 edited.

    ``style``: "inline" word-diff (default) or "before_after" detailed view (before + after + word diff).
    """
    cut = (lambda s: s) if full else (lambda s: truncate(s, MSG_LINE_LIMIT))
    if h.kind == "add":
        return f"🟢 {esc(cut(h.new))}"
    if h.kind == "remove":
        return f"🔴 <s>{esc(cut(h.old))}</s>"
    if style == "before_after":
        wdiff = word_diff_html(h.old, h.new, budget=None if full else MSG_LINE_LIMIT,
                               context_words=None if full else 45)
        return (
            f"🟡 <b>ویرایش خط:</b>\n"
            f"   🔴 <i>قبل:</i> <s>{esc(cut(h.old))}</s>\n"
            f"   🟢 <i>بعد:</i> <b><u>{esc(cut(h.new))}</u></b>\n"
            f"   🔍 <i>کلمه‌به‌کلمه:</i> {wdiff}"
        )
    if full:
        return f"🟡 {word_diff_html(h.old, h.new, budget=None, context_words=None)}"
    return f"🟡 {word_diff_html(h.old, h.new)}"


def render_link(text: str, url: str, icon: str = "•", removed: bool = False) -> str:
    label = esc(truncate(text or _display_url(url), 120))
    if removed:
        label = f"<s>{label}</s>"
    return f'{icon} <a href="{esc_attr(url)}">{label}</a>'


def _display_url(url: str) -> str:
    return truncate(url.rstrip("/"), 100)


def _chunks(lines: list[str], limit: int = SECTION_CHARS):
    chunk: list[str] = []
    size = 0
    for line in lines:
        if chunk and size + len(line) + 1 > limit:
            yield chunk
            chunk, size = [], 0
        chunk.append(line)
        size += len(line) + 1
    if chunk:
        yield chunk


def quote(lines: list[str]) -> str:
    """Lines in a Telegram quote block; long ones collapse ("expandable") to keep the chat tidy."""
    body = "\n".join(lines)
    if len(lines) > EXPAND_LINES or len(body) > EXPAND_CHARS:
        return f"<blockquote expandable>{body}</blockquote>"
    return f"<blockquote>{body}</blockquote>"


def _grouped(heading: str, lines: list[str], *, sep: str = "\n") -> list[str]:
    """``heading`` + quoted lines, split into blocks that each fit in one message."""
    blocks = []
    for index, chunk in enumerate(_chunks(lines)):
        title = heading if index == 0 else (heading + " <i>(ادامه)</i>" if heading else "")
        if sep != "\n" and len(chunk) > 1:
            spaced: list[str] = []
            for idx, item in enumerate(chunk):
                if idx > 0:
                    spaced.append("")
                spaced.append(item)
            blocks.append((f"{title}\n" if title else "") + quote(spaced))
        else:
            blocks.append((f"{title}\n" if title else "") + quote(chunk))
    return blocks


def _sections(hunks: list[Hunk], full: bool, show_context: bool, style: str = "inline",
              base_url: str | None = None) -> list[str]:
    """Changes grouped under the part of the page they belong to (📍 nearest unchanged line)."""
    groups: list[tuple[str, list[str], str]] = []
    for h in hunks:
        ctx = h.context if show_context else ""
        if not groups or (ctx and ctx != groups[-1][0]):
            groups.append((ctx, [], ""))
        if not groups[-1][2] and h.anchor:
            groups[-1] = (groups[-1][0], groups[-1][1], h.anchor)
        groups[-1][1].append(render_hunk(h, full, style))
    blocks = []
    for context, lines, first_anchor in groups:
        heading = f"📍 <b>{esc(truncate(context, 90))}</b>" if context else ""
        # Sprint 4.1: if the first hunk in this group has an anchor, add a jump link under the heading.
        if first_anchor:
            anchor_href = f"#{esc_attr(first_anchor)}"
            if base_url and base_url.startswith(("http://", "https://")):
                from urllib.parse import urlunsplit
                parts = urlsplit(base_url)
                full_jump = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, first_anchor))
                anchor_href = esc_attr(full_jump)
            link_tag = f'<a href="{anchor_href}">#{esc(truncate(first_anchor, 30))}</a>'
            heading = f"{heading} {link_tag}" if heading else link_tag
        blocks.extend(_grouped(heading, lines, sep="\n\n"))
    return blocks


IMPORTANT_LINK_MAX = 3  # keep the header short


def _important_removed(watch, removed: list) -> list:
    """Removed links whose label matches a watch keyword (bounded, deduped)."""
    keywords = getattr(watch, "keywords", None) or []
    if not keywords or not removed:
        return []
    result = []
    seen = set()
    for text, url in removed:
        if not text:
            continue
        if url in seen:
            continue
        if find_keywords(keywords, text):
            result.append((text, url))
            seen.add(url)
            if len(result) >= IMPORTANT_LINK_MAX:
                break
    return result


def _link_blocks(added: list, removed: list) -> list[str]:
    blocks = []
    if added:
        blocks += _grouped(f"🔗 <b>لینک‌های تازه ({fa_digits(len(added))})</b>",
                           [render_link(text, url) for text, url in added])
    if removed:
        blocks += _grouped(f"⛓ <b>لینک‌های حذف‌شده ({fa_digits(len(removed))})</b>",
                           [render_link(text, url, removed=True) for text, url in removed])
    return blocks


def page_button(url: str | None) -> list | None:
    return [[{"text": OPEN_PAGE, "url": url}]] if url and url.startswith(("http://", "https://")) else None


def _header(icon: str, title: str, ts: float, tz: tzinfo, *, url: str | None = None, url_label: str = "",
            lines=(), rule: bool = False) -> str:
    parts = [f"{icon} <b>{title}</b>", f"🕒 {fa_datetime(ts, tz)}"]
    if url:
        parts.append(f'🔗 <a href="{esc_attr(url)}">{esc(url_label or _display_url(url))}</a>')
    parts.extend(line for line in lines if line)
    if rule:
        parts.append(RULE)
    return "\n".join(parts)


def _payload(header: str, cont: str, blocks: list[str], *, silent: bool, doc_title: str | None,
             full_blocks: list[str] | None = None, attach: bool = False, buttons: list | None = None) -> dict:
    """``attach``: send the full report file even if all messages fit (text was shortened)."""
    # Sprint 4.3: always keep full_blocks so the panel can re-send the complete diff.
    if full_blocks is None:
        full_blocks = blocks
    return {"header": header, "cont": cont, "blocks": blocks, "full_blocks": full_blocks,
            "doc_title": doc_title, "attach": bool(attach and doc_title), "silent": silent, "buttons": buttons}


def render_document(title: str, header_html: str, blocks: list[str]) -> str:
    """Stand-alone HTML file with the complete report (sent as a Telegram document)."""
    body = "\n".join(f'<div class="b" data-block="{i}">{block}</div>' for i, block in enumerate(blocks))
    return (
        "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{esc(title)}</title><style>"
        ":root{--bg:#f6f7f9;--card:#ffffff;--border:#e3e6ea;--text:#1f2328;--muted:#667085;"
        "--header-bg:#eef4ff;--quote-bg:#f8fafc;--quote-border:#b6c6f5;--link:#1a5fd0;"
        "--del-fg:#b42318;--del-bg:#fdecea;--ins-fg:#067647;--ins-bg:#e7f6ec}"
        "@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--border:#30363d;"
        "--text:#e6edf3;--muted:#8b949e;--header-bg:#1c2536;--quote-bg:#0d1117;--quote-border:#388bfd;"
        "--link:#58a6ff;--del-fg:#ff7b72;--del-bg:#3d1d20;--ins-fg:#3fb950;--ins-bg:#122d1f}}"
        "*{box-sizing:border-box}"
        "body{font-family:Vazirmatn,Tahoma,'Segoe UI',sans-serif;max-width:960px;margin:auto;padding:16px;"
        "line-height:1.95;background:var(--bg);color:var(--text)}"
        ".toolbar{position:sticky;top:8px;z-index:10;display:flex;flex-wrap:wrap;gap:8px;align-items:center;"
        "background:var(--card);border:1px solid var(--border);border-radius:10px;padding:8px 12px;"
        "margin:10px 0;box-shadow:0 4px 12px rgba(0,0,0,.06)}"
        ".toolbar input{flex:1;min-width:180px;padding:7px 12px;border:1px solid var(--border);"
        "border-radius:8px;background:var(--bg);color:var(--text);font-family:inherit;font-size:14px}"
        ".toolbar button{padding:6px 12px;border:1px solid var(--border);border-radius:8px;"
        "background:var(--bg);color:var(--text);cursor:pointer;font-family:inherit;font-size:13px;min-height:36px}"
        ".toolbar button.active{background:var(--link);color:#fff;border-color:var(--link)}"
        ".h,.b{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 16px;"
        "margin:12px 0;white-space:pre-wrap;unicode-bidi:plaintext;overflow-wrap:anywhere}"
        ".h{background:var(--header-bg)}blockquote{margin:8px 0;padding:8px 14px;"
        "border-inline-start:3px solid var(--quote-border);background:var(--quote-bg);"
        "border-radius:8px;white-space:pre-wrap}"
        "s{color:var(--del-fg);background:var(--del-bg);padding:0 3px;border-radius:4px}"
        "b u{color:var(--ins-fg);background:var(--ins-bg);text-decoration:none;padding:0 3px;border-radius:4px}"
        "a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}i{color:var(--muted)}"
        "</style></head><body>"
        f'<div class="h">{header_html}</div>'
        '<div class="toolbar" role="search" aria-label="فیلتر و جستجوی تغییرات">'
        '<input id="q" type="search" placeholder="🔍 جستجو در تغییرات (کلمه، عدد، لینک)…" '
        'oninput="filterBlocks()">'
        '<button class="active" onclick="setKind(\'\',this)">همه</button>'
        '<button onclick="setKind(\'🟢\',this)">🟢 جدید</button>'
        '<button onclick="setKind(\'🟡\',this)">🟡 ویرایش</button>'
        '<button onclick="setKind(\'🔴\',this)">🔴 حذف</button>'
        '</div>'
        f'{body}'
        "<script>"
        "let curKind='';"
        "function setKind(k,btn){curKind=k;document.querySelectorAll('.toolbar button')"
        ".forEach(b=>b.classList.remove('active'));btn.classList.add('active');filterBlocks();}"
        "function filterBlocks(){const q=(document.getElementById('q').value||'').toLowerCase();"
        "document.querySelectorAll('.b').forEach(el=>{const t=el.textContent.toLowerCase();"
        "const okQ=!q||t.includes(q);const okK=!curKind||el.textContent.includes(curKind);"
        "el.style.display=(okQ&&okK)?'':'none';});}"
        "</script></body></html>"
    )


def _page_identity(watch, url: str, page_title: str) -> str:
    """One line identifying which page changed: main page or subpage, with title and relative path.

    Example: '🏠 صفحهٔ اصلی · «سفارت آلمان - اطلاعات ویزا»'
             '📂 زیرصفحه: 2752046 · «اطلاعیه‌های ویزا»'
    """
    parts = []
    try:
        base = urlsplit(watch.url)
        cur = urlsplit(url)
    except Exception:
        base = cur = None
    if base is not None and cur is not None and base.netloc == cur.netloc:
        base_path = (base.path or "/").rstrip("/") or "/"
        cur_path = cur.path or "/"
        if cur_path == base_path or cur_path == base_path + "/":
            parts.append("🏠 <b>صفحهٔ اصلی</b>")
        else:
            rel = cur_path
            if rel.startswith(base_path + "/"):
                rel = rel[len(base_path) + 1:]
            elif rel.startswith("/"):
                rel = rel.lstrip("/")
            parts.append(f"📂 زیرصفحه: <code>{esc(truncate(rel, 80))}</code>")
    else:
        parts.append("📄 صفحه")
    if page_title:
        parts.append(f"«{esc(truncate(page_title, 100))}»")
    return " · ".join(parts)


def _keywords_line(hits: list[str]) -> str:
    return f"🔑 <b>کلمات کلیدی:</b> {esc('، '.join(hits))}" if hits else ""


def _item_noun(watch) -> str:
    host = (urlsplit(watch.url).hostname or "").lower()
    if host in ("t.me", "telegram.me"):
        return "پست"
    return "خبر" if watch.type in ("feed", "headlines") else "مورد"


def _item_icon(watch) -> str:
    return {"پست": "📢", "خبر": "📰"}.get(_item_noun(watch), "📌")


def _published(value: str, tz: tzinfo) -> str:
    """RSS (RFC 822) or ISO 8601 date in the configured timezone (Jalali)."""
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime

    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return fa_datetime(dt.timestamp(), tz)


# --------------------------------------------------------------------------- events

# --------------------------------------------------------------------------- layout drift

DRIFT_MIN_LINES = 8            # smaller pages are never classified: every change of a tiny page is "everything"
DRIFT_MASS = 0.5               # share of the distinct lines that was replaced
DRIFT_VOCAB = 0.35             # words (without digits) shared by old and new text, below this = new vocabulary
DRIFT_VOCAB_NO_HEADINGS = 0.2  # pages without headings need stronger proof of a redesign
DRIFT_HEADINGS = 0.5           # share of the old headings that must survive
DRIFT_COLLAPSE = 0.2           # new text shorter than this share of the old one ...
DRIFT_COLLAPSE_MIN_CHARS = 400  # ... counts only for pages that had some substance
DRIFT_SAMPLE = 6               # changes shown in the shortened message of a redesign
DRIFT_LABELS = {"mass": "تغییر گسترده", "redesign": "بازطراحی احتمالی", "collapse": "کوتاه شدن ناگهانی محتوا"}
_WORD = re.compile(r"[^\W\d_]{3,}")


@dataclass(frozen=True)
class Drift:
    """How much of a page changed at once, and whether it looks like a redesign instead of news.

    ``mass``     half of the lines or more were replaced (fine for tables of dates, news lists, ...);
    ``redesign`` ... and the vocabulary and the headings are new as well: the site was most likely rebuilt;
    ``collapse`` the text shrank to a fraction (sold out, maintenance page, half-loaded page).
    A drift never hides a change - it only labels it and, for redesign/collapse, shortens the message.
    """
    level: str = "normal"
    churn: float = 0.0
    vocab: float = 1.0
    headings: float = 1.0
    size: float = 1.0

    def as_dict(self) -> dict:
        return {"level": self.level, "churn": round(self.churn, 2), "vocab": round(self.vocab, 2),
                "headings": round(self.headings, 2), "size": round(self.size, 2)}


def _vocabulary(lines) -> set:
    return {word.lower() for line in lines for word in _WORD.findall(line)}


def assess_drift(old_lines, new_lines, old_headings, new_headings, old_chars: int, new_chars: int) -> Drift:
    """Compare two snapshots of the same page (pure function, no I/O)."""
    old_set, new_set = set(old_lines), set(new_lines)
    if len(old_set) < DRIFT_MIN_LINES:
        return Drift()
    union = len(old_set | new_set)
    churn = 1 - len(old_set & new_set) / union if union else 0.0
    old_words, new_words = _vocabulary(old_lines), _vocabulary(new_lines)
    vocab = len(old_words & new_words) / min(len(old_words), len(new_words)) if old_words and new_words else 0.0
    old_heads = {h for h in old_headings if h}
    headings = len(old_heads & {h for h in new_headings if h}) / len(old_heads) if old_heads else 1.0
    size = new_chars / old_chars if old_chars else 1.0
    level = "normal"
    if old_chars >= DRIFT_COLLAPSE_MIN_CHARS and size <= DRIFT_COLLAPSE:
        level = "collapse"
    elif churn >= DRIFT_MASS:
        level = "mass"
        structure_gone = headings < DRIFT_HEADINGS if old_heads else vocab < DRIFT_VOCAB_NO_HEADINGS
        if vocab < DRIFT_VOCAB and structure_gone:
            level = "redesign"
    return Drift(level, churn, vocab, headings, size)


def _drift_lines(drift: Drift) -> list[str]:
    if drift.level == "redesign":
        return ["🧱 <b>احتمالاً سایت بازطراحی شده:</b> بیشتر خط‌ها و عنوان‌ها یکجا عوض شده و واژگان تقریباً کاملاً جدید است.",
                "ℹ️ وضعیت جدید به‌عنوان مبنا ذخیره شد. اگر انتظارش را نداشتید، در کارت سایت «✏️ ویرایش ← 🎯 حالت پایش» "
                "را بزنید تا بخش درست دوباره انتخاب شود."]
    if drift.level == "collapse":
        return [f"📉 <b>حجم محتوا ناگهان به ~{fa_digits(round(drift.size * 100))}٪ قبل رسید.</b> ممکن است ظرفیت تمام شده، "
                "صفحهٔ نگهداری یا بارگذاری ناقص باشد.",
                "ℹ️ متن جدید پایین نشان داده شده است؛ وضعیت جدید به‌عنوان مبنا ذخیره شد."]
    return [f"🧭 <b>تغییر گسترده:</b> حدود {fa_digits(round(drift.churn * 100))}٪ از خط‌ها عوض شده؛ "
            "اگر این صفحه فهرست یا جدول تاریخ‌هاست، طبیعی است."]


def change_event(watch, url: str, hunks: list[Hunk], links_added: list, links_removed: list,
                 ts: float, tz: tzinfo, page_title: str = "", total_chars: int = 0,
                 style: str = "", drift: Drift | None = None) -> tuple[dict, str, list[str]]:
    """Payload, one-line summary and keyword hits for a content change."""
    style = style or getattr(watch, "report_style", "inline")
    counts = Counter(h.kind for h in hunks)
    hits = find_keywords(
        watch.keywords,
        *(h.new for h in hunks if h.kind in ("add", "modify")),
        *(text for text, _ in links_added),
    )
    stats = []
    if counts["add"]:
        stats.append(f"🟢 {fa_digits(counts['add'])} جدید")
    if counts["remove"]:
        stats.append(f"🔴 {fa_digits(counts['remove'])} حذف")
    if counts["modify"]:
        stats.append(f"🟡 {fa_digits(counts['modify'])} ویرایش")
    if links_added:
        stats.append(f"🔗 {fa_digits(len(links_added))} لینک تازه")
    if links_removed:
        stats.append(f"⛓ {fa_digits(len(links_removed))} لینک حذف‌شده")
    important_removed = _important_removed(watch, links_removed)
    is_json = getattr(watch, "type", "page") == "json"
    shown_url = watch.page_url if is_json else url
    lines = []
    if is_json and hits and "{availability}" in getattr(watch, "json_template", ""):
        lines.append("🎉 <b>ظرفیت/نوبت آزاد شد — هرچه زودتر ثبت‌نام کنید!</b>")
    if not is_json:
        lines.append(_page_identity(watch, url, page_title))
    lines.append("📊 <b>خلاصه:</b> " + " · ".join(stats))

    # --- Sprint 1.1: حجم تغییر ---
    if total_chars > 0:
        changed_chars = sum(len(h.new or h.old) for h in hunks)
        percent = min(100.0, 100.0 * changed_chars / total_chars)
        percent_text = fa_digits(f"{percent:.1f}".replace(".", "٫"))
        lines.append(
            f"📈 حجم تغییر: ~{percent_text}٪ از متن "
            f"({fa_number(changed_chars)} از {fa_number(total_chars)} حرف)"
        )

    compact = drift is not None and drift.level in ("redesign", "collapse")
    if drift is not None and drift.level != "normal":
        lines.extend(_drift_lines(drift))

    # --- Sprint 1.1: بخش‌های درگیر ---
    contexts = []
    for h in hunks:
        ctx = (h.context or "").strip()
        if ctx and ctx not in contexts:
            contexts.append(ctx)
    if contexts:
        shown = contexts[:5]
        extra = len(contexts) - len(shown)
        text = " · ".join(esc(truncate(c, 45)) for c in shown)
        if extra > 0:
            text += f" · <i>+{fa_digits(extra)} بخش دیگر</i>"
        lines.append(f"📌 بخش‌های درگیر: {text}")

    if important_removed:
        lines.append("⚠️ <b>لینک مهم حذف شد:</b>")
        for text, _ in important_removed:
            lines.append(f"   🔗 <s>{esc(truncate(text, 80))}</s>")
    lines.append(_keywords_line(hits))
    # Sprint 4.1: direct jump link to the part of the page where the change is.
    if shown_url and shown_url.startswith(("http://", "https://")) and not is_json:
        jump_anchor = next((h.anchor for h in hunks if h.anchor), "")
        if jump_anchor:
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(shown_url)
            jump_url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, jump_anchor))
            lines.append(f'🔗 <a href="{esc_attr(jump_url)}">پرش به بخش «{esc(truncate(jump_anchor, 40))}»</a>')
    if compact:
        icon, title = (("🧱", f"احتمال بازطراحی سایت «{esc(watch.label)}»") if drift.level == "redesign"
                       else ("📉", f"محتوای «{esc(watch.label)}» ناگهان کوتاه شد"))
    else:
        icon, title = "🚨" if hits else "🔔", f"تغییر در «{esc(watch.label)}»"
    header = _header(icon, title, ts, tz, url=shown_url, lines=lines, rule=True)
    if compact:
        # a rebuilt site changes everything at once: a short sample here, the complete diff as an attachment
        sample = [h for h in hunks if h.kind in ("add", "modify")][:DRIFT_SAMPLE] or hunks[:DRIFT_SAMPLE]
        blocks = _sections(sample, full=False, show_context=not is_json, style=style, base_url=shown_url)
        rest = len(hunks) - len(sample)
        blocks.append(f"<i>… و {fa_digits(max(rest, 0))} تغییر دیگر — گزارش کامل در فایل پیوست است.</i>")
    else:
        blocks = (_sections(hunks, full=False, show_context=not is_json, style=style, base_url=shown_url)
                  + _link_blocks(links_added, links_removed))
    full_blocks = _sections(hunks, full=True, show_context=not is_json, style=style, base_url=shown_url) + _link_blocks(links_added, links_removed)
    summary = "، ".join(s.split(" ", 1)[1] for s in stats)
    if drift is not None and drift.level != "normal":
        summary = f"{DRIFT_LABELS[drift.level]} · {summary}"
    shortened = any(len(h.old) > MSG_LINE_LIMIT or len(h.new) > MSG_LINE_LIMIT for h in hunks)
    payload = _payload(header, f"<i>ادامهٔ تغییرات «{esc(watch.label)}»</i>", blocks,
                       silent=watch.silent and not hits, doc_title=f"تغییرات {watch.label}",
                       full_blocks=full_blocks, attach=shortened or compact, buttons=page_button(shown_url))
    return payload, summary, hits


def new_page_event(watch, url: str, snapshot, ts: float, tz: tzinfo) -> tuple[dict, str, list[str]]:
    hits = find_keywords(watch.keywords, snapshot.title, *snapshot.lines)
    title = snapshot.title or url
    lines = [f"📄 <b>{esc(truncate(title, 150))}</b>",
             f"📏 {fa_number(len(snapshot.lines))} خط متن", _keywords_line(hits)]
    header = _header("🚨" if hits else "🆕", f"صفحهٔ جدید در «{esc(watch.label)}»", ts, tz, url=url, lines=lines,
                     rule=True)
    excerpt = _grouped("", [esc(truncate(line, 600)) for line in snapshot.lines[:EXCERPT_LINES]])
    if len(snapshot.lines) > EXCERPT_LINES:
        excerpt.append(f"<i>… و {fa_number(len(snapshot.lines) - EXCERPT_LINES)} خط دیگر "
                       "(متن کامل در فایل پیوست)</i>")
    full = _grouped("", [esc(line) for line in snapshot.lines])
    shortened = len(snapshot.lines) > EXCERPT_LINES or any(len(line) > 600 for line in snapshot.lines)
    payload = _payload(header, f"<i>ادامهٔ صفحهٔ جدید «{esc(watch.label)}»</i>", excerpt,
                       silent=watch.silent and not hits, doc_title=title, full_blocks=full, attach=shortened,
                       buttons=page_button(url))
    return payload, f"صفحهٔ جدید: {truncate(title, 80)}", hits


def removed_page_event(watch, url: str, title: str, ts: float, tz: tzinfo) -> tuple[dict, str]:
    lines = [f"📄 <b>{esc(truncate(title, 150))}</b>" if title else "",
             "این صفحه دیگر باز نمی‌شود (خطای ۴۰۴ در دو بررسی پیاپی)؛ احتمالاً از سایت برداشته شده است."]
    header = _header("🗑", f"صفحه‌ای از «{esc(watch.label)}» حذف شد", ts, tz, url=url, lines=lines)
    return (_payload(header, "", [], silent=watch.silent, doc_title=None),
            f"صفحه حذف شد: {truncate(title or url, 80)}")


def _size(value: int) -> str:
    if value >= 1024 * 1024:
        return fa_digits(f"{value / (1024 * 1024):.1f}".replace(".", "٫")) + " مگابایت"
    if value >= 1024:
        return fa_number(round(value / 1024)) + " کیلوبایت"
    return fa_number(value) + " بایت"


def file_event(watch, url: str, kind: str, info: dict, ts: float, tz: tzinfo) -> tuple[dict, str]:
    name = url.rstrip("/").rsplit("/", 1)[-1] or url
    title = f"فایل جدید در «{esc(watch.label)}»" if kind == "new" else f"فایلی در «{esc(watch.label)}» عوض شد"
    lines = [f'📎 <a href="{esc_attr(url)}">{esc(truncate(name, 120))}</a>']
    if info.get("old_size") is not None and info.get("size") is not None:
        lines.append(f"📦 حجم: {_size(info['old_size'])} ← {_size(info['size'])}")
    elif info.get("size") is not None:
        lines.append(f"📦 حجم: {_size(info['size'])}")
    if info.get("content_type"):
        lines.append(f"🗂 نوع: {esc(info['content_type'])}")
    header = _header("📎", title, ts, tz, lines=lines)
    return (_payload(header, "", [], silent=watch.silent, doc_title=None, buttons=page_button(url)),
            f"فایل {'جدید' if kind == 'new' else 'تغییرکرده'}: {truncate(name, 80)}")


def _number(index: int) -> str:
    return _KEYCAPS[index - 1] if index <= len(_KEYCAPS) else f"<b>{fa_digits(index)}.</b>"


def new_items_event(watch, items: list, ts: float, tz: tzinfo, hits: list[str]) -> tuple[dict, str]:
    count = len(items)
    noun = _item_noun(watch)
    amount = f"{fa_digits(count)} {noun} تازه" if count > 1 else f"{noun} تازه"
    header = _header("🚨" if hits else _item_icon(watch), f"{amount} در «{esc(watch.label)}»", ts, tz,
                     lines=[_keywords_line(hits)], rule=True)
    blocks, full = [], []
    shortened = False
    for index, item in enumerate(items, 1):
        title = esc(truncate(item.title, 250))
        title_html = f'<a href="{esc_attr(item.url)}">{title}</a>' if item.url else title
        head = f"{_number(index)} <b>{title_html}</b>"
        body = item.text
        if body.startswith(item.title):
            body = body[len(item.title):].lstrip(" ·\n")
        when = f"\n<i>🕒 {esc(_published(item.published, tz))}</i>" if item.published else ""
        shortened = shortened or len(body) > 700
        blocks.append(head + (f"\n{quote(esc(truncate(body, 700)).splitlines())}" if body else "") + when)
        full.append(head + (f"\n{quote(esc(body).splitlines())}" if body else "") + when)
    payload = _payload(header, f"<i>ادامهٔ {noun}‌های تازهٔ «{esc(watch.label)}»</i>", blocks,
                       silent=watch.silent and not hits, doc_title=f"{noun}‌های تازه {watch.label}", full_blocks=full,
                       attach=shortened, buttons=page_button(watch.page_url))
    return payload, f"{fa_digits(count)} {noun} تازه: {truncate(items[0].title, 70)}"


def error_event(watch, error: str, count: int, hint: str, ts: float, tz: tzinfo,
                key: int | None = None) -> tuple[dict, str]:
    lines = [f"\n❌ <b>{fa_digits(count)} بار پیاپی</b> ناموفق بود. آخرین خطا:",
             f"<code>{esc(truncate(error, 400))}</code>"]
    if hint:
        lines.append(f"\n💡 <b>راهنما:</b> {hint}")
    lines.append("\n🔄 سیستم خودکار به تلاش ادامه می‌دهد (با فاصلهٔ بیشتر، تا سایت مسدودتر نکند) "
                 "و پس از رفع مشکل خبر می‌دهد.")
    header = _header("⚠️", f"مشکل در بررسی «{esc(watch.label)}»", ts, tz, url=watch.page_url, lines=lines)
    buttons = page_button(watch.page_url) or []
    if key is not None:
        buttons = [[{"text": "🧪 تست دسترسی", "callback_data": f"+dg:{key}"},
                    {"text": "📄 کارت سایت", "callback_data": f"+c:{key}"}]] + buttons
    return (_payload(header, "", [], silent=False, doc_title=None, buttons=buttons or None),
            f"خطا ×{count}: {truncate(error, 100)}")


def recovered_event(watch, down_seconds: float, ts: float, tz: tzinfo) -> tuple[dict, str]:
    lines = [f"⏱ مدت اختلال: {human_duration(down_seconds)}", "پایش عادی ادامه دارد."]
    header = _header("✅", f"«{esc(watch.label)}» دوباره با موفقیت بررسی شد", ts, tz, url=watch.page_url,
                     lines=lines)
    return _payload(header, "", [], silent=True, doc_title=None, buttons=page_button(watch.page_url)), "رفع شد"


def info_event(header_html: str, blocks: list[str] | None = None, silent: bool = True,
               buttons: list | None = None) -> dict:
    return _payload(header_html, "", list(blocks or []), silent=silent, doc_title=None, buttons=buttons)


def digest_payload(watch, payloads: list[dict], first_ts: float, last_ts: float) -> dict:
    """Merge several pending payloads of one watch (used while a cooldown is active)."""
    header = (f"🔔 <b>{fa_digits(len(payloads))} رویداد در «{esc(watch.label)}»</b>\n"
              f"⏳ طی {human_duration(last_ts - first_ts)} گذشته (حالت تجمیع / cooldown)")
    blocks: list[str] = []
    full_blocks: list[str] = []
    for index, payload in enumerate(payloads, 1):
        marker = f"<b>{SEPARATOR} {fa_digits(index)} {SEPARATOR}</b>\n{payload['header']}"
        blocks.append(marker)
        blocks.extend(payload["blocks"])
        full_blocks.append(marker)
        full_blocks.extend(payload.get("full_blocks") or payload["blocks"])
    return _payload(header, f"<i>ادامهٔ رویدادهای «{esc(watch.label)}»</i>", blocks,
                    silent=all(p.get("silent") for p in payloads), doc_title=f"رویدادهای {watch.label}",
                    full_blocks=full_blocks, attach=any(p.get("attach") for p in payloads),
                    buttons=page_button(watch.page_url))
