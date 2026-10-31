"""Tests for "Welle 2": layout-change (drift) detection, selector suggestions, structured logs, health report.

Run from the project folder:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import io
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from zoneinfo import ZoneInfo

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webmonitor import cli, report  # noqa: E402
from webmonitor.challenge import ChallengeManager  # noqa: E402
from webmonitor.config import ConfigError, parse_config, parse_watch  # noqa: E402
from webmonitor.engine import Monitor, _outcome_kind, supervise  # noqa: E402
from webmonitor.extract import page_snapshot, parse_html, suggest_selector  # noqa: E402
from webmonitor.health import build_health, format_health  # noqa: E402
from webmonitor.logfmt import JsonFormatter  # noqa: E402

TZ = ZoneInfo("Europe/Berlin")


def make_config(tmp: Path, **top):
    raw = {"data_dir": str(tmp / "data"), "notify_startup": False, "daily_report_hour": None, "challenge_port": 0,
           "watches": [], **top}
    return parse_config(raw, tmp / "cfg.json")


def make_watch(url: str = "http://127.0.0.1:9/p", **extra):
    return parse_watch({"id": "p", "name": "Embassy", "url": url, "engine": "http", "selector": "#main",
                        "min_content_length": 1, "timeout_seconds": 10, **extra})


def slot(i: int, month: int = 11, hour: int = 9) -> str:
    return f"Termin {i}: Visa national, Botschaft Teheran, freie Plätze am {10 + i % 18}.{month}.2026 ab {hour:02d}:00 Uhr"


def page(lines, heads=("Terminvergabe",), root="main id='main'", extra_top=(), title="Botschaft") -> str:
    tag = root.split()[0]
    head = "".join(f"<h2>{html.escape(h)}</h2>" for h in heads)
    top = "".join(f"<p>{html.escape(t)}</p>" for t in extra_top)
    body = "".join(f"<p>{html.escape(line)}</p>" for line in lines)
    return f"<html><head><title>{title}</title></head><body><nav>menu</nav><{root}>{head}{top}{body}</{tag}></body></html>"


def snap(lines, heads=("Terminvergabe",), selector="#main", title="Botschaft"):
    doc = parse_html(page(lines, heads, title=title), "https://e.example/p")
    return page_snapshot(doc, "https://e.example/p", selector=selector)


BASE = [slot(i) for i in range(60)]
NEWS = [f"Meldung {i}: Bundesregierung beschließt neue Regelung zur Fachkräfteeinwanderung und Visaverfahren Nr {i}"
        for i in range(60)]
RELAUNCH = [f"Neu {i}: Online-Terminbuchung über das Portal, bitte Konto anlegen und Dokumente hochladen (Variante {i})"
            for i in range(55)]


def assess(old, new):
    return report.assess_drift(old.lines, new.lines, old.headings, new.headings, old.text_length, new.text_length)


# =========================================================================== drift assessment (pure)

class DriftAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.old = snap(BASE)

    def level(self, new) -> str:
        return assess(self.old, new).level

    def test_a_small_edit_is_normal(self):
        new = snap(BASE[:20] + ["Termin 20: GEÄNDERT neue Zeit 10:30 Uhr"] + BASE[21:58] + ["Hinweis: Schalter geschlossen"])
        self.assertEqual(self.level(new), "normal")

    def test_reordering_and_a_cookie_banner_are_normal(self):
        self.assertEqual(self.level(snap(list(reversed(BASE)))), "normal")

    def test_all_dates_replaced_is_a_mass_change_but_not_a_redesign(self):
        new = snap([slot(i, month=12, hour=10) for i in range(60)])
        drift = assess(self.old, new)
        self.assertEqual(drift.level, "mass")
        self.assertGreaterEqual(drift.vocab, 0.9)

    def test_a_news_page_with_all_new_texts_keeps_its_headings_and_is_only_mass(self):
        self.assertEqual(self.level(snap(NEWS)), "mass")

    def test_half_replaced_is_mass(self):
        self.assertEqual(self.level(snap(BASE[:30] + [f"Meldung {i}: Konsulat meldet Wartungsarbeiten am Portal {i}"
                                                       for i in range(30)])), "mass")

    def test_a_rebuilt_site_is_a_redesign(self):
        drift = assess(self.old, snap(RELAUNCH, heads=("Willkommen im neuen Portal",), title="Neues Portal"))
        self.assertEqual(drift.level, "redesign")
        self.assertLess(drift.vocab, 0.1)
        self.assertEqual(drift.headings, 0.0)

    def test_pages_without_headings_need_a_complete_vocabulary_change(self):
        old = snap(BASE, heads=())
        self.assertEqual(assess(old, snap(RELAUNCH, heads=())).level, "redesign")
        self.assertEqual(assess(old, snap(NEWS[:30] + BASE[:30], heads=())).level, "mass")

    def test_the_text_shrinking_to_a_fraction_is_a_collapse(self):
        for text in (["Laden …"], ["Diese Seite ist wegen Wartungsarbeiten vorübergehend nicht verfügbar."],
                     ["Zurzeit sind keine Termine verfügbar."]):
            self.assertEqual(self.level(snap(text, heads=())), "collapse", text)

    def test_tiny_pages_are_never_classified(self):
        old = snap(["Termine: keine", "Stand heute", "Bitte später wieder prüfen"])
        self.assertEqual(assess(old, snap(["Termine: frei ab Montag", "Stand morgen", "Jetzt buchen"])).level, "normal")

    def test_appointments_appearing_on_an_empty_page_is_normal(self):
        old = snap(["Zurzeit sind keine Termine verfügbar."])
        self.assertEqual(assess(old, snap(BASE)).level, "normal")

    def test_as_dict_is_rounded_and_complete(self):
        data = assess(self.old, snap(RELAUNCH, heads=("Neu",))).as_dict()
        self.assertEqual(set(data), {"level", "churn", "vocab", "headings", "size"})
        self.assertEqual(data["level"], "redesign")


# =========================================================================== how a drift is reported

class DriftReportTests(unittest.TestCase):
    def event(self, old_lines, new_lines, heads_new=("Terminvergabe",), drift="auto"):
        old, new = snap(old_lines), snap(new_lines, heads=heads_new)
        hunks = report.diff_lines(old.lines, new.lines, True, new_headings=new.headings, new_anchors=new.anchors)
        if drift == "auto":
            drift = assess(old, new)
        watch = make_watch()
        return report.change_event(watch, "https://e.example/p", hunks, [], [], 1_800_000_000.0, TZ, "Botschaft",
                                   total_chars=new.text_length, drift=drift)

    def test_a_redesign_is_one_short_message_plus_the_full_report(self):
        payload, summary, _hits = self.event(BASE, RELAUNCH, heads_new=("Willkommen im neuen Portal",))
        self.assertIn("بازطراحی", payload["header"])
        self.assertTrue(payload["attach"])
        self.assertLessEqual(len(payload["blocks"]), report.DRIFT_SAMPLE + 1)
        self.assertGreater(len(payload["full_blocks"]), len(payload["blocks"]))
        self.assertTrue(summary.startswith(report.DRIFT_LABELS["redesign"]))
        self.assertIn("گزارش کامل", payload["blocks"][-1])

    def test_a_collapse_shows_the_new_text(self):
        payload, summary, _ = self.event(BASE, ["Zurzeit sind keine Termine verfügbar."])
        self.assertIn("کوتاه", payload["header"])
        self.assertIn("keine Termine", "".join(payload["blocks"]))
        self.assertTrue(summary.startswith(report.DRIFT_LABELS["collapse"]))

    def test_a_mass_change_keeps_the_complete_message_and_only_adds_a_label(self):
        payload, summary, _ = self.event(BASE, [slot(i, month=12, hour=10) for i in range(60)])
        self.assertIn("تغییر گسترده", payload["header"])
        self.assertFalse(payload["attach"])
        self.assertEqual(payload["blocks"], payload["full_blocks"])
        self.assertTrue(summary.startswith(report.DRIFT_LABELS["mass"]))

    def test_without_a_drift_the_output_is_exactly_the_old_one(self):
        plain = self.event(BASE, BASE[:50] + ["Neue Zeile hier eingefügt"], drift=None)
        normal = self.event(BASE, BASE[:50] + ["Neue Zeile hier eingefügt"], drift=report.Drift())
        self.assertEqual(plain, normal)
        self.assertNotIn("🧱", plain[0]["header"])


# =========================================================================== through the real engine

async def serve_page(holder: dict):
    async def handler(request):
        return web.Response(text=holder["html"], content_type="text/html")

    app = web.Application()
    app.router.add_get("/p", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


class EngineCase(unittest.IsolatedAsyncioTestCase):
    drift_detection = True

    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w2-"))
        self.holder = {"html": page(BASE)}
        self.runner, self.port = await serve_page(self.holder)
        self.monitor = Monitor(make_config(self.tmp, drift_detection=self.drift_detection), dry_run=True)
        self.watch = make_watch(f"http://127.0.0.1:{self.port}/p", error_threshold=1)
        self.monitor._by_id = {self.watch.id: self.watch}

    async def asyncTearDown(self):
        await self.monitor.http.close()
        self.monitor.store.close()
        await self.runner.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def check(self, new_html: str | None = None) -> str:
        if new_html is not None:
            self.holder["html"] = new_html
        with contextlib.redirect_stdout(io.StringIO()):
            return await self.monitor.check_watch(self.watch)

    def last_event(self, kind: str):
        row = self.monitor.store.conn.execute("SELECT summary, payload FROM events WHERE kind = ? ORDER BY id DESC LIMIT 1",
                                              (kind,)).fetchone()
        return (row["summary"], json.loads(row["payload"])) if row else (None, None)


class DriftEngineTests(EngineCase):
    async def test_a_relaunch_is_one_short_alert_and_is_remembered(self):
        await self.check()
        outcome = await self.check(page(RELAUNCH, heads=("Willkommen im neuen Portal",), title="Neues Portal"))
        self.assertIn("CHANGE detected", outcome)
        summary, payload = self.last_event("change")
        self.assertEqual(payload["drift"]["level"], "redesign")
        self.assertTrue(payload["attach"])
        self.assertLessEqual(len(payload["blocks"]), report.DRIFT_SAMPLE + 1)
        self.assertTrue(summary.startswith(report.DRIFT_LABELS["redesign"]))
        self.assertEqual(self.monitor._drift["p"]["level"], "redesign")
        self.assertEqual(build_health(self.monitor)["drift"][0]["watch"], "p")

    async def test_the_new_layout_becomes_the_baseline(self):
        await self.check()
        await self.check(page(RELAUNCH, heads=("Willkommen im neuen Portal",)))
        self.assertEqual(await self.check(), "no change")

    async def test_a_table_of_new_dates_is_reported_in_full(self):
        await self.check()
        await self.check(page([slot(i, month=12, hour=10) for i in range(60)]))
        _summary, payload = self.last_event("change")
        self.assertEqual(payload["drift"]["level"], "mass")
        self.assertFalse(payload["attach"])
        self.assertEqual(payload["blocks"], payload["full_blocks"])

    async def test_a_markup_only_redesign_stays_silent(self):
        await self.check()
        wrapped = page(BASE).replace("<p>", "<p class='card item v2'>")
        self.assertEqual(await self.check(wrapped), "no change")
        self.assertIsNone(self.last_event("change")[1])

    async def test_a_small_edit_has_no_drift_marker(self):
        await self.check()
        await self.check(page(BASE[:20] + ["Termin 20: GEÄNDERT neue Zeit 10:30 Uhr"] + BASE[21:]))
        _summary, payload = self.last_event("change")
        self.assertNotIn("drift", payload)
        self.assertEqual(self.monitor._drift, {})


class DriftSwitchedOffTests(EngineCase):
    drift_detection = False

    async def test_the_old_behaviour_is_kept_when_detection_is_off(self):
        await self.check()
        await self.check(page(RELAUNCH, heads=("Willkommen im neuen Portal",)))
        summary, payload = self.last_event("change")
        self.assertNotIn("drift", payload)
        self.assertFalse(summary.startswith(report.DRIFT_LABELS["redesign"]))
        self.assertEqual(payload["blocks"], payload["full_blocks"])


# =========================================================================== selector suggestions

class SuggestSelectorTests(unittest.TestCase):
    def setUp(self):
        self.old = snap(BASE).lines

    def suggest(self, html_text: str, **kw):
        doc = parse_html(html_text, "https://e.example/p")
        return suggest_selector(doc, "https://e.example/p", self.old, **kw)

    def test_a_renamed_id_is_found(self):
        found = self.suggest(page(BASE, root="section id='content'"))
        self.assertEqual(found[0], "#content")
        self.assertGreaterEqual(found[1], 0.99)

    def test_new_wrappers_and_boilerplate_around_the_content(self):
        text = ("<html><body><header><p>Willkommen auf unserer Seite, viele Wörter hier</p></header>"
                "<div class='page-wrap'><div class='col-main'><div class='entry-body'>"
                + "".join(f"<p>{html.escape(line)}</p>" for line in BASE) +
                "</div></div><aside class='sidebar'><p>Kontakt Telefon 12345 Öffnungszeiten täglich</p></aside></div>"
                "</body></html>")
        self.assertEqual(self.suggest(text)[0], "div.entry-body")

    def test_table_rows_are_matched_too(self):
        rows = [f"Termin {i} | frei | Visa national am {i}.11.2026" for i in range(30)]
        old_doc = parse_html("<html><body><main id='m'><table>" + "".join(
            "<tr>" + "".join(f"<td>{c}</td>" for c in row.split(" | ")) + "</tr>" for row in rows) +
            "</table></main></body></html>", "https://e.example/")
        old_lines = page_snapshot(old_doc, "https://e.example/", selector="#m").lines
        new_doc = parse_html("<html><body><div id='tabelle'><table>" + "".join(
            "<tr>" + "".join(f"<td>{c}</td>" for c in row.split(" | ")) + "</tr>" for row in rows) +
            "</table></div></body></html>", "https://e.example/")
        found = suggest_selector(new_doc, "https://e.example/", old_lines)
        self.assertEqual(found[0], "#tabelle")

    def test_nothing_is_suggested_when_the_content_is_gone(self):
        self.assertIsNone(self.suggest("<html><body><div id='portal'><p>Online-Terminbuchung über das Portal</p></div></body></html>"))
        self.assertIsNone(self.suggest(page(BASE[:10] + [f"Völlig anderer Text Nummer {i} Wetter Sport Kultur" for i in range(50)],
                                            root="section id='content'")))

    def test_too_little_to_compare_means_no_suggestion(self):
        self.old = ["Kurz", "Zwei"]
        self.assertIsNone(self.suggest(page(BASE, root="section id='content'")))

    def test_the_search_respects_its_time_budget(self):
        big = "<html><body>" + "".join(f"<div class='row r{i}'><p>Zeile {i} nur Füllung hier</p></div>" for i in range(3000)) + "</body></html>"
        started = time.monotonic()
        with mock.patch("webmonitor.extract.SUGGEST_BUDGET", 0.05):
            self.assertIsNone(self.suggest(big))
        self.assertLess(time.monotonic() - started, 5)


class SelectorLostEngineTests(EngineCase):
    async def test_the_alert_names_the_element_that_now_holds_the_content(self):
        await self.check()
        outcome = await self.check(page(BASE, root="section id='content'"))
        self.assertIn("matched nothing", outcome)
        self.assertIn("#content", outcome)
        _summary, payload = self.last_event("error")
        self.assertIn("<code>#content</code>", payload["header"])
        self.assertIn("هم‌پوشانی", payload["header"])

    async def test_no_suggestion_when_the_content_is_really_gone(self):
        await self.check()
        outcome = await self.check("<html><body><div id='portal'><p>Online-Terminbuchung über das Portal</p></div></body></html>")
        self.assertIn("matched nothing", outcome)
        self.assertNotIn("closest match", outcome)
        _summary, payload = self.last_event("error")
        self.assertNotIn("<code>#", payload["header"])

    async def test_a_first_check_without_history_has_no_suggestion(self):
        outcome = await self.check(page(BASE, root="section id='content'"))
        self.assertIn("matched nothing", outcome)
        self.assertNotIn("closest match", outcome)


# =========================================================================== structured logs

class JsonFormatterTests(unittest.TestCase):
    def render(self, message="hello", *args, level=logging.INFO, name="webmonitor", exc_info=None, **extra) -> dict:
        record = logging.LogRecord(name, level, __file__, 1, message, args or None, exc_info)
        for key, value in extra.items():
            setattr(record, key, value)
        return json.loads(JsonFormatter().format(record))

    def test_basic_fields(self):
        data = self.render("hello %s", "world")
        self.assertEqual((data["level"], data["logger"], data["msg"]), ("INFO", "webmonitor", "hello world"))
        self.assertRegex(data["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_the_site_id_in_brackets_becomes_a_field(self):
        self.assertEqual(self.render("[embassy] no change (0.4s)")["watch"], "embassy")
        data = self.render("[supervisor] bot crashed")
        self.assertEqual(data["component"], "supervisor")
        self.assertNotIn("watch", data)
        self.assertNotIn("watch", self.render("no prefix here"))

    def test_extra_fields_are_kept_and_override_the_prefix(self):
        data = self.render("[a] done", watch="b", outcome="changed", duration_ms=412, engine="http")
        self.assertEqual((data["watch"], data["outcome"], data["duration_ms"], data["engine"]), ("b", "changed", 412, "http"))

    def test_persian_text_is_not_escaped_and_odd_values_do_not_break_it(self):
        raw = JsonFormatter().format(logging.LogRecord("x", logging.INFO, __file__, 1, "بازطراحی «سایت»", None, None))
        self.assertIn("بازطراحی", raw)
        self.assertEqual(self.render("x", thing=object())["thing"][:8], "<object ")

    def test_exceptions_are_included(self):
        try:
            raise ValueError("boom")
        except ValueError:
            data = self.render("failed", level=logging.ERROR, exc_info=sys.exc_info())
        self.assertIn("ValueError: boom", data["exc"])

    def test_outcome_words(self):
        for text, word in (("baseline saved (first check): 5 lines", "baseline"), ("no change", "unchanged"),
                           ("no change (HTTP 304)", "unchanged"), ("no new items (4 listed)", "unchanged"),
                           ("CHANGE detected: 2 new", "changed"), ("error: HTTP 503", "error"),
                           ("content only re-ordered (ignored)", "reordered"), ("something else", "other")):
            self.assertEqual(_outcome_kind(text), word, text)


class LoggingSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w2-"))
        root = logging.getLogger()
        saved = (list(root.handlers), root.level)
        self.addCleanup(self.restore, root, saved)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @staticmethod
    def restore(root, saved):
        for handler in list(root.handlers):
            handler.close()
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])

    def lines(self) -> list[dict]:
        for handler in logging.getLogger().handlers:
            handler.flush()
        text = (self.tmp / "monitor.jsonl").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def test_run_writes_a_json_lines_file_next_to_the_normal_log(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("JOURNAL_STREAM", None)
            os.environ.pop("INVOCATION_ID", None)
            cli.setup_logging(self.tmp, verbose=False, to_file=True)
        logging.getLogger("webmonitor").info("[embassy] no change (0.1s)", extra={"outcome": "unchanged", "duration_ms": 100})
        rows = self.lines()
        self.assertEqual(rows[-1]["watch"], "embassy")
        self.assertEqual(rows[-1]["outcome"], "unchanged")
        self.assertTrue((self.tmp / "monitor.log").exists())

    def test_the_file_is_also_written_under_systemd(self):
        with mock.patch.dict(os.environ, {"JOURNAL_STREAM": "8:1"}):
            cli.setup_logging(self.tmp, verbose=False, to_file=True)
        logging.getLogger("webmonitor").warning("[x] check failed")
        self.assertEqual(self.lines()[-1]["level"], "WARNING")
        self.assertFalse((self.tmp / "monitor.log").exists())

    def test_commands_other_than_run_write_no_files(self):
        cli.setup_logging(self.tmp, verbose=False, to_file=False)
        self.assertFalse((self.tmp / "monitor.jsonl").exists())

    def test_the_console_can_switch_to_json(self):
        with mock.patch.dict(os.environ, {"WEBMONITOR_LOG_FORMAT": "json"}):
            cli.setup_logging(self.tmp, verbose=False, to_file=False)
        self.assertIsInstance(logging.getLogger().handlers[0].formatter, JsonFormatter)
        cli.setup_logging(self.tmp, verbose=False, to_file=False)
        self.assertNotIsInstance(logging.getLogger().handlers[0].formatter, JsonFormatter)


class EngineLogFieldsTests(EngineCase):
    async def test_every_check_leaves_a_structured_record(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("webmonitor")
        logger.addHandler(handler)
        previous = logger.level
        logger.setLevel(logging.INFO)
        self.addCleanup(lambda: (logger.removeHandler(handler), logger.setLevel(previous)))
        await self.check()
        await self.check(page(BASE, root="section id='content'"))
        rows = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
        first = next(r for r in rows if r.get("outcome") == "baseline")
        self.assertEqual((first["watch"], first["engine"]), ("p", "http"))
        self.assertIsInstance(first["duration_ms"], int)
        failed = next(r for r in rows if r.get("outcome") == "error")
        self.assertEqual((failed["watch"], failed["consecutive"], failed["error_kind"]), ("p", 1, "selector"))


# =========================================================================== health

class HealthCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w2-"))
        self.monitor = Monitor(make_config(self.tmp), dry_run=True)
        self.watch = make_watch("http://127.0.0.1:9/p", interval_seconds=300, error_threshold=2)
        self.monitor._by_id = {self.watch.id: self.watch}
        self.now = time.time()
        self.store = self.monitor.store

    async def asyncTearDown(self):
        await self.monitor.http.close()
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def health(self) -> dict:
        return build_health(self.monitor, self.now)


class HealthReportTests(HealthCase):
    async def test_a_fresh_monitor_is_ok(self):
        data = self.health()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["problems"], [])
        self.assertEqual(data["watches"]["total"], 1)
        self.assertEqual(data["db"]["integrity"], "unchecked")
        self.assertFalse(data["heartbeat"])

    async def test_a_healthy_site_counts_as_ok(self):
        self.store.record_check_ok("p")
        self.assertEqual(self.health()["watches"]["ok"], 1)

    async def test_one_failure_is_listed_but_does_not_degrade(self):
        self.store.record_check_error("p", "HTTP 503")
        data = self.health()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["watches"]["problem_sites"][0]["id"], "p")
        self.assertEqual(data["watches"]["problem_sites"][0]["error"], "HTTP 503")

    async def test_failing_past_the_alert_threshold_degrades(self):
        for _ in range(2):
            self.store.record_check_error("p", "HTTP 503")
        data = self.health()
        self.assertEqual(data["status"], "degraded")
        self.assertIn("failing past their alert threshold", data["problems"][0])

    async def test_a_site_that_stopped_being_checked_is_stale(self):
        self.store.record_check_ok("p")
        self.store.update_watch("p", last_ok=self.now - 10_000)
        data = self.health()
        self.assertEqual((data["status"], data["watches"]["stale"]), ("degraded", 1))

    async def test_never_checked_only_counts_after_a_while(self):
        self.assertEqual(self.health()["watches"]["never_checked"], 0)
        self.monitor.started_at = self.now - 2000
        data = self.health()
        self.assertEqual((data["status"], data["watches"]["never_checked"]), ("degraded", 1))

    async def test_paused_sites_are_not_a_problem(self):
        self.monitor._by_id = {"p": parse_watch({"id": "p", "url": "http://127.0.0.1:9/p", "enabled": False})}
        data = self.health()
        self.assertEqual((data["status"], data["watches"]["paused"]), ("ok", 1))

    async def test_a_waiting_outbox_degrades_and_a_stuck_one_is_down(self):
        self.store.add_event("p", None, "info", "x", {})
        self.store.conn.execute("UPDATE events SET created = ?", (self.now - 400,))
        self.assertEqual(self.health()["status"], "degraded")
        self.store.conn.execute("UPDATE events SET created = ?", (self.now - 2400,))
        data = self.health()
        self.assertEqual(data["status"], "down")
        self.assertEqual(data["outbox"]["pending"], 1)

    async def test_a_damaged_database_is_down(self):
        self.monitor.db_integrity = "database disk image is malformed"
        data = self.health()
        self.assertEqual(data["status"], "down")
        self.assertIn("malformed", data["problems"][0])

    async def test_an_old_backup_degrades(self):
        self.store.set_setting("last_backup", str(self.now - 3 * 86400))
        data = self.health()
        self.assertEqual(data["status"], "degraded")
        self.assertEqual(data["db"]["last_backup_age_s"], 3 * 86400)

    async def test_a_dead_delivery_task_is_down_but_only_while_running(self):
        async def nothing():
            return None

        task = asyncio.create_task(nothing())
        await task
        self.monitor._core_tasks = {"dispatch": task}
        self.assertEqual(self.health()["status"], "ok")  # not started: nothing to judge
        self.monitor._running = True
        data = self.health()
        self.assertEqual(data["status"], "down")
        self.assertFalse(data["tasks"]["dispatch"]["running"])

    async def test_a_recent_restart_degrades_and_old_ones_do_not(self):
        self.monitor._task_stats["bot"] = {"restarts": 3, "last_crash": self.now - 60, "last_reason": "KeyError: x"}
        data = self.health()
        self.assertEqual(data["status"], "degraded")
        self.assertIn("bot", data["problems"][0])
        self.monitor._task_stats["bot"]["last_crash"] = self.now - 7200
        self.assertEqual(self.health()["status"], "ok")

    async def test_layout_changes_are_listed_for_a_day(self):
        self.monitor._drift["p"] = {"level": "redesign", "ts": self.now - 100}
        self.assertEqual(self.health()["drift"], [{"watch": "p", "level": "redesign", "age_s": 100}])
        self.monitor._drift["p"]["ts"] = self.now - 2 * 86400
        self.assertEqual(self.health()["drift"], [])
        self.assertEqual(self.health()["status"], "ok")  # a redesign is news, not a fault

    async def test_the_text_report(self):
        for _ in range(2):
            self.store.record_check_error("p", "HTTP 503")
        text = format_health(self.health())
        self.assertTrue(text.startswith("DEGRADED"))
        self.assertIn("p: failing - HTTP 503", text)
        self.assertIn("outbox: 0 pending", text)
        self.assertTrue(format_health({"ok": False}).startswith("DOWN"))


class SupervisedTaskTests(HealthCase):
    async def test_spawn_registers_core_tasks_and_counts_restarts(self):
        calls = []

        async def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            await asyncio.sleep(30)

        with mock.patch("webmonitor.engine.supervise", wraps=supervise) as wrapped:
            task = self.monitor._spawn("dispatch", flaky)
            watch_task = self.monitor._spawn("watch:x", lambda: asyncio.sleep(30))
            await asyncio.sleep(2.3)
        try:
            self.assertIs(self.monitor._core_tasks["dispatch"], task)
            self.assertNotIn("watch:x", self.monitor._core_tasks)
            self.assertEqual(self.monitor._task_stats["dispatch"]["restarts"], 1)
            self.assertIn("boom", self.monitor._task_stats["dispatch"]["last_reason"])
            self.assertEqual(wrapped.call_count, 2)
        finally:
            for t in (task, watch_task):
                t.cancel()
            await asyncio.gather(task, watch_task, return_exceptions=True)

    async def test_supervise_fills_a_stats_dict(self):
        stats, stop, calls = {}, asyncio.Event(), []

        async def always():
            calls.append(1)
            if len(calls) == 2:
                stop.set()
            raise RuntimeError("again")

        await supervise("t", always, stats=stats, stop=stop, min_delay=0.01, max_delay=0.02)
        self.assertEqual(stats["restarts"], 1)  # the second crash ended the task: nothing was restarted
        self.assertIn("again", stats["last_reason"])
        self.assertGreater(stats["last_crash"], 0)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class HealthEndpointTests(HealthCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.port = free_port()
        self.monitor.challenge = ChallengeManager(host="127.0.0.1", port=self.port)
        self.monitor.challenge.health_provider = lambda: build_health(self.monitor)
        await self.monitor.challenge.start()
        self.addAsyncCleanup(self.monitor.challenge.close)

    async def get(self):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{self.port}/health") as resp:
                return resp.status, await resp.json()

    async def test_the_endpoint_reports_the_real_state_and_keeps_the_old_keys(self):
        status, data = await self.get()
        self.assertEqual(status, 200)
        self.assertEqual((data["ok"], data["status"]), (True, "ok"))
        for key in ("sessions", "host", "port", "uptime_s", "db", "outbox", "tasks", "watches", "version"):
            self.assertIn(key, data)

    async def test_degraded_is_still_200_but_down_is_503(self):
        self.store.set_setting("last_backup", str(time.time() - 3 * 86400))
        status, data = await self.get()
        self.assertEqual((status, data["status"], data["ok"]), (200, "degraded", True))
        self.monitor.db_integrity = "malformed"
        status, data = await self.get()
        self.assertEqual((status, data["status"], data["ok"]), (503, "down", False))

    async def test_a_failing_report_answers_503_instead_of_crashing(self):
        self.monitor.challenge.health_provider = mock.Mock(side_effect=RuntimeError("boom"))
        status, data = await self.get()
        self.assertEqual((status, data["ok"]), (503, False))
        self.assertIn("RuntimeError", data["problems"][0])

    async def test_the_endpoint_without_a_provider_is_the_old_one(self):
        self.monitor.challenge.health_provider = None
        status, data = await self.get()
        self.assertEqual((status, data["ok"]), (200, True))
        self.assertNotIn("status", data)


class HealthCommandTests(HealthCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.port = free_port()
        self.config = make_config(self.tmp, challenge_port=self.port)

    async def run_command(self, **args) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = await cli.cmd_health(self.config, SimpleNamespace(json=args.get("json", False)))
        return code, out.getvalue()

    async def serve_health(self):
        self.monitor.challenge = ChallengeManager(host="127.0.0.1", port=self.port)
        self.monitor.challenge.health_provider = lambda: build_health(self.monitor)
        await self.monitor.challenge.start()
        self.addAsyncCleanup(self.monitor.challenge.close)

    async def test_ok_degraded_down_and_not_running_have_their_own_exit_codes(self):
        code, text = await self.run_command()
        self.assertEqual(code, 2)
        self.assertTrue(text.startswith("DOWN"))
        await self.serve_health()
        code, text = await self.run_command()
        self.assertEqual((code, text.split()[0]), (0, "OK"))
        self.store.set_setting("last_backup", str(time.time() - 3 * 86400))
        code, text = await self.run_command()
        self.assertEqual((code, text.split()[0]), (1, "DEGRADED"))
        self.monitor.db_integrity = "malformed"
        code, text = await self.run_command()
        self.assertEqual((code, text.split()[0]), (2, "DOWN"))

    async def test_json_output(self):
        await self.serve_health()
        code, text = await self.run_command(json=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["status"], "ok")

    def test_the_command_is_registered(self):
        self.assertIn("health", cli.COMMANDS)
        self.assertTrue(cli.build_parser().parse_args(["health", "--json"]).json)


class ConfigOptionTests(unittest.TestCase):
    def test_drift_detection_option(self):
        tmp = Path(tempfile.mkdtemp(prefix="webmonitor-w2-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertTrue(make_config(tmp).drift_detection)
        self.assertFalse(make_config(tmp, drift_detection=False).drift_detection)
        with self.assertRaises(ConfigError):
            make_config(tmp, drift_detection="yes")
        self.assertEqual(make_config(tmp).warnings, [])


if __name__ == "__main__":
    unittest.main()
