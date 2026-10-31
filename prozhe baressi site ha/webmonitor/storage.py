"""SQLite state: page snapshots, seen items, per-watch health and the notification outbox.

Every detected change is written as an event in the *same transaction* as the
new snapshot (outbox pattern). Events stay "pending" until Telegram confirms
delivery, so a network outage or a crash can delay a notification but never
lose it.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections import Counter
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS pages (
    watch_id      TEXT NOT NULL,
    url           TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'page',
    digest        TEXT,
    snapshot      TEXT,
    title         TEXT,
    engine        TEXT,
    fingerprint   TEXT,
    etag          TEXT,
    last_modified TEXT,
    size          INTEGER,
    first_seen    REAL NOT NULL,
    last_seen     REAL,
    last_changed  REAL,
    fail_count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (watch_id, url)
);
CREATE TABLE IF NOT EXISTS seen_items (
    watch_id   TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    PRIMARY KEY (watch_id, item_id)
);
CREATE TABLE IF NOT EXISTS watch_state (
    watch_id           TEXT PRIMARY KEY,
    engine             TEXT,
    fingerprint        TEXT,
    crawl_fingerprint  TEXT,
    consecutive_errors INTEGER NOT NULL DEFAULT 0,
    first_error_at     REAL,
    last_error         TEXT,
    alerted            INTEGER NOT NULL DEFAULT 0,
    last_ok            REAL,
    last_check         REAL,
    last_crawl         REAL,
    last_notified      REAL,
    route              TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id     TEXT NOT NULL,
    url          TEXT,
    kind         TEXT NOT NULL,
    created      REAL NOT NULL,
    summary      TEXT,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_attempt REAL NOT NULL DEFAULT 0,
    progress     TEXT,
    sent_at      REAL,
    last_error   TEXT
);
CREATE INDEX IF NOT EXISTS events_pending ON events(status, next_attempt);
CREATE INDEX IF NOT EXISTS events_watch ON events(watch_id, created);
CREATE TABLE IF NOT EXISTS watches (
    key         INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id    TEXT NOT NULL UNIQUE,
    spec        TEXT NOT NULL,
    origin      TEXT NOT NULL DEFAULT 'bot',
    config_hash TEXT,
    deleted     INTEGER NOT NULL DEFAULT 0,
    created     REAL NOT NULL,
    updated     REAL NOT NULL,
    created_by  TEXT
);
CREATE TABLE IF NOT EXISTS admins (
    user_id    TEXT PRIMARY KEY,
    name       TEXT,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

_WATCH_COLUMNS = {
    "engine", "fingerprint", "crawl_fingerprint", "consecutive_errors", "first_error_at", "last_error",
    "alerted", "last_ok", "last_check", "last_crawl", "last_notified", "route",
}
# Columns added after the first release: (table, column, type) — added to older databases on start.
_MIGRATIONS = (("watch_state", "route", "TEXT"),)

Event = tuple  # (kind, summary, payload: dict, status)


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(str(path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        for table, column, kind in _MIGRATIONS:
            columns = {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                with self.conn:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ events

    def _insert_event(self, watch_id: str, url: str | None, event: Event) -> int:
        kind, summary, payload, status = event
        now = time.time()
        cur = self.conn.execute(
            "INSERT INTO events (watch_id, url, kind, created, summary, payload, status, sent_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (watch_id, url, kind, now, summary, json.dumps(payload, ensure_ascii=False), status,
             None if status == "pending" else now),
        )
        return cur.lastrowid

    def add_event(self, watch_id: str, url: str | None, kind: str, summary: str, payload: dict,
                  status: str = "pending") -> int:
        with self.conn:
            return self._insert_event(watch_id, url, (kind, summary, payload, status))

    def pending_events(self, now: float | None = None) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM events WHERE status = 'pending' AND next_attempt <= ? ORDER BY id",
            (now if now is not None else time.time(),),
        ).fetchall()

    def pending_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events WHERE status = 'pending'").fetchone()[0]

    def clear_pending_events(self, watch_id: str | None = None) -> int:
        """Cancel pending events in the outbox (all or for a specific watch) so they are not sent."""
        now = time.time()
        with self.conn:
            if watch_id:
                cur = self.conn.execute(
                    "UPDATE events SET status = 'filtered', sent_at = ?, last_error = 'cleared by admin' "
                    "WHERE status = 'pending' AND watch_id = ?",
                    (now, watch_id),
                )
            else:
                cur = self.conn.execute(
                    "UPDATE events SET status = 'filtered', sent_at = ?, last_error = 'cleared by admin' "
                    "WHERE status = 'pending'",
                    (now,),
                )
            return cur.rowcount

    def set_event_progress(self, event_id: int, progress: list[str]) -> None:
        with self.conn:
            self.conn.execute("UPDATE events SET progress = ? WHERE id = ?", (json.dumps(progress), event_id))

    def mark_events_sent(self, event_ids: list[int]) -> None:
        now = time.time()
        with self.conn:
            self.conn.executemany(
                "UPDATE events SET status = 'sent', sent_at = ?, last_error = NULL WHERE id = ?",
                [(now, event_id) for event_id in event_ids],
            )

    def finish_events(self, event_ids: list[int], status: str, error: str) -> None:
        """Close events that cannot (or need not) be retried: status 'sent' or 'failed'."""
        now = time.time()
        with self.conn:
            self.conn.executemany(
                "UPDATE events SET status = ?, sent_at = ?, last_error = ? WHERE id = ?",
                [(status, now, error[:500], event_id) for event_id in event_ids],
            )

    def mark_event_retry(self, event_id: int, attempts: int, next_attempt: float, error: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE events SET attempts = ?, next_attempt = ?, last_error = ? WHERE id = ?",
                (attempts, next_attempt, error[:500], event_id),
            )

    def recent_events(self, watch_id: str | None = None, limit: int = 20) -> list[sqlite3.Row]:
        if watch_id:
            return self.conn.execute(
                "SELECT * FROM events WHERE watch_id = ? ORDER BY id DESC LIMIT ?", (watch_id, limit)
            ).fetchall()
        return self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def last_event(self, watch_id: str, kinds) -> sqlite3.Row | None:
        kinds = list(kinds)
        marks = ",".join("?" * len(kinds))
        return self.conn.execute(
            f"SELECT * FROM events WHERE watch_id = ? AND kind IN ({marks}) ORDER BY id DESC LIMIT 1",
            (watch_id, *kinds),
        ).fetchone()

    def get_event(self, event_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()

    def count_events(self, watch_id: str, kinds, since: float) -> int:
        kinds = list(kinds)
        marks = ",".join("?" * len(kinds))
        return self.conn.execute(
            f"SELECT COUNT(*) FROM events WHERE watch_id = ? AND kind IN ({marks}) AND created >= ?",
            (watch_id, *kinds, since)).fetchone()[0]

    def event_counts_since(self, since: float) -> dict[str, Counter]:
        counts: dict[str, Counter] = {}
        for row in self.conn.execute(
            "SELECT watch_id, kind, COUNT(*) AS n FROM events WHERE created >= ? GROUP BY watch_id, kind", (since,)
        ):
            counts.setdefault(row["watch_id"], Counter())[row["kind"]] = row["n"]
        return counts

    # ------------------------------------------------------------------ pages

    def get_page(self, watch_id: str, url: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM pages WHERE watch_id = ? AND url = ?", (watch_id, url)).fetchone()

    def page_rows(self, watch_id: str) -> dict[str, sqlite3.Row]:
        rows = self.conn.execute("SELECT * FROM pages WHERE watch_id = ?", (watch_id,)).fetchall()
        return {row["url"]: row for row in rows}

    def page_counts(self) -> dict[str, int]:
        """Count tracked pages per watch without loading snapshot blobs."""
        return {
            row["watch_id"]: row["n"]
            for row in self.conn.execute("SELECT watch_id, COUNT(*) AS n FROM pages GROUP BY watch_id")
        }

    def page_summaries(self, watch_id: str, limit: int = 80) -> list[sqlite3.Row]:
        """Return lightweight metadata for subpages of a watch without loading large snapshot blobs."""
        return self.conn.execute(
            "SELECT url, title, engine, last_seen, last_changed FROM pages "
            "WHERE watch_id = ? ORDER BY last_changed DESC, last_seen DESC LIMIT ?",
            (watch_id, limit),
        ).fetchall()

    def page_urls(self, watch_id: str) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT url FROM pages WHERE watch_id = ?", (watch_id,))}

    def record_page(self, watch_id: str, url: str, *, kind: str = "page", digest: str | None = None,
                    snapshot: str | None = None, title: str | None = None, engine: str | None = None,
                    fingerprint: str | None = None, etag: str | None = None, last_modified: str | None = None,
                    size: int | None = None, changed: bool = False, event: Event | None = None) -> None:
        """Upsert a page snapshot and (atomically) queue its change event."""
        now = time.time()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO pages (watch_id, url, kind, digest, snapshot, title, engine, fingerprint, etag,
                                   last_modified, size, first_seen, last_seen, last_changed, fail_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(watch_id, url) DO UPDATE SET
                    kind = excluded.kind, digest = excluded.digest, snapshot = excluded.snapshot,
                    title = excluded.title, engine = excluded.engine, fingerprint = excluded.fingerprint,
                    etag = excluded.etag, last_modified = excluded.last_modified, size = excluded.size,
                    last_seen = excluded.last_seen,
                    last_changed = CASE WHEN ? THEN excluded.last_seen ELSE pages.last_changed END,
                    fail_count = 0
                """,
                (watch_id, url, kind, digest, snapshot, title, engine, fingerprint, etag, last_modified, size,
                 now, now, now if changed else None, 1 if changed else 0),
            )
            if event is not None:
                self._insert_event(watch_id, url, event)

    def touch_page(self, watch_id: str, url: str, etag: str | None = None, last_modified: str | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE pages SET last_seen = ?, fail_count = 0, etag = COALESCE(?, etag), "
                "last_modified = COALESCE(?, last_modified) WHERE watch_id = ? AND url = ?",
                (time.time(), etag, last_modified, watch_id, url),
            )

    def page_failed(self, watch_id: str, url: str) -> int:
        with self.conn:
            self.conn.execute("UPDATE pages SET fail_count = fail_count + 1 WHERE watch_id = ? AND url = ?",
                              (watch_id, url))
        row = self.conn.execute("SELECT fail_count FROM pages WHERE watch_id = ? AND url = ?",
                                (watch_id, url)).fetchone()
        return row[0] if row else 0

    def delete_page(self, watch_id: str, url: str, event: Event | None = None) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM pages WHERE watch_id = ? AND url = ?", (watch_id, url))
            if event is not None:
                self._insert_event(watch_id, url, event)

    # ------------------------------------------------------------------ items

    def seen_ids(self, watch_id: str) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT item_id FROM seen_items WHERE watch_id = ?", (watch_id,))}

    def has_items(self, watch_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM seen_items WHERE watch_id = ? LIMIT 1", (watch_id,)).fetchone() is not None

    def record_items(self, watch_id: str, item_ids: list[str], *, reset: bool = False, fingerprint: str | None = None,
                     event: Event | None = None) -> None:
        now = time.time()
        with self.conn:
            if reset:
                self.conn.execute("DELETE FROM seen_items WHERE watch_id = ?", (watch_id,))
            self.conn.executemany(
                "INSERT INTO seen_items (watch_id, item_id, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(watch_id, item_id) DO UPDATE SET last_seen = excluded.last_seen",
                [(watch_id, item_id, now, now) for item_id in item_ids],
            )
            if fingerprint is not None:
                self._upsert_watch(watch_id, {"fingerprint": fingerprint})
            if event is not None:
                self._insert_event(watch_id, None, event)

    # ------------------------------------------------------------------ watch state

    def watch_state(self, watch_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM watch_state WHERE watch_id = ?", (watch_id,)).fetchone()
        return dict(row) if row else {}

    def all_watch_states(self) -> dict[str, dict]:
        """Return all watch_state rows in a single query."""
        return {
            row["watch_id"]: dict(row)
            for row in self.conn.execute("SELECT * FROM watch_state")
        }

    def _upsert_watch(self, watch_id: str, fields: dict) -> None:
        unknown = set(fields) - _WATCH_COLUMNS
        if unknown:
            raise ValueError(f"unknown watch_state columns: {unknown}")
        self.conn.execute("INSERT OR IGNORE INTO watch_state (watch_id) VALUES (?)", (watch_id,))
        if fields:
            assignments = ", ".join(f"{column} = ?" for column in fields)
            self.conn.execute(f"UPDATE watch_state SET {assignments} WHERE watch_id = ?",
                              (*fields.values(), watch_id))

    def update_watch(self, watch_id: str, **fields) -> None:
        with self.conn:
            self._upsert_watch(watch_id, fields)

    def record_check_error(self, watch_id: str, message: str) -> dict:
        now = time.time()
        with self.conn:
            self._upsert_watch(watch_id, {})
            self.conn.execute(
                "UPDATE watch_state SET consecutive_errors = consecutive_errors + 1, last_error = ?, last_check = ?, "
                "first_error_at = COALESCE(first_error_at, ?) WHERE watch_id = ?",
                (message[:500], now, now, watch_id),
            )
        return self.watch_state(watch_id)

    def record_check_ok(self, watch_id: str) -> dict:
        """Mark a successful check; returns the state from *before* the reset."""
        previous = self.watch_state(watch_id)
        now = time.time()
        with self.conn:
            self._upsert_watch(watch_id, {"consecutive_errors": 0, "first_error_at": None, "alerted": 0,
                                          "last_ok": now, "last_check": now})
        return previous

    # ------------------------------------------------------------------ watch definitions (managed by the bot)

    def list_specs(self, include_deleted: bool = False) -> list[sqlite3.Row]:
        query = "SELECT * FROM watches" + ("" if include_deleted else " WHERE deleted = 0") + " ORDER BY key"
        return self.conn.execute(query).fetchall()

    def get_spec(self, key: int | None = None, watch_id: str | None = None) -> sqlite3.Row | None:
        if key is not None:
            return self.conn.execute("SELECT * FROM watches WHERE key = ?", (key,)).fetchone()
        return self.conn.execute("SELECT * FROM watches WHERE watch_id = ?", (watch_id,)).fetchone()

    def add_spec(self, watch_id: str, spec: dict, origin: str = "bot", config_hash: str | None = None,
                 created_by: str | None = None) -> int:
        now = time.time()
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO watches (watch_id, spec, origin, config_hash, created, updated, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (watch_id, json.dumps(spec, ensure_ascii=False), origin, config_hash, now, now, created_by),
            )
            return cur.lastrowid

    def save_spec(self, key: int, spec: dict, config_hash: str | None = None, undelete: bool = False) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE watches SET spec = ?, updated = ?, config_hash = COALESCE(?, config_hash), "
                "deleted = CASE WHEN ? THEN 0 ELSE deleted END WHERE key = ?",
                (json.dumps(spec, ensure_ascii=False), time.time(), config_hash, 1 if undelete else 0, key),
            )

    def remove_spec(self, key: int, tombstone: bool) -> None:
        """Tombstones keep watches from monitor-config.json from being imported again."""
        with self.conn:
            if tombstone:
                self.conn.execute("UPDATE watches SET deleted = 1, updated = ? WHERE key = ?", (time.time(), key))
            else:
                self.conn.execute("DELETE FROM watches WHERE key = ?", (key,))

    # ------------------------------------------------------------------ admins & settings

    def touch_admin(self, user_id: str, name: str) -> None:
        now = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT INTO admins (user_id, name, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen",
                (user_id, name, now, now),
            )

    def admin_ids(self) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT user_id FROM admins ORDER BY first_seen")]

    def get_setting(self, key: str, default: str) -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row and row[0] is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                              "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # ------------------------------------------------------------------ health & backup

    def quick_check(self) -> str:
        """``"ok"`` or the first problem SQLite reports (a fast structural check, run once at start-up)."""
        try:
            row = self.conn.execute("PRAGMA quick_check(1)").fetchone()
            return str(row[0]) if row else "no result"
        except sqlite3.Error as exc:
            return f"{type(exc).__name__}: {exc}"

    def overdue_outbox_age(self, now: float | None = None) -> float:
        """Seconds the oldest *due* notification has been waiting (0 when nothing is overdue).

        Events that wait on purpose (retry back-off, cooldown digests) are not due yet and do not count; a
        number that keeps growing means alerts are being created but cannot be delivered."""
        now = time.time() if now is None else now
        row = self.conn.execute("SELECT MIN(created) FROM events WHERE status = 'pending' AND next_attempt <= ?",
                                (now,)).fetchone()
        return max(0.0, now - row[0]) if row and row[0] is not None else 0.0

    def backup(self, directory: Path, keep: int = 7) -> Path | None:
        """Write a consistent copy of the database into ``directory`` and drop all but the newest ``keep``.

        Sites added from the Telegram panel exist only in this database, so a copy is the only way back after
        a damaged disk or file. It uses its own connection (``VACUUM INTO``), which makes it safe to call from a
        worker thread while the monitor keeps writing. A copy that fails its own integrity check is deleted
        and ``None`` is returned."""
        directory.mkdir(parents=True, exist_ok=True)
        # UTC stamp + microseconds: names sort in the order the copies were made (also across a DST change)
        moment = time.time()
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(moment))
        target = directory / f"monitor-{stamp}-{int(moment % 1 * 1_000_000):06d}.db"
        source = sqlite3.connect(str(self.path), timeout=30)
        try:
            source.execute("VACUUM INTO ?", (str(target),))
        finally:
            source.close()
        copy = sqlite3.connect(str(target))
        try:
            verdict = copy.execute("PRAGMA quick_check(1)").fetchone()
        finally:
            copy.close()
        if not verdict or verdict[0] != "ok":
            target.unlink(missing_ok=True)
            return None
        try:
            os.chmod(target, 0o600)  # the copy holds the admin list and every watch definition
        except OSError:
            pass
        if keep > 0:  # the new copy plus the newest keep-1 older ones stay
            older = sorted(p for p in directory.glob("monitor-*.db") if p != target)
            for old in older[:max(0, len(older) - (keep - 1))]:
                old.unlink(missing_ok=True)
        return target

    # ------------------------------------------------------------------ maintenance

    def reset_watch(self, watch_id: str) -> None:
        with self.conn:
            for table in ("pages", "seen_items", "watch_state"):
                self.conn.execute(f"DELETE FROM {table} WHERE watch_id = ?", (watch_id,))

    def forget_unknown_watches(self, known_ids: list[str]) -> list[str]:
        stored = {r[0] for r in self.conn.execute(
            "SELECT watch_id FROM pages UNION SELECT watch_id FROM seen_items UNION SELECT watch_id FROM watch_state")}
        stale = sorted(stored - set(known_ids))
        for watch_id in stale:
            self.reset_watch(watch_id)
        return stale

    def prune(self, history_days: int) -> None:
        now = time.time()
        with self.conn:
            self.conn.execute("DELETE FROM events WHERE status IN ('sent', 'filtered') AND created < ?",
                              (now - history_days * 86400,))
            self.conn.execute("DELETE FROM seen_items WHERE last_seen < ?", (now - max(history_days, 60) * 86400,))
