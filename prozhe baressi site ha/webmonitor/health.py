"""Health report: one JSON-able dict that says whether the monitor is really doing its job.

``GET /health`` on the local admin port (127.0.0.1) and ``python monitor_system.py health`` both use it. The
old endpoint answered ``ok`` as long as the process lived - even when notifications were piling up undelivered
or a background task had died. The three states mean:

* ``ok``       - everything is working;
* ``degraded`` - the monitor runs but something needs a look (a site keeps failing or has not been checked for
                 a long time, a part restarted recently, the outbox is slow, no backup for days);
* ``down``     - the monitor cannot do its job (damaged database, delivery loop dead, alerts stuck for 30+ min).
"""

from __future__ import annotations

import os
import time

from . import __version__
from .util import truncate

OUTBOX_DEGRADED = 300      # a due notification waiting longer than this (seconds) is a warning ...
OUTBOX_DOWN = 1800         # ... and this long means alerts are not getting out at all
BACKUP_STALE = 2 * 86400   # the daily backup should never be older than this
STALE_FACTOR = 3           # a site is "stale" after this many missed check intervals ...
STALE_MIN = 900            # ... but never earlier than this many seconds
NEVER_CHECKED_AFTER = 900  # seconds of uptime after which "not checked yet" counts as a problem
RECENT_CRASH = 3600        # a task restart within this window is worth reporting
DRIFT_WINDOW = 86400
MAX_LISTED = 10
CORE_TASKS = ("dispatch", "housekeeping", "heartbeat", "bot")

_RANK = {"ok": 0, "degraded": 1, "down": 2}


def _age(now: float, then) -> int | None:
    """Seconds since the timestamp ``then`` (None when it is missing, zero or unreadable)."""
    try:
        then = float(then or 0)
    except (TypeError, ValueError):
        return None
    return max(0, int(now - then)) if then > 0 else None


def build_health(monitor, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    store = monitor.store
    problems: list[str] = []
    level = "ok"

    def flag(state: str, text: str) -> None:
        nonlocal level
        problems.append(text)
        if _RANK[state] > _RANK[level]:
            level = state

    # --- database
    integrity = getattr(monitor, "db_integrity", "unchecked")
    try:
        size = os.path.getsize(monitor.config.data_dir / "monitor.db")
    except OSError:
        size = None
    backup_age = _age(now, store.get_setting("last_backup", "0") or 0)
    db = {"integrity": integrity, "size_bytes": size, "last_backup_age_s": backup_age}
    if integrity not in ("ok", "unchecked"):
        flag("down", f"database integrity check failed: {truncate(str(integrity), 120)}")
    if backup_age is not None and backup_age > BACKUP_STALE:
        flag("degraded", f"no database backup for {backup_age // 86400} days")

    # --- outbox (notifications that are due but not delivered)
    overdue = int(store.overdue_outbox_age(now))
    outbox = {"pending": store.pending_count(), "overdue_s": overdue}
    if overdue >= OUTBOX_DOWN:
        flag("down", f"notifications are stuck: the oldest has been waiting {overdue // 60} min")
    elif overdue >= OUTBOX_DEGRADED:
        flag("degraded", f"notifications are slow: the oldest has been waiting {overdue // 60} min")

    # --- background tasks
    tasks: dict[str, dict] = {}
    core = getattr(monitor, "_core_tasks", {})
    stats = getattr(monitor, "_task_stats", {})
    for name, task in core.items():
        info = stats.get(name, {})
        tasks[name] = {"running": not task.done(), "restarts": info.get("restarts", 0),
                       "last_crash_s": _age(now, info.get("last_crash")), "last_reason": info.get("last_reason", "")}
    if getattr(monitor, "_running", False):
        for name in ("dispatch", "housekeeping"):
            if name in tasks and not tasks[name]["running"]:
                flag("down", f"the {name} task is not running")
        for name, info in tasks.items():
            if name not in ("dispatch", "housekeeping") and not info["running"]:
                flag("degraded", f"the {name} task is not running")
    restarted = sorted(name for name, info in stats.items()
                       if info.get("last_crash") and now - info["last_crash"] < RECENT_CRASH)
    if restarted:
        shown = ", ".join(restarted[:5]) + (" ..." if len(restarted) > 5 else "")
        flag("degraded", f"restarted in the last hour: {shown}")

    # --- sites
    counts = {"total": 0, "ok": 0, "failing": 0, "stale": 0, "paused": 0, "never_checked": 0}
    listed: list[dict] = []
    uptime = max(0, int(now - getattr(monitor, "started_at", now)))
    persistent = 0
    for w in monitor.all_watches:
        counts["total"] += 1
        if not w.enabled:
            counts["paused"] += 1
            continue
        state = store.watch_state(w.id)
        errors = state.get("consecutive_errors") or 0
        last_ok = state.get("last_ok")
        if errors:
            counts["failing"] += 1
            if errors >= w.error_threshold:
                persistent += 1
            if len(listed) < MAX_LISTED:
                listed.append({"id": w.id, "problem": "failing", "errors": errors,
                               "since_s": _age(now, state.get("first_error_at")),
                               "error": truncate(state.get("last_error") or "", 120)})
        elif last_ok and now - last_ok > max(STALE_FACTOR * w.interval_seconds, STALE_MIN):
            counts["stale"] += 1
            if len(listed) < MAX_LISTED:
                listed.append({"id": w.id, "problem": "stale", "last_ok_s": _age(now, last_ok)})
        elif not last_ok and uptime > NEVER_CHECKED_AFTER:
            counts["never_checked"] += 1
            if len(listed) < MAX_LISTED:
                listed.append({"id": w.id, "problem": "never_checked"})
        else:
            counts["ok"] += 1
    if persistent:
        flag("degraded", f"{persistent} site(s) failing past their alert threshold")
    if counts["stale"]:
        flag("degraded", f"{counts['stale']} site(s) not checked for a long time")
    if counts["never_checked"]:
        flag("degraded", f"{counts['never_checked']} site(s) never checked successfully")
    watches = {**counts, "problem_sites": listed}

    # --- layout changes seen recently (informational: a redesign is news, not a fault)
    drift = [{"watch": watch_id, "level": info["level"], "age_s": _age(now, info["ts"])}
             for watch_id, info in sorted(getattr(monitor, "_drift", {}).items(), key=lambda kv: -kv[1]["ts"])
             if now - info["ts"] < DRIFT_WINDOW][:MAX_LISTED]

    return {"status": level, "problems": problems, "version": __version__, "uptime_s": uptime, "db": db,
            "outbox": outbox, "tasks": tasks, "watches": watches, "drift": drift,
            "heartbeat": bool(monitor.config.heartbeat_url)}


def format_health(data: dict) -> str:
    """The same report as plain text (for the ``health`` command)."""
    def duration(seconds) -> str:
        if seconds is None:
            return "-"
        seconds = int(seconds)
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if seconds >= size:
                return f"{seconds // size}{unit}"
        return f"{seconds}s"

    status = str(data.get("status") or ("ok" if data.get("ok") else "down")).upper()
    lines = [f"{status}   version {data.get('version', '?')}   up {duration(data.get('uptime_s'))}"]
    for problem in data.get("problems", []):
        lines.append(f"  ! {problem}")
    watches = data.get("watches") or {}
    if watches:
        lines.append(f"sites:  {watches.get('ok', 0)} ok, {watches.get('failing', 0)} failing, "
                     f"{watches.get('stale', 0)} stale, {watches.get('never_checked', 0)} never checked, "
                     f"{watches.get('paused', 0)} paused (of {watches.get('total', 0)})")
        for site in watches.get("problem_sites", []):
            extra = site.get("error") or ""
            lines.append(f"  - {site['id']}: {site['problem']}" + (f" - {extra}" if extra else ""))
    outbox = data.get("outbox") or {}
    if outbox:
        lines.append(f"outbox: {outbox.get('pending', 0)} pending, oldest overdue {duration(outbox.get('overdue_s'))}")
    db = data.get("db") or {}
    if db:
        lines.append(f"db:     {db.get('integrity')}, last backup {duration(db.get('last_backup_age_s'))} ago")
    for name, info in (data.get("tasks") or {}).items():
        mark = "running" if info.get("running") else "STOPPED"
        lines.append(f"task {name}: {mark}, {info.get('restarts', 0)} restart(s)")
    for entry in data.get("drift") or []:
        lines.append(f"layout change: {entry['watch']} ({entry['level']}, {duration(entry.get('age_s'))} ago)")
    return "\n".join(lines)
