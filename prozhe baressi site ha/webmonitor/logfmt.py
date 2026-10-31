"""Machine-readable logs: one JSON object per line (``data/monitor.jsonl``).

The human-readable console / ``monitor.log`` output stays as it is; this file is for tools - ``jq``, a log
shipper, or a quick "which site failed how often today" question::

    jq -c 'select(.watch=="embassy" and .level!="INFO")' data/monitor.jsonl
    jq -c 'select(.outcome=="changed") | {ts, watch, duration_ms}' data/monitor.jsonl

Every record has ``ts`` (UTC), ``level``, ``logger`` and ``msg``. A message that starts with ``[site-id]`` gets
a ``watch`` field, and anything passed through ``extra={...}`` (``outcome``, ``duration_ms``, ``engine``, ...)
becomes a field of its own, so the existing log calls did not have to change.
"""

from __future__ import annotations

import json
import logging
import re
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

# every attribute a plain LogRecord has; anything else was passed with ``extra=`` and is worth keeping
_STANDARD = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}
_PREFIX = re.compile(r"^\[([^\]\s]{1,64})\]\s")
_COMPONENTS = frozenset({"supervisor"})  # bracket tags that name a part of the monitor, not a site
MAX_TEXT = 4000


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        data: dict = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": message[:MAX_TEXT],
        }
        match = _PREFIX.match(message)
        if match:
            data["component" if match.group(1) in _COMPONENTS else "watch"] = match.group(1)
        for key, value in record.__dict__.items():
            if key not in _STANDARD and not key.startswith("_"):
                data[key] = value
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)[-MAX_TEXT:]
        return json.dumps(data, ensure_ascii=False, default=str, separators=(",", ":"))


def add_json_file(root: logging.Logger, data_dir: Path, level: int = logging.INFO) -> logging.Handler:
    """Attach the rotating JSON-lines file (5 MB x 3 copies) to ``root``."""
    data_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(data_dir / "monitor.jsonl", maxBytes=5 * 1024 * 1024, backupCount=3,
                                  encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    return handler
