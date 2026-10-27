"""Watch definitions, stored in SQLite and managed from the Telegram panel.

monitor-config.json only *seeds* the registry: its watches are imported once
(and again only if their entry in the file changes). Everything else — adding,
editing, pausing and deleting sites — happens in the database, so the config
file never has to be edited on the server.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import ConfigError, Watch, parse_watch
from .util import sha256_text


@dataclass
class WatchRecord:
    key: int            # short numeric handle (used in bot buttons)
    id: str
    spec: dict          # the definition, same keys as an entry of "watches" in the config file
    origin: str         # "config" | "bot"
    watch: Watch | None
    error: str = ""

    @property
    def label(self) -> str:
        return self.watch.label if self.watch else (self.spec.get("name") or self.id)


def spec_hash(spec: dict) -> str:
    return sha256_text(json.dumps(spec, sort_keys=True, ensure_ascii=False))


def default_crawl(url: str) -> dict:
    """Crawl scope for a URL: its first path section (e.g. /ir-de/…), or the whole site."""
    parts = urlsplit(url)
    host = re.escape((parts.hostname or "").removeprefix("www."))
    segments = [s for s in parts.path.split("/") if s]
    if segments and "." not in segments[0]:
        include = rf"^https?://(www\.)?{host}/{re.escape(segments[0])}(/|$|\?)"
    else:
        include = rf"^https?://(www\.)?{host}/"
    return {"include": [include], "max_pages": 100, "max_depth": 2, "interval_seconds": 900}


class WatchRegistry:
    def __init__(self, store, config):
        self.store = store
        self.config = config

    # ------------------------------------------------------------------ reading

    def _record(self, row) -> WatchRecord:
        spec = json.loads(row["spec"])
        try:
            return WatchRecord(row["key"], row["watch_id"], spec, row["origin"], parse_watch(spec, self.config.defaults))
        except ConfigError as exc:
            return WatchRecord(row["key"], row["watch_id"], spec, row["origin"], None, str(exc))

    def records(self) -> list[WatchRecord]:
        return [self._record(row) for row in self.store.list_specs()]

    def get(self, key: int | None = None, watch_id: str | None = None) -> WatchRecord | None:
        row = self.store.get_spec(key=key, watch_id=watch_id)
        if row is None or row["deleted"]:
            return None
        return self._record(row)

    def watches(self) -> list[Watch]:
        return [record.watch for record in self.records() if record.watch is not None]

    # ------------------------------------------------------------------ syncing with the config file

    def sync_from_config(self) -> list[str]:
        """Import new/changed watches from monitor-config.json. Returns human-readable notes."""
        notes = []
        for spec in self.config.raw_watches:
            watch_id = spec.get("id")
            digest = spec_hash(spec)
            row = self.store.get_spec(watch_id=watch_id)
            if row is None:
                self.store.add_spec(watch_id, spec, origin="config", config_hash=digest)
                notes.append(f"imported watch {watch_id!r} from the config file")
            elif row["origin"] == "config" and row["config_hash"] != digest:
                self.store.save_spec(row["key"], spec, config_hash=digest, undelete=True)
                notes.append(f"watch {watch_id!r} changed in the config file; updated")
        return notes

    # ------------------------------------------------------------------ changes

    def validate(self, spec: dict) -> Watch:
        return parse_watch(spec, self.config.defaults)

    def new_id(self, url: str) -> str:
        host = (urlsplit(url).hostname or "site").removeprefix("www.")
        base = re.sub(r"[^A-Za-z0-9]+", "-", host).strip("-")[:30] or "site"
        while True:
            candidate = f"{base}-{secrets.token_hex(2)}"
            if self.store.get_spec(watch_id=candidate) is None:
                return candidate

    def add(self, spec: dict, created_by: str | None = None) -> WatchRecord:
        spec = dict(spec)
        spec.setdefault("id", self.new_id(spec.get("url", "")))
        self.validate(spec)
        if self.store.get_spec(watch_id=spec["id"]) is not None:
            raise ConfigError(f"a watch with id {spec['id']!r} already exists")
        key = self.store.add_spec(spec["id"], spec, origin="bot", created_by=created_by)
        return self.get(key=key)

    def update(self, key: int, spec: dict) -> WatchRecord:
        current = self.get(key=key)
        if current is None:
            raise ConfigError("this site no longer exists")
        spec = dict(spec, id=current.id)  # the id never changes: history and state are keyed by it
        self.validate(spec)
        self.store.save_spec(key, spec)
        return self.get(key=key)

    def delete(self, key: int) -> WatchRecord | None:
        record = self.get(key=key)
        if record is not None:
            self.store.remove_spec(key, tombstone=record.origin == "config")
        return record
