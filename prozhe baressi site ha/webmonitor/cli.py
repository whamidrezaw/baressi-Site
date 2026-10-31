"""Command-line interface: python monitor_system.py <command> [options]"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import zipfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config, parse_config
from .engine import Monitor
from .health import format_health
from .logfmt import JsonFormatter, add_json_file
from .notifier import NotifyError, TelegramNotifier, build_parts, explain_telegram_error, html_to_text
from .registry import WatchRegistry
from .storage import Store
from .util import format_ts, load_timezone, truncate

log = logging.getLogger("webmonitor")
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "monitor-config.json"


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def setup_logging(data_dir: Path, verbose: bool, to_file: bool) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    under_systemd = bool(os.environ.get("JOURNAL_STREAM") or os.environ.get("INVOCATION_ID"))
    console = logging.StreamHandler(sys.stdout)
    if os.environ.get("WEBMONITOR_LOG_FORMAT", "").strip().lower() == "json":
        console.setFormatter(JsonFormatter())  # one JSON object per line, e.g. for journald or a log shipper
    else:
        console.setFormatter(logging.Formatter(
            "[%(levelname)s] %(message)s" if under_systemd else "%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root.addHandler(console)
    if to_file and not under_systemd:
        data_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(data_dir / "monitor.log", maxBytes=5 * 1024 * 1024, backupCount=3,
                                      encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        root.addHandler(handler)
    if to_file:
        add_json_file(root, data_dir, logging.DEBUG if verbose else logging.INFO)  # data/monitor.jsonl (jq & co.)
    for noisy in ("asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _all_watches(config) -> list:
    """Every site: those from monitor-config.json (imported) plus those added in the Telegram panel."""
    store = Store(config.data_dir / "monitor.db")
    try:
        registry = WatchRegistry(store, config)
        registry.sync_from_config()
        return registry.watches()
    finally:
        store.close()


def _select(watches: list, ids: list[str]) -> list:
    if not ids:
        return [w for w in watches if w.enabled]
    by_id = {w.id: w for w in watches}
    for watch_id in ids:
        if watch_id not in by_id:
            raise ConfigError(f"no watch with id {watch_id!r} (known: {', '.join(by_id) or 'none'})")
    return [by_id[watch_id] for watch_id in ids]


# --------------------------------------------------------------------------- commands

async def cmd_run(config, args) -> int:
    if not config.telegram.enabled:
        log.warning("Telegram is not configured — notifications are only printed here. "
                    "Set telegram.token and telegram.chat_ids in %s", config.path.name)
    monitor = Monitor(config)
    await monitor.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, monitor.stop)
        except (NotImplementedError, RuntimeError, ValueError):
            pass  # Windows: Ctrl+C raises KeyboardInterrupt instead
    try:
        await monitor.run_forever()
    finally:
        await monitor.close()
    return 0


def _use_dry_run_state(config) -> None:
    """Dry runs keep their own memory, so they can never swallow a change the real service must report."""
    config.data_dir = config.data_dir / "dry-run"


async def cmd_once(config, args) -> int:
    watches = _select(_all_watches(config), args.watch)
    if args.dry_run:
        _use_dry_run_state(config)
    monitor = Monitor(config, dry_run=args.dry_run, watches=watches if args.dry_run else None)
    await monitor.start()
    try:
        results = await monitor.run_once(watches)
    finally:
        await monitor.close()
    print("\n=== Results ===")
    failed = 0
    for watch, outcome in results:
        failed += outcome.startswith("error")
        print(f"{watch.id:<24} {outcome}")
    return 1 if failed else 0


async def cmd_preview(config, args) -> int:
    watch = _select(_all_watches(config), [args.watch])[0]
    _use_dry_run_state(config)
    monitor = Monitor(config, dry_run=True, watches=[watch])
    await monitor.start()
    try:
        if watch.type in ("page", "json"):
            result, parsed = await monitor._fetch_parse(watch, watch.url, lambda r: monitor._parse_content(watch, r),
                                                        wait_for=watch.wait_selector)
            snap, discovered = parsed
            print(f"engine={result.engine}  HTTP {result.status}  {result.elapsed:.1f}s  title: {snap.title}")
            print(f"=== {len(snap.lines)} lines, {snap.text_length:,} chars ===")
            for line in snap.lines[: args.limit]:
                print(f"  {line}")
            if len(snap.lines) > args.limit:
                print(f"  … {len(snap.lines) - args.limit} more lines (use --limit)")
            if snap.links:
                print(f"=== {len(snap.links)} tracked links ===")
                for text, url in snap.links[: args.limit]:
                    print(f"  {truncate(text, 70):<70}  {url}")
            if watch.crawl:
                scoped = [u for _, u in discovered if monitor._crawl_kind(watch, u)]
                print(f"=== crawl scope: {len(scoped)} in-scope link(s) on the start page ===")
                for url in scoped[: args.limit]:
                    print(f"  {url}")
        else:
            parse = monitor._parser(watch)
            result, items = await monitor._fetch_parse(watch, watch.url, lambda r: parse(watch, r),
                                                       wait_for=watch.wait_selector)
            print(f"engine={result.engine}  HTTP {result.status}  {result.elapsed:.1f}s  — {len(items)} items")
            for item in items[: args.limit]:
                print(f" • {truncate(item.title, 140)}\n   {item.url or '(no link)'}  [id={truncate(item.id, 60)}]")
    except Exception as exc:  # FetchError / ExtractError
        print(f"FAILED: {exc}")
        return 1
    finally:
        await monitor.close()
    return 0


async def cmd_diagnose(config, args) -> int:
    _use_dry_run_state(config)  # nothing here may touch the live database
    monitor = Monitor(config, dry_run=True, watches=[])
    await monitor.start()
    try:
        results = await monitor.diagnose(args.url)
    finally:
        await monitor.close()
    print(f"Access test for {args.url} from this machine:")
    for route, engine, ok, detail in results:
        where = "via fallback proxy" if route == "fallback" else "direct"
        print(f"  {'OK  ' if ok else 'FAIL'}  {where:<18} {engine:<12} {detail}")
    working = [(route, engine) for route, engine, ok, _ in results if ok]
    if not working:
        print("\n→ nothing works from this machine: the site probably blocks this IP (and the proxy)")
    elif working[0][0] == "fallback":
        print(f"\n→ blocked directly; works through the fallback proxy with engine \"{working[0][1]}\" "
              "(the monitor switches to it automatically)")
    else:
        print(f"\n→ use engine \"{working[0][1]}\"")
    return 0 if working else 1


async def cmd_inspect(config, args) -> int:
    from .analyzer import inspect
    return await inspect(config, args.url, use_browser=args.browser, selector=args.selector or "",
                         items=args.items or "")


async def cmd_test_telegram(config, args) -> int:
    if not config.telegram.token:
        print("No bot token configured (telegram.token or the TELEGRAM_BOT_TOKEN environment variable).")
        return 1
    notifier = TelegramNotifier(config.telegram)
    try:
        me = await notifier.call("getMe")
        print(f"Bot OK: @{me.get('username')} ({me.get('first_name')})")
        if not config.telegram.chat_ids:
            print("No chat_ids configured yet. Run:  python monitor_system.py chat-id")
            return 1
        for chat_id in config.telegram.chat_ids:
            await notifier.send_text(chat_id, "✅ <b>تست موفق</b>\nربات مانیتور می‌تواند به این چت پیام بفرستد.")
            print(f"Test message sent to {chat_id}")
    except NotifyError as exc:
        advice = explain_telegram_error(exc)
        print(f"FAILED: {exc}" + (f"\n→ {advice}" if advice else ""))
        return 1
    finally:
        await notifier.close()
    return 0


async def cmd_chat_id(config, args) -> int:
    if not config.telegram.token:
        print("Set telegram.token first (from @BotFather).")
        return 1
    notifier = TelegramNotifier(config.telegram)
    try:
        updates = await notifier.call("getUpdates", {"timeout": 0,
                                                     "allowed_updates": ["message", "channel_post", "my_chat_member"]})
    except NotifyError as exc:
        print(f"FAILED: {exc}\n(If the monitor service is running it consumes the updates — stop it first.)")
        return 1
    finally:
        await notifier.close()
    chats = {}
    for update in updates or []:
        holder = update.get("message") or update.get("channel_post") or update.get("my_chat_member") or {}
        chat = holder.get("chat")
        if chat:
            chats[chat["id"]] = chat
    if not chats:
        print("No chats found. Open your bot in Telegram and press Start (or send it any message).\n"
              "For a group/channel: add the bot (as admin for channels), post a message, then run this again.")
        return 1
    for chat in chats.values():
        name = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
        print(f"chat_id: {chat['id']:<16} type: {chat.get('type', ''):<10} name: {name}")
    print('\nPut the id(s) into "chat_ids" in monitor-config.json, e.g.  "chat_ids": ["123456789"]')
    return 0


async def cmd_history(config, args) -> int:
    store = Store(config.data_dir / "monitor.db")
    tz = load_timezone(config.timezone)
    try:
        if args.show:
            row = store.conn.execute("SELECT * FROM events WHERE id = ?", (args.show,)).fetchone()
            if row is None:
                print(f"No event #{args.show}")
                return 1
            for kind, content in build_parts(json.loads(row["payload"])):
                if kind == "text":
                    print(html_to_text(content))
                    print("─" * 60)
            return 0
        rows = store.recent_events(args.watch, args.limit)
        if not rows:
            print("No events recorded yet.")
        for row in reversed(rows):
            print(f"#{row['id']:<5} {format_ts(row['created'], tz)}  {row['watch_id']:<20} {row['kind']:<12} "
                  f"{row['status']:<8} {row['summary'] or ''}")
        if rows:
            print("\nShow a full report with:  python monitor_system.py history --show <#id>")
    finally:
        store.close()
    return 0


async def cmd_reset(config, args) -> int:
    watch = _select(_all_watches(config), [args.watch])[0]
    store = Store(config.data_dir / "monitor.db")
    try:
        store.reset_watch(watch.id)
    finally:
        store.close()
    for subdir in ("sessions", "sessions-impersonate"):
        session = config.data_dir / subdir / f"{watch.id}.json"
        if session.exists():
            session.unlink()
    print(f"State of {watch.id!r} cleared; the next check saves a fresh baseline (no notification).")
    return 0


PACKAGE_ITEMS = ("webmonitor", "deploy", "tests", "monitor_system.py", "monitor-config.json",
                 "monitor-config.example.json", "requirements.txt", "README.md", "run_windows.bat")


async def cmd_package(config, args) -> int:
    """Zip only what the server needs (no .venv / data), with forward-slash paths for Linux unzip."""
    root = Path(__file__).resolve().parent.parent
    target = Path(args.output).resolve() if args.output else root.parent / "monitor-deploy.zip"
    count = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in PACKAGE_ITEMS:
            path = root / name
            if path.is_file():
                files = [path]
            elif path.is_dir():
                files = sorted(p for p in path.rglob("*") if p.is_file())
            else:
                continue
            for file in files:
                if "__pycache__" in file.parts or file.suffix == ".pyc":
                    continue
                archive.write(file, file.relative_to(root).as_posix())
                count += 1
    print(f"Created {target}  ({count} files, {target.stat().st_size / 1024:.0f} KB)")
    if not config.telegram.enabled:
        print("WARNING: telegram.token / chat_ids are not set in the config — the server will only log messages.")
    print(f"Sites defined in the config file: {len(config.watches)} (sites added in the Telegram panel live in "
          "the server database and are not affected)")
    print("\nUpload it to your server, for example:\n"
          f'  scp -i "<your key>" "{target}" ubuntu@<server-ip>:monitor-deploy.zip')
    return 0


async def cmd_validate(config, args) -> int:
    print(f"Config OK: {config.path}")
    tg = config.telegram
    if tg.enabled:
        print(f"Telegram: token set, chat_ids: {', '.join(tg.chat_ids)}")
    else:
        print("Telegram: NOT configured — notifications will only be printed to the console")
    watches = _all_watches(config)
    from_file = {w.id for w in config.watches}
    print(f"Sites: {len(watches)} ({len(from_file)} from the config file, {len(watches) - len(from_file)} "
          "added in the Telegram panel)")
    for w in watches:
        extra = [] if w.id in from_file else ["bot"]
        if w.crawl:
            extra.append(f"crawl≤{w.crawl.max_pages} pages/depth {w.crawl.max_depth}")
        if w.keywords:
            extra.append(f"{len(w.keywords)} keywords")
        if w.cooldown_minutes:
            extra.append(f"cooldown {w.cooldown_minutes:g}m")
        state = "on " if w.enabled else "off"
        print(f"  [{state}] {w.id:<22} {w.type:<5} {w.engine:<7} every {w.interval_seconds:g}s  {w.url}"
              + (f"  ({', '.join(extra)})" if extra else ""))
    for warning in config.warnings:
        print(f"WARNING: {warning}")
    return 0


async def cmd_health(config, args) -> int:
    """Ask the RUNNING monitor how it is doing. Exit code: 0 ok, 1 degraded, 2 down or not running."""
    import aiohttp

    host = "127.0.0.1" if config.challenge_host in ("", "0.0.0.0", "::") else config.challenge_host
    url = f"http://{host}:{config.challenge_port}/health"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(url) as resp:
                data = await resp.json(content_type=None)
    except Exception as exc:
        print(f"DOWN   the monitor does not answer on {url} ({type(exc).__name__}) - is it running?")
        return 2
    print(json.dumps(data, ensure_ascii=False, indent=2) if args.json else format_health(data))
    status = data.get("status") or ("ok" if data.get("ok") else "down")
    return {"ok": 0, "degraded": 1}.get(status, 2)


# --------------------------------------------------------------------------- entry point

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monitor_system.py",
        description="Website change monitor with Telegram alerts (embassy pages, news lists, RSS).")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG), help="config file (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.add_parser("run", help="start monitoring (default)")
    p = sub.add_parser("once", help="check every watch once and send/print the results")
    p.add_argument("watch", nargs="*", help="watch ids (default: all enabled)")
    p.add_argument("--dry-run", action="store_true", help="print notifications instead of sending them")
    p = sub.add_parser("inspect", help="analyse a URL and suggest selectors / settings")
    p.add_argument("url")
    p.add_argument("--browser", action="store_true", help="load the page with the browser engine")
    p.add_argument("--selector", help="show exactly the text this selector would monitor")
    p.add_argument("--items", metavar="ITEM_SELECTOR", help="show the items this item_selector would find")
    p = sub.add_parser("diagnose", help="test which fetch engine can open a URL from this machine")
    p.add_argument("url")
    p = sub.add_parser("preview", help="show exactly what a configured watch monitors")
    p.add_argument("watch")
    p.add_argument("--limit", type=int, default=60)
    sub.add_parser("validate", help="check the config file")
    p = sub.add_parser("health", help="ask the running monitor how it is doing (exit code 0 ok, 1 degraded, 2 down)")
    p.add_argument("--json", action="store_true", help="print the raw JSON report")
    sub.add_parser("test-telegram", help="send a test message to every chat id")
    sub.add_parser("chat-id", help="find your Telegram chat id (message your bot first)")
    p = sub.add_parser("history", help="list recent detected changes / alerts")
    p.add_argument("--watch")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--show", type=int, metavar="ID", help="print the full report of one event")
    p = sub.add_parser("reset", help="forget the stored state of a watch (fresh baseline)")
    p.add_argument("watch")
    p = sub.add_parser("package", help="create monitor-deploy.zip for uploading to a server")
    p.add_argument("-o", "--output", help="zip file path (default: next to the project folder)")
    return parser


COMMANDS = {
    "run": cmd_run, "once": cmd_once, "inspect": cmd_inspect, "diagnose": cmd_diagnose, "preview": cmd_preview,
    "validate": cmd_validate, "health": cmd_health,
    "test-telegram": cmd_test_telegram, "chat-id": cmd_chat_id, "history": cmd_history, "reset": cmd_reset,
    "package": cmd_package,
}


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    args = build_parser().parse_args(argv)
    command = args.command or "run"
    try:
        try:
            config = load_config(args.config)
        except ConfigError:
            if command != "inspect":
                raise
            # inspect works without a config file
            config = parse_config({"watches": [{"id": "inspect", "url": args.url}]}, Path(args.config).resolve())
        setup_logging(config.data_dir, args.verbose, to_file=command == "run")
        for warning in config.warnings:
            log.warning("config: %s", warning)
        return asyncio.run(COMMANDS[command](config, args)) or 0
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
