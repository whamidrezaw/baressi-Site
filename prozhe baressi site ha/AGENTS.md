# AGENTS.md — WebMonitor Project Guide

## Overview
**WebMonitor** (`webmonitor/`) is an enterprise-grade, asynchronous website change monitor (embassy pages, appointment portals, news, RSS/Atom, JSON endpoints, and subpage crawlers) with a Persian Telegram admin panel, 3-tier anti-bot fetching (`http` -> `impersonate` via `curl_cffi` -> `browser` via stealth Playwright + automatic Cloudflare Turnstile solver + 1-tap Telegram/SSH tunnel CAPTCHA solver), transactional SQLite outbox (`data/monitor.db`), and word-by-word diff reporting.

## Architecture & Module Map
- [`monitor_system.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/monitor_system.py): Entry point (`run`, `validate`, `preview`, `reset-baseline`, `package`).
- [`webmonitor/config.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/config.py): Configuration parser and validator (`monitor-config.json`), SSRF host validation (`is_public_host`), CSS/regex validation.
- [`webmonitor/fetchers.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/fetchers.py): 3-tier fetchers (`HttpFetcher`, `ImpersonateFetcher`, `BrowserFetcher`) with stealth scripts, automatic Cloudflare Turnstile clicker (`_try_solve_turnstile`), and persistent cookies (`data/sessions/`).
- [`webmonitor/extract.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/extract.py): HTML/RSS/JSON extraction, noise filtering, link discovery, and bot-wall detection (`detect_block`).
- [`webmonitor/report.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/report.py): Line-level (`diff_lines`) and word-level (`word_diff_html`) diffing, 3 report styles (`inline`, `before_after`, `side_by_side`), and standalone dark/light HTML document renderer (`render_document`).
- [`webmonitor/storage.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/storage.py): SQLite WAL database (`pages`, `seen_items`, `watch_state`, `events` outbox, `watches`, `admins`, `settings`).
- [`webmonitor/engine.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/engine.py): Scheduling loop, smart route memory, subpage BFS crawler, quiet hours, and interactive challenge orchestration.
- [`webmonitor/bot.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/bot.py): Telegram inline control panel (`/panel`, `/sites`, `/add`, `/health`, `/digest`, `/search`), 1-tap CAPTCHA solver (`+ck`, `+cd`, `+cc`), cookie importer, and global settings (`⚙️ تنظیمات کلی`).
- [`webmonitor/challenge.py`](file:///c:/Users/HAMIDREZA/Downloads/prozhe%20baressi%20site%20ha/webmonitor/challenge.py): Localhost HTTP/MJPEG challenge solver (`127.0.0.1:8899`) for SSH tunnel solving.

## Local Verification & Testing Commands
```powershell
# Validate configuration
.\.venv\Scripts\python.exe monitor_system.py validate

# Preview a site extraction
.\.venv\Scripts\python.exe monitor_system.py preview de_embassy_home

# Run fast unit test suite (skipping live Playwright browser launches)
$env:WEBMONITOR_SKIP_BROWSER="1"; .\.venv\Scripts\python.exe -m unittest discover -s tests -v

# Run full unit test suite (including live browser tests)
Remove-Item Env:WEBMONITOR_SKIP_BROWSER -ErrorAction SilentlyContinue; .\.venv\Scripts\python.exe -m unittest discover -s tests -v

# Build clean deployment zip
.\.venv\Scripts\python.exe monitor_system.py package -o monitor-deploy.zip
```

## Production Server Deployment (`oracle-server`)
- **SSH Host Alias**: `oracle-server` (`130.61.88.47`, user `ubuntu`, key `~/.ssh/oracle_private.key`)
- **Install Directory**: `/opt/monitor` (owned by `monitorsvc:monitorsvc`)
- **Systemd Service**: `monitor-service.service`
- **One-Command Deploy**:
  ```powershell
  .\.venv\Scripts\python.exe monitor_system.py package -o monitor-deploy.zip
  scp monitor-deploy.zip oracle-server:~/monitor-deploy.zip
  ssh oracle-server "sudo unzip -o ~/monitor-deploy.zip -d /opt/monitor -x monitor-config.json && sudo chown -R monitorsvc:monitorsvc /opt/monitor/webmonitor /opt/monitor/monitor_system.py /opt/monitor/deploy && sudo systemctl restart monitor-service && sudo systemctl status monitor-service --no-pager"
  ```
  *(Note: `-x monitor-config.json` preserves the production server's live `monitor-config.json` if already customized).*
