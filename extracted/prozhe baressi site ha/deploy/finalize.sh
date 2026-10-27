#!/usr/bin/env bash
# Sprint 4.5 - final packaging + summary.
set -euo pipefail

APP_DIR="/opt/monitor"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="/root/monitor-final-$STAMP.tar.gz"

echo "==> Packing the current running code + tests + deploy"
tar -czf "$OUT" \
  -C "$APP_DIR" \
  --exclude='data' --exclude='venv' --exclude='.cache' --exclude='__pycache__' \
  webmonitor monitor_system.py requirements.txt monitor-config.json README.md tests deploy

echo "==> Backup: $OUT"
echo "==> Size: $(du -h "$OUT" | cut -f1)"

echo ""
echo "==> Version report"
sudo -u monitorsvc bash -c "cd $APP_DIR && ./venv/bin/python -c \"
import webmonitor
print('webmonitor version:', webmonitor.__version__)
\""

echo ""
echo "==> Test count"
sudo -u monitorsvc bash -c "cd $APP_DIR && ./venv/bin/python -m unittest tests.test_week3 2>&1 | grep -E '^Ran|^OK|^FAILED'" || true

echo ""
echo "==> Recent features (all sprint patches applied):"
echo "  ✅ Sprint 1.1  Rich change reports (size + sections)"
echo "  ✅ Sprint 1.2  Config crawl.include warning"
echo "  ✅ Sprint 1.3  Precise page identity in reports"
echo "  ✅ Sprint 1.4  Persistent impersonate cookies"
echo "  ✅ Sprint 1.5  Real DOM headings in grouping"
echo "  ✅ Sprint 2.1  Screenshot infrastructure"
echo "  ✅ Sprint 2.2  Screenshot UI in the panel"
echo "  ✅ Sprint 2.3  Screenshot polish + daily shots"
echo "  ✅ Sprint 3.1  Important-removed-link warning"
echo "  ✅ Sprint 3.2  Challenge server (SSH tunnel)"
echo "  ✅ Sprint 3.3  Playwright wired to challenges"
echo "  ✅ Sprint 3.4.1 Rate-limit detection (Error 1015)"
echo "  ✅ Sprint 3.4.2 Adaptive timeout"
echo "  ✅ Sprint 3.4.4 Exit-IP + rate-limit countdown"
echo "  ✅ Sprint 3.4.5 Week-3 unit tests"
echo "  ✅ Sprint 4.1  DOM anchors in reports"
echo "  ✅ Sprint 4.2  Per-watch report style (inline / before_after)"
echo "  ✅ Sprint 4.3  Full-diff document from history"
echo "  ✅ Sprint 4.4  Startup self-check + deploy improvements"
echo ""

echo "==> Sending summary to admins via the bot is not automatic."
echo "    To inspect the log:  sudo journalctl -u monitor-service -n 50"
