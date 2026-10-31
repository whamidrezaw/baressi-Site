#!/usr/bin/env bash
# نصب / به‌روزرسانی مانیتور به‌عنوان سرویس systemd روی Debian/Ubuntu
#
#   sudo bash deploy/install_service.sh
#
# اجرای دوباره امن است: کد به‌روز می‌شود ولی تنظیمات و داده‌های سرور حفظ می‌شوند.
# برای جایگزین کردن تنظیمات سرور با فایل همین پوشه:  sudo FORCE_CONFIG=1 bash deploy/install_service.sh
set -euo pipefail

APP_DIR="/opt/monitor"
SERVICE_USER="monitorsvc"
SERVICE_NAME="monitor-service"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$APP_DIR/venv/bin/python"

if [[ $EUID -ne 0 ]]; then
  echo "لطفاً با دسترسی root اجرا کنید:  sudo bash $0" >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "این اسکریپت برای Debian/Ubuntu (apt) نوشته شده است." >&2
  exit 1
fi

echo "==> [1/9] نصب پیش‌نیازهای سیستم (python3، venv)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ca-certificates >/dev/null

echo "==> [2/9] حافظهٔ swap (برای سرورهای کم‌حافظه)"
ensure_swap() {
  local ram_mb
  ram_mb=$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)
  if (( ram_mb >= 2000 )) || [[ -n "$(swapon --noheadings 2>/dev/null)" ]]; then
    echo "    لازم نیست (RAM: ${ram_mb}MB)"
    return 0
  fi
  echo "    RAM فقط ${ram_mb}MB است؛ ساخت ۲ گیگابایت swap برای پایداری مرورگر…"
  { fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none; } &&
    chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile &&
    { grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab; }
}
ensure_swap || echo "    ساخت swap ناموفق بود؛ ادامه می‌دهیم."

echo "==> [3/9] کاربر سیستمی ایزوله ($SERVICE_USER، بدون امکان ورود)"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

echo "==> [4/9] کپی برنامه به $APP_DIR"
mkdir -p "$APP_DIR"
rm -rf "$APP_DIR/webmonitor"
cp -r "$SRC_DIR/webmonitor" "$SRC_DIR/monitor_system.py" "$SRC_DIR/requirements.txt" "$SRC_DIR/README.md" "$APP_DIR/"
# Sprint 4.4: ship the tests as well, so a server-side sanity check is possible.
if [[ -d "$SRC_DIR/tests" ]]; then
  rm -rf "$APP_DIR/tests"
  cp -r "$SRC_DIR/tests" "$APP_DIR/"
fi
if [[ ! -f "$APP_DIR/monitor-config.json" || "${FORCE_CONFIG:-0}" == "1" ]]; then
  cp "$SRC_DIR/monitor-config.json" "$APP_DIR/"
else
  echo "    فایل monitor-config.json سرور حفظ شد (برای جایگزینی: FORCE_CONFIG=1)"
fi
cd "$APP_DIR"

echo "==> [5/9] محیط مجازی پایتون و کتابخانه‌ها"
[[ -x "$PY" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
# requirements.txt pins the tested versions; only curl_cffi is moved forward afterwards, because bot walls
# reject outdated browser fingerprints
if ! "$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"; then
  echo "    !! نصب یکی از کتابخانه‌ها ناموفق بود؛ بقیه نصب می‌شوند (شبیه‌ساز کروم یا پروکسی SOCKS ممکن است در دسترس نباشد)."
  grep -v -e '^curl_cffi' -e '^aiohttp-socks' "$APP_DIR/requirements.txt" | "$APP_DIR/venv/bin/pip" install -q -r /dev/stdin
  for optional in curl_cffi aiohttp-socks; do
    "$APP_DIR/venv/bin/pip" install -q "$optional" || echo "    !! $optional نصب نشد."
  done
fi
"$APP_DIR/venv/bin/pip" install -q -U curl_cffi || true

echo "==> [6/9] کتابخانه‌های سیستمی لازم برای مرورگر"
"$APP_DIR/venv/bin/patchright" install-deps chromium \
  || echo "    !! کامل نصب نشد؛ موتور سریع HTTP کار می‌کند ولی مرورگر ممکن است اجرا نشود."

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 750 "$APP_DIR"
chmod 640 "$APP_DIR/monitor-config.json"   # contains the bot token

echo "==> [7/9] نصب مرورگر برای کاربر سرویس"
# Installed into $APP_DIR/.cache (the service user's home), where the service can find it.
runuser -u "$SERVICE_USER" -- env HOME="$APP_DIR" "$APP_DIR/venv/bin/patchright" install chromium \
  || echo "    !! دانلود Chromium ناموفق بود؛ بعداً همین اسکریپت را دوباره اجرا کنید."
if [[ "$(dpkg --print-architecture)" == "amd64" ]]; then
  # Real Google Chrome is the least detectable option; Chromium is used if this fails.
  "$APP_DIR/venv/bin/patchright" install chrome || echo "    Google Chrome نصب نشد؛ از Chromium استفاده می‌شود."
fi

echo "==> [8/9] دستور کمکی monitor و بررسی تنظیمات"
cat > /usr/local/bin/monitor <<EOF
#!/bin/sh
# Website monitor commands, run as the service user. Examples:
#   monitor inspect https://example.com     monitor preview <id>     monitor history
[ "\$(id -u)" -eq 0 ] || exec sudo "\$0" "\$@"
case "\${1:-}" in
  ""|run)
    echo "The monitor runs as a background service:"
    echo "  sudo systemctl status $SERVICE_NAME     sudo systemctl restart $SERVICE_NAME"
    echo "  sudo journalctl -u $SERVICE_NAME -f      (live log)"
    echo "Commands: monitor inspect URL | preview ID | once --dry-run | validate | test-telegram | chat-id | history | reset ID"
    exit 0 ;;
esac
cd "$APP_DIR" || exit 1
exec runuser -u "$SERVICE_USER" -- env HOME="$APP_DIR" "$PY" "$APP_DIR/monitor_system.py" "\$@"
EOF
chmod 755 /usr/local/bin/monitor

if ! /usr/local/bin/monitor validate; then
  echo "!! فایل تنظیمات خطا دارد. اصلاح کنید و دوباره اجرا کنید:  sudo nano $APP_DIR/monitor-config.json" >&2
  exit 1
fi
if grep -q "YOUR_TELEGRAM_BOT_TOKEN" "$APP_DIR/monitor-config.json" && ! grep -qs "TELEGRAM_BOT_TOKEN=" "$APP_DIR/.env"; then
  echo "!! توکن ربات تلگرام هنوز تنظیم نشده است؛ پیام‌ها فقط در لاگ نوشته می‌شوند."
  echo "   ویرایش: sudo nano $APP_DIR/monitor-config.json   سپس: sudo systemctl restart $SERVICE_NAME"
fi

echo "==> [9/9] نصب و اجرای سرویس systemd"
install -m 644 "$SRC_DIR/deploy/monitor-service.service" "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"
sleep 5
systemctl --no-pager --lines=20 status "$SERVICE_NAME" || true

# Sprint 4.4: quick sanity check on the installed tree.
if [[ -d "$APP_DIR/tests" && -f "$APP_DIR/tests/test_webmonitor.py" ]]; then
  echo "    🧪 tests/ installed; you can run them with:"
  echo "       sudo runuser -u '$SERVICE_USER' -- env HOME='$APP_DIR' '$PY' -m unittest discover -s tests -v"
fi
if (exec 3<>/dev/tcp/127.0.0.1/40000) 2>/dev/null; then
  echo "    🛡 پروکسی Cloudflare WARP روی 127.0.0.1:40000 فعال است؛ سایت‌هایی که IP سرور را مسدود کنند خودکار از آن بررسی می‌شوند."
else
  echo "    ℹ️ پروکسی WARP پیدا نشد (اختیاری؛ برای سایت‌هایی مثل گوته که IP سرور را مسدود می‌کنند — راهنما در README)."
fi

cat <<EOF

✅ نصب کامل شد.
   🛠 مدیریت سایت‌ها:  ربات را در تلگرام (چت خصوصی) باز کنید و /start بفرستید
   وضعیت سرویس:      sudo systemctl status $SERVICE_NAME
   لاگ زنده:          sudo journalctl -u $SERVICE_NAME -f
   ویرایش تنظیمات:    sudo nano $APP_DIR/monitor-config.json
   اعمال تنظیمات:     monitor validate && sudo systemctl restart $SERVICE_NAME
   دستورات برنامه:    monitor inspect URL | monitor preview ID | monitor history | monitor test-telegram
EOF
