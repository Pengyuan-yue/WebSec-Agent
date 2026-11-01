#!/usr/bin/env bash
# One-shot browser setup for the websec-agent sandbox.
# Sandbox resets wipe /usr and /root/.cache (apt libs + default playwright
# browsers) while /workspace persists. This script:
#   1. installs chromium system libraries (apt, ephemeral)
#   2. fetches Chrome-for-Testing zips from npmmirror (~15MB/s via proxy; the
#      playwright CDN crawls at ~25KB/s here) into tools/pw-browsers
#      (persistent), laying them out exactly as playwright 1.64 expects
#   3. verifies the probe can render a page
# Run: bash tools/setup_browser.sh
set -euo pipefail
cd "$(dirname "$0")/.."

export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:18080}"
export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:18080}"
export PLAYWRIGHT_BROWSERS_PATH="$PWD/tools/pw-browsers"

CFT_VERSION="156.0.8078.4"   # matches playwright 1.64 chromium revision 1248
MIRROR="https://cdn.npmmirror.com/binaries/chrome-for-testing/$CFT_VERSION/linux64"

echo "[1/4] apt system libraries for chromium..."
apt-get update -qq
apt-get install -y -qq libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 \
  libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
  libcairo2 libasound2t64 libnss3 libnspr4 libatspi2.0-0 >/dev/null

echo "[2/4] fetching Chrome-for-Testing $CFT_VERSION from npmmirror..."
mkdir -p "tools/pw-browsers/chromium-1248" "tools/pw-browsers/chromium-headless-shell-1248" /tmp/cft
curl -sf --retry 3 -o /tmp/cft/chrome.zip "$MIRROR/chrome-linux64.zip"
curl -sf --retry 3 -o /tmp/cft/shell.zip "$MIRROR/chrome-headless-shell-linux64.zip"

echo "[3/4] extracting into $PLAYWRIGHT_BROWSERS_PATH..."
unzip -qo /tmp/cft/chrome.zip -d "tools/pw-browsers/chromium-1248/"
unzip -qo /tmp/cft/shell.zip -d "tools/pw-browsers/chromium-headless-shell-1248/"
touch "tools/pw-browsers/chromium-1248/INSTALLATION_COMPLETE" \
      "tools/pw-browsers/chromium-headless-shell-1248/INSTALLATION_COMPLETE"
rm -rf /tmp/cft

echo "[4/4] probe check..."
.venv/bin/python tools/browser_probe.py '{"action":"get","url":"http://example.com/","allowed_hosts":["example.com"]}' \
  | .venv/bin/python -c 'import json,sys; p=json.load(sys.stdin); print("browser ok" if not p.get("error") and p.get("screenshot_b64") else f"probe error: {p.get(\"error\")}")'
