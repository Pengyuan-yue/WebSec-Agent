#!/usr/bin/env bash
# External pentest tool setup for websec-agent.
#
# Installs the binaries listed in config/tools.yaml into tools/bin, clones the
# Python-based tools (sqlmap / nikto / commix) into tools/, and installs arjun
# into the project venv. Safe to re-run: existing tools are skipped.
#
# Usage: bash tools/setup_tools.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Optional proxy (remove these two lines if your network is direct).
export HTTP_PROXY="${HTTP_PROXY:-}"
export HTTPS_PROXY="${HTTPS_PROXY:-}"

BIN="tools/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$BIN"

GO_VER="1.22.5"

fetch_zip() {  # url dest_binary
  local url="$1" name="$2"
  if [[ -x "$BIN/$name" ]]; then echo "  = $name already installed"; return; fi
  echo "  + downloading $name"
  curl -sfL --retry 3 -o "$TMP/$name.zip" "$url"
  unzip -qo "$TMP/$name.zip" -d "$TMP/$name"
  local found
  found="$(find "$TMP/$name" -maxdepth 2 -type f -name "$name" | head -1)"
  install -m 0755 "$found" "$BIN/$name"
}

fetch_tar() {  # url dest_binary
  local url="$1" name="$2"
  if [[ -x "$BIN/$name" ]]; then echo "  = $name already installed"; return; fi
  echo "  + downloading $name"
  curl -sfL --retry 3 -o "$TMP/$name.tgz" "$url"
  tar -xzf "$TMP/$name.tgz" -C "$TMP" "$name"
  install -m 0755 "$TMP/$name" "$BIN/$name"
}

echo "[1/4] ProjectDiscovery / web fuzzers -> $BIN"
fetch_zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip" nuclei
fetch_zip "https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip" katana
fetch_zip "https://github.com/projectdiscovery/httpx/releases/download/v1.7.1/httpx_1.7.1_linux_amd64.zip" httpx
fetch_zip "https://github.com/projectdiscovery/interactsh/releases/download/v1.4.1/interactsh-client_1.4.1_linux_amd64.zip" interactsh-client
fetch_tar "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" ffuf
fetch_tar "https://github.com/hahwul/dalfox/releases/download/v2.11.0/dalfox_2.11.0_linux_amd64.tar.gz" dalfox
fetch_tar "https://github.com/lc/gau/releases/download/v2.2.1/gau_2.2.1_linux_amd64.tar.gz" gau

echo "[2/4] Python-based tools (sqlmap / nikto / commix)"
for repo in sqlmap nikto commix; do
  case "$repo" in
    sqlmap) url="https://github.com/sqlmapproject/sqlmap.git" ;;
    nikto)  url="https://github.com/sullo/nikto.git" ;;
    commix) url="https://github.com/commixproject/commix.git" ;;
  esac
  if [[ -e "tools/$repo" ]]; then echo "  = $repo already present"; else
    echo "  + cloning $repo"
    git clone --depth 1 "$url" "tools/$repo"
  fi
done

echo "[3/4] arjun (venv)"
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -c "import arjun" 2>/dev/null || .venv/bin/python -m pip install -q "arjun>=2.2"
else
  echo "  ! .venv not found; install arjun manually (pip install arjun)"
fi

echo "[4/4] version check"
for t in ffuf nuclei katana httpx dalfox gau interactsh-client; do
  printf "  %-18s " "$t"
  "$BIN/$t" -version 2>&1 | head -1 || true
done
echo "Done. Wordlists are bundled in tools/wordlists/."
