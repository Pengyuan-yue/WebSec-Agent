# Playwright browser setup for websec-agent (Windows).
#
# Installs Chromium + chrome-headless-shell into tools\pw-browsers so the
# browser probe works without touching %LOCALAPPDATA%.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\setup_browser.ps1
#   powershell -ExecutionPolicy Bypass -File tools\setup_browser.ps1 -Mirror   # 国内镜像
param(
    [switch]$Mirror
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-Location (Split-Path -Parent $PSScriptRoot)

$Py = Join-Path (Get-Location) ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    Write-Error "venv not found. Run: python -m venv .venv && .venv\Scripts\pip install -e `".[web,browser,tools,dev]`""
}

$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path (Get-Location) "tools\pw-browsers"
New-Item -ItemType Directory -Force -Path $env:PLAYWRIGHT_BROWSERS_PATH | Out-Null

if ($Mirror) {
    $env:PLAYWRIGHT_DOWNLOAD_HOST = "https://npmmirror.com/mirrors/playwright"
    Write-Host "Using mirror: $env:PLAYWRIGHT_DOWNLOAD_HOST"
}

Write-Host "[1/2] installing chromium + headless shell..."
& $Py -m playwright install chromium chromium-headless-shell
if ($LASTEXITCODE -ne 0) { throw "playwright install failed" }

Write-Host "[2/2] probe check..."
$spec = '{"action":"get","url":"https://example.com/","allowed_hosts":["example.com"],"wait_ms":1500}'
$out = & $Py tools\browser_probe.py $spec
$parsed = $out | ConvertFrom-Json
if ($parsed.error) { throw "browser probe error: $($parsed.error)" }
Write-Host "browser ok: title=$($parsed.title) status=$($parsed.status)"
