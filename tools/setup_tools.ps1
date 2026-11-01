# External pentest tool setup for websec-agent (Windows).
#
# Downloads the Windows builds listed in config/tools.yaml into tools\bin,
# unpacks sqlmap / nikto / commix into tools\, and installs arjun into the venv.
# Safe to re-run: existing tools are skipped.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\setup_tools.ps1
#   powershell -ExecutionPolicy Bypass -File tools\setup_tools.ps1 -Proxy http://127.0.0.1:7890
param(
    [string]$Proxy = $env:HTTP_PROXY
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-Location (Split-Path -Parent $PSScriptRoot)

$Bin = Join-Path (Get-Location) "tools\bin"
$Tmp = Join-Path $env:TEMP ("websec-tools-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Bin, $Tmp | Out-Null

function Get-File([string]$Url, [string]$Out) {
    $curlArgs = @("-fsSL", "--retry", "3", "-o", $Out, $Url)
    if ($Proxy) { $curlArgs = @("-fsSL", "--retry", "3", "--proxy", $Proxy, "-o", $Out, $Url) }
    & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "download failed: $Url" }
}

function Install-Zip([string]$Url, [string]$Name) {
    $target = Join-Path $Bin "$Name.exe"
    if (Test-Path $target) { Write-Host "  = $Name already installed"; return }
    Write-Host "  + $Name"
    $zip = Join-Path $Tmp "$Name.zip"
    Get-File $Url $zip
    $dir = Join-Path $Tmp $Name
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    $exe = Get-ChildItem -Path $dir -Filter "$Name.exe" -Recurse | Select-Object -First 1
    if (-not $exe) { throw "no $Name.exe inside $Url" }
    Copy-Item $exe.FullName $target -Force
}

function Install-Tar([string]$Url, [string]$Name) {
    $target = Join-Path $Bin "$Name.exe"
    if (Test-Path $target) { Write-Host "  = $Name already installed"; return }
    Write-Host "  + $Name"
    $tgz = Join-Path $Tmp "$Name.tar.gz"
    Get-File $Url $tgz
    & tar.exe -xzf $tgz -C $Tmp $Name.exe
    if ($LASTEXITCODE -ne 0) { throw "extract failed: $Url" }
    Copy-Item (Join-Path $Tmp "$Name.exe") $target -Force
}

function Install-Source([string]$Url, [string]$Name) {
    $dest = Join-Path (Get-Location) "tools\$Name"
    if (Test-Path $dest) { Write-Host "  = $Name already present"; return }
    Write-Host "  + $Name"
    $zip = Join-Path $Tmp "$Name-src.zip"
    Get-File $Url $zip
    $dir = Join-Path $Tmp "$Name-src"
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    $inner = Get-ChildItem -Path $dir -Directory | Select-Object -First 1
    Move-Item $inner.FullName $dest
}

Write-Host "[1/4] ProjectDiscovery / web fuzzers -> tools\bin"
Install-Zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip" "nuclei"
Install-Zip "https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_windows_amd64.zip" "katana"
Install-Zip "https://github.com/projectdiscovery/httpx/releases/download/v1.7.1/httpx_1.7.1_windows_amd64.zip" "httpx"
Install-Zip "https://github.com/projectdiscovery/interactsh/releases/download/v1.4.1/interactsh-client_1.4.1_windows_amd64.zip" "interactsh-client"
Install-Zip "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip" "ffuf"
Install-Tar "https://github.com/hahwul/dalfox/releases/download/v2.11.0/dalfox_2.11.0_windows_amd64.tar.gz" "dalfox"
Install-Zip "https://github.com/lc/gau/releases/download/v2.2.1/gau_2.2.1_windows_amd64.zip" "gau"

Write-Host "[2/4] Python-based tools (sqlmap / nikto / commix)"
Install-Source "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" "sqlmap"
Install-Source "https://github.com/sullo/nikto/archive/refs/heads/master.zip" "nikto"
Install-Source "https://github.com/commixproject/commix/archive/refs/heads/master.zip" "commix"

Write-Host "[3/4] arjun (venv)"
$Py = Join-Path (Get-Location) ".venv\Scripts\python.exe"
if (Test-Path $Py) {
    & $Py -c "import arjun" 2>$null
    if ($LASTEXITCODE -ne 0) { & $Py -m pip install -q "arjun>=2.2" }
} else {
    Write-Host "  ! .venv not found; install arjun manually (pip install arjun)"
}

Write-Host "[4/4] version check"
foreach ($t in @("ffuf", "nuclei", "katana", "httpx", "dalfox", "gau", "interactsh-client")) {
    $exe = Join-Path $Bin "$t.exe"
    if (Test-Path $exe) {
        Write-Host -NoNewline ("  {0,-18} " -f $t)
        & $exe -version 2>&1 | Select-Object -First 1
    } else {
        Write-Host ("  {0,-18} MISSING" -f $t)
    }
}
Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
Write-Host "Done. nikto needs Perl: install Strawberry Perl from https://strawberryperl.com/"
