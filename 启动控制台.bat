@echo off
setlocal
cd /d "%~dp0"

set "URL=http://127.0.0.1:8080/"
set "PORT=8080"

rem [1] already running -> open browser
powershell -NoProfile -Command "try{$r=Invoke-WebRequest '%URL%' -UseBasicParsing -TimeoutSec 2;exit 0}catch{exit 1}"
if not errorlevel 1 goto OPEN

rem [2] proxy: keep existing env, else probe local 7897
if defined HTTP_PROXY goto CHECK
powershell -NoProfile -Command "if(Test-NetConnection -ComputerName 127.0.0.1 -Port 7897 -InformationLevel Quiet -WarningAction SilentlyContinue){exit 0}else{exit 1}"
if not errorlevel 1 set "HTTP_PROXY=http://127.0.0.1:7897" & set "HTTPS_PROXY=http://127.0.0.1:7897"

:CHECK
if exist "tools\pw-browsers" set "PLAYWRIGHT_BROWSERS_PATH=%CD%\tools\pw-browsers"
if not exist ".venv\Scripts\websec-agent-web.exe" goto NOPY

rem [3] start server
start "websec-agent" /min ".venv\Scripts\websec-agent-web.exe" --host 127.0.0.1 --port %PORT%

rem [4] wait until ready then open browser
powershell -NoProfile -Command "for($i=0;$i -lt 60;$i++){try{Invoke-WebRequest '%URL%' -UseBasicParsing -TimeoutSec 2|Out-Null;break}catch{Start-Sleep -Milliseconds 500}};Start-Process '%URL%'"
echo Console started: %URL%
echo Stop: Get-Process websec-agent-web ^| Stop-Process
goto END

:OPEN
echo Console already running, opening browser...
start "" "%URL%"
goto END

:NOPY
echo [ERROR] .venv\Scripts\websec-agent-web.exe not found
echo Run: python -m venv .venv
echo      .venv\Scripts\pip.exe install -e ".[web,browser,tools,dev]"
pause

:END
endlocal
