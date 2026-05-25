@echo off
title PDF-Forensik Backend - Claude Bridge + SSH Tunnel zum VPS
color 0B
setlocal

set "VPS=ubuntu@51.195.86.119"
set "BRIDGE_PY=C:\Users\emir\Projects\pdf-forensik\bridge\claude_bridge.py"
set "BRIDGE_LOG=C:\Users\emir\Projects\pdf-forensik\bridge\bridge.log"
set "PYTHON=python"

REM Subprocess-Timeout fuer claude CLI (Opus mit grossem Schema braucht 60-180s)
set "CLI_TIMEOUT=480"

REM Shared-Secret Token aus Datei lesen (nicht git-tracked).
REM Wenn die Datei fehlt -> kein Token -> nur Loopback-Schutz.
set "TOKEN_FILE=C:\Users\emir\Projects\pdf-forensik\bridge\.bridge_token"
set "CLAUDE_BRIDGE_TOKEN="
if exist "%TOKEN_FILE%" (
    for /f "usebackq delims=" %%T in ("%TOKEN_FILE%") do set "CLAUDE_BRIDGE_TOKEN=%%T"
)

echo ================================================
echo  PDF-FORENSIK CLAUDE BACKEND
echo  1) Claude Bridge auf 127.0.0.1:11600 (FastAPI)
echo  2) SSH-Reverse-Tunnel  PC:11600 -^> VPS:11600
echo  Auth bleibt am PC (Pro/Max Subscription)
echo ================================================
echo.

:start
echo [%TIME:~0,8%] Pruefe claude CLI ...
where claude >nul 2>&1
if errorlevel 1 (
    echo [%TIME:~0,8%] FEHLER: claude CLI nicht im PATH gefunden
    echo                Installation: https://docs.claude.com/claude-code
    timeout /t 30 /nobreak >nul
    goto start
)

echo [%TIME:~0,8%] Pruefe Bridge auf 127.0.0.1:11600 ...
curl -s --max-time 2 http://127.0.0.1:11600/healthz >nul 2>&1
if errorlevel 1 (
    echo [%TIME:~0,8%] Bridge down - starte im Hintergrund...
    REM Background-Start mit Logfile
    start "Claude Bridge" /MIN cmd /c ""%PYTHON%" "%BRIDGE_PY%" > "%BRIDGE_LOG%" 2>&1"
    echo [%TIME:~0,8%] Warte auf Bridge-Bereitschaft...
    :wait_bridge
    timeout /t 2 /nobreak >nul
    curl -s --max-time 2 http://127.0.0.1:11600/healthz >nul 2>&1
    if errorlevel 1 goto wait_bridge
    echo [%TIME:~0,8%] Bridge ist bereit
) else (
    echo [%TIME:~0,8%] Bridge laeuft bereits
)

REM Claude-Auth verifizieren - kurzer Ping (mit Token wenn gesetzt)
echo [%TIME:~0,8%] Auth-Check ...
if defined CLAUDE_BRIDGE_TOKEN (
    curl -s --max-time 60 -X POST http://127.0.0.1:11600/review ^
        -H "Content-Type: application/json" ^
        -H "X-Bridge-Token: %CLAUDE_BRIDGE_TOKEN%" ^
        -d "{\"prompt\":\"sag nur OK\"}" >nul 2>&1
) else (
    curl -s --max-time 60 -X POST http://127.0.0.1:11600/review ^
        -H "Content-Type: application/json" ^
        -d "{\"prompt\":\"sag nur OK\"}" >nul 2>&1
)
if errorlevel 1 (
    echo [%TIME:~0,8%] WARNUNG: Auth-Check fehlgeschlagen
    echo                Pruefe mit: claude -p "OK"
) else (
    echo [%TIME:~0,8%] Auth-Check ok
)

echo.
echo [%TIME:~0,8%] Starte SSH-Reverse-Tunnel ...
echo                (Fenster offen lassen - Schliessen beendet Tunnel)
echo.
ssh -N -R 11600:127.0.0.1:11600 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes %VPS%

echo.
echo [%TIME:~0,8%] Tunnel getrennt. Versuche in 5 Sekunden neu... (Strg+C zum Beenden)
timeout /t 5 /nobreak >nul
goto start
