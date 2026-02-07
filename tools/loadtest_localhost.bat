@echo off
setlocal EnableDelayedExpansion

REM Localhost-only load test for BareMetalWeb
REM Ensure the app is running on http://localhost:5045 before starting.

set "URL=http://localhost:5045/"
set "TOTAL=500"
set "CONCURRENCY=20"
set "SLEEP_MS=50"

set /a launched=0
for /l %%i in (1,1,%TOTAL%) do (
    start "" /b cmd /c "curl -s -o NUL %URL%"
    set /a launched+=1
    if !launched! GEQ %CONCURRENCY% (
        REM small pause to avoid overwhelming the machine
        powershell -NoProfile -Command "Start-Sleep -Milliseconds %SLEEP_MS%" >nul 2>&1
        set /a launched=0
    )
)

echo Done. Launched %TOTAL% requests to %URL%.
endlocal
