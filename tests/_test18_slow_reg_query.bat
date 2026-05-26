@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

set VLAUNCHER_DEBUG=true

cd ..\build

echo ____start reg query speed test

:: Capture Start Time and replace any leading spaces with a zero
set "STARTTIME=%TIME: =0%"

:: Execute the command
VirtLauncher64.exe -r -e reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes" 2>nul | findstr "EnumA"

:: Capture End Time and replace any leading spaces with a zero
set "ENDTIME=%TIME: =0%"

:: Format Start Time to Centiseconds
for /F "tokens=1-4 delims=:.," %%a in ("%STARTTIME%") do (
    set /a "start_h=100%%a %% 100", "start_m=100%%b %% 100", "start_s=100%%c %% 100", "start_ms=100%%d %% 100"
)
set /a "start_total=(start_h * 360000) + (start_m * 6000) + (start_s * 100) + start_ms"

:: Format End Time to Centiseconds
for /F "tokens=1-4 delims=:.," %%a in ("%ENDTIME%") do (
    set /a "end_h=100%%a %% 100", "end_m=100%%b %% 100", "end_s=100%%c %% 100", "end_ms=100%%d %% 100"
)
set /a "end_total=(end_h * 360000) + (end_m * 6000) + (end_s * 100) + end_ms"

:: Calculate Elapsed Time
set /a "elapsed=end_total - start_total"

:: Handle midnight crossover
if %elapsed% lss 0 set /a "elapsed+=8640000"

:: Break down into hours, minutes, seconds, milliseconds
set /a "ms=elapsed %% 100", "rest=elapsed / 100"
set /a "s=rest %% 60", "rest=rest / 60"
set /a "m=rest %% 60", "h=rest / 60"

:: Add leading zeros for clean display
if %h% lss 10 set "h=0%h%"
if %m% lss 10 set "m=0%m%"
if %s% lss 10 set "s=0%s%"
if %ms% lss 10 set "ms=0%ms%"

echo ____end
echo --------------------------------------------------
echo Execution Started:  %STARTTIME%
echo Execution Finished: %ENDTIME%
echo Total Time Spent:   %h%:%m%:%s%.%ms%
echo --------------------------------------------------

echo.
echo.
:: Threshold Check (2 seconds = 200 centiseconds)
if %elapsed% lss 200 (
    color 2F
    echo good: time spent is less than 2s
) else (
    color 4F
    echo bad: time spent is greater than 2s
)
echo.
echo.
pause