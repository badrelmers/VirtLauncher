@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
CD /D "%~dp0"
chcp 65001
REM ============================================================
REM  VirtLauncher Full Registry Virtualisation Test Suite
REM  Tests: tombstone, special hives, merged view, enumeration,
REM         re-create, cross-hive HKCR consistency, edge cases
REM  MUST RUN AS ADMINISTRATOR
REM ============================================================
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

rem mode con | findstr "32766" >nul || mode con lines=32766 COLS=160
mode con | findstr "11111" >nul || mode con lines=11111 COLS=120

cd /d "..\build"

set LAUNCHER=VirtLauncher64.exe
set "VIRT_ROOT=HKEY_CURRENT_USER\VirtTestFull_Root222"

set /a PASS_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0

REM ── get current user SID ─────────────────────────────────────
for /f "tokens=2 delims==" %%A in ('wmic useraccount where "name=''%username%''" get sid /value 2^>nul') do set "USER_SID=%%A"
if "%USER_SID%"=="" for /f "tokens=2" %%A in ('whoami /user /fo table /nh') do set "USER_SID=%%A"
set "USER_SID=%USER_SID: =%"


REM HKCR writes go to two virtual destinations:
REM   VirtRoot\HKEY_LOCAL_MACHINE\SOFTWARE\Classes  (HKLM backing path)
REM   VirtRoot\HKEY_USERS\SID_Classes               (per-user backing path)
REM The test verifies both.
set "STORE_ID=HKCR_ROOT"
set "REAL_KEY=HKEY_CLASSES_ROOT"


echo.
echo   [8] Enumeration with Tombstones
call :CLEANUP

REM Set up: two virtual values + one real-only value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v EnumA /t REG_SZ /d DataA /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v EnumB /t REG_SZ /d DataB /f >nul
reg add "%REAL_KEY%" /v RealEnum /t REG_SZ /d RealData /f >nul

set VLAUNCHER_DEBUG=true
echo        real-only value RealEnum still visible
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "RealEnum" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only RealEnum not visible after sibling delete")

REM Delete middle value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v EnumB /f >nul 2>nul

echo        real-only value RealEnum still visible after deleting a virtual key
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "RealEnum" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only RealEnum not visible after sibling delete")
set VLAUNCHER_DEBUG=false
pause

call :CLEANUP
pause

REM ════════════════════════════════════════════════════════════
REM  Helpers
REM ════════════════════════════════════════════════════════════
:Pass
echo         good
set /a PASS_COUNT+=1
goto :eof

:Fail
echo         BAD  -- %~1
set /a FAIL_COUNT+=1
rem pause
goto :eof

:Skip
echo         skip -- %~1
set /a SKIP_COUNT+=1
goto :eof

:CLEANUP
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "%REAL_KEY%"  /v WriteVal /f >nul 2>&1
reg delete "%REAL_KEY%\virtleakkk" /f >nul 2>&1
exit /b

:GLOBAL_CLEANUP
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v TestVal    /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v DwordVal   /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v RealVal    /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v TombVal    /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v PersistVal /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v Cycle      /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software" /v OW         /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software\ManyVals" /f >nul 2>&1
exit /b

