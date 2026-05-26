@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
CD /D "%~dp0"

fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

cd /d "..\build"

set LAUNCHER=VirtLauncher64.exe
set "VIRT_ROOT=HKEY_CURRENT_USER\VirtTestFull_Root222"



REM ── get current user SID ─────────────────────────────────────
for /f "tokens=2 delims==" %%A in ('wmic useraccount where "name=''%username%''" get sid /value 2^>nul') do set "USER_SID=%%A"
if "%USER_SID%"=="" for /f "tokens=2" %%A in ('whoami /user /fo table /nh') do set "USER_SID=%%A"
set "USER_SID=%USER_SID: =%"


REM HKEY_USERS\SID writes must go to VirtRoot\HKEY_CURRENT_USER
set "STORE_ID=HKU_SID"
set "REAL_KEY=HKEY_USERS\%USER_SID%"
set "VIRT_KEY=%VIRT_ROOT%\HKEY_CURRENT_USER"
 
 
echo.
call :CLEANUP
call :GLOBAL_CLEANUP

echo _____________1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%"

%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MV1 /t REG_SZ /d One   /f >nul

echo _____________2: bug
set VLAUNCHER_DEBUG=true
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%"   
set VLAUNCHER_DEBUG=false

echo _____________3
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MV1  
 

call :CLEANUP
call :GLOBAL_CLEANUP
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

