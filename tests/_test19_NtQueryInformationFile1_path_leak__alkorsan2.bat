@echo off
SETLOCAL
CD /D "%~dp0"

:: ============================================================
::  NtQueryInformationFile path-leak regression test  (v2)
::
::  The bug: Hook_NtQueryInformationFile classes 9 and 21 return
::  FileName as a volume-relative physical path (no drive letter).
::  Without the fix, the value is never translated, so callers
::  see the sandbox path instead of the logical path.
::
::  IMPORTANT - why the sandbox MUST be on the same drive as the
::  logical path for the bug to be observable:
::
::    FileName = volume-relative on the PHYSICAL volume, e.g.:
::      Physical handle on F:\sandbox\C\myapp  -> FileName = \sandbox\C\myapp
::      Physical handle on C:\sandbox\C\myapp  -> FileName = \sandbox\C\myapp
::
::    To call ReverseApplyFsRedirect we prepend the physical drive:
::      Cross-drive (sandbox F:, logical C:):  \??\F:\sandbox\C\myapp
::        -> ReverseApplyFsRedirect matches FsDirNtBase on F: -> \??\C:\myapp  FIXED
::        -> But without fix code: driveRoot was taken from logPath = \??\C:
::           so fullPhys = \??\C:\sandbox\C\myapp -> no match -> NOT fixed
::             (previous wrong version used logPath's drive - cross-drive still broken)
::
::    With the corrected fix (NtQueryObject on e.hVirt for physical drive):
::      Both same-drive and cross-drive cases work correctly.
::
::    To make the bug VISIBLE in a test, we need the sandbox on the SAME
::    drive as the logical path, because:
::      Same-drive (sandbox C:\sandbox, logical C:\myapp):
::        Physical FileName = \sandbox\C\myapp
::        Without fix: raw FileName returned -> caller sees C:\sandbox\C\myapp  BUG
::        With fix:    reversed to \myapp    -> caller sees C:\myapp            OK
::
::  Test setup:
::    Logical dir : C:\_vltest_logical\myapp\data   (or %SYSTEMDRIVE%)
::    Sandbox     : C:\_vltest_sandbox              (same drive!)
::    Shadow path : C:\_vltest_sandbox\C\_vltest_logical\myapp\data
::
::  If sandbox and logical are on different drives the bug is invisible,
::  which is why the previous test (sandbox on F:, logical on C:) passed
::  both with and without the fix.
:: ============================================================

cd "..\build"
set LAUNCHER=%CD%\VirtLauncher64.exe
if not exist "%LAUNCHER%" set LAUNCHER=%CD%\VirtLauncher32.exe
if not exist "%LAUNCHER%" (
    echo [ERROR] VirtLauncher not found in build folder.
    pause & exit /b 1
)

:: Use %SYSTEMDRIVE% so the sandbox is guaranteed on the same drive
:: as the logical path.
set "SD=%SYSTEMDRIVE%"
set "WS=%SD%\_vltest_ws"
set "LOGICAL_DIR=%WS%\logical\myapp\data"
set "SANDBOX=%WS%\sandbox"

:: Shadow = where LOGICAL_DIR lands inside the sandbox
:: VirtHook maps X:\foo -> sandbox\X\foo
set "_TAIL=%LOGICAL_DIR:~2%"
set "_DL=%SD:~0,1%"
set "SHADOW=%SANDBOX%\%_DL%%_TAIL%"

rmdir /s /q "%WS%" 2>nul
mkdir "%LOGICAL_DIR%" || ( echo [ERROR] could not create %LOGICAL_DIR% & pause & exit /b 1 )
mkdir "%SANDBOX%"

set /a PASS=0
set /a FAIL=0

echo.
echo ============================================================
echo  NtQueryInformationFile path-leak test
echo  (sandbox and logical on same drive: %SD%)
echo ============================================================
echo.
echo  Logical dir  : %LOGICAL_DIR%
echo  Sandbox root : %SANDBOX%
echo  Shadow path  : %SHADOW%
echo.

set "OUT=%WS%\out.txt"

:: Capture %CD% after cd'ing into the logical dir inside the sandbox.
:: Use cmd /V:ON with delayed expansion so !CD! is evaluated AFTER the cd,
:: not at parse time (%%CD%% would expand before the cd runs).
setlocal DisableDelayedExpansion
%LAUNCHER% -f "%SANDBOX%" cmd /V:ON /S /C "cd /D "%LOGICAL_DIR%" && echo CURRENT_DIR=!CD!" > "%OUT%" 2>nul
setlocal EnableDelayedExpansion

if not exist "%OUT%" (
    echo   [-] FAIL: no output file captured
    set /a FAIL+=1
    goto :summary
)

set "CAPTURED="
for /f "tokens=1,* delims==" %%A in ('findstr /i "CURRENT_DIR=" "%OUT%"') do set "CAPTURED=%%B"

if "!CAPTURED!"=="" (
    echo   [-] FAIL: CURRENT_DIR line not found in output
    echo   Output:
    type "%OUT%"
    set /a FAIL+=1
    goto :summary
)

echo   Captured CD  : !CAPTURED!
echo   Logical dir  : %LOGICAL_DIR%
echo   Shadow path  : %SHADOW%
echo.

:: Test 1 -- must NOT contain the sandbox root
echo !CAPTURED!z | findstr /i /c:"%SANDBOX%z" >nul
if !errorlevel! equ 0 (
    echo   [-] FAIL Test 1: CD contains sandbox root -- path leaked!
    echo       Got      : !CAPTURED!
    echo       Must NOT : %SANDBOX%
    set /a FAIL+=1
) else (
    echo   [+] PASS Test 1: CD does not expose sandbox root
    set /a PASS+=1
)

:: Test 2 -- must equal the logical path exactly
if /i "!CAPTURED!"=="%LOGICAL_DIR%" (
    echo   [+] PASS Test 2: CD equals logical path exactly
    set /a PASS+=1
) else (
    echo   [-] FAIL Test 2: CD does not match logical path
    echo       Expected : %LOGICAL_DIR%
    echo       Got      : !CAPTURED!
    set /a FAIL+=1
)

:summary
rmdir /s /q "%WS%" 2>nul

echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed : !PASS!
echo  Failed : !FAIL!
echo ============================================================

if !FAIL! equ 0 (
    echo  [OK] ALL TESTS PASSED - path-leak fix is working correctly
    color 2F
) else (
    echo  [X] TESTS FAILED - virtual-store path leaking via NtQueryInformationFile
    echo.
    echo  To reproduce without fix: revert reverseTranslateVolRel in
    echo  Hook_NtQueryInformationFile, rebuild, and rerun.
    echo  CD will show %SANDBOX%\%_DL%%_TAIL% instead of %LOGICAL_DIR%.
    color 4F
)

echo.
if not "%DoNotPause%"=="yes" pause
exit /b !FAIL!
