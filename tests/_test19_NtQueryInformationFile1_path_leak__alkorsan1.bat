@echo off
SETLOCAL
CD /D "%~dp0"

:: ============================================================
::  NtQueryInformationFile path-leak regression test
::
::  Without the Hook_NtQueryInformationFile fix, GetCurrentDirectory()
::  and %CD% inside a virtualised cmd.exe return the PHYSICAL path
::  inside the virtual store instead of the logical path the app
::  intended to open.
::
::  Example (FSDIR sandbox on C:\Sandbox, logical dir C:\MyApp):
::    Without fix:  CD = C:\Sandbox\C\MyApp     <- physical store path leaks
::    With fix:     CD = C:\MyApp               <- correct logical path
::
::  The test works by:
::    1. Creating a logical directory to chdir into.
::    2. Launching a virtualised cmd.exe that cds into it and echoes %CD%.
::    3. Capturing the output.
::    4. Checking whether the result contains the sandbox root (leak)
::       or the logical path (correct).
::
::  Class 9  (FileNameInformation)   - used by GetCurrentDirectoryW / %CD%
::  Class 21 (FileAllInformation)    - same embedded FILE_NAME_INFORMATION,
::                                     used by many path-querying APIs.
::
::  Both classes are exercised because cmd.exe internally uses class 9 for
::  %CD% and several Win32 APIs fall back to class 21 for full file info.
:: ============================================================

cd "..\build"
set "test_dir=%cd%"
set LAUNCHER=%cd%\VirtLauncher64.exe

:: ---- Workspace ----
set "WS=f:\_qleak_test_ws"
set "LOGICAL_DIR=%WS%\logical\myapp\data"
set "SANDBOX=%CD%\sandbox"
set "SHADOW=%SANDBOX%\f\_qleak_test_ws\logical\myapp\data"

rmdir /s /q "%WS%" 2>nul
mkdir "%LOGICAL_DIR%"
mkdir "%SANDBOX%"

set /a PASS=0
set /a FAIL=0

echo.
echo ============================================================
echo  NtQueryInformationFile path-leak test
echo ============================================================
echo.
echo  Logical dir : %LOGICAL_DIR%
echo  Sandbox root: %SANDBOX%
echo.

:: ---- Compute expected shadow path ----
::  VirtHook maps  X:\foo  ->  sandbox\X\foo
rem for %%D in ("%LOGICAL_DIR%") do set "_DRV=%%~dD"
rem set "_DL=!_DRV:~0,1!"
rem set "_TAIL=!LOGICAL_DIR:~2!"
rem set "SHADOW=%SANDBOX%\!_DL!!_TAIL!"

echo  Shadow path : %SHADOW%
echo.

:: ---- Capture %CD% from inside the virtualised process ----
::
::  We redirect stderr to nul so VirtHook debug noise doesn't pollute output.
::  The /S /C wrapper ensures the whole "cd ... && ..." is treated as one command.
::
    
set "OUT_FILE=%WS%\cd_output.txt"

rem ======================================================
rem cd /D c:\
rem this is wrong it prints  c:\ not d:\
rem This is not a bug; it is a classic Windows command-line quirk involving parse-time vs. execution-time variable expansion. the command interpreter compiles/evaluates the entire line of code before it executes the first instruction on that line.
rem Here is exactly what is happening in the background:
rem The Breakdown
rem 	1. Parent Parsing: When your batch file runs, it sees %%CD%% and escapes it down to %CD%.
rem 	2. Child Parsing: The child process spawned by cmd /C receives the following string: cd /D "d:\" && echo CURRENT_DIR22=%CD%
rem 	3. Premature Evaluation: The child cmd.exe parses this entire line at once before executing anything. At the exact moment of parsing, the directory has not changed yet; it is still c:\ (inherited from the pushd c:\ command).
rem 	4. Execution: It replaces %CD% with c:\, creating the final execution instruction: cd /D "d:\" && echo CURRENT_DIR22=c:\. It successfully changes the directory to D:\ in memory, but echoes the pre-evaluated string.
rem cmd /S /C "cd /D "d:\" && echo CURRENT_DIR22=%%CD%%"  

rem solution:
rem met1
rem cmd /S /C "@echo off && cd /D "d:\" && for /f "delims=" %%I in ('cd') do echo CURRENT_DIR22=%%I"
rem met2
rem setlocal DisableDelayedExpansion
rem cmd /V:ON /S /C "cd /D "d:\" && echo CURRENT_DIR22=!CD!"
rem ======================================================

rem lets fake the current dir
pushd c:\

:: wrong
rem %LAUNCHER% -f "%SANDBOX%" cmd /S /C "cd /D "%LOGICAL_DIR%" && echo CURRENT_DIR=%%CD%%"  
:: good
rem %LAUNCHER% -f "%SANDBOX%" cmd /S /C \"@echo off && cd /D \"%LOGICAL_DIR%\" && for /f \"delims=\" %%I in ('cd') do echo CURRENT_DIR=%%I\"
:: good
rem setlocal DisableDelayedExpansion
rem %LAUNCHER% -f "%SANDBOX%" cmd /V:ON /S /C "cd /D "%LOGICAL_DIR%" && echo CURRENT_DIR=!CD!"




:: wrong
rem %LAUNCHER% -f "%SANDBOX%" cmd /S /C "cd /D "%LOGICAL_DIR%" && echo CURRENT_DIR=%%CD%%" > "%OUT_FILE%" 2>nul
:: good
setlocal DisableDelayedExpansion
%LAUNCHER% -f "%SANDBOX%" cmd /V:ON /S /C "cd /D "%LOGICAL_DIR%" && echo CURRENT_DIR=!CD!" > "%OUT_FILE%" 2>nul


if not exist "%OUT_FILE%" (
    echo   [-] FAIL: no output captured from virtualised cmd.exe
    set /a FAIL+=1
    goto :summary
)

set "CAPTURED="
for /f "tokens=1,* delims==" %%A in ('findstr /i "CURRENT_DIR=" "%OUT_FILE%"') do (
    set "CAPTURED=%%B"
)

SETLOCAL EnableDelayedExpansion

if "!CAPTURED!"=="" (
    echo   [-] FAIL: CURRENT_DIR line not found in output
    echo       Output was:
    type "%OUT_FILE%"
    set /a FAIL+=1
    goto :summary
)

echo   Captured CD  : !CAPTURED!
echo   Logical dir  : %LOGICAL_DIR%
echo   Shadow path  : %SHADOW%
echo.

:: ---- Test 1: result must NOT contain the sandbox root (path-leak check) ----
echo !CAPTURED!z | findstr /i /c:"%SANDBOX%z" >nul
if !errorlevel! equ 0 (
    echo   [-] FAIL Test 1: CD contains sandbox root -- physical path leaked!
    echo       Got : !CAPTURED!
    echo       Must NOT contain: %SANDBOX%
    set /a FAIL+=1
) else (
    echo   [+] PASS Test 1: CD does not expose sandbox root
    set /a PASS+=1
)

:: ---- Test 2: result must equal the logical path ----
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
:: ---- Cleanup ----
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
    echo  [X] TESTS FAILED - virtual-store path is leaking through NtQueryInformationFile
    echo.
    echo  To reproduce the bug: comment out or revert the reverseTranslateVolRel
    echo  lambda in Hook_NtQueryInformationFile in VirtHook.cpp, rebuild, and
    echo  rerun this script.  The captured CD will show the sandbox path instead
    echo  of the logical path.
    color 4F
)

echo.
if not "%DoNotPause%"=="yes" pause
exit /b !FAIL!
