@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

:: ============================================================
::  NtQueryInformationFile class-9 path-leak test (v4 - correct)
::
::  THE BUG
::  -------
::  Hook_NtQueryInformationFile handles class 9 (FileNameInformation)
::  and class 21 (FileAllInformation). Both return FileName as a
::  volume-relative path like \sandbox\D\myapp\file.txt.
::
::  The original reverseTranslate lambda passes this directly to
::  ReverseApplyFsRedirect, which only matches \??\ NT paths.
::  A volume-relative path never matches -> translation is a no-op.
::
::  HOW TO TRIGGER THE HOOK
::  -----------------------
::  GetFileEntry must return true, meaning the handle must be in
::  g_FileMap. All CoW-fallback handles ARE tracked (isRealOnly=true).
::  The hook fires when GetFinalPathNameByHandle is called on a handle
::  that was opened through the virtualised process.
::
::  We open a file handle inside the virtualised process and keep it
::  open, then call GetFinalPathNameByHandle on that handle.
::  Without the fix: returns sandbox path (leak).
::  With the fix: returns logical path.
::
::  We implement this with a small C# program compiled and run inside
::  the virtualised process using csc.exe (available on all Windows).
:: ============================================================

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true

cd "..\build"
set LAUNCHER=%CD%\VirtLauncher64.exe
if not exist "%LAUNCHER%" set LAUNCHER=%CD%\VirtLauncher32.exe
if not exist "%LAUNCHER%" (
    echo [ERROR] VirtLauncher not found in build folder.
    pause & exit /b 1
)

set "SD=%SYSTEMDRIVE%"
set "_DL=%SD:~0,1%"
set "WS=%SD%\_vltest_ws"
set "LOGICAL_FILE=%WS%\logical\testfile.txt"
set "SANDBOX=%WS%\sandbox"
set "_TAIL=%LOGICAL_FILE:~2%"
set "SHADOW_FILE=%SANDBOX%\%_DL%%_TAIL%"
set "OUT=%WS%\result.txt"
set "CS=%WS%\test.cs"
set "EXE=%WS%\test.exe"

rmdir /s /q "%WS%" 2>nul
mkdir "%WS%\logical"
mkdir "%SANDBOX%"
echo hello > "%LOGICAL_FILE%"

set /a PASS=0
set /a FAIL=0

echo.
echo ============================================================
echo  NtQueryInformationFile class-9 path-leak test
echo  Sandbox and logical on same drive: %SD%
echo ============================================================
echo.
echo  Logical file : %LOGICAL_FILE%
echo  Sandbox root : %SANDBOX%
echo  Shadow file  : %SHADOW_FILE%
echo.

:: Write a C# program that:
::   1. Opens the logical file (gets a tracked CoW handle)
::   2. Calls GetFinalPathNameByHandle on it (triggers NtQueryInformationFile class 9)
::   3. Prints the result
(
echo using System;
echo using System.IO;
echo using System.Runtime.InteropServices;
echo using System.Text;
echo class T {
echo   [DllImport^("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode^)]
echo   static extern uint GetFinalPathNameByHandle^(IntPtr h, StringBuilder s, uint c, uint f^);
echo   static void Main^(string[] a^) {
echo     var fs = File.Open^(a[0], FileMode.Open, FileAccess.Read, FileShare.ReadWrite^);
echo     var sb = new StringBuilder^(1024^);
echo     GetFinalPathNameByHandle^(fs.SafeFileHandle.DangerousGetHandle^(^), sb, 1024, 0^);
echo     fs.Close^(^);
echo     Console.WriteLine^(sb.ToString^(^)^);
echo   }
echo }
) > "%CS%"

:: Compile the test program (outside sandbox, just needs csc)
for /f "delims=" %%i in ('where csc.exe 2^>nul') do set CSC=%%i
if not defined CSC (
    :: Try well-known .NET path
    if exist "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" (
        set CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
    )
)
if not defined CSC (
    echo [SKIP] csc.exe not found, cannot compile test program
    goto :summary
)

"%CSC%" /nologo /out:"%EXE%" "%CS%" >nul 2>&1
if not exist "%EXE%" (
    echo [SKIP] Compilation failed
    goto :summary
)

:: Run the test executable inside the sandbox, passing the logical file path.
:: The virtualised process opens the file -> CoW fallback -> tracked handle.
:: GetFinalPathNameByHandle calls NtQueryInformationFile class 9 on that handle.
%LAUNCHER% -f "%SANDBOX%" "%EXE%" "%LOGICAL_FILE%" > "%OUT%" 2>nul

if not exist "%OUT%" (
    echo   [-] FAIL: no output
    set /a FAIL+=1
    goto :summary
)

set "CAPTURED="
for /f "usebackq delims=" %%L in ("%OUT%") do (
    set "RAW=%%L"
    set "CAPTURED=!RAW:~4!"
)

if "!CAPTURED!"=="" (
    echo   [-] FAIL: no path returned
    type "%OUT%"
    set /a FAIL+=1
    goto :summary
)

echo   Returned : !CAPTURED!
echo   Expected : %LOGICAL_FILE%
echo.

:: Test 1: must NOT contain sandbox root
echo !CAPTURED!z | findstr /i /c:"%SANDBOX%z" >nul
if !errorlevel! equ 0 (
    echo   [-] FAIL Test 1: sandbox path leaked!
    echo       Got      : !CAPTURED!
    echo       Must NOT : %SANDBOX%
    set /a FAIL+=1
) else (
    echo   [+] PASS Test 1: path does not expose sandbox root
    set /a PASS+=1
)

:: Test 2: must equal the logical path
if /i "!CAPTURED!"=="%LOGICAL_FILE%" (
    echo   [+] PASS Test 2: path equals logical path exactly
    set /a PASS+=1
) else (
    echo   [-] FAIL Test 2: path does not match logical path
    echo       Expected : %LOGICAL_FILE%
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
    echo  [OK] ALL TESTS PASSED
    color 2F
) else (
    echo  [X] TESTS FAILED
    echo.
    echo  Without the fix: the sandbox path leaks because reverseTranslate
    echo  passes a volume-relative FileName directly to ReverseApplyFsRedirect,
    echo  which only matches \??\ NT paths and always returns unchanged.
    echo  Rebuild with the fix and rerun to see it pass.
    color 4F
)
echo.
if not "%DoNotPause%"=="yes" pause
exit /b !FAIL!
