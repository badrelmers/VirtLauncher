@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

:: ============================================================
::  NtQueryInformationFile class-9 path-leak regression test (v3)
::
::  ROOT CAUSE
::  ----------
::  Hook_NtQueryInformationFile calls ReverseApplyFsRedirect on the
::  raw volume-relative FileName (e.g. \_vltest_ws\logical\file.txt).
::  ReverseApplyFsRedirect expects a full \??\ NT path.  A bare
::  volume-relative path never matches either rule, so the function
::  always returns it unchanged -- the hook is a permanent no-op.
::
::  WHY %CD% IS THE WRONG TEST
::  --------------------------
::  cmd.exe stores the current directory in ProcessParameters->CurrentDirectory
::  (the PEB) and reads it back via RtlGetCurrentDirectory_U, which never
::  calls NtQueryInformationFile at all.  So %CD% is always correct
::  regardless of whether this hook works or not.
::
::  THE RIGHT API TO TEST
::  ---------------------
::  GetFinalPathNameByHandle() calls NtQueryInformationFile class 9
::  (FileNameInformation) on an open file handle to resolve the path.
::  Without the fix, it returns the sandbox-rooted physical path.
::  With the fix, it returns the logical path.
::
::  We call it from PowerShell (available everywhere on modern Windows)
::  since batch has no built-in for it.
::
::  SETUP
::  -----
::  Logical file : %SD%\_vltest_ws\logical\testfile.txt
::  Sandbox      : %SD%\_vltest_ws\sandbox   (SAME drive -- bug only visible same-drive)
::  Shadow file  : %SD%\_vltest_ws\sandbox\%DL%\_vltest_ws\logical\testfile.txt
::
::  The sandbox is on the same drive as the logical path because the
::  volume-relative FileName is relative to the physical volume.
::  Cross-drive: FileName=\sandbox\D\..., physical drive F: -> prepend \??\F:
::               -> ReverseApplyFsRedirect sees \??\F:\sandbox\D\...  (correct, matches)
::  Same-drive:  FileName=\sandbox\D\..., physical drive D: -> prepend \??\D:
::               -> ReverseApplyFsRedirect sees \??\D:\sandbox\D\...  (correct, matches)
::  Both cases need the fix.  Same-drive is easiest to test since we
::  can guarantee both paths exist on one machine without a second volume.
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
set "LOGICAL_DIR=%WS%\logical"
set "LOGICAL_FILE=%LOGICAL_DIR%\testfile.txt"
set "SANDBOX=%WS%\sandbox"
set "SHADOW_DIR=%SANDBOX%\%_DL%\_vltest_ws\logical"
set "OUT=%WS%\out.txt"

rmdir /s /q "%WS%" 2>nul
mkdir "%LOGICAL_DIR%"
mkdir "%SANDBOX%"
echo hello > "%LOGICAL_FILE%"

set /a PASS=0
set /a FAIL=0

echo.
echo ============================================================
echo  NtQueryInformationFile class-9 path-leak test (GetFinalPathNameByHandle)
echo  Sandbox and logical on same drive: %SD%
echo ============================================================
echo.
echo  Logical file : %LOGICAL_FILE%
echo  Sandbox root : %SANDBOX%
echo.

:: PowerShell script: open the logical file path as a handle inside the
:: virtualised process, call GetFinalPathNameByHandle on it, print the result.
::
:: GetFinalPathNameByHandle internally calls NtQueryInformationFile class 9.
:: Without the fix the returned path is the sandbox physical path.
:: With the fix it is the logical path.
::
:: We use [System.IO.File]::Open to get a FileStream (which holds a Win32
:: handle), then P/Invoke GetFinalPathNameByHandleW from kernel32.
set "PS_SCRIPT=%WS%\getpath.ps1"
(
echo $sig = @'
echo [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode^)]
echo public static extern uint GetFinalPathNameByHandle(IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags^);
echo '@
echo $k = Add-Type -MemberDefinition $sig -Name K32 -Namespace Win32 -PassThru
echo $fs = [System.IO.File]::Open('%LOGICAL_FILE%', 'Open', 'Read', 'ReadWrite'^)
echo $sb = New-Object System.Text.StringBuilder 1024
echo $r = $k::GetFinalPathNameByHandle($fs.SafeFileHandle.DangerousGetHandle(^), $sb, 1024, 0^)
echo $fs.Close(^)
echo if ($r -gt 0^) { Write-Output $sb.ToString(^) } else { Write-Output "FAILED" }
) > "%PS_SCRIPT%"

:: Run the PS script inside the virtualised sandbox
%LAUNCHER% -f "%SANDBOX%" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" > "%OUT%" 2>nul

if not exist "%OUT%" (
    echo   [-] FAIL: no output captured
    set /a FAIL+=1
    goto :summary
)

:: Strip the \\?\ prefix that GetFinalPathNameByHandle prepends (VOLUME_NAME_DOS flag=0)
set "CAPTURED="
for /f "usebackq delims=" %%L in ("%OUT%") do (
    set "RAW=%%L"
    :: strip \\?\ prefix
    set "STRIPPED=!RAW:~4!"
    if not "!STRIPPED!"=="" set "CAPTURED=!STRIPPED!"
)

if "!CAPTURED!"=="" (
    echo   [-] FAIL: no path returned from GetFinalPathNameByHandle
    echo   Raw output:
    type "%OUT%"
    set /a FAIL+=1
    goto :summary
)

echo   Returned path : !CAPTURED!
echo   Expected      : %LOGICAL_FILE%
echo   Would leak    : %SHADOW_DIR%\testfile.txt
echo.

:: Test 1: must NOT contain sandbox root
echo !CAPTURED!z | findstr /i /c:"%SANDBOX%z" >nul
if !errorlevel! equ 0 (
    echo   [-] FAIL Test 1: sandbox path leaked via GetFinalPathNameByHandle
    echo       Got      : !CAPTURED!
    echo       Must NOT : %SANDBOX%
    set /a FAIL+=1
) else (
    echo   [+] PASS Test 1: returned path does not expose sandbox root
    set /a PASS+=1
)

:: Test 2: must match logical path exactly
if /i "!CAPTURED!"=="%LOGICAL_FILE%" (
    echo   [+] PASS Test 2: returned path equals logical path exactly
    set /a PASS+=1
) else (
    echo   [-] FAIL Test 2: returned path does not match logical path
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
    echo  Without the Hook_NtQueryInformationFile fix, GetFinalPathNameByHandle
    echo  returns the physical sandbox path instead of the logical path.
    echo  Rebuild with the reverseTranslateVolRel fix and rerun to see it pass.
    color 4F
)

echo.
if not "%DoNotPause%"=="yes" pause
exit /b !FAIL!
