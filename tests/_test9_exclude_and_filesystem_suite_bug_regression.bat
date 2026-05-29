@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
@rem fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


:: ============================================================
::  VirtLauncher [exclude] Feature Test Suite  (v1)
::
::  Covers:
::    Section 1: [exclude] + --config            basic exclude operations
::    Section 2: [exclude] + --config            deep nesting and sibling paths
::    Section 3: --filesystem flag               catch-all sandbox (no exclude)
::    Section 4: --filesystem + [exclude]        exclude bypass inside sandbox
::    Section 5: Component-boundary guard        prefix != path component
::
::  What is tested per section:
::    Write / Read / Delete / Rename on excluded paths stay on real FS.
::    Non-excluded paths under the same redirect still virtualise normally.
::    Excluded writes do NOT appear in the virtual store.
::    --filesystem catch-all is correctly bypassed for excluded paths.
::    Excluding  foo  never accidentally excludes  foo_sibling  or  foobar.
:: ============================================================

:: ---- Build directory ----
cd "..\build"


:: ---- Launcher (prefer 64-bit) ----
set LAUNCHER=VirtLauncher64.exe
if not exist "%LAUNCHER%" set LAUNCHER=VirtLauncher32.exe
if not exist "%LAUNCHER%" (
    echo [ERROR] VirtLauncher executable not found in build folder.
    pause
    exit /b 1
)

:: ====================================================================
::  Workspace layout
::
::  _excl_test_ws\
::    src\              logical source  (what the app sees)
::      excl\           the directory we will mark as [exclude]
::      excl_sibling\   same parent, shares "excl" as a string prefix
::    dst\              redirect destination for --config tests
::    sandbox1\         --filesystem store  (Section 3, no exclude)
::    sandbox2\         --filesystem store  (Section 4, with exclude)
::    full.ini          [redirect] src->dst  +  [exclude] excl
::    excl_only.ini     [exclude] excl  only  (for --filesystem tests)
:: ====================================================================

set "TEST_DIR=%CD%\_excl_test_ws"
set "SRC_DIR=%TEST_DIR%\src"
set "DST_DIR=%TEST_DIR%\dst"
set "EXCL_DIR=%SRC_DIR%\excl"
set "EXCL_SIBLING=%SRC_DIR%\excl_sibling"
set "SANDBOX1=%TEST_DIR%\sandbox1"
set "SANDBOX2=%TEST_DIR%\sandbox2"
set "FULL_INI=%TEST_DIR%\full.ini"
set "EXCL_ONLY_INI=%TEST_DIR%\excl_only.ini"

:: ---- Compute --filesystem shadow paths --------------------------------
::
::  VirtHook maps:   \??\X:\some\path   ->   \??\<sandboxroot>\X\some\path
::  On disk that is: <sandboxroot>\<DriveLetter><path_without_drive_colon>
::
::  Example:  SRC_DIR = D:\build\_excl_test_ws\src
::    _DL           = D
::    _SRC_TAIL     = \build\_excl_test_ws\src
::    SHADOW1       = %SANDBOX1%\D\build\_excl_test_ws\src
::
for %%D in ("%SRC_DIR%")     do set "_SDRIVE=%%~dD"
set "_DL=!_SDRIVE:~0,1!"
set "_SRC_TAIL=!SRC_DIR:~2!"
set "_EXCL_TAIL=!EXCL_DIR:~2!"
set "_EXCL_SIB_TAIL=!EXCL_SIBLING:~2!"

::  SHADOW1 / SHADOW2  = virtual store copy of SRC_DIR
set "SHADOW1=%SANDBOX1%\!_DL!!_SRC_TAIL!"
set "SHADOW2=%SANDBOX2%\!_DL!!_SRC_TAIL!"

::  EXCL_SHADOW1/2  = where EXCL_DIR *would* land if it were not excluded
set "EXCL_SHADOW1=%SANDBOX1%\!_DL!!_EXCL_TAIL!"
set "EXCL_SHADOW2=%SANDBOX2%\!_DL!!_EXCL_TAIL!"

::  EXCL_SIB_SHADOW2  = where EXCL_SIBLING would land in sandbox2
set "EXCL_SIB_SHADOW2=%SANDBOX2%\!_DL!!_EXCL_SIB_TAIL!"

:: ---- Clean and create workspace ----
rmdir /s /q "%TEST_DIR%" 2>nul
mkdir "%SRC_DIR%"
mkdir "%DST_DIR%"
mkdir "%EXCL_DIR%"
mkdir "%EXCL_SIBLING%"
mkdir "%SANDBOX1%"
mkdir "%SANDBOX2%"

:: ---- full.ini : [redirect] src -> dst  +  [exclude] excl_dir ----
(
    echo # VirtLauncher test config -- redirect + exclude
    echo [redirect]
    echo %SRC_DIR%=%DST_DIR%
    echo.
    echo [exclude]
    echo %EXCL_DIR%
) > "%FULL_INI%"

:: ---- excl_only.ini : [exclude] only, used with --filesystem ----
:: NOTE: no parentheses anywhere inside this block -- a bare ) in an echo
::       line would prematurely close the compound redirect and leave the
::       [exclude] section unwritten (root cause of the section-4 failures).
(
    echo # Test config: exclude only, used paired with --filesystem flag
    echo [exclude]
    echo %EXCL_DIR%
) > "%EXCL_ONLY_INI%"

set /a PASS_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0

mkdir "%SHADOW1%"

:: 3.4  Delete via -f: plant in shadow, delete via logical path, must remove from shadow
echo ___________________
echo DeleteMe>"%SHADOW1%\fs_del.txt"
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "del "%SRC_DIR%\fs_del.txt" "
if not exist "%SHADOW1%\fs_del.txt" (
    call :Pass "3.4  FS Delete: delete via logical path removed file from sandbox shadow"
) else (
    call :Fail "3.4  FS Delete: sandbox shadow file still present after delete"
)


mkdir "%EXCL_SHADOW2%" 2>nul
:: 4.5  Delete in excluded path: must delete the real file, not the shadow decoy
echo ___________________
echo RealDeleteTarget>"%EXCL_DIR%\fsexcl_del.txt"
echo ShadowDecoy>"%EXCL_SHADOW2%\fsexcl_del.txt"
%LAUNCHER% -f "%SANDBOX2%" -c "%EXCL_ONLY_INI%" cmd /S /c "del "%EXCL_DIR%\fsexcl_del.txt" "
if not exist "%EXCL_DIR%\fsexcl_del.txt" (
    if exist "%EXCL_SHADOW2%\fsexcl_del.txt" (
        call :Pass "4.5  FS+Excl Delete: real file deleted, shadow decoy untouched"
    ) else (
        call :Fail "4.5  FS+Excl Delete: both real and shadow files gone (shadow should be untouched)"
    )
) else (
    call :Fail "4.5  FS+Excl Delete: real file still present after delete via excluded path"
)


:: ============================================================
:: CLEANUP & SUMMARY
:: ============================================================
echo.
echo [*] Cleaning up test artifacts...
attrib -R "%DST_DIR%\*" /s >nul 2>&1
attrib -R "%SRC_DIR%\*" /s >nul 2>&1
rmdir /s /q "%TEST_DIR%" 2>nul

echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed  : %PASS_COUNT%
echo  Failed  : %FAIL_COUNT%
echo  Skipped : %SKIP_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY!
    color 2F
) else (
    echo  [X] SOME TESTS FAILED!
    color 4F
)

echo.
pause
exit /b %FAIL_COUNT%


:: -------------------------------------------------------------------------
:: Helpers
:: -------------------------------------------------------------------------
:Pass
echo   [+] PASS: %~1
set /a PASS_COUNT+=1
goto :eof

:Fail
echo   [-] FAIL: %~1
set /a FAIL_COUNT+=1
goto :eof

:Skip
echo   [~] SKIP: %~1
set /a SKIP_COUNT+=1
goto :eof
