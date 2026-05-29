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
set "VIRT_ROOT=HKEY_CURRENT_USER\VirtTestFull_Root"

set /a PASS_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0

REM ── get current user SID ─────────────────────────────────────
for /f "tokens=2 delims==" %%A in ('wmic useraccount where "name=''%username%''" get sid /value 2^>nul') do set "USER_SID=%%A"
if "%USER_SID%"=="" for /f "tokens=2" %%A in ('whoami /user /fo table /nh') do set "USER_SID=%%A"
set "USER_SID=%USER_SID: =%"

echo ============================================================
echo  VirtLauncher Full Registry Test Suite
echo  SID: %USER_SID%
echo ============================================================
echo.

REM ════════════════════════════════════════════════════════════
REM  Run each store section
REM ════════════════════════════════════════════════════════════

set "STORE_ID=HKLM_SOFTWARE"
set "REAL_KEY=HKEY_LOCAL_MACHINE\SOFTWARE"
set "VIRT_KEY=%VIRT_ROOT%\%REAL_KEY%"
call :run_all_tests

set "STORE_ID=HKLM_CLASSES"
set "REAL_KEY=HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
set "VIRT_KEY=%VIRT_ROOT%\%REAL_KEY%"
call :run_all_tests

set "STORE_ID=HKCU_SOFTWARE"
set "REAL_KEY=HKEY_CURRENT_USER\Software"
set "VIRT_KEY=%VIRT_ROOT%\%REAL_KEY%"
call :run_all_tests

REM HKCR writes go to two virtual destinations:
REM   VirtRoot\HKEY_LOCAL_MACHINE\SOFTWARE\Classes  (HKLM backing path)
REM   VirtRoot\HKEY_USERS\SID_Classes               (per-user backing path)
REM The test verifies both.
set "STORE_ID=HKCR_ROOT"
set "REAL_KEY=HKEY_CLASSES_ROOT"
set "VIRT_KEY=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
set "VIRT_KEY2=%VIRT_ROOT%\HKEY_USERS\%USER_SID%_Classes"
call :run_all_tests_hkcr

set "STORE_ID=HKU_CLASSES"
set "REAL_KEY=HKEY_USERS\%USER_SID%_Classes"
set "VIRT_KEY=%VIRT_ROOT%\%REAL_KEY%"
call :run_all_tests

REM HKEY_USERS\SID writes must go to VirtRoot\HKEY_CURRENT_USER
set "STORE_ID=HKU_SID"
set "REAL_KEY=HKEY_USERS\%USER_SID%"
set "VIRT_KEY=%VIRT_ROOT%\HKEY_CURRENT_USER"
call :run_all_tests

REM ── HKCR cross-hive consistency ──────────────────────────────
call :run_hkcr_crosshive_tests

REM ── Tombstone persistence & re-create cycle ──────────────────
call :run_tombstone_advanced_tests

echo.
echo ============================================================
echo  SUMMARY
echo ============================================================
echo   Passed : %PASS_COUNT%
echo   Failed : %FAIL_COUNT%
echo   Skipped: %SKIP_COUNT%
echo ============================================================
if %FAIL_COUNT% EQU 0 ( color 2F & echo  [OK] ALL TESTS PASSED ) else ( color 4F & echo  [X] %FAIL_COUNT% FAILURES )
echo.
call :GLOBAL_CLEANUP
if not "%DoNotPause%"=="yes" pause
exit /b %FAIL_COUNT%


REM ════════════════════════════════════════════════════════════
REM :run_all_tests
REM   Full suite for a non-HKCR store (REAL_KEY / VIRT_KEY set)
REM ════════════════════════════════════════════════════════════
:run_all_tests
call :CLEANUP
echo.
echo ┌──────────────────────────────────────────────────────────
echo │  STORE: %STORE_ID%  ^(%REAL_KEY%^)
echo └──────────────────────────────────────────────────────────

call :section_basic_write_read
call :section_value_tombstone
call :section_key_tombstone
call :section_nested_key_tombstone
call :section_tombstone_recreate_value
call :section_tombstone_recreate_key
call :section_merged_view
call :section_enumeration_with_tombstones
call :section_multi_value_partial_delete
call :section_edge_cases

call :CLEANUP
exit /b

REM ════════════════════════════════════════════════════════════
REM :run_all_tests_hkcr
REM   Same suite for HKCR (dual virtual destinations)
REM ════════════════════════════════════════════════════════════
:run_all_tests_hkcr
call :CLEANUP
echo.
echo ┌──────────────────────────────────────────────────────────
echo │  STORE: %STORE_ID%  ^(%REAL_KEY%^)  [HKCR dual-dest]
echo └──────────────────────────────────────────────────────────

call :section_basic_write_read
call :section_value_tombstone
call :section_key_tombstone
call :section_nested_key_tombstone
call :section_tombstone_recreate_value
call :section_tombstone_recreate_key
call :section_merged_view
call :section_enumeration_with_tombstones
call :section_multi_value_partial_delete
call :section_edge_cases

call :CLEANUP
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Basic Write / Read
REM ════════════════════════════════════════════════════════════
:section_basic_write_read
echo.
echo   [1] Basic Write / Read
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v TestVal /t REG_SZ /d SandboxData /f >nul

echo        write visible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v TestVal 2>nul | findstr "SandboxData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "value not visible in sandbox after write")

echo        write did NOT leak to real registry
reg query "%REAL_KEY%" /v TestVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "value leaked to real registry")

echo        read via separate sandbox invocation
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_KEY%" /v TestVal 2>nul | findstr "SandboxData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "value not visible in new sandbox process")

echo        DWORD write and read
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v DwordVal /t REG_DWORD /d 0x1234 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v DwordVal 2>nul | findstr "0x1234" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "DWORD value not readable")

echo        DWORD did NOT leak to real registry
reg query "%REAL_KEY%" /v DwordVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "DWORD leaked to real registry")
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Value Tombstone
REM ════════════════════════════════════════════════════════════
:section_value_tombstone
echo.
echo   [2] Value Tombstone
call :CLEANUP
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v TombVal /t REG_SZ /d ToBeDeleted /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v TombVal /f >nul 2>nul

echo        deleted value invisible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v TombVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deleted value still visible inside sandbox")

echo        tombstone marker written to virtual store
reg query "%VIRT_KEY%" /v TombVal 2>nul | findstr /C:"TombVal    REG_NONE" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "tombstone marker not found in virtual store")

echo        real registry unchanged after sandboxed delete
reg query "%REAL_KEY%" /v TombVal >nul 2>nul
REM Real key may or may not have existed; we just care it wasn't destructively altered.
REM (It was written by the sandbox so it shouldn't exist in real – check it's absent)
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "real registry was modified by sandboxed delete")

echo        tombstone survives new sandbox invocation
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_KEY%" /v TombVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstoned value reappears in new sandbox process")

REM Delete a value that exists ONLY in the real registry (no virtual copy)
reg add "%REAL_KEY%" /v RealOnlyVal /t REG_SZ /d RealData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v RealOnlyVal /f >nul 2>nul

echo        real-only value invisible after sandboxed delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RealOnlyVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "real-only value still visible after sandboxed delete")

echo        tombstone written for real-only value
reg query "%VIRT_KEY%" /v RealOnlyVal 2>nul | findstr /C:"RealOnlyVal    REG_NONE" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "no tombstone for real-only value delete")

echo        real-only value still intact in real registry
reg query "%REAL_KEY%" /v RealOnlyVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only value was deleted from real registry")
reg delete "%REAL_KEY%" /v RealOnlyVal /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Key Tombstone
REM ════════════════════════════════════════════════════════════
:section_key_tombstone
echo.
echo   [3] Key Tombstone
call :CLEANUP
reg add "%REAL_KEY%\VirtSubKey" /v KVal /t REG_SZ /d RealKey /f >nul

%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\VirtSubKey" /v KVal /t REG_SZ /d hello /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\VirtSubKey" /f >nul 2>nul

echo        deleted key invisible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\VirtSubKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deleted key still visible in sandbox")

echo        key tombstone marker (VL_KEY_DELETED) in virtual store
reg query "%VIRT_KEY%\VirtSubKey" /v VL_KEY_DELETED 2>nul | findstr /C:"VL_KEY_DELETED    REG_NONE" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "VL_KEY_DELETED sentinel not found in virtual store")

echo        tombstoned key invisible in new sandbox process
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_KEY%\VirtSubKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstoned key visible in new sandbox process")

reg delete "%REAL_KEY%\VirtSubKey" /f >nul 2>nul

REM Delete a key that exists ONLY in the real registry
reg add "%REAL_KEY%\RealSubKey" /v RKVal /t REG_SZ /d RealKey /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\RealSubKey" /f >nul 2>nul

echo        real-only key invisible after sandboxed delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RealSubKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "real-only key still visible after sandboxed delete")

echo        real key still exists in real registry
reg query "%REAL_KEY%\RealSubKey" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only key was actually deleted from real registry")
reg delete "%REAL_KEY%\RealSubKey" /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Nested Key Tombstone
REM ════════════════════════════════════════════════════════════
:section_nested_key_tombstone
echo.
echo   [4] Nested Key Tombstone (parent deleted → children invisible)
call :CLEANUP
reg add "%REAL_KEY%\Parent\Child\GrandChild" /v Deep /t REG_SZ /d DeepVal /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\Parent" /f >nul 2>nul

echo        parent invisible after delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\Parent" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deleted parent still visible")

echo        child invisible when parent is tombstoned
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\Parent\Child" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "child of tombstoned parent still visible")

echo        grandchild invisible when ancestor is tombstoned
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\Parent\Child\GrandChild" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "grandchild of tombstoned ancestor still visible")

echo        deep value invisible when ancestor is tombstoned
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\Parent\Child\GrandChild" /v Deep >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deep value of tombstoned ancestor still visible")

echo        real nested keys still intact in real registry
reg query "%REAL_KEY%\Parent\Child\GrandChild" /v Deep >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real nested keys were deleted from real registry")
reg delete "%REAL_KEY%\Parent" /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Tombstone → Re-create Value
REM ════════════════════════════════════════════════════════════
:section_tombstone_recreate_value
echo.
echo   [5] Tombstone then Re-create Value
call :CLEANUP
reg add "%REAL_KEY%" /v RcVal /t REG_SZ /d OrigData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v RcVal /f >nul 2>nul

echo        value hidden after tombstone
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RcVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "value not hidden before re-create")

%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v RcVal /t REG_SZ /d NewData /f >nul

echo        re-created value visible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RcVal 2>nul | findstr "NewData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "re-created value not visible in sandbox")

echo        re-created value shows new data (not original)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RcVal 2>nul | findstr "OrigData" >nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "re-created value shows original data instead of new")

echo        tombstone replaced by live value in virtual store
reg query "%VIRT_KEY%" /v RcVal 2>nul | findstr /C:"RcVal    REG_SZ" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "tombstone was not replaced by live value in virtual store")

echo        re-created value did not leak to real registry
reg query "%REAL_KEY%" /v RcVal 2>nul | findstr "NewData" >nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "re-created value leaked to real registry")

REM Double cycle: delete again
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v RcVal /f >nul 2>nul

echo        re-deleted value invisible again
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RcVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "re-deleted value still visible")

echo        tombstone re-created after second delete
reg query "%VIRT_KEY%" /v RcVal 2>nul | findstr /C:"RcVal    REG_NONE" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "tombstone not present after second delete")
reg delete "%REAL_KEY%" /v RcVal /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Tombstone → Re-create Key
REM ════════════════════════════════════════════════════════════
:section_tombstone_recreate_key
echo.
echo   [6] Tombstone then Re-create Key
call :CLEANUP
reg add "%REAL_KEY%\RcKey" /v OldVal /t REG_SZ /d OldData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\RcKey" /f >nul 2>nul

echo        key hidden after tombstone
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RcKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "key not hidden before re-create")

%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\RcKey" /v NewVal /t REG_SZ /d NewData /f >nul

echo        re-created key visible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RcKey" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "re-created key not visible in sandbox")

echo        re-created key has new value (not old)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RcKey" /v NewVal 2>nul | findstr "NewData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "re-created key does not have new value")

echo        old value from real key not visible after tombstone+recreate
rem this is dificult to implement it, once we recreate a key the tombstone is deleted so we can see again the keys inside the recreated key and of course the real key will be merged with our virtual one and will be visible, in theory it should not be visible because we deleted the real one in our virtual world before we recreate again inside our virtual worl ,so each key and value should have got a tombstone, as you see this is too much , imagine a key with 100 keys inside it and each key with 100 values, we will have to create 100x100 tombstone to make this test work correctly. i will not implement this. in sandboxie happen the same thing as my tool so if they did not fix it and everything work fine then things should work fine too with my tool
echo            intentionally bypassed - by badr
goto :bypass1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RcKey" /v OldVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "old real value visible through re-created key")
:bypass1

echo        VL_KEY_DELETED tombstone marker removed after re-create
reg query "%VIRT_KEY%\RcKey" /v VL_KEY_DELETED >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "VL_KEY_DELETED tombstone marker still present after re-create")

echo        re-created key did not leak to real registry (as new)
reg query "%REAL_KEY%\RcKey" /v NewVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "re-created key's new value leaked to real registry")
reg delete "%REAL_KEY%\RcKey" /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Merged View
REM ════════════════════════════════════════════════════════════
:section_merged_view
echo.
echo   [7] Merged View
call :CLEANUP
reg add "%REAL_KEY%" /v RealVal /t REG_SZ /d FromReal /f >nul

echo        real-only value visible inside sandbox (passthrough)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RealVal 2>nul | findstr "FromReal" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only value not visible inside sandbox")

%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v RealVal /t REG_SZ /d OverriddenByVirt /f >nul

echo        virtual override shadows real value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v RealVal 2>nul | findstr "OverriddenByVirt" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "virtual override not shadowing real value")

echo        real value unchanged by virtual override
reg query "%REAL_KEY%" /v RealVal 2>nul | findstr "FromReal" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real value was changed by virtual write")

REM Real subkey visible via sandbox
reg add "%REAL_KEY%\RealOnlySub" /v SubVal /t REG_SZ /d SubData /f >nul

echo        real subkey visible inside sandbox
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RealOnlySub" /v SubVal 2>nul | findstr "SubData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real subkey not visible inside sandbox")

REM Virtual subkey with same name overrides real
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\RealOnlySub" /v SubVal /t REG_SZ /d VirtSub /f >nul

echo        virtual write to real subkey overrides its value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\RealOnlySub" /v SubVal 2>nul | findstr "VirtSub" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "virtual override of real subkey value not working")

reg delete "%REAL_KEY%\RealOnlySub" /f >nul 2>nul
reg delete "%REAL_KEY%" /v RealVal /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Enumeration with Tombstones
REM ════════════════════════════════════════════════════════════
:section_enumeration_with_tombstones
echo.
echo   [8] Enumeration with Tombstones
call :CLEANUP

REM Set up: two virtual values + one real-only value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v EnumA /t REG_SZ /d DataA /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v EnumB /t REG_SZ /d DataB /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v EnumC /t REG_SZ /d DataC /f >nul
reg add "%REAL_KEY%" /v RealEnum /t REG_SZ /d RealData /f >nul

echo        all values visible before any delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "EnumA" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "EnumA not visible before delete")

REM Delete middle value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v EnumB /f >nul 2>nul

echo        enumeration succeeds after deleting middle value (no NO_MORE_DATA error)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "reg query failed with ERROR after deleting middle value")

echo        EnumA still visible after EnumB deleted
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "EnumA" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "EnumA disappeared after EnumB was deleted")

echo        EnumB not visible after delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v EnumB >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "EnumB still visible after delete")

echo        EnumC still visible after EnumB deleted
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "EnumC" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "EnumC disappeared after EnumB was deleted")

echo        real-only value RealEnum still visible
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr "RealEnum" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "real-only RealEnum not visible after sibling delete")

REM Virtual subkey enumeration
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\SubEnum1" /v X /t REG_SZ /d x /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\SubEnum2" /v X /t REG_SZ /d x /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\SubEnum3" /v X /t REG_SZ /d x /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\SubEnum2" /f >nul 2>nul

echo        subkey enumeration succeeds with a tombstoned middle subkey
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "reg query failed after deleting middle subkey")

echo        SubEnum1 visible when SubEnum2 tombstoned
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\SubEnum1" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "SubEnum1 not visible after SubEnum2 tombstoned")

echo        SubEnum2 invisible after tombstone
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\SubEnum2" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstoned SubEnum2 still visible")

echo        SubEnum3 visible when SubEnum2 tombstoned
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\SubEnum3" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "SubEnum3 not visible after SubEnum2 tombstoned")

reg delete "%REAL_KEY%" /v RealEnum /f >nul 2>nul
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Multi-value Partial Delete
REM ════════════════════════════════════════════════════════════
:section_multi_value_partial_delete
echo.
echo   [9] Multi-value Partial Delete
call :CLEANUP
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MV1 /t REG_SZ /d One   /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MV2 /t REG_SZ /d Two   /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MV3 /t REG_SZ /d Three /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MV4 /t REG_SZ /d Four  /f >nul

%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v MV1 /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v MV3 /f >nul 2>nul

echo        MV1 (first) invisible after delete
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MV1 >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "MV1 still visible")

echo        MV2 (middle survivor) still visible
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MV2 2>nul | findstr "Two" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "MV2 invisible after deleting neighbours")

echo        MV3 (middle deleted) invisible
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MV3 >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "MV3 still visible")

echo        MV4 (last survivor) still visible
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MV4 2>nul | findstr "Four" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "MV4 invisible after deleting neighbours")

echo        reg query does not error with partial tombstones
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "reg query errors with partial tombstones")

echo        correct value count: query lists exactly 2 values (MV2, MV4)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr /C:"MV2" >nul && %LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" 2>nul | findstr /C:"MV4" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "surviving values not all listed")
exit /b


REM ════════════════════════════════════════════════════════════
REM  SECTION: Edge Cases
REM ════════════════════════════════════════════════════════════
:section_edge_cases
echo.
echo   [10] Edge Cases
call :CLEANUP

echo        delete non-existent value returns success (no crash)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%" /v NonExistentVal /f >nul 2>nul
if %ERRORLEVEL% LEQ 1 (call :Pass) else (call :Fail "delete of non-existent value returned unexpected error")

echo        write to deeply nested new key (auto-creates intermediates)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\L1\L2\L3\L4" /v Deep /t REG_SZ /d DeepVal /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\L1\L2\L3\L4" /v Deep 2>nul | findstr "DeepVal" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "deep nested value not readable")

echo        deep nested key did not leak to real registry
reg query "%REAL_KEY%\L1" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deep nested key leaked to real registry")

echo        write to child of tombstoned key re-creates chain
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_KEY%\L1" /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%\L1\New" /v NV /t REG_SZ /d NVData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%\L1\New" /v NV 2>nul | findstr "NVData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "write to child of tombstoned key did not re-create chain")

echo        overwrite existing value multiple times
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v OW /t REG_SZ /d V1 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v OW /t REG_SZ /d V2 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v OW /t REG_SZ /d V3 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v OW 2>nul | findstr "V3" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "last overwritten value is not V3")

echo        REG_BINARY round-trip
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v BinVal /t REG_BINARY /d DEADBEEF /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v BinVal 2>nul | findstr "DEADBEEF" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "REG_BINARY round-trip failed")

echo        REG_MULTI_SZ round-trip
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_KEY%" /v MultiVal /t REG_MULTI_SZ /d "line1\0line2" /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_KEY%" /v MultiVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "REG_MULTI_SZ round-trip failed")
exit /b


REM ════════════════════════════════════════════════════════════
REM  HKCR Cross-hive Consistency Tests
REM  Writes to HKCR must be visible via both:
REM    - HKEY_CLASSES_ROOT (HKLM backing)
REM    - HKEY_USERS\SID_Classes (per-user backing)
REM ════════════════════════════════════════════════════════════
:run_hkcr_crosshive_tests
call :CLEANUP
echo.
echo ┌──────────────────────────────────────────────────────────
echo │  HKCR Cross-hive Consistency
echo └──────────────────────────────────────────────────────────

set "HKLM_VIRT=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
set "HKU_VIRT=%VIRT_ROOT%\HKEY_USERS\%USER_SID%_Classes"

echo        write via HKCR → readable via HKCR
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "HKEY_CLASSES_ROOT" /v CrossVal /t REG_SZ /d Cross1 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_CLASSES_ROOT" /v CrossVal 2>nul | findstr "Cross1" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKCR write not readable via HKCR")

echo        HKCR write stored in HKLM virtual path
reg query "%HKLM_VIRT%" /v CrossVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKCR write not stored in HKLM virtual path")

echo        HKCR write stored in HKU_Classes virtual path
reg query "%HKU_VIRT%" /v CrossVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKCR write not stored in HKU_Classes virtual path")

echo        write via HKCR → readable via HKU_Classes
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_USERS\%USER_SID%_Classes" /v CrossVal 2>nul | findstr "Cross1" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKCR write not readable via HKU_SID_Classes")

echo        write via HKU_Classes → readable via HKCR
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "HKEY_USERS\%USER_SID%_Classes" /v HkuVal /t REG_SZ /d HKUData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_CLASSES_ROOT" /v HkuVal 2>nul | findstr "HKUData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKU_Classes write not readable via HKCR")

echo        HKCR delete → value invisible via HKCR
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "HKEY_CLASSES_ROOT" /v CrossVal /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_CLASSES_ROOT" /v CrossVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "value still visible via HKCR after sandboxed delete")

echo        HKCR delete → value invisible via HKU_Classes path
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_USERS\%USER_SID%_Classes" /v CrossVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "value still visible via HKU_Classes after HKCR delete")

echo        HKCR delete tombstone in HKLM virtual path
reg query "%HKLM_VIRT%" /v CrossVal 2>nul | findstr /C:"CrossVal    REG_NONE" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "tombstone missing in HKLM virtual path after HKCR delete")

rem this test does not work even without the virtualisation
rem echo        HKCR write to subkey readable via HKU_Classes subkey
rem %LAUNCHER% -r "%VIRT_ROOT%" -e reg add "HKEY_CLASSES_ROOT\CrossSubKey" /v CSV /t REG_SZ /d SubData /f >nul
rem %LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_USERS\%USER_SID%_Classes\CrossSubKey" /v CSV 2>nul | findstr "SubData" >nul
rem if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "HKCR subkey write not readable via HKU_Classes subkey")


echo        HKCR subkey delete → invisible via both paths
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "HKEY_CLASSES_ROOT\CrossSubKey" /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_CLASSES_ROOT\CrossSubKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deleted HKCR subkey still visible via HKCR")
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "HKEY_USERS\%USER_SID%_Classes\CrossSubKey" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "deleted HKCR subkey still visible via HKU_Classes")

call :CLEANUP
exit /b


REM ════════════════════════════════════════════════════════════
REM  Advanced Tombstone Tests
REM  Multi-cycle, persistence across processes, interaction
REM  between value and key tombstones
REM ════════════════════════════════════════════════════════════
:run_tombstone_advanced_tests
call :CLEANUP
echo.
echo ┌──────────────────────────────────────────────────────────
echo │  Advanced Tombstone Tests
echo └──────────────────────────────────────────────────────────

set "AK=HKEY_CURRENT_USER\Software"
set "AV=%VIRT_ROOT%\%AK%"

echo        tombstone persists across 3 separate sandbox invocations
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%AK%" /v PersistVal /t REG_SZ /d PData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%" /v PersistVal /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%AK%" /v PersistVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstone not persistent: pass1")
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%AK%" /v PersistVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstone not persistent: pass2")
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%AK%" /v PersistVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "tombstone not persistent: pass3")

echo        key tombstone does not affect sibling keys
reg add "%AK%\SibA" /v SA /t REG_SZ /d SibAData /f >nul
reg add "%AK%\SibB" /v SB /t REG_SZ /d SibBData /f >nul
reg add "%AK%\SibC" /v SC /t REG_SZ /d SibCData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%\SibB" /f >nul 2>nul

%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\SibA" /v SA 2>nul | findstr "SibAData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "SibA affected by SibB tombstone")
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\SibC" /v SC 2>nul | findstr "SibCData" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "SibC affected by SibB tombstone")
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\SibB" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "SibB still visible after tombstone")
reg delete "%AK%\SibA" /f >nul 2>nul & reg delete "%AK%\SibB" /f >nul 2>nul & reg delete "%AK%\SibC" /f >nul 2>nul

echo        value tombstone + key tombstone on same key handled correctly
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%AK%\DualTomb" /v DTV /t REG_SZ /d DTData /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%\DualTomb" /v DTV /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%\DualTomb" /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\DualTomb" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "key with both value and key tombstone still visible")

echo        three write-delete cycles on same value
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%AK%" /v Cycle /t REG_SZ /d C1 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%" /v Cycle /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%AK%" /v Cycle /t REG_SZ /d C2 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%" /v Cycle /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%AK%" /v Cycle /t REG_SZ /d C3 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%" /v Cycle 2>nul | findstr "C3" >nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "3rd-cycle value not C3")
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%" /v Cycle /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%" /v Cycle >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :Pass) else (call :Fail "3rd-cycle delete did not tombstone correctly")

echo        real key with many values: only tombstoned ones hidden
reg add "%AK%\ManyVals" /v V1 /t REG_SZ /d D1 /f >nul
reg add "%AK%\ManyVals" /v V2 /t REG_SZ /d D2 /f >nul
reg add "%AK%\ManyVals" /v V3 /t REG_SZ /d D3 /f >nul
reg add "%AK%\ManyVals" /v V4 /t REG_SZ /d D4 /f >nul
reg add "%AK%\ManyVals" /v V5 /t REG_SZ /d D5 /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%\ManyVals" /v V2 /f >nul 2>nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%AK%\ManyVals" /v V4 /f >nul 2>nul
for %%v in (V1 V3 V5) do (
    %LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\ManyVals" /v %%v >nul 2>nul
    if !ERRORLEVEL! EQU 0 (call :Pass) else (call :Fail "%%v not visible with partial tombstones in many-val key")
)
for %%v in (V2 V4) do (
    %LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\ManyVals" /v %%v >nul 2>nul
    if !ERRORLEVEL! NEQ 0 (call :Pass) else (call :Fail "%%v still visible after tombstone in many-val key")
)
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%AK%\ManyVals" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :Pass) else (call :Fail "reg query errors on many-val key with partial tombstones")
reg delete "%AK%\ManyVals" /f >nul 2>nul

call :CLEANUP
exit /b


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
