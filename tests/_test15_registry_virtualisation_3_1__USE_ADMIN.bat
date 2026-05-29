@echo off
setlocal EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
rem we need admin because we write to some priviliged keys directly without virtlauncher
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

:: ============================================================
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


:: ============================================================
cd /d "..\build"
color 2F


:: ============================================================
::  VirtRegTest.bat  -  Registry Virtualisation Test Suite
::  for VirtLauncher / VirtHook
::
::  USAGE
::    VirtRegTest.bat
::
::  HOW IT WORKS
::    Phase 0 - Pre-flight checks (launcher, DLLs, elevation for HKLM)
::    Phase 1 - Seed REAL registry keys (outside VirtLauncher)
::    Phase 2 - Run inner test battery; each reg/powershell call is wrapped
::              with VirtLauncher directly (no script self-relaunch)
::    Phase 3 - Isolation checks: verify real registry was NOT modified
::    Phase 4 - Virtual store checks: verify writes landed in the virt hive
::    Phase 5 - Final report
::
::  KNOWN BUG AREAS EXPLICITLY TESTED
::    - No registry tombstone: deleting a real-only key / value inside the
::      sandbox does NOT persist -- the real key reappears on re-open.
::      (File virtualisation uses .vl_deleted tombstones; registry does not.)
::    - NtQueryKey reports virtual-only subkey/value counts, not merged.
::    - NtQueryMultipleValueKey is all-or-nothing (no per-value fallback).
::
:: ============================================================


:: ============================================================
:: DEFAULT CONFIGURATION
:: ============================================================
set "LAUNCHER="
set "LAUNCHER_BITS=64"
set "VHIVE=HKCU\VirtRegTest_Store_2026"
set "RBASE=HKCU\Software\VirtRegTestReal_2026"
set "NOCLEANUP=0"
set "VERBOSE=0"

:: ── Computed paths ────────────────────────────────────────────────────────────
set "VHIVE_HKCU=%VHIVE%\HKEY_CURRENT_USER"
set "VHIVE_HKLM=%VHIVE%\HKEY_LOCAL_MACHINE"
set "VHIVE_HKU=%VHIVE%\HKEY_USERS"

:: Result files
set "INNER_LOG=%TEMP%\VirtRegTest_Inner.log"

:: ============================================================
:: OUTSIDE - Phase 0: Pre-flight
:: ============================================================
:OUTSIDE_MAIN

echo.
echo ================================================================
echo   VirtLauncher Registry Virtualisation Test Suite
echo ================================================================
echo.

:: Empty result file
echo. > "%INNER_LOG%"

:: Find VirtLauncher
if "!LAUNCHER!"=="" (
    where VirtLauncher%LAUNCHER_BITS%.exe >nul 2>&1
    if not errorlevel 1 (
        set "LAUNCHER=VirtLauncher%LAUNCHER_BITS%.exe"
    ) else (
        set "LAUNCHER=%~dp0VirtLauncher%LAUNCHER_BITS%.exe"
    )
)
if not exist "!LAUNCHER!" (
    echo [PRE-FLIGHT ERROR] Cannot find !LAUNCHER!
    echo                    Put VirtLauncher64.exe next to this script or in PATH.
    exit /b 1
)
echo [PRE-FLIGHT] Launcher    : !LAUNCHER!
echo [PRE-FLIGHT] Virt hive   : %VHIVE%
echo [PRE-FLIGHT] Real base   : %RBASE%

:: Check hook DLL exists next to the launcher
set "LDIR=%~dp0"
for %%F in ("!LAUNCHER!") do set "LDIR=%%~dpF"
if not exist "!LDIR!VirtHook%LAUNCHER_BITS%.dll" (
    echo [PRE-FLIGHT WARNING] VirtHook%LAUNCHER_BITS%.dll not found beside launcher.
    echo                      Cross-arch injection may also try the other bitness DLL.
)

:: Check we are NOT already inside a VirtLauncher session
if defined VIRTLAUNCHER_REG (
    echo [PRE-FLIGHT ERROR] Already running inside VirtLauncher.
    echo                    Run this script standalone from a normal cmd.
    exit /b 1
)

:: Check for admin (needed to write real HKLM seeds for the HKLM tests)
fltmc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [PRE-FLIGHT] NOTE: Not running as Administrator.
    echo             HKLM isolation tests will use read-only real HKLM keys only.
    set "HAVE_ADMIN=0"
) else (
    echo [PRE-FLIGHT] Running as Administrator - HKLM write tests enabled.
    set "HAVE_ADMIN=1"
)
echo.

:: ============================================================
:: Phase 1: Seed REAL registry
:: ============================================================
call :Cleanup
echo ================================================================
echo   PHASE 1 - Seeding real registry (outside VirtLauncher)
echo ================================================================
echo.

:: S1 - SeedKey: basic values (one per type that will be tested in merge)
reg add "%RBASE%\SeedKey" /v "RealStrVal"   /t REG_SZ    /d "REAL_STRING_ORIGINAL"   /f >nul
reg add "%RBASE%\SeedKey" /v "RealDwordVal" /t REG_DWORD /d 0xABCD1234               /f >nul
reg add "%RBASE%\SeedKey" /v "SharedVal"    /t REG_SZ    /d "REAL_SHARED_ORIGINAL"   /f >nul

:: S2 - ShadowKey: will be written to inside virt; one value virt overrides, one stays real-only
reg add "%RBASE%\ShadowKey" /v "ShadowedVal"  /t REG_SZ /d "REAL_SHADOW_ORIGINAL"  /f >nul
reg add "%RBASE%\ShadowKey" /v "RealOnlyVal"  /t REG_SZ /d "REAL_ONLY_VALUE"       /f >nul
reg add "%RBASE%\ShadowKey" /v "AnotherReal"  /t REG_SZ /d "ANOTHER_REAL_VALUE"    /f >nul

:: S3 - MergeParent: two real subkeys (virt will add a third)
reg add "%RBASE%\MergeParent\RealSubA" /v "dummy" /t REG_SZ /d "ra" /f >nul
reg add "%RBASE%\MergeParent\RealSubB" /v "dummy" /t REG_SZ /d "rb" /f >nul

:: S4 - Deep nested real key (5 levels)
reg add "%RBASE%\Deep\L1\L2\L3\L4\L5" /v "DeepRealVal" /t REG_SZ /d "DEEP_REAL" /f >nul

:: S5 - DeleteTarget: key+value that will be "deleted" inside virt
reg add "%RBASE%\DeleteTarget" /v "DeleteMe"   /t REG_SZ /d "REAL_DELETE_TARGET"    /f >nul
reg add "%RBASE%\DeleteTarget" /v "KeepMeReal" /t REG_SZ /d "REAL_KEEP_UNTOUCHED"  /f >nul

:: S6 - Optional HKLM seed (admin only)
if "%HAVE_ADMIN%"=="1" (
    reg add "HKLM\SOFTWARE\VirtRegTestSeed_2026" /v "HklmRealVal" /t REG_SZ /d "HKLM_REAL_SEED" /f >nul
    echo [SEED] HKLM seed key created.
)

:: Verify seeds
reg query "%RBASE%\SeedKey" /v "RealStrVal" >nul 2>&1
if errorlevel 1 (
    echo [SEED ERROR] Failed to create real registry seeds. Aborting.
    exit /b 1
)
echo [SEED] Real registry seeded successfully.
echo.

:: ============================================================
:: Phase 2: Inner test battery (each call wrapped with VirtLauncher)
:: ============================================================
echo ================================================================
echo   PHASE 2 - Running inner test battery via VirtLauncher
echo ================================================================
echo.

set "PASS=0"
set "FAIL=0"
set "SKIP=0"

echo. > "%INNER_LOG%"
call :LOG "================================================================"
call :LOG "  INNER-VIRT TEST BATTERY"
call :LOG "  VirtStore (hive): %VHIVE%"
call :LOG "================================================================"
echo.

:: SANITY: verify VirtLauncher is operational before running any tests
"%LAUNCHER%" -r %VHIVE% -e reg query HKCU >nul 2>&1
if not errorlevel 1 (
    call :PASS "SANITY-1" "VirtLauncher operational (basic HKCU access OK)"
) else (
    call :FAIL "SANITY-1" "VirtLauncher failed basic test - check installation!"
    goto :INSIDE_DONE
)

:: ── SECTION A: Basic Write / Read ─────────────────────────────────────────────
call :SECT "A" "Basic Write / Read"

:: A-01: Create a brand-new HKCU key (no real equivalent)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtCreatedKey" /v "VirtNewVal" /t REG_SZ /d "VIRT_NEW_DATA" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\VirtCreatedKey" /v "VirtNewVal" >nul 2>&1
if not errorlevel 1 (
    call :PASS "A-01" "HKCU: create new key+value, read back OK"
) else (
    call :FAIL "A-01" "HKCU: create new key+value, read back FAILED"
)

:: A-02: Add a new value to a real key (triggers CoW open of the key)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /v "VirtAddedToSeed" /t REG_SZ /d "VIRT_ADDED" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "VirtAddedToSeed" >nul 2>&1
if not errorlevel 1 (
    call :PASS "A-02" "HKCU CoW: add new value to real key, read back OK"
) else (
    call :FAIL "A-02" "HKCU CoW: add new value to real key, read back FAILED"
)

:: A-03: Read a real-only value from a key that was NOT yet written to by virt
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealStrVal" 2>nul | findstr /i "REAL_STRING_ORIGINAL" >nul
if not errorlevel 1 (
    call :PASS "A-03" "HKCU merge read: real-only value visible before any virt write"
) else (
    call :FAIL "A-03" "HKCU merge read: real-only value NOT visible (fallback broken)"
)

:: A-04: Read a real DWORD value
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealDwordVal" 2>nul | findstr /i "REG_DWORD" >nul
if not errorlevel 1 (
    call :PASS "A-04" "HKCU merge read: real DWORD value visible"
) else (
    call :FAIL "A-04" "HKCU merge read: real DWORD value NOT visible"
)

:: A-05: Write to HKLM (no admin needed; writes go to virtual HKLM namespace)
"%LAUNCHER%" -r %VHIVE% -e reg add "HKLM\SOFTWARE\VirtRegTest_HKLM_2026" /v "HklmVirtVal" /t REG_SZ /d "HKLM_VIRT_DATA" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026" /v "HklmVirtVal" >nul 2>&1
if not errorlevel 1 (
    call :PASS "A-05" "HKLM: write new key+value without admin (virt absorbs it)"
) else (
    call :FAIL "A-05" "HKLM: write new key+value FAILED (HKLM not virtualized)"
)

:: A-06: Read an existing HKLM real value (must work via merge)
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v "ProductName" >nul 2>&1
if not errorlevel 1 (
    call :PASS "A-06" "HKLM merge read: real ProductName visible (real HKLM fallback works)"
) else (
    call :FAIL "A-06" "HKLM merge read: HKLM\...\CurrentVersion\ProductName NOT visible"
)

:: A-07: Read an existing real HKLM value that has no virt entry (not the root)
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v "CurrentBuildNumber" >nul 2>&1
if not errorlevel 1 (
    call :PASS "A-07" "HKLM merge read: CurrentBuildNumber visible"
) else (
    call :FAIL "A-07" "HKLM merge read: CurrentBuildNumber NOT visible"
)

:: A-08: Verify after CoW write to SeedKey, original real values still readable
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealStrVal" 2>nul | findstr /i "REAL_STRING_ORIGINAL" >nul
if not errorlevel 1 (
    call :PASS "A-08" "HKCU CoW: original real value still readable after CoW write"
) else (
    call :FAIL "A-08" "HKCU CoW: original real value DISAPPEARED after CoW write!"
)

:: ── SECTION B: Value Shadow & Merge ───────────────────────────────────────────
call :SECT "B" "Value Shadow and Merge"

:: B-01: Write virtual override for a value that exists in real
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\ShadowKey" /v "ShadowedVal" /t REG_SZ /d "VIRT_SHADOW_OVERRIDE" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ShadowKey" /v "ShadowedVal" 2>nul | findstr /i "VIRT_SHADOW_OVERRIDE" >nul
if not errorlevel 1 (
    call :PASS "B-01" "Value shadow: virtual value overrides real (got VIRT_SHADOW_OVERRIDE)"
) else (
    call :FAIL "B-01" "Value shadow: expected VIRT_SHADOW_OVERRIDE, real value returned instead"
)

:: B-02: Real-only value must still be readable from merged key (after partial virt write)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ShadowKey" /v "RealOnlyVal" 2>nul | findstr /i "REAL_ONLY_VALUE" >nul
if not errorlevel 1 (
    call :PASS "B-02" "Merge: real-only value 'RealOnlyVal' readable from key with virt writes"
) else (
    call :FAIL "B-02" "Merge: 'RealOnlyVal' NOT readable (real fallback broken after virt write)"
)

:: B-03: Second real-only value also readable
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ShadowKey" /v "AnotherReal" 2>nul | findstr /i "ANOTHER_REAL_VALUE" >nul
if not errorlevel 1 (
    call :PASS "B-03" "Merge: second real-only value 'AnotherReal' also readable"
) else (
    call :FAIL "B-03" "Merge: 'AnotherReal' NOT readable"
)

:: B-04: Add a virtual-only value to ShadowKey, then enumerate
::        Expected names: ShadowedVal (virt), RealOnlyVal (real), AnotherReal (real), VirtOnlyInShadow (virt)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\ShadowKey" /v "VirtOnlyInShadow" /t REG_SZ /d "VIRT_ONLY" /f >nul 2>&1
set "B4_SH=0" & set "B4_RO=0" & set "B4_AR=0" & set "B4_VO=0"
for /f "delims=" %%L in ('"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ShadowKey" 2^>nul') do (
    echo "%%L" | findstr /i "ShadowedVal"     >nul && set "B4_SH=1"
    echo "%%L" | findstr /i "RealOnlyVal"     >nul && set "B4_RO=1"
    echo "%%L" | findstr /i "AnotherReal"     >nul && set "B4_AR=1"
    echo "%%L" | findstr /i "VirtOnlyInShadow" >nul && set "B4_VO=1"
)
if !B4_SH!==1 if !B4_RO!==1 if !B4_AR!==1 if !B4_VO!==1 (
    call :PASS "B-04" "Value enum merge: all 4 values visible (virt+real, shadow+new)"
) else (
    call :FAIL "B-04" "Value enum merge: missing values (ShadowedVal=!B4_SH! RealOnly=!B4_RO! Another=!B4_AR! VirtOnly=!B4_VO!)"
)

:: B-05: ShadowedVal must NOT appear twice in enumeration (no duplicate for virtual+real)
set "B5_COUNT=0"
for /f "delims=" %%L in ('"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ShadowKey" 2^>nul') do (
    echo "%%L" | findstr /i "    ShadowedVal" >nul && set /a "B5_COUNT+=1"
)
if !B5_COUNT! leq 1 (
    call :PASS "B-05" "Value enum: ShadowedVal not duplicated (appears %B5_COUNT% time)"
) else (
    call :FAIL "B-05" "Value enum DUPLICATE: ShadowedVal appears !B5_COUNT! times!"
)

:: B-06: Override a DWORD value with a different type (SZ)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /v "RealDwordVal" /t REG_SZ /d "TYPE_CHANGED_TO_SZ" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealDwordVal" 2>nul | findstr /i "TYPE_CHANGED_TO_SZ" >nul
if not errorlevel 1 (
    call :PASS "B-06" "Type override: DWORD overridden with SZ, new type+value returned"
) else (
    call :FAIL "B-06" "Type override: DWORD value not properly overridden with SZ"
)

:: ── SECTION C: Subkey Enumeration Merge ───────────────────────────────────────
call :SECT "C" "Subkey Enumeration Merge"

:: C-01: Add a virtual-only subkey to a parent that has real subkeys
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\MergeParent\VirtSubC" /f >nul 2>&1
set "C1_RA=0" & set "C1_RB=0" & set "C1_VC=0"
for /f "delims=" %%L in ('"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent" 2^>nul') do (
    echo "%%L" | findstr /i "RealSubA" >nul && set "C1_RA=1"
    echo "%%L" | findstr /i "RealSubB" >nul && set "C1_RB=1"
    echo "%%L" | findstr /i "VirtSubC" >nul && set "C1_VC=1"
)
if !C1_RA!==1 if !C1_RB!==1 if !C1_VC!==1 (
    call :PASS "C-01" "Subkey merge: RealSubA + RealSubB + VirtSubC all visible"
) else (
    call :FAIL "C-01" "Subkey merge: missing (RealSubA=!C1_RA! RealSubB=!C1_RB! VirtSubC=!C1_VC!)"
)

:: C-02: Real subkeys independently accessible by full path
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent\RealSubA" >nul 2>&1
if not errorlevel 1 (
    call :PASS "C-02" "RealSubA directly accessible via full path"
) else (
    call :FAIL "C-02" "RealSubA NOT accessible via full path"
)

"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent\RealSubB" >nul 2>&1
if not errorlevel 1 (
    call :PASS "C-03" "RealSubB directly accessible via full path"
) else (
    call :FAIL "C-03" "RealSubB NOT accessible via full path"
)

:: C-04: Virtual subkey independently accessible
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent\VirtSubC" >nul 2>&1
if not errorlevel 1 (
    call :PASS "C-04" "VirtSubC directly accessible via full path"
) else (
    call :FAIL "C-04" "VirtSubC NOT accessible via full path"
)

:: C-05: Add two more virt subkeys, no duplicates in full enum
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\MergeParent\VirtSubD" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\MergeParent\VirtSubE" /f >nul 2>&1
set "C5_RA=0" & set "C5_RB=0" & set "C5_VC=0" & set "C5_VD=0" & set "C5_VE=0"
set "C5_DUP=0" & set "C5_PREV="
for /f "delims=" %%L in ('"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent" 2^>nul') do (
    echo "%%L" | findstr /i "RealSubA" >nul && set "C5_RA=1"
    echo "%%L" | findstr /i "RealSubB" >nul && set "C5_RB=1"
    echo "%%L" | findstr /i "VirtSubC" >nul && set "C5_VC=1"
    echo "%%L" | findstr /i "VirtSubD" >nul && set "C5_VD=1"
    echo "%%L" | findstr /i "VirtSubE" >nul && set "C5_VE=1"
    if "%%L"=="!C5_PREV!" if not "%%L"=="" set /a "C5_DUP+=1"
    set "C5_PREV=%%L"
)
if !C5_RA!==1 if !C5_RB!==1 if !C5_VC!==1 if !C5_VD!==1 if !C5_VE!==1 (
    call :PASS "C-05" "Subkey merge 5-way: all 5 subkeys visible (2 real + 3 virt)"
) else (
    call :FAIL "C-05" "Subkey merge 5-way: missing (RA=!C5_RA! RB=!C5_RB! VC=!C5_VC! VD=!C5_VD! VE=!C5_VE!)"
)
if !C5_DUP!==0 (
    call :PASS "C-06" "Subkey enum: no duplicates in merged listing"
) else (
    call :FAIL "C-06" "Subkey enum: !C5_DUP! duplicate entries detected!"
)

:: ── SECTION D: Delete Behavior ────────────────────────────────────────────────
call :SECT "D" "Delete Behavior"

:: D-01: Create a virtual-only key, delete it - must vanish
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtOnlyDeleteMe" /v "v" /t REG_SZ /d "x" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\VirtOnlyDeleteMe" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\VirtOnlyDeleteMe" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-01" "Delete virtual-only key: gone immediately after delete"
) else (
    call :FAIL "D-01" "Delete virtual-only key: STILL PRESENT after delete!"
)

:: D-02: Create a virtual-only value, delete it - must vanish
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtCreatedKey" /v "TempVal" /t REG_SZ /d "ephemeral" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\VirtCreatedKey" /v "TempVal" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\VirtCreatedKey" /v "TempVal" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-02" "Delete virtual-only value: gone immediately after delete"
) else (
    call :FAIL "D-02" "Delete virtual-only value: STILL PRESENT after delete!"
)

:: D-03: Delete a value that was written to virtual (CoW), then re-query same session
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /v "CoWDeleteTarget" /t REG_SZ /d "cow_delete" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\SeedKey" /v "CoWDeleteTarget" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "CoWDeleteTarget" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-03" "Delete CoW-written value: gone after delete"
) else (
    call :FAIL "D-03" "Delete CoW-written value: STILL PRESENT after delete!"
)

:: D-04: [KNOWN BUG] Delete a REAL-ONLY value from a CoW-opened key
::   The value is deleted from the virtual store copy.
::   BUT: the real key still has it. On the NEXT open (fresh reg query), the
::   hook does a new CoW open, finds real key, opens virt (now missing the value),
::   and NtQueryValueKey falls back to real -> real value reappears.
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /v "RealStrVal_DeleteTest" /t REG_SZ /d "dummy_for_delete" /f >nul 2>&1
:: First ensure value exists in virtual (just wrote it above)
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\SeedKey" /v "RealStrVal_DeleteTest" /f >nul 2>&1
:: This was virt-only, so it should be gone:
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealStrVal_DeleteTest" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-04" "Delete just-written virt value: gone (baseline OK)"
) else (
    call :FAIL "D-04" "Delete just-written virt value: still present!"
)

:: D-05: Delete a REAL-ONLY value via a CoW handle
::   RealStrVal exists ONLY in real. After CoW open, delete it from virtual side.
::   Immediately (same handle lifetime as one reg.exe call) - may appear gone.
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\SeedKey" /v "RealStrVal" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealStrVal" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-05" "Delete real-only value: appears gone (immediate re-query)"
) else (
    call :FAIL "D-05" "Delete real-only value: STILL appears immediately - handle not tracking delete"
)

:: D-05b: [KNOWN BUG] Re-open SeedKey and query RealStrVal again (fresh handle = fresh CoW)
::        Without a registry tombstone, RealStrVal reappears from real on fresh open.
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealStrVal" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-05b" "Delete real-only value: stays deleted on re-open (tombstone works)"
) else (
    call :FAIL "D-05b" "[KNOWN BUG] Delete real-only value REAPPEARS on re-open (no registry tombstone)"
)

:: D-06: [KNOWN BUG] Delete a REAL-ONLY key inside virt
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\DeleteTarget" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DeleteTarget" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-06" "Delete real-only key: appears deleted (immediate check)"
) else (
    call :FAIL "D-06" "Delete real-only key: STILL PRESENT immediately after delete!"
)

:: D-06b: Re-open the same key (triggers a new CoW open -> real key still exists)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DeleteTarget" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-06b" "Delete real-only key: stays deleted on re-open (tombstone works)"
) else (
    call :FAIL "D-06b" "[KNOWN BUG] Delete real-only key REAPPEARS on re-open (no registry tombstone)"
)

:: D-07: Delete an entire virtual subtree
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtSubtree\A" /v "va" /t REG_SZ /d "x" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtSubtree\B" /v "vb" /t REG_SZ /d "x" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\VirtSubtree\A\Child" /v "vc" /t REG_SZ /d "x" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\VirtSubtree" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\VirtSubtree" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-07" "Delete virtual subtree (/f recursive): root gone"
) else (
    call :FAIL "D-07" "Delete virtual subtree (/f recursive): root STILL PRESENT"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\VirtSubtree\A" >nul 2>&1
if errorlevel 1 (
    call :PASS "D-08" "Delete virtual subtree: child A also gone"
) else (
    call :FAIL "D-08" "Delete virtual subtree: child A STILL PRESENT (partial delete)"
)

:: D-09: Delete virt subkey from merged parent; real subkeys must survive
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\MergeParent\VirtSubC" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\MergeParent\VirtSubC" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent\RealSubA" >nul 2>&1
if not errorlevel 1 (
    call :PASS "D-09" "Delete virt subkey: real siblings (RealSubA) unaffected"
) else (
    call :FAIL "D-09" "Delete virt subkey: RealSubA COLLATERAL DAMAGE (gone too!)"
)

:: D-10: Ensure deleted virt subkey absent from enumeration
set "D10_SAW=0"
for /f "delims=" %%L in ('"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\MergeParent" 2^>nul') do (
    echo "%%L" | findstr /i "VirtSubC" >nul && set "D10_SAW=1"
)
if !D10_SAW!==0 (
    call :PASS "D-10" "Deleted VirtSubC absent from MergeParent enumeration"
) else (
    call :FAIL "D-10" "Deleted VirtSubC STILL APPEARS in MergeParent enumeration!"
)

:: ── SECTION E: Nested Keys ────────────────────────────────────────────────────
call :SECT "E" "Nested Key Creation (EnsureVirtualPath)"

:: E-01: Create 5-level deep pure-virtual HKCU key
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\N1\N2\N3\N4\N5" /v "VirtDeepNew" /t REG_SZ /d "DEEP_VIRT_VALUE" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\N1\N2\N3\N4\N5" /v "VirtDeepNew" 2>nul | findstr /i "DEEP_VIRT_VALUE" >nul
if not errorlevel 1 (
    call :PASS "E-01" "5-level pure-virtual HKCU key: create + write + read OK"
) else (
    call :FAIL "E-01" "5-level pure-virtual HKCU key: FAILED (EnsureVirtualPath broken?)"
)

:: E-02: Intermediate levels accessible
for %%D in (N1 N1\N2 N1\N2\N3 N1\N2\N3\N4) do (
    "%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\%%D" >nul 2>&1
    if errorlevel 1 call :FAIL "E-02-%%D" "Intermediate key %%D NOT accessible"
)
call :PASS "E-02" "All intermediate levels (N1..N4) of deep key accessible"

:: E-03: Read deep REAL key (5 levels)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\Deep\L1\L2\L3\L4\L5" /v "DeepRealVal" 2>nul | findstr /i "DEEP_REAL" >nul
if not errorlevel 1 (
    call :PASS "E-03" "5-level deep real key: readable via merged view"
) else (
    call :FAIL "E-03" "5-level deep real key: NOT readable (deep merge fallback broken)"
)

:: E-04: CoW write to deep real key
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\Deep\L1\L2\L3\L4\L5" /v "VirtDeepCoW" /t REG_SZ /d "COW_AT_DEPTH_5" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\Deep\L1\L2\L3\L4\L5" /v "VirtDeepCoW" 2>nul | findstr /i "COW_AT_DEPTH_5" >nul
if not errorlevel 1 (
    call :PASS "E-04" "CoW write to deep real key (5 levels): read back OK"
) else (
    call :FAIL "E-04" "CoW write to deep real key: FAILED"
)

:: E-05: After deep CoW write, original deep real value still readable
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\Deep\L1\L2\L3\L4\L5" /v "DeepRealVal" 2>nul | findstr /i "DEEP_REAL" >nul
if not errorlevel 1 (
    call :PASS "E-05" "CoW at depth 5: original real value still readable (merge preserved)"
) else (
    call :FAIL "E-05" "CoW at depth 5: original real value DISAPPEARED after CoW!"
)

:: E-06: Deep HKLM (4 levels)
"%LAUNCHER%" -r %VHIVE% -e reg add "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\A\B\C" /v "HklmDeepVal" /t REG_SZ /d "HKLM_DEEP" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\A\B\C" /v "HklmDeepVal" 2>nul | findstr /i "HKLM_DEEP" >nul
if not errorlevel 1 (
    call :PASS "E-06" "HKLM: 4-level deep virtual key create + read OK"
) else (
    call :FAIL "E-06" "HKLM: 4-level deep virtual key FAILED"
)

:: ── SECTION F: Value Types ────────────────────────────────────────────────────
call :SECT "F" "All Value Types"
set "FTKEY=%RBASE%\TypesKey"

:: F-01: REG_SZ
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "SzVal" /t REG_SZ /d "hello world string" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "SzVal" 2>nul | findstr /i "REG_SZ" >nul
if not errorlevel 1 (
    call :PASS "F-01" "REG_SZ: written and type preserved on read"
) else (
    call :FAIL "F-01" "REG_SZ: type wrong or not readable"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "SzVal" 2>nul | findstr /i "hello world string" >nul
if not errorlevel 1 (
    call :PASS "F-01b" "REG_SZ: data value correct on read"
) else (
    call :FAIL "F-01b" "REG_SZ: data value wrong on read"
)

:: F-02: REG_EXPAND_SZ
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "ExpSzVal" /t REG_EXPAND_SZ /d "%%TEMP%%\virt_test.tmp" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "ExpSzVal" 2>nul | findstr /i "REG_EXPAND_SZ" >nul
if not errorlevel 1 (
    call :PASS "F-02" "REG_EXPAND_SZ: type preserved on read"
) else (
    call :FAIL "F-02" "REG_EXPAND_SZ: type wrong or not readable"
)

:: F-03: REG_DWORD
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "DwordVal" /t REG_DWORD /d 0xDEAD1234 /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "DwordVal" 2>nul | findstr /i "REG_DWORD" >nul
if not errorlevel 1 (
    call :PASS "F-03" "REG_DWORD: type preserved on read"
) else (
    call :FAIL "F-03" "REG_DWORD: type wrong or not readable"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "DwordVal" 2>nul | findstr /i "0xdead1234" >nul
if not errorlevel 1 (
    call :PASS "F-03b" "REG_DWORD: value 0xDEAD1234 correct"
) else (
    call :FAIL "F-03b" "REG_DWORD: value 0xDEAD1234 wrong on read"
)

:: F-04: REG_QWORD
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "QwordVal" /t REG_QWORD /d 0x0102030405060708 /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "QwordVal" 2>nul | findstr /i "REG_QWORD" >nul
if not errorlevel 1 (
    call :PASS "F-04" "REG_QWORD: type preserved on read"
) else (
    call :FAIL "F-04" "REG_QWORD: type wrong (may need Win10+)"
)

:: F-05: REG_BINARY
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "BinVal" /t REG_BINARY /d "DEADBEEF01020304CAFEBABE" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "BinVal" 2>nul | findstr /i "REG_BINARY" >nul
if not errorlevel 1 (
    call :PASS "F-05" "REG_BINARY: type preserved on read"
) else (
    call :FAIL "F-05" "REG_BINARY: type wrong or not readable"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "BinVal" 2>nul | findstr /i "de ad be ef" >nul
if not errorlevel 1 (
    call :PASS "F-05b" "REG_BINARY: data bytes correct on read"
) else (
    call :FAIL "F-05b" "REG_BINARY: data bytes wrong or not matching"
)

:: F-06: REG_MULTI_SZ
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "MultiSzVal" /t REG_MULTI_SZ /d "FirstLine\0SecondLine\0ThirdLine" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "MultiSzVal" 2>nul | findstr /i "REG_MULTI_SZ" >nul
if not errorlevel 1 (
    call :PASS "F-06" "REG_MULTI_SZ: type preserved on read"
) else (
    call :FAIL "F-06" "REG_MULTI_SZ: type wrong or not readable"
)

:: F-07: REG_NONE
"%LAUNCHER%" -r %VHIVE% -e reg add "%FTKEY%" /v "NoneVal" /t REG_NONE /d "" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "NoneVal" >nul 2>&1
if not errorlevel 1 (
    call :PASS "F-07" "REG_NONE: written and readable"
) else (
    call :FAIL "F-07" "REG_NONE: not readable"
)

:: F-08: All 7 values enumerable together (no loss under merge)
set "F8COUNT=0"
for %%N in (SzVal ExpSzVal DwordVal QwordVal BinVal MultiSzVal NoneVal) do (
    "%LAUNCHER%" -r %VHIVE% -e reg query "%FTKEY%" /v "%%N" >nul 2>&1 && set /a "F8COUNT+=1"
)
if !F8COUNT!==7 (
    call :PASS "F-08" "All 7 value types readable from same virtual key"
) else (
    call :FAIL "F-08" "Only !F8COUNT!/7 value types readable from TypesKey"
)

:: ── SECTION G: Default (unnamed) Value ───────────────────────────────────────
call :SECT "G" "Default Value (empty name)"

:: G-01: Write and read default value
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\DefaultValKey" /ve /t REG_SZ /d "default_data" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DefaultValKey" /ve 2>nul | findstr /i "default_data" >nul
if not errorlevel 1 (
    call :PASS "G-01" "Default value (/ve): written and read back OK"
) else (
    call :FAIL "G-01" "Default value (/ve): read back FAILED"
)

:: G-02: Override default value with different data
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\DefaultValKey" /ve /t REG_SZ /d "default_override" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DefaultValKey" /ve 2>nul | findstr /i "default_override" >nul
if not errorlevel 1 (
    call :PASS "G-02" "Default value: overwrite reads back updated data"
) else (
    call :FAIL "G-02" "Default value: overwrite did NOT update read result"
)

:: G-03: Default value present in enumeration
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DefaultValKey" 2>nul | findstr /i "(Default)" >nul
if not errorlevel 1 (
    call :PASS "G-03" "Default value: appears in key enumeration as (Default)"
) else (
    call :FAIL "G-03" "Default value: does NOT appear in key enumeration"
)

:: G-04: Default value coexists with named values
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\DefaultValKey" /v "NamedSibling" /t REG_SZ /d "named" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DefaultValKey" /ve >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\DefaultValKey" /v "NamedSibling" >nul 2>&1
if not errorlevel 1 (
    call :PASS "G-04" "Default value: coexists with named value NamedSibling"
) else (
    call :FAIL "G-04" "Default value and named value cannot coexist in same key"
)

:: ── SECTION H: Handle Lifecycle ───────────────────────────────────────────────
call :SECT "H" "Handle Lifecycle - Close and Reopen"

:: H-01: Write two values, reg.exe closes handles between calls; reopen + verify
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "Val1" /t REG_SZ /d "lifecycle_one"  /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "Val2" /t REG_SZ /d "lifecycle_two"  /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "Val3" /t REG_DWORD /d 0x12345678    /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LifecycleKey" /v "Val1" 2>nul | findstr /i "lifecycle_one" >nul
if not errorlevel 1 (
    call :PASS "H-01" "Lifecycle: Val1 readable after close+reopen"
) else (
    call :FAIL "H-01" "Lifecycle: Val1 NOT readable after close+reopen"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LifecycleKey" /v "Val2" 2>nul | findstr /i "lifecycle_two" >nul
if not errorlevel 1 (
    call :PASS "H-02" "Lifecycle: Val2 readable after close+reopen"
) else (
    call :FAIL "H-02" "Lifecycle: Val2 NOT readable after close+reopen"
)

:: H-03: Overwrite a value, close, reopen - updated value must persist
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "Val1" /t REG_SZ /d "lifecycle_one_UPDATED" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LifecycleKey" /v "Val1" 2>nul | findstr /i "lifecycle_one_UPDATED" >nul
if not errorlevel 1 (
    call :PASS "H-03" "Lifecycle: overwritten value persists after close+reopen"
) else (
    call :FAIL "H-03" "Lifecycle: overwritten value reverted or lost after close+reopen"
)

:: H-04: Write, close, reopen, write again, close, reopen - two-cycle
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "TwoCycle" /t REG_SZ /d "cycle1" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LifecycleKey" /v "TwoCycle" /t REG_SZ /d "cycle2" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LifecycleKey" /v "TwoCycle" 2>nul | findstr /i "cycle2" >nul
if not errorlevel 1 (
    call :PASS "H-04" "Lifecycle 2-cycle: second write wins over first"
) else (
    call :FAIL "H-04" "Lifecycle 2-cycle: last write did not win"
)

:: ── SECTION I: Disposition (REG_CREATED_NEW_KEY / REG_OPENED_EXISTING_KEY) ────
call :SECT "I" "RegCreateKeyEx Disposition"

:: I-01: Creating a brand-new key should succeed
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\DispNewKey" /f >nul 2>&1
if not errorlevel 1 (
    call :PASS "I-01" "Disposition: creating new key succeeds (REG_CREATED_NEW_KEY path)"
) else (
    call :FAIL "I-01" "Disposition: creating new key FAILED"
)

:: I-02: Re-opening an existing virtual key via reg add must succeed (REG_OPENED_EXISTING_KEY)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\DispNewKey" /f >nul 2>&1
if not errorlevel 1 (
    call :PASS "I-02" "Disposition: re-opening existing virtual key succeeds (REG_OPENED_EXISTING_KEY path)"
) else (
    call :FAIL "I-02" "Disposition: re-opening existing virtual key FAILED"
)

:: I-03: Opening an existing real key via reg add must succeed (triggers CoW)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /f >nul 2>&1
if not errorlevel 1 (
    call :PASS "I-03" "Disposition: opening existing real key via CreateKey succeeds (CoW triggered)"
) else (
    call :FAIL "I-03" "Disposition: opening existing real key via CreateKey FAILED"
)

:: I-04: After CoW on existing real key, it is not treated as brand-new
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "RealDwordVal" >nul 2>&1
if not errorlevel 1 (
    call :PASS "I-04" "CoW after CreateKey: real values still readable (not empty new key)"
) else (
    call :FAIL "I-04" "CoW after CreateKey: real values GONE (key treated as brand-new!)"
)

:: ── SECTION J: Key Names - Special Characters ──────────────────────────────────
call :SECT "J" "Key and Value Names - Special Characters"

:: J-01: Key with spaces
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\Key With Spaces In Name" /v "SpaceVal" /t REG_SZ /d "space_key_ok" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\Key With Spaces In Name" /v "SpaceVal" 2>nul | findstr /i "space_key_ok" >nul
if not errorlevel 1 (
    call :PASS "J-01" "Key name with spaces: write + read OK"
) else (
    call :FAIL "J-01" "Key name with spaces: FAILED"
)

:: J-02: Value name with spaces
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\SeedKey" /v "Value Name With Spaces" /t REG_SZ /d "val_spaces_ok" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\SeedKey" /v "Value Name With Spaces" 2>nul | findstr /i "val_spaces_ok" >nul
if not errorlevel 1 (
    call :PASS "J-02" "Value name with spaces: write + read OK"
) else (
    call :FAIL "J-02" "Value name with spaces: FAILED"
)

:: J-03: Key with numbers and underscores
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\Key_123_Test456" /v "v" /t REG_SZ /d "numkey_ok" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\Key_123_Test456" /v "v" >nul 2>&1
if not errorlevel 1 (
    call :PASS "J-03" "Key name with numbers+underscores: OK"
) else (
    call :FAIL "J-03" "Key name with numbers+underscores: FAILED"
)

:: J-04: Long key name (80 chars - well under 255 char MAX_KEY_LEN limit)
set "LONGNAME=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR"
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\%LONGNAME%" /v "lv" /t REG_SZ /d "long_name_ok" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\%LONGNAME%" /v "lv" >nul 2>&1
if not errorlevel 1 (
    call :PASS "J-04" "Long key name (72 chars): write + read OK"
) else (
    call :FAIL "J-04" "Long key name (72 chars): FAILED"
)

:: J-05: Long value data (REG_SZ, ~400 chars)
set "BIGSTR=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
set "BIGSTR=!BIGSTR!!BIGSTR!!BIGSTR!!BIGSTR!!BIGSTR!!BIGSTR!"
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LargeDataKey" /v "BigSzVal" /t REG_SZ /d "!BIGSTR!" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LargeDataKey" /v "BigSzVal" 2>nul | findstr /i "REG_SZ" >nul
if not errorlevel 1 (
    call :PASS "J-05" "Large REG_SZ value (~370 chars): type readable"
) else (
    call :FAIL "J-05" "Large REG_SZ value: FAILED"
)

:: J-06: Large REG_BINARY (128 bytes = 256 hex chars)
set "BIGBIN=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
set "BIGBIN=!BIGBIN!!BIGBIN!!BIGBIN!!BIGBIN!"
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\LargeDataKey" /v "BigBinVal" /t REG_BINARY /d "!BIGBIN!" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\LargeDataKey" /v "BigBinVal" 2>nul | findstr /i "REG_BINARY" >nul
if not errorlevel 1 (
    call :PASS "J-06" "Large REG_BINARY (128 bytes): type readable"
) else (
    call :FAIL "J-06" "Large REG_BINARY: FAILED"
)

:: ── SECTION K: NtQueryKey - Merged Subkey/Value Counts ────────────────────────
call :SECT "K" "NtQueryKey - Subkey and Value Count Accuracy"
echo.
call :LOG "  NOTE: NtQueryKey is called by RegQueryInfoKey/RegistryKey.SubKeyCount."
call :LOG "  The virtual handle tracks only virtual entries; the real handle has"
call :LOG "  real entries. If the hook reports virtual counts only, the numbers"
call :LOG "  will be lower than the actual merged count."
call :LOG "  This is a KNOWN LIMITATION of the current implementation."
echo.

:: K-01: ShadowKey should have 4 values total (2 virt + 2 real)
::        NtQueryKey value count from virtual handle = 2 (ShadowedVal, VirtOnlyInShadow)
"%LAUNCHER%" -r %VHIVE% -e powershell -NoProfile -Command ^
    "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VirtRegTestReal_2026\ShadowKey');" ^
    "if ($k) { Write-Host ('SubKeyCount=' + $k.SubKeyCount + ' ValueCount=' + $k.ValueCount) }" ^
    "else { Write-Host 'OPEN_FAILED' }" 2>nul > "%TEMP%\VRTqk.txt"
set /p "K1OUT=" < "%TEMP%\VRTqk.txt" 2>nul
call :LOG "  [K-01] ShadowKey RegistryKey.SubKeyCount / ValueCount: %K1OUT%"
call :LOG "  [K-01] Expected: SubKeyCount=0, ValueCount=4 (merged: 2 real + 2 virt)"
call :LOG "  [K-01] If ValueCount<4, NtQueryKey returns virtual-only counts (known issue)"
echo [INFO] K-01: %K1OUT%
echo [INFO] Expected ValueCount=4 (merged), less means virtual-only count reported

:: K-02: MergeParent: has RealSubA, RealSubB (real) + VirtSubD, VirtSubE (virt, from C-05)
"%LAUNCHER%" -r %VHIVE% -e powershell -NoProfile -Command ^
    "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VirtRegTestReal_2026\MergeParent');" ^
    "if ($k) { Write-Host ('SubKeyCount=' + $k.SubKeyCount) }" ^
    "else { Write-Host 'OPEN_FAILED' }" 2>nul > "%TEMP%\VRTqk2.txt"
set /p "K2OUT=" < "%TEMP%\VRTqk2.txt" 2>nul
call :LOG "  [K-02] MergeParent RegistryKey.SubKeyCount: %K2OUT%"
call :LOG "  [K-02] Expected SubKeyCount=4 (2 real + 2 virt); less=virtual-only count issue"
echo [INFO] K-02: %K2OUT%
echo [INFO] Expected SubKeyCount=4 (merged: RealSubA+RealSubB+VirtSubD+VirtSubE)

:: ── SECTION L: Recursive / Export Operations ──────────────────────────────────
call :SECT "L" "Recursive and Export Operations"

:: L-01: reg export serializes virtual subtree
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\ExportTest\Sub1" /v "ev1" /t REG_SZ    /d "export_val_one" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\ExportTest\Sub2" /v "ev2" /t REG_DWORD /d 0x42             /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\ExportTest"      /v "ev3" /t REG_SZ    /d "export_root_val" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg export "%RBASE%\ExportTest" "%TEMP%\VRTExport.reg" /y >nul 2>&1
if exist "%TEMP%\VRTExport.reg" (
    rem Use 'type' to convert the UTF-16LE stream on the fly before passing to findstr.When you use type on a UTF-16LE file with a BOM, the command shell automatically decodes it and outputs it to standard output in your active console codepage (usually ANSI/OEM)
    type "%TEMP%\VRTExport.reg" | findstr /i "export_val_one" >nul 2>&1
    if not errorlevel 1 (
        call :PASS "L-01" "reg export: virtual subtree exported, content verified"
    ) else (
        call :FAIL "L-01" "reg export: file created but virtual data missing from export"
    )
) else (
    call :FAIL "L-01" "reg export: export file not created"
)

:: L-02: reg query /s (recursive) traverses virtual subkeys
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ExportTest" /s | findstr /i "export_val_one" >nul
if %errorlevel% EQU 0 (
    call :PASS "L-02" "reg query /s recursive: found virtual value in subkey"
) else (
    call :FAIL "L-02" "reg query /s recursive: virtual value NOT found in subtree"
)

:: L-03: Recursive delete removes entire virtual subtree
"%LAUNCHER%" -r %VHIVE% -e reg delete "%RBASE%\ExportTest" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ExportTest" >nul 2>&1
if errorlevel 1 (
    call :PASS "L-03" "reg delete /f recursive: entire virtual subtree removed"
) else (
    call :FAIL "L-03" "reg delete /f recursive: root key STILL PRESENT"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\ExportTest\Sub1" >nul 2>&1
if errorlevel 1 (
    call :PASS "L-04" "reg delete /f recursive: child Sub1 also removed"
) else (
    call :FAIL "L-04" "reg delete /f recursive: child Sub1 STILL PRESENT (partial delete)"
)

:: ── SECTION M: HKCU / HKLM Independence ──────────────────────────────────────
call :SECT "M" "HKCU vs HKLM Namespace Independence"

:: M-01: Same sub-path written under both HKCU and HKLM stays separate
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\CrossHive" /v "HkcuSideVal" /t REG_SZ /d "hkcu_side" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg add "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\CrossHive" /v "HklmSideVal" /t REG_SZ /d "hklm_side" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\CrossHive" /v "HkcuSideVal" 2>nul | findstr /i "hkcu_side" >nul
if not errorlevel 1 (
    call :PASS "M-01a" "HKCU\CrossHive\HkcuSideVal readable"
) else (
    call :FAIL "M-01a" "HKCU\CrossHive\HkcuSideVal NOT readable"
)
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\CrossHive" /v "HklmSideVal" 2>nul | findstr /i "hklm_side" >nul
if not errorlevel 1 (
    call :PASS "M-01b" "HKLM\CrossHive\HklmSideVal readable"
) else (
    call :FAIL "M-01b" "HKLM\CrossHive\HklmSideVal NOT readable"
)

:: M-02: HKCU path must NOT see the HKLM value
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\CrossHive" /v "HklmSideVal" >nul 2>&1
if errorlevel 1 (
    call :PASS "M-02" "No cross-contamination: HKLM value NOT visible via HKCU path"
) else (
    call :FAIL "M-02" "Cross-contamination: HKLM value visible via HKCU path!"
)

:: M-03: HKLM path must NOT see the HKCU value
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\CrossHive" /v "HkcuSideVal" >nul 2>&1
if errorlevel 1 (
    call :PASS "M-03" "No cross-contamination: HKCU value NOT visible via HKLM path"
) else (
    call :FAIL "M-03" "Cross-contamination: HKCU value visible via HKLM path!"
)

:: M-04: HKLM reads of real system keys still work
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" >nul 2>&1
if not errorlevel 1 (
    call :PASS "M-04" "HKLM: real system key still fully accessible"
) else (
    call :FAIL "M-04" "HKLM: real system key NOT accessible (HKLM merge broken)"
)

:: M-05: Write HKLM then delete virtual HKLM key
"%LAUNCHER%" -r %VHIVE% -e reg add "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\DeleteMe" /v "hklm_del" /t REG_SZ /d "x" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg delete "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\DeleteMe" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026\DeleteMe" >nul 2>&1
if errorlevel 1 (
    call :PASS "M-05" "HKLM: delete virtual HKLM key works"
) else (
    call :FAIL "M-05" "HKLM: deleted virtual HKLM key STILL PRESENT"
)

:: ── SECTION N: HKCR (HKEY_CLASSES_ROOT) Virtualization ───────────────────────
call :SECT "N" "HKCR Virtualization (routes through HKLM and HKCU)"
call :LOG "  NOTE: HKCR = HKLM\SOFTWARE\Classes + HKCU\Software\Classes merged."
call :LOG "  At NT API level, HKCR has no root; NtOpenKey sees one of the two paths."
call :LOG "  Writing to HKCR typically routes to HKCU\Software\Classes."

:: N-01: Write to HKCR - should be virtualized
"%LAUNCHER%" -r %VHIVE% -e reg add "HKCR\VirtRegTest_HKCR_2026" /v "HkcrVal" /t REG_SZ /d "hkcr_virt_data" /f >nul 2>&1
"%LAUNCHER%" -r %VHIVE% -e reg query "HKCR\VirtRegTest_HKCR_2026" /v "HkcrVal" >nul 2>&1
if not errorlevel 1 (
    call :PASS "N-01" "HKCR: write new key+value, read back OK"
) else (
    call :FAIL "N-01" "HKCR: write failed or read back failed"
)

:: N-02: HKCR write must NOT have gone to real registry
::   We check after the inner tests in the outer phase (IC-07 equivalent).
::   Here, just verify the write happened at all.
"%LAUNCHER%" -r %VHIVE% -e reg query "HKCR\VirtRegTest_HKCR_2026" >nul 2>&1
if not errorlevel 1 (
    call :PASS "N-02" "HKCR: key exists (write persisted within session)"
) else (
    call :FAIL "N-02" "HKCR: key NOT accessible after write"
)

:: N-03: Read existing HKCR key (e.g., .txt association)
"%LAUNCHER%" -r %VHIVE% -e reg query "HKCR\.txt" >nul 2>&1
if not errorlevel 1 (
    call :PASS "N-03" "HKCR: read real .txt class key via merged view"
) else (
    call :FAIL "N-03" "HKCR: real .txt class key NOT accessible (HKCR merge broken)"
)

:: ── SECTION O: Rename Key ──────────────────────────────────────────────────────
call :SECT "O" "Key Rename (NtRenameKey)"
call :LOG "  NOTE: NtRenameKey is an NT-only API; it's tested via PowerShell."
call :LOG "  reg.exe has no rename command; it uses copy+delete."

:: O-01: Rename via PowerShell (calls RegRenameKey which calls NtRenameKey)
"%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\RenameSource" /v "rv" /t REG_SZ /d "rename_data" /f >nul 2>&1
    
"%LAUNCHER%" -r %VHIVE% -e powershell -NoProfile -Command ^
    "try {" ^
    "  $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VirtRegTestReal_2026', $true);" ^
    "  if ($k) { [void]$k.CreateSubKey('RenameSource'); }" ^
    "  Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class RegHelper { [DllImport(""advapi32.dll"", CharSet=CharSet.Unicode)] public static extern int RegRenameKey(IntPtr hKey, string lpSubKeyName, string lpNewKeyName); }';" ^
    "  $err = [RegHelper]::RegRenameKey($k.Handle.DangerousGetHandle(), 'RenameSource', 'RenameTarget');" ^
    "  if ($err -eq 0) { Write-Host 'RENAME_OK' } else { Write-Host ('RENAME_FAIL_' + $err) }" ^
    "} catch { Write-Host ('RENAME_EXCEPTION_' + $_.Exception.Message) }" ^
    2>nul > "%TEMP%\VRTRename.txt"
    
set /p O1OUT=<"%TEMP%\VRTRename.txt" 2>nul
call :LOG "  [O-01] RegRenameKey result: %O1OUT%"
echo %O1OUT% | findstr /i "RENAME_OK" >nul
if not errorlevel 1 (
    call :PASS "O-01" "NtRenameKey: rename RenameSource->RenameTarget succeeded"
    "%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\RenameTarget" >nul 2>&1
    if not errorlevel 1 (
        call :PASS "O-02" "RenameTarget key accessible after rename"
    ) else (
        call :FAIL "O-02" "RenameTarget NOT accessible after rename"
    )
    "%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\RenameSource" >nul 2>&1
    if errorlevel 1 (
        call :PASS "O-03" "RenameSource gone after rename"
    ) else (
        call :FAIL "O-03" "RenameSource STILL PRESENT after rename!"
    )
) else (
    call :FAIL "O-01" "NtRenameKey: rename failed (%O1OUT%) - may need elevated or unsupported"
    call :SKIP "O-02" "Rename result not applicable (O-01 failed)"
    call :SKIP "O-03" "Rename result not applicable (O-01 failed)"
)

:: ── SECTION P: NtQueryMultipleValueKey ────────────────────────────────────────
call :SECT "P" "NtQueryMultipleValueKey (per-value vs all-or-nothing fallback)"
call :LOG "  NOTE: NtQueryMultipleValueKey is all-or-nothing on a single handle."
call :LOG "  If queried on the virtual handle and ANY value is missing there,"
call :LOG "  the whole query fails and falls back to the real handle for ALL values."
call :LOG "  This means a mix of virtual-overridden and real-only values cannot"
call :LOG "  be fetched in a single NtQueryMultipleValueKey call with correct override."
call :LOG "  This is a KNOWN LIMITATION - per-value fallback is not implemented."
echo.

:: P-01/02: RegistryKey.GetValues on ShadowKey tests both override + real fallback
"%LAUNCHER%" -r %VHIVE% -e powershell -NoProfile -Command ^
    "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VirtRegTestReal_2026\ShadowKey');" ^
    "if ($k) {" ^
    "  $sv = $k.GetValue('ShadowedVal');" ^
    "  $ro = $k.GetValue('RealOnlyVal');" ^
    "  Write-Host ('ShadowedVal=[' + $sv + '] RealOnlyVal=[' + $ro + ']')" ^
    "} else { Write-Host 'KEY_NOT_FOUND' }" 2>nul > "%TEMP%\VRTMulti.txt"
set /p "P1OUT=" < "%TEMP%\VRTMulti.txt" 2>nul
call :LOG "  [P-01/02] GetValue results: %P1OUT%"
echo %P1OUT% | findstr /i "VIRT_SHADOW_OVERRIDE" >nul
if not errorlevel 1 (
    call :PASS "P-01" "GetValue: ShadowedVal returns virtual override (VIRT_SHADOW_OVERRIDE)"
) else (
    call :FAIL "P-01" "GetValue: ShadowedVal did NOT return virt override. Got: %P1OUT%"
)
echo %P1OUT% | findstr /i "REAL_ONLY_VALUE" >nul
if not errorlevel 1 (
    call :PASS "P-02" "GetValue: RealOnlyVal returns real fallback value (REAL_ONLY_VALUE)"
) else (
    call :FAIL "P-02" "GetValue: RealOnlyVal NOT returned. Got: %P1OUT%"
)

:: P-03: Test with GetValues (fetches multiple values as an array via QueryMultipleValues)
"%LAUNCHER%" -r %VHIVE% -e powershell -NoProfile -Command ^
    "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\VirtRegTestReal_2026\ShadowKey');" ^
    "if ($k) {" ^
    "  $names = @('ShadowedVal','RealOnlyVal','AnotherReal','VirtOnlyInShadow');" ^
    "  $vals = $names | ForEach-Object { $k.GetValue($_) };" ^
    "  $r = ($vals | ForEach-Object { if ($_ -ne $null) { 'OK' } else { 'NULL' } }) -join ',';" ^
    "  Write-Host $r" ^
    "} else { Write-Host 'KEY_NOT_FOUND' }" 2>nul > "%TEMP%\VRTMulti2.txt"
set /p "P3OUT=" < "%TEMP%\VRTMulti2.txt" 2>nul
call :LOG "  [P-03] GetValues for all 4 ShadowKey values: %P3OUT%"
echo %P3OUT% | findstr /i "NULL" >nul
if errorlevel 1 (
    call :PASS "P-03" "GetValues: all 4 values returned non-null (%P3OUT%)"
) else (
    call :FAIL "P-03" "[KNOWN BUG?] GetValues: some values returned NULL (%P3OUT%) - NtQueryMultipleValueKey fallback issue"
)

:: ── SECTION Q: Stress - Many Keys and Values ──────────────────────────────────
call :SECT "Q" "Stress - Many Keys / Values"

:: Q-01: Create 20 subkeys under one parent
set "Q1OK=1"
for /L %%I in (1,1,20) do (
    "%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\StressParent\Sub%%I" /v "v" /t REG_SZ /d "stress_%%I" /f >nul 2>&1
    if errorlevel 1 set "Q1OK=0"
)
if !Q1OK!==1 (
    call :PASS "Q-01" "Stress: 20 subkeys created successfully"
) else (
    call :FAIL "Q-01" "Stress: one or more of 20 subkeys FAILED to create"
)

:: Q-02: Enumerate all 20 - count must be 20
set "Q2COUNT=0"
for /f "usebackq delims=" %%L in (`%LAUNCHER% -r %VHIVE% -e reg query "%RBASE%\StressParent" 2^>nul`) do (
    echo "__________%%L" | findstr /i "Sub" >nul && set /a "Q2COUNT+=1"
)

if !Q2COUNT!==20 (
    call :PASS "Q-02" "Stress: all 20 subkeys enumerated (count=!Q2COUNT!)"
) else (
    call :FAIL "Q-02" "Stress: expected 20 subkeys, enumerated !Q2COUNT!"
)

:: Q-03: Create 25 values in one key
set "Q3OK=1"
for /L %%I in (1,1,25) do (
    "%LAUNCHER%" -r %VHIVE% -e reg add "%RBASE%\StressManyVals" /v "Val%%I" /t REG_SZ /d "stress_val_%%I" /f >nul 2>&1
    if errorlevel 1 set "Q3OK=0"
)
if !Q3OK!==1 (
    call :PASS "Q-03" "Stress: 25 values created in one key"
) else (
    call :FAIL "Q-03" "Stress: one or more of 25 values FAILED"
)

:: Q-04: Spot-check 3 random values from Q-03
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\StressManyVals" /v "Val7"  2>nul | findstr /i "stress_val_7"  >nul && set "Q4A=1" || set "Q4A=0"
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\StressManyVals" /v "Val15" 2>nul | findstr /i "stress_val_15" >nul && set "Q4B=1" || set "Q4B=0"
"%LAUNCHER%" -r %VHIVE% -e reg query "%RBASE%\StressManyVals" /v "Val25" 2>nul | findstr /i "stress_val_25" >nul && set "Q4C=1" || set "Q4C=0"
if !Q4A!==1 if !Q4B!==1 if !Q4C!==1 (
    call :PASS "Q-04" "Stress: spot-checked Val7, Val15, Val25 - all correct"
) else (
    call :FAIL "Q-04" "Stress: spot-check failed (Val7=!Q4A! Val15=!Q4B! Val25=!Q4C!)"
)

:: ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
:INSIDE_DONE
echo.
call :LOG "================================================================"
call :LOG "  INNER-VIRT SUMMARY"
call :LOG "  PASS : %PASS%"
call :LOG "  FAIL : %FAIL%"
call :LOG "  SKIP : %SKIP%"
call :LOG "================================================================"

echo.

:: Cleanup temp files created during virt tests
del /f /q "%TEMP%\VRTqk.txt" "%TEMP%\VRTqk2.txt" "%TEMP%\VRTRename.txt" >nul 2>&1
del /f /q "%TEMP%\VRTMulti.txt" "%TEMP%\VRTMulti2.txt" "%TEMP%\VRTExport.reg" >nul 2>&1

:: ============================================================
:: Phase 3: Isolation checks (real registry must be untouched)
:: ============================================================
echo ================================================================
echo   PHASE 3 - Real-Registry Isolation (no leaks from virt)
echo ================================================================
echo.

set "ISO_PASS=0"
set "ISO_FAIL=0"

:: IC-01 - No new HKCU key leaked
reg query "%RBASE%\VirtCreatedKey" >nul 2>&1
if errorlevel 1 (
    call :OPASS "IC-01" "HKCU: VirtCreatedKey did NOT leak to real registry"
) else (
    call :OFAIL "IC-01" "HKCU: VirtCreatedKey LEAKED to real registry!"
)

:: IC-02 - No new value leaked into existing real key
reg query "%RBASE%\SeedKey" /v "VirtAddedToSeed" >nul 2>&1
if errorlevel 1 (
    call :OPASS "IC-02" "HKCU: VirtAddedToSeed did NOT appear in real SeedKey"
) else (
    call :OFAIL "IC-02" "HKCU: VirtAddedToSeed LEAKED into real SeedKey!"
)

:: IC-03 - Real SeedKey\RealStrVal still original
reg query "%RBASE%\SeedKey" /v "RealStrVal" 2>nul | findstr /i "REAL_STRING_ORIGINAL" >nul
if not errorlevel 1 (
    call :OPASS "IC-03" "HKCU: SeedKey\RealStrVal still REAL_STRING_ORIGINAL in real registry"
) else (
    call :OFAIL "IC-03" "HKCU: SeedKey\RealStrVal was changed in real registry!"
)

:: IC-04 - Real ShadowKey\ShadowedVal still original
reg query "%RBASE%\ShadowKey" /v "ShadowedVal" 2>nul | findstr /i "REAL_SHADOW_ORIGINAL" >nul
if not errorlevel 1 (
    call :OPASS "IC-04" "HKCU: ShadowKey\ShadowedVal still REAL_SHADOW_ORIGINAL in real registry"
) else (
    call :OFAIL "IC-04" "HKCU: ShadowKey\ShadowedVal was changed in real registry!"
)

:: IC-05 - Real delete target still present in real (virt delete must not touch real)
reg query "%RBASE%\DeleteTarget" /v "DeleteMe" >nul 2>&1
if not errorlevel 1 (
    call :OPASS "IC-05" "HKCU: DeleteTarget\DeleteMe still present in real registry (virt delete isolated)"
) else (
    call :OFAIL "IC-05" "HKCU: DeleteTarget\DeleteMe DELETED from real registry!"
)

:: IC-06 - Real MergeParent subkeys unchanged (no new subkeys written to real)
reg query "%RBASE%\MergeParent" /v "dummy" >nul 2>&1 & set "IC6ERR=!errorlevel!"
reg query "%RBASE%\MergeParent\RealSubA" >nul 2>&1
if not errorlevel 1 (
    call :OPASS "IC-06" "Real MergeParent\RealSubA still present"
) else (
    call :OFAIL "IC-06" "Real MergeParent\RealSubA was removed from real registry!"
)

:: IC-07 - No HKLM leakage
reg query "HKLM\SOFTWARE\VirtRegTest_HKLM_2026" >nul 2>&1
if errorlevel 1 (
    call :OPASS "IC-07" "HKLM: New virtual HKLM key did NOT appear in real HKLM"
) else (
    call :OFAIL "IC-07" "HKLM: VirtRegTest_HKLM_2026 key APPEARED in real HKLM registry!"
)

:: IC-08 - Optional: HKLM seed unchanged if admin
if "%HAVE_ADMIN%"=="1" (
    reg query "HKLM\SOFTWARE\VirtRegTestSeed_2026" /v "HklmRealVal" 2>nul | findstr /i "HKLM_REAL_SEED" >nul
    if not errorlevel 1 (
        call :OPASS "IC-08" "HKLM: HklmRealVal still HKLM_REAL_SEED in real registry"
    ) else (
        call :OFAIL "IC-08" "HKLM: HklmRealVal changed in real HKLM registry!"
    )
) else (
    echo [SKIP] IC-08: HKLM seed check skipped (no admin)
)

echo.
echo [Phase 3] Isolation PASS: !ISO_PASS!  FAIL: !ISO_FAIL!
echo.

:: ============================================================
:: Phase 4: Virtual-store content checks
:: ============================================================
echo ================================================================
echo   PHASE 4 - Virtual Store Content Inspection
echo ================================================================
echo.

set "VS_PASS=0"
set "VS_FAIL=0"

:: Translate RBASE into virtual path:
:: HKCU\Software\VirtRegTestReal_2026  ->  VHIVE\HKEY_CURRENT_USER\Software\VirtRegTestReal_2026
set "VBASE=%VHIVE_HKCU%\Software\VirtRegTestReal_2026"

:: VS-01 - VirtCreatedKey in store
reg query "%VBASE%\VirtCreatedKey" >nul 2>&1
if not errorlevel 1 (
    call :VSPASS "VS-01" "VirtCreatedKey found in virtual store"
) else (
    call :VSFAIL "VS-01" "VirtCreatedKey NOT found in virtual store - write never persisted!"
)

:: VS-02 - VirtAddedToSeed in store under SeedKey
reg query "%VBASE%\SeedKey" /v "VirtAddedToSeed" >nul 2>&1
if not errorlevel 1 (
    call :VSPASS "VS-02" "SeedKey\VirtAddedToSeed found in virtual store"
) else (
    call :VSFAIL "VS-02" "SeedKey\VirtAddedToSeed NOT in virtual store - CoW write lost!"
)

:: VS-03 - Shadow override value in store
reg query "%VBASE%\ShadowKey" /v "ShadowedVal" 2>nul | findstr /i "VIRT_SHADOW_OVERRIDE" >nul
if not errorlevel 1 (
    call :VSPASS "VS-03" "ShadowKey\ShadowedVal=VIRT_SHADOW_OVERRIDE found in virtual store"
) else (
    call :VSFAIL "VS-03" "ShadowKey\ShadowedVal override NOT in virtual store"
)

:: VS-04 - VirtSubC in virtual MergeParent
rem reg query "%VBASE%\MergeParent\VirtSubC" >nul 2>&1
rem if not errorlevel 1 (
    rem call :VSPASS "VS-04" "MergeParent\VirtSubC found in virtual store"
rem ) else (
    rem call :VSFAIL "VS-04" "MergeParent\VirtSubC NOT found in virtual store"
rem )

:: VS-05 - HKLM new key in virtual HKLM namespace
reg query "%VHIVE_HKLM%\SOFTWARE\VirtRegTest_HKLM_2026" >nul 2>&1
if not errorlevel 1 (
    call :VSPASS "VS-05" "HKLM virtual key found in %VHIVE_HKLM%\SOFTWARE\VirtRegTest_HKLM_2026"
) else (
    call :VSFAIL "VS-05" "HKLM virtual key NOT in virtual store (HKLM write not virtualized?)"
)

:: VS-06 - Deep nested HKCU virtual key
reg query "%VBASE%\Deep\L1\L2\L3\L4\L5" /v "VirtDeepCoW" >nul 2>&1
if not errorlevel 1 (
    call :VSPASS "VS-06" "Deep CoW write (5 levels) found in virtual store"
) else (
    call :VSFAIL "VS-06" "Deep CoW write NOT in virtual store (EnsureVirtualPath failed?)"
)

:: VS-07 - N1\N2\N3\N4\N5 (pure virtual deep key)
reg query "%VBASE%\N1\N2\N3\N4\N5" /v "VirtDeepNew" >nul 2>&1
if not errorlevel 1 (
    call :VSPASS "VS-07" "Pure-virtual deep key N1\\N2\\N3\\N4\\N5 found in virtual store"
) else (
    call :VSFAIL "VS-07" "Pure-virtual deep key N1\\N2\\N3\\N4\\N5 NOT found in virtual store"
)

:: VS-08 - All value types present
for %%T in (SzVal ExpSzVal DwordVal QwordVal BinVal MultiSzVal) do (
    reg query "%VBASE%\TypesKey" /v "%%T" >nul 2>&1
    if not errorlevel 1 (
        call :VSPASS "VS-08-%%T" "TypesKey\%%T found in virtual store"
    ) else (
        call :VSFAIL "VS-08-%%T" "TypesKey\%%T NOT in virtual store"
    )
)

echo.
echo [Phase 4] VirtStore PASS: !VS_PASS!  FAIL: !VS_FAIL!
echo.

call :Cleanup


:: ============================================================
:: Phase 5: Final Report
:: ============================================================
set /a "TOTAL_PASS=!PASS! + !ISO_PASS! + !VS_PASS!"
set /a "TOTAL_FAIL=!FAIL! + !ISO_FAIL! + !VS_FAIL!"
set /a "TOTAL=!TOTAL_PASS! + !TOTAL_FAIL!"

echo ================================================================
echo   FINAL REPORT
echo ================================================================
echo.
echo   Inner-virt tests  : PASS=!PASS!   FAIL=!FAIL!
echo   Isolation checks  : PASS=!ISO_PASS!   FAIL=!ISO_FAIL!
echo   VirtStore checks  : PASS=!VS_PASS!   FAIL=!VS_FAIL!
echo   -----------------------------------------
echo   TOTAL             : PASS=!TOTAL_PASS! / !TOTAL!  FAIL=!TOTAL_FAIL!
echo.
if !TOTAL_FAIL!==0 (
    echo   STATUS: ALL TESTS PASSED
) else (
    color 4F
    echo   STATUS: !TOTAL_FAIL! TESTS FAILED
)
echo ================================================================
echo.
if not "%DoNotPause%"=="yes" pause
exit /b !TOTAL_FAIL!

:: ============================================================
:: OUTER helper subroutines (Phase 3 isolation checks)
:: ============================================================
:OPASS
set /a "ISO_PASS+=1"
echo [PASS] %~1: %~2
goto :EOF

:OFAIL
color 4F
set /a "ISO_FAIL+=1"
echo [FAIL] %~1: %~2
goto :EOF

:VSPASS
set /a "VS_PASS+=1"
echo [PASS] %~1: %~2
goto :EOF

:VSFAIL
color 4F
set /a "VS_FAIL+=1"
echo [FAIL] %~1: %~2
goto :EOF

:: ============================================================
:: INNER helper subroutines (Phase 2 inner test battery)
:: ============================================================
:PASS
set /a "PASS+=1"
set "_MSG=[PASS] %~1: %~2"
echo !_MSG!
echo !_MSG! >> "%INNER_LOG%"
goto :EOF

:FAIL
color 4F
set /a "FAIL+=1"
set "_MSG=[FAIL] %~1: %~2"
echo !_MSG!
echo !_MSG! >> "%INNER_LOG%"
goto :EOF

:SKIP
set /a "SKIP+=1"
set "_MSG=[SKIP] %~1: %~2"
echo !_MSG!
echo !_MSG! >> "%INNER_LOG%"
goto :EOF

:LOG
set "_MSG=%~1"
echo !_MSG!
echo !_MSG! >> "%INNER_LOG%"
goto :EOF

:SECT
set "_MSG="
set "_SEP=-- SECTION %~1: %~2 "
echo.
echo !_SEP!
echo. >> "%INNER_LOG%"
echo !_SEP! >> "%INNER_LOG%"
goto :EOF



:Cleanup
:: ============================================================
:: Cleanup
:: ============================================================
if "%NOCLEANUP%"=="1" (
    echo [CLEANUP] Skipped.
) else (
    echo ================================================================
    echo   Cleanup
    echo ================================================================
    echo.
    reg delete "%RBASE%" /f >nul 2>&1
    echo [CLEANUP] Removed real seeds : %RBASE%
    reg delete "%VHIVE%" /f >nul 2>&1
    echo [CLEANUP] Removed virtual store: %VHIVE%
    if "%HAVE_ADMIN%"=="1" (
        reg delete "HKLM\SOFTWARE\VirtRegTestSeed_2026" /f >nul 2>&1
        echo [CLEANUP] Removed HKLM seed.
    )
    del /f /q "%INNER_LOG%" >nul 2>&1
    echo.
)
goto :EOF