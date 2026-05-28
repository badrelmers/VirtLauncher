@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

::_______________________________________________
rem set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


::_______________________________________________

cd ..\build



REM ── Pre-seed real registry keys (run OUTSIDE VirtLauncher) ───────────────────
REM These keys must exist in the real registry before the virtualisation test
REM runs. The test reads them through CoW/merge handles to verify fallback.

set "virt_store=HKCU\VirtRegTest_Store_2026"
set "rbase=HKCU\Software\VirtRegTestReal_2026"
reg delete "%virt_store%" /f >nul 2>nul
reg delete "%rbase%" /f >nul 2>nul

 
REM --- Section NA & NB & NF-03: CoW and Read Fallback Targets ---
reg add "%rbase%\SeedKey" /f >nul
reg add "%rbase%\SeedKey" /v "RealStrVal" /t REG_SZ /d "REAL_STRING_ORIGINAL" /f >nul
reg add "%rbase%\SeedKey" /v "RealDwordVal" /t REG_DWORD /d 1 /f >nul

REM --- Section NC: EnumerateKey Merge Targets ---
reg add "%rbase%\MergeParent\RealSubA" /f >nul
reg add "%rbase%\MergeParent\RealSubB" /f >nul

REM --- Section ND & NG: EnumerateValueKey Merge and MultipleValue targets ---
reg add "%rbase%\ShadowKey" /f >nul
reg add "%rbase%\ShadowKey" /v "ShadowedVal" /t REG_SZ /d "REAL_SHADOW_ORIGINAL" /f >nul
reg add "%rbase%\ShadowKey" /v "RealOnlyVal" /t REG_SZ /d "REAL_ONLY_VALUE" /f >nul
reg add "%rbase%\ShadowKey" /v "AnotherReal" /t REG_SZ /d "ANOTHER_REAL_VALUE" /f >nul

REM --- Section NF-04: Key Deletion/Tombstone Target ---
reg add "%rbase%\DeleteTarget" /f >nul

VirtLauncher64.exe -r "%virt_store%" --exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0_test15_registry_virtualisation_3_NT_level_2.ps1"

echo.
echo.
if %errorlevel% EQU 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY
    color 2F
) else (
    echo  [X] SOME TESTS FAILED
    color 4F
)
echo.
echo.

reg delete "%virt_store%" /f >nul 2>nul
reg delete "%rbase%" /f >nul 2>nul
pause
