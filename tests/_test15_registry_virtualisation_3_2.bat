@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


::_______________________________________________

cd ..\build



REM ── Pre-seed real registry keys (run OUTSIDE VirtLauncher) ───────────────────
REM These keys must exist in the real registry before the virtualisation test
REM runs. The test reads them through CoW/merge handles to verify fallback.

set "rbase=HKCU\Software\VirtRegTestReal_2026"

reg add "%rbase%\SeedKey" /f >nul
reg add "%rbase%\SeedKey" /v "RealStrVal" /t REG_SZ /d "REAL_STRING_ORIGINAL" /f >nul

reg add "%rbase%\MergeParent\RealSubA" /f >nul
reg add "%rbase%\MergeParent\RealSubB" /f >nul

reg add "%rbase%\ShadowKey" /f >nul
reg add "%rbase%\ShadowKey" /v "ShadowedVal" /t REG_SZ /d "REAL_SHADOW_ORIGINAL" /f >nul
reg add "%rbase%\ShadowKey" /v "RealOnlyVal" /t REG_SZ /d "REAL_ONLY_VALUE" /f >nul
reg add "%rbase%\ShadowKey" /v "AnotherReal" /t REG_SZ /d "ANOTHER_REAL_VALUE" /f >nul


VirtLauncher64.exe -r HKCU\VirtRegTest_Store_2026 --exec ^
    powershell.exe -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0_test15_registry_virtualisation_3_2.ps1"


reg delete "%rbase%" /f >nul
pause
