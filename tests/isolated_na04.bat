@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

::_______________________________________________
set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


::_______________________________________________

cd ..\build
set "virt_store=HKCU\VirtRegTest_Store_2026"
set "rbase=HKCU\Software\VirtRegTestReal_2026"

:: Clean up any previous state
reg delete "%virt_store%" /f >nul 2>nul
reg delete "%rbase%" /f >nul 2>nul

:: Pre-seed the real registry key required for the NA-04 CoW test
reg add "%rbase%\SeedKey" /f >nul

:: Execute the isolated PowerShell test via VirtLauncher
VirtLauncher64.exe -r "%virt_store%" --exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0isolated_na04.ps1"

:: Clean up
reg delete "%virt_store%" /f >nul 2>nul
reg delete "%rbase%" /f >nul 2>nul
pause
