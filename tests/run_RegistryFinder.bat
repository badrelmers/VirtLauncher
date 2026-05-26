@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true

set "RegistryFinder=F:\_bin\_code\_kickstart\____shortcuts\_appz\_Registry editors\RegistryFinder+++++++++\RegistryFinder64\RegistryFinder.exe"


cd "..\build"

:: 1. Initial Cleanup
taskkill /f /im RegistryFinder.exe /t >nul 2>&1
timeout /t 1 /nobreak >nul
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"

echo __________start RegistryFinder
echo.
VirtLauncher64.exe -r -f -e "%RegistryFinder%"


if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"

pause


