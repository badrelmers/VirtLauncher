@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

set VLAUNCHER_DEBUG=true

cd ..\build

echo.|time
echo ____start
VirtLauncher64.exe -r -e reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes" 2>nul | findstr "EnumA"
echo.|time

if not "%DoNotPause%"=="yes" pause
