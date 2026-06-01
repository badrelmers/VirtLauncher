@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


::_______________________________________________

cd "..\build"

rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

echo virtual store: C:\virtl

set ProfilePath=D:\zbala\GoogleChromePortableProfileeeeeeddd_sandboxed_64
VirtLauncher64.exe -r -f C:\virtl -e "F:\_bin\_binz\+browsers\chrome\_chrome\+chrome 109 org from google\109.0.5414.168_chrome_installer X64\Chrome-bin\chrome64.exe"  --start-maximized --new-window --user-data-dir="%ProfilePath%" --restore-last-session --no-default-browser-check --allow-file-access-from-files
 
 
 
@rem this will not run
rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

pause
exit


