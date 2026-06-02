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

set ProfilePath=D:\zbala\GoogleChromePortableProfileeeeeeddd_supermium_138_no-sandbox_32
VirtLauncher64.exe -r -f C:\virtl -e "E:\archivosdeprogramas\GoogleChromePortable\_last\chromium_supermium_32\Supermium\chromium_supermium_32.exe"  --start-maximized --new-window --user-data-dir="%ProfilePath%" --restore-last-session --no-default-browser-check --allow-file-access-from-files --no-sandbox
 
 
 
@rem this will not run
rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

pause
exit


