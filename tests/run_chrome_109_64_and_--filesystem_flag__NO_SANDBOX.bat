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

set ProfilePath=D:\zbala\GoogleChromePortableProfileeeeeeddd_109_no-sandbox_64
VirtLauncher64.exe -r -f C:\virtl -e "E:\archivosdeprogramas\GoogleChromePortable\_last\chrome_109_x64\chrome_v109_x64.exe"  --start-maximized --new-window --user-data-dir="%ProfilePath%" --restore-last-session --no-default-browser-check --allow-file-access-from-files --no-sandbox
 
 
 
@rem this will not run
rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

pause
exit


