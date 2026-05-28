@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 @rem set VLAUNCHER_DEBUG=true


::_______________________________________________

cd "..\build"

if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul

echo virtual store: C:\virtl
VirtLauncher64.exe -r -f C:\virtl -e cmd /c F:\_bin\_binz\_ide\_VSCode\_last_ORG_VxKex\_start_VSCode.bat

@rem this will not run
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul

pause
exit


