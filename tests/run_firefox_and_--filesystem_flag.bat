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
VirtLauncher64.exe -r -f C:\virtl -e cmd /c E:\archivosdeprogramas\FirefoxPortableLegacy115\FirefoxPortable.exe

@rem this will not run
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul

pause
exit


