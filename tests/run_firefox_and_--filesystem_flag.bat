@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
set VLAUNCHER_VERBOSE=true
rem set VLAUNCHER_DEBUG=true


::_______________________________________________

cd "..\build"

rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

echo virtual store: C:\virtl
rem VirtLauncher64.exe -r -f C:\virtl -e E:\archivosdeprogramas\FirefoxPortableLegacy115\FirefoxPortable.exe

VirtLauncher64.exe -r -f C:\virtl -e "E:\archivosdeprogramas\FirefoxPortableLegacy115\App\Firefox64\firefox.exe" -profile D:\zbala\FirefoxPortableLegacy115Profileeeeee

@rem this will not run
rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

pause
exit


