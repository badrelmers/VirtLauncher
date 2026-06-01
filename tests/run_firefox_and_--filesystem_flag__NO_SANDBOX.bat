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
rem VirtLauncher64.exe -r -f C:\virtl -e "E:\archivosdeprogramas\FirefoxPortableLegacy115\App\Firefox64\firefox.exe"

rem https://wiki.mozilla.org/Security/Sandbox
rem ENVIRONMENT VARIABLE	DESCRIPTION	PLATFORM
rem MOZ_DISABLE_CONTENT_SANDBOX	Disables content process sandboxing for debugging purposes.	All
rem MOZ_DISABLE_GMP_SANDBOX	Disable media plugin sandbox for debugging purposes	All
rem MOZ_DISABLE_NPAPI_SANDBOX	Disable 64-bit NPAPI process sandbox	Windows and Mac
rem MOZ_DISABLE_GPU_SANDBOX	Disable GPU process sandbox	Windows
rem MOZ_DISABLE_RDD_SANDBOX	Disable Data Decoder process sandbox	All
rem MOZ_DISABLE_SOCKET_PROCESS_SANDBOX	Disable Socket Process process sandbox	All

set "MOZ_DISABLE_CONTENT_SANDBOX=1"
set "MOZ_DISABLE_GMP_SANDBOX=1"
set "MOZ_DISABLE_NPAPI_SANDBOX=1"
set "MOZ_DISABLE_GPU_SANDBOX=1"
set "MOZ_DISABLE_RDD_SANDBOX=1"
set "MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1"
VirtLauncher64.exe -r -f C:\virtl -e "E:\archivosdeprogramas\FirefoxPortableLegacy115\App\Firefox64\firefox.exe" -profile D:\zbala\FirefoxPortableLegacy115Profileeeeee

@rem this will not run
rem if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rem rmdir /Q /S c:\virtl 2>nul

pause
exit


