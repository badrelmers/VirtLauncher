@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________

cd "..\build"

if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul

echo virtual store: C:\virtl

@rem powershell crash
VirtLauncher64.exe -r -f C:\virtl -e powershell

@rem powershell do no crash if i do not virtualise registry
@rem VirtLauncher64.exe  -f C:\virtl -e powershell

@rem this will not run
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul

pause
exit


