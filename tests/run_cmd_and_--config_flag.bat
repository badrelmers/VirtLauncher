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

@rem echo c:\=c:\virtl>"%TEMP%\redir.ini"
@rem echo d:\=c:\virtl>>"%TEMP%\redir.ini"
@rem echo e:\=c:\virtl>>"%TEMP%\redir.ini"
@rem echo f:\=c:\virtl>>"%TEMP%\redir.ini"

echo c:\=c:\virtl\>"%TEMP%\redir.ini"
echo d:\=c:\virtl>>"%TEMP%\redir.ini"
echo e:\=c:\virtl\>>"%TEMP%\redir.ini"
echo f:\=c:\virtl>>"%TEMP%\redir.ini"

echo virtual store: C:\virtl
VirtLauncher64.exe -r -c "%TEMP%\redir.ini" -e cmd

@rem this will not run
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S c:\virtl 2>nul
pause
exit


