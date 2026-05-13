@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
:: --- Configuration ---
set "TEST32_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe"
set "TEST64_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"

@rem ___________________________________________________________
:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

cd "..\build"
if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S C:\virtl_excluded 2>nul
rmdir /Q /S c:\virtl 2>nul




echo [exclude]>"%TEMP%\redir3.ini"
echo C:\virtl_excluded>>"%TEMP%\redir3.ini"
mkdir C:\virtl_excluded 2>nul

echo virtual store: C:\virtl
echo excluded: C:\virtl_excluded

VirtLauncher64.exe -r -f c:\virtl -c "%TEMP%\redir3.ini" -e "%TEST64_PATH%"


if exist "%CD%\VIRTL" rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S C:\virtl_excluded 2>nul
rmdir /Q /S c:\virtl 2>nul

pause
exit


