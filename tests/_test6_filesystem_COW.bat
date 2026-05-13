@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________

@rem dont use tasklist to list exe dll, it does not list all dll of x32 exe!! use listdlls


:: --- Configuration ---
set "TEST32_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe"
set "TEST64_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"
set "LISTDLLS_EXE=%~dp0ListDlls\listdlls64.exe"
set "BUILD_DIR=..\build"

@rem ___________________________________________________________
:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

:: Counters
set /a SUCCESS_COUNT=0
set /a FAIL_COUNT=0

cd "%BUILD_DIR%"

echo ============================================================
echo  VirtLauncher Injection Test Suite
echo ============================================================
color 2F

set "currdir=%CD%"
@rem remove :
set "currdir=%currdir::=%"
@rem echo currdir: %currdir%

mkdir VIRTL 2>nul
rmdir /Q /S VIRTL || (echo error & pause & exit)



echo ______write to absolute path
VirtLauncher64.exe -r -f -e cmd /c "mkdir c:\ccc & echo fff>c:\ccc\absolute"
if exist "%CD%\VIRTL\c\ccc\absolute" (
    echo good 
) else (
    color 4F & echo bad
)


echo ______write to relative path
VirtLauncher64.exe -r -f -e cmd /c "mkdir ccc & echo fff>ccc\relative"
if exist "%CD%\VIRTL\%currdir%\ccc\relative" (
    echo good 
) else (
    color 4F & echo bad
)


echo ______read from relative path
echo bad>rrr
echo good> "%CD%\VIRTL\%currdir%\rrr"
VirtLauncher64.exe -r -f -e cmd /c "type rrr" | findstr good >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)
del rrr


echo ______read from relative path 2
echo good>rrr
VirtLauncher64.exe -r -f -e cmd /c "type rrr" | findstr good >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)
del rrr


echo ______merged view
mkdir "%CD%\VIRTL\c" 2>nul
echo zzz>"%CD%\VIRTL\c\virtttt"
VirtLauncher64.exe -r -f -e cmd /c "dir /B c:\ " | findstr Windows >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo ______tombstone (delete aaa create aaa.vl_deleted)
mkdir c:\ccc 2>nul
echo real>c:\ccc\delll
VirtLauncher64.exe -r -f -e cmd /c "echo virttt>c:\ccc\delll & del c:\ccc\delll"
if exist "%CD%\VIRTL\c\ccc\delll.vl_deleted" (
    echo good 
) else (
    color 4F & echo bad
)

echo ______tombstone file vl_deleted must be hidden inside virt store
VirtLauncher64.exe -r -f -e cmd /c "dir /b c:\ccc" | findstr delll.vl_deleted >nul
if %ERRORLEVEL% EQU 0 (
    @rem bad, my dll do not hide the tombstone
    color 4F & echo bad
) else (
    echo good
)

rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S "c:\ccc"

echo.
echo.
echo ______merged view using TablacusExplorer
echo press Enter to run TablacusExplorer to test Merged View: 
echo create a folder in c:\ then refresh c:\ you must see the usual c:\ files + our new folder, if you see only the new folder then Merged View have a Bug
echo virtual store dir: %CD%\VIRTL
echo.

pause

:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

:: 1. Initial Cleanup
echo [*] Cleaning up existing processes...
taskkill /f /im %APP32_NAME% /t >nul 2>&1
taskkill /f /im %APP64_NAME% /t >nul 2>&1
timeout /t 1 /nobreak >nul

VirtLauncher64.exe -r -f -e "%TEST64_PATH%"


rmdir /Q /S "%CD%\VIRTL"



pause
exit


