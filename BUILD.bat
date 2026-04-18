@echo off
@rem SETLOCAL
CD /D %~dp0

del *.exe
del *.dll

:: ============================================================
:: BUILD.bat  -  VirtLauncher + VirtHook  build script
:: Requires: Visual Studio 2010 (or any MSVC with VS2010 compat)
::            Microsoft Detours 4.0
::            Windows SDK 7.1 (or later)
::
:: Set DETOURS_PATH below before running.
:: ============================================================

:: ---- CONFIGURE THIS ----------------------------------------
set "DETOURS_PATH=%~dp0detours"
:: Path to the root of your Detours installation.
:: Must contain:
::   %DETOURS_PATH%\include\detours.h
::   %DETOURS_PATH%\lib.X86\detours.lib
::   %DETOURS_PATH%\lib.X64\detours.lib
:: ------------------------------------------------------------

if not exist "%DETOURS_PATH%\include\detours.h" (
    echo ERROR: Detours not found at %DETOURS_PATH%
    echo        Edit DETOURS_PATH in this script.
    echo        Download: https://github.com/microsoft/detours
    pause
    exit /b 1
)

echo ============================================================
echo  VirtLauncher Build Script
echo  Detours: %DETOURS_PATH%
echo ============================================================

:: ============================================================
::  x86  Build
:: ============================================================
echo.
echo [1/4] Building VirtHook32.dll  (x86) ...
call :build_x86 VirtHook "VirtHook32.dll" "/LD"
if errorlevel 1 goto :err

echo [2/4] Building VirtLauncher32.exe  (x86) ...
call :build_x86 VirtLauncher "VirtLauncher32.exe" "/Fe:VirtLauncher32.exe"
if errorlevel 1 goto :err

:: ============================================================
::  x64  Build  (needs x64 toolchain)
:: ============================================================
echo.
echo [3/4] Building VirtHook64.dll  (x64) ...
call :build_x64 VirtHook "VirtHook64.dll" "/LD"
if errorlevel 1 goto :err

echo [4/4] Building VirtLauncher64.exe  (x64) ...
call :build_x64 VirtLauncher "VirtLauncher64.exe" "/Fe:VirtLauncher64.exe"
if errorlevel 1 goto :err

echo.
echo ============================================================
echo  Build complete!
echo    VirtLauncher32.exe  + VirtHook32.dll  (for 32-bit apps)
echo    VirtLauncher64.exe  + VirtHook64.dll  (for 64-bit apps)
echo ============================================================
echo.
echo Deployment: copy all four files to the same folder.
echo.
pause
exit /b 0

:: ============================================================
::  Subroutine: build_x86  %1=source  %2=output  %3=extra_flags
:: ============================================================
:build_x86
setlocal
set SRC=%1.cpp
set OUT=%2
set EXTRA=%3


@rem VS100COMNTOOLS=D:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\Tools
@rem "D:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"

:: Try to find vcvarsall for VS2010 first, then any MSVC
set VCVARS=
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
) else (
    for /f "tokens=*" %%i in ('where vcvarsall.bat 2^>nul') do set VCVARS="%%i"
)
if "%VCVARS%"=="" (
    echo ERROR: Could not find vcvarsall.bat. Is Visual Studio installed?
    exit /b 1
)

call "%VCVARS%" x86
 @rem >nul 2>&1

cl /nologo /EHsc /O2 /MD /W3 %EXTRA% %SRC% ^
   /I"%DETOURS_PATH%\include" ^
   /link /SUBSYSTEM:CONSOLE ^
   "%DETOURS_PATH%\lib.X86\detours.lib" ^
   shlwapi.lib advapi32.lib

if errorlevel 1 ( echo FAILED: %SRC% x86 & exit /b 1 )
echo   OK: %OUT%
endlocal
exit /b 0

:: ============================================================
::  Subroutine: build_x64  %1=source  %2=output  %3=extra_flags
:: ============================================================
:build_x64
setlocal
set SRC=%1.cpp
set OUT=%2
set EXTRA=%3

set VCVARS=
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
) else (
    for /f "tokens=*" %%i in ('where vcvarsall.bat 2^>nul') do set VCVARS="%%i"
)
if "%VCVARS%"=="" (
    echo ERROR: Could not find vcvarsall.bat. Is Visual Studio installed?
    exit /b 1
)

call "%VCVARS%" x64
 @rem >nul 2>&1

cl /nologo /EHsc /O2 /MD /W3 %EXTRA% %SRC% ^
   /I"%DETOURS_PATH%\include" ^
   /link /SUBSYSTEM:CONSOLE ^
   "%DETOURS_PATH%\lib.X64\detours.lib" ^
   shlwapi.lib advapi32.lib

if errorlevel 1 ( echo FAILED: %SRC% x64 & exit /b 1 )
echo   OK: %OUT%
endlocal
exit /b 0

:err
echo.
echo BUILD FAILED.
pause
exit /b 1
