@echo off
@rem SETLOCAL
CD /D %~dp0

del *.exe
del *.dll
del *.obj

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
:: Build all four targets explicitly
:: ============================================================

echo.
echo [1/4] Building VirtHook32.dll   (x86) ...
call :build_VirtHook32
if errorlevel 1 goto :err

echo [2/4] Building VirtLauncher32.exe (x86) ...
call :build_VirtLauncher32
if errorlevel 1 goto :err

echo.
echo [3/4] Building VirtHook64.dll   (x64) ...
call :build_VirtHook64
if errorlevel 1 goto :err

echo [4/4] Building VirtLauncher64.exe (x64) ...
call :build_VirtLauncher64
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
del *.obj

pause
exit /b 0

:: ============================================================
:: Dedicated build routines - one per output file
:: ============================================================

:build_VirtHook32
setlocal
call :setup_x86_env
cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp ^
   /I"%DETOURS_PATH%\include" ^
   /link "%DETOURS_PATH%\lib.X86\detours.lib" /OUT:VirtHook32.dll
if errorlevel 1 ( echo FAILED: VirtHook32.dll & exit /b 1 )
echo   OK: VirtHook32.dll
endlocal
exit /b 0

:build_VirtLauncher32
setlocal
call :setup_x86_env
cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp ^
   /I"%DETOURS_PATH%\include" ^
   /link /SUBSYSTEM:CONSOLE "%DETOURS_PATH%\lib.X86\detours.lib" /OUT:VirtLauncher32.exe shlwapi.lib advapi32.lib
if errorlevel 1 ( echo FAILED: VirtLauncher32.exe & exit /b 1 )
echo   OK: VirtLauncher32.exe
endlocal
exit /b 0

:build_VirtHook64
setlocal
call :setup_x64_env
cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp ^
   /I"%DETOURS_PATH%\include" ^
   /link "%DETOURS_PATH%\lib.X64\detours.lib" /OUT:VirtHook64.dll
if errorlevel 1 ( echo FAILED: VirtHook64.dll & exit /b 1 )
echo   OK: VirtHook64.dll
endlocal
exit /b 0

:build_VirtLauncher64
setlocal
call :setup_x64_env
cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp ^
   /I"%DETOURS_PATH%\include" ^
   /link /SUBSYSTEM:CONSOLE "%DETOURS_PATH%\lib.X64\detours.lib" /OUT:VirtLauncher64.exe shlwapi.lib advapi32.lib
if errorlevel 1 ( echo FAILED: VirtLauncher64.exe & exit /b 1 )
echo   OK: VirtLauncher64.exe
endlocal
exit /b 0

:: ============================================================
:: Environment setup helpers
:: ============================================================

:setup_x86_env
set VCVARS=
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
) else (
    for /f "tokens=*" %%i in ('where vcvarsall.bat 2^>nul') do set VCVARS="%%i"
)
if "%VCVARS%"=="" (
    echo ERROR: Could not find vcvarsall.bat
    exit /b 1
)
call "%VCVARS%" x86 >nul 2>&1
exit /b 0

:setup_x64_env
set VCVARS=
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
) else (
    for /f "tokens=*" %%i in ('where vcvarsall.bat 2^>nul') do set VCVARS="%%i"
)
if "%VCVARS%"=="" (
    echo ERROR: Could not find vcvarsall.bat
    exit /b 1
)
call "%VCVARS%" x64 >nul 2>&1
exit /b 0

:err
echo.
echo BUILD FAILED.
pause
exit /b 1