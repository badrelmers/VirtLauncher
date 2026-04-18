@echo off
@rem SETLOCAL
CD /D %~dp0

del *.exe
del *.dll
del *.obj

:: ============================================================
:: BUILD.bat  -  VirtLauncher + VirtHook
:: Fix: each architecture runs in a FRESH cmd.exe session
::      so vcvarsall x86 / x64 never contaminate each other.
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
    echo        Place the Detours folder next to this bat.
    pause & exit /b 1
)

:: Locate vcvarsall.bat
set "VCVARS="
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
)
:: VS2012-VS2019 fallback
if "%VCVARS%"=="" (
    for /f "usebackq tokens=*" %%i in (`where vcvarsall.bat 2^>nul`) do (
        if "%VCVARS%"=="" set "VCVARS=%%i"
    )
)
if "%VCVARS%"=="" (
    echo ERROR: vcvarsall.bat not found. Is Visual Studio installed?
    pause & exit /b 1
)

echo ============================================================
echo  VirtLauncher Build
echo  Detours : %DETOURS_PATH%
echo  VCVARS  : %VCVARS%
echo ============================================================

:: ============================================================
:: X86 block -- fresh cmd session for x86
:: ============================================================
echo.
echo [x86] Compiling VirtHook32.dll and VirtLauncher32.exe ...

cmd /S /c "call "%VCVARS%" x86 && cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp /Fe:VirtHook32.dll /I"%DETOURS_PATH%\include" /link "%DETOURS_PATH%\lib.X86\detours.lib" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher32.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE "%DETOURS_PATH%\lib.X86\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 (
    echo.
    echo FAILED: x86 build.
    goto :err
)
echo   OK: VirtHook32.dll + VirtLauncher32.exe

:: ============================================================
:: X64 block -- fresh cmd session for x64
:: ============================================================
echo.
echo [x64] Compiling VirtHook64.dll and VirtLauncher64.exe ...

cmd /S /c ""%VCVARS%" x64 && cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp /Fe:VirtHook64.dll /I"%DETOURS_PATH%\include" /link "%DETOURS_PATH%\lib.X64\detours.lib" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher64.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE "%DETOURS_PATH%\lib.X64\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 (
    echo.
    echo FAILED: x64 build.
    goto :err
)
echo   OK: VirtHook64.dll + VirtLauncher64.exe

:: ============================================================
:: Done
:: ============================================================
del /Q *.obj 2>nul

echo.
echo ============================================================
echo  Build complete!
echo    VirtLauncher32.exe + VirtHook32.dll  (for 32-bit apps)
echo    VirtLauncher64.exe + VirtHook64.dll  (for 64-bit apps)
echo ============================================================
echo.
echo Deployment: copy all four files to the same folder.
echo.
pause
exit /b 0

:err
del /Q *.obj 2>nul
echo.
echo BUILD FAILED. See errors above.
pause
exit /b 1
