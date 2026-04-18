@echo off
CD /D "%~dp0"

del /Q *.exe *.dll *.obj 2>nul

set "DETOURS_PATH=%~dp0detours"
set "SRCDIR=%~dp0"

if not exist "%DETOURS_PATH%\include\detours.h" (
    echo ERROR: Detours not found at %DETOURS_PATH%
    pause & exit /b 1
)

set "VCVARS="
if exist "%VS100COMNTOOLS%..\..\VC\vcvarsall.bat" (
    set "VCVARS=%VS100COMNTOOLS%..\..\VC\vcvarsall.bat"
)
if "%VCVARS%"=="" (
    for /f "usebackq tokens=*" %%i in (`where vcvarsall.bat 2^>nul`) do (
        if "%VCVARS%"=="" set "VCVARS=%%i"
    )
)
if "%VCVARS%"=="" (
    echo ERROR: vcvarsall.bat not found.
    pause & exit /b 1
)

echo ============================================================
echo  VirtLauncher Build
echo  Detours : %DETOURS_PATH%
echo  VCVARS  : %VCVARS%
echo  SrcDir  : %SRCDIR%
echo ============================================================

:: ============================================================
:: X86
:: NOTE: cd back to SRCDIR after vcvarsall (it changes CWD).
::       Use bare filenames only - no drive paths in /Fe or /OUT
::       to avoid the ":C:\..." misparse bug.
:: ============================================================
echo.
echo [x86] Compiling VirtHook32.dll and VirtLauncher32.exe ...

cmd /S /c "call "%VCVARS%" x86 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp /Fe:VirtHook32.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook32.dll "%DETOURS_PATH%\lib.X86\detours.lib" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher32.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher32.exe "%DETOURS_PATH%\lib.X86\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 ( echo. & echo FAILED: x86 build. & goto :err )
echo   OK: VirtHook32.dll + VirtLauncher32.exe

:: ============================================================
:: X64
:: ============================================================
echo.
echo [x64] Compiling VirtHook64.dll and VirtLauncher64.exe ...

cmd /S /c "call "%VCVARS%" x64 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp /Fe:VirtHook64.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook64.dll "%DETOURS_PATH%\lib.X64\detours.lib" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher64.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher64.exe "%DETOURS_PATH%\lib.X64\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 ( echo. & echo FAILED: x64 build. & goto :err )
echo   OK: VirtHook64.dll + VirtLauncher64.exe

del /Q *.obj 2>nul

echo.
echo ============================================================
echo  Build complete!  Files are in: %SRCDIR%
echo    VirtLauncher32.exe + VirtHook32.dll  (for 32-bit apps)
echo    VirtLauncher64.exe + VirtHook64.dll  (for 64-bit apps)
echo ============================================================
echo.
pause
exit /b 0

:err
del /Q *.obj 2>nul
echo.
echo BUILD FAILED.
pause
exit /b 1
