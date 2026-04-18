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
echo  NOTE: VirtHook.dll uses /MT (static CRT) so it has zero
echo        runtime DLL dependencies inside the target process.
echo        VirtLauncher.exe uses /MD (dynamic CRT) as normal.
echo ============================================================

:: ============================================================
:: X86
:: VirtHook  -> /MT  (static CRT -- no MSVCR dependency in target)
:: VirtLauncher -> /MD (dynamic CRT -- normal for an EXE)
:: ============================================================
echo.
echo [x86] Compiling VirtHook32.dll  (x86, /MT static CRT) ...

cmd /S /c "call "%VCVARS%" x86 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp /Fe:VirtHook32.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook32.dll "%DETOURS_PATH%\lib.X86\detours.lib""

if errorlevel 1 ( echo. & echo FAILED: VirtHook32.dll & goto :err )
echo   OK: VirtHook32.dll

echo [x86] Compiling VirtLauncher32.exe  (x86, /MD) ...

cmd /S /c "call "%VCVARS%" x86 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher32.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher32.exe "%DETOURS_PATH%\lib.X86\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 ( echo. & echo FAILED: VirtLauncher32.exe & goto :err )
echo   OK: VirtLauncher32.exe

:: ============================================================
:: X64
:: ============================================================
echo.
echo [x64] Compiling VirtHook64.dll  (x64, /MT static CRT) ...

cmd /S /c "call "%VCVARS%" x64 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp /Fe:VirtHook64.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook64.dll "%DETOURS_PATH%\lib.X64\detours.lib""

if errorlevel 1 ( echo. & echo FAILED: VirtHook64.dll & goto :err )
echo   OK: VirtHook64.dll

echo [x64] Compiling VirtLauncher64.exe  (x64, /MD) ...

cmd /S /c "call "%VCVARS%" x64 && cd /D "%SRCDIR%" && cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher64.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher64.exe "%DETOURS_PATH%\lib.X64\detours.lib" shlwapi.lib advapi32.lib"

if errorlevel 1 ( echo. & echo FAILED: VirtLauncher64.exe & goto :err )
echo   OK: VirtLauncher64.exe

del /Q *.obj 2>nul

echo.
echo ============================================================
echo  Build complete!  Files in: %SRCDIR%
echo    VirtLauncher32.exe + VirtHook32.dll  (for 32-bit apps)
echo    VirtLauncher64.exe + VirtHook64.dll  (for 64-bit apps)
echo ============================================================
echo.
echo  To verify architecture of built DLLs, run:
echo    dumpbin /headers VirtHook32.dll ^| findstr "machine"
echo    dumpbin /headers VirtHook64.dll ^| findstr "machine"
echo  x86 DLL should say: 14C  (i386)
echo  x64 DLL should say: 8664 (AMD64)
echo.
pause
exit /b 0

:err
del /Q *.obj 2>nul
echo.
echo BUILD FAILED. See errors above.
pause
exit /b 1
