@echo off
CD /D "%~dp0"

del /Q *.exe *.dll *.obj _build_x86.bat _build_x64.bat 2>nul
del /Q build\*.exe build\*.dll 2>nul

set "DETOURS_PATH=%~dp0detours"
set "SRCDIR=%~dp0"

if not exist "%DETOURS_PATH%\include\detours.h" (
    echo ERROR: Detours not found at %DETOURS_PATH%
    pause & exit /b 1
)

:: Locate vcvarsall.bat
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
echo  VirtLauncher Build v6
echo  Detours : %DETOURS_PATH%
echo  VCVARS  : %VCVARS%
echo  SrcDir  : %SRCDIR%
echo ============================================================

:: ============================================================
:: Write x86 helper bat to disk  (avoids ALL nested-quote issues)
:: ============================================================
(
    echo @echo off
    echo call "%VCVARS%" x86
    echo cd /D "%SRCDIR%"
    echo echo --- cl x86: VirtHook32.dll ---
    echo cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp /Fe:VirtHook32.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook32.dll /DEF:VirtHook.def "%DETOURS_PATH%\lib.X86\detours.lib"
    echo if errorlevel 1 exit /b 1
    echo echo --- cl x86: VirtLauncher32.exe ---
    echo cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher32.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher32.exe "%DETOURS_PATH%\lib.X86\detours.lib" shlwapi.lib advapi32.lib
    echo if errorlevel 1 exit /b 1
) > "%SRCDIR%_build_x86.bat"

:: ============================================================
:: Write x64 helper bat to disk
:: ============================================================
(
    echo @echo off
    echo call "%VCVARS%" x64
    echo cd /D "%SRCDIR%"
    echo echo --- cl x64: VirtHook64.dll ---
    echo cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp /Fe:VirtHook64.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook64.dll /DEF:VirtHook.def "%DETOURS_PATH%\lib.X64\detours.lib"
    echo if errorlevel 1 exit /b 1
    echo echo --- cl x64: VirtLauncher64.exe ---
    echo cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher64.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher64.exe "%DETOURS_PATH%\lib.X64\detours.lib" shlwapi.lib advapi32.lib
    echo if errorlevel 1 exit /b 1
) > "%SRCDIR%_build_x64.bat"

:: ============================================================
:: Execute x86 in a fresh cmd session
:: ============================================================
echo.
echo [x86] Building VirtHook32.dll + VirtLauncher32.exe ...
cmd /c "%SRCDIR%_build_x86.bat"
if errorlevel 1 ( echo FAILED: x86. & goto :err )
echo   OK: x86

:: ============================================================
:: Execute x64 in a fresh cmd session
:: ============================================================
echo.
echo [x64] Building VirtHook64.dll + VirtLauncher64.exe ...
cmd /c "%SRCDIR%_build_x64.bat"
if errorlevel 1 ( echo FAILED: x64. & goto :err )
echo   OK: x64

del /Q *.obj _build_x86.bat _build_x64.bat 2>nul

:: ============================================================
:: Verify architecture of both DLLs (must differ: 14C vs 8664)
:: ============================================================
echo.
echo ============================================================
echo  Architecture verification  (14C=x86  8664=x64)
echo ============================================================
"D:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\amd64\dumpbin.exe" /headers VirtHook32.dll 2>nul | findstr /i "machine"
"D:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\amd64\dumpbin.exe" /headers VirtHook64.dll 2>nul | findstr /i "machine"
echo --- Ordinal 1 export check (must show DetourFinishHelperProcess) ---
"D:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\amd64\dumpbin.exe" /exports VirtHook32.dll 2>nul | findstr /i "DetourFinish"
"D:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\amd64\dumpbin.exe" /exports VirtHook64.dll 2>nul | findstr /i "DetourFinish"
echo ============================================================

if not exist build mkdir build
move /y VirtLauncher32.exe build
move /y VirtHook32.dll build
move /y VirtLauncher64.exe build
move /y VirtHook64.dll build
copy /y redirects.ini build

echo.
echo  Build complete!  Files in: %SRCDIR%
echo    VirtLauncher32.exe + VirtHook32.dll  (for 32-bit apps)
echo    VirtLauncher64.exe + VirtHook64.dll  (for 64-bit apps)
echo.
pause
exit /b 0

:err
del /Q *.obj _build_x86.bat _build_x64.bat 2>nul
echo.
echo BUILD FAILED. See errors above.
pause
exit /b 1
