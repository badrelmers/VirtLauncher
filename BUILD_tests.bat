@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
REM fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )


@echo off
CD /D "%~dp0"

del /Q tests\*.exe 2>nul

set "SRCDIR=%~dp0"

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
echo  tests Build v1
echo  VCVARS  : %VCVARS%
echo  SrcDir  : %SRCDIR%
echo ============================================================

 
@rem (
@rem     echo @echo off
@rem     echo call "%VCVARS%" x86
@rem     echo cd /D "%SRCDIR%"
@rem     echo echo --- cl x86: VirtHook32.dll ---
@rem     echo cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp /Fe:VirtHook32.dll /I"%DETOURS_PATH%\include" /link /OUT:VirtHook32.dll /DEF:VirtHook.def "%DETOURS_PATH%\lib.X86\detours.lib"
@rem     echo if errorlevel 1 exit /b 1
@rem     echo echo --- cl x86: VirtLauncher32.exe ---
@rem     echo cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp /Fe:VirtLauncher32.exe /I"%DETOURS_PATH%\include" /link /SUBSYSTEM:CONSOLE /OUT:VirtLauncher32.exe "%DETOURS_PATH%\lib.X86\detours.lib" shlwapi.lib advapi32.lib
@rem     echo if errorlevel 1 exit /b 1
@rem ) > "%SRCDIR%_build_x86.bat"


call "%VCVARS%" x86
cd /D "%SRCDIR%"

echo [x86] Building test_bug1.exe ...
@rem cl /nologo /O2 "%~dp0test_bug1.c" /Fe:test_bug1.exe
cl /nologo /EHsc /O2 /MD /W3 test_bug1.c /Fe:test_bug1.exe /link /SUBSYSTEM:CONSOLE /OUT:test_bug1.exe   shlwapi.lib advapi32.lib

if errorlevel 1 ( echo FAILED: x86. & goto :err )
echo   OK: x86


echo [x86] Building test_bug2.exe ...
cl /nologo /EHsc /O2 /MD /W3 test_bug2.c /Fe:test_bug2.exe /link /SUBSYSTEM:CONSOLE /OUT:test_bug2.exe   shlwapi.lib advapi32.lib

if errorlevel 1 ( echo FAILED: x86. & goto :err )
echo   OK: x86

del /Q *.obj 2>nul

echo ============================================================

move /y test_bug1.exe tests
move /y test_bug2.exe tests

echo.
echo  Build complete!  Files in: %SRCDIR%
echo    test_bug1.exe
echo    test_bug2.exe
echo.
pause
exit /b 0


:err
del /Q *.obj 2>nul
echo.
echo BUILD FAILED. See errors above.
pause
exit /b 1


