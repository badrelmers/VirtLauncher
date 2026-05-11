@echo off
SETLOCAL
CD /D "%~dp0"

set "BUILD_DIR=..\build"
copy /y test_bug2.exe "%BUILD_DIR%" >nul 2>&1
cd "%BUILD_DIR%"

:: Create the real directory that the test will open (must exist on real FS)
set "BUG2_REALDIR=c:\vl_bug2_testdir"
mkdir "%BUG2_REALDIR%" 2>nul

:: Remove any leftover virtual counterpart so the test starts clean
set "BUG2_VIRTDIR=%CD%\VIRTL\%BUG2_REALDIR::=%"
if exist "%BUG2_VIRTDIR%" rmdir /S /Q "%BUG2_VIRTDIR%" 2>nul

echo ============================================================
echo  TEST BUG2: Read-only CoW directory handles excluded from merged view enumeration
@rem echo  Bug 2 reproduction: stale isRealOnly directory handle
@rem echo  missing virtual-only files created after the handle opened
echo ============================================================
echo.
@rem echo  Why cmd cannot reproduce this:
@rem echo  cmd opens, enumerates, and closes a directory handle all inside
@rem echo  one "dir" command. There is no way to hold a handle open across
@rem echo  commands. This test uses a C program that holds hDir open across
@rem echo  the write so the hook sees the stale isRealOnly handle.
@rem echo.

echo ______Bug2: stale read-only dir handle misses virtual file
VirtLauncher64.exe -f -e test_bug2.exe %BUG2_REALDIR% >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)

:: Cleanup
rmdir /S /Q "%BUG2_REALDIR%" 2>nul

pause
exit /b
