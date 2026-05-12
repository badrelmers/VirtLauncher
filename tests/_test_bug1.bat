@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F
set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

echo ============================================================
echo  TEST BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
@rem echo  Bug 1 reproduction tests (NT-relative opens via virtual dir handle)
@rem echo  These tests CANNOT be reproduced by cmd.exe alone because
@rem echo  cmd always resolves relative paths to absolute before calling NT.
echo ============================================================
echo.

:: -------------------------------------------------------
:: Setup: create the virtual directory FIRST so the hook
:: returns the virtual-store handle when we open it later.
:: -------------------------------------------------------
set "BUG1_REALDIR=c:\vl_bug1_testdir"
mkdir "%BUG1_REALDIR%" 2>nul

:: Create the virtual dir inside the sandbox (so virtual handle is returned on open)
VirtLauncher64.exe -f -e cmd /c "mkdir %BUG1_REALDIR%" 2>nul

:: Create a real-only file that does NOT exist in the virtual store
echo real_content > "%BUG1_REALDIR%\cow_file.txt"

:: Sanity-check: confirm it's NOT in the virtual store
if exist "%CD%\VIRTL\%BUG1_REALDIR::=%\cow_file.txt" del "%CD%\VIRTL\%BUG1_REALDIR::=%\cow_file.txt"


echo ______Bug1: COW read via NT-relative open through virtual dir handle
@rem echo   [open %BUG1_REALDIR% via Win32 inside sandbox -> virtual handle]
@rem echo   [then NtOpenFile with RootDirectory=virtual_handle, ObjectName=cow_file.txt]
@rem echo   [file is real-only, COW should serve it; Bug1 causes STATUS_OBJECT_NAME_NOT_FOUND]

VirtLauncher64.exe -f -e "%~dp0test_bug1.exe" %BUG1_REALDIR% cow_file.txt >nul
if %ERRORLEVEL% EQU 0 (
    @rem [Bug1 is FIXED: COW fallback via NT-relative open works]
    echo good
) else (
    @rem [Bug1 is PRESENT: COW fallback broken for NT-relative opens]
    color 4F & echo bad
)


echo ______Bug1 variant: same dir, different file to rule out caching
echo good_variant > "%BUG1_REALDIR%\cow_file2.txt"

VirtLauncher64.exe -f -e "%~dp0test_bug1.exe" %BUG1_REALDIR% cow_file2.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo ______Baseline: Win32 read from same dir (this always works, even with Bug1)
@rem echo   [proves the file IS accessible via Win32 COW -- just not via NT-relative]
echo real_content > "%BUG1_REALDIR%\cow_file3.txt"

VirtLauncher64.exe -f -e cmd /c "type %BUG1_REALDIR%\cow_file3.txt" | findstr real_content >nul
if %ERRORLEVEL% EQU 0 (
    @rem [expected: Win32 always resolves to absolute, COW works]
    echo good
) else (
    @rem [unexpected: basic COW is broken]
    color 4F & echo bad
)

pause
exit /b


 