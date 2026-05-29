@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F

:: Counters
set /a PASS_COUNT=0
set /a FAIL_COUNT=0

:: --- Configuration ---
set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

rmdir /Q /S "%CD%\VIRTL" 2>nul

@rem this test failed in the past because i was not using STATUS_NO_SUCH_FILE, now it works fine
@rem bug: if a folder is similar to the executable folder exist in the virtual store i get 'D:\Windows\System32\cmd.exe' is not recognized as an internal or external command...
echo __________________ 
mkdir "%CD%\VIRTL\%SystemDrive::=%\Windows\System32" 2>nul
VirtLauncher64.exe -r -f -e cmd /c %SystemDrive%\Windows\System32\cmd.exe /C echo hello1 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)

@rem no bug if i delete the similar folder
echo __________________
rmdir "%CD%\VIRTL\%SystemDrive::=%\Windows\System32" 2>nul
VirtLauncher64.exe -r -f -e cmd /c "%SystemDrive%\Windows\System32\cmd.exe /C echo hello2" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)

@rem no bug when i remove cmd /c even if a folder is similar to the executable folder exist in the virtual store
echo __________________
mkdir "%CD%\VIRTL\%SystemDrive::=%\Windows\System32" 2>nul
VirtLauncher64.exe -r -f -e %SystemDrive%\Windows\System32\cmd.exe /C echo hello3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)


rmdir /Q /S "%CD%\VIRTL" 2>nul




echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed : %PASS_COUNT%
echo  Failed : %FAIL_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY!
    color 2F
) else (
    echo  [X] SOME TESTS FAILED!
    color 4F
)

echo.
if not "%DoNotPause%"=="yes" pause
exit /b %FAIL_COUNT%


:Pass
echo good
set /a PASS_COUNT+=1
goto :eof

:Fail
color 4F
echo bad
set /a FAIL_COUNT+=1
goto :eof


