@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________

:: --- Configuration ---
set "TEST32_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe"
set "TEST64_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"
set "BUILD_DIR=..\build"

@rem ___________________________________________________________
:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

:: Counters
set /a PASS_COUNT=0
set /a FAIL_COUNT=0

cd "%BUILD_DIR%"

echo ============================================================
echo  VirtLauncher Injection Test Suite
echo ============================================================
color 2F

set "currdir=%CD%"
@rem remove :
set "currdir=%currdir::=%"
@rem echo currdir: %currdir%

mkdir VIRTL 2>nul
rmdir /Q /S VIRTL || (echo error & pause & exit)



echo ______write to absolute path
VirtLauncher64.exe -r -f -e cmd /c "mkdir c:\ccc & echo fff>c:\ccc\absolute"
if exist "%CD%\VIRTL\c\ccc\absolute" (
    call :Pass
) else (
    call :Fail
)


echo ______write to relative path
VirtLauncher64.exe -r -f -e cmd /c "mkdir ccc & echo fff>ccc\relative"
if exist "%CD%\VIRTL\%currdir%\ccc\relative" (
    call :Pass
) else (
    call :Fail
)


echo ______read from relative path
echo bad>rrr
echo good> "%CD%\VIRTL\%currdir%\rrr"
VirtLauncher64.exe -r -f -e cmd /c "type rrr" | findstr good >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)
del rrr


echo ______read from relative path 2
echo good>rrr
VirtLauncher64.exe -r -f -e cmd /c "type rrr" | findstr good >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)
del rrr


echo ______merged view
mkdir "%CD%\VIRTL\c" 2>nul
echo zzz>"%CD%\VIRTL\c\virtttt"
VirtLauncher64.exe -r -f -e cmd /c "dir /B c:\ " | findstr Windows >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail
)


echo ______tombstone (delete aaa create aaa.vl_deleted)
mkdir c:\ccc 2>nul
echo real>c:\ccc\delll
VirtLauncher64.exe -r -f -e cmd /c "echo virttt>c:\ccc\delll & del c:\ccc\delll"
if exist "%CD%\VIRTL\c\ccc\delll.vl_deleted" (
    call :Pass
) else (
    call :Fail
)

echo ______tombstone file vl_deleted must be hidden inside virt store
VirtLauncher64.exe -r -f -e cmd /c "dir /b c:\ccc" | findstr delll.vl_deleted >nul
if %ERRORLEVEL% EQU 0 (
    @rem bad, my dll do not hide the tombstone
    call :Fail
) else (
    call :Pass
)

rmdir /Q /S "%CD%\VIRTL"
rmdir /Q /S "c:\ccc"

 

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


