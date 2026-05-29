@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
REM set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F

:: Counters
set /a SUCCESS_COUNT=0
set /a FAIL_COUNT=0

cd ..\build
echo C:\ccc=c:\vvv> redirectstest.ini
if exist c:\vvv rmdir /Q /S c:\vvv

echo ______test cygwin mv
call :prepare
VirtLauncher64.exe -c redirectstest.ini "F:\_inst_\cygwin\bin\mv.exe" /cygdrive/c/ccc/zzzV /cygdrive/c/ccc/zzzV2
call :check

echo ______test cmd rename
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "rename c:\ccc\zzzV zzzV2" >nul
call :check

echo ______test cmd move
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "move c:\ccc\zzzV c:\ccc\zzzV2" >nul
call :check

echo ______test hard link
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /H c:\ccc\zzzV2 c:\ccc\zzzV" >nul
call :check

echo ______test symlink
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink c:\ccc\zzzV2 c:\ccc\zzzV" >nul
call :check

echo ______test symlink dir
call :preparedir
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /D c:\ccc\dirV2 c:\ccc\dirV" >nul
call :checkdir

echo ______test Junction
call :preparedir
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /J c:\ccc\dirV2 c:\ccc\dirV" >nul
call :checkdir





if exist c:\vvv rmdir /Q /S c:\vvv
del redirectstest.ini

if %FAIL_COUNT% equ 0 (
    echo  ALL TESTS PASSED
    color 2F
) else (
    echo  SOME TESTS FAILED
    color 4F
)

if not "%DoNotPause%"=="yes" pause
exit /b %FAIL_COUNT%

:prepare
    if exist c:\vvv rmdir /Q /S c:\vvv
    mkdir c:\vvv
    echo ddd>c:\vvv\zzzV
exit /b

:preparedir
    if exist c:\vvv rmdir /Q /S c:\vvv
    mkdir c:\vvv\dirV
exit /b

:check
    if exist c:\vvv\zzzV2 (
        echo GOOD 
        set /a SUCCESS_COUNT+=1
    ) else (
        color 4F
        echo BAD!!!!!!!!!!
        set /a FAIL_COUNT+=1
    )
exit /b

:checkdir
    if exist c:\vvv\dirV2 (
        echo GOOD 
    ) else (
        color 4F
        echo BAD!!!!!!!!!!
    )
exit /b
