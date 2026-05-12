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
cd ..\build
echo C:\ccc=D:\vvv> redirectstest.ini


echo ___test cygwin mv__________________________
call :prepare
VirtLauncher64.exe -c redirectstest.ini "F:\_inst_\cygwin\bin\mv.exe" /cygdrive/c/ccc/zzzV /cygdrive/c/ccc/zzzV2
call :check

echo ___test cmd rename__________________________
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "rename c:\ccc\zzzV zzzV2"
call :check

echo ___test cmd move__________________________
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "move c:\ccc\zzzV c:\ccc\zzzV2"
call :check

echo ___test hard link__________________________
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /H c:\ccc\zzzV2 c:\ccc\zzzV"
call :check
@rem pause

echo ___test symlink__________________________
call :prepare
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink c:\ccc\zzzV2 c:\ccc\zzzV"
call :check
@rem pause

echo ___test symlink dir__________________________
call :preparedir
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /D c:\ccc\dirV2 c:\ccc\dirV"
call :checkdir
@rem pause

echo ___test Junction__________________________
call :preparedir
VirtLauncher64.exe -c redirectstest.ini cmd /c "mklink /J c:\ccc\dirV2 c:\ccc\dirV"
call :checkdir



@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtLauncher "F:\_bin\_code\_kickstart\____shortcuts\_appz\_Registry editors\RegistryFinder+++++++++\RegistryFinder64\RegistryFinder.exe"
@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtLauncher D:\Windows\regedit.exe

del redirectstest.ini
pause
exit /b

:prepare
    rmdir /Q /S d:\vvv
    mkdir d:\vvv
    echo ddd>d:\vvv\zzzV
exit /b

:preparedir
    rmdir /Q /S d:\vvv
    mkdir d:\vvv\dirV
exit /b

:check
    if exist d:\vvv\zzzV2 (
        echo.
        echo =========
        echo   GOOD 
        echo =========
        echo.
    ) else (
        color 4F
        echo.
        echo =========
        echo    BAD!!!!!!!!!!
        echo =========
        echo.
    )
exit /b

:checkdir
    if exist d:\vvv\dirV2 (
        echo.
        echo =========
        echo   GOOD 
        echo =========
        echo.
    ) else (
        color 4F
        echo.
        echo =========
        echo    BAD!!!!!!!!!!
        echo =========
        echo.
    )
exit /b
