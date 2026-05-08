@echo off
SETLOCAL
CD /D "%~dp0"

cd ..\build
echo C:\ccc=D:\vvv> redirectstest.ini

echo ___test cygwin mv__________________________
call :prepare
VirtLauncher64.exe -fs redirectstest.ini "F:\_inst_\cygwin\bin\mv.exe" /cygdrive/c/ccc/zzzV /cygdrive/c/ccc/zzzV2
call :check

echo ___test cmd rename__________________________
call :prepare
VirtLauncher64.exe -fs redirectstest.ini cmd /c "rename c:\ccc\zzzV zzzV2"
call :check

echo ___test cmd move__________________________
call :prepare
VirtLauncher64.exe -fs redirectstest.ini cmd /c "move c:\ccc\zzzV c:\ccc\zzzV2"
call :check

@rem VirtLauncher64.exe  -reg HKEY_CURRENT_USER\VirtLauncher "F:\_bin\_code\_kickstart\____shortcuts\_appz\_Registry editors\RegistryFinder+++++++++\RegistryFinder64\RegistryFinder.exe"
@rem VirtLauncher64.exe  -reg HKEY_CURRENT_USER\VirtLauncher D:\Windows\regedit.exe

del redirectstest.ini
pause
exit /b

:prepare
    rmdir /Q /S d:\vvv
    mkdir d:\vvv
    echo ddd>d:\vvv\zzzV
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


