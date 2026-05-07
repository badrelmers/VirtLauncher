@echo off
SETLOCAL
CD /D %~dp0

cd build
mkdir d:\vvv
echo ddd>d:\vvv\zzzV
del d:\vvv\zzzV2

rem VirtLauncher64.exe -fs redirects.ini "F:\_inst_\cygwin\bin\mv.exe" /cygdrive/c/ccc/zzzV /cygdrive/c/ccc/zzzV2
VirtLauncher64.exe -fs redirects.ini cmd /c "rename c:\ccc\zzzV zzzV2"

if exist d:\vvv\zzzV2 (
    echo.
    echo =========
    echo   GOOD 
    echo =========
) else (
    echo.
    echo =========
    echo    BAD!!!!!!!!!!
    echo =========
)


rem VirtLauncher64.exe -fs redirects.ini cmd /c "move c:\ccc\zzzV c:\ccc\zzzV2"


rem VirtLauncher64.exe -fs redirects.ini cmd /c "rename c:\ccc\zzzV zzzV2 & dir /B c:\ccc"
rem dir /B c:\ccc

@rem VirtLauncher64.exe  -reg HKEY_CURRENT_USER\VirtLauncher "F:\_bin\_code\_kickstart\____shortcuts\_appz\_Registry editors\RegistryFinder+++++++++\RegistryFinder64\RegistryFinder.exe"
@rem VirtLauncher64.exe  -reg HKEY_CURRENT_USER\VirtLauncher D:\Windows\regedit.exe
pause

