@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F
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
    echo good
) else (
    color 4F & echo bad
)

@rem no bug if i delete the similar folder
echo __________________
rmdir "%CD%\VIRTL\%SystemDrive::=%\Windows\System32" 2>nul
VirtLauncher64.exe -r -f -e cmd /c "%SystemDrive%\Windows\System32\cmd.exe /C echo hello2" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)

@rem no bug when i remove cmd /c even if a folder is similar to the executable folder exist in the virtual store
echo __________________
mkdir "%CD%\VIRTL\%SystemDrive::=%\Windows\System32" 2>nul
VirtLauncher64.exe -r -f -e %SystemDrive%\Windows\System32\cmd.exe /C echo hello3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


rmdir /Q /S "%CD%\VIRTL" 2>nul
pause
