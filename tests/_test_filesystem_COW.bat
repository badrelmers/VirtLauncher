@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________

@rem dont use tasklist to list exe dll, it does not list all dll of x32 exe!! use listdlls


:: --- Configuration ---
set "TEST32_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe"
set "TEST64_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"
set "LISTDLLS_EXE=%~dp0ListDlls\listdlls64.exe"
set "BUILD_DIR=..\build"

@rem ___________________________________________________________
:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

:: Counters
set /a SUCCESS_COUNT=0
set /a FAIL_COUNT=0

if not exist "%BUILD_DIR%" (
    echo [ERROR] Build directory not found. Please build the project first.
    pause
    exit /b
)

cd "%BUILD_DIR%"

echo ============================================================
echo  VirtLauncher Injection Test Suite
echo ============================================================


@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtApp -f sandbox  cmd /c %cd%\sandbox\TE64.exe
@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtApp -f sandbox -e cmd /c "F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox\TE64.exe"
@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtApp -f F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox -e cmd /c "F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox\TE64.exe"

@rem cannot find api ms win service code l1 1 0 dll
@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtApp -f F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox -e "F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox\TE64.exe"

@rem VirtLauncher64.exe -r HKEY_CURRENT_USER\VirtApp -f F:\_bin\_src\_launcher_virtualization\__VirtLauncher\_claude\files\git\build\sandbox -e %TEST64_PATH%"




set "currdir=%CD%"
@rem remove :
set "currdir=%currdir::=%"
@rem echo currdir: %currdir%

mkdir VIRTL 2>nul
rmdir /Q /S VIRTL || (echo error & pause & exit)



echo ______write to absolute path
VirtLauncher64.exe -r -f -e cmd /c "mkdir c:\ccc & echo fff>c:\ccc\absolute"
if exist "%CD%\VIRTL\c\ccc\absolute" (
    echo good 
) else (
    echo bad
)


echo ______write to relative path
VirtLauncher64.exe -r -f -e cmd /c "mkdir ccc & echo fff>ccc\relative"
if exist "%CD%\VIRTL\%currdir%\ccc\relative" (
    echo good 
) else (
    echo bad
)


echo ______read from relative path
echo bad>rrr
echo good> "%CD%\VIRTL\%currdir%\rrr"
VirtLauncher64.exe -r -f -e cmd /c "type rrr"
del rrr


echo ______merged view
mkdir "%CD%\VIRTL\c"
echo zzz>"%CD%\VIRTL\c\virtttt"
VirtLauncher64.exe -r -f -e cmd /c "dir /B c:\ " | findstr Windows
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    echo bad
)


echo ______tombstone
mkdir c:\ccc 2>nul
echo real>c:\ccc\delll
VirtLauncher64.exe -r -f -e cmd /c "echo virttt>c:\ccc\delll & del c:\ccc\delll"
if exist "%CD%\VIRTL\c\ccc\delll.vl_deleted" (
    echo good 
) else (
    echo bad
)


pause
echo ______merged view using TablacusExplorer
VirtLauncher64.exe -r -f -e "%TEST64_PATH%"



pause
exit


