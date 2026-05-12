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
color 2F

set "currdir=%CD%"
@rem remove :
set "currdir=%currdir::=%"
@rem echo currdir: %currdir%

mkdir VIRTL 2>nul
rmdir /Q /S VIRTL || (echo error & pause & exit)

@rem echo c:\=d:\z1>redir.ini
@rem echo d:\=d:\z2>>redir.ini
@rem echo e:\=d:\z3>>redir.ini
@rem echo f:\=d:\z4>>redir.ini

@rem echo c:\=d:\z1\>redir.ini
@rem echo d:\=d:\z2\>>redir.ini
@rem echo e:\=d:\z3\>>redir.ini
@rem echo f:\=d:\z4\>>redir.ini

@rem echo c:\=d:\z>redir.ini
@rem echo d:\=d:\z>>redir.ini
@rem echo e:\=d:\z>>redir.ini
@rem echo f:\=d:\z>>redir.ini

echo c:\=d:\z\>redir.ini
echo d:\=d:\z\>>redir.ini
echo e:\=d:\z\>>redir.ini
echo f:\=d:\z\>>redir.ini
echo [exclude]>>redir.ini
echo C:\ccc\excluded>>redir.ini
mkdir C:\ccc\excluded
VirtLauncher64.exe -r -c redir.ini -e "%TEST64_PATH%"



pause
exit


