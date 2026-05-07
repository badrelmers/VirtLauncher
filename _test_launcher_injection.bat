@echo off
SETLOCAL
CD /D %~dp0

cd build
VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c "F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"

VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini "F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"


@rem _______________________________
VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe

VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe


@rem ________________________
VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c "F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"

VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini "F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"


@rem _________________________________
VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe

VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe




pause
