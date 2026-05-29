# VirtLauncher - Virtualization Launcher
Launches an application with a virtual file system and virtual registry by injecting VirtHook[32|64].dll.

# Security:
is this a sandboxie alternative?
NO! sandboxie have better security sandboxing, i never had in mind security when i made this tool, in fact even sandboxie cannot be used safely to run unsecure code, so this tool should not be used for secure sandboxing, this is just a babysitter not a criminal prison

# Build instructions:
  - Install Visual Studio 10 or Windows SDK 7.1 for Windows 7
  - use BUILD.bat
  - Requires Microsoft Detours 4.0  https://github.com/microsoft/detours which is already included in this repo
  
NOTE: MinGW is NOT supported (Microsoft Detours requires MSVC).
i think i m wrong:
// Allow Detours to cleanly compile with the MingW toolchain.
 https://github.com/microsoft/Detours/blob/f4c0fc91b8a93fc09ccbbd6e4277efe6872784fe/src/detours.h#L53 

VirtLauncher is compatible with what Detours is compatible with. Detours is compatible with the Windows NT family of operating systems: Windows NT, Windows XP, Windows Server 2003, Windows 7, Windows 8, Windows 10, and Windows 11. It cannot be used by Windows Store apps because Detours requires APIs not available to those applications.



Copyright (c) 2026 Badr Elmers, https://github.com/badrelmers/VirtLauncher
