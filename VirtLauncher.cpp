// ============================================================
// VirtLauncher.cpp  - Application Virtualization Launcher
//
// Launches an application with a virtual file system and
// virtual registry by injecting VirtHook[32|64].dll.
//
// Requires Microsoft Detours 4.0
//   https://github.com/microsoft/detours
//
// ============================================================
// Build instructions (see also BUILD.bat):
//
//  x86  (VS2010 x86 Native Tools Command Prompt):
//    cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp
//       /I<detours>\include /Fe:VirtLauncher32.exe
//       /link /SUBSYSTEM:CONSOLE
//       <detours>\lib.X86\detours.lib shlwapi.lib advapi32.lib
//
//  x64  (VS2010 x64 Native Tools Command Prompt):
//    cl /nologo /EHsc /O2 /MD /W3 VirtLauncher.cpp
//       /I<detours>\include /Fe:VirtLauncher64.exe
//       /link /SUBSYSTEM:CONSOLE
//       <detours>\lib.X64\detours.lib shlwapi.lib advapi32.lib
//
// NOTE: MinGW is NOT supported (Microsoft Detours requires MSVC).
//
// ============================================================
// Usage:
//   VirtLauncher.exe [-reg <HivePath>] [-fs <config.ini>] <app.exe> [args...]
//
//   -reg <HivePath>
//       Win32 registry path to use as the virtual root.
//       All app registry writes go here; reads show a merged view.
//       Examples:
//         -reg HKEY_CURRENT_USER\VirtLauncher
//         -reg HKCU\MyApp
//         -reg HKEY_LOCAL_MACHINE\SOFTWARE\VirtApps\Foo
//
//   -fs <config.ini>
//       Path to a file-system redirect config (INI format).
//       See below for format.
//
// FS Config File Format  (plain text, UTF-8 or ANSI):
//   # Comment lines start with # or ;
//   [redirect]
//   C:\OriginalPath=D:\RedirectedPath
//   C:\Program Files\MyApp=E:\Portable\MyApp
//
//   Rules:
//    - One redirect per line, format:  source=destination
//    - Paths are Win32 absolute paths
//    - Matching is case-insensitive prefix match on NT paths
//    - Longer/more-specific rules should come first
//    - Environment variables are NOT expanded
//
// Architecture notes:
//   Use VirtLauncher32.exe for 32-bit target apps.
//   Use VirtLauncher64.exe for 64-bit target apps.
//   The launcher auto-detects target bitness and warns on mismatch.
//   VirtHook32.dll / VirtHook64.dll must be in the same folder
//   as the launcher EXE.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <shlwapi.h>
#include <sddl.h>       // ConvertSidToStringSidW
#include <detours.h>

#include <stdio.h>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "detours.lib")

// ============================================================
// Utilities
// ============================================================

static bool StartsWithI(const std::wstring& s, const wchar_t* pfx) {
    size_t n = wcslen(pfx);
    return s.size() >= n && _wcsnicmp(s.c_str(), pfx, n) == 0;
}

// Return true if the PE at 'path' is a 64-bit image
static bool IsPe64(const wchar_t* path) {
    HANDLE hf = CreateFileW(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return false;

    DWORD rd = 0;
    IMAGE_DOS_HEADER dos = {};
    ReadFile(hf, &dos, sizeof(dos), &rd, NULL);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { CloseHandle(hf); return false; }

    SetFilePointer(hf, dos.e_lfanew, NULL, FILE_BEGIN);
    DWORD sig = 0;
    ReadFile(hf, &sig, 4, &rd, NULL);
    if (sig != IMAGE_NT_SIGNATURE)  { CloseHandle(hf); return false; }

    IMAGE_FILE_HEADER fh = {};
    ReadFile(hf, &fh, sizeof(fh), &rd, NULL);
    CloseHandle(hf);

    // return fh.Machine == IMAGE_FILE_MACHINE_AMD64 ||
    //        fh.Machine == IMAGE_FILE_MACHINE_IA64  ||
    //        fh.Machine == IMAGE_FILE_MACHINE_ARM64;
    
    return fh.Machine == IMAGE_FILE_MACHINE_AMD64;
}

// Build path to VirtHookNN.dll (same directory as this EXE)
static void BuildHookDllPath(wchar_t* out, size_t cch, bool want64) {
    wchar_t dir[MAX_PATH] = {};
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    PathRemoveFileSpecW(dir);
    _snwprintf(out, cch - 1, L"%s\\VirtHook%s.dll",
               dir, want64 ? L"64" : L"32");
    out[cch - 1] = L'\0';
}

// ============================================================
// Registry path conversion:  Win32  ->  NT  (\Registry\...)
// ============================================================

static std::wstring GetCurrentUserSid() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return L"";

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    std::vector<BYTE> buf(sz, 0);
    if (!GetTokenInformation(hToken, TokenUser, &buf[0], sz, &sz)) {
        CloseHandle(hToken);
        return L"";
    }
    CloseHandle(hToken);

    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(&buf[0]);
    LPWSTR sidStr = NULL;
    if (!ConvertSidToStringSidW(tu->User.Sid, &sidStr)) return L"";
    std::wstring sid(sidStr);
    LocalFree(sidStr);
    return sid;
}

// Convert  HKEY_CURRENT_USER\foo  (or HKCU\foo, etc.)
//       to  \Registry\User\<SID>\foo
static std::wstring RegWin32ToNt(const std::wstring& win32) {
    struct Mapping { const wchar_t* win32; const wchar_t* ntBase; bool needSid; };
    static const Mapping kMap[] = {
        { L"HKEY_LOCAL_MACHINE",  L"\\Registry\\Machine",               false },
        { L"HKLM",                L"\\Registry\\Machine",               false },
        { L"HKEY_CURRENT_USER",   L"\\Registry\\User\\",                true  },
        { L"HKCU",                L"\\Registry\\User\\",                true  },
        { L"HKEY_USERS",          L"\\Registry\\User",                  false },
        { L"HKU",                 L"\\Registry\\User",                  false },
        { L"HKEY_CLASSES_ROOT",   L"\\Registry\\Machine\\Software\\Classes", false },
        { L"HKCR",                L"\\Registry\\Machine\\Software\\Classes", false },
        { L"HKEY_CURRENT_CONFIG", L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current", false },
    };

    for (size_t i = 0; i < sizeof(kMap)/sizeof(kMap[0]); ++i) {
        const Mapping& m = kMap[i];
        if (!StartsWithI(win32, m.win32)) continue;

        size_t skip = wcslen(m.win32);
        std::wstring sub = win32.substr(skip);
        // strip leading backslash from subpath
        if (!sub.empty() && sub[0] == L'\\') sub = sub.substr(1);

        std::wstring base = m.ntBase;
        if (m.needSid) base += GetCurrentUserSid();

        if (sub.empty()) return base;
        return base + L"\\" + sub;
    }

    wprintf(L"Warning: Unrecognised hive in '%s', using path as-is.\n", win32.c_str());
    return win32;
}

// ============================================================
// Print Usage
// ============================================================

static void PrintUsage(const wchar_t* self) {
    wprintf(L"VirtLauncher - Application Virtualization Launcher\n");
    wprintf(L"Requires VirtHook32.dll / VirtHook64.dll alongside the EXE.\n\n");
    wprintf(L"Usage:\n");
    wprintf(L"  %s [-reg <HivePath>] [-fs <config.ini>] <app.exe> [app args...]\n\n",
            self);
    wprintf(L"Options:\n");
    wprintf(L"  -reg <HivePath>   Virtual registry root.\n");
    wprintf(L"                    e.g.  -reg HKCU\\VirtLauncher\n");
    wprintf(L"  -fs  <config.ini> File system redirect config.\n\n");
    wprintf(L"FS Config format (one redirect per line):\n");
    wprintf(L"  # Comment\n");
    wprintf(L"  [redirect]\n");
    wprintf(L"  C:\\OldPath=D:\\NewPath\n\n");
    wprintf(L"Architecture:\n");
    wprintf(L"  VirtLauncher32.exe + VirtHook32.dll  -> for 32-bit apps\n");
    wprintf(L"  VirtLauncher64.exe + VirtHook64.dll  -> for 64-bit apps\n\n");
    wprintf(L"Example:\n");
    wprintf(L"  VirtLauncher64.exe -reg HKCU\\VirtApp -fs redir.ini notepad.exe\n");
}

// ============================================================
// wmain
// ============================================================

int wmain(int argc, wchar_t* argv[]) {
    // Parse arguments
    std::wstring regPath;
    std::wstring fsConfig;
    int appIdx = 1;

    while (appIdx < argc) {
        if (_wcsicmp(argv[appIdx], L"-reg") == 0 && appIdx + 1 < argc) {
            regPath = argv[++appIdx];
        } else if (_wcsicmp(argv[appIdx], L"-fs") == 0 && appIdx + 1 < argc) {
            fsConfig = argv[++appIdx];
        } else if (_wcsicmp(argv[appIdx], L"-h") == 0 ||
                   _wcsicmp(argv[appIdx], L"--help") == 0 ||
                   _wcsicmp(argv[appIdx], L"/?") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else {
            break; // start of app exe + args
        }
        ++appIdx;
    }

    if (appIdx >= argc) {
        PrintUsage(argv[0]);
        return 1;
    }

    const wchar_t* appExe = argv[appIdx];

    // --------------------------------------------------------
    // Resolve full path of target EXE
    // --------------------------------------------------------
    wchar_t appFullPath[MAX_PATH] = {};
    if (!SearchPathW(NULL, appExe, L".exe", MAX_PATH, appFullPath, NULL)) {
        wcsncpy(appFullPath, appExe, MAX_PATH - 1);
        // Also try GetFullPathName in case it's a relative path
        if (GetFileAttributesW(appFullPath) == INVALID_FILE_ATTRIBUTES) {
            GetFullPathNameW(appExe, MAX_PATH, appFullPath, NULL);
        }
    }

    if (GetFileAttributesW(appFullPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"Error: Cannot find executable: %s\n", appExe);
        return 1;
    }

    // --------------------------------------------------------
    // Architecture detection
    // --------------------------------------------------------
    bool target64 = IsPe64(appFullPath);
    bool self64   = (sizeof(void*) == 8);

    wprintf(L"[VirtLauncher] Target : %s (%s)\n",
            appFullPath, target64 ? L"64-bit" : L"32-bit");
    wprintf(L"[VirtLauncher] Launcher: %s\n", self64 ? L"64-bit" : L"32-bit");

    if (target64 != self64) {
        wprintf(L"[VirtLauncher] Note: cross-arch launch (Detours will use rundll32 helper).\n");
    }

    // --------------------------------------------------------
    // Find the hook DLL
    // --------------------------------------------------------
    wchar_t dllPath[MAX_PATH] = {};
    BuildHookDllPath(dllPath, MAX_PATH, target64);

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        // Try same-arch DLL as fallback
        BuildHookDllPath(dllPath, MAX_PATH, self64);
        if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
            wprintf(L"Error: VirtHook DLL not found.\n"
                    L"       Expected: VirtHook%s.dll\n"
                    L"       In folder: %s\n",
                    target64 ? L"64" : L"32",
                    dllPath);
            return 1;
        }
        wprintf(L"[VirtLauncher] Using fallback DLL (arch mismatch may occur).\n");
    }

    wprintf(L"[VirtLauncher] Hook DLL: %s\n", dllPath);

    // --------------------------------------------------------
    // Set environment variables consumed by VirtHook.dll
    // --------------------------------------------------------
    if (!regPath.empty()) {
        std::wstring ntPath = RegWin32ToNt(regPath);
        SetEnvironmentVariableW(L"VIRTLAUNCHER_REG", ntPath.c_str());
        wprintf(L"[VirtLauncher] Reg VRoot : %s\n", ntPath.c_str());
        wprintf(L"                (Win32)  : %s\n", regPath.c_str());
    }

    if (!fsConfig.empty()) {
        wchar_t absFs[MAX_PATH] = {};
        GetFullPathNameW(fsConfig.c_str(), MAX_PATH, absFs, NULL);
        if (GetFileAttributesW(absFs) == INVALID_FILE_ATTRIBUTES) {
            wprintf(L"[VirtLauncher] Warning: FS config not found: %s\n", absFs);
        } else {
            SetEnvironmentVariableW(L"VIRTLAUNCHER_FS", absFs);
            wprintf(L"[VirtLauncher] FS Config : %s\n", absFs);
        }
    }

    // Store DLL path so the hook can propagate injection to children.
    // We set BOTH arch-specific paths so that a 32-bit hook inside a child
    // can correctly inject into a 64-bit grandchild and vice-versa.
    SetEnvironmentVariableW(L"VIRTLAUNCHER_DLL", dllPath);

    {
        wchar_t dll32[MAX_PATH] = {}, dll64[MAX_PATH] = {};
        BuildHookDllPath(dll32, MAX_PATH, false);  // VirtHook32.dll
        BuildHookDllPath(dll64, MAX_PATH, true);   // VirtHook64.dll
        if (GetFileAttributesW(dll32) != INVALID_FILE_ATTRIBUTES)
            SetEnvironmentVariableW(L"VIRTLAUNCHER_DLL32", dll32);
        if (GetFileAttributesW(dll64) != INVALID_FILE_ATTRIBUTES)
            SetEnvironmentVariableW(L"VIRTLAUNCHER_DLL64", dll64);
    }

    // --------------------------------------------------------
    // Build command line for target process
    // --------------------------------------------------------
    std::wstring cmdLine;
    for (int i = appIdx; i < argc; ++i) {
        if (i > appIdx) cmdLine += L' ';
        bool needQuote = (wcschr(argv[i], L' ')  != NULL ||
                          wcschr(argv[i], L'\t') != NULL ||
                          argv[i][0] == L'\0');
        if (needQuote) {
            cmdLine += L'"';
            // Escape interior backslashes before closing quotes
            for (const wchar_t* p = argv[i]; *p; ++p) {
                if (*p == L'"') cmdLine += L'\\';
                cmdLine += *p;
            }
            cmdLine += L'"';
        } else {
            cmdLine += argv[i];
        }
    }

    // Mutable buffer required by CreateProcess
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    wprintf(L"[VirtLauncher] Command  : %s\n\n", cmdLine.c_str());

    // --------------------------------------------------------
    // Prepare DLL path for Detours injection.
    //
    // Pass ONE DLL whose name ends in "32" or "64".
    // DetourCreateProcessWithDllsW auto-swaps the suffix when the target
    // process bitness differs from ours, then uses a rundll32 helper of the
    // matching arch to patch the import table.
    // DO NOT pass both 32 and 64 paths -- Detours would inject BOTH, and the
    // wrong-arch one crashes the process with 0xC000007B.
    // --------------------------------------------------------
    // Always use the launcher's own arch DLL as the "base" path; Detours
    // will swap "32"<->"64" if the target is a different bitness.
    char dllPathA[MAX_PATH] = {};
    {
        wchar_t ownDll[MAX_PATH] = {};
        BuildHookDllPath(ownDll, MAX_PATH, self64);   // our own arch
        WideCharToMultiByte(CP_ACP, 0, ownDll, -1, dllPathA, MAX_PATH, NULL, NULL);
    }
    const char* dlls[1] = { dllPathA };

    wprintf(L"[VirtLauncher] Injecting : %S\n", dllPathA);
    wprintf(L"               (Detours swaps 32<->64 automatically for cross-arch)\n");

    // --------------------------------------------------------
    // Launch target with DLL injection via Detours
    // --------------------------------------------------------
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = DetourCreateProcessWithDllsW(
        appFullPath,              // lpApplicationName
        &cmdBuf[0],               // lpCommandLine  (mutable)
        NULL,                     // lpProcessAttributes
        NULL,                     // lpThreadAttributes
        FALSE,                    // bInheritHandles
        CREATE_DEFAULT_ERROR_MODE,// dwCreationFlags
        NULL,                     // lpEnvironment  (inherited, includes VIRTLAUNCHER_*)
        NULL,                     // lpCurrentDirectory
        &si,
        &pi,
        1,                        // nDlls (one path; Detours swaps 32<->64 suffix as needed)
        dlls,                     // rlpDlls
        NULL                      // pfCreateProcessW (NULL = standard CreateProcessW)
    );

    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"Error: DetourCreateProcessWithDllsW failed (code %u).\n", err);
        if (err == ERROR_ELEVATION_REQUIRED)
            wprintf(L"       The target requires elevation. Run as Administrator.\n");
        else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            wprintf(L"       Check that the EXE and DLL paths are correct.\n");
        return 1;
    }

    wprintf(L"[VirtLauncher] Process started (PID %u). Waiting for exit...\n",
            pi.dwProcessId);

    // Wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"[VirtLauncher] Process exited with code %u (0x%X).\n",
            exitCode, exitCode);
    return static_cast<int>(exitCode);
}
