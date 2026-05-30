// Copyright 2026 Badr Elmers, https://github.com/badrelmers
//
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
// Build instructions (see BUILD.bat):
// NOTE: MinGW is NOT supported (Microsoft Detours requires MSVC).
//
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
// Global flags (set from CLI args or environment)
// ============================================================

static bool g_Verbose = false;  // --verbose / VLAUNCHER_VERBOSE
static bool g_Debug   = false;  // --debug   / VLAUNCHER_DEBUG

// Verbose-only informational output.
// Errors use wprintf directly so they always appear.
//
// Writes to two destinations simultaneously:
//   1. wprintf  -- the console window (existing behaviour).
//   2. OutputDebugStringW -- DebugView / any attached debugger,
//      using the same "[PID] message" format as VirtHook.dll's VL_INFO
//      so all [VirtLauncher] messages from every process in the tree
//      appear together in a single DebugView session.
//
// The trailing newline is stripped for OutputDebugString because
// DebugView adds its own line separator; wprintf keeps it for the console.
static void VL_INFO_impl(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list va;
    va_start(va, fmt);
    _vsnwprintf(buf, 2047, fmt, va);
    va_end(va);
    buf[2047] = L'\0';

    // Console output (original behaviour).
    wprintf(L"%s", buf);

    // DebugView output: strip trailing CR/LF so DebugView displays the
    // message on a single line, then prepend the PID as VirtHook.dll does.
    size_t len = wcslen(buf);
    while (len > 0 && (buf[len - 1] == L'\n' || buf[len - 1] == L'\r'))
        buf[--len] = L'\0';

    if (len > 0) {
        wchar_t dbg[2200];
        _snwprintf(dbg, 2199, L"[%u] %s", GetCurrentProcessId(), buf);
        dbg[2199] = L'\0';
        OutputDebugStringW(dbg);
    }
}
#define VL_INFO(...)  do { if (g_Verbose) VL_INFO_impl(__VA_ARGS__); } while(0)

// ============================================================
// Utilities
// ============================================================

// Check a boolean environment variable ("1", "true", "yes" → true).
static bool GetEnvBool(const wchar_t* name) {
    wchar_t buf[16] = {};
    if (GetEnvironmentVariableW(name, buf, 15) > 0)
        return (_wcsicmp(buf, L"1")    == 0 ||
                _wcsicmp(buf, L"true") == 0 ||
                _wcsicmp(buf, L"yes")  == 0);
    return false;
}

static bool StartsWithI(const std::wstring& s, const wchar_t* pfx) {
    size_t n = wcslen(pfx);
    return s.size() >= n && _wcsnicmp(s.c_str(), pfx, n) == 0;
}

// Return true if the PE at 'path' is a 64-bit image.
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

    return fh.Machine == IMAGE_FILE_MACHINE_AMD64;
}

// Build path to VirtHookNN.dll (same directory as this EXE).
static void BuildHookDllPath(wchar_t* out, size_t cch, bool want64) {
    wchar_t dir[MAX_PATH] = {};
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    PathRemoveFileSpecW(dir);
    _snwprintf(out, cch - 1, L"%s\\VirtHook%s.dll",
               dir, want64 ? L"64" : L"32");
    out[cch - 1] = L'\0';
}

// Recursively create all components of a directory path.
static void CreateFolderRecursive(const wchar_t* path) {
    if (!path || !path[0]) return;
    DWORD attr = GetFileAttributesW(path);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return; // already exists

    // Create parent first
    wchar_t parent[MAX_PATH];
    wcsncpy(parent, path, MAX_PATH - 1);
    parent[MAX_PATH - 1] = L'\0';
    PathRemoveFileSpecW(parent);

    if (parent[0] && wcscmp(parent, path) != 0)
        CreateFolderRecursive(parent);

    CreateDirectoryW(path, NULL);
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
// Optional-argument peek heuristics
// ============================================================
//
// --registry and --filesystem both take an *optional* value.  The parser
// peeks at the next token and uses these helpers to decide whether it is
// the flag's value or the start of the target command.  If the token is
// ambiguous the caller should use --exec to mark the command boundary
// explicitly.

// Returns true if 's' looks like a registry hive path that could be the
// value of --registry / -r.  Accepted prefixes (case-insensitive):
//   HKCU, HKLM, HKEY_, HKU, HKCR, \Registry\ .
static bool LooksLikeRegPath(const wchar_t* s) {
    if (!s || !s[0]) return false;
    static const wchar_t* kPfx[] = {
        L"HKCU", L"HKLM", L"HKEY_", L"HKU", L"HKCR", L"\\Registry\\"
    };
    for (size_t i = 0; i < sizeof(kPfx)/sizeof(kPfx[0]); ++i) {
        size_t n = wcslen(kPfx[i]);
        if (_wcsnicmp(s, kPfx[i], n) == 0) return true;
    }
    return false;
}

// Returns true if 's' looks like a filesystem path that could be the
// value of --filesystem / -f.  Accepted forms:
//   X:         drive-letter paths  (C:\foo, D:, etc.)
//   \\         UNC paths           (\\server\share)
//   .\  ..\    relative dot-paths
static bool LooksLikeFsPath(const wchar_t* s) {
    if (!s || !s[0]) return false;
    // Drive-letter path: X: or X:\... .
    if (s[1] == L':' && iswalpha(s[0])) return true;
    // UNC or \\?\ long-path
    if (s[0] == L'\\' && s[1] == L'\\') return true;
    // Explicit relative: .\ or ..\ .
    if (s[0] == L'.' && (s[1] == L'\\' || (s[1] == L'.' && s[2] == L'\\'))) return true;
    return false;
}

// ============================================================
// Print Help
// ============================================================

static void PrintUsage(const wchar_t* self) {
    wprintf(L"VirtLauncher - Application Virtualization Launcher\n");
    wprintf(L"Copyright 2026 Badr Elmers, https://github.com/badrelmers\n");

    wprintf(L"Requires VirtHook32.dll / VirtHook64.dll alongside the EXE.\n\n");

    wprintf(L"Usage:\n");
    wprintf(L"  VirtLauncher64.exe [options] --exec <app.exe> [app args...]\n");
    wprintf(L"  VirtLauncher64.exe [options] <app.exe> [app args...]   (see Ambiguity note)\n\n");

    wprintf(L"Options:\n");
    wprintf(L"  --verbose, -v\n");
    wprintf(L"      Print informational messages to stdout while launching.\n");
    wprintf(L"      Set VLAUNCHER_VERBOSE=1 as an alternative.\n\n");

    wprintf(L"  --debug, -d\n");
    wprintf(L"      Enable hook-level debug logging visible in Sysinternals DebugView.\n");
    wprintf(L"      Run DebugView as Administrator before launching.\n");
    wprintf(L"      Set VLAUNCHER_DEBUG=1 as an alternative.\n\n");

    wprintf(L"  --exec <app.exe> [args...], -e <app.exe> [args...]\n");
    wprintf(L"      Explicitly marks where the target command begins. Everything after\n");
    wprintf(L"      this flag is the application and its arguments. Use this whenever\n");
    wprintf(L"      -r or -f are used without an explicit hive/folder value, because\n");
    wprintf(L"      the parser cannot otherwise distinguish the app name from a flag\n");
    wprintf(L"      value.\n\n");

    wprintf(L"  --registry [HivePath], -r [HivePath]\n");
    wprintf(L"      Enable registry virtualisation. All writes from the target app go\n");
    wprintf(L"      to HivePath; reads show a merged view (virtual shadowing real).\n");
    wprintf(L"      HivePath is OPTIONAL. It is only consumed if the next token looks\n");
    wprintf(L"      like a hive path (starts with HKCU, HKLM, HKEY_*, HKU, HKCR, or\n");
    wprintf(L"      \\Registry\\). Default hive: HKCU\\VirtLauncher\n");
    wprintf(L"      When in doubt use --exec to mark the command boundary.\n\n");

    wprintf(L"  --filesystem [Folder], -f [Folder]\n");
    wprintf(L"      Enable filesystem virtualisation. All file writes from the target\n");
    wprintf(L"      app are redirected into Folder (organised by drive letter).\n");
    wprintf(L"      Reads check Folder first, then fall back to the real path.\n");
    wprintf(L"      Folder is OPTIONAL. It is only consumed if the next token looks\n");
    wprintf(L"      like a path (drive letter, UNC \\\\..., or relative .\\...).\n");
    wprintf(L"      Default: .\\VIRTL  (created if absent).\n");
    wprintf(L"      When in doubt use --exec to mark the command boundary.\n\n");

    wprintf(L"  --config <config.ini>, -c <config.ini>\n");
    wprintf(L"      Load explicit source=destination path redirect rules from an INI\n");
    wprintf(L"      file.  If --filesystem is also set, --config rules take precedence\n");
    wprintf(L"      (matched paths follow the INI; everything else goes to the folder).\n\n");

    wprintf(L"  --help, -h, /?\n");
    wprintf(L"      Show this help.\n\n");

    wprintf(L"Ambiguity note (-r and -f with optional values):\n");
    wprintf(L"  -r and -f accept an optional value.  The parser uses heuristics to\n");
    wprintf(L"  decide if the next token is the value or the start of the command:\n");
    wprintf(L"    -r: consumes the next token only if it starts with a known hive prefix.\n");
    wprintf(L"    -f: consumes the next token only if it starts with a drive letter,\n");
    wprintf(L"        \\\\ (UNC), or .\\ / ..\\ (relative dot-path).\n");
    wprintf(L"  Bare names (e.g. 'cmd', 'notepad') are never consumed as values.\n");
    wprintf(L"  For complete safety use --exec:\n");
    wprintf(L"    VirtLauncher64.exe -r -f --exec cmd /c echo hello\n\n");

    wprintf(L"FS Config file format  (--config):\n");
    wprintf(L"  # Lines starting with # or ; are comments\n");
    wprintf(L"  [redirect]\n");
    wprintf(L"  C:\\OldPath=D:\\NewPath\n");
    wprintf(L"  C:\\Program Files\\MyApp=E:\\Portable\\MyApp\n\n");
    wprintf(L"  [exclude]\n");
    wprintf(L"  C:\\Windows\n");
    wprintf(L"  C:\\Program Files\\CommonApp\n\n");
    wprintf(L"  Rules:\n");
    wprintf(L"    - One redirect per line: source=destination (Win32 absolute paths)\n");
    wprintf(L"    - Matching is case-insensitive prefix match on NT paths\n");
    wprintf(L"    - List more-specific rules before less-specific ones\n");
    wprintf(L"    - Environment variables are NOT expanded\n");
    wprintf(L"    - [exclude] paths are never virtualised; reads and writes always\n");
    wprintf(L"      go to the real folder even when --filesystem or [redirect] would\n");
    wprintf(L"      otherwise cover them. Exclusions take priority over all redirects.\n\n");

    wprintf(L"Architecture:\n");
    wprintf(L"  Either launcher can target either bitness -- Detours automatically\n");
    wprintf(L"  selects VirtHook32.dll or VirtHook64.dll to match the target process.\n\n");
    wprintf(L"  VirtLauncher32.exe -- runs on both 32-bit and 64-bit Windows:\n");
    wprintf(L"    32-bit OS : can only launch 32-bit target apps (OS limitation)\n");
    wprintf(L"    64-bit OS : can launch both 32-bit and 64-bit target apps\n\n");
    wprintf(L"  VirtLauncher64.exe -- runs on 64-bit Windows only:\n");
    wprintf(L"    64-bit OS : can launch both 32-bit and 64-bit target apps\n\n");
    wprintf(L"  Both VirtHook32.dll and VirtHook64.dll must be present in the same\n");
    wprintf(L"  folder as the launcher EXE for cross-arch injection to work.\n\n");

    wprintf(L"Environment variables (user-settable):\n");
    wprintf(L"  VLAUNCHER_VERBOSE=1   Same effect as --verbose\n");
    wprintf(L"  VLAUNCHER_DEBUG=1     Same effect as --debug\n\n");

    wprintf(L"Internal environment variables (set automatically, do not set manually):\n");
    wprintf(L"  VIRTLAUNCHER_REG   NT registry base path passed to VirtHook.dll\n");
    wprintf(L"  VIRTLAUNCHER_FS    Path to the FS redirect config INI for VirtHook.dll\n");
    wprintf(L"  VIRTLAUNCHER_FSDIR Virtual store root folder path for VirtHook.dll\n");
    wprintf(L"  VIRTLAUNCHER_DLL   Absolute path to VirtHook DLL for child injection\n\n");
    wprintf(L"  This vars are set automatically by the launcher for VirtHook.dll -- do\n");
    wprintf(L"  not set these manually unless you are doing advanced custom injection.\n\n");
    
    wprintf(L"Notes:\n");
    wprintf(L"  - Run as Administrator if the target requires elevation.\n\n");
    

    wprintf(L"Examples:\n");
    wprintf(L"  # Registry virtualisation with explicit hive\n");
    wprintf(L"  VirtLauncher64.exe -r HKCU\\VirtApp notepad.exe\n\n");

    wprintf(L"  # Registry virtualisation with default hive -- use --exec to avoid\n");
    wprintf(L"  # ambiguity between the hive and the app name\n");
    wprintf(L"  VirtLauncher64.exe -r --exec notepad.exe\n");
    wprintf(L"  VirtLauncher64.exe -r --exec cmd /c echo hello\n\n");

    wprintf(L"  # Filesystem virtualisation with default folder -- same pattern\n");
    wprintf(L"  VirtLauncher64.exe -f --exec notepad.exe\n");
    wprintf(L"  VirtLauncher64.exe -f --exec cmd /c echo hello\n\n");

    wprintf(L"  # Filesystem virtualisation with explicit folder (path heuristic works)\n");
    wprintf(L"  VirtLauncher64.exe -f D:\\MySandbox notepad.exe\n\n");

    wprintf(L"  # Both -r and -f with defaults, explicit command boundary\n");
    wprintf(L"  VirtLauncher64.exe -r -f --exec cmd /c echo hello\n\n");

    wprintf(L"  # Redirect specific paths via INI config only\n");
    wprintf(L"  VirtLauncher64.exe --config redir.ini notepad.exe\n\n");

    wprintf(L"  # INI config for specific paths + catch-all virtual folder for everything else\n");
    wprintf(L"  VirtLauncher64.exe --config redir.ini -f D:\\Sandbox notepad.exe\n\n");

    wprintf(L"  # Full virtualisation: registry + filesystem + verbose output\n");
    wprintf(L"  VirtLauncher64.exe -v -r HKCU\\VirtApp -f D:\\Sandbox --exec installer.exe /SILENT\n\n");

}

// ============================================================
// wmain
// ============================================================

int wmain(int argc, wchar_t* argv[]) {
    // --- Read env-var defaults before parsing CLI (CLI overrides) ---
    g_Verbose = GetEnvBool(L"VLAUNCHER_VERBOSE");
    g_Debug   = GetEnvBool(L"VLAUNCHER_DEBUG");

    // --- Parse arguments ---
    std::wstring regPath;
    bool         regEnabled   = false;
    std::wstring fsConfig;        // --config  INI file
    std::wstring fsFolder;        // --filesystem  virtual store folder
    bool         fsDirEnabled = false;
    bool         execSeen     = false;   // --exec / -e encountered
    int appIdx = 1;

    while (appIdx < argc) {
        const wchar_t* arg = argv[appIdx];

        // --exec / -e : everything that follows is the target command.
        // Advance past the flag itself and break immediately so appIdx
        // points at the executable.
        if (_wcsicmp(arg, L"--exec") == 0 || _wcsicmp(arg, L"-e") == 0) {
            execSeen = true;
            ++appIdx;
            break;
        }

        if (_wcsicmp(arg, L"--verbose") == 0 || _wcsicmp(arg, L"-v") == 0) {
            g_Verbose = true;
        }
        else if (_wcsicmp(arg, L"--debug") == 0 || _wcsicmp(arg, L"-d") == 0) {
            g_Debug = true;
        }
        else if (_wcsicmp(arg, L"--registry") == 0 || _wcsicmp(arg, L"-r") == 0) {
            regEnabled = true;
            // Consume the next token as the hive path ONLY if it looks like
            // a registry path.  A bare name like "cmd" or "notepad" is not a
            // hive and must not be stolen from the command.
            if (appIdx + 1 < argc && LooksLikeRegPath(argv[appIdx + 1])) {
                regPath = argv[++appIdx];
            } else {
                regPath = L"HKCU\\VirtLauncher";
            }
        }
        else if (_wcsicmp(arg, L"--config") == 0 || _wcsicmp(arg, L"-c") == 0) {
            if (appIdx + 1 < argc) {
                fsConfig = argv[++appIdx];
            } else {
                wprintf(L"Error: --config requires an INI file path argument.\n");
                return 1;
            }
        }
        else if (_wcsicmp(arg, L"--filesystem") == 0 || _wcsicmp(arg, L"-f") == 0) {
            fsDirEnabled = true;
            // Consume the next token as the folder ONLY if it looks like a
            // filesystem path (drive letter, UNC, or relative dot-path).
            // A bare name like "cmd" is not a path and must not be stolen.
            if (appIdx + 1 < argc && LooksLikeFsPath(argv[appIdx + 1])) {
                fsFolder = argv[++appIdx];
            }
            // else resolved to default (.\VIRTL) below
        }
        else if (_wcsicmp(arg, L"-h") == 0 ||
                 _wcsicmp(arg, L"--help") == 0 ||
                 _wcsicmp(arg, L"/?") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else {
            break; // start of app exe + args (no --exec, legacy style)
        }
        ++appIdx;
    }

    if (appIdx >= argc) {
        if (execSeen)
            wprintf(L"Error: --exec requires an application path.\n");
        else
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
        if (GetFileAttributesW(appFullPath) == INVALID_FILE_ATTRIBUTES)
            GetFullPathNameW(appExe, MAX_PATH, appFullPath, NULL);
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

    VL_INFO(L"[VirtLauncher] Target : %s (%s)\n",
            appFullPath, target64 ? L"64-bit" : L"32-bit");
    VL_INFO(L"[VirtLauncher] Launcher: %s\n", self64 ? L"64-bit" : L"32-bit");

    if (target64 != self64) {
        VL_INFO(L"[VirtLauncher] Note: cross-arch launch (Detours will use rundll32 helper).\n");
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
        VL_INFO(L"[VirtLauncher] Using fallback DLL (arch mismatch may occur).\n");
    }

    VL_INFO(L"[VirtLauncher] Hook DLL: %s\n", dllPath);

    // --------------------------------------------------------
    // Propagate verbose/debug flags to child processes
    // --------------------------------------------------------
    if (g_Verbose) SetEnvironmentVariableW(L"VLAUNCHER_VERBOSE", L"1");
    if (g_Debug)   SetEnvironmentVariableW(L"VLAUNCHER_DEBUG",   L"1");

    // --------------------------------------------------------
    // Set environment variables consumed by VirtHook.dll
    // --------------------------------------------------------

    // Registry virtualisation
    if (regEnabled && !regPath.empty()) {
        std::wstring ntPath = RegWin32ToNt(regPath);
        SetEnvironmentVariableW(L"VIRTLAUNCHER_REG", ntPath.c_str());
        VL_INFO(L"[VirtLauncher] Reg VRoot : %s\n", ntPath.c_str());
        VL_INFO(L"                (Win32)  : %s\n", regPath.c_str());
    }

    // FS redirect via config INI (--config, takes precedence over --filesystem)
    if (!fsConfig.empty()) {
        wchar_t absFs[MAX_PATH] = {};
        GetFullPathNameW(fsConfig.c_str(), MAX_PATH, absFs, NULL);
        if (GetFileAttributesW(absFs) == INVALID_FILE_ATTRIBUTES) {
            wprintf(L"[VirtLauncher] Warning: FS config not found: %s\n", absFs);
        } else {
            SetEnvironmentVariableW(L"VIRTLAUNCHER_FS", absFs);
            VL_INFO(L"[VirtLauncher] FS Config : %s\n", absFs);
        }
    }

    // FS virtualisation via virtual store folder (--filesystem)
    if (fsDirEnabled) {
        if (fsFolder.empty()) {
            // Default: .\VIRTL  (current working directory)
            wchar_t cwd[MAX_PATH] = {};
            GetCurrentDirectoryW(MAX_PATH, cwd);
            std::wstring virtl = std::wstring(cwd) + L"\\VIRTL";
            fsFolder = virtl;
        }
        // Resolve to absolute path
        wchar_t absFsDir[MAX_PATH] = {};
        GetFullPathNameW(fsFolder.c_str(), MAX_PATH, absFsDir, NULL);
        // Create directory if it doesn't exist
        CreateFolderRecursive(absFsDir);
        SetEnvironmentVariableW(L"VIRTLAUNCHER_FSDIR", absFsDir);
        VL_INFO(L"[VirtLauncher] FS VRoot  : %s\n", absFsDir);
        if (!fsConfig.empty()) {
            VL_INFO(L"               (--config rules take precedence for matched paths)\n");
        }
    }

    // Store DLL paths so the hook can propagate injection to children.
    // Set BOTH arch-specific paths so a 32-bit hook inside a child can inject
    // into a 64-bit grandchild and vice-versa.
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

    VL_INFO(L"[VirtLauncher] Command  : %s\n", cmdLine.c_str());

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

    VL_INFO(L"[VirtLauncher] Injecting : %S\n", dllPathA);
    VL_INFO(L"               (Detours swaps 32<->64 automatically for cross-arch)\n");

    // --------------------------------------------------------
    // Launch target with DLL injection via Detours.
    //
    // CRITICAL for 32-bit launcher: disable WOW64 FS redirection so that:
    //   1. SearchPathW finds cmd.exe / target.exe from real System32 (64-bit),
    //      not SysWOW64 (32-bit) when the user types an unqualified name.
    //   2. Inside DetourCreateProcessWithDllsW, when it needs to spawn a
    //      cross-arch helper, GetSystemDirectory() returns the real System32
    //      with the 64-bit rundll32.exe, not the 32-bit one from SysWOW64.
    // This is a no-op in the 64-bit launcher build.
    // --------------------------------------------------------
    PVOID wow64Old = NULL;
    BOOL  wow64Off = FALSE;
    {
        typedef BOOL (WINAPI *PfnDisable)(PVOID*);
        PfnDisable pfn = (PfnDisable)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "Wow64DisableWow64FsRedirection");
        if (pfn) wow64Off = pfn(&wow64Old);
    }

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
        NULL,                     // lpEnvironment  (inherited environment (includes all VIRTLAUNCHER_* vars))
        NULL,                     // lpCurrentDirectory
        &si,
        &pi,
        1,                        // nDlls (one path; Detours swaps 32<->64 suffix as needed)
        dlls,                     // rlpDlls
        NULL                      // pfCreateProcessW (NULL = real CreateProcessW, no re-entry risk)
    );

    // Restore WOW64 FS redirection immediately after process creation.
    if (wow64Off) {
        typedef BOOL (WINAPI *PfnRevert)(PVOID);
        PfnRevert pfn = (PfnRevert)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
        if (pfn) pfn(wow64Old);
    }

    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"Error: DetourCreateProcessWithDllsW failed (code %u).\n", err);
        if (err == ERROR_ELEVATION_REQUIRED)
            wprintf(L"       The target requires elevation. Run as Administrator.\n");
        else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            wprintf(L"       Check that the EXE and DLL paths are correct.\n");
        return 1;
    }

    VL_INFO(L"[VirtLauncher] Process started (PID %u). Waiting for exit...\n",
            pi.dwProcessId);

    // Wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    VL_INFO(L"[VirtLauncher] Process exited with code %u (0x%X).\n",
            exitCode, exitCode);
    return static_cast<int>(exitCode);
}
