// ============================================================
// VirtHook.cpp  - VirtLauncher Hook DLL
// Injected into target process by VirtLauncher.exe via Detours
//
// Virtualizes:
//   Registry : NtOpenKey, NtOpenKeyEx, NtCreateKey, NtQueryKey,
//              NtEnumerateKey, NtEnumerateValueKey, NtQueryValueKey,
//              NtSetValueKey, NtDeleteKey, NtDeleteValueKey,
//              NtNotifyChangeKey, NtClose
//   Files    : NtCreateFile, NtOpenFile
//   Children : CreateProcessW/A (propagate injection)
//
// Config via environment variables set by VirtLauncher.exe:
//   VIRTLAUNCHER_REG = NT reg base  e.g. \Registry\User\SID\VirtApp
//   VIRTLAUNCHER_FS  = path to FS redirect config file
//   VIRTLAUNCHER_DLL = absolute path to this DLL (for child injection)
//
// Build x86  (run from VS2010 x86 command prompt):
//   cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp
//      /I<detours>\include /Fe:VirtHook32.dll
//      /link /DLL <detours>\lib.X86\detours.lib
//
// Build x64  (run from VS2010 x64 command prompt):
//   cl /nologo /EHsc /O2 /MD /W3 /LD VirtHook.cpp
//      /I<detours>\include /Fe:VirtHook64.dll
//      /link /DLL <detours>\lib.X64\detours.lib
//
// NOTE: MinGW is NOT supported -- Microsoft Detours requires MSVC.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <detours.h>

// DetourFinishHelperProcess is exported as ordinal 1 via VirtHook.def
// DetourRestoreAfterWith() is called in DllMain DLL_PROCESS_ATTACH below

#include <string>
#include <vector>
#include <map>
#include <algorithm>

// ============================================================
// Debug logging -- output visible in Sysinternals DebugView
// (run DebugView as admin before launching VirtLauncher).
// Set VL_DEBUG 0 to disable for release builds.
// ============================================================
#define VL_DEBUG 1
#if VL_DEBUG
static void VL_DBG(const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list va;
    va_start(va, fmt);
    _vsnwprintf(buf, 1023, fmt, va);
    va_end(va);
    buf[1023] = L'\0';
    
    // Prefix so DebugView filter is easy
    // Combine into a single buffer for one output call
    wchar_t fullbuf[2048];
    wcscpy(fullbuf, L"[VirtHook] ");
    wcscat(fullbuf, buf);
    wcscat(fullbuf, L"\n");

    OutputDebugStringW(fullbuf);
}
#else
static inline void VL_DBG(const wchar_t*, ...) {}
#endif

// ============================================================
// NT Type Definitions
// (winternl.h omitted to avoid redefinition conflicts)
// ============================================================

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#  define NT_SUCCESS(s)  (((NTSTATUS)(s)) >= 0)
#endif

#define VL_STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define VL_STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define VL_STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#define VL_STATUS_BUFFER_OVERFLOW      ((NTSTATUS)0x80000005L)
#define VL_STATUS_OBJECT_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#define VL_STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)
#define VL_STATUS_INVALID_HANDLE       ((NTSTATUS)0xC0000008L)

#ifndef OBJ_CASE_INSENSITIVE
#  define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif

typedef struct _VL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} VL_UNICODE_STRING, *PVL_UNICODE_STRING;

typedef struct _VL_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PVL_UNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} VL_OBJECT_ATTRIBUTES, *PVL_OBJECT_ATTRIBUTES;

typedef struct _VL_IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} VL_IO_STATUS_BLOCK, *PVL_IO_STATUS_BLOCK;

typedef VOID (NTAPI *VL_PIO_APC_ROUTINE)(PVOID, PVL_IO_STATUS_BLOCK, ULONG);

// Registry information classes
typedef enum _VL_KEY_INFORMATION_CLASS {
    VlKeyBasicInformation     = 0,
    VlKeyNodeInformation      = 1,
    VlKeyFullInformation      = 2,
    VlKeyNameInformation      = 3,
    VlKeyCachedInformation    = 4
} VL_KEY_INFORMATION_CLASS;

typedef enum _VL_KEY_VALUE_INFORMATION_CLASS {
    VlKeyValueBasicInformation    = 0,
    VlKeyValueFullInformation     = 1,
    VlKeyValuePartialInformation  = 2
} VL_KEY_VALUE_INFORMATION_CLASS;

#pragma pack(push,4)
typedef struct _VL_KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength; // bytes
    WCHAR         Name[1];
} VL_KEY_BASIC_INFORMATION;

typedef struct _VL_KEY_NAME_INFORMATION {
    ULONG NameLength; // bytes
    WCHAR Name[1];
} VL_KEY_NAME_INFORMATION;

typedef struct _VL_KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} VL_KEY_FULL_INFORMATION;

typedef struct _VL_KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;  // bytes
    WCHAR Name[1];
} VL_KEY_VALUE_BASIC_INFORMATION;

typedef struct _VL_KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} VL_KEY_VALUE_FULL_INFORMATION;

typedef struct _VL_KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} VL_KEY_VALUE_PARTIAL_INFORMATION;
#pragma pack(pop)

// ============================================================
// NT Function Pointer Types
// ============================================================

typedef NTSTATUS (NTAPI *PfnNtOpenKey)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtOpenKeyEx)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG);

typedef NTSTATUS (NTAPI *PfnNtCreateKey)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, PVL_UNICODE_STRING, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtEnumerateKey)
    (HANDLE, ULONG, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtEnumerateValueKey)
    (HANDLE, ULONG, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryKey)
    (HANDLE, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryValueKey)
    (HANDLE, PVL_UNICODE_STRING, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtSetValueKey)
    (HANDLE, PVL_UNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *PfnNtDeleteKey)    (HANDLE);
typedef NTSTATUS (NTAPI *PfnNtDeleteValueKey)(HANDLE, PVL_UNICODE_STRING);

typedef NTSTATUS (NTAPI *PfnNtNotifyChangeKey)
    (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK,
     ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);

typedef NTSTATUS (NTAPI *PfnNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *PfnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtCreateFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK,
     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *PfnNtOpenFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryFullAttributesFile)
    (PVL_OBJECT_ATTRIBUTES, PVOID);

typedef NTSTATUS (NTAPI *PfnNtSetInformationFile)
    (HANDLE, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);

typedef BOOL (WINAPI *PfnCreateProcessW)
    (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef BOOL (WINAPI *PfnCreateProcessA)
    (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

typedef BOOL (WINAPI *PfnMoveFileExW)(LPCWSTR, LPCWSTR, DWORD);

typedef DWORD (WINAPI *PfnGetFileAttributesW)(LPCWSTR);
typedef BOOL  (WINAPI *PfnGetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);

typedef HANDLE (WINAPI *PfnFindFirstFileExW)
    (LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);

// ============================================================
// Global State
// ============================================================

// Original (real) function pointers -- modified by Detours in-place
static PfnNtOpenKey            Real_NtOpenKey;
static PfnNtOpenKeyEx          Real_NtOpenKeyEx;
static PfnNtCreateKey          Real_NtCreateKey;
static PfnNtEnumerateKey       Real_NtEnumerateKey;
static PfnNtEnumerateValueKey  Real_NtEnumerateValueKey;
static PfnNtQueryKey           Real_NtQueryKey;
static PfnNtQueryValueKey      Real_NtQueryValueKey;
static PfnNtSetValueKey        Real_NtSetValueKey;
static PfnNtDeleteKey          Real_NtDeleteKey;
static PfnNtDeleteValueKey     Real_NtDeleteValueKey;
static PfnNtNotifyChangeKey    Real_NtNotifyChangeKey;
static PfnNtClose              Real_NtClose;
static PfnNtQueryObject        Real_NtQueryObject;
static PfnNtCreateFile         Real_NtCreateFile;
static PfnNtOpenFile                Real_NtOpenFile;
static PfnNtQueryFullAttributesFile Real_NtQueryFullAttributesFile;
static PfnNtSetInformationFile Real_NtSetInformationFile;
static PfnCreateProcessW       Real_CreateProcessW;
static PfnCreateProcessA       Real_CreateProcessA;
static PfnMoveFileExW          Real_MoveFileExW;
static PfnGetFileAttributesW   Real_GetFileAttributesW;
static PfnGetFileAttributesExW Real_GetFileAttributesExW;
static PfnFindFirstFileExW     Real_FindFirstFileExW;

// Config flags
static bool g_RegEnabled = false;
static bool g_FsEnabled  = false;

// Registry virtualisation:
//   g_VirtNtBase = e.g.  \Registry\User\S-1-5-21-x\VirtApp
//   g_RealNtBase = parent e.g. \Registry\User\S-1-5-21-x
static std::wstring g_VirtNtBase;
static std::wstring g_RealNtBase;

// FS redirections: vector of (nt_from_prefix, nt_to_prefix)
static std::vector< std::pair<std::wstring,std::wstring> > g_FsRedirects;

// Tracked virtual registry handles
struct VirtKeyEntry {
    HANDLE       hVirt;   // handle to VirtNtBase\X  (NULL if none)
    HANDLE       hReal;   // handle to RealNtBase\X  (NULL if none)
    std::wstring logPath; // LOGICAL NT path (under RealNtBase)
};
static std::map<HANDLE, VirtKeyEntry> g_KeyMap;
static CRITICAL_SECTION g_KeyMapLock;

// TLS index for reentrancy guard
static DWORD g_TlsIdx = TLS_OUT_OF_INDEXES;

// DLL path (ANSI) for child process injection
static char g_DllPathA[MAX_PATH];

// ============================================================
// Inline helpers
// ============================================================

static inline bool IsReentrant() {
    return g_TlsIdx != TLS_OUT_OF_INDEXES &&
           TlsGetValue(g_TlsIdx) != NULL;
}
static inline void SetReentrant(bool v) {
    if (g_TlsIdx != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_TlsIdx, v ? (PVOID)1 : NULL);
}

static inline bool StartsWithI(const std::wstring& s, const std::wstring& pfx) {
    return s.size() >= pfx.size() &&
           _wcsnicmp(s.c_str(), pfx.c_str(), pfx.size()) == 0;
}

static inline void MakeUStr(VL_UNICODE_STRING* us, const std::wstring& s) {
    us->Buffer         = const_cast<PWSTR>(s.c_str());
    us->Length         = static_cast<USHORT>(s.size() * sizeof(WCHAR));
    us->MaximumLength  = us->Length + sizeof(WCHAR);
}

static inline std::wstring FromUStr(const VL_UNICODE_STRING* us) {
    if (!us || !us->Buffer || us->Length == 0) return L"";
    return std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
}

static inline void MakeOA(VL_OBJECT_ATTRIBUTES* oa,
                           VL_UNICODE_STRING* name,
                           ULONG attrs = OBJ_CASE_INSENSITIVE)
{
    oa->Length                   = sizeof(VL_OBJECT_ATTRIBUTES);
    oa->RootDirectory            = NULL;
    oa->ObjectName               = name;
    oa->Attributes               = attrs;
    oa->SecurityDescriptor       = NULL;
    oa->SecurityQualityOfService = NULL;
}

// ============================================================
// Registry handle map helpers  (lock must be held by caller
// for TrackHandle / UntrackHandle, but GetEntry locks itself)
// ============================================================

static void TrackHandle(HANDLE h, HANDLE hVirt, HANDLE hReal,
                         const std::wstring& logPath)
{
    VirtKeyEntry e;
    e.hVirt   = hVirt;
    e.hReal   = hReal;
    e.logPath = logPath;
    EnterCriticalSection(&g_KeyMapLock);
    g_KeyMap[h] = e;
    LeaveCriticalSection(&g_KeyMapLock);
}

static void UntrackHandle(HANDLE h) {
    EnterCriticalSection(&g_KeyMapLock);
    g_KeyMap.erase(h);
    LeaveCriticalSection(&g_KeyMapLock);
}

static bool GetEntry(HANDLE h, VirtKeyEntry& out) {
    EnterCriticalSection(&g_KeyMapLock);
    std::map<HANDLE,VirtKeyEntry>::iterator it = g_KeyMap.find(h);
    if (it != g_KeyMap.end()) { out = it->second; }
    bool found = (it != g_KeyMap.end());
    LeaveCriticalSection(&g_KeyMapLock);
    return found;
}

// ============================================================
// Path Resolution
// ============================================================

// Return the LOGICAL NT path for a registry handle.
// For tracked virtual handles we return the stored logical path.
// For untracked handles we call Real_NtQueryKey (returns physical path
// which for untracked handles equals the logical path).
static std::wstring GetHandleLogicalPath(HANDLE h) {
    if (!h) return L"";

    // Check our own tracking map first
    VirtKeyEntry e;
    if (GetEntry(h, e)) {
        VL_DBG(L"GetHandleLogicalPath: tracked handle -> %s", e.logPath.c_str());
        return e.logPath;
    }

    // Strategy 1: NtQueryObject(ObjectNameInformation) = class 1
    // Returns full NT path like \REGISTRY\USER\SID\key -- works on XP+
    // and doesn't require KEY_QUERY_VALUE (unlike some NtQueryKey classes).
    if (Real_NtQueryObject) {
        std::vector<BYTE> buf(2048, 0);
        ULONG resultLen = 0;
        // ObjectNameInformation = 1
        NTSTATUS st = Real_NtQueryObject(h, 1, &buf[0], (ULONG)buf.size(), &resultLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            buf.assign(resultLen + 8, 0);
            st = Real_NtQueryObject(h, 1, &buf[0], (ULONG)buf.size(), &resultLen);
        }
        if (NT_SUCCESS(st) && resultLen >= sizeof(VL_UNICODE_STRING)) {
            VL_UNICODE_STRING* us = reinterpret_cast<VL_UNICODE_STRING*>(&buf[0]);
            if (us->Buffer && us->Length > 0) {
                std::wstring path = std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
                VL_DBG(L"GetHandleLogicalPath: NtQueryObject -> %s", path.c_str());
                return path;
            }
        }
        VL_DBG(L"GetHandleLogicalPath: NtQueryObject failed st=0x%08X, trying NtQueryKey", (ULONG)st);
    }

    // Strategy 2: NtQueryKey(KeyNameInformation) = class 3 (Vista+)
    if (Real_NtQueryKey) {
        std::vector<BYTE> buf(4096, 0);
        ULONG resultLen = 0;
        NTSTATUS st = Real_NtQueryKey(h, VlKeyNameInformation,
                                       &buf[0], (ULONG)buf.size(), &resultLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            buf.assign(resultLen + 8, 0);
            st = Real_NtQueryKey(h, VlKeyNameInformation,
                                  &buf[0], (ULONG)buf.size(), &resultLen);
        }
        if (NT_SUCCESS(st)) {
            VL_KEY_NAME_INFORMATION* kni =
                reinterpret_cast<VL_KEY_NAME_INFORMATION*>(&buf[0]);
            if (kni->NameLength > 0) {
                std::wstring path = std::wstring(kni->Name, kni->NameLength / sizeof(WCHAR));
                VL_DBG(L"GetHandleLogicalPath: NtQueryKey -> %s", path.c_str());
                return path;
            }
        }
        VL_DBG(L"GetHandleLogicalPath: NtQueryKey also failed st=0x%08X", (ULONG)st);
    }

    VL_DBG(L"GetHandleLogicalPath: FAILED to resolve handle 0x%p", h);
    return L"";
}

// Build the full NT path from an OBJECT_ATTRIBUTES
static std::wstring GetFullNtPath(PVL_OBJECT_ATTRIBUTES oa) {
    if (!oa) return L"";
    std::wstring name = FromUStr(oa->ObjectName);
    if (!oa->RootDirectory) return name;

    std::wstring parentPath = GetHandleLogicalPath(oa->RootDirectory);
    if (name.empty()) return parentPath;
    return parentPath + L"\\" + name;
}

// Compute virtual NT path from logical path.
// Logical: \Registry\User\SID\foo\bar
// Virtual: \Registry\User\SID\VirtApp\foo\bar
static bool LogicalToVirtual(const std::wstring& logical,
                               std::wstring& virt)
{
    if (!g_RegEnabled) return false;
    // Must be under RealNtBase but NOT under VirtNtBase
    if (!StartsWithI(logical, g_RealNtBase)) {
        VL_DBG(L"LogicalToVirtual: SKIP (not under RealNtBase) path=%s base=%s",
               logical.c_str(), g_RealNtBase.c_str());
        return false;
    }
    if (StartsWithI(logical, g_VirtNtBase)) {
        VL_DBG(L"LogicalToVirtual: SKIP (already under VirtNtBase) path=%s", logical.c_str());
        return false;
    }

    std::wstring sub = logical.substr(g_RealNtBase.size());
    if (sub.empty()) {
        VL_DBG(L"LogicalToVirtual: SKIP (hive root itself)");
        return false;
    }

    virt = g_VirtNtBase + sub;
    VL_DBG(L"LogicalToVirtual: REDIRECT %s -> %s", logical.c_str(), virt.c_str());
    return true;
}

// Ensure every component of virtPath exists (creates missing keys)
static void EnsureVirtualPath(const std::wstring& virtPath) {
    if (!StartsWithI(virtPath, g_VirtNtBase)) return;

    // Walk components after g_VirtNtBase
    std::wstring remaining = virtPath.substr(g_VirtNtBase.size());
    std::wstring current   = g_VirtNtBase;

    while (!remaining.empty()) {
        // strip leading backslash
        size_t start = (remaining[0] == L'\\') ? 1u : 0u;
        size_t slash = remaining.find(L'\\', start);
        std::wstring seg;
        if (slash != std::wstring::npos) {
            seg       = remaining.substr(start, slash - start);
            remaining = remaining.substr(slash);
        } else {
            seg       = remaining.substr(start);
            remaining = L"";
        }
        if (seg.empty()) continue;
        current += L"\\" + seg;

        VL_UNICODE_STRING us; MakeUStr(&us, current);
        VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
        HANDLE h = NULL; ULONG disp = 0;
        NTSTATUS st = Real_NtCreateKey(&h, KEY_ALL_ACCESS, &oa,
                                        0, NULL, 0, &disp);
        if (NT_SUCCESS(st) && h) Real_NtClose(h);
    }
}

// ============================================================
// FS Path Helpers
// ============================================================

// Convert Win32 path "C:\foo" -> NT path "\??\C:\foo"
static std::wstring Win32ToNtPath(const std::wstring& win32) {
    if (StartsWithI(win32, L"\\??\\") ||
        StartsWithI(win32, L"\\\\?\\") ||
        StartsWithI(win32, L"\\Device\\")) return win32;

    if (win32.size() >= 2 && iswalpha(win32[0]) && win32[1] == L':')
        return L"\\??\\" + win32;

    if (StartsWithI(win32, L"\\\\"))
        return L"\\??\\UNC\\" + win32.substr(2);

    return win32;
}

// Apply FS redirections to an NT path.  Returns redirected NT path or original.
static std::wstring ApplyFsRedirect(const std::wstring& ntPath) {
    if (!g_FsEnabled) return ntPath;
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, from)) {
            std::wstring suffix = ntPath.substr(from.size());
            return to + suffix;
        }
    }
    return ntPath;
}

// ============================================================
// Config Loading
// ============================================================

static void LoadFsConfig(const std::wstring& path) {
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;

    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(hf); return; }

    std::vector<char> raw(sz + 1, 0);
    DWORD read = 0;
    ReadFile(hf, &raw[0], sz, &read, NULL);
    CloseHandle(hf);

    // Convert to wide
    int wlen = MultiByteToWideChar(CP_UTF8, 0, &raw[0], -1, NULL, 0);
    if (wlen <= 0) {
        wlen = MultiByteToWideChar(CP_ACP, 0, &raw[0], -1, NULL, 0);
    }
    std::wstring content(wlen + 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, &raw[0], -1, &content[0], wlen);

    // Parse line by line
    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find(L'\n', pos);
        std::wstring line = (nl != std::wstring::npos)
                            ? content.substr(pos, nl - pos)
                            : content.substr(pos);
        pos = (nl != std::wstring::npos) ? nl + 1 : content.size();

        // Trim CR/spaces
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' '))
            line.resize(line.size() - 1);
        while (!line.empty() && (line[0] == L' '))
            line = line.substr(1);

        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        if (line[0] == L'[') continue; // section header

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring src = line.substr(0, eq);
        std::wstring dst = line.substr(eq + 1);

        // Trim
        while (!src.empty() && src.back() == L' ') src.resize(src.size()-1);
        while (!dst.empty() && dst[0]   == L' ') dst = dst.substr(1);
        if (src.empty() || dst.empty()) continue;

        // Convert to NT paths and store
        g_FsRedirects.push_back(
            std::make_pair(Win32ToNtPath(src), Win32ToNtPath(dst)));
    }
}

static void LoadConfig() {
    wchar_t buf[2048] = {};

    // Registry virtualisation
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_REG", buf, 2047) > 0) {
        g_VirtNtBase = buf;
        // Derive RealNtBase = parent of VirtNtBase
        size_t sl = g_VirtNtBase.rfind(L'\\');
        if (sl != std::wstring::npos)
            g_RealNtBase = g_VirtNtBase.substr(0, sl);
        if (!g_VirtNtBase.empty() && !g_RealNtBase.empty())
            g_RegEnabled = true;
    }

    // FS redirection
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FS", buf, 2047) > 0) {
        LoadFsConfig(buf);
        if (!g_FsRedirects.empty())
            g_FsEnabled = true;
    }

    // DLL path for child injection
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL", g_DllPathA, MAX_PATH);

    // --- Debug summary ---
    VL_DBG(L"LoadConfig: RegEnabled=%d  VirtNtBase=%s",
           (int)g_RegEnabled, g_VirtNtBase.c_str());
    VL_DBG(L"LoadConfig:             RealNtBase=%s", g_RealNtBase.c_str());
    VL_DBG(L"LoadConfig: FsEnabled=%d  redirects=%u",
           (int)g_FsEnabled, (unsigned)g_FsRedirects.size());
}

// ============================================================
// Collect subkey names from a handle (for merge enumeration)
// ============================================================

static std::vector<std::wstring> CollectSubkeyNames(HANDLE h) {
    std::vector<std::wstring> names;
    if (!h) return names;
    std::vector<BYTE> buf(1024, 0);
    for (ULONG idx = 0; ; ++idx) {
        ULONG resLen = 0;
        NTSTATUS st = Real_NtEnumerateKey(h, idx, VlKeyBasicInformation,
                                           &buf[0], (ULONG)buf.size(), &resLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            buf.assign(resLen + 4, 0);
            st = Real_NtEnumerateKey(h, idx, VlKeyBasicInformation,
                                      &buf[0], (ULONG)buf.size(), &resLen);
        }
        if (!NT_SUCCESS(st)) break;
        VL_KEY_BASIC_INFORMATION* kbi =
            reinterpret_cast<VL_KEY_BASIC_INFORMATION*>(&buf[0]);
        names.push_back(std::wstring(kbi->Name, kbi->NameLength / sizeof(WCHAR)));
    }
    return names;
}

// Collect value names from a handle
static std::vector<std::wstring> CollectValueNames(HANDLE h) {
    std::vector<std::wstring> names;
    if (!h) return names;
    std::vector<BYTE> buf(1024, 0);
    for (ULONG idx = 0; ; ++idx) {
        ULONG resLen = 0;
        NTSTATUS st = Real_NtEnumerateValueKey(h, idx,
                            VlKeyValueBasicInformation,
                            &buf[0], (ULONG)buf.size(), &resLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            buf.assign(resLen + 4, 0);
            st = Real_NtEnumerateValueKey(h, idx,
                            VlKeyValueBasicInformation,
                            &buf[0], (ULONG)buf.size(), &resLen);
        }
        if (!NT_SUCCESS(st)) break;
        VL_KEY_VALUE_BASIC_INFORMATION* kvbi =
            reinterpret_cast<VL_KEY_VALUE_BASIC_INFORMATION*>(&buf[0]);
        names.push_back(std::wstring(kvbi->Name, kvbi->NameLength / sizeof(WCHAR)));
    }
    return names;
}

static bool NameInList(const std::wstring& name,
                        const std::vector<std::wstring>& list)
{
    for (size_t i = 0; i < list.size(); ++i)
        if (_wcsicmp(name.c_str(), list[i].c_str()) == 0) return true;
    return false;
}

// ============================================================
// REGISTRY HOOKS
// ============================================================

// ---- NtOpenKey ----
static NTSTATUS NTAPI Hook_NtOpenKey(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

    SetReentrant(true);

    std::wstring fullPath = GetFullNtPath(ObjectAttributes);
    std::wstring virtPath;

    if (!LogicalToVirtual(fullPath, virtPath)) {
        SetReentrant(false);
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    }

    VL_DBG(L"Hook_NtOpenKey: fullPath=%s", fullPath.c_str());

    // Try virtual key first
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);

    HANDLE hVirt = NULL;
    NTSTATUS stV = Real_NtOpenKey(&hVirt, DesiredAccess, &voa);

    // Also open real key (for merge reads)
    HANDLE hReal = NULL;
    Real_NtOpenKey(&hReal, KEY_READ, ObjectAttributes);

    if (NT_SUCCESS(stV)) {
        // Virtual key exists -- use it
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, hReal, fullPath);
        VL_DBG(L"Hook_NtOpenKey: opened virtual hVirt=%p hReal=%p", hVirt, hReal);
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Virtual key doesn't exist yet.
    // COPY-ON-WRITE: only if the real key exists -- if neither exists we must
    // return failure so callers probing for unique names (e.g. regedit's
    // "New Key #N" loop) get the correct NOT_FOUND status instead of
    // accidentally creating phantom virtual keys.
    if (!hReal) {
        if (hVirt) Real_NtClose(hVirt);
        VL_DBG(L"Hook_NtOpenKey: neither virtual nor real exists, returning NOT_FOUND");
        SetReentrant(false);
        return VL_STATUS_OBJECT_NOT_FOUND;
    }

    HANDLE hVirtNew = NULL;
    ULONG disp = 0;
    EnsureVirtualPath(virtPath);

    VL_UNICODE_STRING vus2; MakeUStr(&vus2, virtPath);
    VL_OBJECT_ATTRIBUTES voa2; MakeOA(&voa2, &vus2,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);
    NTSTATUS stC = Real_NtCreateKey(&hVirtNew, DesiredAccess | KEY_READ,
                                     &voa2, 0, NULL, 0, &disp);

    if (NT_SUCCESS(stC)) {
        *KeyHandle = hVirtNew;
        TrackHandle(hVirtNew, hVirtNew, hReal, fullPath);
        VL_DBG(L"Hook_NtOpenKey: CoW created virtual hVirt=%p hReal=%p disp=%u",
               hVirtNew, hReal, disp);
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Virtual creation failed -- use real handle untracked (unusual path)
    VL_DBG(L"Hook_NtOpenKey: virtual CoW FAILED st=0x%08X -- using real handle (untracked)", (ULONG)stC);
    if (hVirtNew) Real_NtClose(hVirtNew);

    HANDLE hRealWrite = NULL;
    NTSTATUS stR = Real_NtOpenKey(&hRealWrite, DesiredAccess, ObjectAttributes);
    if (hReal && hReal != hRealWrite) Real_NtClose(hReal);

    if (NT_SUCCESS(stR)) {
        *KeyHandle = hRealWrite;
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    if (hRealWrite) Real_NtClose(hRealWrite);
    SetReentrant(false);
    return stR;
}

// ---- NtOpenKeyEx (Vista+) ----
static NTSTATUS NTAPI Hook_NtOpenKeyEx(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG                 OpenOptions)
{
    // Delegate to NtOpenKey hook logic by re-using it
    // (OpenOptions is mostly for transactions -- ignore for virtualisation)
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    SetReentrant(true);

    std::wstring fullPath = GetFullNtPath(ObjectAttributes);
    std::wstring virtPath;

    if (!LogicalToVirtual(fullPath, virtPath)) {
        SetReentrant(false);
        return Real_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
    }

    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);

    HANDLE hVirt = NULL;
    NTSTATUS stV = Real_NtOpenKeyEx(&hVirt, DesiredAccess, &voa, OpenOptions);

    // Also open real key for merge reads
    HANDLE hReal = NULL;
    Real_NtOpenKeyEx(&hReal, KEY_READ, ObjectAttributes, OpenOptions);

    if (NT_SUCCESS(stV)) {
        // Virtual key exists -- use it
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, hReal, fullPath);
        VL_DBG(L"Hook_NtOpenKeyEx: opened virtual hVirt=%p hReal=%p", hVirt, hReal);
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Virtual key doesn't exist yet -- CoW only if the real key exists.
    // If neither exists return failure so name-probing loops (e.g. regedit's
    // "New Key #N") get the correct NOT_FOUND and don't loop forever.
    if (!hReal) {
        if (hVirt) Real_NtClose(hVirt);
        VL_DBG(L"Hook_NtOpenKeyEx: neither virtual nor real exists, returning NOT_FOUND");
        SetReentrant(false);
        return VL_STATUS_OBJECT_NOT_FOUND;
    }

    HANDLE hVirtNew = NULL;
    ULONG disp = 0;
    EnsureVirtualPath(virtPath);

    VL_UNICODE_STRING vus2; MakeUStr(&vus2, virtPath);
    VL_OBJECT_ATTRIBUTES voa2; MakeOA(&voa2, &vus2,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);
    NTSTATUS stC = Real_NtCreateKey(&hVirtNew, DesiredAccess | KEY_READ,
                                     &voa2, 0, NULL, 0, &disp);

    if (NT_SUCCESS(stC)) {
        *KeyHandle = hVirtNew;
        TrackHandle(hVirtNew, hVirtNew, hReal, fullPath);
        VL_DBG(L"Hook_NtOpenKeyEx: CoW created virtual hVirt=%p hReal=%p disp=%u",
               hVirtNew, hReal, disp);
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // CoW failed -- fall back to real but warn
    VL_DBG(L"Hook_NtOpenKeyEx: virtual CoW FAILED st=0x%08X -- using real handle (untracked)", (ULONG)stC);
    if (hVirtNew) Real_NtClose(hVirtNew);

    if (hReal) {
        *KeyHandle = hReal;
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Re-open real with full access for the caller
    HANDLE hRealWrite = NULL;
    NTSTATUS stR = Real_NtOpenKeyEx(&hRealWrite, DesiredAccess, ObjectAttributes, OpenOptions);
    SetReentrant(false);
    if (NT_SUCCESS(stR)) { *KeyHandle = hRealWrite; return VL_STATUS_SUCCESS; }
    if (hRealWrite) Real_NtClose(hRealWrite);
    return stR;
}

// ---- NtCreateKey -- always creates in virtual store ----
static NTSTATUS NTAPI Hook_NtCreateKey(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG                 TitleIndex,
    PVL_UNICODE_STRING    Class,
    ULONG                 CreateOptions,
    PULONG                Disposition)
{
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                 TitleIndex, Class, CreateOptions, Disposition);

    SetReentrant(true);

    std::wstring fullPath = GetFullNtPath(ObjectAttributes);
    VL_DBG(L"Hook_NtCreateKey: fullPath=%s", fullPath.c_str());
    std::wstring virtPath;

    if (!LogicalToVirtual(fullPath, virtPath)) {
        SetReentrant(false);
        return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                 TitleIndex, Class, CreateOptions, Disposition);
    }

    VL_DBG(L"Hook_NtCreateKey: VIRT creating %s", virtPath.c_str());

    // Ensure all parent virtual keys exist
    EnsureVirtualPath(virtPath);

    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);

    HANDLE hVirt = NULL;
    NTSTATUS st = Real_NtCreateKey(&hVirt, DesiredAccess, &voa,
                                    TitleIndex, Class, CreateOptions, Disposition);

    if (NT_SUCCESS(st)) {
        // Also open real key (if exists) for merge reads
        HANDLE hReal = NULL;
        Real_NtOpenKey(&hReal, KEY_READ, ObjectAttributes);
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, hReal, fullPath);
        VL_DBG(L"Hook_NtCreateKey: OK hVirt=%p hReal=%p", hVirt, hReal);
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Virtual creation failed -- do NOT fall back silently to real location.
    // Return the failure so the caller knows, rather than writing to the
    // real registry without the application's knowledge.
    VL_DBG(L"Hook_NtCreateKey: virtual create FAILED st=0x%08X -- NOT falling back", (ULONG)st);
    SetReentrant(false);
    return st;
}

// ---- NtQueryKey ----
static NTSTATUS NTAPI Hook_NtQueryKey(
    HANDLE                 KeyHandle,
    VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                  KeyInformation,
    ULONG                  Length,
    PULONG                 ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e))
        return Real_NtQueryKey(KeyHandle, KeyInformationClass,
                               KeyInformation, Length, ResultLength);

    HANDLE queryH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    NTSTATUS st = Real_NtQueryKey(queryH, KeyInformationClass,
                                   KeyInformation, Length, ResultLength);

    // For KeyFullInformation we could merge SubKeys/Values counts
    // For now return virtual (priority) info as-is
    return st;
}

// ---- NtEnumerateKey -- merged view ----
static NTSTATUS NTAPI Hook_NtEnumerateKey(
    HANDLE                 KeyHandle,
    ULONG                  Index,
    VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                  KeyInformation,
    ULONG                  Length,
    PULONG                 ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtEnumerateKey(KeyHandle, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    }

    HANDLE hV = e.hVirt;
    HANDLE hR = e.hReal;

    // If only one handle is available, no merging needed
    if (!hV) {
        return Real_NtEnumerateKey(hR ? hR : KeyHandle, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    }
    if (!hR) {
        return Real_NtEnumerateKey(hV, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    }

    // Merge: virtual first, then real entries not in virtual
    SetReentrant(true);
    std::vector<std::wstring> virtNames = CollectSubkeyNames(hV);
    SetReentrant(false);

    ULONG virtCount = static_cast<ULONG>(virtNames.size());

    if (Index < virtCount) {
        return Real_NtEnumerateKey(hV, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    }

    // Walk real keys, skipping those shadowed by virtual
    ULONG want    = Index - virtCount;
    ULONG skipped = 0;
    std::vector<BYTE> tmpBuf(1024, 0);

    for (ULONG ri = 0; ; ++ri) {
        ULONG resLen = 0;
        NTSTATUS st = Real_NtEnumerateKey(hR, ri, VlKeyBasicInformation,
                                           &tmpBuf[0], (ULONG)tmpBuf.size(), &resLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            tmpBuf.assign(resLen + 4, 0);
            st = Real_NtEnumerateKey(hR, ri, VlKeyBasicInformation,
                                      &tmpBuf[0], (ULONG)tmpBuf.size(), &resLen);
        }
        if (!NT_SUCCESS(st)) return VL_STATUS_NO_MORE_ENTRIES;

        VL_KEY_BASIC_INFORMATION* kbi =
            reinterpret_cast<VL_KEY_BASIC_INFORMATION*>(&tmpBuf[0]);
        std::wstring name(kbi->Name, kbi->NameLength / sizeof(WCHAR));

        if (!NameInList(name, virtNames)) {
            if (skipped == want) {
                return Real_NtEnumerateKey(hR, ri, KeyInformationClass,
                                            KeyInformation, Length, ResultLength);
            }
            ++skipped;
        }
    }
}

// ---- NtEnumerateValueKey -- merged view ----
static NTSTATUS NTAPI Hook_NtEnumerateValueKey(
    HANDLE                        KeyHandle,
    ULONG                         Index,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                         KeyValueInformation,
    ULONG                         Length,
    PULONG                        ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtEnumerateValueKey(KeyHandle, Index,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    HANDLE hV = e.hVirt;
    HANDLE hR = e.hReal;

    if (!hV) {
        return Real_NtEnumerateValueKey(hR ? hR : KeyHandle, Index,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }
    if (!hR) {
        return Real_NtEnumerateValueKey(hV, Index,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    SetReentrant(true);
    std::vector<std::wstring> virtVals = CollectValueNames(hV);
    SetReentrant(false);

    ULONG virtCount = static_cast<ULONG>(virtVals.size());

    if (Index < virtCount) {
        return Real_NtEnumerateValueKey(hV, Index, KeyValueInformationClass,
                                         KeyValueInformation, Length, ResultLength);
    }

    ULONG want = Index - virtCount;
    ULONG skipped = 0;
    std::vector<BYTE> tmpBuf(1024, 0);

    for (ULONG ri = 0; ; ++ri) {
        ULONG resLen = 0;
        NTSTATUS st = Real_NtEnumerateValueKey(hR, ri,
                            VlKeyValueBasicInformation,
                            &tmpBuf[0], (ULONG)tmpBuf.size(), &resLen);
        if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
            tmpBuf.assign(resLen + 4, 0);
            st = Real_NtEnumerateValueKey(hR, ri,
                            VlKeyValueBasicInformation,
                            &tmpBuf[0], (ULONG)tmpBuf.size(), &resLen);
        }
        if (!NT_SUCCESS(st)) return VL_STATUS_NO_MORE_ENTRIES;

        VL_KEY_VALUE_BASIC_INFORMATION* kvbi =
            reinterpret_cast<VL_KEY_VALUE_BASIC_INFORMATION*>(&tmpBuf[0]);
        std::wstring name(kvbi->Name, kvbi->NameLength / sizeof(WCHAR));

        if (!NameInList(name, virtVals)) {
            if (skipped == want) {
                return Real_NtEnumerateValueKey(hR, ri, KeyValueInformationClass,
                                                 KeyValueInformation, Length, ResultLength);
            }
            ++skipped;
        }
    }
}

// ---- NtQueryValueKey -- virtual takes priority ----
static NTSTATUS NTAPI Hook_NtQueryValueKey(
    HANDLE                        KeyHandle,
    PVL_UNICODE_STRING             ValueName,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                         KeyValueInformation,
    ULONG                         Length,
    PULONG                        ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtQueryValueKey(KeyHandle, ValueName,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    // Try virtual first
    if (e.hVirt) {
        NTSTATUS st = Real_NtQueryValueKey(e.hVirt, ValueName,
                            KeyValueInformationClass, KeyValueInformation,
                            Length, ResultLength);
        if (NT_SUCCESS(st) || st == VL_STATUS_BUFFER_TOO_SMALL ||
            st == VL_STATUS_BUFFER_OVERFLOW)
            return st;
    }

    // Fall back to real
    if (e.hReal) {
        return Real_NtQueryValueKey(e.hReal, ValueName,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    return Real_NtQueryValueKey(KeyHandle, ValueName,
                KeyValueInformationClass, KeyValueInformation,
                Length, ResultLength);
}

// ---- NtSetValueKey -- write to virtual ----
static NTSTATUS NTAPI Hook_NtSetValueKey(
    HANDLE              KeyHandle,
    PVL_UNICODE_STRING  ValueName,
    ULONG               TitleIndex,
    ULONG               Type,
    PVOID               Data,
    ULONG               DataSize)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e))
        return Real_NtSetValueKey(KeyHandle, ValueName, TitleIndex,
                                   Type, Data, DataSize);

    HANDLE writeH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    return Real_NtSetValueKey(writeH, ValueName, TitleIndex, Type, Data, DataSize);
}

// ---- NtDeleteKey -- delete from virtual only ----
static NTSTATUS NTAPI Hook_NtDeleteKey(HANDLE KeyHandle) {
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e))
        return Real_NtDeleteKey(KeyHandle);

    if (e.hVirt) return Real_NtDeleteKey(e.hVirt);
    // If no virtual key, pass through to real
    return Real_NtDeleteKey(e.hReal ? e.hReal : KeyHandle);
}

// ---- NtDeleteValueKey -- delete from virtual only ----
static NTSTATUS NTAPI Hook_NtDeleteValueKey(
    HANDLE             KeyHandle,
    PVL_UNICODE_STRING ValueName)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e))
        return Real_NtDeleteValueKey(KeyHandle, ValueName);

    if (e.hVirt) return Real_NtDeleteValueKey(e.hVirt, ValueName);
    return Real_NtDeleteValueKey(e.hReal ? e.hReal : KeyHandle, ValueName);
}

// ---- NtNotifyChangeKey -- forward to virtual handle ----
static NTSTATUS NTAPI Hook_NtNotifyChangeKey(
    HANDLE                 KeyHandle,
    HANDLE                 Event,
    VL_PIO_APC_ROUTINE     ApcRoutine,
    PVOID                  ApcContext,
    PVL_IO_STATUS_BLOCK    IoStatusBlock,
    ULONG                  CompletionFilter,
    BOOLEAN                WatchTree,
    PVOID                  Buffer,
    ULONG                  BufferSize,
    BOOLEAN                Asynchronous)
{
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    return Real_NtNotifyChangeKey(useH, Event, ApcRoutine, ApcContext,
                                   IoStatusBlock, CompletionFilter, WatchTree,
                                   Buffer, BufferSize, Asynchronous);
}

// ---- NtClose -- CRITICAL: only special-case tracked handles ----
static NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    VirtKeyEntry e;
    if (!GetEntry(Handle, e))
        return Real_NtClose(Handle);

    // Close both physical handles
    UntrackHandle(Handle);

    NTSTATUS st = VL_STATUS_SUCCESS;
    if (e.hVirt == Handle) {
        // Handle IS the virtual handle -- close it
        st = Real_NtClose(Handle);
        // Also close the real handle if different
        if (e.hReal && e.hReal != Handle)
            Real_NtClose(e.hReal);
    } else if (e.hReal == Handle) {
        // Handle is the real handle -- close it
        st = Real_NtClose(Handle);
        // Also close the virtual handle if different
        if (e.hVirt && e.hVirt != Handle)
            Real_NtClose(e.hVirt);
    } else {
        // Shouldn't happen -- close both and the handle itself
        if (e.hVirt) Real_NtClose(e.hVirt);
        if (e.hReal) Real_NtClose(e.hReal);
        st = Real_NtClose(Handle);
    }

    return st;
}

// ============================================================
// FILE SYSTEM HOOKS
// ============================================================

static NTSTATUS NTAPI Hook_NtCreateFile(
    PHANDLE             FileHandle,
    ULONG               DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER      AllocationSize,
    ULONG               FileAttributes,
    ULONG               ShareAccess,
    ULONG               CreateDisposition,
    ULONG               CreateOptions,
    PVOID               EaBuffer,
    ULONG               EaLength)
{
    // Resolve full path including RootDirectory handle (handles relative opens)
    std::wstring ntPath = ObjectAttributes ? GetFullNtPath(ObjectAttributes) : L"";
    if (!ntPath.empty())
        VL_DBG(L"Hook_NtCreateFile: %s", ntPath.c_str());

    if (!g_FsEnabled || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        IsReentrant())
    {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);
    }

    std::wstring redPath = ApplyFsRedirect(ntPath);

    if (redPath == ntPath) {
        VL_DBG(L"Hook_NtCreateFile: no redirect for %s", ntPath.c_str());
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);
    }

    VL_DBG(L"Hook_NtCreateFile: REDIRECT %s -> %s", ntPath.c_str(), redPath.c_str());

    // Use absolute redirected path with no RootDirectory
    VL_UNICODE_STRING newName;  MakeUStr(&newName, redPath);
    VL_OBJECT_ATTRIBUTES newOa = *ObjectAttributes;
    newOa.ObjectName    = &newName;
    newOa.RootDirectory = NULL;

    return Real_NtCreateFile(FileHandle, DesiredAccess, &newOa,
                              IoStatusBlock, AllocationSize, FileAttributes,
                              ShareAccess, CreateDisposition, CreateOptions,
                              EaBuffer, EaLength);
}

static NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE             FileHandle,
    ULONG               DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions)
{
    std::wstring ntPath = ObjectAttributes ? GetFullNtPath(ObjectAttributes) : L"";
    if (!ntPath.empty())
        VL_DBG(L"Hook_NtOpenFile: %s", ntPath.c_str());

    if (!g_FsEnabled || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        IsReentrant())
    {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring redPath = ApplyFsRedirect(ntPath);

    if (redPath == ntPath) {
        VL_DBG(L"Hook_NtOpenFile: no redirect for %s", ntPath.c_str());
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    VL_DBG(L"Hook_NtOpenFile: REDIRECT %s -> %s", ntPath.c_str(), redPath.c_str());
    VL_UNICODE_STRING newName;  MakeUStr(&newName, redPath);
    VL_OBJECT_ATTRIBUTES newOa = *ObjectAttributes;
    newOa.ObjectName    = &newName;
    newOa.RootDirectory = NULL;

    return Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                            IoStatusBlock, ShareAccess, OpenOptions);
}

// ---- NtQueryFullAttributesFile -- used by GetFileAttributesW ----
//
// cmd.exe calls GetFileAttributesW(src) to check file existence before rename.
// This goes through NtQueryFullAttributesFile, NOT NtOpenFile/NtCreateFile.
// Without this hook the existence check fails on the real path and cmd bails
// before ever reaching MoveFileW.
static NTSTATUS NTAPI Hook_NtQueryFullAttributesFile(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVOID                 FileInformation)  // FILE_NETWORK_OPEN_INFORMATION
{
    std::wstring ntPath = ObjectAttributes ? GetFullNtPath(ObjectAttributes) : L"";
    if (!ntPath.empty())
        VL_DBG(L"Hook_NtQueryFullAttributesFile: %s", ntPath.c_str());

    if (!g_FsEnabled || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        IsReentrant())
    {
        return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    }

    std::wstring redPath = ApplyFsRedirect(ntPath);

    if (redPath == ntPath) {
        VL_DBG(L"Hook_NtQueryFullAttributesFile: no redirect for %s", ntPath.c_str());
        return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    }

    VL_DBG(L"Hook_NtQueryFullAttributesFile: REDIRECT %s -> %s", ntPath.c_str(), redPath.c_str());
    VL_UNICODE_STRING newName; MakeUStr(&newName, redPath);
    VL_OBJECT_ATTRIBUTES newOa = *ObjectAttributes;
    newOa.ObjectName    = &newName;
    newOa.RootDirectory = NULL;

    return Real_NtQueryFullAttributesFile(&newOa, FileInformation);
}
//
// When an app renames a file the kernel path of the NEW name is embedded
// inside a FILE_RENAME_INFORMATION / FILE_RENAME_INFORMATION_EX structure
// passed here.  We patch that target path through ApplyFsRedirect so that
// both ends of the rename land in the virtual store.
//
// FILE_RENAME_INFORMATION true layout (compiler-padded):
//
//   32-bit:
//     offset  0 : BOOLEAN ReplaceIfExists (1 byte)
//     offset  1 : pad[3]
//     offset  4 : HANDLE  RootDirectory   (4 bytes)
//     offset  8 : ULONG   FileNameLength  (4 bytes)
//     offset 12 : WCHAR   FileName[1]
//
//   64-bit:
//     offset  0 : BOOLEAN ReplaceIfExists (1 byte)
//     offset  1 : pad[7]
//     offset  8 : HANDLE  RootDirectory   (8 bytes)
//     offset 16 : ULONG   FileNameLength  (4 bytes)
//     offset 20 : WCHAR   FileName[1]
//
// FileRenameInformationEx (Win10 RS1+) has ULONG Flags at offset 0
// instead of BOOLEAN, but the rest of the layout is identical per-bitness.

#define FileRenameInformation   10
#define FileRenameInformationEx 65   // Windows 10 RS1+

// Correct offsets based on actual struct layout:
#ifdef _WIN64
  #define RENAME_INFO_HANDLE_OFFSET   8
  #define RENAME_INFO_NAMELEN_OFFSET  16
  #define RENAME_INFO_NAME_OFFSET     20
  #define RENAME_INFO_MIN_SIZE        20
#else
  #define RENAME_INFO_HANDLE_OFFSET   4
  #define RENAME_INFO_NAMELEN_OFFSET  8
  #define RENAME_INFO_NAME_OFFSET     12
  #define RENAME_INFO_MIN_SIZE        12
#endif

static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE              FileHandle,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID               FileInformation,
    ULONG               Length,
    ULONG               FileInformationClass)
{
    VL_DBG(L"Hook_NtSetInformationFile: class=%u len=%u fsEnabled=%d",
           FileInformationClass, Length, (int)g_FsEnabled);

    if (!g_FsEnabled || IsReentrant() ||
        (FileInformationClass != FileRenameInformation &&
         FileInformationClass != FileRenameInformationEx) ||
        !FileInformation || Length < RENAME_INFO_MIN_SIZE)
    {
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    BYTE* p           = (BYTE*)FileInformation;
    ULONG nameByteLen = *(ULONG*)(p + RENAME_INFO_NAMELEN_OFFSET);

    if (nameByteLen == 0 || Length < (ULONG)(RENAME_INFO_NAME_OFFSET + nameByteLen)) {
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    std::wstring origName((WCHAR*)(p + RENAME_INFO_NAME_OFFSET),
                          nameByteLen / sizeof(WCHAR));
    VL_DBG(L"Hook_NtSetInformationFile: rename dest orig=%s", origName.c_str());

    std::wstring redName = ApplyFsRedirect(origName);

    if (redName == origName) {
        VL_DBG(L"Hook_NtSetInformationFile: no redirect for dest");
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    VL_DBG(L"Hook_NtSetInformationFile: rename dest redir=%s", redName.c_str());

    ULONG  newNameBytes = (ULONG)(redName.size() * sizeof(WCHAR));
    ULONG  newLength    = RENAME_INFO_NAME_OFFSET + newNameBytes;
    std::vector<BYTE> buf(newLength, 0);
    memcpy(buf.data(), p, RENAME_INFO_NAME_OFFSET);
    *(ULONG*)(buf.data() + RENAME_INFO_NAMELEN_OFFSET) = newNameBytes;
    memcpy(buf.data() + RENAME_INFO_NAME_OFFSET, redName.c_str(), newNameBytes);

    return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                      buf.data(), newLength,
                                      FileInformationClass);
}

// ---- GetFileAttributesW / GetFileAttributesExW ----
// cmd.exe calls one of these to verify the source file exists before rename.

static DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR lpFileName)
{
    VL_DBG(L"Hook_GetFileAttributesW: %s", lpFileName ? lpFileName : L"(null)");

    if (!g_FsEnabled || IsReentrant() || !lpFileName)
        return Real_GetFileAttributesW(lpFileName);

    std::wstring ntPath  = Win32ToNtPath(lpFileName);
    std::wstring redNt   = ApplyFsRedirect(ntPath);

    if (redNt == ntPath) {
        VL_DBG(L"Hook_GetFileAttributesW: no redirect");
        return Real_GetFileAttributesW(lpFileName);
    }

    // Strip \??\ back to Win32
    std::wstring redWin32 = redNt;
    if (redWin32.size() > 4 && redWin32[0]==L'\\' && redWin32[1]==L'?' &&
        redWin32[2]==L'?' && redWin32[3]==L'\\')
        redWin32 = redWin32.substr(4);

    VL_DBG(L"Hook_GetFileAttributesW: REDIRECT %s -> %s", lpFileName, redWin32.c_str());
    SetReentrant(true);
    DWORD result = Real_GetFileAttributesW(redWin32.c_str());
    SetReentrant(false);
    return result;
}

static BOOL WINAPI Hook_GetFileAttributesExW(
    LPCWSTR                lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation)
{
    VL_DBG(L"Hook_GetFileAttributesExW: %s", lpFileName ? lpFileName : L"(null)");

    if (!g_FsEnabled || IsReentrant() || !lpFileName)
        return Real_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);

    std::wstring ntPath  = Win32ToNtPath(lpFileName);
    std::wstring redNt   = ApplyFsRedirect(ntPath);

    if (redNt == ntPath) {
        VL_DBG(L"Hook_GetFileAttributesExW: no redirect");
        return Real_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    }

    std::wstring redWin32 = redNt;
    if (redWin32.size() > 4 && redWin32[0]==L'\\' && redWin32[1]==L'?' &&
        redWin32[2]==L'?' && redWin32[3]==L'\\')
        redWin32 = redWin32.substr(4);

    VL_DBG(L"Hook_GetFileAttributesExW: REDIRECT %s -> %s", lpFileName, redWin32.c_str());
    SetReentrant(true);
    BOOL result = Real_GetFileAttributesExW(redWin32.c_str(), fInfoLevelId, lpFileInformation);
    SetReentrant(false);
    return result;
}

// ---- FindFirstFileExW -- cmd.exe uses this to check file existence before rename ----
//
// cmd.exe calls FindFirstFileExW(src) for wildcard expansion BEFORE calling
// MoveFileW. If the source doesn't appear to exist, cmd bails immediately.
// We redirect the Win32 path here so the virtual file is found.

static HANDLE WINAPI Hook_FindFirstFileExW(
    LPCWSTR            lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID             lpFindFileData,
    FINDEX_SEARCH_OPS  fSearchOp,
    LPVOID             lpSearchFilter,
    DWORD              dwAdditionalFlags)
{
    VL_DBG(L"Hook_FindFirstFileExW: %s", lpFileName ? lpFileName : L"(null)");

    if (!g_FsEnabled || IsReentrant() || !lpFileName) {
        return Real_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData,
                                      fSearchOp, lpSearchFilter, dwAdditionalFlags);
    }

    std::wstring ntPath  = Win32ToNtPath(lpFileName);
    std::wstring redNt   = ApplyFsRedirect(ntPath);

    if (redNt == ntPath) {
        VL_DBG(L"Hook_FindFirstFileExW: no redirect");
        return Real_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData,
                                      fSearchOp, lpSearchFilter, dwAdditionalFlags);
    }

    // Strip \??\ back to Win32 for the redirected path
    std::wstring redWin32 = redNt;
    if (redWin32.size() > 4 &&
        redWin32[0]==L'\\' && redWin32[1]==L'?' &&
        redWin32[2]==L'?' && redWin32[3]==L'\\')
        redWin32 = redWin32.substr(4);

    VL_DBG(L"Hook_FindFirstFileExW: REDIRECT %s -> %s", lpFileName, redWin32.c_str());

    SetReentrant(true);
    HANDLE h = Real_FindFirstFileExW(redWin32.c_str(), fInfoLevelId, lpFindFileData,
                                      fSearchOp, lpSearchFilter, dwAdditionalFlags);
    SetReentrant(false);
    return h;
}

// ---- MoveFileW / MoveFileExW -- belt-and-suspenders FS rename hook ----
//
// NtSetInformationFile handles the kernel rename path, but we also hook
// the Win32 MoveFile* APIs directly. This catches cases where the
// destination path is constructed in Win32 space before ever reaching
// the NT layer, and ensures both source and destination are redirected.

static BOOL WINAPI Hook_MoveFileExW(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    DWORD   dwFlags)
{
    VL_DBG(L"Hook_MoveFileExW: src=%s dst=%s",
           lpExistingFileName ? lpExistingFileName : L"(null)",
           lpNewFileName      ? lpNewFileName      : L"(null)");

    if (!g_FsEnabled || IsReentrant()) {
        return Real_MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
    }

    // Convert Win32 paths to NT, apply redirect, convert back to Win32
    std::wstring srcNt = lpExistingFileName ? Win32ToNtPath(lpExistingFileName) : L"";
    std::wstring dstNt = lpNewFileName      ? Win32ToNtPath(lpNewFileName)      : L"";

    std::wstring srcRed = srcNt.empty() ? srcNt : ApplyFsRedirect(srcNt);
    std::wstring dstRed = dstNt.empty() ? dstNt : ApplyFsRedirect(dstNt);

    // Convert back to Win32 (strip \??\ prefix)
    auto toWin32 = [](const std::wstring& nt) -> std::wstring {
        if (nt.size() > 4 && nt[0]==L'\\' && nt[1]==L'?' &&
            nt[2]==L'?' && nt[3]==L'\\')
            return nt.substr(4);
        return nt;
    };

    bool srcChanged = (!srcNt.empty() && srcRed != srcNt);
    bool dstChanged = (!dstNt.empty() && dstRed != dstNt);

    if (!srcChanged && !dstChanged) {
        return Real_MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
    }

    std::wstring newSrc = srcChanged ? toWin32(srcRed) : lpExistingFileName;
    std::wstring newDst = dstChanged ? toWin32(dstRed) : (lpNewFileName ? lpNewFileName : L"");

    VL_DBG(L"Hook_MoveFileExW: redir src=%s dst=%s", newSrc.c_str(), newDst.c_str());

    SetReentrant(true);
    BOOL result = Real_MoveFileExW(newSrc.c_str(),
                                    lpNewFileName ? newDst.c_str() : NULL,
                                    dwFlags);
    SetReentrant(false);
    return result;
}

// ============================================================
// CHILD PROCESS PROPAGATION
// ============================================================

static bool InjectIntoProcess(HANDLE hProcess) {
    if (!g_DllPathA[0]) return false;
    const char* dlls[] = { g_DllPathA };
    return DetourUpdateProcessWithDll(hProcess, dlls, 1) != FALSE;
}

static BOOL WINAPI Hook_CreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    DWORD flags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL ok = Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, flags, lpEnvironment,
                                   lpCurrentDirectory, lpStartupInfo,
                                   lpProcessInformation);
    if (ok && lpProcessInformation) {
        InjectIntoProcess(lpProcessInformation->hProcess);
        if (!(dwCreationFlags & CREATE_SUSPENDED))
            ResumeThread(lpProcessInformation->hThread);
    }
    return ok;
}

static BOOL WINAPI Hook_CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    DWORD flags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL ok = Real_CreateProcessA(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, flags, lpEnvironment,
                                   lpCurrentDirectory, lpStartupInfo,
                                   lpProcessInformation);
    if (ok && lpProcessInformation) {
        InjectIntoProcess(lpProcessInformation->hProcess);
        if (!(dwCreationFlags & CREATE_SUSPENDED))
            ResumeThread(lpProcessInformation->hThread);
    }
    return ok;
}

// ============================================================
// Hook Install / Uninstall
// ============================================================

#define VL_GETPROC(mod, name) \
    Real_##name = reinterpret_cast<Pfn##name>(GetProcAddress(mod, #name))

#define VL_ATTACH(fn) \
    if (Real_##fn) DetourAttach(reinterpret_cast<PVOID*>(&Real_##fn), Hook_##fn)

#define VL_DETACH(fn) \
    if (Real_##fn) DetourDetach(reinterpret_cast<PVOID*>(&Real_##fn), Hook_##fn)

static void InstallHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !k32) return;

    // Resolve NT functions via GetProcAddress
    VL_GETPROC(ntdll, NtClose);
    VL_GETPROC(ntdll, NtQueryObject);  // for robust handle path resolution
    VL_GETPROC(k32,   CreateProcessW);
    VL_GETPROC(k32,   CreateProcessA);

    if (g_RegEnabled) {
        VL_GETPROC(ntdll, NtOpenKey);
        VL_GETPROC(ntdll, NtOpenKeyEx);
        VL_GETPROC(ntdll, NtCreateKey);
        VL_GETPROC(ntdll, NtEnumerateKey);
        VL_GETPROC(ntdll, NtEnumerateValueKey);
        VL_GETPROC(ntdll, NtQueryKey);
        VL_GETPROC(ntdll, NtQueryValueKey);
        VL_GETPROC(ntdll, NtSetValueKey);
        VL_GETPROC(ntdll, NtDeleteKey);
        VL_GETPROC(ntdll, NtDeleteValueKey);
        VL_GETPROC(ntdll, NtNotifyChangeKey);
    }
    if (g_FsEnabled) {
        VL_GETPROC(ntdll, NtCreateFile);
        VL_GETPROC(ntdll, NtOpenFile);
        VL_GETPROC(ntdll, NtQueryFullAttributesFile);
        VL_GETPROC(ntdll, NtSetInformationFile);
        VL_GETPROC(k32,   MoveFileExW);
        // MoveFileExW may live in KernelBase on Win8+; fall back if needed
        if (!Real_MoveFileExW) {
            HMODULE kb = GetModuleHandleA("KernelBase.dll");
            if (kb) Real_MoveFileExW = (PfnMoveFileExW)GetProcAddress(kb, "MoveFileExW");
        }
        VL_GETPROC(k32,   GetFileAttributesW);
        if (!Real_GetFileAttributesW) {
            HMODULE kb = GetModuleHandleA("KernelBase.dll");
            if (kb) Real_GetFileAttributesW = (PfnGetFileAttributesW)GetProcAddress(kb, "GetFileAttributesW");
        }
        VL_GETPROC(k32,   GetFileAttributesExW);
        if (!Real_GetFileAttributesExW) {
            HMODULE kb = GetModuleHandleA("KernelBase.dll");
            if (kb) Real_GetFileAttributesExW = (PfnGetFileAttributesExW)GetProcAddress(kb, "GetFileAttributesExW");
        }
        VL_GETPROC(k32,   FindFirstFileExW);
        if (!Real_FindFirstFileExW) {
            HMODULE kb = GetModuleHandleA("KernelBase.dll");
            if (kb) Real_FindFirstFileExW = (PfnFindFirstFileExW)GetProcAddress(kb, "FindFirstFileExW");
        }
        VL_DBG(L"InstallHooks FS ptrs: NtCreateFile=%p NtOpenFile=%p NtSetInfoFile=%p MoveFileExW=%p GetFileAttrW=%p",
               (void*)Real_NtCreateFile, (void*)Real_NtOpenFile,
               (void*)Real_NtSetInformationFile, (void*)Real_MoveFileExW,
               (void*)Real_GetFileAttributesW);
    }

    // ---------------------------------------------------------------
    // CRITICAL: Create the VirtApp root key and all ancestor components
    // BEFORE installing hooks, using raw (unhooked) function pointers.
    //
    // EnsureVirtualPath only creates components *below* g_VirtNtBase.
    // If g_VirtNtBase itself doesn't exist, every NtCreateKey that calls
    // EnsureVirtualPath will silently fail and fall through to the real
    // location.  We fix this here, once, at startup.
    // ---------------------------------------------------------------
    if (g_RegEnabled && Real_NtCreateKey && Real_NtClose) {
        // Walk every component of g_VirtNtBase and create it if missing.
        // e.g. for "\Registry\User\SID\VirtApp" we create:
        //   \Registry\User              (already exists, REG_OPENED_EXISTING)
        //   \Registry\User\SID          (already exists)
        //   \Registry\User\SID\VirtApp  (may be new)
        std::wstring path;
        const std::wstring& base = g_VirtNtBase;
        size_t start = 1; // skip the leading '\'
        while (start < base.size()) {
            size_t slash = base.find(L'\\', start);
            if (slash == std::wstring::npos) slash = base.size();
            path = base.substr(0, slash);
            start = slash + 1;

            VL_UNICODE_STRING us; MakeUStr(&us, path);
            VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
            HANDLE h = NULL; ULONG disp = 0;
            NTSTATUS st = Real_NtCreateKey(&h, KEY_ALL_ACCESS, &oa,
                                            0, NULL, 0, &disp);
            if (NT_SUCCESS(st) && h) {
                VL_DBG(L"EnsureVirtRoot: created/opened %s (disp=%u)",
                       path.c_str(), disp);
                Real_NtClose(h);
            } else {
                VL_DBG(L"EnsureVirtRoot: FAILED to create %s st=0x%08X",
                       path.c_str(), (ULONG)st);
            }
        }
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Always hook NtClose (to handle tracked registry handles)
    // and child process spawns
    VL_ATTACH(NtClose);
    VL_ATTACH(CreateProcessW);
    VL_ATTACH(CreateProcessA);

    if (g_RegEnabled) {
        VL_ATTACH(NtOpenKey);
        if (Real_NtOpenKeyEx)      VL_ATTACH(NtOpenKeyEx);
        VL_ATTACH(NtCreateKey);
        VL_ATTACH(NtEnumerateKey);
        VL_ATTACH(NtEnumerateValueKey);
        VL_ATTACH(NtQueryKey);
        VL_ATTACH(NtQueryValueKey);
        VL_ATTACH(NtSetValueKey);
        VL_ATTACH(NtDeleteKey);
        VL_ATTACH(NtDeleteValueKey);
        VL_ATTACH(NtNotifyChangeKey);
    }
    if (g_FsEnabled) {
        VL_ATTACH(NtCreateFile);
        VL_ATTACH(NtOpenFile);
        if (Real_NtQueryFullAttributesFile) VL_ATTACH(NtQueryFullAttributesFile);
        if (Real_NtSetInformationFile) VL_ATTACH(NtSetInformationFile);
        if (Real_MoveFileExW)          VL_ATTACH(MoveFileExW);
        if (Real_GetFileAttributesW)   VL_ATTACH(GetFileAttributesW);
        if (Real_GetFileAttributesExW) VL_ATTACH(GetFileAttributesExW);
        if (Real_FindFirstFileExW)     VL_ATTACH(FindFirstFileExW);
    }
    LONG commitResult = DetourTransactionCommit();
    VL_DBG(L"InstallHooks: DetourTransactionCommit = %d (0=OK)", commitResult);
}

static void UninstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    VL_DETACH(NtClose);
    VL_DETACH(CreateProcessW);
    VL_DETACH(CreateProcessA);

    if (g_RegEnabled) {
        VL_DETACH(NtOpenKey);
        if (Real_NtOpenKeyEx) VL_DETACH(NtOpenKeyEx);
        VL_DETACH(NtCreateKey);
        VL_DETACH(NtEnumerateKey);
        VL_DETACH(NtEnumerateValueKey);
        VL_DETACH(NtQueryKey);
        VL_DETACH(NtQueryValueKey);
        VL_DETACH(NtSetValueKey);
        VL_DETACH(NtDeleteKey);
        VL_DETACH(NtDeleteValueKey);
        VL_DETACH(NtNotifyChangeKey);
    }
    if (g_FsEnabled) {
        VL_DETACH(NtCreateFile);
        VL_DETACH(NtOpenFile);
        if (Real_NtQueryFullAttributesFile) VL_DETACH(NtQueryFullAttributesFile);
        if (Real_NtSetInformationFile) VL_DETACH(NtSetInformationFile);
        if (Real_MoveFileExW)          VL_DETACH(MoveFileExW);
        if (Real_GetFileAttributesW)   VL_DETACH(GetFileAttributesW);
        if (Real_GetFileAttributesExW) VL_DETACH(GetFileAttributesExW);
        if (Real_FindFirstFileExW)     VL_DETACH(FindFirstFileExW);
    }

    DetourTransactionCommit();
}

// ============================================================
// DllMain
// ============================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {

    // Detours helper process check (required by Detours)
    if (DetourIsHelperProcess()) return TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // REQUIRED by Detours when loaded via DetourCreateProcessWithDlls
        // Restores the original import table that Detours modified during injection
        DetourRestoreAfterWith();

        // Initialise TLS reentrancy guard FIRST
        g_TlsIdx = TlsAlloc();
        InitializeCriticalSectionAndSpinCount(&g_KeyMapLock, 4000);

        VL_DBG(L"DllMain: DLL_PROCESS_ATTACH -- VirtHook loading");

        // Read config from environment variables
        LoadConfig();

        // Install API hooks
        InstallHooks();

        VL_DBG(L"DllMain: hooks installed OK");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        UninstallHooks();

        // Close any still-tracked handles
        EnterCriticalSection(&g_KeyMapLock);
        for (std::map<HANDLE,VirtKeyEntry>::iterator it = g_KeyMap.begin();
             it != g_KeyMap.end(); ++it)
        {
            if (it->second.hVirt && it->second.hVirt != it->first)
                Real_NtClose(it->second.hVirt);
            if (it->second.hReal && it->second.hReal != it->first)
                Real_NtClose(it->second.hReal);
        }
        g_KeyMap.clear();
        LeaveCriticalSection(&g_KeyMapLock);
        DeleteCriticalSection(&g_KeyMapLock);

        if (g_TlsIdx != TLS_OUT_OF_INDEXES) {
            TlsFree(g_TlsIdx);
            g_TlsIdx = TLS_OUT_OF_INDEXES;
        }
    }

    return TRUE;
}
