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

// =============================================================
// MANDATORY DETOURS EXPORT
// DetourCreateProcessWithDllsW spawns a helper thread in the
// target process that calls DetourFinishHelperProcess from our
// DLL export table.  detours.lib has the implementation; this
// pragma forces the linker to export it without redeclaring it
// (detours.h already declares it -- redeclaring causes C2375).
// =============================================================
#pragma comment(linker, "/export:DetourFinishHelperProcess")

#include <string>
#include <vector>
#include <map>
#include <algorithm>

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

typedef NTSTATUS (NTAPI *PfnNtCreateFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK,
     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *PfnNtOpenFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG);

typedef BOOL (WINAPI *PfnCreateProcessW)
    (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef BOOL (WINAPI *PfnCreateProcessA)
    (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

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
static PfnNtCreateFile         Real_NtCreateFile;
static PfnNtOpenFile           Real_NtOpenFile;
static PfnCreateProcessW       Real_CreateProcessW;
static PfnCreateProcessA       Real_CreateProcessA;

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
    VirtKeyEntry e;
    if (GetEntry(h, e)) return e.logPath;

    // Not tracked -- ask the kernel (not reentrant since we call Real_*)
    std::vector<BYTE> buf(4096, 0);
    ULONG resultLen = 0;
    NTSTATUS st = Real_NtQueryKey(h, VlKeyNameInformation,
                                   &buf[0], (ULONG)buf.size(), &resultLen);
    if (st == VL_STATUS_BUFFER_TOO_SMALL || st == VL_STATUS_BUFFER_OVERFLOW) {
        buf.assign(resultLen + 4, 0);
        st = Real_NtQueryKey(h, VlKeyNameInformation,
                              &buf[0], (ULONG)buf.size(), &resultLen);
    }
    if (!NT_SUCCESS(st)) return L"";
    VL_KEY_NAME_INFORMATION* kni =
        reinterpret_cast<VL_KEY_NAME_INFORMATION*>(&buf[0]);
    return std::wstring(kni->Name, kni->NameLength / sizeof(WCHAR));
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
    if (!StartsWithI(logical, g_RealNtBase)) return false;
    if (StartsWithI(logical, g_VirtNtBase))  return false;

    std::wstring sub = logical.substr(g_RealNtBase.size());
    // sub starts with '\' or is empty
    if (sub.empty()) return false; // opening the hive root itself -- don't redirect

    virt = g_VirtNtBase + sub;
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

    // Try virtual key
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        ObjectAttributes->Attributes | OBJ_CASE_INSENSITIVE);

    HANDLE hVirt = NULL;
    NTSTATUS stV = Real_NtOpenKey(&hVirt, DesiredAccess, &voa);

    // Try real key
    HANDLE hReal = NULL;
    NTSTATUS stR = Real_NtOpenKey(&hReal, DesiredAccess, ObjectAttributes);

    NTSTATUS ret;
    if (NT_SUCCESS(stV)) {
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, NT_SUCCESS(stR) ? hReal : NULL, fullPath);
        if (!NT_SUCCESS(stR) && hReal) { Real_NtClose(hReal); hReal = NULL; }
        ret = VL_STATUS_SUCCESS;
    } else if (NT_SUCCESS(stR)) {
        // Only real exists -- pass through without tracking
        if (hVirt) Real_NtClose(hVirt);
        *KeyHandle = hReal;
        ret = VL_STATUS_SUCCESS;
    } else {
        if (hVirt) Real_NtClose(hVirt);
        if (hReal) Real_NtClose(hReal);
        ret = stR; // Return real failure
    }

    SetReentrant(false);
    return ret;
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
    HANDLE hReal = NULL;
    NTSTATUS stR = Real_NtOpenKeyEx(&hReal, DesiredAccess, ObjectAttributes, OpenOptions);

    NTSTATUS ret;
    if (NT_SUCCESS(stV)) {
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, NT_SUCCESS(stR) ? hReal : NULL, fullPath);
        if (!NT_SUCCESS(stR) && hReal) { Real_NtClose(hReal); hReal = NULL; }
        ret = VL_STATUS_SUCCESS;
    } else if (NT_SUCCESS(stR)) {
        if (hVirt) Real_NtClose(hVirt);
        *KeyHandle = hReal;
        ret = VL_STATUS_SUCCESS;
    } else {
        if (hVirt) Real_NtClose(hVirt);
        if (hReal) Real_NtClose(hReal);
        ret = stR;
    }

    SetReentrant(false);
    return ret;
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
    std::wstring virtPath;

    if (!LogicalToVirtual(fullPath, virtPath)) {
        SetReentrant(false);
        return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                 TitleIndex, Class, CreateOptions, Disposition);
    }

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
        SetReentrant(false);
        return VL_STATUS_SUCCESS;
    }

    // Fallback to real if virtual creation failed
    SetReentrant(false);
    return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                             TitleIndex, Class, CreateOptions, Disposition);
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
    if (!g_FsEnabled || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        IsReentrant())
    {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);
    }

    std::wstring ntPath  = FromUStr(ObjectAttributes->ObjectName);
    std::wstring redPath = ApplyFsRedirect(ntPath);

    if (redPath == ntPath) {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);
    }

    VL_UNICODE_STRING newName;  MakeUStr(&newName, redPath);
    VL_OBJECT_ATTRIBUTES newOa = *ObjectAttributes;
    newOa.ObjectName = &newName;

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
    if (!g_FsEnabled || !ObjectAttributes || !ObjectAttributes->ObjectName ||
        IsReentrant())
    {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring ntPath  = FromUStr(ObjectAttributes->ObjectName);
    std::wstring redPath = ApplyFsRedirect(ntPath);

    if (redPath == ntPath) {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    VL_UNICODE_STRING newName;  MakeUStr(&newName, redPath);
    VL_OBJECT_ATTRIBUTES newOa = *ObjectAttributes;
    newOa.ObjectName = &newName;

    return Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                            IoStatusBlock, ShareAccess, OpenOptions);
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
    }

    DetourTransactionCommit();
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

        // Initialise TLS reentrancy guard FIRST
        g_TlsIdx = TlsAlloc();
        InitializeCriticalSectionAndSpinCount(&g_KeyMapLock, 4000);

        // Read config from environment variables
        LoadConfig();

        // Install API hooks
        InstallHooks();
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
