// ============================================================
// VirtHook.cpp  - VirtLauncher Hook DLL  (v9 - pure ntdll hooks)
// Injected into target process by VirtLauncher.exe via Detours
//
// Virtualizes:
//
//   REGISTRY:
//     NtCreateKey, NtCreateKeyTransacted
//     NtOpenKey,   NtOpenKeyEx,   NtOpenKeyTransacted, NtOpenKeyTransactedEx
//     NtDeleteKey, NtDeleteValueKey
//     NtEnumerateKey, NtEnumerateValueKey
//     NtQueryKey, NtQueryValueKey, NtQueryMultipleValueKey
//     NtSetValueKey
//     NtRenameKey
//     NtReplaceKey
//     NtSaveKey,  NtSaveKeyEx
//     NtLoadKey,  NtLoadKey2, NtLoadKeyEx, NtLoadKey3 (Win10 RS5+)
//     NtNotifyChangeKey, NtNotifyChangeMultipleKeys
//     NtFlushKey         (redirects tracked handle to virtual hive)
//     NtRestoreKey       (redirects tracked handle to virtual hive)
//     NtSetInformationKey (redirects tracked handle to virtual hive)
//     NtUnloadKey        (redirects OA target path to virtual hive)
//     NtClose  (filtered: only for tracked virtual handles)
//
//   FILES (all pure ntdll):
//     NtCreateFile, NtOpenFile
//     NtCreateDirectoryObject, NtOpenDirectoryObject
//     NtCreateMailslotFile, NtCreateNamedPipeFile
//     NtDeleteFile
//     NtQueryAttributesFile, NtQueryFullAttributesFile
//     NtQueryInformationByName
//     NtSetInformationFile      (intercepts FileRenameInformation)
//
//   CHILDREN: CreateProcessW/A (propagate injection)
//
// NOTE: NtQueryInformationFile, NtQueryVolumeInformationFile,
//       NtQueryDirectoryFile, NtQueryDirectoryFileEx,
//       NtDeviceIoControlFile, NtFsControlFile, NtReadFile, NtWriteFile
//       are NOT hooked. All are handle-based and the handle was already
//       redirected at NtCreateFile/NtOpenFile time, so hooking them adds
//       overhead with zero virtualization benefit.
//
// NOTE: Win32 wrappers (GetFileAttributesW, FindFirstFileExW,
//       MoveFileExW, etc.) are intentionally NOT hooked.
//       All interception happens at the ntdll layer.
//
// Config via environment variables set by VirtLauncher.exe:
//   VIRTLAUNCHER_REG = NT reg base  e.g. \Registry\User\SID\VirtApp
//   VIRTLAUNCHER_FS  = path to FS redirect config file
//   VIRTLAUNCHER_DLL = absolute path to this DLL (for child injection)
//
// Build x86  (VS2010 x86 command prompt):
//   cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp
//      /I<detours>\include /Fe:VirtHook32.dll
//      /link /OUT:VirtHook32.dll /DEF:VirtHook.def
//         <detours>\lib.X86\detours.lib
//
// Build x64  (VS2010 x64 command prompt):
//   cl /nologo /EHsc /O2 /MT /W3 /LD VirtHook.cpp
//      /I<detours>\include /Fe:VirtHook64.dll
//      /link /OUT:VirtHook64.dll /DEF:VirtHook.def
//         <detours>\lib.X64\detours.lib
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
    ULONG              Length;
    HANDLE             RootDirectory;
    PVL_UNICODE_STRING ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
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
    ULONG         NameLength;
    WCHAR         Name[1];
} VL_KEY_BASIC_INFORMATION;

typedef struct _VL_KEY_NAME_INFORMATION {
    ULONG NameLength;
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
    ULONG NameLength;
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

// KEY_VALUE_ENTRY for NtQueryMultipleValueKey
typedef struct _VL_KEY_VALUE_ENTRY {
    PVL_UNICODE_STRING ValueName;
    ULONG              DataLength;
    ULONG              DataOffset;
    ULONG              Type;
} VL_KEY_VALUE_ENTRY, *PVL_KEY_VALUE_ENTRY;
#pragma pack(pop)

// ============================================================
// NT Function Pointer Types
// ============================================================

// ---- Registry ----
typedef NTSTATUS (NTAPI *PfnNtOpenKey)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtOpenKeyEx)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG);

typedef NTSTATUS (NTAPI *PfnNtOpenKeyTransacted)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, HANDLE);

typedef NTSTATUS (NTAPI *PfnNtOpenKeyTransactedEx)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *PfnNtCreateKey)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, PVL_UNICODE_STRING, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtCreateKeyTransacted)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, PVL_UNICODE_STRING, ULONG, HANDLE, PULONG);

typedef NTSTATUS (NTAPI *PfnNtDeleteKey)    (HANDLE);
typedef NTSTATUS (NTAPI *PfnNtDeleteValueKey)(HANDLE, PVL_UNICODE_STRING);

typedef NTSTATUS (NTAPI *PfnNtEnumerateKey)
    (HANDLE, ULONG, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtEnumerateValueKey)
    (HANDLE, ULONG, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryKey)
    (HANDLE, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryValueKey)
    (HANDLE, PVL_UNICODE_STRING, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryMultipleValueKey)
    (HANDLE, PVL_KEY_VALUE_ENTRY, ULONG, PVOID, PULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtSetValueKey)
    (HANDLE, PVL_UNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *PfnNtRenameKey)
    (HANDLE, PVL_UNICODE_STRING);

typedef NTSTATUS (NTAPI *PfnNtReplaceKey)
    (PVL_OBJECT_ATTRIBUTES, HANDLE, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtSaveKey)
    (HANDLE, HANDLE);

typedef NTSTATUS (NTAPI *PfnNtSaveKeyEx)
    (HANDLE, HANDLE, ULONG);

typedef NTSTATUS (NTAPI *PfnNtLoadKey)
    (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtLoadKey2)
    (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG);

typedef NTSTATUS (NTAPI *PfnNtLoadKeyEx)
    (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG, HANDLE, HANDLE, ULONG, PHANDLE, PVOID);

typedef NTSTATUS (NTAPI *PfnNtNotifyChangeKey)
    (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK,
     ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);

typedef NTSTATUS (NTAPI *PfnNtNotifyChangeMultipleKeys)
    (HANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, HANDLE, VL_PIO_APC_ROUTINE,
     PVOID, PVL_IO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);

// NtFlushKey: flush a key's dirty pages to disk
typedef NTSTATUS (NTAPI *PfnNtFlushKey)
    (HANDLE);

// NtRestoreKey: load a hive file onto an existing key
typedef NTSTATUS (NTAPI *PfnNtRestoreKey)
    (HANDLE, HANDLE, ULONG);

// NtSetInformationKey: set key metadata (e.g. last-write time virtualization flag)
typedef NTSTATUS (NTAPI *PfnNtSetInformationKey)
    (HANDLE, ULONG, PVOID, ULONG);

// NtUnloadKey: unmount a hive loaded by NtLoadKey* (OA-based, like NtLoadKey)
typedef NTSTATUS (NTAPI *PfnNtUnloadKey)
    (PVL_OBJECT_ATTRIBUTES);

// NtLoadKey3: extended load (Win10 RS5 / 1809+), supersedes NtLoadKeyEx in newer code
typedef NTSTATUS (NTAPI *PfnNtLoadKey3)
    (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG,
     PVOID, ULONG, ULONG, HANDLE, PVOID);

typedef NTSTATUS (NTAPI *PfnNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *PfnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// ---- Files ----
typedef NTSTATUS (NTAPI *PfnNtCreateFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK,
     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *PfnNtOpenFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG);

typedef NTSTATUS (NTAPI *PfnNtCreateDirectoryObject)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtOpenDirectoryObject)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtCreateMailslotFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK,
     ULONG, ULONG, ULONG, PLARGE_INTEGER);

typedef NTSTATUS (NTAPI *PfnNtCreateNamedPipeFile)
    (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK,
     ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);

typedef NTSTATUS (NTAPI *PfnNtDeleteFile)
    (PVL_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *PfnNtQueryAttributesFile)
    (PVL_OBJECT_ATTRIBUTES, PVOID);  // PFILE_BASIC_INFORMATION

typedef NTSTATUS (NTAPI *PfnNtQueryFullAttributesFile)
    (PVL_OBJECT_ATTRIBUTES, PVOID);  // PFILE_NETWORK_OPEN_INFORMATION

typedef NTSTATUS (NTAPI *PfnNtQueryInformationByName)
    (PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);

typedef NTSTATUS (NTAPI *PfnNtSetInformationFile)
    (HANDLE, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);

typedef NTSTATUS (NTAPI *PfnNtFsControlFile)
    (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK,
     ULONG, PVOID, ULONG, PVOID, ULONG);

// ---- Child process ----
typedef BOOL (WINAPI *PfnCreateProcessW)
    (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef BOOL (WINAPI *PfnCreateProcessA)
    (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
     BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

// ============================================================
// Global State
// ============================================================

// ----- Registry -----
static PfnNtOpenKey               Real_NtOpenKey;
static PfnNtOpenKeyEx             Real_NtOpenKeyEx;
static PfnNtOpenKeyTransacted     Real_NtOpenKeyTransacted;
static PfnNtOpenKeyTransactedEx   Real_NtOpenKeyTransactedEx;
static PfnNtCreateKey             Real_NtCreateKey;
static PfnNtCreateKeyTransacted   Real_NtCreateKeyTransacted;
static PfnNtDeleteKey             Real_NtDeleteKey;
static PfnNtDeleteValueKey        Real_NtDeleteValueKey;
static PfnNtEnumerateKey          Real_NtEnumerateKey;
static PfnNtEnumerateValueKey     Real_NtEnumerateValueKey;
static PfnNtQueryKey              Real_NtQueryKey;
static PfnNtQueryValueKey         Real_NtQueryValueKey;
static PfnNtQueryMultipleValueKey Real_NtQueryMultipleValueKey;
static PfnNtSetValueKey           Real_NtSetValueKey;
static PfnNtRenameKey             Real_NtRenameKey;
static PfnNtReplaceKey            Real_NtReplaceKey;
static PfnNtSaveKey               Real_NtSaveKey;
static PfnNtSaveKeyEx             Real_NtSaveKeyEx;
static PfnNtLoadKey               Real_NtLoadKey;
static PfnNtLoadKey2              Real_NtLoadKey2;
static PfnNtLoadKeyEx             Real_NtLoadKeyEx;
static PfnNtNotifyChangeKey       Real_NtNotifyChangeKey;
static PfnNtNotifyChangeMultipleKeys Real_NtNotifyChangeMultipleKeys;
static PfnNtFlushKey              Real_NtFlushKey;
static PfnNtRestoreKey            Real_NtRestoreKey;
static PfnNtSetInformationKey     Real_NtSetInformationKey;
static PfnNtUnloadKey             Real_NtUnloadKey;
static PfnNtLoadKey3              Real_NtLoadKey3;
static PfnNtClose                 Real_NtClose;
static PfnNtQueryObject           Real_NtQueryObject;

// ----- Files -----
static PfnNtCreateFile              Real_NtCreateFile;
static PfnNtOpenFile                Real_NtOpenFile;
static PfnNtCreateDirectoryObject   Real_NtCreateDirectoryObject;
static PfnNtOpenDirectoryObject     Real_NtOpenDirectoryObject;
static PfnNtCreateMailslotFile      Real_NtCreateMailslotFile;
static PfnNtCreateNamedPipeFile     Real_NtCreateNamedPipeFile;
static PfnNtDeleteFile              Real_NtDeleteFile;
static PfnNtQueryAttributesFile     Real_NtQueryAttributesFile;
static PfnNtQueryFullAttributesFile Real_NtQueryFullAttributesFile;
static PfnNtQueryInformationByName  Real_NtQueryInformationByName;
static PfnNtSetInformationFile      Real_NtSetInformationFile;
static PfnNtFsControlFile           Real_NtFsControlFile;

// ----- Children -----
static PfnCreateProcessW  Real_CreateProcessW;
static PfnCreateProcessA  Real_CreateProcessA;

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

// DLL paths (ANSI) for child process injection.
// Both are read from env vars so the hook can inject the right DLL even when
// the child process has a different bitness from the current process.
static char g_DllPathA[MAX_PATH];    // Launcher's primary target-arch DLL (fallback)
static char g_DllPathA32[MAX_PATH];  // VirtHook32.dll absolute path
static char g_DllPathA64[MAX_PATH];  // VirtHook64.dll absolute path

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
    us->Buffer        = const_cast<PWSTR>(s.c_str());
    us->Length        = static_cast<USHORT>(s.size() * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
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
// Registry handle map helpers
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
// Registry Path Resolution
// ============================================================

static std::wstring GetHandleLogicalPath(HANDLE h) {
    if (!h) return L"";

    VirtKeyEntry e;
    if (GetEntry(h, e)) {
        VL_DBG(L"GetHandleLogicalPath: tracked -> %s", e.logPath.c_str());
        return e.logPath;
    }

    // NtQueryObject(ObjectNameInformation = class 1)
    if (Real_NtQueryObject) {
        std::vector<BYTE> buf(2048, 0);
        ULONG resultLen = 0;
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
    }

    // NtQueryKey(KeyNameInformation = class 3, Vista+)
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
    }

    VL_DBG(L"GetHandleLogicalPath: FAILED for handle %p", h);
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
//
// CRITICAL: StartsWithI is a pure prefix check. We must also verify the
// match ends on a path separator, otherwise the _Classes shadow hive
// (\Registry\User\S-1-5-21-...-1000_Classes) would match a g_RealNtBase
// of (\Registry\User\S-1-5-21-...-1000) and every HKCR / COM access would
// be intercepted, redirected to garbage virtual paths, and crash the app.
static bool LogicalToVirtual(const std::wstring& logical,
                               std::wstring& virt)
{
    if (!g_RegEnabled) return false;

    if (!StartsWithI(logical, g_RealNtBase)) {
        VL_DBG(L"LogicalToVirtual: SKIP (not under RealNtBase) path=%s base=%s",
               logical.c_str(), g_RealNtBase.c_str());
        return false;
    }

    // Path-boundary guard: the char immediately after g_RealNtBase must be
    // '\' (sub-key) or end-of-string (hive root itself). Anything else (like
    // '_', letters) means this is a *different* hive that just shares the
    // same SID prefix (e.g. \Registry\User\<SID>_Classes).
    size_t baseLen = g_RealNtBase.size();
    if (logical.size() > baseLen && logical[baseLen] != L'\\') {
        VL_DBG(L"LogicalToVirtual: SKIP (boundary mismatch, sibling hive?) path=%s",
               logical.c_str());
        return false;
    }

    if (StartsWithI(logical, g_VirtNtBase)) {
        VL_DBG(L"LogicalToVirtual: SKIP (already under VirtNtBase) %s", logical.c_str());
        return false;
    }

    std::wstring sub = logical.substr(baseLen);
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

    std::wstring remaining = virtPath.substr(g_VirtNtBase.size());
    std::wstring current   = g_VirtNtBase;

    while (!remaining.empty()) {
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

// Apply FS redirections to an NT path.
static std::wstring ApplyFsRedirect(const std::wstring& ntPath) {
    if (!g_FsEnabled) return ntPath;
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, from)) {
            return to + ntPath.substr(from.size());
        }
    }
    return ntPath;
}

// Helper: redirect OA path-based file call -- returns true if redirect happened.
// If true, caller should use newOa / newName instead of the original OA.
static bool RedirectFileOA(PVL_OBJECT_ATTRIBUTES oa,
                             VL_UNICODE_STRING& newName,
                             VL_OBJECT_ATTRIBUTES& newOa,
                             std::wstring& ntPath,
                             std::wstring& redPath)
{
    if (!g_FsEnabled || !oa || !oa->ObjectName || IsReentrant()) return false;
    ntPath  = GetFullNtPath(oa);
    redPath = ApplyFsRedirect(ntPath);
    if (redPath == ntPath) return false;
    MakeUStr(&newName, redPath);
    newOa               = *oa;
    newOa.ObjectName    = &newName;
    newOa.RootDirectory = NULL;
    return true;
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

    int wlen = MultiByteToWideChar(CP_UTF8, 0, &raw[0], -1, NULL, 0);
    if (wlen <= 0)
        wlen = MultiByteToWideChar(CP_ACP, 0, &raw[0], -1, NULL, 0);

    std::wstring content(wlen + 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, &raw[0], -1, &content[0], wlen);

    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find(L'\n', pos);
        std::wstring line = (nl != std::wstring::npos)
                            ? content.substr(pos, nl - pos)
                            : content.substr(pos);
        pos = (nl != std::wstring::npos) ? nl + 1 : content.size();

        while (!line.empty() && (line.back() == L'\r' || line.back() == L' '))
            line.resize(line.size() - 1);
        while (!line.empty() && line[0] == L' ')
            line = line.substr(1);

        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        if (line[0] == L'[') continue;

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring src = line.substr(0, eq);
        std::wstring dst = line.substr(eq + 1);
        while (!src.empty() && src.back() == L' ') src.resize(src.size()-1);
        while (!dst.empty() && dst[0]   == L' ') dst = dst.substr(1);
        if (src.empty() || dst.empty()) continue;

        g_FsRedirects.push_back(
            std::make_pair(Win32ToNtPath(src), Win32ToNtPath(dst)));
    }
}

static void LoadConfig() {
    wchar_t buf[2048] = {};

    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_REG", buf, 2047) > 0) {
        g_VirtNtBase = buf;
        size_t sl = g_VirtNtBase.rfind(L'\\');
        if (sl != std::wstring::npos)
            g_RealNtBase = g_VirtNtBase.substr(0, sl);
        if (!g_VirtNtBase.empty() && !g_RealNtBase.empty())
            g_RegEnabled = true;
    }

    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FS", buf, 2047) > 0) {
        LoadFsConfig(buf);
        if (!g_FsRedirects.empty())
            g_FsEnabled = true;
    }

    GetEnvironmentVariableA("VIRTLAUNCHER_DLL",   g_DllPathA,   MAX_PATH);
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL32", g_DllPathA32, MAX_PATH);
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL64", g_DllPathA64, MAX_PATH);
    // If arch-specific paths not set, default both to the primary path
    if (!g_DllPathA32[0] && g_DllPathA[0])
        strncpy(g_DllPathA32, g_DllPathA, MAX_PATH - 1);
    if (!g_DllPathA64[0] && g_DllPathA[0])
        strncpy(g_DllPathA64, g_DllPathA, MAX_PATH - 1);

    VL_DBG(L"LoadConfig: RegEnabled=%d  VirtNtBase=%s",
           (int)g_RegEnabled, g_VirtNtBase.c_str());
    VL_DBG(L"LoadConfig:             RealNtBase=%s", g_RealNtBase.c_str());
    VL_DBG(L"LoadConfig: FsEnabled=%d  redirects=%u",
           (int)g_FsEnabled, (unsigned)g_FsRedirects.size());
}

// ============================================================
// Collect subkey/value names from a handle (for merge enumeration)
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
// Shared open/create helper
// (avoids code duplication across Nt*Key and Nt*KeyTransacted)
// ============================================================

static NTSTATUS DoVirtOpen(
    PVL_OBJECT_ATTRIBUTES OrigOA,
    ULONG                 DesiredAccess,
    PHANDLE               KeyHandle,
    bool                  isCreate,
    ULONG                 TitleIndex,
    PVL_UNICODE_STRING    Class,
    ULONG                 CreateOptions,
    PULONG                Disposition)
{
    std::wstring fullPath = GetFullNtPath(OrigOA);
    std::wstring virtPath;

    if (!LogicalToVirtual(fullPath, virtPath)) {
        // Not in our scope -- let caller decide which real function to call
        return VL_STATUS_OBJECT_NOT_FOUND; // sentinel: caller must call real fn
    }

    VL_DBG(L"DoVirtOpen: fullPath=%s  isCreate=%d", fullPath.c_str(), (int)isCreate);

    if (isCreate) {
        EnsureVirtualPath(virtPath);
        VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
        VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
            OrigOA->Attributes | OBJ_CASE_INSENSITIVE);

        HANDLE hVirt = NULL;
        NTSTATUS st = Real_NtCreateKey(&hVirt, DesiredAccess, &voa,
                                        TitleIndex, Class, CreateOptions, Disposition);
        if (NT_SUCCESS(st)) {
            HANDLE hReal = NULL;
            Real_NtOpenKey(&hReal, KEY_READ, OrigOA);
            *KeyHandle = hVirt;
            TrackHandle(hVirt, hVirt, hReal, fullPath);
            VL_DBG(L"DoVirtOpen: CREATE OK hVirt=%p hReal=%p", hVirt, hReal);
            return VL_STATUS_SUCCESS;
        }
        VL_DBG(L"DoVirtOpen: CREATE FAILED st=0x%08X", (ULONG)st);
        return st;
    }

    // Open path: try virtual first
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        OrigOA->Attributes | OBJ_CASE_INSENSITIVE);

    HANDLE hVirt = NULL;
    NTSTATUS stV = Real_NtOpenKey(&hVirt, DesiredAccess, &voa);

    HANDLE hReal = NULL;
    Real_NtOpenKey(&hReal, KEY_READ, OrigOA);

    if (NT_SUCCESS(stV)) {
        *KeyHandle = hVirt;
        TrackHandle(hVirt, hVirt, hReal, fullPath);
        VL_DBG(L"DoVirtOpen: OPEN virtual hVirt=%p hReal=%p", hVirt, hReal);
        return VL_STATUS_SUCCESS;
    }

    if (!hReal) {
        if (hVirt) Real_NtClose(hVirt);
        VL_DBG(L"DoVirtOpen: OPEN neither exists -> NOT_FOUND");
        return VL_STATUS_OBJECT_NOT_FOUND;
    }

    // Copy-on-write
    HANDLE hVirtNew = NULL;
    ULONG disp = 0;
    EnsureVirtualPath(virtPath);
    VL_UNICODE_STRING vus2; MakeUStr(&vus2, virtPath);
    VL_OBJECT_ATTRIBUTES voa2; MakeOA(&voa2, &vus2,
        OrigOA->Attributes | OBJ_CASE_INSENSITIVE);
    NTSTATUS stC = Real_NtCreateKey(&hVirtNew, DesiredAccess | KEY_READ,
                                     &voa2, 0, NULL, 0, &disp);
    if (NT_SUCCESS(stC)) {
        *KeyHandle = hVirtNew;
        TrackHandle(hVirtNew, hVirtNew, hReal, fullPath);
        VL_DBG(L"DoVirtOpen: OPEN CoW hVirt=%p hReal=%p", hVirtNew, hReal);
        return VL_STATUS_SUCCESS;
    }

    VL_DBG(L"DoVirtOpen: OPEN CoW FAILED st=0x%08X -- using real untracked", (ULONG)stC);
    if (hVirtNew) Real_NtClose(hVirtNew);
    if (hReal) {
        *KeyHandle = hReal;
        return VL_STATUS_SUCCESS;
    }
    return stC;
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
    VL_DBG(L"Hook_NtOpenKey: path=%s",
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND) {
        // Sentinel: not in our scope, call real
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    }
    return st;
}

// ---- NtOpenKeyEx (Vista+) ----
static NTSTATUS NTAPI Hook_NtOpenKeyEx(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG                 OpenOptions)
{
    VL_DBG(L"Hook_NtOpenKeyEx: opts=0x%X path=%s", OpenOptions,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
    return st;
}

// ---- NtOpenKeyTransacted (Vista+) ----
// We strip the transaction and open a non-transacted virtual key.
// This is safe for virtualisation: transactions on virtual keys add
// complexity without benefit since the virtual store is our own.
static NTSTATUS NTAPI Hook_NtOpenKeyTransacted(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE                TransactionHandle)
{
    VL_DBG(L"Hook_NtOpenKeyTransacted: TxH=%p path=%s",
           TransactionHandle,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyTransacted(KeyHandle, DesiredAccess,
                                         ObjectAttributes, TransactionHandle);

    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKeyTransacted(KeyHandle, DesiredAccess,
                                         ObjectAttributes, TransactionHandle);
    return st;
}

// ---- NtOpenKeyTransactedEx (Win8+) ----
static NTSTATUS NTAPI Hook_NtOpenKeyTransactedEx(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG                 OpenOptions,
    HANDLE                TransactionHandle)
{
    VL_DBG(L"Hook_NtOpenKeyTransactedEx: TxH=%p opts=0x%X path=%s",
           TransactionHandle, OpenOptions,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyTransactedEx(KeyHandle, DesiredAccess,
                                           ObjectAttributes, OpenOptions,
                                           TransactionHandle);

    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKeyTransactedEx(KeyHandle, DesiredAccess,
                                           ObjectAttributes, OpenOptions,
                                           TransactionHandle);
    return st;
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
    VL_DBG(L"Hook_NtCreateKey: path=%s",
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                 TitleIndex, Class, CreateOptions, Disposition);

    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              true, TitleIndex, Class, CreateOptions, Disposition);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
                                 TitleIndex, Class, CreateOptions, Disposition);
    return st;
}

// ---- NtCreateKeyTransacted (Vista+) ----
static NTSTATUS NTAPI Hook_NtCreateKeyTransacted(
    PHANDLE               KeyHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG                 TitleIndex,
    PVL_UNICODE_STRING    Class,
    ULONG                 CreateOptions,
    HANDLE                TransactionHandle,
    PULONG                Disposition)
{
    VL_DBG(L"Hook_NtCreateKeyTransacted: TxH=%p path=%s",
           TransactionHandle,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");

    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes,
                                           TitleIndex, Class, CreateOptions,
                                           TransactionHandle, Disposition);

    SetReentrant(true);
    // Strip transaction -- virtual store is non-transacted
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              true, TitleIndex, Class, CreateOptions, Disposition);
    SetReentrant(false);

    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes,
                                           TitleIndex, Class, CreateOptions,
                                           TransactionHandle, Disposition);
    return st;
}

// ---- NtQueryKey ----
static NTSTATUS NTAPI Hook_NtQueryKey(
    HANDLE                   KeyHandle,
    VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                    KeyInformation,
    ULONG                    Length,
    PULONG                   ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtQueryKey(KeyHandle, KeyInformationClass,
                               KeyInformation, Length, ResultLength);
    }

    VL_DBG(L"Hook_NtQueryKey: class=%d handle=%p virt=%p real=%p",
           (int)KeyInformationClass, KeyHandle, e.hVirt, e.hReal);

    HANDLE queryH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    return Real_NtQueryKey(queryH, KeyInformationClass,
                            KeyInformation, Length, ResultLength);
}

// ---- NtEnumerateKey -- merged view ----
static NTSTATUS NTAPI Hook_NtEnumerateKey(
    HANDLE                   KeyHandle,
    ULONG                    Index,
    VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                    KeyInformation,
    ULONG                    Length,
    PULONG                   ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtEnumerateKey(KeyHandle, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    }

    VL_DBG(L"Hook_NtEnumerateKey: index=%u handle=%p virt=%p real=%p",
           Index, KeyHandle, e.hVirt, e.hReal);

    HANDLE hV = e.hVirt;
    HANDLE hR = e.hReal;

    if (!hV)
        return Real_NtEnumerateKey(hR ? hR : KeyHandle, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    if (!hR)
        return Real_NtEnumerateKey(hV, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);

    // Merge: virtual first, then real entries not shadowed by virtual
    SetReentrant(true);
    std::vector<std::wstring> virtNames = CollectSubkeyNames(hV);
    SetReentrant(false);

    ULONG virtCount = (ULONG)virtNames.size();
    if (Index < virtCount)
        return Real_NtEnumerateKey(hV, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);

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
            if (skipped == want)
                return Real_NtEnumerateKey(hR, ri, KeyInformationClass,
                                            KeyInformation, Length, ResultLength);
            ++skipped;
        }
    }
}

// ---- NtEnumerateValueKey -- merged view ----
static NTSTATUS NTAPI Hook_NtEnumerateValueKey(
    HANDLE                         KeyHandle,
    ULONG                          Index,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                          KeyValueInformation,
    ULONG                          Length,
    PULONG                         ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtEnumerateValueKey(KeyHandle, Index,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    VL_DBG(L"Hook_NtEnumerateValueKey: index=%u handle=%p virt=%p real=%p",
           Index, KeyHandle, e.hVirt, e.hReal);

    HANDLE hV = e.hVirt;
    HANDLE hR = e.hReal;

    if (!hV)
        return Real_NtEnumerateValueKey(hR ? hR : KeyHandle, Index,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    if (!hR)
        return Real_NtEnumerateValueKey(hV, Index, KeyValueInformationClass,
                                         KeyValueInformation, Length, ResultLength);

    SetReentrant(true);
    std::vector<std::wstring> virtVals = CollectValueNames(hV);
    SetReentrant(false);

    ULONG virtCount = (ULONG)virtVals.size();
    if (Index < virtCount)
        return Real_NtEnumerateValueKey(hV, Index, KeyValueInformationClass,
                                         KeyValueInformation, Length, ResultLength);

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
            if (skipped == want)
                return Real_NtEnumerateValueKey(hR, ri, KeyValueInformationClass,
                                                 KeyValueInformation, Length, ResultLength);
            ++skipped;
        }
    }
}

// ---- NtQueryValueKey -- virtual takes priority ----
static NTSTATUS NTAPI Hook_NtQueryValueKey(
    HANDLE                         KeyHandle,
    PVL_UNICODE_STRING              ValueName,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                          KeyValueInformation,
    ULONG                          Length,
    PULONG                         ResultLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtQueryValueKey(KeyHandle, ValueName,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }

    VL_DBG(L"Hook_NtQueryValueKey: name=%s handle=%p virt=%p real=%p",
           ValueName ? FromUStr(ValueName).c_str() : L"(null)",
           KeyHandle, e.hVirt, e.hReal);

    // Virtual has priority
    if (e.hVirt) {
        NTSTATUS st = Real_NtQueryValueKey(e.hVirt, ValueName,
                            KeyValueInformationClass, KeyValueInformation,
                            Length, ResultLength);
        if (NT_SUCCESS(st) || st == VL_STATUS_BUFFER_TOO_SMALL ||
            st == VL_STATUS_BUFFER_OVERFLOW)
            return st;
    }
    if (e.hReal) {
        return Real_NtQueryValueKey(e.hReal, ValueName,
                    KeyValueInformationClass, KeyValueInformation,
                    Length, ResultLength);
    }
    return Real_NtQueryValueKey(KeyHandle, ValueName,
                KeyValueInformationClass, KeyValueInformation,
                Length, ResultLength);
}

// ---- NtQueryMultipleValueKey -- route to virtual handle ----
static NTSTATUS NTAPI Hook_NtQueryMultipleValueKey(
    HANDLE             KeyHandle,
    PVL_KEY_VALUE_ENTRY ValueEntries,
    ULONG              EntryCount,
    PVOID              ValueBuffer,
    PULONG             BufferLength,
    PULONG             RequiredBufferLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtQueryMultipleValueKey(KeyHandle, ValueEntries, EntryCount,
                                             ValueBuffer, BufferLength,
                                             RequiredBufferLength);
    }

    VL_DBG(L"Hook_NtQueryMultipleValueKey: entryCount=%u handle=%p virt=%p real=%p",
           EntryCount, KeyHandle, e.hVirt, e.hReal);

    // Try virtual first; fall back to real for entries not found
    HANDLE useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    NTSTATUS st = Real_NtQueryMultipleValueKey(useH, ValueEntries, EntryCount,
                                                ValueBuffer, BufferLength,
                                                RequiredBufferLength);
    if (!NT_SUCCESS(st) && e.hReal && e.hReal != useH) {
        VL_DBG(L"Hook_NtQueryMultipleValueKey: virtual failed, trying real");
        st = Real_NtQueryMultipleValueKey(e.hReal, ValueEntries, EntryCount,
                                           ValueBuffer, BufferLength,
                                           RequiredBufferLength);
    }
    return st;
}

// ---- NtSetValueKey -- write to virtual ----
static NTSTATUS NTAPI Hook_NtSetValueKey(
    HANDLE             KeyHandle,
    PVL_UNICODE_STRING ValueName,
    ULONG              TitleIndex,
    ULONG              Type,
    PVOID              Data,
    ULONG              DataSize)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtSetValueKey(KeyHandle, ValueName, TitleIndex,
                                   Type, Data, DataSize);
    }

    VL_DBG(L"Hook_NtSetValueKey: name=%s handle=%p virt=%p",
           ValueName ? FromUStr(ValueName).c_str() : L"(null)",
           KeyHandle, e.hVirt);

    HANDLE writeH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    return Real_NtSetValueKey(writeH, ValueName, TitleIndex, Type, Data, DataSize);
}

// ---- NtDeleteKey -- delete from virtual only ----
static NTSTATUS NTAPI Hook_NtDeleteKey(HANDLE KeyHandle) {
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        VL_DBG(L"Hook_NtDeleteKey: untracked handle=%p", KeyHandle);
        return Real_NtDeleteKey(KeyHandle);
    }

    VL_DBG(L"Hook_NtDeleteKey: handle=%p virt=%p real=%p",
           KeyHandle, e.hVirt, e.hReal);

    if (e.hVirt) return Real_NtDeleteKey(e.hVirt);
    return Real_NtDeleteKey(e.hReal ? e.hReal : KeyHandle);
}

// ---- NtDeleteValueKey -- delete from virtual only ----
static NTSTATUS NTAPI Hook_NtDeleteValueKey(
    HANDLE             KeyHandle,
    PVL_UNICODE_STRING ValueName)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        VL_DBG(L"Hook_NtDeleteValueKey: untracked handle=%p name=%s",
               KeyHandle, ValueName ? FromUStr(ValueName).c_str() : L"(null)");
        return Real_NtDeleteValueKey(KeyHandle, ValueName);
    }

    VL_DBG(L"Hook_NtDeleteValueKey: name=%s handle=%p virt=%p",
           ValueName ? FromUStr(ValueName).c_str() : L"(null)",
           KeyHandle, e.hVirt);

    if (e.hVirt) return Real_NtDeleteValueKey(e.hVirt, ValueName);
    return Real_NtDeleteValueKey(e.hReal ? e.hReal : KeyHandle, ValueName);
}

// ---- NtRenameKey -- rename in virtual store ----
static NTSTATUS NTAPI Hook_NtRenameKey(
    HANDLE             KeyHandle,
    PVL_UNICODE_STRING NewName)
{
    VirtKeyEntry e;
    bool tracked = g_RegEnabled && GetEntry(KeyHandle, e);
    HANDLE useH  = tracked ? (e.hVirt ? e.hVirt : e.hReal) : KeyHandle;

    VL_DBG(L"Hook_NtRenameKey: handle=%p useH=%p newName=%s",
           KeyHandle, useH,
           NewName ? FromUStr(NewName).c_str() : L"(null)");

    return Real_NtRenameKey(useH, NewName);
}

// ---- NtReplaceKey -- complex (hive replacement); pass through with log ----
static NTSTATUS NTAPI Hook_NtReplaceKey(
    PVL_OBJECT_ATTRIBUTES NewFile,
    HANDLE                TargetHandle,
    PVL_OBJECT_ATTRIBUTES OldFile)
{
    VL_DBG(L"Hook_NtReplaceKey: TargetHandle=%p NewFile=%s OldFile=%s",
           TargetHandle,
           (NewFile && NewFile->ObjectName) ? FromUStr(NewFile->ObjectName).c_str() : L"(null)",
           (OldFile && OldFile->ObjectName) ? FromUStr(OldFile->ObjectName).c_str() : L"(null)");

    // NtReplaceKey is an admin operation (replaces a whole hive from a file).
    // We route the target handle to virtual if tracked; file paths pass through.
    VirtKeyEntry e;
    HANDLE useH = TargetHandle;
    if (g_RegEnabled && GetEntry(TargetHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : TargetHandle);

    return Real_NtReplaceKey(NewFile, useH, OldFile);
}

// ---- NtSaveKey -- save virtual key to file ----
static NTSTATUS NTAPI Hook_NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtSaveKey: handle=%p useH=%p fileH=%p",
           KeyHandle, useH, FileHandle);

    return Real_NtSaveKey(useH, FileHandle);
}

// ---- NtSaveKeyEx -- save virtual key to file (extended) ----
static NTSTATUS NTAPI Hook_NtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtSaveKeyEx: handle=%p useH=%p fileH=%p fmt=%u",
           KeyHandle, useH, FileHandle, Format);

    return Real_NtSaveKeyEx(useH, FileHandle, Format);
}

// ---- NtLoadKey -- redirect TargetKey to virtual path ----
static NTSTATUS NTAPI Hook_NtLoadKey(
    PVL_OBJECT_ATTRIBUTES TargetKey,
    PVL_OBJECT_ATTRIBUTES SourceFile)
{
    std::wstring fullPath = GetFullNtPath(TargetKey);
    VL_DBG(L"Hook_NtLoadKey: target=%s", fullPath.c_str());

    std::wstring virtPath;
    if (!g_RegEnabled || !LogicalToVirtual(fullPath, virtPath))
        return Real_NtLoadKey(TargetKey, SourceFile);

    VL_DBG(L"Hook_NtLoadKey: REDIRECT target -> %s", virtPath.c_str());
    EnsureVirtualPath(virtPath);
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        TargetKey->Attributes | OBJ_CASE_INSENSITIVE);

    return Real_NtLoadKey(&voa, SourceFile);
}

// ---- NtLoadKey2 -- redirect TargetKey to virtual path ----
static NTSTATUS NTAPI Hook_NtLoadKey2(
    PVL_OBJECT_ATTRIBUTES TargetKey,
    PVL_OBJECT_ATTRIBUTES SourceFile,
    ULONG                 Flags)
{
    std::wstring fullPath = GetFullNtPath(TargetKey);
    VL_DBG(L"Hook_NtLoadKey2: flags=0x%X target=%s", Flags, fullPath.c_str());

    std::wstring virtPath;
    if (!g_RegEnabled || !LogicalToVirtual(fullPath, virtPath))
        return Real_NtLoadKey2(TargetKey, SourceFile, Flags);

    VL_DBG(L"Hook_NtLoadKey2: REDIRECT target -> %s", virtPath.c_str());
    EnsureVirtualPath(virtPath);
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        TargetKey->Attributes | OBJ_CASE_INSENSITIVE);

    return Real_NtLoadKey2(&voa, SourceFile, Flags);
}

// ---- NtLoadKeyEx -- redirect TargetKey to virtual path ----
static NTSTATUS NTAPI Hook_NtLoadKeyEx(
    PVL_OBJECT_ATTRIBUTES TargetKey,
    PVL_OBJECT_ATTRIBUTES SourceFile,
    ULONG                 Flags,
    HANDLE                TrustClassKey,
    HANDLE                Event,
    ULONG                 DesiredAccess,
    PHANDLE               RootHandle,
    PVOID                 Reserved)
{
    std::wstring fullPath = GetFullNtPath(TargetKey);
    VL_DBG(L"Hook_NtLoadKeyEx: flags=0x%X target=%s", Flags, fullPath.c_str());

    std::wstring virtPath;
    if (!g_RegEnabled || !LogicalToVirtual(fullPath, virtPath))
        return Real_NtLoadKeyEx(TargetKey, SourceFile, Flags,
                                 TrustClassKey, Event, DesiredAccess,
                                 RootHandle, Reserved);

    VL_DBG(L"Hook_NtLoadKeyEx: REDIRECT target -> %s", virtPath.c_str());
    EnsureVirtualPath(virtPath);
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        TargetKey->Attributes | OBJ_CASE_INSENSITIVE);

    return Real_NtLoadKeyEx(&voa, SourceFile, Flags,
                             TrustClassKey, Event, DesiredAccess,
                             RootHandle, Reserved);
}

// ---- NtNotifyChangeKey -- forward to virtual handle ----
static NTSTATUS NTAPI Hook_NtNotifyChangeKey(
    HANDLE              KeyHandle,
    HANDLE              Event,
    VL_PIO_APC_ROUTINE  ApcRoutine,
    PVOID               ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    ULONG               CompletionFilter,
    BOOLEAN             WatchTree,
    PVOID               Buffer,
    ULONG               BufferSize,
    BOOLEAN             Asynchronous)
{
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtNotifyChangeKey: handle=%p useH=%p filter=0x%X async=%d",
           KeyHandle, useH, CompletionFilter, (int)Asynchronous);

    return Real_NtNotifyChangeKey(useH, Event, ApcRoutine, ApcContext,
                                   IoStatusBlock, CompletionFilter, WatchTree,
                                   Buffer, BufferSize, Asynchronous);
}

// ---- NtNotifyChangeMultipleKeys -- forward master handle to virtual ----
static NTSTATUS NTAPI Hook_NtNotifyChangeMultipleKeys(
    HANDLE              MasterKeyHandle,
    ULONG               Count,
    PVL_OBJECT_ATTRIBUTES SubordinateObjects,
    HANDLE              Event,
    VL_PIO_APC_ROUTINE  ApcRoutine,
    PVOID               ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    ULONG               CompletionFilter,
    BOOLEAN             WatchTree,
    PVOID               Buffer,
    ULONG               BufferSize,
    BOOLEAN             Asynchronous)
{
    VirtKeyEntry e;
    HANDLE useH = MasterKeyHandle;
    if (g_RegEnabled && GetEntry(MasterKeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : MasterKeyHandle);

    VL_DBG(L"Hook_NtNotifyChangeMultipleKeys: masterH=%p useH=%p count=%u filter=0x%X",
           MasterKeyHandle, useH, Count, CompletionFilter);

    return Real_NtNotifyChangeMultipleKeys(useH, Count, SubordinateObjects,
                                            Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, CompletionFilter,
                                            WatchTree, Buffer, BufferSize,
                                            Asynchronous);
}

// ---- NtFlushKey -- redirect tracked handle to virtual hive ----
// Without this hook an app that calls NtFlushKey with a handle obtained
// outside our open/create path could flush a real hive key, exposing the
// app's registry footprint in the global hive.
static NTSTATUS NTAPI Hook_NtFlushKey(HANDLE KeyHandle) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtFlushKey: handle=%p useH=%p", KeyHandle, useH);

    return Real_NtFlushKey(useH);
}

// ---- NtRestoreKey -- redirect tracked handle to virtual hive ----
// NtRestoreKey loads a hive file onto an existing key.  Redirecting to
// hVirt ensures the restore lands in the virtual store, not the real hive.
static NTSTATUS NTAPI Hook_NtRestoreKey(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG  Flags)
{
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtRestoreKey: handle=%p useH=%p fileH=%p flags=0x%X",
           KeyHandle, useH, FileHandle, Flags);

    return Real_NtRestoreKey(useH, FileHandle, Flags);
}

// ---- NtSetInformationKey -- redirect tracked handle to virtual hive ----
// Prevents key metadata changes (e.g. virtualization flags, last-write time
// via KeyWriteTimeInformation) from leaking to the real hive.
static NTSTATUS NTAPI Hook_NtSetInformationKey(
    HANDLE KeyHandle,
    ULONG  KeySetInformationClass,
    PVOID  KeySetInformation,
    ULONG  KeySetInformationLength)
{
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);

    VL_DBG(L"Hook_NtSetInformationKey: handle=%p useH=%p class=%u len=%u",
           KeyHandle, useH, KeySetInformationClass, KeySetInformationLength);

    return Real_NtSetInformationKey(useH, KeySetInformationClass,
                                     KeySetInformation, KeySetInformationLength);
}

// ---- NtUnloadKey -- redirect OA target to virtual path ----
// NtUnloadKey takes an OBJECT_ATTRIBUTES (absolute path), NOT a handle.
// Without this hook an app (or a library it loads) can unload a real hive
// subtree by absolute path regardless of our open/create redirections.
static NTSTATUS NTAPI Hook_NtUnloadKey(PVL_OBJECT_ATTRIBUTES TargetKey) {
    std::wstring fullPath = GetFullNtPath(TargetKey);
    VL_DBG(L"Hook_NtUnloadKey: target=%s", fullPath.c_str());

    std::wstring virtPath;
    if (!g_RegEnabled || !LogicalToVirtual(fullPath, virtPath))
        return Real_NtUnloadKey(TargetKey);

    VL_DBG(L"Hook_NtUnloadKey: REDIRECT target -> %s", virtPath.c_str());
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        TargetKey->Attributes | OBJ_CASE_INSENSITIVE);

    return Real_NtUnloadKey(&voa);
}

// ---- NtLoadKey3 (Win10 RS5 / 1809+) -- redirect TargetKey to virtual path ----
// NtLoadKey3 is the newest load variant; semantically identical to NtLoadKeyEx
// for our purposes.  Without this hook a newly compiled app can load a hive
// into the real registry even though NtLoadKey/NtLoadKey2/NtLoadKeyEx are all
// redirected.
static NTSTATUS NTAPI Hook_NtLoadKey3(
    PVL_OBJECT_ATTRIBUTES TargetKey,
    PVL_OBJECT_ATTRIBUTES SourceFile,
    ULONG                 Flags,
    PVOID                 ExtendedParameters,
    ULONG                 ExtendedParameterCount,
    ULONG                 DesiredAccess,
    HANDLE                RootHandle,
    PVOID                 Reserved)
{
    std::wstring fullPath = GetFullNtPath(TargetKey);
    VL_DBG(L"Hook_NtLoadKey3: flags=0x%X extParamCount=%u target=%s",
           Flags, ExtendedParameterCount, fullPath.c_str());

    std::wstring virtPath;
    if (!g_RegEnabled || !LogicalToVirtual(fullPath, virtPath))
        return Real_NtLoadKey3(TargetKey, SourceFile, Flags,
                                ExtendedParameters, ExtendedParameterCount,
                                DesiredAccess, RootHandle, Reserved);

    VL_DBG(L"Hook_NtLoadKey3: REDIRECT target -> %s", virtPath.c_str());
    EnsureVirtualPath(virtPath);
    VL_UNICODE_STRING vus; MakeUStr(&vus, virtPath);
    VL_OBJECT_ATTRIBUTES voa; MakeOA(&voa, &vus,
        TargetKey->Attributes | OBJ_CASE_INSENSITIVE);

    return Real_NtLoadKey3(&voa, SourceFile, Flags,
                            ExtendedParameters, ExtendedParameterCount,
                            DesiredAccess, RootHandle, Reserved);
}

// ---- NtClose -- CRITICAL: only special-case tracked handles ----
static NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    VirtKeyEntry e;
    if (!GetEntry(Handle, e)) {
        return Real_NtClose(Handle);
    }

    VL_DBG(L"Hook_NtClose: tracked handle=%p hVirt=%p hReal=%p",
           Handle, e.hVirt, e.hReal);

    UntrackHandle(Handle);

    NTSTATUS st = VL_STATUS_SUCCESS;
    if (e.hVirt == Handle) {
        st = Real_NtClose(Handle);
        if (e.hReal && e.hReal != Handle)
            Real_NtClose(e.hReal);
    } else if (e.hReal == Handle) {
        st = Real_NtClose(Handle);
        if (e.hVirt && e.hVirt != Handle)
            Real_NtClose(e.hVirt);
    } else {
        if (e.hVirt) Real_NtClose(e.hVirt);
        if (e.hReal) Real_NtClose(e.hReal);
        st = Real_NtClose(Handle);
    }
    return st;
}

// ============================================================
// Reparse Point Constants and Structures
// (for NtFsControlFile FSCTL_SET_REPARSE_POINT interception)
// ============================================================

#define VL_FSCTL_SET_REPARSE_POINT  0x000900A4UL
#define VL_IO_REPARSE_TAG_MOUNT_POINT 0xA0000003UL
#define VL_IO_REPARSE_TAG_SYMLINK     0xA000000CUL
#define VL_SYMLINK_FLAG_RELATIVE      0x00000001UL

// REPARSE_DATA_BUFFER header size (ReparseTag+ReparseDataLength+Reserved)
#define VL_REPARSE_HDR_SIZE       8
// Fixed fields before PathBuffer for each tag type (bytes):
//   SymLink:     SubstOff(2)+SubstLen(2)+PrtOff(2)+PrtLen(2)+Flags(4) = 12
//   MountPoint:  SubstOff(2)+SubstLen(2)+PrtOff(2)+PrtLen(2)          =  8
#define VL_SYMLINK_FIELDS_SIZE    12
#define VL_MOUNTPOINT_FIELDS_SIZE  8

// Mirrors REPARSE_DATA_BUFFER from ntifs.h.
// No #pragma pack needed: all natural alignment works out.
struct VL_REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength; // byte count of the union below (not including the 8-byte header)
    USHORT Reserved;
    union {
        struct {                        // IO_REPARSE_TAG_SYMLINK
            USHORT SubstituteNameOffset;  // byte offset into PathBuffer
            USHORT SubstituteNameLength;  // byte length
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;               // VL_SYMLINK_FLAG_RELATIVE if relative
            WCHAR  PathBuffer[1];       // SubstituteName then PrintName (not null-terminated)
        } SymLink;
        struct {                        // IO_REPARSE_TAG_MOUNT_POINT (junctions)
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPoint;
    };
};

// Redirect a path that may be:
//   - NT form:    \??\C:\ccc\file  (redirect directly)
//   - Win32 form: C:\ccc\file       (convert to NT, redirect, strip \??\ back)
// Returns the input unchanged if no redirect matches.
static std::wstring RedirectSymlinkPath(const std::wstring& path) {
    if (path.empty()) return path;

    // Try as-is (covers \??\ and \Device\ prefixed NT paths)
    std::wstring red = ApplyFsRedirect(path);
    if (red != path) return red;

    // Try as a Win32-style path (e.g. C:\ccc\...)
    std::wstring nt = Win32ToNtPath(path);
    if (nt != path) {
        red = ApplyFsRedirect(nt);
        if (red != nt) {
            // Strip the \??\ we prepended if the original didn't have it
            if (StartsWithI(red, L"\\??\\") && !StartsWithI(path, L"\\??\\"))
                return red.substr(4);
            return red;
        }
    }
    return path;
}

// ============================================================
// FILE SYSTEM HOOKS
// ============================================================

// FILE_OPEN_BY_FILE_ID: when set in CreateOptions/OpenOptions, ObjectName
// contains a raw binary file ID (8 bytes NTFS, 16 bytes ReFS), NOT a path.
// Path-based redirection cannot apply to such opens; we skip RedirectFileOA
// entirely and pass through directly.  (Without this guard FromUStr would
// silently interpret the binary ID as garbage wchar_t characters.)
#ifndef FILE_OPEN_BY_FILE_ID
#  define FILE_OPEN_BY_FILE_ID 0x00002000
#endif

// ---- NtCreateFile ----
static NTSTATUS NTAPI Hook_NtCreateFile(
    PHANDLE               FileHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER        AllocationSize,
    ULONG                 FileAttributes,
    ULONG                 ShareAccess,
    ULONG                 CreateDisposition,
    ULONG                 CreateOptions,
    PVOID                 EaBuffer,
    ULONG                 EaLength)
{
    // When FILE_OPEN_BY_FILE_ID is set the ObjectName field contains a
    // binary file ID, not a string.  Pass through without touching it.
    if (CreateOptions & FILE_OPEN_BY_FILE_ID) {
        VL_DBG(L"Hook_NtCreateFile: FILE_OPEN_BY_FILE_ID - pass through");
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);
    }

    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtCreateFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);

    VL_DBG(L"Hook_NtCreateFile: -> %s", redPath.c_str());
    return Real_NtCreateFile(FileHandle, DesiredAccess, &newOa,
                              IoStatusBlock, AllocationSize, FileAttributes,
                              ShareAccess, CreateDisposition, CreateOptions,
                              EaBuffer, EaLength);
}

// ---- NtOpenFile ----
static NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE               FileHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    ULONG                 ShareAccess,
    ULONG                 OpenOptions)
{
    // Same FILE_OPEN_BY_FILE_ID guard as NtCreateFile.
    if (OpenOptions & FILE_OPEN_BY_FILE_ID) {
        VL_DBG(L"Hook_NtOpenFile: FILE_OPEN_BY_FILE_ID - pass through");
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtOpenFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);

    VL_DBG(L"Hook_NtOpenFile: -> %s", redPath.c_str());
    return Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                            IoStatusBlock, ShareAccess, OpenOptions);
}

// ---- NtCreateDirectoryObject ----
static NTSTATUS NTAPI Hook_NtCreateDirectoryObject(
    PHANDLE               DirectoryHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtCreateDirectoryObject: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);

    VL_DBG(L"Hook_NtCreateDirectoryObject: -> %s", redPath.c_str());
    return Real_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess, &newOa);
}

// ---- NtOpenDirectoryObject ----
static NTSTATUS NTAPI Hook_NtOpenDirectoryObject(
    PHANDLE               DirectoryHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtOpenDirectoryObject: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);

    VL_DBG(L"Hook_NtOpenDirectoryObject: -> %s", redPath.c_str());
    return Real_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, &newOa);
}

// ---- NtCreateMailslotFile ----
static NTSTATUS NTAPI Hook_NtCreateMailslotFile(
    PHANDLE               FileHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    ULONG                 CreateOptions,
    ULONG                 MailslotQuota,
    ULONG                 MaximumMessageSize,
    PLARGE_INTEGER        ReadTimeout)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtCreateMailslotFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtCreateMailslotFile(FileHandle, DesiredAccess, ObjectAttributes,
                                          IoStatusBlock, CreateOptions,
                                          MailslotQuota, MaximumMessageSize, ReadTimeout);

    VL_DBG(L"Hook_NtCreateMailslotFile: -> %s", redPath.c_str());
    return Real_NtCreateMailslotFile(FileHandle, DesiredAccess, &newOa,
                                      IoStatusBlock, CreateOptions,
                                      MailslotQuota, MaximumMessageSize, ReadTimeout);
}

// ---- NtCreateNamedPipeFile ----
static NTSTATUS NTAPI Hook_NtCreateNamedPipeFile(
    PHANDLE               FileHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    ULONG                 ShareAccess,
    ULONG                 CreateDisposition,
    ULONG                 CreateOptions,
    ULONG                 NamedPipeType,
    ULONG                 ReadMode,
    ULONG                 CompletionMode,
    ULONG                 MaximumInstances,
    ULONG                 InboundQuota,
    ULONG                 OutboundQuota,
    PLARGE_INTEGER        DefaultTimeout)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtCreateNamedPipeFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes,
                                           IoStatusBlock, ShareAccess, CreateDisposition,
                                           CreateOptions, NamedPipeType, ReadMode,
                                           CompletionMode, MaximumInstances,
                                           InboundQuota, OutboundQuota, DefaultTimeout);

    VL_DBG(L"Hook_NtCreateNamedPipeFile: -> %s", redPath.c_str());
    return Real_NtCreateNamedPipeFile(FileHandle, DesiredAccess, &newOa,
                                       IoStatusBlock, ShareAccess, CreateDisposition,
                                       CreateOptions, NamedPipeType, ReadMode,
                                       CompletionMode, MaximumInstances,
                                       InboundQuota, OutboundQuota, DefaultTimeout);
}

// ---- NtDeleteFile ----
static NTSTATUS NTAPI Hook_NtDeleteFile(PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtDeleteFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtDeleteFile(ObjectAttributes);

    VL_DBG(L"Hook_NtDeleteFile: -> %s", redPath.c_str());
    return Real_NtDeleteFile(&newOa);
}

// ---- NtQueryAttributesFile ----
// Simpler variant of NtQueryFullAttributesFile (returns FILE_BASIC_INFORMATION).
static NTSTATUS NTAPI Hook_NtQueryAttributesFile(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVOID                 FileInformation)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtQueryAttributesFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtQueryAttributesFile(ObjectAttributes, FileInformation);

    VL_DBG(L"Hook_NtQueryAttributesFile: -> %s", redPath.c_str());
    return Real_NtQueryAttributesFile(&newOa, FileInformation);
}

// ---- NtQueryFullAttributesFile ----
// Used by GetFileAttributesW internally.
static NTSTATUS NTAPI Hook_NtQueryFullAttributesFile(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVOID                 FileInformation)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtQueryFullAttributesFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    VL_DBG(L"Hook_NtQueryFullAttributesFile: -> %s", redPath.c_str());
    return Real_NtQueryFullAttributesFile(&newOa, FileInformation);
}

// ---- NtQueryInformationByName (Win10+) ----
// Queries file information by name without opening a handle.
static NTSTATUS NTAPI Hook_NtQueryInformationByName(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    PVOID                 FileInformation,
    ULONG                 Length,
    ULONG                 FileInformationClass)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    VL_DBG(L"Hook_NtQueryInformationByName: class=%u %s%s",
           FileInformationClass, ntPath.c_str(),
           redirected ? L" [REDIRECT]" : L"");

    if (!redirected)
        return Real_NtQueryInformationByName(ObjectAttributes, IoStatusBlock,
                                              FileInformation, Length,
                                              FileInformationClass);

    VL_DBG(L"Hook_NtQueryInformationByName: -> %s", redPath.c_str());
    return Real_NtQueryInformationByName(&newOa, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
}

// ---- NtFsControlFile -- intercepts FSCTL_SET_REPARSE_POINT ----
//
// Symbolic links and junctions store their target path inside NTFS reparse
// point data that is written by NtFsControlFile(FSCTL_SET_REPARSE_POINT).
// The NT kernel resolves these reparse paths *in kernel mode*, completely
// bypassing user-mode hooks.  Therefore, if the embedded target path still
// refers to the original (non-virtualized) location (e.g. \??\C:\ccc\file)
// the kernel will fail to follow the link because C:\ccc doesn't exist on
// real disk.
//
// This hook intercepts the FSCTL call, extracts the SubstituteName (used by
// the kernel for resolution) and the PrintName (display only) from the
// REPARSE_DATA_BUFFER, applies the same FS redirections that NtCreateFile
// uses, rebuilds the buffer with the redirected paths, and forwards it.
//
// Covered reparse tags:
//   IO_REPARSE_TAG_SYMLINK (0xA000000C): mklink / CreateSymbolicLinkW
//   IO_REPARSE_TAG_MOUNT_POINT (0xA0000003): mklink /J (junction points)
//
// Relative symlinks (SYMLINK_FLAG_RELATIVE) are skipped -- their target is
// relative to the link's own parent directory and requires no prefix redirect.
static NTSTATUS NTAPI Hook_NtFsControlFile(
    HANDLE              FileHandle,
    HANDLE              Event,
    VL_PIO_APC_ROUTINE  ApcRoutine,
    PVOID               ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    ULONG               FsControlCode,
    PVOID               InputBuffer,
    ULONG               InputBufferLength,
    PVOID               OutputBuffer,
    ULONG               OutputBufferLength)
{
    // Only intercept FSCTL_SET_REPARSE_POINT when FS virtualisation is active
    if (!g_FsEnabled ||
        FsControlCode != VL_FSCTL_SET_REPARSE_POINT ||
        !InputBuffer ||
        InputBufferLength < VL_REPARSE_HDR_SIZE)
    {
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     InputBuffer, InputBufferLength,
                                     OutputBuffer, OutputBufferLength);
    }

    VL_REPARSE_DATA_BUFFER* rdb = (VL_REPARSE_DATA_BUFFER*)InputBuffer;

    // ---- Symbolic link ----
    if (rdb->ReparseTag == VL_IO_REPARSE_TAG_SYMLINK) {

        // Relative symlinks use a path relative to the link's own directory;
        // prefix-based redirection doesn't apply to them.
        if (rdb->SymLink.Flags & VL_SYMLINK_FLAG_RELATIVE) {
            VL_DBG(L"Hook_NtFsControlFile SYMLINK: relative -- pass through");
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        }

        WCHAR* pathBuf = rdb->SymLink.PathBuffer;
        std::wstring subst(pathBuf + rdb->SymLink.SubstituteNameOffset / sizeof(WCHAR),
                            rdb->SymLink.SubstituteNameLength / sizeof(WCHAR));
        std::wstring print(pathBuf + rdb->SymLink.PrintNameOffset / sizeof(WCHAR),
                            rdb->SymLink.PrintNameLength / sizeof(WCHAR));

        std::wstring redSubst = RedirectSymlinkPath(subst);
        std::wstring redPrint = RedirectSymlinkPath(print);

        VL_DBG(L"Hook_NtFsControlFile SYMLINK: subst=%s->%s  print=%s->%s",
               subst.c_str(), redSubst.c_str(), print.c_str(), redPrint.c_str());

        if (redSubst == subst && redPrint == print) {
            // Nothing to redirect
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        }

        // Rebuild the reparse buffer with redirected paths.
        // Layout: [8-byte header][12-byte symlink fields][SubstituteName][PrintName]
        USHORT newSubBytes      = (USHORT)(redSubst.size() * sizeof(WCHAR));
        USHORT newPrtBytes      = (USHORT)(redPrint.size() * sizeof(WCHAR));
        USHORT newReparseDataLen = (USHORT)(VL_SYMLINK_FIELDS_SIZE + newSubBytes + newPrtBytes);
        ULONG  newBufSize       = VL_REPARSE_HDR_SIZE + newReparseDataLen;

        std::vector<BYTE> newBuf(newBufSize, 0);
        VL_REPARSE_DATA_BUFFER* n = (VL_REPARSE_DATA_BUFFER*)newBuf.data();
        n->ReparseTag                   = rdb->ReparseTag;
        n->ReparseDataLength            = newReparseDataLen;
        n->Reserved                     = 0;
        n->SymLink.SubstituteNameOffset = 0;
        n->SymLink.SubstituteNameLength = newSubBytes;
        n->SymLink.PrintNameOffset      = newSubBytes;   // immediately after SubstituteName
        n->SymLink.PrintNameLength      = newPrtBytes;
        n->SymLink.Flags                = rdb->SymLink.Flags;
        memcpy(n->SymLink.PathBuffer,
               redSubst.c_str(), newSubBytes);
        memcpy((BYTE*)n->SymLink.PathBuffer + newSubBytes,
               redPrint.c_str(), newPrtBytes);

        VL_DBG(L"Hook_NtFsControlFile SYMLINK: rebuilt buffer %u->%u bytes", InputBufferLength, newBufSize);
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     newBuf.data(), newBufSize,
                                     OutputBuffer, OutputBufferLength);
    }

    // ---- Junction / mount point ----
    if (rdb->ReparseTag == VL_IO_REPARSE_TAG_MOUNT_POINT) {

        WCHAR* pathBuf = rdb->MountPoint.PathBuffer;
        std::wstring subst(pathBuf + rdb->MountPoint.SubstituteNameOffset / sizeof(WCHAR),
                            rdb->MountPoint.SubstituteNameLength / sizeof(WCHAR));
        std::wstring print(pathBuf + rdb->MountPoint.PrintNameOffset / sizeof(WCHAR),
                            rdb->MountPoint.PrintNameLength / sizeof(WCHAR));

        std::wstring redSubst = RedirectSymlinkPath(subst);
        std::wstring redPrint = RedirectSymlinkPath(print);

        VL_DBG(L"Hook_NtFsControlFile JUNCTION: subst=%s->%s  print=%s->%s",
               subst.c_str(), redSubst.c_str(), print.c_str(), redPrint.c_str());

        if (redSubst == subst && redPrint == print) {
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        }

        // Rebuild: [8-byte header][8-byte mountpoint fields][SubstituteName][PrintName]
        USHORT newSubBytes       = (USHORT)(redSubst.size() * sizeof(WCHAR));
        USHORT newPrtBytes       = (USHORT)(redPrint.size() * sizeof(WCHAR));
        USHORT newReparseDataLen = (USHORT)(VL_MOUNTPOINT_FIELDS_SIZE + newSubBytes + newPrtBytes);
        ULONG  newBufSize        = VL_REPARSE_HDR_SIZE + newReparseDataLen;

        std::vector<BYTE> newBuf(newBufSize, 0);
        VL_REPARSE_DATA_BUFFER* n = (VL_REPARSE_DATA_BUFFER*)newBuf.data();
        n->ReparseTag                       = rdb->ReparseTag;
        n->ReparseDataLength                = newReparseDataLen;
        n->Reserved                         = 0;
        n->MountPoint.SubstituteNameOffset  = 0;
        n->MountPoint.SubstituteNameLength  = newSubBytes;
        n->MountPoint.PrintNameOffset       = newSubBytes;
        n->MountPoint.PrintNameLength       = newPrtBytes;
        memcpy(n->MountPoint.PathBuffer,
               redSubst.c_str(), newSubBytes);
        memcpy((BYTE*)n->MountPoint.PathBuffer + newSubBytes,
               redPrint.c_str(), newPrtBytes);

        VL_DBG(L"Hook_NtFsControlFile JUNCTION: rebuilt buffer %u->%u bytes", InputBufferLength, newBufSize);
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     newBuf.data(), newBufSize,
                                     OutputBuffer, OutputBufferLength);
    }

    // Unknown reparse tag -- pass through untouched
    return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                 IoStatusBlock, FsControlCode,
                                 InputBuffer, InputBufferLength,
                                 OutputBuffer, OutputBufferLength);
}

// ---- NtSetInformationFile -- intercepts rename and hardlink creation ----
//
// Both FILE_RENAME_INFORMATION and FILE_LINK_INFORMATION embed a target
// path string in their payload.  The structures are IDENTICAL in memory
// layout -- same field ordering and same arch-dependent offsets -- so the
// same translation code handles all four classes.
//
//   FileRenameInformation   (10): rename target path must stay in virt store
//   FileLinkInformation     (11): hardlink target path must stay in virt store
//   FileRenameInformationEx (65): Windows 10 RS1+ extended rename
//   FileLinkInformationEx   (72): Windows 10 RS1+ extended hardlink
//
// Without handling FileLinkInformation a sandboxed app can call
// NtSetInformationFile(..., FileLinkInformation, ...) with a real host path
// and create a hardlink that escapes the virtual file store entirely.
//
//   32-bit layout: offset 0 BOOLEAN, +4 HANDLE, +8 ULONG NameLen, +12 WCHAR Name[]
//   64-bit layout: offset 0 BOOLEAN, +8 HANDLE, +16 ULONG NameLen, +20 WCHAR Name[]
//
#define FileRenameInformation   10
#define FileLinkInformation     11
#define FileRenameInformationEx 65   // Windows 10 RS1+
#define FileLinkInformationEx   72   // Windows 10 RS1+

#ifdef _WIN64
#  define RENAME_INFO_HANDLE_OFFSET   8
#  define RENAME_INFO_NAMELEN_OFFSET  16
#  define RENAME_INFO_NAME_OFFSET     20
#  define RENAME_INFO_MIN_SIZE        20
#else
#  define RENAME_INFO_HANDLE_OFFSET   4
#  define RENAME_INFO_NAMELEN_OFFSET  8
#  define RENAME_INFO_NAME_OFFSET     12
#  define RENAME_INFO_MIN_SIZE        12
#endif

static NTSTATUS NTAPI Hook_NtSetInformationFile(
    HANDLE              FileHandle,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID               FileInformation,
    ULONG               Length,
    ULONG               FileInformationClass)
{
    VL_DBG(L"Hook_NtSetInformationFile: handle=%p class=%u len=%u",
           FileHandle, FileInformationClass, Length);

    if (!g_FsEnabled || IsReentrant() ||
        (FileInformationClass != FileRenameInformation &&
         FileInformationClass != FileRenameInformationEx &&
         FileInformationClass != FileLinkInformation    &&
         FileInformationClass != FileLinkInformationEx) ||
        !FileInformation || Length < RENAME_INFO_MIN_SIZE)
    {
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    BYTE*  p           = (BYTE*)FileInformation;
    ULONG  nameByteLen = *(ULONG*)(p + RENAME_INFO_NAMELEN_OFFSET);

    if (nameByteLen == 0 || Length < (ULONG)(RENAME_INFO_NAME_OFFSET + nameByteLen))
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);

    std::wstring origName((WCHAR*)(p + RENAME_INFO_NAME_OFFSET),
                           nameByteLen / sizeof(WCHAR));

    const bool isLink = (FileInformationClass == FileLinkInformation ||
                         FileInformationClass == FileLinkInformationEx);
    VL_DBG(L"Hook_NtSetInformationFile: %s dest orig=%s",
           isLink ? L"hardlink" : L"rename", origName.c_str());

    std::wstring redName = ApplyFsRedirect(origName);
    if (redName == origName) {
        VL_DBG(L"Hook_NtSetInformationFile: no redirect for %s dest",
               isLink ? L"hardlink" : L"rename");
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    VL_DBG(L"Hook_NtSetInformationFile: %s dest -> %s",
           isLink ? L"hardlink" : L"rename", redName.c_str());
    ULONG newNameBytes = (ULONG)(redName.size() * sizeof(WCHAR));
    ULONG newLength    = RENAME_INFO_NAME_OFFSET + newNameBytes;
    std::vector<BYTE> buf(newLength, 0);
    memcpy(buf.data(), p, RENAME_INFO_NAME_OFFSET);
    *(ULONG*)(buf.data() + RENAME_INFO_NAMELEN_OFFSET) = newNameBytes;
    memcpy(buf.data() + RENAME_INFO_NAME_OFFSET, redName.c_str(), newNameBytes);

    return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                      buf.data(), newLength,
                                      FileInformationClass);
}

// ============================================================
// CHILD PROCESS PROPAGATION
// ============================================================
//
// We always use DetourCreateProcessWithDlls[W|A] for child injection.
// Detours handles same-arch and cross-arch transparently via its helper-
// process mechanism (spawns a matching-arch rundll32 for cross-arch).
//
// CRITICAL WOW64 FIX: From a 32-bit WOW64 process, GetSystemDirectory()
// returns SysWOW64 (32-bit rundll32).  Detours uses GetSystemDirectory()
// internally to find its helper process.  If the child is 64-bit, the
// 32-bit helper can't patch the 64-bit import table and injection silently
// fails.  Fix: always disable WOW64 FS redirection around the Detours call
// so GetSystemDirectory() returns the real System32 (64-bit rundll32).
// This is a no-op in the 64-bit DLL build (#ifdef _WIN64 makes the
// Wow64Disable/Revert functions empty stubs).
//
// We pass Real_CreateProcessW/A as pfCreateProcessW to avoid re-entering
// our own hook when Detours internally spawns the helper process.
// Real_CreateProcessW is the Detours trampoline that bypasses our hook and
// calls the original CreateProcessW directly.
//
// The DLL path must end in "32" or "64" (e.g. VirtHook32.dll / VirtHook64.dll).
// Detours auto-swaps the suffix when the target arch differs from the caller.

// The DLL path matching our own arch (used as the "base" for Detours suffix swap).
static const char* PickDllPath() {
#ifdef _WIN64
    return g_DllPathA64[0] ? g_DllPathA64 : g_DllPathA;
#else
    return g_DllPathA32[0] ? g_DllPathA32 : g_DllPathA;
#endif
}

// Disable WOW64 FS redirection.  No-op in 64-bit builds.
// Returns true if redirection was actually disabled; caller must restore.
static bool DisableWow64Redir(PVOID* pOld) {
#ifndef _WIN64
    typedef BOOL (WINAPI *Pfn)(PVOID*);
    static Pfn s_fn = (Pfn)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "Wow64DisableWow64FsRedirection");
    if (s_fn) return s_fn(pOld) != FALSE;
#else
    (void)pOld;
#endif
    return false;
}

static void RestoreWow64Redir(bool wasDisabled, PVOID old) {
#ifndef _WIN64
    if (!wasDisabled) return;
    typedef BOOL (WINAPI *Pfn)(PVOID);
    static Pfn s_fn = (Pfn)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "Wow64RevertWow64FsRedirection");
    if (s_fn) s_fn(old);
#else
    (void)wasDisabled; (void)old;
#endif
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
    VL_DBG(L"Hook_CreateProcessW: app=%s cmd=%s",
           lpApplicationName ? lpApplicationName : L"(null)",
           lpCommandLine     ? lpCommandLine     : L"(null)");

    const char* dllPath = PickDllPath();
    if (!dllPath || !dllPath[0]) {
        VL_DBG(L"Hook_CreateProcessW: no DLL path configured, pass-through");
        return Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, dwCreationFlags, lpEnvironment,
                                   lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    VL_DBG(L"Hook_CreateProcessW: injecting dll=%S", dllPath);

    // Disable WOW64 FS redirection so Detours finds the correct (same-bitness)
    // rundll32.exe in System32 when it needs a cross-arch helper process.
    // Safe no-op in the 64-bit build.
    PVOID wow64Old = NULL;
    bool  wow64Off = DisableWow64Redir(&wow64Old);

    const char* dlls[1] = { dllPath };
    BOOL ok = DetourCreateProcessWithDllsW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation,
        1, dlls,
        Real_CreateProcessW);  // bypass our hook; avoids re-entrancy

    RestoreWow64Redir(wow64Off, wow64Old);

    if (!ok) {
        VL_DBG(L"Hook_CreateProcessW: DetourCreateProcessWithDllsW FAILED err=%u"
               L" -- falling back to unhooked launch", GetLastError());
        // Fall back: create without injection so the child at least runs.
        ok = Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                  lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment,
                                  lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
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
    VL_DBG(L"Hook_CreateProcessA: app=%S cmd=%S",
           lpApplicationName ? lpApplicationName : "(null)",
           lpCommandLine     ? lpCommandLine     : "(null)");

    const char* dllPath = PickDllPath();
    if (!dllPath || !dllPath[0]) {
        VL_DBG(L"Hook_CreateProcessA: no DLL path configured, pass-through");
        return Real_CreateProcessA(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles, dwCreationFlags, lpEnvironment,
                                   lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }

    VL_DBG(L"Hook_CreateProcessA: injecting dll=%S", dllPath);

    PVOID wow64Old = NULL;
    bool  wow64Off = DisableWow64Redir(&wow64Old);

    const char* dlls[1] = { dllPath };
    BOOL ok = DetourCreateProcessWithDllsA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation,
        1, dlls,
        Real_CreateProcessA);  // bypass our hook; avoids re-entrancy

    RestoreWow64Redir(wow64Off, wow64Old);

    if (!ok) {
        VL_DBG(L"Hook_CreateProcessA: DetourCreateProcessWithDllsA FAILED err=%u"
               L" -- falling back to unhooked launch", GetLastError());
        ok = Real_CreateProcessA(lpApplicationName, lpCommandLine,
                                  lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment,
                                  lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
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

    // Always needed
    VL_GETPROC(ntdll, NtClose);
    VL_GETPROC(ntdll, NtQueryObject);
    VL_GETPROC(k32,   CreateProcessW);
    VL_GETPROC(k32,   CreateProcessA);

    // Registry hooks
    if (g_RegEnabled) {
        VL_GETPROC(ntdll, NtOpenKey);
        VL_GETPROC(ntdll, NtOpenKeyEx);
        VL_GETPROC(ntdll, NtOpenKeyTransacted);
        VL_GETPROC(ntdll, NtOpenKeyTransactedEx);
        VL_GETPROC(ntdll, NtCreateKey);
        VL_GETPROC(ntdll, NtCreateKeyTransacted);
        VL_GETPROC(ntdll, NtDeleteKey);
        VL_GETPROC(ntdll, NtDeleteValueKey);
        VL_GETPROC(ntdll, NtEnumerateKey);
        VL_GETPROC(ntdll, NtEnumerateValueKey);
        VL_GETPROC(ntdll, NtQueryKey);
        VL_GETPROC(ntdll, NtQueryValueKey);
        VL_GETPROC(ntdll, NtQueryMultipleValueKey);
        VL_GETPROC(ntdll, NtSetValueKey);
        VL_GETPROC(ntdll, NtRenameKey);
        VL_GETPROC(ntdll, NtReplaceKey);
        VL_GETPROC(ntdll, NtSaveKey);
        VL_GETPROC(ntdll, NtSaveKeyEx);
        VL_GETPROC(ntdll, NtLoadKey);
        VL_GETPROC(ntdll, NtLoadKey2);
        VL_GETPROC(ntdll, NtLoadKeyEx);
        VL_GETPROC(ntdll, NtLoadKey3);          // Win10 RS5+, may be NULL
        VL_GETPROC(ntdll, NtNotifyChangeKey);
        VL_GETPROC(ntdll, NtNotifyChangeMultipleKeys);
        VL_GETPROC(ntdll, NtFlushKey);
        VL_GETPROC(ntdll, NtRestoreKey);
        VL_GETPROC(ntdll, NtSetInformationKey);
        VL_GETPROC(ntdll, NtUnloadKey);

        VL_DBG(L"InstallHooks REG: NtOpenKey=%p NtCreateKey=%p NtLoadKeyEx=%p"
               L" NtLoadKey3=%p NtFlushKey=%p NtUnloadKey=%p",
               (void*)Real_NtOpenKey, (void*)Real_NtCreateKey,
               (void*)Real_NtLoadKeyEx, (void*)Real_NtLoadKey3,
               (void*)Real_NtFlushKey, (void*)Real_NtUnloadKey);
    }

    // File hooks
    if (g_FsEnabled) {
        VL_GETPROC(ntdll, NtCreateFile);
        VL_GETPROC(ntdll, NtOpenFile);
        VL_GETPROC(ntdll, NtCreateDirectoryObject);
        VL_GETPROC(ntdll, NtOpenDirectoryObject);
        VL_GETPROC(ntdll, NtCreateMailslotFile);
        VL_GETPROC(ntdll, NtCreateNamedPipeFile);
        VL_GETPROC(ntdll, NtDeleteFile);
        VL_GETPROC(ntdll, NtQueryAttributesFile);
        VL_GETPROC(ntdll, NtQueryFullAttributesFile);
        VL_GETPROC(ntdll, NtQueryInformationByName);   // Win8+ may be NULL on XP
        VL_GETPROC(ntdll, NtSetInformationFile);
        VL_GETPROC(ntdll, NtFsControlFile);

        VL_DBG(L"InstallHooks FS: NtCreateFile=%p NtOpenFile=%p NtDeleteFile=%p"
               L" NtSetInformationFile=%p NtFsControlFile=%p",
               (void*)Real_NtCreateFile, (void*)Real_NtOpenFile,
               (void*)Real_NtDeleteFile, (void*)Real_NtSetInformationFile,
               (void*)Real_NtFsControlFile);
    }

    // ---------------------------------------------------------------
    // Pre-create the virtual root key and all ancestor components
    // BEFORE installing hooks, using raw (unhooked) function pointers.
    // ---------------------------------------------------------------
    if (g_RegEnabled && Real_NtCreateKey && Real_NtClose) {
        std::wstring path;
        const std::wstring& base = g_VirtNtBase;
        size_t start = 1;
        while (start < base.size()) {
            size_t slash = base.find(L'\\', start);
            if (slash == std::wstring::npos) slash = base.size();
            path  = base.substr(0, slash);
            start = slash + 1;

            VL_UNICODE_STRING us; MakeUStr(&us, path);
            VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
            HANDLE h = NULL; ULONG disp = 0;
            NTSTATUS st = Real_NtCreateKey(&h, KEY_ALL_ACCESS, &oa,
                                            0, NULL, 0, &disp);
            if (NT_SUCCESS(st) && h) {
                VL_DBG(L"EnsureVirtRoot: created/opened %s (disp=%u)", path.c_str(), disp);
                Real_NtClose(h);
            } else {
                VL_DBG(L"EnsureVirtRoot: FAILED %s st=0x%08X", path.c_str(), (ULONG)st);
            }
        }
    }

    // ---------------------------------------------------------------
    // Attach all hooks in one transaction
    // ---------------------------------------------------------------
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Always
    VL_ATTACH(NtClose);
    VL_ATTACH(CreateProcessW);
    VL_ATTACH(CreateProcessA);

    // Registry
    if (g_RegEnabled) {
        VL_ATTACH(NtOpenKey);
        if (Real_NtOpenKeyEx)           VL_ATTACH(NtOpenKeyEx);
        if (Real_NtOpenKeyTransacted)    VL_ATTACH(NtOpenKeyTransacted);
        if (Real_NtOpenKeyTransactedEx)  VL_ATTACH(NtOpenKeyTransactedEx);
        VL_ATTACH(NtCreateKey);
        if (Real_NtCreateKeyTransacted)  VL_ATTACH(NtCreateKeyTransacted);
        VL_ATTACH(NtDeleteKey);
        VL_ATTACH(NtDeleteValueKey);
        VL_ATTACH(NtEnumerateKey);
        VL_ATTACH(NtEnumerateValueKey);
        VL_ATTACH(NtQueryKey);
        VL_ATTACH(NtQueryValueKey);
        if (Real_NtQueryMultipleValueKey) VL_ATTACH(NtQueryMultipleValueKey);
        VL_ATTACH(NtSetValueKey);
        if (Real_NtRenameKey)            VL_ATTACH(NtRenameKey);
        if (Real_NtReplaceKey)           VL_ATTACH(NtReplaceKey);
        if (Real_NtSaveKey)              VL_ATTACH(NtSaveKey);
        if (Real_NtSaveKeyEx)            VL_ATTACH(NtSaveKeyEx);
        if (Real_NtLoadKey)              VL_ATTACH(NtLoadKey);
        if (Real_NtLoadKey2)             VL_ATTACH(NtLoadKey2);
        if (Real_NtLoadKeyEx)            VL_ATTACH(NtLoadKeyEx);
        if (Real_NtLoadKey3)             VL_ATTACH(NtLoadKey3);
        VL_ATTACH(NtNotifyChangeKey);
        if (Real_NtNotifyChangeMultipleKeys) VL_ATTACH(NtNotifyChangeMultipleKeys);
        if (Real_NtFlushKey)             VL_ATTACH(NtFlushKey);
        if (Real_NtRestoreKey)           VL_ATTACH(NtRestoreKey);
        if (Real_NtSetInformationKey)    VL_ATTACH(NtSetInformationKey);
        if (Real_NtUnloadKey)            VL_ATTACH(NtUnloadKey);
    }

    // Files
    if (g_FsEnabled) {
        VL_ATTACH(NtCreateFile);
        VL_ATTACH(NtOpenFile);
        if (Real_NtCreateDirectoryObject) VL_ATTACH(NtCreateDirectoryObject);
        if (Real_NtOpenDirectoryObject)   VL_ATTACH(NtOpenDirectoryObject);
        if (Real_NtCreateMailslotFile)    VL_ATTACH(NtCreateMailslotFile);
        if (Real_NtCreateNamedPipeFile)   VL_ATTACH(NtCreateNamedPipeFile);
        if (Real_NtDeleteFile)            VL_ATTACH(NtDeleteFile);
        if (Real_NtQueryAttributesFile)   VL_ATTACH(NtQueryAttributesFile);
        if (Real_NtQueryFullAttributesFile) VL_ATTACH(NtQueryFullAttributesFile);
        if (Real_NtQueryInformationByName)  VL_ATTACH(NtQueryInformationByName);
        if (Real_NtSetInformationFile)    VL_ATTACH(NtSetInformationFile);
        if (Real_NtFsControlFile)         VL_ATTACH(NtFsControlFile);
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
        if (Real_NtOpenKeyEx)           VL_DETACH(NtOpenKeyEx);
        if (Real_NtOpenKeyTransacted)    VL_DETACH(NtOpenKeyTransacted);
        if (Real_NtOpenKeyTransactedEx)  VL_DETACH(NtOpenKeyTransactedEx);
        VL_DETACH(NtCreateKey);
        if (Real_NtCreateKeyTransacted)  VL_DETACH(NtCreateKeyTransacted);
        VL_DETACH(NtDeleteKey);
        VL_DETACH(NtDeleteValueKey);
        VL_DETACH(NtEnumerateKey);
        VL_DETACH(NtEnumerateValueKey);
        VL_DETACH(NtQueryKey);
        VL_DETACH(NtQueryValueKey);
        if (Real_NtQueryMultipleValueKey) VL_DETACH(NtQueryMultipleValueKey);
        VL_DETACH(NtSetValueKey);
        if (Real_NtRenameKey)            VL_DETACH(NtRenameKey);
        if (Real_NtReplaceKey)           VL_DETACH(NtReplaceKey);
        if (Real_NtSaveKey)              VL_DETACH(NtSaveKey);
        if (Real_NtSaveKeyEx)            VL_DETACH(NtSaveKeyEx);
        if (Real_NtLoadKey)              VL_DETACH(NtLoadKey);
        if (Real_NtLoadKey2)             VL_DETACH(NtLoadKey2);
        if (Real_NtLoadKeyEx)            VL_DETACH(NtLoadKeyEx);
        if (Real_NtLoadKey3)             VL_DETACH(NtLoadKey3);
        VL_DETACH(NtNotifyChangeKey);
        if (Real_NtNotifyChangeMultipleKeys) VL_DETACH(NtNotifyChangeMultipleKeys);
        if (Real_NtFlushKey)             VL_DETACH(NtFlushKey);
        if (Real_NtRestoreKey)           VL_DETACH(NtRestoreKey);
        if (Real_NtSetInformationKey)    VL_DETACH(NtSetInformationKey);
        if (Real_NtUnloadKey)            VL_DETACH(NtUnloadKey);
    }

    if (g_FsEnabled) {
        VL_DETACH(NtCreateFile);
        VL_DETACH(NtOpenFile);
        if (Real_NtCreateDirectoryObject) VL_DETACH(NtCreateDirectoryObject);
        if (Real_NtOpenDirectoryObject)   VL_DETACH(NtOpenDirectoryObject);
        if (Real_NtCreateMailslotFile)    VL_DETACH(NtCreateMailslotFile);
        if (Real_NtCreateNamedPipeFile)   VL_DETACH(NtCreateNamedPipeFile);
        if (Real_NtDeleteFile)            VL_DETACH(NtDeleteFile);
        if (Real_NtQueryAttributesFile)   VL_DETACH(NtQueryAttributesFile);
        if (Real_NtQueryFullAttributesFile) VL_DETACH(NtQueryFullAttributesFile);
        if (Real_NtQueryInformationByName)  VL_DETACH(NtQueryInformationByName);
        if (Real_NtSetInformationFile)    VL_DETACH(NtSetInformationFile);
        if (Real_NtFsControlFile)         VL_DETACH(NtFsControlFile);
    }

    DetourTransactionCommit();
}

// ============================================================
// DllMain
// ============================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {

    if (DetourIsHelperProcess()) return TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        DetourRestoreAfterWith();

        g_TlsIdx = TlsAlloc();
        InitializeCriticalSectionAndSpinCount(&g_KeyMapLock, 4000);

        VL_DBG(L"DllMain: DLL_PROCESS_ATTACH -- VirtHook loading (v9 pure ntdll)");

        LoadConfig();
        InstallHooks();

        VL_DBG(L"DllMain: hooks installed OK");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        UninstallHooks();

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
