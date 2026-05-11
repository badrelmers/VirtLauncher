// ============================================================
// VirtHook.cpp  - VirtLauncher Hook DLL  (v11 - COW FS + merged dirs + tombstones)
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
//     NtFlushKey
//     NtRestoreKey
//     NtSetInformationKey
//     NtUnloadKey
//     NtClose  (filtered: tracked handles only)
//
//   FILES (all pure ntdll):
//     NtCreateFile, NtOpenFile
//     NtCreateDirectoryObject, NtOpenDirectoryObject
//     NtCreateMailslotFile, NtCreateNamedPipeFile
//     NtDeleteFile
//     NtQueryAttributesFile, NtQueryFullAttributesFile
//     NtQueryInformationByName
//     NtSetInformationFile  (FileRenameInformation + FileLinkInformation + FileDispositionInformation)
//     NtFsControlFile       (FSCTL_SET_REPARSE_POINT / FSCTL_GET_REPARSE_POINT)
//     NtQueryDirectoryFile, NtQueryDirectoryFileEx   (merged view)
//     NtQueryInformationFile                           (path reverse-translate)
//
//   CHILDREN: CreateProcessW/A (propagate injection)
//
// NOTE: NtQueryVolumeInformationFile, NtDeviceIoControlFile,
//       NtReadFile, NtWriteFile are NOT hooked.
//       All are handle-based and the handle was already redirected at
//       NtCreateFile/NtOpenFile time.
//
// Config via environment variables set by VirtLauncher.exe:
//   VIRTLAUNCHER_REG   = NT reg base  e.g. \Registry\User\SID\VirtApp
//   VIRTLAUNCHER_FS    = path to FS redirect config file   (--config)
//   VIRTLAUNCHER_FSDIR = Win32 path to virtual store root  (--filesystem)
//   VIRTLAUNCHER_DLL   = absolute path to this DLL (for child injection)
//
// User-settable flags propagated by VirtLauncher.exe:
//   VLAUNCHER_DEBUG=1  = enable OutputDebugString logging (--debug)
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
#include <set>
#include <algorithm>

// ============================================================
// Debug logging -- output visible in Sysinternals DebugView
// (run DebugView as admin before launching VirtLauncher).
//
// Controlled at runtime by the VLAUNCHER_DEBUG env var, which
// VirtLauncher.exe sets when --debug / -d is passed or when
// VLAUNCHER_DEBUG=1 is present in the environment.
//
// VL_DEBUG=1 compiles the logging code in; g_DebugEnabled guards
// actual output so there is zero overhead when debugging is off.
// ============================================================
#define VL_DEBUG 1

// Initialized to false; set to true by LoadConfig() when VLAUNCHER_DEBUG=1.
static bool g_DebugEnabled = false;

#if VL_DEBUG
static void VL_DBG(const wchar_t* fmt, ...) {
    if (!g_DebugEnabled) return;
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

#define VL_STATUS_SUCCESS                ((NTSTATUS)0x00000000L)
#define VL_STATUS_NO_MORE_ENTRIES        ((NTSTATUS)0x8000001AL)
#define VL_STATUS_NO_MORE_FILES          ((NTSTATUS)0x80000006L)
#define VL_STATUS_BUFFER_TOO_SMALL       ((NTSTATUS)0xC0000023L)
#define VL_STATUS_BUFFER_OVERFLOW        ((NTSTATUS)0x80000005L)
#define VL_STATUS_OBJECT_NAME_NOT_FOUND  ((NTSTATUS)0xC0000034L)
#define VL_STATUS_OBJECT_PATH_NOT_FOUND  ((NTSTATUS)0xC000003AL)
#define VL_STATUS_NO_SUCH_FILE           ((NTSTATUS)0xC000000FL)
#define VL_STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#define VL_STATUS_INVALID_HANDLE         ((NTSTATUS)0xC0000008L)
#define VL_STATUS_END_OF_FILE            ((NTSTATUS)0xC0000011L)

// Compatibility alias used by older registry code
#define VL_STATUS_OBJECT_NOT_FOUND       VL_STATUS_OBJECT_NAME_NOT_FOUND

#ifndef OBJ_CASE_INSENSITIVE
#  define OBJ_CASE_INSENSITIVE 0x00000040UL
#endif

// CreateDisposition values
#ifndef FILE_SUPERSEDE
#  define FILE_SUPERSEDE    0x00000000
#  define FILE_OPEN         0x00000001
#  define FILE_CREATE       0x00000002
#  define FILE_OPEN_IF      0x00000003
#  define FILE_OVERWRITE    0x00000004
#  define FILE_OVERWRITE_IF 0x00000005
#endif

#ifndef FILE_DIRECTORY_FILE
#  define FILE_DIRECTORY_FILE           0x00000001
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#  define FILE_NON_DIRECTORY_FILE       0x00000040
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#  define FILE_SYNCHRONOUS_IO_NONALERT  0x00000020
#endif
#ifndef FILE_OPEN_BY_FILE_ID
#  define FILE_OPEN_BY_FILE_ID          0x00002000
#endif
#ifndef FILE_LIST_DIRECTORY
#  define FILE_LIST_DIRECTORY           0x00000001
#endif
#ifndef SYNCHRONIZE
#  define SYNCHRONIZE                   0x00100000
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

// Directory enumeration structures (natural alignment, canonical field names)
struct VL_FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
};

struct VL_FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
};

struct VL_FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
};

struct VL_FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
};

struct VL_FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
};

struct VL_FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
};

// ============================================================
// NT Function Pointer Types
// ============================================================

typedef NTSTATUS (NTAPI *PfnNtOpenKey)            (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtOpenKeyEx)          (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PfnNtOpenKeyTransacted)  (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, HANDLE);
typedef NTSTATUS (NTAPI *PfnNtOpenKeyTransactedEx)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PfnNtCreateKey)          (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, PVL_UNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtCreateKeyTransacted)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, ULONG, PVL_UNICODE_STRING, ULONG, HANDLE, PULONG);
typedef NTSTATUS (NTAPI *PfnNtDeleteKey)          (HANDLE);
typedef NTSTATUS (NTAPI *PfnNtDeleteValueKey)     (HANDLE, PVL_UNICODE_STRING);
typedef NTSTATUS (NTAPI *PfnNtEnumerateKey)       (HANDLE, ULONG, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtEnumerateValueKey)  (HANDLE, ULONG, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryKey)           (HANDLE, VL_KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryValueKey)      (HANDLE, PVL_UNICODE_STRING, VL_KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryMultipleValueKey)(HANDLE, PVL_KEY_VALUE_ENTRY, ULONG, PVOID, PULONG, PULONG);
typedef NTSTATUS (NTAPI *PfnNtSetValueKey)        (HANDLE, PVL_UNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PfnNtRenameKey)          (HANDLE, PVL_UNICODE_STRING);
typedef NTSTATUS (NTAPI *PfnNtReplaceKey)         (PVL_OBJECT_ATTRIBUTES, HANDLE, PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtSaveKey)            (HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *PfnNtSaveKeyEx)          (HANDLE, HANDLE, ULONG);
typedef NTSTATUS (NTAPI *PfnNtLoadKey)            (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtLoadKey2)           (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PfnNtLoadKeyEx)          (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG, HANDLE, HANDLE, ULONG, PHANDLE, PVOID);
typedef NTSTATUS (NTAPI *PfnNtNotifyChangeKey)    (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *PfnNtNotifyChangeMultipleKeys)(HANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *PfnNtFlushKey)           (HANDLE);
typedef NTSTATUS (NTAPI *PfnNtRestoreKey)         (HANDLE, HANDLE, ULONG);
typedef NTSTATUS (NTAPI *PfnNtSetInformationKey)  (HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PfnNtUnloadKey)          (PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtLoadKey3)           (PVL_OBJECT_ATTRIBUTES, PVL_OBJECT_ATTRIBUTES, ULONG, PVOID, ULONG, ULONG, HANDLE, PVOID);
typedef NTSTATUS (NTAPI *PfnNtClose)              (HANDLE);
typedef NTSTATUS (NTAPI *PfnNtQueryObject)        (HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtCreateFile)         (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PfnNtOpenFile)           (PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PfnNtCreateDirectoryObject)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtOpenDirectoryObject)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtCreateMailslotFile)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PfnNtCreateNamedPipeFile)(PHANDLE, ULONG, PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PfnNtDeleteFile)         (PVL_OBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PfnNtQueryAttributesFile)(PVL_OBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS (NTAPI *PfnNtQueryFullAttributesFile)(PVL_OBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS (NTAPI *PfnNtQueryInformationByName)(PVL_OBJECT_ATTRIBUTES, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PfnNtSetInformationFile) (HANDLE, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PfnNtFsControlFile)      (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PfnNtReadFile)           (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *PfnNtWriteFile)          (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryInformationFile)(HANDLE, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryDirectoryFile) (HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, PVL_UNICODE_STRING, BOOLEAN);
typedef NTSTATUS (NTAPI *PfnNtQueryDirectoryFileEx)(HANDLE, HANDLE, VL_PIO_APC_ROUTINE, PVOID, PVL_IO_STATUS_BLOCK, PVOID, ULONG, ULONG, ULONG);

typedef BOOL (WINAPI *PfnCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PfnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

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
static PfnNtReadFile                Real_NtReadFile;
static PfnNtWriteFile               Real_NtWriteFile;
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
static PfnNtQueryInformationFile    Real_NtQueryInformationFile;
static PfnNtQueryDirectoryFile      Real_NtQueryDirectoryFile;
static PfnNtQueryDirectoryFileEx    Real_NtQueryDirectoryFileEx;

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

// FS redirections from --config INI: vector of (nt_from_prefix, nt_to_prefix).
static std::vector< std::pair<std::wstring,std::wstring> > g_FsRedirects;

// FS catch-all virtual store root from --filesystem (VIRTLAUNCHER_FSDIR).
static std::wstring g_FsDirNtBase;

// Tracked virtual registry handles
struct VirtKeyEntry {
    HANDLE       hVirt;
    HANDLE       hReal;
    std::wstring logPath;
};
static std::map<HANDLE, VirtKeyEntry> g_KeyMap;
static CRITICAL_SECTION g_KeyMapLock;

// Case-insensitive comparator for filename sets (NTFS is case-insensitive)
struct CiLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    }
};

// File-system handle tracking (COW + merged dirs)
struct VirtFileEntry {
    HANDLE       hVirt;
    HANDLE       hReal;
    std::wstring logPath;
    bool         isDir;
    bool         isRealOnly;
    // Directory enumeration state
    bool         virtEnumDone;
    bool         realEnumDone;
    bool         realRestartPending;
    bool         hasCachedFileName;  // true once FileName pattern has been saved
    std::set<std::wstring, CiLess> virtNames;
    std::wstring cachedFileName;     // saved FileName search pattern for 1st real call

    // Zero-initialize all scalar fields so stack garbage never causes bugs
    VirtFileEntry()
        : hVirt(NULL), hReal(NULL),
          isDir(false), isRealOnly(false),
          virtEnumDone(false), realEnumDone(false),
          realRestartPending(false), hasCachedFileName(false)
    {}
};
static std::map<HANDLE, VirtFileEntry> g_FileMap;
static CRITICAL_SECTION g_FileMapLock;

// TLS index for reentrancy guard
static DWORD g_TlsIdx = TLS_OUT_OF_INDEXES;

// DLL paths (ANSI) for child process injection.
static char g_DllPathA[MAX_PATH];
static char g_DllPathA32[MAX_PATH];
static char g_DllPathA64[MAX_PATH];

// ============================================================
// Inline helpers
// ============================================================

static inline bool IsReentrant() {
    return g_TlsIdx != TLS_OUT_OF_INDEXES && TlsGetValue(g_TlsIdx) != NULL;
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
// File handle map helpers
// ============================================================

static void TrackFileHandle(HANDLE h, const VirtFileEntry& e) {
    EnterCriticalSection(&g_FileMapLock);
    g_FileMap[h] = e;
    LeaveCriticalSection(&g_FileMapLock);
}

static void UntrackFileHandle(HANDLE h) {
    EnterCriticalSection(&g_FileMapLock);
    g_FileMap.erase(h);
    LeaveCriticalSection(&g_FileMapLock);
}

static bool GetFileEntry(HANDLE h, VirtFileEntry& out) {
    EnterCriticalSection(&g_FileMapLock);
    std::map<HANDLE,VirtFileEntry>::iterator it = g_FileMap.find(h);
    if (it != g_FileMap.end()) { out = it->second; }
    bool found = (it != g_FileMap.end());
    LeaveCriticalSection(&g_FileMapLock);
    return found;
}

static void UpdateFileEntry(HANDLE h, const VirtFileEntry& e) {
    EnterCriticalSection(&g_FileMapLock);
    g_FileMap[h] = e;
    LeaveCriticalSection(&g_FileMapLock);
}

// ============================================================
// Registry Path Resolution
// ============================================================

static std::wstring DevicePathToDosPath(const std::wstring& devicePath) {
    static std::map<std::wstring, std::wstring> s_devToDos;
    static bool s_init = false;
    if (!s_init) {
        s_init = true;
        wchar_t drives[512] = {0};
        DWORD len = GetLogicalDriveStringsW(511, drives);
        if (len > 0 && len < 512) {
            wchar_t* p = drives;
            while (*p) {
                wchar_t drive[3] = { p[0], L':', L'\0' };
                wchar_t ntDev[MAX_PATH] = {0};
                if (QueryDosDeviceW(drive, ntDev, MAX_PATH)) {
                    std::wstring dev(ntDev);
                    while (!dev.empty() && dev[dev.size()-1] == L'\\') dev.pop_back();
                    s_devToDos[dev] = std::wstring(L"\\??\\") + drive;
                }
                while (*p) ++p;
                ++p;
            }
        }
    }
    for (std::map<std::wstring, std::wstring>::iterator it = s_devToDos.begin();
         it != s_devToDos.end(); ++it)
    {
        if (devicePath.size() >= it->first.size() &&
            _wcsnicmp(devicePath.c_str(), it->first.c_str(), it->first.size()) == 0) {
            if (devicePath.size() == it->first.size() || devicePath[it->first.size()] == L'\\') {
                return it->second + devicePath.substr(it->first.size());
            }
        }
    }
    return devicePath;
}

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
                if (StartsWithI(path, L"\\Device\\")) {
                    path = DevicePathToDosPath(path);
                }
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
static bool LogicalToVirtual(const std::wstring& logical, std::wstring& virt) {
    if (!g_RegEnabled) return false;
    if (!StartsWithI(logical, g_RealNtBase)) {
        VL_DBG(L"LogicalToVirtual: SKIP (not under RealNtBase) path=%s base=%s",
               logical.c_str(), g_RealNtBase.c_str());
        return false;
    }
    size_t baseLen = g_RealNtBase.size();
    if (logical.size() > baseLen && logical[baseLen] != L'\\') {
        VL_DBG(L"LogicalToVirtual: SKIP (boundary mismatch) path=%s", logical.c_str());
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

    // --- 1. Config-based rules (take precedence) ---
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, from)) {
            return to + ntPath.substr(from.size());
        }
    }

    // --- 2. FSDIR catch-all ---
    if (!g_FsDirNtBase.empty() &&
        ntPath.size() >= 6 &&
        StartsWithI(ntPath, L"\\??\\") &&
        iswalpha(ntPath[4]) && ntPath[5] == L':' &&
        (ntPath.size() == 6 || ntPath[6] == L'\\') &&
        !StartsWithI(ntPath, g_FsDirNtBase))
    {
        wchar_t driveStr[3] = { L'\\', towupper(ntPath[4]), L'\0' };
        std::wstring rest = (ntPath.size() > 6) ? ntPath.substr(6) : L"";
        return g_FsDirNtBase + driveStr + rest;
    }
    return ntPath;
}

// Reverse of ApplyFsRedirect: physical -> logical
static std::wstring ReverseApplyFsRedirect(const std::wstring& ntPath) {
    if (!g_FsEnabled) return ntPath;
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, to))
            return from + ntPath.substr(to.size());
    }
    if (!g_FsDirNtBase.empty() && StartsWithI(ntPath, g_FsDirNtBase)) {
        std::wstring tail = ntPath.substr(g_FsDirNtBase.size());
        if (tail.size() >= 2 && tail[0] == L'\\' && iswalpha(tail[1])) {
            wchar_t drive = towupper(tail[1]);
            std::wstring rest = (tail.size() > 2) ? tail.substr(2) : L"";
            return std::wstring(L"\\??\\") + drive + L':' + rest;
        }
    }
    return ntPath;
}

// Redirect a reparse-point path that may be in NT form or Win32 form.
static std::wstring RedirectSymlinkPath(const std::wstring& path) {
    if (path.empty()) return path;
    std::wstring red = ApplyFsRedirect(path);
    if (red != path) return red;
    std::wstring nt = Win32ToNtPath(path);
    if (nt != path) {
        red = ApplyFsRedirect(nt);
        if (red != nt) {
            if (StartsWithI(red, L"\\??\\") && !StartsWithI(path, L"\\??\\"))
                return red.substr(4);
            return red;
        }
    }
    return path;
}

static std::wstring ReverseRedirectSymlinkPath(const std::wstring& path) {
    if (path.empty()) return path;
    std::wstring rev = ReverseApplyFsRedirect(path);
    if (rev != path) return rev;
    std::wstring nt = Win32ToNtPath(path);
    if (nt != path) {
        rev = ReverseApplyFsRedirect(nt);
        if (rev != nt) {
            if (StartsWithI(rev, L"\\??\\") && !StartsWithI(path, L"\\??\\"))
                return rev.substr(4);
            return rev;
        }
    }
    return path;
}

// If true, caller should use newOa / newName instead of the original OA.
static bool RedirectFileOA(PVL_OBJECT_ATTRIBUTES oa,
                             VL_UNICODE_STRING& newName,
                             VL_OBJECT_ATTRIBUTES& newOa,
                             std::wstring& ntPath,
                             std::wstring& redPath)
{
    if (!g_FsEnabled || !oa || !oa->ObjectName || IsReentrant()) return false;
    ntPath  = GetFullNtPath(oa);
    ntPath  = Win32ToNtPath(ntPath);   // ensure NT format
    redPath = ApplyFsRedirect(ntPath);
    if (redPath == ntPath) return false;
    MakeUStr(&newName, redPath);
    newOa               = *oa;
    newOa.ObjectName    = &newName;
    newOa.RootDirectory = NULL;
    return true;
}

// ============================================================
// FS COW / Merge helpers
// ============================================================

static inline bool IsFsNotFound(NTSTATUS st) {
    return st == VL_STATUS_OBJECT_NAME_NOT_FOUND  ||
           st == VL_STATUS_OBJECT_PATH_NOT_FOUND  ||
           st == VL_STATUS_NO_SUCH_FILE;
}

static inline bool HasWriteAccess(ULONG access) {
    return (access & (GENERIC_WRITE | GENERIC_ALL |
                      FILE_WRITE_DATA | FILE_APPEND_DATA |
                      FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                      DELETE | WRITE_DAC | WRITE_OWNER |
                      FILE_DELETE_CHILD)) != 0;
}

static void EnsureVirtualFsPath(const std::wstring& virtualNtFilePath) {
    if (!Real_NtCreateFile) return;
    size_t lastSlash = virtualNtFilePath.rfind(L'\\');
    if (lastSlash == std::wstring::npos) return;
    const std::wstring dirPath = virtualNtFilePath.substr(0, lastSlash);
    std::wstring virtRoot;
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& to = g_FsRedirects[i].second;
        if (!to.empty() && StartsWithI(dirPath, to)) {
            virtRoot = to;
            break;
        }
    }
    if (virtRoot.empty() &&
        !g_FsDirNtBase.empty() &&
        StartsWithI(dirPath, g_FsDirNtBase))
    {
        virtRoot = g_FsDirNtBase;
    }
    if (virtRoot.empty()) return;
    std::wstring remaining = dirPath.substr(virtRoot.size());
    std::wstring current   = virtRoot;
    while (!remaining.empty()) {
        size_t start = (remaining[0] == L'\\') ? 1u : 0u;
        size_t slash  = remaining.find(L'\\', start);
        std::wstring seg;
        if (slash != std::wstring::npos) {
            seg = remaining.substr(start, slash - start);
            remaining = remaining.substr(slash);
        } else {
            seg = remaining.substr(start);
            remaining = L"";
        }
        if (seg.empty()) continue;
        current += L"\\" + seg;
        VL_UNICODE_STRING us;  MakeUStr(&us, current);
        VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
        VL_IO_STATUS_BLOCK iosb;
        ZeroMemory(&iosb, sizeof(iosb));
        HANDLE h = NULL;
        NTSTATUS st = Real_NtCreateFile(
            &h,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &oa, &iosb,
            NULL,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
        if (NT_SUCCESS(st) && h) Real_NtClose(h);
    }
}

static std::wstring TombstonePath(const std::wstring& virtualNtPath) {
    return virtualNtPath + L".vl_deleted";
}

static bool TombstoneExists(const std::wstring& virtualNtPath) {
    std::wstring tp = TombstonePath(virtualNtPath);
    VL_UNICODE_STRING us; MakeUStr(&us, tp);
    VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
    BYTE dummy[48] = {0};
    return NT_SUCCESS(Real_NtQueryAttributesFile(&oa, dummy));
}

static void CreateTombstone(const std::wstring& virtualNtPath) {
    if (!Real_NtCreateFile) return;
    std::wstring tp = TombstonePath(virtualNtPath);
    EnsureVirtualFsPath(tp);
    VL_UNICODE_STRING us; MakeUStr(&us, tp);
    VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
    VL_IO_STATUS_BLOCK iosb;
    ZeroMemory(&iosb, sizeof(iosb));
    HANDLE h = NULL;
    NTSTATUS st = Real_NtCreateFile(
        &h,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (NT_SUCCESS(st) && h) Real_NtClose(h);
    VL_DBG(L"CreateTombstone: %s st=0x%08X", tp.c_str(), (ULONG)st);
}

static void DeleteTombstoneIfPresent(const std::wstring& virtualNtPath) {
    std::wstring tp = TombstonePath(virtualNtPath);
    VL_UNICODE_STRING us; MakeUStr(&us, tp);
    VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
    Real_NtDeleteFile(&oa);
}

static bool CopyRealFileToVirtual(const std::wstring& realNtPath,
                                    const std::wstring& virtualNtPath)
{
    if (!Real_NtReadFile || !Real_NtWriteFile || !Real_NtCreateFile) return false;
    VL_DBG(L"CopyRealFileToVirtual: %s -> %s",
           realNtPath.c_str(), virtualNtPath.c_str());
    VL_UNICODE_STRING srcUs; MakeUStr(&srcUs, realNtPath);
    VL_OBJECT_ATTRIBUTES srcOa; MakeOA(&srcOa, &srcUs);
    VL_IO_STATUS_BLOCK iosb;
    ZeroMemory(&iosb, sizeof(iosb));
    HANDLE hSrc = NULL;
    NTSTATUS st = Real_NtCreateFile(
        &hSrc,
        GENERIC_READ | SYNCHRONIZE,
        &srcOa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(st)) {
        VL_DBG(L"CopyRealFileToVirtual: open src FAILED st=0x%08X", (ULONG)st);
        return false;
    }
    EnsureVirtualFsPath(virtualNtPath);
    VL_UNICODE_STRING dstUs; MakeUStr(&dstUs, virtualNtPath);
    VL_OBJECT_ATTRIBUTES dstOa; MakeOA(&dstOa, &dstUs);
    // iosb = {};
    ZeroMemory(&iosb, sizeof(iosb));
    HANDLE hDst = NULL;
    st = Real_NtCreateFile(
        &hDst,
        GENERIC_WRITE | SYNCHRONIZE,
        &dstOa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(st)) {
        VL_DBG(L"CopyRealFileToVirtual: create dst FAILED st=0x%08X", (ULONG)st);
        Real_NtClose(hSrc);
        return false;
    }
    static const ULONG kBufSize = 256 * 1024;
    std::vector<BYTE> buf(kBufSize);
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    LONGLONG totalBytes = 0;
    for (;;) {
        VL_IO_STATUS_BLOCK rIosb;
        ZeroMemory(&rIosb, sizeof(rIosb));
        st = Real_NtReadFile(hSrc, NULL, NULL, NULL, &rIosb,
                              &buf[0], kBufSize, &offset, NULL);
        if (!NT_SUCCESS(st) || rIosb.Information == 0) break;
        ULONG chunk = (ULONG)rIosb.Information;
        VL_IO_STATUS_BLOCK wIosb;
        ZeroMemory(&wIosb, sizeof(wIosb));
        Real_NtWriteFile(hDst, NULL, NULL, NULL, &wIosb,
                          &buf[0], chunk, &offset, NULL);
        offset.QuadPart += chunk;
        totalBytes      += chunk;
    }
    Real_NtClose(hSrc);
    Real_NtClose(hDst);
    VL_DBG(L"CopyRealFileToVirtual: done %I64d bytes", totalBytes);
    return true;
}

static std::wstring ExtractDirFileName(PVOID info, ULONG infoClass) {
    switch (infoClass) {
        case 1: {
            VL_FILE_DIRECTORY_INFORMATION* p = (VL_FILE_DIRECTORY_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
        case 2: {
            VL_FILE_FULL_DIR_INFORMATION* p = (VL_FILE_FULL_DIR_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
        case 3: {
            VL_FILE_BOTH_DIR_INFORMATION* p = (VL_FILE_BOTH_DIR_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
        case 12: {
            VL_FILE_NAMES_INFORMATION* p = (VL_FILE_NAMES_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
        case 37: {
            VL_FILE_ID_BOTH_DIR_INFORMATION* p = (VL_FILE_ID_BOTH_DIR_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
        case 38: {
            VL_FILE_ID_FULL_DIR_INFORMATION* p = (VL_FILE_ID_FULL_DIR_INFORMATION*)info;
            return std::wstring(p->FileName, p->FileNameLength / sizeof(WCHAR));
        }
    }
    return L"";
}

// ============================================================
// Merged-view buffer helpers
// ============================================================

// Check whether a real-directory entry (by filename) has a tombstone
// in the virtual layer, meaning the file was deleted inside the sandbox.
static bool FileHasTombstoneInVirtDir(const std::wstring& virtDirPath,
                                       const std::wstring& fileName)
{
    if (virtDirPath.empty() || fileName.empty()) return false;
    std::wstring tp = virtDirPath + L"\\" + fileName + L".vl_deleted";
    VL_UNICODE_STRING us; MakeUStr(&us, tp);
    VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
    BYTE dummy[48] = {0};
    return NT_SUCCESS(Real_NtQueryAttributesFile(&oa, dummy));
}

// Return true if the filename ends with the tombstone suffix ".vl_deleted".
static inline bool IsTombstoneName(const std::wstring& name) {
    static const wchar_t kSuffix[] = L".vl_deleted";
    static const size_t  kSuffixLen = 11;
    return name.size() > kSuffixLen &&
           _wcsicmp(name.c_str() + name.size() - kSuffixLen, kSuffix) == 0;
}

// Filter a raw NtQueryDirectoryFile output buffer in-place.
//   skipNames   – names already seen in the virtual layer (dedup); may be NULL.
//   virtDirPath – virtual path of the directory, used for tombstone probing;
//                 empty string disables tombstone probe.
// Returns the new valid byte count (0 means the buffer is now empty).
static ULONG FilterDirBuffer(
    PVOID  buf,
    ULONG  len,
    ULONG  infoClass,
    const std::set<std::wstring, CiLess>* skipNames,
    const std::wstring& virtDirPath)
{
    if (!buf || len == 0) return 0;

    BYTE*  base         = (BYTE*)buf;
    ULONG  readOff      = 0;
    ULONG  writeOff     = 0;
    ULONG  prevWriteOff = (ULONG)-1; // position of the last KEPT entry

    while (readOff < len) {
        BYTE*  entry     = base + readOff;
        ULONG  nextOff   = *(ULONG*)entry;       // NextEntryOffset is always first field
        ULONG  entrySize = (nextOff > 0) ? nextOff : (len - readOff);

        std::wstring name = ExtractDirFileName(entry, infoClass);

        bool skip = false;

        // Always hide .vl_deleted tombstone marker files from callers
        if (!skip && IsTombstoneName(name)) skip = true;

        // Hide entries that exist in the virtual layer (virtual wins, no dups)
        if (!skip && skipNames && !name.empty() && skipNames->count(name))
            skip = true;

        // Hide real entries that were deleted inside the sandbox (tombstone exists)
        if (!skip && !virtDirPath.empty() && !name.empty()) {
            SetReentrant(true);
            skip = FileHasTombstoneInVirtDir(virtDirPath, name);
            SetReentrant(false);
        }

        if (!skip) {
            if (writeOff != readOff)
                memmove(base + writeOff, entry, entrySize);

            // Fix up the previous kept entry's NextEntryOffset to point here
            if (prevWriteOff != (ULONG)-1)
                *(ULONG*)(base + prevWriteOff) = writeOff - prevWriteOff;

            prevWriteOff = writeOff;
            writeOff    += entrySize;
        }

        if (nextOff == 0) break;
        readOff += nextOff;
    }

    // Mark the last kept entry as the final one
    if (prevWriteOff != (ULONG)-1) {
        *(ULONG*)(base + prevWriteOff) = 0;
        return writeOff;
    }
    return 0; // every entry was filtered
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
        while (!line.empty() && (line[line.size()-1] == L'\r' || line[line.size()-1] == L' '))
            line.resize(line.size() - 1);
        while (!line.empty() && line[0] == L' ')
            line = line.substr(1);
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        if (line[0] == L'[') continue;
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring src = line.substr(0, eq);
        std::wstring dst = line.substr(eq + 1);
        while (!src.empty() && src[src.size()-1] == L' ') src.resize(src.size()-1);
        while (!dst.empty() && dst[0]   == L' ') dst = dst.substr(1);
        if (src.empty() || dst.empty()) continue;
        g_FsRedirects.push_back(
            std::make_pair(Win32ToNtPath(src), Win32ToNtPath(dst)));
    }
}

static void LoadConfig() {
    wchar_t buf[2048] = {0};

    // ---- Read the debug flag FIRST ----
    if (GetEnvironmentVariableW(L"VLAUNCHER_DEBUG", buf, 2047) > 0)
        g_DebugEnabled = (_wcsicmp(buf, L"1")    == 0 ||
                          _wcsicmp(buf, L"true") == 0 ||
                          _wcsicmp(buf, L"yes")  == 0);

    // ---- Registry virtualisation ----
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_REG", buf, 2047) > 0) {
        g_VirtNtBase = buf;
        size_t sl = g_VirtNtBase.rfind(L'\\');
        if (sl != std::wstring::npos)
            g_RealNtBase = g_VirtNtBase.substr(0, sl);
        if (!g_VirtNtBase.empty() && !g_RealNtBase.empty())
            g_RegEnabled = true;
    }

    // ---- FS redirect config file ----
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FS", buf, 2047) > 0) {
        LoadFsConfig(buf);
        if (!g_FsRedirects.empty())
            g_FsEnabled = true;
    }

    // ---- FS virtual store folder ----
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FSDIR", buf, 2047) > 0 && buf[0]) {
        std::wstring fsdir = buf;
        if (fsdir.size() >= 2 && iswalpha(fsdir[0]) && fsdir[1] == L':')
            fsdir = L"\\??\\" + fsdir;
        while (fsdir.size() > 4 && fsdir[fsdir.size()-1] == L'\\')
            fsdir.resize(fsdir.size() - 1);
        g_FsDirNtBase = fsdir;
        g_FsEnabled   = true;
        VL_DBG(L"LoadConfig: FsDirNtBase=%s", g_FsDirNtBase.c_str());
    }

    // ---- DLL paths for child-process injection ----
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL",   g_DllPathA,   MAX_PATH);
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL32", g_DllPathA32, MAX_PATH);
    GetEnvironmentVariableA("VIRTLAUNCHER_DLL64", g_DllPathA64, MAX_PATH);
    if (!g_DllPathA32[0] && g_DllPathA[0])
        strncpy(g_DllPathA32, g_DllPathA, MAX_PATH - 1);
    if (!g_DllPathA64[0] && g_DllPathA[0])
        strncpy(g_DllPathA64, g_DllPathA, MAX_PATH - 1);
    VL_DBG(L"LoadConfig: DebugEnabled=%d", (int)g_DebugEnabled);
    VL_DBG(L"LoadConfig: RegEnabled=%d  VirtNtBase=%s",
           (int)g_RegEnabled, g_VirtNtBase.c_str());
    VL_DBG(L"LoadConfig:             RealNtBase=%s", g_RealNtBase.c_str());
    VL_DBG(L"LoadConfig: FsEnabled=%d  redirects=%u  FsDirNtBase=%s",
           (int)g_FsEnabled, (unsigned)g_FsRedirects.size(), g_FsDirNtBase.c_str());
}

// ============================================================
// Registry enumeration helpers
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
// Shared registry open/create helper
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
        return VL_STATUS_OBJECT_NOT_FOUND;
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

static NTSTATUS NTAPI Hook_NtOpenKey(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes)
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
    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    return st;
}

static NTSTATUS NTAPI Hook_NtOpenKeyEx(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
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

static NTSTATUS NTAPI Hook_NtOpenKeyTransacted(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle)
{
    VL_DBG(L"Hook_NtOpenKeyTransacted: TxH=%p path=%s", TransactionHandle,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);
    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
    return st;
}

static NTSTATUS NTAPI Hook_NtOpenKeyTransactedEx(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions, HANDLE TransactionHandle)
{
    VL_DBG(L"Hook_NtOpenKeyTransactedEx: TxH=%p opts=0x%X path=%s",
           TransactionHandle, OpenOptions,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtOpenKeyTransactedEx(KeyHandle, DesiredAccess,
                                           ObjectAttributes, OpenOptions, TransactionHandle);
    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              false, 0, NULL, 0, NULL);
    SetReentrant(false);
    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtOpenKeyTransactedEx(KeyHandle, DesiredAccess,
                                           ObjectAttributes, OpenOptions, TransactionHandle);
    return st;
}

static NTSTATUS NTAPI Hook_NtCreateKey(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex, PVL_UNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
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

static NTSTATUS NTAPI Hook_NtCreateKeyTransacted(
    PHANDLE KeyHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex, PVL_UNICODE_STRING Class, ULONG CreateOptions,
    HANDLE TransactionHandle, PULONG Disposition)
{
    VL_DBG(L"Hook_NtCreateKeyTransacted: TxH=%p path=%s", TransactionHandle,
           (ObjectAttributes && ObjectAttributes->ObjectName)
           ? FromUStr(ObjectAttributes->ObjectName).c_str() : L"(null)");
    if (!g_RegEnabled || IsReentrant() || !ObjectAttributes)
        return Real_NtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes,
                                           TitleIndex, Class, CreateOptions,
                                           TransactionHandle, Disposition);
    SetReentrant(true);
    NTSTATUS st = DoVirtOpen(ObjectAttributes, DesiredAccess, KeyHandle,
                              true, TitleIndex, Class, CreateOptions, Disposition);
    SetReentrant(false);
    if (st == VL_STATUS_OBJECT_NOT_FOUND)
        return Real_NtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes,
                                           TitleIndex, Class, CreateOptions,
                                           TransactionHandle, Disposition);
    return st;
}

static NTSTATUS NTAPI Hook_NtQueryKey(
    HANDLE KeyHandle, VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength)
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

static NTSTATUS NTAPI Hook_NtEnumerateKey(
    HANDLE KeyHandle, ULONG Index, VL_KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength)
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
    SetReentrant(true);
    std::vector<std::wstring> virtNames = CollectSubkeyNames(hV);
    SetReentrant(false);
    ULONG virtCount = (ULONG)virtNames.size();
    if (Index < virtCount)
        return Real_NtEnumerateKey(hV, Index, KeyInformationClass,
                                    KeyInformation, Length, ResultLength);
    ULONG want = Index - virtCount;
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

static NTSTATUS NTAPI Hook_NtEnumerateValueKey(
    HANDLE KeyHandle, ULONG Index,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
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

static NTSTATUS NTAPI Hook_NtQueryValueKey(
    HANDLE KeyHandle, PVL_UNICODE_STRING ValueName,
    VL_KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
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

static NTSTATUS NTAPI Hook_NtQueryMultipleValueKey(
    HANDLE KeyHandle, PVL_KEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount, PVOID ValueBuffer, PULONG BufferLength, PULONG RequiredBufferLength)
{
    VirtKeyEntry e;
    if (!g_RegEnabled || !GetEntry(KeyHandle, e)) {
        return Real_NtQueryMultipleValueKey(KeyHandle, ValueEntries, EntryCount,
                                             ValueBuffer, BufferLength,
                                             RequiredBufferLength);
    }
    VL_DBG(L"Hook_NtQueryMultipleValueKey: entryCount=%u handle=%p virt=%p real=%p",
           EntryCount, KeyHandle, e.hVirt, e.hReal);
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

static NTSTATUS NTAPI Hook_NtSetValueKey(
    HANDLE KeyHandle, PVL_UNICODE_STRING ValueName,
    ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
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

static NTSTATUS NTAPI Hook_NtDeleteValueKey(
    HANDLE KeyHandle, PVL_UNICODE_STRING ValueName)
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

static NTSTATUS NTAPI Hook_NtRenameKey(
    HANDLE KeyHandle, PVL_UNICODE_STRING NewName)
{
    VirtKeyEntry e;
    bool tracked = g_RegEnabled && GetEntry(KeyHandle, e);
    HANDLE useH  = tracked ? (e.hVirt ? e.hVirt : e.hReal) : KeyHandle;
    VL_DBG(L"Hook_NtRenameKey: handle=%p useH=%p newName=%s",
           KeyHandle, useH,
           NewName ? FromUStr(NewName).c_str() : L"(null)");
    return Real_NtRenameKey(useH, NewName);
}

static NTSTATUS NTAPI Hook_NtReplaceKey(
    PVL_OBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, PVL_OBJECT_ATTRIBUTES OldFile)
{
    VL_DBG(L"Hook_NtReplaceKey: TargetHandle=%p NewFile=%s OldFile=%s",
           TargetHandle,
           (NewFile && NewFile->ObjectName) ? FromUStr(NewFile->ObjectName).c_str() : L"(null)",
           (OldFile && OldFile->ObjectName) ? FromUStr(OldFile->ObjectName).c_str() : L"(null)");
    VirtKeyEntry e;
    HANDLE useH = TargetHandle;
    if (g_RegEnabled && GetEntry(TargetHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : TargetHandle);
    return Real_NtReplaceKey(NewFile, useH, OldFile);
}

static NTSTATUS NTAPI Hook_NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    VL_DBG(L"Hook_NtSaveKey: handle=%p useH=%p fileH=%p",
           KeyHandle, useH, FileHandle);
    return Real_NtSaveKey(useH, FileHandle);
}

static NTSTATUS NTAPI Hook_NtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    VL_DBG(L"Hook_NtSaveKeyEx: handle=%p useH=%p fileH=%p fmt=%u",
           KeyHandle, useH, FileHandle, Format);
    return Real_NtSaveKeyEx(useH, FileHandle, Format);
}

static NTSTATUS NTAPI Hook_NtLoadKey(
    PVL_OBJECT_ATTRIBUTES TargetKey, PVL_OBJECT_ATTRIBUTES SourceFile)
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

static NTSTATUS NTAPI Hook_NtLoadKey2(
    PVL_OBJECT_ATTRIBUTES TargetKey, PVL_OBJECT_ATTRIBUTES SourceFile, ULONG Flags)
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

static NTSTATUS NTAPI Hook_NtLoadKeyEx(
    PVL_OBJECT_ATTRIBUTES TargetKey, PVL_OBJECT_ATTRIBUTES SourceFile, ULONG Flags,
    HANDLE TrustClassKey, HANDLE Event, ULONG DesiredAccess,
    PHANDLE RootHandle, PVOID Reserved)
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

static NTSTATUS NTAPI Hook_NtNotifyChangeKey(
    HANDLE KeyHandle, HANDLE Event, VL_PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree,
    PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous)
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

static NTSTATUS NTAPI Hook_NtNotifyChangeMultipleKeys(
    HANDLE MasterKeyHandle, ULONG Count, PVL_OBJECT_ATTRIBUTES SubordinateObjects,
    HANDLE Event, VL_PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree,
    PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous)
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

static NTSTATUS NTAPI Hook_NtFlushKey(HANDLE KeyHandle) {
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    VL_DBG(L"Hook_NtFlushKey: handle=%p useH=%p", KeyHandle, useH);
    return Real_NtFlushKey(useH);
}

static NTSTATUS NTAPI Hook_NtRestoreKey(
    HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags)
{
    VirtKeyEntry e;
    HANDLE useH = KeyHandle;
    if (g_RegEnabled && GetEntry(KeyHandle, e))
        useH = e.hVirt ? e.hVirt : (e.hReal ? e.hReal : KeyHandle);
    VL_DBG(L"Hook_NtRestoreKey: handle=%p useH=%p fileH=%p flags=0x%X",
           KeyHandle, useH, FileHandle, Flags);
    return Real_NtRestoreKey(useH, FileHandle, Flags);
}

static NTSTATUS NTAPI Hook_NtSetInformationKey(
    HANDLE KeyHandle, ULONG KeySetInformationClass,
    PVOID KeySetInformation, ULONG KeySetInformationLength)
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

static NTSTATUS NTAPI Hook_NtLoadKey3(
    PVL_OBJECT_ATTRIBUTES TargetKey, PVL_OBJECT_ATTRIBUTES SourceFile, ULONG Flags,
    PVOID ExtendedParameters, ULONG ExtendedParameterCount,
    ULONG DesiredAccess, HANDLE RootHandle, PVOID Reserved)
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

// ============================================================
// NtClose -- handles BOTH registry and file tracked handles
// ============================================================

static NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    // Try registry first
    VirtKeyEntry ke;
    if (GetEntry(Handle, ke)) {
        VL_DBG(L"Hook_NtClose: tracked REG handle=%p hVirt=%p hReal=%p",
               Handle, ke.hVirt, ke.hReal);
        UntrackHandle(Handle);
        NTSTATUS st = VL_STATUS_SUCCESS;
        if (ke.hVirt == Handle) {
            st = Real_NtClose(Handle);
            if (ke.hReal && ke.hReal != Handle) Real_NtClose(ke.hReal);
        } else if (ke.hReal == Handle) {
            st = Real_NtClose(Handle);
            if (ke.hVirt && ke.hVirt != Handle) Real_NtClose(ke.hVirt);
        } else {
            if (ke.hVirt) Real_NtClose(ke.hVirt);
            if (ke.hReal) Real_NtClose(ke.hReal);
            st = Real_NtClose(Handle);
        }
        return st;
    }

    // Try files
    VirtFileEntry fe;
    if (GetFileEntry(Handle, fe)) {
        VL_DBG(L"Hook_NtClose: tracked FS handle=%p hVirt=%p hReal=%p",
               Handle, fe.hVirt, fe.hReal);
        UntrackFileHandle(Handle);
        NTSTATUS st = VL_STATUS_SUCCESS;
        if (fe.hVirt == Handle) {
            st = Real_NtClose(Handle);
            if (fe.hReal && fe.hReal != Handle) Real_NtClose(fe.hReal);
        } else if (fe.hReal == Handle) {
            st = Real_NtClose(Handle);
            if (fe.hVirt && fe.hVirt != Handle) Real_NtClose(fe.hVirt);
        } else {
            if (fe.hVirt) Real_NtClose(fe.hVirt);
            if (fe.hReal) Real_NtClose(fe.hReal);
            st = Real_NtClose(Handle);
        }
        return st;
    }

    return Real_NtClose(Handle);
}

// ============================================================
// REPARSE POINT HOOK
// ============================================================

#define VL_FSCTL_SET_REPARSE_POINT  0x000900A4UL
#define VL_FSCTL_GET_REPARSE_POINT  0x000900A8UL
#define VL_IO_REPARSE_TAG_MOUNT_POINT 0xA0000003UL
#define VL_IO_REPARSE_TAG_SYMLINK     0xA000000CUL
#define VL_SYMLINK_FLAG_RELATIVE      0x00000001UL

#define VL_REPARSE_HDR_SIZE        8u
#define VL_SYMLINK_FIELDS_SIZE    12u
#define VL_MOUNTPOINT_FIELDS_SIZE  8u

struct VL_REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymLink;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPoint;
    };
};

static NTSTATUS NTAPI Hook_NtFsControlFile(
    HANDLE FileHandle, HANDLE Event, VL_PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength)
{
    if (!g_FsEnabled)
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     InputBuffer, InputBufferLength,
                                     OutputBuffer, OutputBufferLength);

    // FSCTL_GET_REPARSE_POINT -- reverse-translate
    if (FsControlCode == VL_FSCTL_GET_REPARSE_POINT) {
        NTSTATUS st = Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, FsControlCode,
                                            InputBuffer, InputBufferLength,
                                            OutputBuffer, OutputBufferLength);
        if ((!NT_SUCCESS(st) && st != (NTSTATUS)0x80000005L) ||
            !OutputBuffer || OutputBufferLength < VL_REPARSE_HDR_SIZE)
            return st;
        VL_REPARSE_DATA_BUFFER* rdb = (VL_REPARSE_DATA_BUFFER*)OutputBuffer;
        if (rdb->ReparseTag == VL_IO_REPARSE_TAG_SYMLINK &&
            !(rdb->SymLink.Flags & VL_SYMLINK_FLAG_RELATIVE))
        {
            WCHAR* pb = rdb->SymLink.PathBuffer;
            std::wstring subst(pb + rdb->SymLink.SubstituteNameOffset / sizeof(WCHAR),
                                rdb->SymLink.SubstituteNameLength / sizeof(WCHAR));
            std::wstring print(pb + rdb->SymLink.PrintNameOffset / sizeof(WCHAR),
                                rdb->SymLink.PrintNameLength / sizeof(WCHAR));
            std::wstring revSubst = ReverseRedirectSymlinkPath(subst);
            std::wstring revPrint = ReverseRedirectSymlinkPath(print);
            VL_DBG(L"Hook_NtFsControlFile GET SYMLINK: subst=%s->%s  print=%s->%s",
                   subst.c_str(), revSubst.c_str(), print.c_str(), revPrint.c_str());
            if (revSubst.size() <= subst.size() && revPrint.size() <= print.size()) {
                USHORT rss = (USHORT)(revSubst.size() * sizeof(WCHAR));
                USHORT rps = (USHORT)(revPrint.size() * sizeof(WCHAR));
                memcpy(pb + rdb->SymLink.SubstituteNameOffset / sizeof(WCHAR),
                       revSubst.c_str(), rss);
                rdb->SymLink.SubstituteNameLength = rss;
                memcpy(pb + rdb->SymLink.PrintNameOffset / sizeof(WCHAR),
                       revPrint.c_str(), rps);
                rdb->SymLink.PrintNameLength = rps;
            }
        }
        else if (rdb->ReparseTag == VL_IO_REPARSE_TAG_MOUNT_POINT)
        {
            WCHAR* pb = rdb->MountPoint.PathBuffer;
            std::wstring subst(pb + rdb->MountPoint.SubstituteNameOffset / sizeof(WCHAR),
                                rdb->MountPoint.SubstituteNameLength / sizeof(WCHAR));
            std::wstring print(pb + rdb->MountPoint.PrintNameOffset / sizeof(WCHAR),
                                rdb->MountPoint.PrintNameLength / sizeof(WCHAR));
            std::wstring revSubst = ReverseRedirectSymlinkPath(subst);
            std::wstring revPrint = ReverseRedirectSymlinkPath(print);
            VL_DBG(L"Hook_NtFsControlFile GET JUNCTION: subst=%s->%s  print=%s->%s",
                   subst.c_str(), revSubst.c_str(), print.c_str(), revPrint.c_str());
            if (revSubst.size() <= subst.size() && revPrint.size() <= print.size()) {
                USHORT rss = (USHORT)(revSubst.size() * sizeof(WCHAR));
                USHORT rps = (USHORT)(revPrint.size() * sizeof(WCHAR));
                memcpy(pb + rdb->MountPoint.SubstituteNameOffset / sizeof(WCHAR),
                       revSubst.c_str(), rss);
                rdb->MountPoint.SubstituteNameLength = rss;
                memcpy(pb + rdb->MountPoint.PrintNameOffset / sizeof(WCHAR),
                       revPrint.c_str(), rps);
                rdb->MountPoint.PrintNameLength = rps;
            }
        }
        return st;
    }

    // FSCTL_SET_REPARSE_POINT -- redirect embedded paths
    if (FsControlCode != VL_FSCTL_SET_REPARSE_POINT ||
        !InputBuffer || InputBufferLength < VL_REPARSE_HDR_SIZE)
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     InputBuffer, InputBufferLength,
                                     OutputBuffer, OutputBufferLength);

    VL_REPARSE_DATA_BUFFER* rdb = (VL_REPARSE_DATA_BUFFER*)InputBuffer;

    if (rdb->ReparseTag == VL_IO_REPARSE_TAG_SYMLINK) {
        if (rdb->SymLink.Flags & VL_SYMLINK_FLAG_RELATIVE) {
            VL_DBG(L"Hook_NtFsControlFile SET SYMLINK: relative -- pass through");
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        }
        WCHAR* pb = rdb->SymLink.PathBuffer;
        std::wstring subst(pb + rdb->SymLink.SubstituteNameOffset / sizeof(WCHAR),
                            rdb->SymLink.SubstituteNameLength / sizeof(WCHAR));
        std::wstring print(pb + rdb->SymLink.PrintNameOffset / sizeof(WCHAR),
                            rdb->SymLink.PrintNameLength / sizeof(WCHAR));
        std::wstring redSubst = RedirectSymlinkPath(subst);
        std::wstring redPrint = RedirectSymlinkPath(print);
        VL_DBG(L"Hook_NtFsControlFile SET SYMLINK: subst=%s->%s  print=%s->%s",
               subst.c_str(), redSubst.c_str(), print.c_str(), redPrint.c_str());
        if (redSubst == subst && redPrint == print)
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        USHORT newSubBytes      = (USHORT)(redSubst.size() * sizeof(WCHAR));
        USHORT newPrtBytes      = (USHORT)(redPrint.size() * sizeof(WCHAR));
        USHORT newReparseDataLen = (USHORT)(VL_SYMLINK_FIELDS_SIZE + newSubBytes + newPrtBytes);
        ULONG  newBufSize       = VL_REPARSE_HDR_SIZE + newReparseDataLen;
        std::vector<BYTE> newBuf(newBufSize, 0);
        VL_REPARSE_DATA_BUFFER* n = (VL_REPARSE_DATA_BUFFER*)&newBuf[0];
        n->ReparseTag                   = rdb->ReparseTag;
        n->ReparseDataLength            = newReparseDataLen;
        n->Reserved                     = 0;
        n->SymLink.SubstituteNameOffset = 0;
        n->SymLink.SubstituteNameLength = newSubBytes;
        n->SymLink.PrintNameOffset      = newSubBytes;
        n->SymLink.PrintNameLength      = newPrtBytes;
        n->SymLink.Flags                = rdb->SymLink.Flags;
        memcpy(n->SymLink.PathBuffer, redSubst.c_str(), newSubBytes);
        memcpy((BYTE*)n->SymLink.PathBuffer + newSubBytes, redPrint.c_str(), newPrtBytes);
        VL_DBG(L"Hook_NtFsControlFile SET SYMLINK: rebuilt buffer %u->%u bytes",
               InputBufferLength, newBufSize);
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     &newBuf[0], newBufSize,
                                     OutputBuffer, OutputBufferLength);
    }

    if (rdb->ReparseTag == VL_IO_REPARSE_TAG_MOUNT_POINT) {
        WCHAR* pb = rdb->MountPoint.PathBuffer;
        std::wstring subst(pb + rdb->MountPoint.SubstituteNameOffset / sizeof(WCHAR),
                            rdb->MountPoint.SubstituteNameLength / sizeof(WCHAR));
        std::wstring print(pb + rdb->MountPoint.PrintNameOffset / sizeof(WCHAR),
                            rdb->MountPoint.PrintNameLength / sizeof(WCHAR));
        std::wstring redSubst = RedirectSymlinkPath(subst);
        std::wstring redPrint = RedirectSymlinkPath(print);
        VL_DBG(L"Hook_NtFsControlFile SET JUNCTION: subst=%s->%s  print=%s->%s",
               subst.c_str(), redSubst.c_str(), print.c_str(), redPrint.c_str());
        if (redSubst == subst && redPrint == print)
            return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                         IoStatusBlock, FsControlCode,
                                         InputBuffer, InputBufferLength,
                                         OutputBuffer, OutputBufferLength);
        USHORT newSubBytes  = (USHORT)(redSubst.size() * sizeof(WCHAR));
        USHORT newPrtBytes  = (USHORT)(redPrint.size() * sizeof(WCHAR));
        USHORT newPrtOff    = newSubBytes + (USHORT)sizeof(WCHAR);
        USHORT newDataLen   = (USHORT)(VL_MOUNTPOINT_FIELDS_SIZE
                                       + newPrtOff + newPrtBytes
                                       + (USHORT)sizeof(WCHAR));
        ULONG  newBufSize   = VL_REPARSE_HDR_SIZE + newDataLen;
        std::vector<BYTE> newBuf(newBufSize, 0);
        VL_REPARSE_DATA_BUFFER* n = (VL_REPARSE_DATA_BUFFER*)&newBuf[0];
        n->ReparseTag                      = rdb->ReparseTag;
        n->ReparseDataLength               = newDataLen;
        n->Reserved                        = 0;
        n->MountPoint.SubstituteNameOffset = 0;
        n->MountPoint.SubstituteNameLength = newSubBytes;
        n->MountPoint.PrintNameOffset      = newPrtOff;
        n->MountPoint.PrintNameLength      = newPrtBytes;
        memcpy(n->MountPoint.PathBuffer, redSubst.c_str(), newSubBytes);
        memcpy((BYTE*)n->MountPoint.PathBuffer + newPrtOff, redPrint.c_str(), newPrtBytes);
        VL_DBG(L"Hook_NtFsControlFile SET JUNCTION: rebuilt buffer %u->%u bytes"
               L" (subst=%u prtOff=%u prt=%u)",
               InputBufferLength, newBufSize, newSubBytes, newPrtOff, newPrtBytes);
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     &newBuf[0], newBufSize,
                                     OutputBuffer, OutputBufferLength);
    }

    return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                 IoStatusBlock, FsControlCode,
                                 InputBuffer, InputBufferLength,
                                 OutputBuffer, OutputBufferLength);
}

// ============================================================
// FILE SYSTEM HOOKS
// ============================================================

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

    if (!redirected)
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);

    bool isDir = (CreateOptions & FILE_DIRECTORY_FILE) != 0;
    bool isWrite = HasWriteAccess(DesiredAccess);

    VL_DBG(L"Hook_NtCreateFile: %s -> %s disp=%u acc=0x%08X dir=%d",
           ntPath.c_str(), redPath.c_str(), CreateDisposition, DesiredAccess, (int)isDir);

    // WRITE-ONLY / CREATE dispositions -> virtual only
    if (CreateDisposition == FILE_CREATE ||
        CreateDisposition == FILE_SUPERSEDE ||
        CreateDisposition == FILE_OVERWRITE ||
        CreateDisposition == FILE_OVERWRITE_IF)
    {
        SetReentrant(true);
        EnsureVirtualFsPath(redPath);
        DeleteTombstoneIfPresent(redPath);
        SetReentrant(false);

        ULONG dispToUse = CreateDisposition;
        if ((CreateDisposition == FILE_OVERWRITE ||
             CreateDisposition == FILE_OVERWRITE_IF) && !isDir) {
            VL_UNICODE_STRING probe; MakeUStr(&probe, redPath);
            VL_OBJECT_ATTRIBUTES probeOa; MakeOA(&probeOa, &probe);
            BYTE dummy[48] = {0};
            if (IsFsNotFound(Real_NtQueryAttributesFile(&probeOa, dummy)))
                dispToUse = FILE_SUPERSEDE;
        }

        NTSTATUS st = Real_NtCreateFile(FileHandle, DesiredAccess, &newOa,
                                          IoStatusBlock, AllocationSize, FileAttributes,
                                          ShareAccess, dispToUse, CreateOptions,
                                          EaBuffer, EaLength);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = isDir;
            e.isRealOnly = false;
            // Try to open real dir shadow for future merge
            if (!e.isDir) {
                // Try to open real dir for merging (in case this is a dir opened without flag)
                VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
                VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
                VL_IO_STATUS_BLOCK iosb;
                Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
                if (e.hReal) e.isDir = true;
            } else {
                VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
                VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
                VL_IO_STATUS_BLOCK iosb;
                Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            }
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    }

    // FILE_OPEN_IF + write: ensure dirs then fall through to CoW logic
    if (CreateDisposition == FILE_OPEN_IF && isWrite) {
        SetReentrant(true);
        EnsureVirtualFsPath(redPath);
        DeleteTombstoneIfPresent(redPath);
        SetReentrant(false);
    }

    // Try virtual first
    NTSTATUS st = Real_NtCreateFile(FileHandle, DesiredAccess, &newOa,
                                     IoStatusBlock, AllocationSize, FileAttributes,
                                     ShareAccess, CreateDisposition, CreateOptions,
                                     EaBuffer, EaLength);
    if (NT_SUCCESS(st)) {
        VirtFileEntry e;
        e.hVirt = *FileHandle;
        e.logPath = ntPath;
        e.isDir = isDir;
        e.isRealOnly = false;
        if (!e.isDir) {
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            if (e.hReal) e.isDir = true;
        } else {
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
        TrackFileHandle(*FileHandle, e);
        return st;
    }

    if (!IsFsNotFound(st)) return st;

    // Tombstone check
    SetReentrant(true);
    bool tombstoned = TombstoneExists(redPath);
    SetReentrant(false);
    if (tombstoned) {
        VL_DBG(L"Hook_NtCreateFile: tombstone -> deleted in sandbox");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Check real
    BYTE basicBuf[48] = {0};
    NTSTATUS realCheck = Real_NtQueryAttributesFile(ObjectAttributes, basicBuf);
    if (IsFsNotFound(realCheck)) {
        VL_DBG(L"Hook_NtCreateFile: real also not found, returning 0x%08X", (ULONG)st);
        return st;
    }

    if (!isWrite) {
        // Read-only CoW: serve real directly
        VL_DBG(L"Hook_NtCreateFile: read-only CoW fallback to real");
        NTSTATUS stReal = Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                             IoStatusBlock, AllocationSize, FileAttributes,
                                             ShareAccess, CreateDisposition, CreateOptions,
                                             EaBuffer, EaLength);
        if (NT_SUCCESS(stReal)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.hReal = *FileHandle;
            e.logPath = ntPath;
            e.isDir = isDir;
            e.isRealOnly = true;
            TrackFileHandle(*FileHandle, e);
        }
        return stReal;
    }

    // Write CoW
    if (isDir) {
        SetReentrant(true);
        EnsureVirtualFsPath(redPath);
        SetReentrant(false);
        st = Real_NtCreateFile(FileHandle, DesiredAccess, &newOa, IoStatusBlock,
                                AllocationSize, FileAttributes, ShareAccess,
                                CreateDisposition, CreateOptions, EaBuffer, EaLength);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = true;
            e.isRealOnly = false;
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    } else {
        VL_DBG(L"Hook_NtCreateFile: write CoW, copying real->virtual");
        SetReentrant(true);
        bool copied = CopyRealFileToVirtual(ntPath, redPath);
        SetReentrant(false);
        if (!copied) {
            VL_DBG(L"Hook_NtCreateFile: CoW copy failed, returning 0x%08X", (ULONG)st);
            return st;
        }
        st = Real_NtCreateFile(FileHandle, DesiredAccess, &newOa, IoStatusBlock,
                                AllocationSize, FileAttributes, ShareAccess,
                                CreateDisposition, CreateOptions, EaBuffer, EaLength);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = false;
            e.isRealOnly = false;
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    }
}

static NTSTATUS NTAPI Hook_NtOpenFile(
    PHANDLE               FileHandle,
    ULONG                 DesiredAccess,
    PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK   IoStatusBlock,
    ULONG                 ShareAccess,
    ULONG                 OpenOptions)
{
    if (OpenOptions & FILE_OPEN_BY_FILE_ID) {
        VL_DBG(L"Hook_NtOpenFile: FILE_OPEN_BY_FILE_ID - pass through");
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);

    if (!redirected)
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, ShareAccess, OpenOptions);

    bool isDir = (OpenOptions & FILE_DIRECTORY_FILE) != 0;
    bool isWrite = HasWriteAccess(DesiredAccess);

    VL_DBG(L"Hook_NtOpenFile: %s -> %s dir=%d write=%d",
           ntPath.c_str(), redPath.c_str(), (int)isDir, (int)isWrite);

    NTSTATUS st = Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                                   IoStatusBlock, ShareAccess, OpenOptions);
    if (NT_SUCCESS(st)) {
        VirtFileEntry e;
        e.hVirt = *FileHandle;
        e.logPath = ntPath;
        e.isDir = isDir;
        e.isRealOnly = false;
        if (!isDir) {
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            if (e.hReal) e.isDir = true;
        } else {
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
        TrackFileHandle(*FileHandle, e);
        return st;
    }

    if (!IsFsNotFound(st)) return st;

    SetReentrant(true);
    bool tombstoned = TombstoneExists(redPath);
    SetReentrant(false);
    if (tombstoned) {
        VL_DBG(L"Hook_NtOpenFile: tombstone -> deleted in sandbox");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    BYTE basicBuf[48] = {0};
    if (IsFsNotFound(Real_NtQueryAttributesFile(ObjectAttributes, basicBuf))) {
        VL_DBG(L"Hook_NtOpenFile: real also not found, returning 0x%08X", (ULONG)st);
        return st;
    }

    if (!isWrite) {
        VL_DBG(L"Hook_NtOpenFile: read-only CoW fallback to real");
        NTSTATUS stReal = Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                           IoStatusBlock, ShareAccess, OpenOptions);
        if (NT_SUCCESS(stReal)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.hReal = *FileHandle;
            e.logPath = ntPath;
            e.isDir = isDir;
            e.isRealOnly = true;
            TrackFileHandle(*FileHandle, e);
        }
        return stReal;
    }

    if (isDir) {
        SetReentrant(true);
        EnsureVirtualFsPath(redPath);
        SetReentrant(false);
        st = Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                              IoStatusBlock, ShareAccess, OpenOptions);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = true;
            e.isRealOnly = false;
            VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
            VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    } else {
        VL_DBG(L"Hook_NtOpenFile: write CoW, copying real->virtual");
        SetReentrant(true);
        bool copied = CopyRealFileToVirtual(ntPath, redPath);
        SetReentrant(false);
        if (!copied) {
            VL_DBG(L"Hook_NtOpenFile: CoW copy failed, returning 0x%08X", (ULONG)st);
            return st;
        }
        st = Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                              IoStatusBlock, ShareAccess, OpenOptions);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = false;
            e.isRealOnly = false;
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    }
}

static NTSTATUS NTAPI Hook_NtCreateDirectoryObject(
    PHANDLE DirectoryHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes)
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

static NTSTATUS NTAPI Hook_NtOpenDirectoryObject(
    PHANDLE DirectoryHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes)
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

static NTSTATUS NTAPI Hook_NtCreateMailslotFile(
    PHANDLE FileHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota,
    ULONG MaximumMessageSize, PLARGE_INTEGER ReadTimeout)
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

static NTSTATUS NTAPI Hook_NtCreateNamedPipeFile(
    PHANDLE FileHandle, ULONG DesiredAccess, PVL_OBJECT_ATTRIBUTES ObjectAttributes,
    PVL_IO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode,
    ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota,
    PLARGE_INTEGER DefaultTimeout)
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

static NTSTATUS NTAPI Hook_NtDeleteFile(PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);
    VL_DBG(L"Hook_NtDeleteFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");
    if (!redirected)
        return Real_NtDeleteFile(ObjectAttributes);

    // Try delete virtual
    NTSTATUS st = Real_NtDeleteFile(&newOa);
    if (NT_SUCCESS(st)) {
        // Virtual delete succeeded. If real still exists, create tombstone.
        BYTE basicBuf[48] = {0};
        if (!IsFsNotFound(Real_NtQueryAttributesFile(ObjectAttributes, basicBuf))) {
            SetReentrant(true);
            CreateTombstone(redPath);
            SetReentrant(false);
        } else {
            DeleteTombstoneIfPresent(redPath);
        }
        return st;
    }

    if (!IsFsNotFound(st)) return st;

    // Virtual didn't exist. Does real exist?
    BYTE basicBuf[48] = {0};
    if (IsFsNotFound(Real_NtQueryAttributesFile(ObjectAttributes, basicBuf))) {
        return st; // neither has it
    }

    // Real exists, virtual doesn't -> create tombstone to mask real
    SetReentrant(true);
    EnsureVirtualFsPath(redPath);
    CreateTombstone(redPath);
    SetReentrant(false);
    return VL_STATUS_SUCCESS;
}

static NTSTATUS NTAPI Hook_NtQueryAttributesFile(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);
    VL_DBG(L"Hook_NtQueryAttributesFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");
    if (!redirected)
        return Real_NtQueryAttributesFile(ObjectAttributes, FileInformation);

    NTSTATUS st = Real_NtQueryAttributesFile(&newOa, FileInformation);
    if (NT_SUCCESS(st)) return st;
    if (!IsFsNotFound(st)) return st;

    if (TombstoneExists(redPath)) return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    return Real_NtQueryAttributesFile(ObjectAttributes, FileInformation);
}

static NTSTATUS NTAPI Hook_NtQueryFullAttributesFile(
    PVL_OBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);
    VL_DBG(L"Hook_NtQueryFullAttributesFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");
    if (!redirected)
        return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);

    NTSTATUS st = Real_NtQueryFullAttributesFile(&newOa, FileInformation);
    if (NT_SUCCESS(st)) return st;
    if (!IsFsNotFound(st)) return st;

    if (TombstoneExists(redPath)) return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
}

// ---- NtQueryInformationByName (Win10+) ----
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

    NTSTATUS st = Real_NtQueryInformationByName(&newOa, IoStatusBlock,
                                                 FileInformation, Length,
                                                 FileInformationClass);
    if (NT_SUCCESS(st)) return st;
    if (!IsFsNotFound(st)) return st;

    if (TombstoneExists(redPath)) return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    return Real_NtQueryInformationByName(ObjectAttributes, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
}

// ============================================================
// Merged directory enumeration
// ============================================================

static NTSTATUS NTAPI Hook_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    VL_PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PVL_UNICODE_STRING FileName,
    BOOLEAN RestartScan)
{
    VirtFileEntry e;
    if (!g_FsEnabled || !GetFileEntry(FileHandle, e) || !e.isDir || e.isRealOnly) {
        return Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                          IoStatusBlock, FileInformation, Length,
                                          FileInformationClass, ReturnSingleEntry,
                                          FileName, RestartScan);
    }

    // On-demand open of real shadow handle if missing
    if (!e.hReal && !e.logPath.empty()) {
        VL_UNICODE_STRING realName; MakeUStr(&realName, e.logPath);
        VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
        VL_IO_STATUS_BLOCK iosb;
        Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        if (e.hReal) {
            UpdateFileEntry(FileHandle, e);
            VL_DBG(L"Hook_NtQueryDirectoryFile: on-demand opened real h=%p for %s",
                   e.hReal, e.logPath.c_str());
        } else {
            VL_DBG(L"Hook_NtQueryDirectoryFile: on-demand real open FAILED for %s",
                   e.logPath.c_str());
            return Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                              IoStatusBlock, FileInformation, Length,
                                              FileInformationClass, ReturnSingleEntry,
                                              FileName, RestartScan);
        }
    }

    // Save the search pattern on the very first call so we can replay it
    // when we open real-side enumeration later.
    if (RestartScan || !e.hasCachedFileName) {
        e.cachedFileName    = FileName ? FromUStr(FileName) : L"";
        e.hasCachedFileName = true;
    }

    if (RestartScan) {
        e.virtEnumDone       = false;
        e.realEnumDone       = false;
        e.realRestartPending = true;
        e.virtNames.clear();
    }
    UpdateFileEntry(FileHandle, e);

    // Virtual dir path used for tombstone probing during real enumeration
    const std::wstring virtDirPath = ApplyFsRedirect(e.logPath);

    // ---------------------------------------------------------------
    // Multi-entry path  (!ReturnSingleEntry)
    // ---------------------------------------------------------------
    if (!ReturnSingleEntry) {
        BOOLEAN virtRestart              = RestartScan;
        BOOLEAN localFileName_consumed   = FALSE;

        while (!e.virtEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFile(
                e.hVirt, Event, ApcRoutine, ApcContext,
                IoStatusBlock, FileInformation, Length,
                FileInformationClass, FALSE,
                localFileName_consumed ? NULL : FileName, virtRestart);
            virtRestart            = FALSE;
            localFileName_consumed = TRUE;

            if (NT_SUCCESS(st)) {
                // Record all names for real-side dedup
                {
                    BYTE* p = (BYTE*)FileInformation;
                    while (p) {
                        std::wstring nm = ExtractDirFileName(p, FileInformationClass);
                        if (!nm.empty()) e.virtNames.insert(nm);
                        ULONG nx = *(ULONG*)p;
                        if (nx == 0) break;
                        p += nx;
                    }
                }
                // Filter .vl_deleted marker files from the virtual buffer
                ULONG newLen = FilterDirBuffer(
                    FileInformation, (ULONG)IoStatusBlock->Information,
                    FileInformationClass, nullptr, L"");
                if (newLen > 0) {
                    IoStatusBlock->Information = newLen;
                    UpdateFileEntry(FileHandle, e);
                    return st;
                }
                // Entire buffer was tombstone markers — query again
                continue;
            }
            // FIX: recognise both end-of-dir status codes
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.virtEnumDone       = true;
                e.realRestartPending = true;
                UpdateFileEntry(FileHandle, e);
                break;
            }
            return st;
        }

        // Real-side multi-entry phase
        BOOLEAN realRestart = e.realRestartPending ? TRUE : FALSE;
        VL_UNICODE_STRING realFnUs;
        PVL_UNICODE_STRING pRealFn = NULL;
        if (realRestart && !e.cachedFileName.empty()) {
            MakeUStr(&realFnUs, e.cachedFileName);
            pRealFn = &realFnUs;
        }

        while (!e.realEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFile(
                e.hReal, Event, ApcRoutine, ApcContext,
                IoStatusBlock, FileInformation, Length,
                FileInformationClass, FALSE,
                pRealFn, realRestart);
            realRestart = FALSE;
            pRealFn     = NULL;

            if (NT_SUCCESS(st)) {
                ULONG newLen = FilterDirBuffer(
                    FileInformation, (ULONG)IoStatusBlock->Information,
                    FileInformationClass, &e.virtNames, virtDirPath);
                if (newLen > 0) {
                    e.realRestartPending = false;
                    IoStatusBlock->Information = newLen;
                    UpdateFileEntry(FileHandle, e);
                    return st;
                }
                continue; // all filtered; query again
            }
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.realEnumDone = true;
                UpdateFileEntry(FileHandle, e);
                return VL_STATUS_NO_MORE_FILES;
            }
            return st;
        }

        return VL_STATUS_NO_MORE_FILES;
    }

    // ---------------------------------------------------------------
    // Single-entry path  (ReturnSingleEntry = TRUE)
    // Used by FindFirstFile / FindNextFile — this is the hot path.
    // ---------------------------------------------------------------
    BOOLEAN restartVirt = RestartScan;
    BOOLEAN restartReal = e.realRestartPending ? TRUE : FALSE;

    // Prepare real-side FileName pointer for the first real query
    VL_UNICODE_STRING realFnUs;
    PVL_UNICODE_STRING pRealFileName = NULL;
    if (restartReal && !e.cachedFileName.empty()) {
        MakeUStr(&realFnUs, e.cachedFileName);
        pRealFileName = &realFnUs;
    }

    while (true) {
        // --- Virtual side ---
        if (!e.virtEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFile(
                e.hVirt, Event, ApcRoutine, ApcContext,
                IoStatusBlock, FileInformation, Length,
                FileInformationClass, TRUE,
                FileName, restartVirt);
            restartVirt = FALSE;

            if (NT_SUCCESS(st)) {
                std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                // Hide tombstone marker files (.vl_deleted) from callers
                if (IsTombstoneName(name)) continue;
                if (!name.empty()) e.virtNames.insert(name);
                UpdateFileEntry(FileHandle, e);
                return st;
            }
            // FIX: accept STATUS_NO_MORE_FILES from the virtual handle too
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.virtEnumDone       = true;
                e.realRestartPending = true;
                // Build real FileName pointer if not already set
                if (!pRealFileName && !e.cachedFileName.empty()) {
                    MakeUStr(&realFnUs, e.cachedFileName);
                    pRealFileName = &realFnUs;
                    restartReal   = TRUE;
                } else {
                    restartReal = TRUE;
                }
                UpdateFileEntry(FileHandle, e);
                continue;
            }
            return st;
        }

        // --- Real side ---
        if (!e.realEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFile(
                e.hReal, Event, ApcRoutine, ApcContext,
                IoStatusBlock, FileInformation, Length,
                FileInformationClass, TRUE,
                pRealFileName, restartReal);
            restartReal   = FALSE;
            pRealFileName = NULL; // only pass on first real call

            if (NT_SUCCESS(st)) {
                std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                // FIX: case-insensitive duplicate check (virtNames uses CiLess)
                if (!name.empty() && e.virtNames.count(name))
                    continue;
                // FIX: tombstone check — file was deleted inside the sandbox
                if (!name.empty() && !virtDirPath.empty()) {
                    SetReentrant(true);
                    bool tomb = FileHasTombstoneInVirtDir(virtDirPath, name);
                    SetReentrant(false);
                    if (tomb) continue;
                }
                e.realRestartPending = false;
                UpdateFileEntry(FileHandle, e);
                return st;
            }
            // FIX: recognise both end-of-dir codes from the real handle
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.realEnumDone = true;
                UpdateFileEntry(FileHandle, e);
                return VL_STATUS_NO_MORE_FILES;
            }
            return st;
        }

        // FIX: both exhausted — return the code callers (FindNextFile) expect
        return VL_STATUS_NO_MORE_FILES;
    }
}

// ---- NtQueryDirectoryFileEx -- merged view ----
static NTSTATUS NTAPI Hook_NtQueryDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event,
    VL_PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass,
    ULONG QueryFlags)
{
    VirtFileEntry e;
    if (!g_FsEnabled || !GetFileEntry(FileHandle, e) || !e.isDir || e.isRealOnly) {
        return Real_NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, FileInformation, Length,
                                            FileInformationClass, QueryFlags);
    }

    // On-demand open of real shadow handle if missing
    if (!e.hReal && !e.logPath.empty()) {
        VL_UNICODE_STRING realName; MakeUStr(&realName, e.logPath);
        VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realName);
        VL_IO_STATUS_BLOCK iosb;
        Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        if (e.hReal) {
            UpdateFileEntry(FileHandle, e);
            VL_DBG(L"Hook_NtQueryDirectoryFileEx: on-demand opened real h=%p for %s",
                   e.hReal, e.logPath.c_str());
        } else {
            VL_DBG(L"Hook_NtQueryDirectoryFileEx: on-demand real open FAILED for %s",
                   e.logPath.c_str());
            return Real_NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
                                                IoStatusBlock, FileInformation, Length,
                                                FileInformationClass, QueryFlags);
        }
    }

    BOOLEAN restartScan  = (QueryFlags & 0x01) ? TRUE : FALSE;
    BOOLEAN returnSingle = (QueryFlags & 0x02) ? TRUE : FALSE;

    // Save search pattern and reset state on restart
    if (restartScan || !e.hasCachedFileName) {
        // NtQueryDirectoryFileEx has no FileName parameter; pattern comes from QueryFlags
        // (there is no FileName arg in this variant). Cache empty string.
        e.cachedFileName    = L"";
        e.hasCachedFileName = true;
    }

    if (restartScan) {
        e.virtEnumDone       = false;
        e.realEnumDone       = false;
        e.realRestartPending = true;
        e.virtNames.clear();
    }
    UpdateFileEntry(FileHandle, e);

    const std::wstring virtDirPath = ApplyFsRedirect(e.logPath);

    // ---------------------------------------------------------------
    // Multi-entry path
    // ---------------------------------------------------------------
    if (!returnSingle) {
        ULONG flagsVirt = QueryFlags;

        while (!e.virtEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFileEx(e.hVirt, Event, ApcRoutine, ApcContext,
                                                        IoStatusBlock, FileInformation, Length,
                                                        FileInformationClass, flagsVirt);
            flagsVirt &= ~0x01u; // clear restart bit after first call

            if (NT_SUCCESS(st)) {
                {
                    BYTE* p = (BYTE*)FileInformation;
                    while (p) {
                        std::wstring nm = ExtractDirFileName(p, FileInformationClass);
                        if (!nm.empty()) e.virtNames.insert(nm);
                        ULONG nx = *(ULONG*)p;
                        if (nx == 0) break;
                        p += nx;
                    }
                }
                ULONG newLen = FilterDirBuffer(
                    FileInformation, (ULONG)IoStatusBlock->Information,
                    FileInformationClass, nullptr, L"");
                if (newLen > 0) {
                    IoStatusBlock->Information = newLen;
                    UpdateFileEntry(FileHandle, e);
                    return st;
                }
                continue; // all filtered
            }
            // FIX: accept both end-of-dir codes
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.virtEnumDone       = true;
                e.realRestartPending = true;
                UpdateFileEntry(FileHandle, e);
                break;
            }
            return st;
        }

        // Real-side multi-entry
        ULONG flagsReal = e.realRestartPending ? (QueryFlags | 0x01u) : (QueryFlags & ~0x01u);

        while (!e.realEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFileEx(e.hReal, Event, ApcRoutine, ApcContext,
                                                        IoStatusBlock, FileInformation, Length,
                                                        FileInformationClass, flagsReal);
            flagsReal &= ~0x01u;

            if (NT_SUCCESS(st)) {
                ULONG newLen = FilterDirBuffer(
                    FileInformation, (ULONG)IoStatusBlock->Information,
                    FileInformationClass, &e.virtNames, virtDirPath);
                if (newLen > 0) {
                    e.realRestartPending = false;
                    IoStatusBlock->Information = newLen;
                    UpdateFileEntry(FileHandle, e);
                    return st;
                }
                continue;
            }
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.realEnumDone = true;
                UpdateFileEntry(FileHandle, e);
                return VL_STATUS_NO_MORE_FILES;
            }
            return st;
        }

        return VL_STATUS_NO_MORE_FILES;
    }

    // ---------------------------------------------------------------
    // Single-entry path
    // ---------------------------------------------------------------
    ULONG flagsVirt = QueryFlags;
    ULONG flagsReal = e.realRestartPending ? (QueryFlags | 0x01u) : (QueryFlags & ~0x01u);

    while (true) {
        if (!e.virtEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFileEx(e.hVirt, Event, ApcRoutine, ApcContext,
                                                        IoStatusBlock, FileInformation, Length,
                                                        FileInformationClass, flagsVirt);
            flagsVirt &= ~0x01u; // clear restart after first call

            if (NT_SUCCESS(st)) {
                std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                if (IsTombstoneName(name)) continue;
                if (!name.empty()) e.virtNames.insert(name);
                UpdateFileEntry(FileHandle, e);
                return st;
            }
            // FIX: accept both end-of-dir codes
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.virtEnumDone       = true;
                e.realRestartPending = true;
                flagsReal            = (QueryFlags & ~0x01u) | 0x01u; // restart real
                UpdateFileEntry(FileHandle, e);
                continue;
            }
            return st;
        }

        if (!e.realEnumDone) {
            NTSTATUS st = Real_NtQueryDirectoryFileEx(e.hReal, Event, ApcRoutine, ApcContext,
                                                        IoStatusBlock, FileInformation, Length,
                                                        FileInformationClass, flagsReal);
            flagsReal &= ~0x01u;

            if (NT_SUCCESS(st)) {
                std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                // FIX: case-insensitive dedup (CiLess)
                if (!name.empty() && e.virtNames.count(name))
                    continue;
                // FIX: tombstone check
                if (!name.empty() && !virtDirPath.empty()) {
                    SetReentrant(true);
                    bool tomb = FileHasTombstoneInVirtDir(virtDirPath, name);
                    SetReentrant(false);
                    if (tomb) continue;
                }
                e.realRestartPending = false;
                UpdateFileEntry(FileHandle, e);
                return st;
            }
            // FIX: accept both end-of-dir codes
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES) {
                e.realEnumDone = true;
                UpdateFileEntry(FileHandle, e);
                return VL_STATUS_NO_MORE_FILES;
            }
            return st;
        }

        return VL_STATUS_NO_MORE_FILES;
    }
}

// ---- NtQueryInformationFile -- reverse-translate filename ----
static NTSTATUS NTAPI Hook_NtQueryInformationFile(
    HANDLE FileHandle,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass)
{
    VirtFileEntry e;
    if (!g_FsEnabled || !GetFileEntry(FileHandle, e)) {
        return Real_NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    NTSTATUS st = Real_NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    if (!NT_SUCCESS(st)) return st;

    if (FileInformationClass == 9 /*FileNameInformation*/ && Length >= sizeof(ULONG)) {
        struct MY_FNI {
            ULONG FileNameLength;
            WCHAR FileName[1];
        };
        MY_FNI* p = (MY_FNI*)FileInformation;
        if (p->FileNameLength > 0 && Length >= sizeof(ULONG) + p->FileNameLength) {
            std::wstring phys(p->FileName, p->FileNameLength / sizeof(WCHAR));
            std::wstring log = ReverseApplyFsRedirect(phys);
            if (log != phys && log.size() <= phys.size()) {
                USHORT newLen = (USHORT)(log.size() * sizeof(WCHAR));
                memcpy(p->FileName, log.c_str(), newLen);
                p->FileNameLength = newLen;
            }
        }
    }
    return st;
}

// ---- NtSetInformationFile -- intercepts rename, hardlink, and delete-on-close ----
#define FileRenameInformation      10
#define FileLinkInformation        11
#define FileRenameInformationEx    65
#define FileLinkInformationEx      72
#define FileDispositionInformation 13

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
    HANDLE FileHandle,
    PVL_IO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass)
{
    VL_DBG(L"Hook_NtSetInformationFile: handle=%p class=%u len=%u",
           FileHandle, FileInformationClass, Length);

    if (!g_FsEnabled || IsReentrant() || !FileInformation) {
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    // FileDispositionInformation (delete-on-close)
    if (FileInformationClass == FileDispositionInformation && Length >= sizeof(UCHAR)) {
        BOOLEAN deleteOnClose = *(BOOLEAN*)FileInformation;
        if (deleteOnClose) {
            VirtFileEntry e;
            if (GetFileEntry(FileHandle, e) && !e.isRealOnly && !e.isDir && !e.logPath.empty()) {
                std::wstring redPath = ApplyFsRedirect(e.logPath);
                VL_UNICODE_STRING realUs; MakeUStr(&realUs, e.logPath);
                VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realUs);
                BYTE basicBuf[48] = {0};
                if (!IsFsNotFound(Real_NtQueryAttributesFile(&realOa, basicBuf))) {
                    SetReentrant(true);
                    EnsureVirtualFsPath(redPath);
                    CreateTombstone(redPath);
                    SetReentrant(false);
                }
            }
        }
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    if (FileInformationClass != FileRenameInformation &&
        FileInformationClass != FileRenameInformationEx &&
        FileInformationClass != FileLinkInformation    &&
        FileInformationClass != FileLinkInformationEx)
    {
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    if (Length < RENAME_INFO_MIN_SIZE)
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);

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
    memcpy(&buf[0], p, RENAME_INFO_NAME_OFFSET);
    *(ULONG*)(&buf[0] + RENAME_INFO_NAMELEN_OFFSET) = newNameBytes;
    memcpy(&buf[0] + RENAME_INFO_NAME_OFFSET, redName.c_str(), newNameBytes);

    return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                      &buf[0], newLength,
                                      FileInformationClass);
}

// ============================================================
// CHILD PROCESS PROPAGATION
// ============================================================

static const char* PickDllPath() {
#ifdef _WIN64
    return g_DllPathA64[0] ? g_DllPathA64 : g_DllPathA;
#else
    return g_DllPathA32[0] ? g_DllPathA32 : g_DllPathA;
#endif
}

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
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
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
    PVOID wow64Old = NULL;
    bool  wow64Off = DisableWow64Redir(&wow64Old);
    const char* dlls[1] = { dllPath };
    BOOL ok = DetourCreateProcessWithDllsW(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation,
        1, dlls,
        Real_CreateProcessW);
    RestoreWow64Redir(wow64Off, wow64Old);
    if (!ok) {
        VL_DBG(L"Hook_CreateProcessW: DetourCreateProcessWithDllsW FAILED err=%u"
               L" -- falling back to unhooked launch", GetLastError());
        ok = Real_CreateProcessW(lpApplicationName, lpCommandLine,
                                  lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment,
                                  lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    return ok;
}

static BOOL WINAPI Hook_CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
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
        Real_CreateProcessA);
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

    // Internal raw pointers (not hooked, used for CoW copy / merge)
    VL_GETPROC(ntdll, NtReadFile);
    VL_GETPROC(ntdll, NtWriteFile);
    VL_GETPROC(ntdll, NtQueryInformationFile);
    VL_GETPROC(ntdll, NtQueryDirectoryFile);
    VL_GETPROC(ntdll, NtQueryDirectoryFileEx);

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
        VL_GETPROC(ntdll, NtLoadKey3);
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
        VL_GETPROC(ntdll, NtQueryInformationByName);
        VL_GETPROC(ntdll, NtSetInformationFile);
        VL_GETPROC(ntdll, NtFsControlFile);

        VL_DBG(L"InstallHooks FS: NtCreateFile=%p NtOpenFile=%p NtDeleteFile=%p"
               L" NtSetInformationFile=%p NtFsControlFile=%p",
               (void*)Real_NtCreateFile, (void*)Real_NtOpenFile,
               (void*)Real_NtDeleteFile, (void*)Real_NtSetInformationFile,
               (void*)Real_NtFsControlFile);
    }

    // Pre-create virtual root key
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

    // Attach all hooks in one transaction
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
        if (Real_NtQueryDirectoryFile)    VL_ATTACH(NtQueryDirectoryFile);
        if (Real_NtQueryDirectoryFileEx)  VL_ATTACH(NtQueryDirectoryFileEx);
        if (Real_NtQueryInformationFile)  VL_ATTACH(NtQueryInformationFile);
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
        if (Real_NtQueryDirectoryFile)    VL_DETACH(NtQueryDirectoryFile);
        if (Real_NtQueryDirectoryFileEx)  VL_DETACH(NtQueryDirectoryFileEx);
        if (Real_NtQueryInformationFile)  VL_DETACH(NtQueryInformationFile);
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
        InitializeCriticalSectionAndSpinCount(&g_FileMapLock, 4000);

        VL_DBG(L"DllMain: DLL_PROCESS_ATTACH -- VirtHook loading (v11 COW FS)");

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

        EnterCriticalSection(&g_FileMapLock);
        for (std::map<HANDLE,VirtFileEntry>::iterator it = g_FileMap.begin();
             it != g_FileMap.end(); ++it)
        {
            if (it->second.hVirt && it->second.hVirt != it->first)
                Real_NtClose(it->second.hVirt);
            if (it->second.hReal && it->second.hReal != it->first)
                Real_NtClose(it->second.hReal);
        }
        g_FileMap.clear();
        LeaveCriticalSection(&g_FileMapLock);
        DeleteCriticalSection(&g_FileMapLock);

        if (g_TlsIdx != TLS_OUT_OF_INDEXES) {
            TlsFree(g_TlsIdx);
            g_TlsIdx = TLS_OUT_OF_INDEXES;
        }
    }

    return TRUE;
}