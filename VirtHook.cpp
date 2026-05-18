// ============================================================
// VirtHook.cpp  - VirtLauncher Hook DLL  (v12 - console title fix)
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
//     NtSetInformationFile  (FileRenameInformation + FileLinkInformation + FileDispositionInformation)
//     NtFsControlFile       (FSCTL_SET_REPARSE_POINT / FSCTL_GET_REPARSE_POINT)
//     NtQueryDirectoryFile, NtQueryDirectoryFileEx   (merged view)
//     NtQueryInformationFile                           (path reverse-translate)
//
//   CHILDREN: CreateProcessW/A (propagate injection + prefix child lpTitle)
//
//   WINDOW TITLE PREFIXING (@ marker, same concept as Sandboxie's #):
//     SetWindowTextW/A      — GUI app title changes
//     CreateWindowExW/A     — GUI app window creation
//     SetConsoleTitleW/A    — console apps (cmd, PowerShell, etc.)
//                             cmd.exe calls SetConsoleTitleW (kernel32), NOT
//                             SetWindowTextW. conhost.exe owns the HWND; our
//                             SetWindowTextW hook is invisible to it.
//     Initial title fix     — conhost sets the title before DLL injection;
//                             DllMain re-prefixes it right after hooks go live.
//     STARTUPINFO.lpTitle   — child console windows start pre-titled.
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
// STATUS_NO_MORE_FILES (used by NtQueryDirectoryFile at end of dir)
#define VL_STATUS_NO_MORE_FILES          ((NTSTATUS)0x80000006L)
#define VL_STATUS_BUFFER_TOO_SMALL       ((NTSTATUS)0xC0000023L)
#define VL_STATUS_BUFFER_OVERFLOW        ((NTSTATUS)0x80000005L)
// STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) -- primary "not found" code
#define VL_STATUS_OBJECT_NAME_NOT_FOUND  ((NTSTATUS)0xC0000034L)
// STATUS_OBJECT_NAME_COLLISION (0xC0000035) -- returned when a file already exists
// in the merged namespace and FILE_CREATE / rename-without-replace is requested.
// This is what triggers Explorer's "- Copy" naming and cmd.exe's overwrite prompt.
#define VL_STATUS_OBJECT_NAME_COLLISION  ((NTSTATUS)0xC0000035L)
// STATUS_OBJECT_PATH_NOT_FOUND -- missing intermediate directory
#define VL_STATUS_OBJECT_PATH_NOT_FOUND  ((NTSTATUS)0xC000003AL)
// STATUS_NO_SUCH_FILE -- alternate "not found" used by some Nt calls
#define VL_STATUS_NO_SUCH_FILE           ((NTSTATUS)0xC000000FL)
#define VL_STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#define VL_STATUS_INVALID_HANDLE         ((NTSTATUS)0xC0000008L)
// STATUS_END_OF_FILE -- returned by NtReadFile at EOF
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

// ---- Registry ----
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

// ---- Files ----
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

// Window title prefixing (@)
typedef BOOL  (WINAPI *PfnSetWindowTextW)(HWND, LPCWSTR);
typedef BOOL  (WINAPI *PfnSetWindowTextA)(HWND, LPCSTR);
typedef HWND  (WINAPI *PfnCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef HWND  (WINAPI *PfnCreateWindowExA)(DWORD, LPCSTR,  LPCSTR,  DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
// Console title prefixing — cmd.exe calls SetConsoleTitleW (kernel32), not SetWindowTextW.
// conhost.exe owns the actual window; our SetWindowTextW hook is invisible to it.
// Hooking SetConsoleTitleW/A in the target process is the correct interception layer.
typedef BOOL  (WINAPI *PfnSetConsoleTitleW)(LPCWSTR);
typedef BOOL  (WINAPI *PfnSetConsoleTitleA)(LPCSTR);

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

// ----- Window title prefixing -----
static PfnSetWindowTextW  Real_SetWindowTextW;
static PfnSetWindowTextA  Real_SetWindowTextA;
static PfnCreateWindowExW Real_CreateWindowExW;
static PfnCreateWindowExA Real_CreateWindowExA;
// Console title (kernel32) — needed for cmd.exe / PowerShell / any console app
static PfnSetConsoleTitleW Real_SetConsoleTitleW;
static PfnSetConsoleTitleA Real_SetConsoleTitleA;

// Config flags
static bool g_RegEnabled = false;
static bool g_FsEnabled  = false;

// Registry virtualisation:
//   g_VirtNtBase = e.g.  \Registry\User\S-1-5-21-x\VirtApp
//   g_RealNtBase = parent e.g. \Registry\User\S-1-5-21-x
static std::wstring g_VirtNtBase;
static std::wstring g_RealNtBase;

// FS redirections from --config INI: vector of (nt_from_prefix, nt_to_prefix).
// Checked first; takes precedence over g_FsDirNtBase catch-all below.
static std::vector< std::pair<std::wstring,std::wstring> > g_FsRedirects;

// FS catch-all virtual store root from --filesystem (VIRTLAUNCHER_FSDIR).
// NT form of the folder, e.g. \??\D:\sandbox  (no trailing backslash).
// When set, any drive-letter path not matched by g_FsRedirects AND not
// already inside g_FsDirNtBase is redirected:
//   \??\X:\rest  ->  \??\<g_FsDirNtBase>\X\rest
static std::wstring g_FsDirNtBase;

// FS exclude prefixes from the [exclude] section of the --config INI file.
// Stored in NT form with no trailing backslash (e.g. \??\C:\Windows).
// If an NT path starts with any of these prefixes (with a component-boundary
// check so \??\C:\Win does not accidentally match \??\C:\Windows), that path
// is NEVER redirected -- all reads and writes go directly to the real file.
// Exclusions are evaluated after the Recycle Bin bypass and before any
// config-based or FSDIR catch-all redirect rules fire, so they take the
// highest priority among user-visible settings.
static std::vector<std::wstring> g_FsExcludes;

// Tracked virtual registry handles
struct VirtKeyEntry {
    HANDLE       hVirt;   // handle to VirtNtBase\X  (NULL if none)
    HANDLE       hReal;   // handle to RealNtBase\X  (NULL if none)
    std::wstring logPath; // LOGICAL NT path (under RealNtBase)
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
// Tracked virtual filesystem handles
// Needed so GetHandleLogicalPath can resolve a file handle back to its
// logical NT path (e.g. \??\C:\Windows\foo.dll) for relative-path opens.
// Without this a child open like  NtOpenFile(hDir, "foo.dll")  would have
// ObjectName="foo.dll" with no way to know the parent directory path,
// causing tombstones to be created/checked at the wrong location.
struct VirtFileEntry {
    HANDLE       hVirt;          // virtual-store handle (or real handle when isRealOnly)
    HANDLE       hReal;          // shadow real-dir handle for directory merge (may be NULL)
    std::wstring logPath;        // LOGICAL NT path (e.g. \??\C:\dir\file.dll)
    bool         isDir;          // true if this is a directory handle
    bool         isRealOnly;     // true if served from real store (read-only CoW pass-through)
    // Directory enumeration state
    bool         virtEnumDone;   // NtQueryDirectoryFile: virtual listing exhausted
    bool         realEnumDone;   // NtQueryDirectoryFile: real listing exhausted
    bool         realRestartPending; // restart-scan flag for real shadow handle
    bool         hasCachedFileName;  // true once FileName pattern has been saved
    bool         virtRestartPending; // force virtual handle to use cached pattern on first query
    std::set<std::wstring, CiLess> virtNames;
    std::wstring cachedFileName;     // saved FileName search pattern for 1st real call

    // Zero-initialize all scalar fields so stack garbage never causes bugs
    VirtFileEntry()
        : hVirt(NULL), hReal(NULL),
          isDir(false), isRealOnly(false),
          virtEnumDone(false), realEnumDone(false),
          realRestartPending(false), hasCachedFileName(false),
          virtRestartPending(false)
    {}
};
static std::map<HANDLE, VirtFileEntry> g_FileMap;
static CRITICAL_SECTION g_FileMapLock;

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
// Filesystem handle map helpers
// These mirror the registry helpers above.  Every file/dir handle
// opened through Hook_NtCreateFile / Hook_NtOpenFile is registered
// here so that GetHandleLogicalPath can resolve a later relative-path
// open (oa->RootDirectory != NULL, oa->ObjectName = "foo.dll") to the
// correct full logical NT path for tombstone / CoW path computation.
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

// Convert a kernel device path (\Device\HarddiskVolumeX\...) to a DOS
// NT path (\??\C:\...) by querying the drive-letter -> device mappings
// once and caching them.  Needed because NtQueryObject on a file handle
// returns \Device\... form while all our redirect tables use \??\X:\ form.
static std::wstring DevicePathToDosPath(const std::wstring& devicePath) {
    // Build the map once (lazy, no lock needed – worst case double-init is harmless)
    static std::map<std::wstring, std::wstring> s_devToDos;
    static bool s_init = false;
    if (!s_init) {
        s_init = true;
        wchar_t drives[512] = {0};
        DWORD len = GetLogicalDriveStringsW(511, drives);
        if (len > 0 && len < 512) {
            wchar_t* p = drives;
            while (*p) {
                // p points to e.g. "C:\", isolate the drive letter
                wchar_t drive[3] = { p[0], L':', L'\0' };
                wchar_t ntDev[MAX_PATH] = {0};
                if (QueryDosDeviceW(drive, ntDev, MAX_PATH)) {
                    std::wstring dev(ntDev);
                    // Strip trailing backslashes from the device path
                    while (!dev.empty() && dev[dev.size()-1] == L'\\') dev.pop_back();
                    // Map  \Device\HarddiskVolumeX  ->  \??\C:
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
    return devicePath;  // fallback: return unchanged
}

static std::wstring GetHandleLogicalPath(HANDLE h) {
    if (!h) return L"";
    
    // Fast path 1: filesystem handle tracked by our hook
    // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
    {
        VirtFileEntry fe;
        if (GetFileEntry(h, fe) && !fe.logPath.empty()) {
            VL_DBG(L"GetHandleLogicalPath: tracked FS -> %s", fe.logPath.c_str());
            return fe.logPath;
        }
    }

    // Fast path 2: registry handle tracked by our hook
    VirtKeyEntry e;
    if (GetEntry(h, e)) {
        VL_DBG(L"GetHandleLogicalPath: tracked -> %s", e.logPath.c_str());
        return e.logPath;
    }

    // NtQueryObject(ObjectNameInformation = class 1)
    // Returns the kernel path which may be \Device\HarddiskVolumeX\...
    // for file handles -- convert to \??\X:\ form.
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
                // Convert kernel device path to \??\ DOS form
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
//
// CRITICAL: StartsWithI is a pure prefix check. We must also verify the
// match ends on a path separator, otherwise the _Classes shadow hive
// (\Registry\User\S-1-5-21-...-1000_Classes) would match a g_RealNtBase
// of (\Registry\User\S-1-5-21-...-1000) and every HKCR / COM access would
// be intercepted, redirected to garbage virtual paths, and crash the app.
static bool LogicalToVirtual(const std::wstring& logical, std::wstring& virt) {
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

// Convert an NT path (\??\C:\foo) to a Win32 extended path (\\?\C:\foo)
// suitable for direct Win32 API calls (CopyFileExW, DeleteFileW, etc.).
// Handles both the \\?\\ and \?\\ NT prefixes.
static std::wstring NtPathToWin32(const std::wstring& ntPath) {
    // \??\X:\...  ->  \\?\X:\...
    if (ntPath.size() >= 4 &&
        ntPath[0] == L'\\' && ntPath[1] == L'?' &&
        ntPath[2] == L'?' && ntPath[3] == L'\\')
    {
        return L"\\\\?\\" + ntPath.substr(4);
    }
    // Already \\?\... form
    if (ntPath.size() >= 4 &&
        ntPath[0] == L'\\' && ntPath[1] == L'\\' &&
        ntPath[2] == L'?' && ntPath[3] == L'\\')
    {
        return ntPath;
    }
    return ntPath;   // unrecognised form: pass through unchanged
}

// ============================================================
// Recycle Bin path detection
// ============================================================
//
// Returns true if the NT path (\\??\X:\...) contains a Windows Recycle
// Bin folder component.  Three folder names are checked to cover all
// Windows versions:
//
//   $RECYCLE.BIN  -- Vista and later (NTFS)
//   RECYCLER       -- Windows XP / 2000 (NTFS)
//   RECYCLED       -- Windows 9x / FAT
//
// The check is case-insensitive and does a substring scan, so it
// matches:
//   \\??\C:\$RECYCLE.BIN
//   \\??\C:\$RECYCLE.BIN\S-1-5-...\$RXXX.txt
//   \\??\D:\RECYCLER\S-1-5-...
//   (and so on for any depth)
//
// WHY:  When --filesystem virtualisation is active, ApplyFsRedirect
// redirects every drive-letter path into the virtual store, including
// $RECYCLE.BIN.  That causes two problems:
//
//   1.  Deleted files land in <VirtStore>\X\$RECYCLE.BIN, not in the
//       real Windows Recycle Bin.  The Recycle Bin UI and "restore"
//       functionality are therefore bypassed entirely.
//
//   2.  The $I metadata files written by the Shell contain the original
//       logical path (e.g. C:\foo.txt), but that path is itself subject
//       to redirection, producing deeply nested corruption such as:
//         VirtStore\F\$RECYCLE.BIN\...\$R..\VirtStore\F\...
//
// FIX:  Recycle Bin paths are exempt from redirection.  Files opened or
// created inside $RECYCLE.BIN go directly to the real filesystem so the
// Shell's recycle mechanism works normally.  Cross-volume renames (when
// the source file was CoW-copied into the virtual store but the recycle
// destination is on the original drive) are handled separately in
// Hook_NtSetInformationFile.
static bool IsRecycleBinPath(const std::wstring& ntPath) {
    // We search for the folder name surrounded by backslashes (or at
    // the very end) to avoid false-positives on names that merely
    // contain the substring (e.g. "not_a_$RECYCLE.BIN_folder").
    static const wchar_t* const kBinFolders[] = {
        L"\\$RECYCLE.BIN",   // Vista+
        L"\\RECYCLER",        // XP / 2000
        L"\\RECYCLED",        // Win9x / FAT
    };
    for (size_t i = 0; i < sizeof(kBinFolders)/sizeof(kBinFolders[0]); ++i) {
        const wchar_t* folder = kBinFolders[i];
        size_t flen = wcslen(folder);
        // Case-insensitive scan
        size_t pathLen = ntPath.size();
        if (pathLen < flen) continue;
        for (size_t pos = 0; pos <= pathLen - flen; ++pos) {
            if (_wcsnicmp(ntPath.c_str() + pos, folder, flen) == 0) {
                // Must be at end OR followed by a backslash
                size_t after = pos + flen;
                if (after == pathLen || ntPath[after] == L'\\')
                    return true;
            }
        }
    }
    return false;
}

// Returns true if ntPath is covered by one of the user-defined [exclude]
// prefixes.  Uses the same case-insensitive prefix + component-boundary
// guard used throughout this file, so  \??\C:\Win  never matches
// \??\C:\Windows  even though it is a prefix string.
static bool IsExcludedPath(const std::wstring& ntPath) {
    for (size_t i = 0; i < g_FsExcludes.size(); ++i) {
        const std::wstring& excl = g_FsExcludes[i];
        if (StartsWithI(ntPath, excl) &&
            (ntPath.size() == excl.size() || ntPath[excl.size()] == L'\\'))
        {
            return true;
        }
    }
    return false;
}

// Apply FS redirections to an NT path.
// Priority order:
//   0. [exclude] rules -- path is returned unchanged (no redirection at all).
//   1. Explicit rules from --config INI (g_FsRedirects), checked in order.
//   2. FSDIR catch-all (g_FsDirNtBase) for any drive-letter path not yet
//      matched and not already located inside the virtual store itself.
static std::wstring ApplyFsRedirect(const std::wstring& ntPath) {
    if (!g_FsEnabled) return ntPath;

    // --- 0. Recycle Bin bypass ---
    // Never redirect paths inside $RECYCLE.BIN / RECYCLER / RECYCLED.
    // This lets the real Windows Recycle Bin handle deletions from the
    // virtualised app, avoiding virtual-store corruption and the deeply
    // nested paths produced when the $I metadata files contain paths
    // that are themselves subject to redirection.
    // Cross-volume rename edge cases (source in virtual store, destination
    // in the real Recycle Bin) are handled in Hook_NtSetInformationFile.
    if (IsRecycleBinPath(ntPath)) {
        VL_DBG(L"ApplyFsRedirect: recycle bin bypass -> %s", ntPath.c_str());
        return ntPath;
    }

    // --- 0b. User-defined [exclude] bypass ---
    // Paths listed in the [exclude] section of the --config INI are never
    // redirected: reads and writes pass straight through to the real file
    // system.  This check runs before both the config redirect rules and the
    // FSDIR catch-all so that e.g. virtualising C:\ while excluding
    // C:\Windows results in C:\Windows always hitting the real folder.
    if (IsExcludedPath(ntPath)) {
        VL_DBG(L"ApplyFsRedirect: excluded path bypass -> %s", ntPath.c_str());
        return ntPath;
    }

    // --- 1. Config-based rules (take precedence) ---
    // Both 'from' and 'to' are normalized in LoadFsConfig to have NO trailing
    // backslash (e.g. \??\c:  and  \??\d:\z1).  The suffix therefore either:
    //   - is empty    (ntPath == from, i.e. the root itself was opened), or
    //   - starts with '\'  (e.g. \ccc for \??\c:\ccc).
    // Concatenating to + suffix always produces a correctly separated path.
    // The component-boundary guard prevents \??\c:  matching  \??\c:_other.
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, from) &&
            (ntPath.size() == from.size() || ntPath[from.size()] == L'\\'))
        {
            return to + ntPath.substr(from.size());
        }
    }

    // --- 2. FSDIR catch-all: \??\X:[\rest]  ->  \??\<FsDirNtBase>\X[\rest] ---
    // Guard: must have an FSDIR configured, path must be a Win32 drive-letter NT
    // path (\??\X:\ or \??\X:), and the path must NOT already be inside the
    // virtual store (avoids infinite redirect loops).
    if (!g_FsDirNtBase.empty() &&
        ntPath.size() >= 6 &&
        StartsWithI(ntPath, L"\\??\\") &&
        iswalpha(ntPath[4]) && ntPath[5] == L':' &&
        (ntPath.size() == 6 || ntPath[6] == L'\\') &&
        !StartsWithI(ntPath, g_FsDirNtBase))
    {
        // \??\X:\rest  -> \??\<FsDirNtBase>\X\rest
        //   ntPath[4]      = drive letter (e.g. 'C')
        //   ntPath.substr(6) = \rest  (includes leading backslash, or empty)
        wchar_t driveStr[3] = { L'\\', towupper(ntPath[4]), L'\0' };
        std::wstring rest = (ntPath.size() > 6) ? ntPath.substr(6) : L"";
        return g_FsDirNtBase + driveStr + rest;
    }

    return ntPath;
}

// Reverse of ApplyFsRedirect: maps a physical (virtual-store) NT path back to
// the logical path the sandboxed app originally intended.  Used when reading
// reparse point data back out of NTFS so tools see the virtualized path.
static std::wstring ReverseApplyFsRedirect(const std::wstring& ntPath) {
    if (!g_FsEnabled) return ntPath;

    // --- 1. Reverse config-based rules ---
    // Mirror of the forward check: 'to' has no trailing backslash after
    // normalization, so the suffix is either empty or starts with '\'.
    // The component-boundary guard prevents partial-component false-matches.
    for (size_t i = 0; i < g_FsRedirects.size(); ++i) {
        const std::wstring& from = g_FsRedirects[i].first;
        const std::wstring& to   = g_FsRedirects[i].second;
        if (StartsWithI(ntPath, to) &&
            (ntPath.size() == to.size() || ntPath[to.size()] == L'\\'))
            return from + ntPath.substr(to.size());
    }

    // --- 2. Reverse FSDIR catch-all ---
    // Physical path: \??\<FsDirNtBase>\X\rest
    //   -> logical: \??\X:\rest
    if (!g_FsDirNtBase.empty() && StartsWithI(ntPath, g_FsDirNtBase)) {
        std::wstring tail = ntPath.substr(g_FsDirNtBase.size());
        // tail should be \X\rest  (backslash + single drive letter + rest)
        if (tail.size() >= 2 && tail[0] == L'\\' && iswalpha(tail[1])) {
            wchar_t drive = towupper(tail[1]);
            // tail.substr(2) is either empty or starts with backslash (\rest)
            std::wstring rest = (tail.size() > 2) ? tail.substr(2) : L"";
            return std::wstring(L"\\??\\") + drive + L':' + rest;
        }
    }

    return ntPath;
}

// Redirect a reparse-point path that may be in NT form (\??\...) or Win32
// form (C:\...).  Returns the path unchanged if no redirect applies.
// Used for both SubstituteName and PrintName in FSCTL_SET_REPARSE_POINT.
static std::wstring RedirectSymlinkPath(const std::wstring& path) {
    if (path.empty()) return path;
    std::wstring red = ApplyFsRedirect(path);
    if (red != path) return red;
    // Try as Win32 path (no \??\ prefix)
    std::wstring nt = Win32ToNtPath(path);
    if (nt != path) {
        red = ApplyFsRedirect(nt);
        if (red != nt) {
            // Strip the \??\ we added if the caller didn't have it
            if (StartsWithI(red, L"\\??\\") && !StartsWithI(path, L"\\??\\"))
                return red.substr(4);
            return red;
        }
    }
    return path;
}

// Inverse of RedirectSymlinkPath: physical path -> logical path.
// Used when intercepting FSCTL_GET_REPARSE_POINT output.
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

    // Anchor the directory-creation walk at the NT drive root (\??\X:) rather
    // than at virtRoot.  This guarantees that every intermediate folder is
    // created even when it does not yet exist on disk.  Without this, a
    // config rule like  c:\=d:\z1  produces virtRoot=\??\d:\z1, but
    // d:\z1 itself may be absent, so FILE_OPEN_IF on \??\d:\z1\subdir
    // immediately fails with STATUS_OBJECT_PATH_NOT_FOUND.
    //
    // We strip virtRoot back to just \??\X: (6 chars) so the walk starts
    // one level below the drive root and visits every folder on the way.
    // virtRoot is already normalised (no trailing backslash) by LoadFsConfig.
    std::wstring anchor = virtRoot;
    if (anchor.size() >= 6 &&
        StartsWithI(anchor, L"\\??\\") &&
        iswalpha(anchor[4]) && anchor[5] == L':')
    {
        anchor = anchor.substr(0, 6); // e.g. \??\d:
    }

    std::wstring remaining = dirPath.substr(anchor.size());
    std::wstring current   = anchor;
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

    // Build the virtual path of the entry and delegate to TombstoneExists —
    // the SAME function used by Hook_NtOpenFile's tombstone check.  This
    // guarantees the path construction is byte-for-byte identical, eliminating
    // any divergence between what NtOpenFile finds and what NtQueryDirectoryFile
    // finds.
    //
    // Previous implementation built the path separately with Fix A (strip
    // trailing '\'), but a subtle lifetime issue with the const-ref-to-ternary
    // could produce wrong results on some call paths.  Delegating to
    // TombstoneExists is simpler, correct, and consistent.
    //
    // Strip ALL trailing backslashes from virtDirPath so we always get exactly
    // one '\\' between the dir and the fileName component.
    std::wstring virtEntryPath = virtDirPath;
    while (!virtEntryPath.empty() && virtEntryPath.back() == L'\\')
        virtEntryPath.pop_back();
    if (virtEntryPath.empty()) return false;
    virtEntryPath += L'\\';
    virtEntryPath += fileName;

    VL_DBG(L"FileHasTombstoneInVirtDir: probing %s.vl_deleted", virtEntryPath.c_str());
    return TombstoneExists(virtEntryPath);
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
            skip = FileHasTombstoneInVirtDir(virtDirPath, name);
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

    // Track which INI section we are currently inside.
    // SEC_REDIRECT  -> lines are  source=destination  path pairs (legacy default).
    // SEC_EXCLUDE   -> lines are plain paths that must NEVER be redirected.
    // SEC_UNKNOWN   -> lines inside an unrecognised section are ignored.
    // SEC_NONE      -> lines before any section header are treated as SEC_REDIRECT
    //                  for backward compatibility with config files that omit the
    //                  [redirect] header entirely.
    enum Section { SEC_NONE, SEC_REDIRECT, SEC_EXCLUDE, SEC_UNKNOWN } section = SEC_NONE;

    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find(L'\n', pos);
        std::wstring line = (nl != std::wstring::npos)
                            ? content.substr(pos, nl - pos)
                            : content.substr(pos);
        pos = (nl != std::wstring::npos) ? nl + 1 : content.size();
        // Strip trailing CR and spaces, then leading spaces
        while (!line.empty() && (line[line.size()-1] == L'\r' || line[line.size()-1] == L' '))
            line.resize(line.size() - 1);
        while (!line.empty() && line[0] == L' ')
            line = line.substr(1);

        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;

        // ---- Section header ----
        if (line[0] == L'[') {
            // Extract the header name between [ and ] (or end of string).
            std::wstring hdr = line.substr(1);
            size_t close = hdr.find(L']');
            if (close != std::wstring::npos) hdr = hdr.substr(0, close);
            // Trim spaces inside the header
            while (!hdr.empty() && hdr[0]         == L' ') hdr = hdr.substr(1);
            while (!hdr.empty() && hdr[hdr.size()-1] == L' ') hdr.resize(hdr.size() - 1);

            if (_wcsicmp(hdr.c_str(), L"redirect") == 0)
                section = SEC_REDIRECT;
            else if (_wcsicmp(hdr.c_str(), L"exclude") == 0)
                section = SEC_EXCLUDE;
            else
                section = SEC_UNKNOWN;
            continue;
        }

        // ---- Lines inside [exclude] ----
        // Each non-blank, non-comment line is a single path to be excluded from
        // all virtualisation.  The path may be a Win32 path (C:\Windows) or an
        // NT path (\??\C:\Windows); both forms are accepted.
        if (section == SEC_EXCLUDE) {
            std::wstring excl = Win32ToNtPath(line);
            // Normalise: strip trailing backslashes (same rule as redirect 'from')
            while (excl.size() > 4 && excl.back() == L'\\') excl.resize(excl.size() - 1);
            if (!excl.empty()) {
                g_FsExcludes.push_back(excl);
                VL_DBG(L"LoadFsConfig: exclude  %s", excl.c_str());
            }
            continue;
        }

        // ---- Lines inside [redirect] (or before any section header) ----
        // Unrecognised sections are silently skipped.
        if (section == SEC_UNKNOWN) continue;

        // SEC_NONE / SEC_REDIRECT: expect  source=destination  pairs.
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring src = line.substr(0, eq);
        std::wstring dst = line.substr(eq + 1);
        while (!src.empty() && src[src.size()-1] == L' ') src.resize(src.size()-1);
        while (!dst.empty() && dst[0]   == L' ') dst = dst.substr(1);
        if (src.empty() || dst.empty()) continue;

        {
            std::wstring from = Win32ToNtPath(src);
            std::wstring to   = Win32ToNtPath(dst);
            // Normalize: strip trailing backslashes so separator insertion is
            // consistent regardless of whether the caller wrote
            //   "c:\=d:\z1"   or   "c:\=d:\z1\"
            // in the config file.  The loop preserves the mandatory \??\ prefix
            // (4 chars) so we never strip into the device namespace marker.
            while (from.size() > 4 && from.back() == L'\\') from.resize(from.size() - 1);
            while (to.size()   > 4 && to.back()   == L'\\') to.resize(to.size() - 1);
            g_FsRedirects.push_back(std::make_pair(from, to));
            VL_DBG(L"LoadFsConfig: redirect %s -> %s", from.c_str(), to.c_str());
        }
    }
}

static void LoadConfig() {
    wchar_t buf[2048] = {0};

    // ---- Read the debug flag FIRST so subsequent VL_DBG calls work ----
    if (GetEnvironmentVariableW(L"VLAUNCHER_DEBUG", buf, 2047) > 0)
        g_DebugEnabled = (_wcsicmp(buf, L"1")    == 0 ||
                          _wcsicmp(buf, L"true") == 0 ||
                          _wcsicmp(buf, L"yes")  == 0);

    // ---- Registry virtualisation (VIRTLAUNCHER_REG) ----
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_REG", buf, 2047) > 0) {
        g_VirtNtBase = buf;
        size_t sl = g_VirtNtBase.rfind(L'\\');
        if (sl != std::wstring::npos)
            g_RealNtBase = g_VirtNtBase.substr(0, sl);
        if (!g_VirtNtBase.empty() && !g_RealNtBase.empty())
            g_RegEnabled = true;
    }

    // ---- FS redirect config file (VIRTLAUNCHER_FS, from --config) ----
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FS", buf, 2047) > 0) {
        LoadFsConfig(buf);
        if (!g_FsRedirects.empty())
            g_FsEnabled = true;
    }

    // ---- FS virtual store folder (VIRTLAUNCHER_FSDIR, from --filesystem) ----
    // VirtLauncher.exe sets this to the absolute Win32 path of the virtual store
    // root.  We convert it to an NT path and use it as a catch-all redirect for
    // any drive-letter path not already handled by the --config rules.
    if (GetEnvironmentVariableW(L"VIRTLAUNCHER_FSDIR", buf, 2047) > 0 && buf[0]) {
        // Convert Win32 path to NT path  e.g.  D:\sandbox  ->  \??\D:\sandbox
        std::wstring fsdir = buf;
        if (fsdir.size() >= 2 && iswalpha(fsdir[0]) && fsdir[1] == L':')
            fsdir = L"\\??\\" + fsdir;
        // Strip trailing backslash (keep \??\ prefix safe)
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
    // If arch-specific paths not set, default both to the primary path
    if (!g_DllPathA32[0] && g_DllPathA[0])
        strncpy(g_DllPathA32, g_DllPathA, MAX_PATH - 1);
    if (!g_DllPathA64[0] && g_DllPathA[0])
        strncpy(g_DllPathA64, g_DllPathA, MAX_PATH - 1);

    VL_DBG(L"LoadConfig: DebugEnabled=%d", (int)g_DebugEnabled);
    VL_DBG(L"LoadConfig: RegEnabled=%d  VirtNtBase=%s",
           (int)g_RegEnabled, g_VirtNtBase.c_str());
    VL_DBG(L"LoadConfig:             RealNtBase=%s", g_RealNtBase.c_str());
    VL_DBG(L"LoadConfig: FsEnabled=%d  redirects=%u  excludes=%u  FsDirNtBase=%s",
           (int)g_FsEnabled, (unsigned)g_FsRedirects.size(),
           (unsigned)g_FsExcludes.size(), g_FsDirNtBase.c_str());
}

// ============================================================
// Registry enumeration helpers
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
// Shared registry open/create helper
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

    if (st == VL_STATUS_OBJECT_NOT_FOUND) {
        // Sentinel: not in our scope, call real
        return Real_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    }
    return st;
}

// ---- NtOpenKeyEx (Vista+) ----
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

// ---- NtOpenKeyTransacted (Vista+) ----
// We strip the transaction and open a non-transacted virtual key.
// This is safe for virtualisation: transactions on virtual keys add
// complexity without benefit since the virtual store is our own.
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

// ---- NtOpenKeyTransactedEx (Win8+) ----
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

// ---- NtCreateKey -- always creates in virtual store ----
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

// ---- NtCreateKeyTransacted (Vista+) ----
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

// ---- NtEnumerateKey -- merged view ----
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

    // Merge: virtual first, then real entries not shadowed by virtual
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

// ---- NtEnumerateValueKey -- merged view ----
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

// ---- NtQueryValueKey -- virtual takes priority ----
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

// ---- NtRenameKey -- rename in virtual store ----
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

// ---- NtReplaceKey -- complex (hive replacement); pass through with log ----
static NTSTATUS NTAPI Hook_NtReplaceKey(
    PVL_OBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, PVL_OBJECT_ATTRIBUTES OldFile)
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

// ---- NtLoadKey2 -- redirect TargetKey to virtual path ----
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

// ---- NtLoadKeyEx -- redirect TargetKey to virtual path ----
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

// ---- NtNotifyChangeKey -- forward to virtual handle ----
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

// ---- NtNotifyChangeMultipleKeys -- forward master handle to virtual ----
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

// ---- NtSetInformationKey -- redirect tracked handle to virtual hive ----
// Prevents key metadata changes (e.g. virtualization flags, last-write time
// via KeyWriteTimeInformation) from leaking to the real hive.
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

// ---- NtClose -- CRITICAL: only special-case tracked handles ----
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
// REPARSE POINT HOOK  (FSCTL_SET_REPARSE_POINT / FSCTL_GET_REPARSE_POINT)
// ============================================================
//
// Symbolic links and junctions embed their target path inside NTFS reparse
// point data written via NtFsControlFile(FSCTL_SET_REPARSE_POINT).  The
// kernel resolves reparse paths in kernel mode, completely bypassing any
// user-mode hook.  So if the embedded SubstituteName still refers to the
// logical (non-virtual) location (e.g. \??\C:\ccc\dir) the kernel will
// fail to follow the link because C:\ccc doesn't exist on real disk.
//
// FSCTL_GET_REPARSE_POINT is the mirror: tools reading a junction target
// (dir /AL, junction.exe, GetFinalPathNameByHandle) would otherwise see the
// physical virtual-store path (D:\vvv\dir) rather than the logical one the
// app expects (C:\ccc\dir).  We reverse-translate the output buffer so the
// caller always sees the logical view.
//
// FSCTL_DELETE_REPARSE_POINT needs no hook.  The file handle was already
// redirected to the virtual-store location by NtCreateFile/NtOpenFile, so
// the delete operates on the right object with no path translation needed.
//
// Reparse-buffer layout (from ntifs.h / Windows Internals):
//
//   [HEADER 8 bytes]
//     ULONG  ReparseTag
//     USHORT ReparseDataLength   (byte count of everything below)
//     USHORT Reserved
//
//   [SYMLINK union -- IO_REPARSE_TAG_SYMLINK 0xA000000C]
//     USHORT SubstituteNameOffset  } byte offsets into PathBuffer
//     USHORT SubstituteNameLength  }
//     USHORT PrintNameOffset       }
//     USHORT PrintNameLength       }
//     ULONG  Flags                 (VL_SYMLINK_FLAG_RELATIVE if relative)
//     WCHAR  PathBuffer[1]         (SubstituteName then PrintName, packed,
//                                   NO null separator between them)
//
//   [MOUNTPOINT union -- IO_REPARSE_TAG_MOUNT_POINT 0xA0000003 (junctions)]
//     USHORT SubstituteNameOffset  }
//     USHORT SubstituteNameLength  }
//     USHORT PrintNameOffset       }
//     USHORT PrintNameLength       }
//     WCHAR  PathBuffer[1]         (SubstituteName, L'\0', PrintName, L'\0')
//                                  NTFS validates PathBuffer[SubstLen/2]==L'\0'
//
// CRITICAL DIFFERENCE between symlinks and junctions:
//   Symlinks:  PrintNameOffset == SubstituteNameLength  (packed, NO null gap)
//   Junctions: PrintNameOffset == SubstituteNameLength + 2  (null separator)
//              and NTFS VALIDATES the null separator before accepting the buffer.
//              A rebuilt junction buffer without the null separator returns
//              STATUS_IO_REPARSE_DATA_INVALID even if all lengths are in-bounds.

#define VL_FSCTL_SET_REPARSE_POINT  0x000900A4UL
#define VL_FSCTL_GET_REPARSE_POINT  0x000900A8UL
#define VL_IO_REPARSE_TAG_MOUNT_POINT 0xA0000003UL
#define VL_IO_REPARSE_TAG_SYMLINK     0xA000000CUL
#define VL_SYMLINK_FLAG_RELATIVE      0x00000001UL

#define VL_REPARSE_HDR_SIZE        8u   // ReparseTag(4) + DataLen(2) + Reserved(2)
#define VL_SYMLINK_FIELDS_SIZE    12u   // SubstOff(2)+SubstLen(2)+PrtOff(2)+PrtLen(2)+Flags(4)
#define VL_MOUNTPOINT_FIELDS_SIZE  8u   // SubstOff(2)+SubstLen(2)+PrtOff(2)+PrtLen(2)

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

    // ================================================================
    // FSCTL_GET_REPARSE_POINT -- reverse-translate output buffer so
    // callers see the logical path, not the physical virtual-store path.
    // ================================================================
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
            // Patch in-place only when reverse-translated strings fit the existing slots.
            // (If they are longer than the originals the buffer would overflow -- skip.)
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

    // ================================================================
    // FSCTL_SET_REPARSE_POINT -- redirect embedded target paths so the
    // kernel resolves the link to the virtual store, not the real location.
    // ================================================================
    if (FsControlCode != VL_FSCTL_SET_REPARSE_POINT ||
        !InputBuffer || InputBufferLength < VL_REPARSE_HDR_SIZE)
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     InputBuffer, InputBufferLength,
                                     OutputBuffer, OutputBufferLength);

    VL_REPARSE_DATA_BUFFER* rdb = (VL_REPARSE_DATA_BUFFER*)InputBuffer;

    // ---- Symbolic link ----
    if (rdb->ReparseTag == VL_IO_REPARSE_TAG_SYMLINK) {
        // Relative symlinks are relative to the link's own directory;
        // prefix-based redirection does not apply to them.
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

        // Rebuild buffer.
        // Symlink PathBuffer layout: [SubstituteName][PrintName]  (no null separator)
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

    // ---- Junction / mount point ----
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

        // Rebuild buffer.
        // Junction PathBuffer layout (mandatory, NTFS validates this):
        //   [SubstituteName (newSubBytes)]
        //   [L'\0' null separator (sizeof WCHAR = 2 bytes)]   <- NTFS checks this byte
        //   [PrintName (newPrtBytes)]
        //   [L'\0' null terminator (sizeof WCHAR = 2 bytes)]
        //
        // PrintNameOffset MUST be SubstituteNameLength + sizeof(WCHAR).
        // If it equals SubstituteNameLength (no null gap), NTFS finds a non-zero
        // WCHAR at PathBuffer[SubstituteNameLength/2] and returns
        // STATUS_IO_REPARSE_DATA_INVALID, causing the junction creation to fail.
        USHORT newSubBytes  = (USHORT)(redSubst.size() * sizeof(WCHAR));
        USHORT newPrtBytes  = (USHORT)(redPrint.size() * sizeof(WCHAR));
        USHORT newPrtOff    = newSubBytes + (USHORT)sizeof(WCHAR);  // after null separator
        USHORT newDataLen   = (USHORT)(VL_MOUNTPOINT_FIELDS_SIZE
                                       + newPrtOff + newPrtBytes
                                       + (USHORT)sizeof(WCHAR));    // trailing null
        ULONG  newBufSize   = VL_REPARSE_HDR_SIZE + newDataLen;
        std::vector<BYTE> newBuf(newBufSize, 0);  // zero-init: nulls already in place
        VL_REPARSE_DATA_BUFFER* n = (VL_REPARSE_DATA_BUFFER*)&newBuf[0];
        n->ReparseTag                      = rdb->ReparseTag;
        n->ReparseDataLength               = newDataLen;
        n->Reserved                        = 0;
        n->MountPoint.SubstituteNameOffset = 0;
        n->MountPoint.SubstituteNameLength = newSubBytes;
        n->MountPoint.PrintNameOffset      = newPrtOff;  // SubstLen + 2 (past null separator)
        n->MountPoint.PrintNameLength      = newPrtBytes;
        memcpy(n->MountPoint.PathBuffer, redSubst.c_str(), newSubBytes);
        // PathBuffer[newSubBytes/2] is already L'\0' (buffer is zero-initialized)
        memcpy((BYTE*)n->MountPoint.PathBuffer + newPrtOff, redPrint.c_str(), newPrtBytes);
        // PathBuffer at (newPrtOff+newPrtBytes)/2 is already L'\0' (trailing null)

        VL_DBG(L"Hook_NtFsControlFile SET JUNCTION: rebuilt buffer %u->%u bytes"
               L" (subst=%u prtOff=%u prt=%u)",
               InputBufferLength, newBufSize, newSubBytes, newPrtOff, newPrtBytes);
        return Real_NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                                     IoStatusBlock, FsControlCode,
                                     &newBuf[0], newBufSize,
                                     OutputBuffer, OutputBufferLength);
    }

    // Unknown reparse tag -- pass through untouched (covers FSCTL_DELETE_REPARSE_POINT
    // which uses a different FSCTL code and reaches the pass-through above this block,
    // plus any third-party reparse tags).
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

    if (!redirected)
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                                  IoStatusBlock, AllocationSize, FileAttributes,
                                  ShareAccess, CreateDisposition, CreateOptions,
                                  EaBuffer, EaLength);

    bool isDir = (CreateOptions & FILE_DIRECTORY_FILE) != 0;
    bool isWrite = HasWriteAccess(DesiredAccess);

    VL_DBG(L"Hook_NtCreateFile: %s -> %s disp=%u acc=0x%08X dir=%d",
           ntPath.c_str(), redPath.c_str(), CreateDisposition, DesiredAccess, (int)isDir);

    // ----------------------------------------------------------------
    // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
    // Build a clean OA that always points to the REAL filesystem.
    // This uses ntPath (the logical path, e.g. \??\C:\dir\file.txt)
    // with RootDirectory=NULL so Real_Nt*File never follows a
    // virtual-store handle that may be sitting in ObjectAttributes.
    // ----------------------------------------------------------------
    VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
    VL_OBJECT_ATTRIBUTES realOa;  MakeOA(&realOa, &realName);

    // ----------------------------------------------------------------
    // WRITE-ONLY / CREATE dispositions
    //   FILE_CREATE, FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF
    //
    // These never read existing content from real so we:
    //   1. Ensure the virtual directory tree exists.
    //   2. Remove any stale tombstone (file is being re-created).
    //   3. Redirect entirely to virtual.
    //
    // Special case: FILE_OVERWRITE(_IF) requires the file to already
    // exist.  If the virtual store doesn't have it yet (only real does),
    // promote the disposition to FILE_SUPERSEDE -- the app is about to
    // replace the content anyway, so a fresh empty virtual file is fine.
    // ----------------------------------------------------------------
    if (CreateDisposition == FILE_CREATE    ||
        CreateDisposition == FILE_SUPERSEDE ||
        CreateDisposition == FILE_OVERWRITE ||
        CreateDisposition == FILE_OVERWRITE_IF)
    {
        // ---- Sandboxie-style: strict merged namespace collision for FILE_CREATE ----
        //
        // FILE_CREATE means "create only if the name is free".  Under a merged
        // namespace the name is NOT free if the file exists in the real store
        // (unless a tombstone is hiding it, which means it was deleted inside the
        // sandbox and really is gone from the merged view).
        //
        // Without this check the virtual store is empty, so the kernel happily
        // creates the file and returns STATUS_SUCCESS.  Explorer never sees a
        // collision, so:
        //   • Copying aaa.txt inside the same folder produces a second aaa.txt
        //     (silently shadowing the real one) instead of "aaa - Copy.txt".
        //   • Lock-file logic (SQLite, Git, etc.) can be fooled by multiple
        //     sandboxed processes all succeeding on FILE_CREATE of the same lock.
        //
        // Returning STATUS_OBJECT_NAME_COLLISION here is exactly what Sandboxie
        // does and what the kernel itself would return for a real collision.
        // Explorer uses that status code to decide to append " - Copy"; cmd.exe
        // uses it to trigger the "Overwrite? (Yes/No/All)" prompt for move.
        if (CreateDisposition == FILE_CREATE) {
            // Only probe the real store when there is no tombstone (tombstone
            // means the file was explicitly deleted inside the sandbox, so the
            // merged namespace correctly considers it absent).
            // Applies to both files AND directories: "mkdir cc" should fail with
            // COLLISION when cc already exists in the real store, just like Sandboxie.
            if (!TombstoneExists(redPath)) {
                BYTE realCollBuf[48] = {0};
                if (!IsFsNotFound(Real_NtQueryAttributesFile(&realOa, realCollBuf))) {
                    VL_DBG(L"Hook_NtCreateFile: FILE_CREATE, entry exists in real merged NS -> COLLISION");
                    return VL_STATUS_OBJECT_NAME_COLLISION;
                }
            }
        }

        EnsureVirtualFsPath(redPath);
        DeleteTombstoneIfPresent(redPath);

        ULONG dispToUse = CreateDisposition;
        if ((CreateDisposition == FILE_OVERWRITE ||
             CreateDisposition == FILE_OVERWRITE_IF) && !isDir) {
            // Probe: does the virtual store already have this file?
            VL_UNICODE_STRING probe; MakeUStr(&probe, redPath);
            VL_OBJECT_ATTRIBUTES probeOa; MakeOA(&probeOa, &probe);
            BYTE dummy[48] = {0};
            if (IsFsNotFound(Real_NtQueryAttributesFile(&probeOa, dummy)))
                dispToUse = FILE_SUPERSEDE;  // create fresh; app overwrites anyway
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
                VL_IO_STATUS_BLOCK iosb;
                Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
                if (e.hReal) e.isDir = true;
            } else {
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
        EnsureVirtualFsPath(redPath);
        DeleteTombstoneIfPresent(redPath);
    }

    // ----------------------------------------------------------------
    // FILE_OPEN / FILE_OPEN_IF -- CoW read / write semantics
    //
    //   1. Try virtual first.
    //   2. On success -> return (virtual file served).
    //   3. On non-"not found" error -> propagate (e.g. ACCESS_DENIED).
    //   4. On "not found":
    //      a. If tombstone exists -> deleted in sandbox -> NOT_FOUND.
    //      b. If real also doesn't have it -> original not-found.
    //      c. Read-only access -> serve real directly (zero sandbox change).
    //      d. Write access on dir -> EnsureVirtualFsPath + create virtual dir.
    //      e. Write access on file -> copy real->virtual, then open virtual.
    // ----------------------------------------------------------------
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
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            if (e.hReal) e.isDir = true;
        } else {
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
    bool tombstoned = TombstoneExists(redPath);
    if (tombstoned) {
        VL_DBG(L"Hook_NtCreateFile: tombstone -> deleted in sandbox, NOT_FOUND");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Does the real file exist?
    // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
    // FIX: use realOa (built from ntPath, RootDirectory=NULL) instead of
    // ObjectAttributes, which may carry a virtual-store RootDirectory handle
    // that would make Real_NtQueryAttributesFile look inside the virtual store.
    BYTE basicBuf[48] = {0};
    NTSTATUS realCheck = Real_NtQueryAttributesFile(&realOa, basicBuf);
    if (IsFsNotFound(realCheck)) {
        VL_DBG(L"Hook_NtCreateFile: real also not found, returning 0x%08X", (ULONG)st);
        return st;
    }

    // Upgrade isDir if the real entity has FILE_ATTRIBUTE_DIRECTORY set.
    // This is necessary because callers (e.g. cmd.exe doing a rename/move)
    // may open a directory WITHOUT FILE_DIRECTORY_FILE in CreateOptions, so
    // isDir would be false even though the target is a directory.  Without
    // this fix we would try CopyRealFileToVirtual on a directory, which
    // fails with STATUS_FILE_IS_A_DIRECTORY -> caller sees "file not found".
    // FILE_BASIC_INFORMATION layout: CreationTime(8)+LastAccessTime(8)+
    //   LastWriteTime(8)+ChangeTime(8)+FileAttributes(4) -> offset 32.
    {
        ULONG realAttrs = *(ULONG*)(basicBuf + 32);
        if (realAttrs & FILE_ATTRIBUTE_DIRECTORY) {
            isDir = true;
            VL_DBG(L"Hook_NtCreateFile: upgraded isDir=true from real FILE_ATTRIBUTE_DIRECTORY");
        }
    }

    if (!isWrite) {
        // Read-only CoW: serve the real file directly; sandbox state unchanged.
        // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
        // FIX: use realOa (RootDirectory=NULL, full ntPath) instead of
        // ObjectAttributes so we open the REAL file, not a path relative to
        // the virtual-store handle that may be in ObjectAttributes->RootDirectory.
        VL_DBG(L"Hook_NtCreateFile: read-only CoW fallback to real");
        NTSTATUS stReal = Real_NtCreateFile(FileHandle, DesiredAccess, &realOa,
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

    // Write CoW on directory: create the virtual directory and open it.
    if (isDir) {
        EnsureVirtualFsPath(redPath);
        // When isDir was upgraded from FILE_ATTRIBUTE_DIRECTORY (caller didn't
        // pass FILE_DIRECTORY_FILE in CreateOptions), force the directory flags
        // so the kernel creates/opens a directory, not a regular file.
        ULONG dirCreateOptions = CreateOptions
                                 | FILE_DIRECTORY_FILE
                                 | FILE_SYNCHRONOUS_IO_NONALERT;
        ULONG dirAccess        = DesiredAccess | SYNCHRONIZE;
        st = Real_NtCreateFile(FileHandle, dirAccess, &newOa, IoStatusBlock,
                                AllocationSize, FileAttributes | FILE_ATTRIBUTE_DIRECTORY,
                                ShareAccess, CreateDisposition,
                                dirCreateOptions, EaBuffer, EaLength);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = true;
            e.isRealOnly = false;
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    } else {
        // Write CoW on file: copy real -> virtual, then open the virtual copy.
        VL_DBG(L"Hook_NtCreateFile: write CoW, copying real->virtual");
        bool copied = CopyRealFileToVirtual(ntPath, redPath);
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

// ---- NtOpenFile ----
// NtOpenFile always has FILE_OPEN semantics.
// CoW read/write logic mirrors Hook_NtCreateFile with CreateDisposition==FILE_OPEN.
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

    // ----------------------------------------------------------------
    // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
    // Build a clean OA that always points to the REAL filesystem.
    // This uses ntPath (the logical path, e.g. \??\C:\dir\file.txt)
    // with RootDirectory=NULL so Real_Nt*File never follows a
    // virtual-store handle that may be sitting in ObjectAttributes.
    // ----------------------------------------------------------------
    VL_UNICODE_STRING realName; MakeUStr(&realName, ntPath);
    VL_OBJECT_ATTRIBUTES realOa;  MakeOA(&realOa, &realName);

    // Try virtual first.
    NTSTATUS st = Real_NtOpenFile(FileHandle, DesiredAccess, &newOa,
                                   IoStatusBlock, ShareAccess, OpenOptions);
    if (NT_SUCCESS(st)) {
        VirtFileEntry e;
        e.hVirt = *FileHandle;
        e.logPath = ntPath;
        e.isDir = isDir;
        e.isRealOnly = false;
        if (!isDir) {
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            if (e.hReal) e.isDir = true;
        } else {
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
        TrackFileHandle(*FileHandle, e);
        return st;
    }

    if (!IsFsNotFound(st)) return st;

    // Tombstone check.
    bool tombstoned = TombstoneExists(redPath);
    if (tombstoned) {
        VL_DBG(L"Hook_NtOpenFile: tombstone -> deleted in sandbox, NOT_FOUND");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Does the real file exist?
    // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
    // FIX: use realOa (built from ntPath, RootDirectory=NULL) instead of
    // ObjectAttributes, which may carry a virtual-store RootDirectory handle
    // that would make Real_NtQueryAttributesFile look inside the virtual store.
    BYTE basicBuf[48] = {0};
    if (IsFsNotFound(Real_NtQueryAttributesFile(&realOa, basicBuf))) {
        VL_DBG(L"Hook_NtOpenFile: real also not found, returning 0x%08X", (ULONG)st);
        return st;
    }

    // Upgrade isDir if the real entity has FILE_ATTRIBUTE_DIRECTORY set.
    // cmd.exe and other callers open a directory for rename/move WITHOUT
    // FILE_DIRECTORY_FILE in OpenOptions, so isDir starts as false.
    // Without this upgrade the hook falls into CopyRealFileToVirtual on a
    // directory, which fails with STATUS_FILE_IS_A_DIRECTORY (0xC00000BA)
    // and the caller sees "The system cannot find the file specified".
    // FILE_BASIC_INFORMATION layout (NtQueryAttributesFile output):
    //   CreationTime(8)+LastAccessTime(8)+LastWriteTime(8)+ChangeTime(8)
    //   +FileAttributes(4)  -> FileAttributes is at byte offset 32.
    {
        ULONG realAttrs = *(ULONG*)(basicBuf + 32);
        if (realAttrs & FILE_ATTRIBUTE_DIRECTORY) {
            isDir = true;
            VL_DBG(L"Hook_NtOpenFile: upgraded isDir=true from real FILE_ATTRIBUTE_DIRECTORY");
        }
    }

    if (!isWrite) {
        // Read-only CoW: serve real directly; sandbox unchanged.
        // Fix BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
        // FIX: use realOa (RootDirectory=NULL, full ntPath) instead of
        // ObjectAttributes so we open the REAL file, not a path relative to
        // the virtual-store handle that may be in ObjectAttributes->RootDirectory.
        VL_DBG(L"Hook_NtOpenFile: read-only CoW fallback to real");
        NTSTATUS stReal = Real_NtOpenFile(FileHandle, DesiredAccess, &realOa,
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

    // Write CoW on directory.
    if (isDir) {
        // EnsureVirtualFsPath creates the PARENT directory chain but NOT the
        // target directory itself (it treats the leaf as a file name).
        // We must explicitly create the virtual directory before opening it,
        // because NtOpenFile can only OPEN — it cannot create.
        //
        // Two-step:
        //   1. NtCreateFile(FILE_OPEN_IF | FILE_DIRECTORY_FILE) creates the
        //      virtual directory if absent, or opens it if already there.
        //      We immediately close this handle; its only job is to materialise
        //      the directory in the virtual store.
        //   2. NtOpenFile with the caller's original DesiredAccess + OpenOptions
        //      (plus FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT so the
        //      kernel allows opening a directory) gives the caller their handle.
        EnsureVirtualFsPath(redPath);
        {
            HANDLE hMkdir = NULL;
            VL_IO_STATUS_BLOCK iosbMkdir = {};
            VL_UNICODE_STRING virtDirUs; MakeUStr(&virtDirUs, redPath);
            VL_OBJECT_ATTRIBUTES virtDirOa; MakeOA(&virtDirOa, &virtDirUs);
            Real_NtCreateFile(&hMkdir,
                               FILE_LIST_DIRECTORY | SYNCHRONIZE,
                               &virtDirOa, &iosbMkdir, NULL,
                               FILE_ATTRIBUTE_DIRECTORY,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN_IF,
                               FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                               NULL, 0);
            if (hMkdir) Real_NtClose(hMkdir);
        }
        // Open the now-materialised virtual directory for the caller.
        // Always include FILE_DIRECTORY_FILE + FILE_SYNCHRONOUS_IO_NONALERT so
        // the kernel accepts a directory handle regardless of what the caller
        // passed (cmd.exe omits FILE_DIRECTORY_FILE when opening for rename).
        ULONG dirOpenOptions = OpenOptions
                               | FILE_DIRECTORY_FILE
                               | FILE_SYNCHRONOUS_IO_NONALERT;
        ULONG dirAccess      = DesiredAccess | SYNCHRONIZE;
        st = Real_NtOpenFile(FileHandle, dirAccess, &newOa,
                              IoStatusBlock, ShareAccess, dirOpenOptions);
        VL_DBG(L"Hook_NtOpenFile: write CoW dir, virtual open st=0x%08X", (ULONG)st);
        if (NT_SUCCESS(st)) {
            VirtFileEntry e;
            e.hVirt = *FileHandle;
            e.logPath = ntPath;
            e.isDir = true;
            e.isRealOnly = false;
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&e.hReal, FILE_LIST_DIRECTORY | SYNCHRONIZE, &realOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
            TrackFileHandle(*FileHandle, e);
        }
        return st;
    } else {
        // Write CoW on file: copy real -> virtual then open virtual.
        VL_DBG(L"Hook_NtOpenFile: write CoW, copying real->virtual");
        bool copied = CopyRealFileToVirtual(ntPath, redPath);
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

// ---- EnsureVirtualNamespaceDir ----
// DIRECTORY_ALL_ACCESS is 0x000F000F in winnt.h; provide a fallback for
// minimal-header build environments.
#ifndef DIRECTORY_ALL_ACCESS
#  define DIRECTORY_ALL_ACCESS 0x000F000F
#endif
// Recursively ensures every ancestor component of virtPath exists in the
// virtual Object Manager namespace by calling Real_NtCreateDirectoryObject on
// each segment.  This mirrors EnsureVirtualFsPath but operates on OM namespace
// directories (in-memory kernel objects), not filesystem directories.
// Failures on intermediate segments are silently ignored -- the segment may be
// a real OM directory that requires elevated privilege to create; if it is
// genuinely missing the final NtCreateDirectoryObject call will surface the
// real error.
static void EnsureVirtualNamespaceDir(const std::wstring& virtPath) {
    if (!Real_NtCreateDirectoryObject) return;
    size_t lastSlash = virtPath.rfind(L'\\');
    if (lastSlash == std::wstring::npos || lastSlash == 0) return;

    std::wstring dirPath = virtPath.substr(0, lastSlash);
    // Recurse to ensure the grandparent exists first.
    EnsureVirtualNamespaceDir(dirPath);

    VL_UNICODE_STRING us; MakeUStr(&us, dirPath);
    VL_OBJECT_ATTRIBUTES oa; MakeOA(&oa, &us);
    HANDLE h = NULL;
    NTSTATUS st = Real_NtCreateDirectoryObject(&h, DIRECTORY_ALL_ACCESS, &oa);
    if (NT_SUCCESS(st) && h) Real_NtClose(h);
}

// ---- NtCreateDirectoryObject ----
// Object-namespace directories (not filesystem directories).
// Create always goes to virtual; namespace dirs are not on disk so no
// tombstone or CoW copy is needed.  We ensure virtual parent segments
// exist before the final create to avoid STATUS_OBJECT_PATH_NOT_FOUND.
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
    EnsureVirtualNamespaceDir(redPath);
    return Real_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess, &newOa);
}

// ---- NtOpenDirectoryObject ----
// Object-namespace directory open: try virtual, fall back to real on not-found.
// No tombstone / CoW copy needed (namespace dirs are not on disk).
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

    // Try virtual namespace first.
    NTSTATUS st = Real_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, &newOa);
    if (NT_SUCCESS(st)) return st;

    // If the virtual counterpart simply doesn't exist yet, fall back to the
    // real object namespace so the sandboxed app can still open real objects
    // (e.g. mutexes, events) that live only in the real namespace.
    if (IsFsNotFound(st))
        return Real_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);

    return st;
}

// ---- NtCreateMailslotFile ----
// Mailslots are IPC objects, not stored on disk.
// Redirect name to virtual namespace; no CoW needed.
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

// ---- NtCreateNamedPipeFile ----
// Named pipes are IPC objects, not stored on disk.
// Redirect name to virtual namespace; no CoW needed.
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

// ---- NtDeleteFile ----
// CoW delete semantics:
//   1. Always try to delete from virtual first.
//   2a. If virtual delete succeeded AND real still exists at the same
//       logical path: create a tombstone so the real file does not
//       reappear on the next read.
//   2b. If virtual had nothing but real exists: EnsureVirtualFsPath then
//       create tombstone to mask the real file, return success.
//   3. The real file is NEVER deleted.
static NTSTATUS NTAPI Hook_NtDeleteFile(PVL_OBJECT_ATTRIBUTES ObjectAttributes)
{
    std::wstring ntPath, redPath;
    VL_UNICODE_STRING newName; VL_OBJECT_ATTRIBUTES newOa;
    bool redirected = RedirectFileOA(ObjectAttributes, newName, newOa, ntPath, redPath);
    VL_DBG(L"Hook_NtDeleteFile: %s%s",
           ntPath.c_str(), redirected ? L" [REDIRECT]" : L"");
    if (!redirected)
        return Real_NtDeleteFile(ObjectAttributes);

    // Build a clean OA pointing at the real (logical) path with no root-directory
    // handle.  ObjectAttributes may carry a RootDirectory that points into the
    // virtual store; using it for a "does the real file exist?" probe would make
    // Real_NtQueryAttributesFile look inside the virtual store instead of the
    // real filesystem.  ntPath is already the fully-resolved absolute logical
    // path produced by GetFullNtPath + Win32ToNtPath, so this is always safe.
    VL_UNICODE_STRING realUs; MakeUStr(&realUs, ntPath);
    VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realUs);

    // Try delete virtual
    NTSTATUS st = Real_NtDeleteFile(&newOa);
    if (NT_SUCCESS(st)) {
        // Virtual file deleted.  If real still exists at the same logical path,
        // create a tombstone so it doesn't reappear on the next read or query.
        BYTE basicBuf[48] = {0};
        if (!IsFsNotFound(Real_NtQueryAttributesFile(&realOa, basicBuf))) {
            CreateTombstone(redPath);
        } else {
            DeleteTombstoneIfPresent(redPath);
        }
        return st;
    }

    if (!IsFsNotFound(st)) return st;  // unexpected error (e.g. sharing violation)

    // Virtual didn't exist. Does real exist?
    BYTE basicBuf[48] = {0};
    if (IsFsNotFound(Real_NtQueryAttributesFile(&realOa, basicBuf))) {
        return st; // neither has it
    }

    // Real exists, virtual doesn't -> create tombstone to mask real
    VL_DBG(L"Hook_NtDeleteFile: real-only file, creating tombstone");
    EnsureVirtualFsPath(redPath);
    CreateTombstone(redPath);

    // Return success: as far as the sandboxed app is concerned the file is gone.
    return VL_STATUS_SUCCESS;
}

// ---- NtQueryAttributesFile ----
// Used by GetFileAttributesW internally (returns FILE_BASIC_INFORMATION).
// CoW read: try virtual, tombstone check, then fall back to real.
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

    if (TombstoneExists(redPath)) {
        VL_DBG(L"Hook_NtQueryAttributesFile: tombstone -> NOT_FOUND");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // CoW read fallback to real.
    VL_DBG(L"Hook_NtQueryAttributesFile: virtual not found, fallback to real");
    return Real_NtQueryAttributesFile(ObjectAttributes, FileInformation);
}

// ---- NtQueryFullAttributesFile ----
// Returns FILE_NETWORK_OPEN_INFORMATION.
// CoW read: same semantics as NtQueryAttributesFile.
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

    if (TombstoneExists(redPath)) {
        VL_DBG(L"Hook_NtQueryFullAttributesFile: tombstone -> NOT_FOUND");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    VL_DBG(L"Hook_NtQueryFullAttributesFile: virtual not found, fallback to real");
    return Real_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
}

// ---- NtQueryInformationByName (Win10+) ----
// Queries file information by name without opening a handle.
// CoW read: same semantics -- virtual first, tombstone check, real fallback.
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

    if (TombstoneExists(redPath)) {
        VL_DBG(L"Hook_NtQueryInformationByName: tombstone -> NOT_FOUND");
        return VL_STATUS_OBJECT_NAME_NOT_FOUND;
    }

    VL_DBG(L"Hook_NtQueryInformationByName: virtual not found, fallback to real");
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
    // Bug 2 fix: removed || e.isRealOnly -- isRealOnly dirs now enter the
    // body so we can attempt an on-demand upgrade to merged view.
    if (!g_FsEnabled || !GetFileEntry(FileHandle, e) || !e.isDir) {
        return Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                          IoStatusBlock, FileInformation, Length,
                                          FileInformationClass, ReturnSingleEntry,
                                          FileName, RestartScan);
    }

    // FIX 1: Cache the search pattern immediately, BEFORE any early returns
    if (RestartScan || !e.hasCachedFileName) {
        e.cachedFileName    = FileName ? FromUStr(FileName) : L"";
        e.hasCachedFileName = true;
        UpdateFileEntry(FileHandle, e);
    }

    // ----------------------------------------------------------------
    // Bug 2 fix: isRealOnly directory upgrade.
    //
    // When this handle was opened, the virtual store had no counterpart
    // directory so we set isRealOnly=true and handed the caller the real
    // handle. Since then a write may have created VIRTL\...\<dir>\.
    // Try to open a virtual handle now; if it succeeds, upgrade the
    // entry to a full merged pair and reset enumeration state.
    // If it still fails, fall back to real-only pass-through.
    // ----------------------------------------------------------------
    if (e.isRealOnly) {
        std::wstring virtPath = ApplyFsRedirect(e.logPath);
        HANDLE hNewVirt = NULL;
        if (!virtPath.empty()) {
            VL_UNICODE_STRING virtName; MakeUStr(&virtName, virtPath);
            VL_OBJECT_ATTRIBUTES virtOa;  MakeOA(&virtOa, &virtName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&hNewVirt, FILE_LIST_DIRECTORY | SYNCHRONIZE,
                            &virtOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
        if (!hNewVirt) {
            // Virtual dir still doesn't exist — pass through to real, but still
            // filter tombstoned entries so deleted-in-sandbox files don't appear.
            VL_DBG(L"Hook_NtQueryDirectoryFile: isRealOnly dir, tombstone-filtered pass-through: %s",
                   e.logPath.c_str());
            const std::wstring virtDirPathRT = ApplyFsRedirect(e.logPath);
            BOOLEAN restart = RestartScan;
            while (true) {
                NTSTATUS st = Real_NtQueryDirectoryFile(
                    FileHandle, Event, ApcRoutine, ApcContext,
                    IoStatusBlock, FileInformation, Length,
                    FileInformationClass, ReturnSingleEntry,
                    FileName, restart);
                restart = FALSE;
                if (!NT_SUCCESS(st)) return st;
                if (!virtDirPathRT.empty()) {
                    if (ReturnSingleEntry) {
                        std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                        if (!name.empty() && IsTombstoneName(name)) continue;
                        if (!name.empty() && FileHasTombstoneInVirtDir(virtDirPathRT, name))
                            continue;
                    } else {
                        FilterDirBuffer(FileInformation, Length, FileInformationClass,
                                        nullptr, virtDirPathRT);
                    }
                }
                return st;
            }
        }
        // Virtual dir now exists - upgrade to merged view.
        // FileHandle IS the real handle (hVirt==hReal==FileHandle for isRealOnly).
        // hVirt becomes the new virtual handle; hReal stays as FileHandle.
        VL_DBG(L"Hook_NtQueryDirectoryFile: upgrading isRealOnly dir to merged view: %s",
               e.logPath.c_str());
        e.hVirt              = hNewVirt;
        e.hReal              = FileHandle;
        e.isRealOnly         = false;
        // The virtual dir was just created by a CoW triggered during this
        // enumeration session (e.g. by opening an entry for rename/delete).
        // Its only content is CoW copies of files the real side already yielded.
        // Setting virtEnumDone=true skips the virtual side entirely so those
        // files are not presented a second time, which would cause cmd.exe to
        // attempt (and fail) the same rename twice, printing the error twice.
        e.virtEnumDone       = true;
        e.virtRestartPending = false;
        // DO NOT reset e.realRestartPending or clear e.virtNames here —
        // preserve the real handle's enumeration position across the upgrade.
        UpdateFileEntry(FileHandle, e);
    }

    // On-demand open of real shadow handle if missing (non-isRealOnly path).
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
        // Evaluate restart requirement based on new flag
        BOOLEAN virtRestart = e.virtRestartPending ? TRUE : RestartScan;
        e.virtRestartPending = false; 
        BOOLEAN localFileName_consumed   = FALSE;

        while (!e.virtEnumDone) {
            PVL_UNICODE_STRING pVirtFn = localFileName_consumed ? NULL : FileName;
            VL_UNICODE_STRING virtFnUs;
            // Provide cached pattern if this is a newly upgraded virtual handle
            if (virtRestart && !pVirtFn && e.hasCachedFileName && !e.cachedFileName.empty()) {
                MakeUStr(&virtFnUs, e.cachedFileName);
                pVirtFn = &virtFnUs;
            }

            NTSTATUS st = Real_NtQueryDirectoryFile(
                e.hVirt, Event, ApcRoutine, ApcContext,
                IoStatusBlock, FileInformation, Length,
                FileInformationClass, FALSE,
                pVirtFn, virtRestart);
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
            // FIX: also treat STATUS_NO_SUCH_FILE as "nothing in virtual" so we
            // fall through to the real-side phase.  An empty virtual directory
            // returns NO_SUCH_FILE (not NO_MORE_FILES) when a FileName filter is
            // active and nothing matches — without this the real store is skipped.
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES ||
                st == VL_STATUS_NO_SUCH_FILE) {
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
    BOOLEAN restartVirt = e.virtRestartPending ? TRUE : RestartScan;
    e.virtRestartPending = false;
    BOOLEAN restartReal = e.realRestartPending ? TRUE : FALSE;

    // Apply cached pattern to a newly upgraded virtual handle
    VL_UNICODE_STRING virtFnUs;
    PVL_UNICODE_STRING pVirtFileName = FileName;
    if (restartVirt && !pVirtFileName && e.hasCachedFileName && !e.cachedFileName.empty()) {
        MakeUStr(&virtFnUs, e.cachedFileName);
        pVirtFileName = &virtFnUs;
    }

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
                pVirtFileName, restartVirt);
            restartVirt = FALSE;
            pVirtFileName = NULL; // Clear for subsequent virtual calls

            if (NT_SUCCESS(st)) {
                std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                // Hide tombstone marker files (.vl_deleted) from callers
                if (IsTombstoneName(name)) continue;
                if (!name.empty()) e.virtNames.insert(name);
                UpdateFileEntry(FileHandle, e);
                return st;
            }
            // FIX: accept STATUS_NO_MORE_FILES from the virtual handle too
            // FIX: also treat STATUS_NO_SUCH_FILE as "nothing in virtual" so we
            // fall through to the real-side phase.  An empty virtual directory
            // returns NO_SUCH_FILE (not NO_MORE_FILES) when a FileName filter is
            // active and nothing matches — without this the real store is skipped.
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES ||
                st == VL_STATUS_NO_SUCH_FILE) {
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
                    bool tomb = FileHasTombstoneInVirtDir(virtDirPath, name);
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
    // Bug 2 fix: removed || e.isRealOnly -- same reasoning as above.
    if (!g_FsEnabled || !GetFileEntry(FileHandle, e) || !e.isDir) {
        return Real_NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
                                            IoStatusBlock, FileInformation, Length,
                                            FileInformationClass, QueryFlags);
    }

    // ----------------------------------------------------------------
    // Bug 2 fix: isRealOnly directory upgrade (same logic as above).
    // ----------------------------------------------------------------
    if (e.isRealOnly) {
        std::wstring virtPath = ApplyFsRedirect(e.logPath);
        HANDLE hNewVirt = NULL;
        if (!virtPath.empty()) {
            VL_UNICODE_STRING virtName; MakeUStr(&virtName, virtPath);
            VL_OBJECT_ATTRIBUTES virtOa;  MakeOA(&virtOa, &virtName);
            VL_IO_STATUS_BLOCK iosb;
            Real_NtOpenFile(&hNewVirt, FILE_LIST_DIRECTORY | SYNCHRONIZE,
                            &virtOa, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        }
        if (!hNewVirt) {
            // Virtual dir still doesn't exist — pass through with tombstone filtering.
            VL_DBG(L"Hook_NtQueryDirectoryFileEx: isRealOnly dir, tombstone-filtered pass-through: %s",
                   e.logPath.c_str());
            const std::wstring virtDirPathRT = ApplyFsRedirect(e.logPath);
            bool singleEntry = (QueryFlags & 0x02u) != 0; // SL_RETURN_SINGLE_ENTRY
            bool firstCall   = true;
            while (true) {
                ULONG qf = firstCall ? (QueryFlags | 0x01u) : (QueryFlags & ~0x01u);
                firstCall = false;
                NTSTATUS st = Real_NtQueryDirectoryFileEx(
                    FileHandle, Event, ApcRoutine, ApcContext,
                    IoStatusBlock, FileInformation, Length,
                    FileInformationClass, qf);
                if (!NT_SUCCESS(st)) return st;
                if (!virtDirPathRT.empty()) {
                    if (singleEntry) {
                        std::wstring name = ExtractDirFileName(FileInformation, FileInformationClass);
                        if (!name.empty() && IsTombstoneName(name)) continue;
                        if (!name.empty() && FileHasTombstoneInVirtDir(virtDirPathRT, name))
                            continue;
                    } else {
                        FilterDirBuffer(FileInformation, Length, FileInformationClass,
                                        nullptr, virtDirPathRT);
                    }
                }
                return st;
            }
        }
        VL_DBG(L"Hook_NtQueryDirectoryFileEx: upgrading isRealOnly dir to merged view: %s",
               e.logPath.c_str());
        e.hVirt              = hNewVirt;
        e.hReal              = FileHandle;
        e.isRealOnly         = false;
        // Same reasoning as NtQueryDirectoryFile: the virtual dir was created by
        // a CoW during this enumeration; skip it to avoid re-yielding CoW copies.
        e.virtEnumDone       = true;
        e.virtRestartPending = false;
        // DO NOT reset realRestartPending, realEnumDone, or virtNames —
        // preserve enumeration state across the upgrade.
        UpdateFileEntry(FileHandle, e);
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
            // FIX: also treat STATUS_NO_SUCH_FILE as "nothing in virtual" so we
            // fall through to the real-side phase.  An empty virtual directory
            // returns NO_SUCH_FILE (not NO_MORE_FILES) when a FileName filter is
            // active and nothing matches — without this the real store is skipped.
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES ||
                st == VL_STATUS_NO_SUCH_FILE) {
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
    ULONG flagsVirt = e.virtRestartPending ? (QueryFlags | 0x01u) : (QueryFlags & ~0x01u);
    e.virtRestartPending = false;
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
            // FIX: also treat STATUS_NO_SUCH_FILE as "nothing in virtual" so we
            // fall through to the real-side phase.  An empty virtual directory
            // returns NO_SUCH_FILE (not NO_MORE_FILES) when a FileName filter is
            // active and nothing matches — without this the real store is skipped.
            if (st == VL_STATUS_NO_MORE_ENTRIES || st == VL_STATUS_NO_MORE_FILES ||
                st == VL_STATUS_NO_SUCH_FILE) {
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
                    bool tomb = FileHasTombstoneInVirtDir(virtDirPath, name);
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

// Returns true if the merged (virtual + real) view of a directory is empty.
// Used to enforce correct rmdir-without-/S semantics: the hook must NOT allow
// delete-on-close to succeed when the merged directory still has visible entries,
// even though the virtual CoW copy the kernel sees is always empty.
//
// A directory is considered empty in the merged view when:
//   (a) the virtual store directory has no visible (non-tombstone) entries, AND
//   (b) every entry in the real directory has a tombstone in the virtual store.
//
// Must be called with SetReentrant(true) active so FindFirstFileW does not
// re-enter the FS hooks.
static bool IsMergedDirEmpty(const std::wstring& logPath,
                              const std::wstring& virtNtPath)
{
    // Step 1: scan the virtual directory for any visible (non-tombstone) entries.
    std::wstring win32Virt = NtPathToWin32(virtNtPath);
    if (!win32Virt.empty()) {
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW((win32Virt + L"\\*").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 ||
                    wcscmp(fd.cFileName, L"..") == 0) continue;
                if (IsTombstoneName(fd.cFileName)) continue; // internal marker
                FindClose(hFind);
                return false; // visible virtual entry found
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // Step 2: scan the real directory; any entry without a tombstone is visible.
    std::wstring win32Real = NtPathToWin32(logPath);
    if (!win32Real.empty()) {
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW((win32Real + L"\\*").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 ||
                    wcscmp(fd.cFileName, L"..") == 0) continue;
                if (!FileHasTombstoneInVirtDir(virtNtPath, fd.cFileName)) {
                    FindClose(hFind);
                    return false; // real entry visible in merged view
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    return true;
}

// ---- Win32RecursiveDeleteContentsNoHook ----
// Deletes all contents of a directory (not the directory itself) using raw
// Win32 calls.  Must be called with SetReentrant(true) active so our NT hooks
// do not intercept the Win32 → Nt call chain and try to redirect paths that
// are already physical virtual-store paths.
//
// Purpose: before the kernel's delete-on-close fires on a virtual directory,
// we must evacuate any tombstone files (.vl_deleted) we placed inside it.
// The kernel refuses to delete a non-empty directory, which causes rmdir /S
// to fail with "The directory is not empty" even though from the sandbox's
// point of view the directory was already empty.
static void Win32RecursiveDeleteContentsNoHook(const std::wstring& win32Dir) {
    std::wstring pattern = win32Dir + L"\\*";
    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring child = win32Dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            Win32RecursiveDeleteContentsNoHook(child);
            RemoveDirectoryW(child.c_str());
        } else {
            DeleteFileW(child.c_str());
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

// ---- NtSetInformationFile -- intercepts rename, hardlink, and delete-on-close ----
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
#define FileRenameInformation      10
#define FileLinkInformation        11
#define FileRenameInformationEx    65   // Windows 10 RS1+
#define FileLinkInformationEx      72   // Windows 10 RS1+
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
            // Removed the old !e.isDir guard: directories also need tombstones
            // when deleted, otherwise the real directory reappears in the merged
            // view as soon as the virtual copy is gone.
            if (GetFileEntry(FileHandle, e) && !e.isRealOnly && !e.logPath.empty()) {
                std::wstring redPath = ApplyFsRedirect(e.logPath);
                VL_UNICODE_STRING realUs; MakeUStr(&realUs, e.logPath);
                VL_OBJECT_ATTRIBUTES realOa; MakeOA(&realOa, &realUs);
                BYTE basicBuf[48] = {0};
                if (!IsFsNotFound(Real_NtQueryAttributesFile(&realOa, basicBuf))) {

                    // For directories: verify the merged view is empty BEFORE touching
                    // the tombstone. rmdir without /S must fail with
                    // STATUS_DIRECTORY_NOT_EMPTY when the directory has visible content.
                    // Without this check the hook creates an empty virtual CoW copy and
                    // the kernel deletes it successfully, bypassing the emptiness guard.
                    if (e.isDir) {
                        SetReentrant(true);
                        bool empty = IsMergedDirEmpty(e.logPath, redPath);
                        SetReentrant(false);
                        if (!empty) {
                            VL_DBG(L"Hook_NtSetInformationFile: dir not empty in merged view, "
                                   L"returning STATUS_DIRECTORY_NOT_EMPTY for %s",
                                   e.logPath.c_str());
                            return (NTSTATUS)0xC0000101L; // STATUS_DIRECTORY_NOT_EMPTY
                        }
                    }

                    EnsureVirtualFsPath(redPath);
                    CreateTombstone(redPath);

                    // Directories only: the virtual copy may contain .vl_deleted
                    // tombstone files left by sandbox-level deletion of the
                    // directory's contents (e.g. rmdir /S deletes files first,
                    // each creating a tombstone, THEN deletes the directory).
                    // The kernel refuses to delete a non-empty directory and
                    // returns STATUS_DIRECTORY_NOT_EMPTY, which propagates to
                    // cmd.exe as "The directory is not empty".
                    //
                    // Fix: evacuate all tombstone files (and any other virtual
                    // content) from the virtual directory before calling
                    // Real_NtSetInformationFile so the kernel sees an empty dir
                    // and can apply delete-on-close successfully.
                    // The tombstone we just created at the PARENT level (above)
                    // is enough to keep the real directory masked.
                    if (e.isDir) {
                        std::wstring win32VirtDir = NtPathToWin32(redPath);
                        SetReentrant(true);
                        Win32RecursiveDeleteContentsNoHook(win32VirtDir);
                        SetReentrant(false);
                        VL_DBG(L"Hook_NtSetInformationFile: evacuated virtual dir before "
                               L"delete-on-close: %s", win32VirtDir.c_str());
                    }
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
    HANDLE hRoot       = *(HANDLE*)(p + RENAME_INFO_HANDLE_OFFSET);

    if (nameByteLen == 0 || Length < (ULONG)(RENAME_INFO_NAME_OFFSET + nameByteLen))
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);

    std::wstring origName((WCHAR*)(p + RENAME_INFO_NAME_OFFSET),
                           nameByteLen / sizeof(WCHAR));

    const bool isLink = (FileInformationClass == FileLinkInformation ||
                         FileInformationClass == FileLinkInformationEx);
    VL_DBG(L"Hook_NtSetInformationFile: %s dest orig=%s hRoot=%p",
           isLink ? L"hardlink" : L"rename", origName.c_str(), hRoot);

    // Resolve relative destination to absolute if the caller supplied a root handle.
    // When hRoot is NULL and origName has no leading backslash the rename
    // destination is malformed at the NT level (no CWD concept here), so we pass
    // it through unchanged -- the kernel will reject it with the appropriate status.
    std::wstring targetLogicalPath;
    if (hRoot) {
        std::wstring rootPath = GetHandleLogicalPath(hRoot);
        targetLogicalPath = rootPath + L"\\" + origName;
    } else {
        targetLogicalPath = origName;
    }

    targetLogicalPath = Win32ToNtPath(targetLogicalPath);
    std::wstring redName = ApplyFsRedirect(targetLogicalPath);
    if (redName == targetLogicalPath) {
        // No FS redirect for destination.  Check for the cross-volume Recycle
        // Bin edge case:
        //
        // When a virtualised app (or the Explorer Shell on its behalf) recycles
        // a file that was CoW-promoted into the virtual store, the source handle
        // points to a file inside the virtual store (e.g. D:\VirtStore\C\foo.txt)
        // while the rename destination is the real $RECYCLE.BIN on the original
        // drive (e.g. C:\$RECYCLE.BIN\<SID>\$RXXX.txt).  Because the two paths
        // are on DIFFERENT volumes, the NT rename would fail with
        // STATUS_NOT_SAME_DEVICE.
        //
        // We handle this by manually copying the virtual-store file to the
        // recycle bin destination, then deleting it from the virtual store and
        // creating a tombstone so the logical source path appears deleted.
        //
        // Only applies to:
        //   - rename (not hardlink) operations
        //   - destination paths inside $RECYCLE.BIN / RECYCLER / RECYCLED
        //   - source handles that are tracked as non-real-only virtual files
        //     (real-only files are still on the original drive and can be
        //     renamed cross-path natively, but only when they are on the same
        //     volume as the recycle bin — the native call below handles that)
        if (!isLink && IsRecycleBinPath(targetLogicalPath)) {
            VirtFileEntry srcEntry;
            if (GetFileEntry(FileHandle, srcEntry) &&
                !srcEntry.isRealOnly &&
                !srcEntry.logPath.empty())
            {
                // Physical location of the file in the virtual store
                std::wstring physSrc = ApplyFsRedirect(srcEntry.logPath);
                std::wstring win32Src = NtPathToWin32(physSrc);
                std::wstring win32Dst = NtPathToWin32(targetLogicalPath);

                VL_DBG(L"Hook_NtSetInformationFile: cross-volume recycle "
                       L"src=%s dst=%s", win32Src.c_str(), win32Dst.c_str());

                // Ensure the destination $RECYCLE.BIN\<SID> directory exists.
                // It is normally already present; CreateDirectoryW is a no-op
                // when it does.  We only create one level up from the file.
                {
                    std::wstring dstDir = win32Dst;
                    size_t sl = dstDir.rfind(L'\\');
                    if (sl != std::wstring::npos) {
                        dstDir.resize(sl);
                        // CreateDirectory is idempotent — ignore failure
                        SetReentrant(true);
                        CreateDirectoryW(dstDir.c_str(), NULL);
                        SetReentrant(false);
                    }
                }

                // Copy the file from the virtual store to the real Recycle Bin.
                SetReentrant(true);
                BOOL copied = CopyFileExW(
                    win32Src.c_str(),
                    win32Dst.c_str(),
                    NULL, NULL, NULL,
                    COPY_FILE_ALLOW_DECRYPTED_DESTINATION |
                    COPY_FILE_COPY_SYMLINK);
                if (copied) {
                    // Remove from the virtual store (the recycle bin now owns it).
                    DeleteFileW(win32Src.c_str());
                    SetReentrant(false);

                    // Create a tombstone so the logical source path appears deleted
                    // in the sandbox (prevents the real file from reappearing on
                    // the next read or enumeration).
                    EnsureVirtualFsPath(physSrc);
                    CreateTombstone(physSrc);

                    // Remove the stale tracking entry; the handle is no longer valid
                    // against the file we just deleted.
                    UntrackFileHandle(FileHandle);

                    VL_DBG(L"Hook_NtSetInformationFile: cross-volume recycle OK");
                    if (IoStatusBlock) {
                        IoStatusBlock->Status      = VL_STATUS_SUCCESS;
                        IoStatusBlock->Information = 0;
                    }
                    return VL_STATUS_SUCCESS;
                }
                SetReentrant(false);
                // Copy failed — fall through and let the native rename attempt
                // run (it will fail with STATUS_NOT_SAME_DEVICE, which the Shell
                // treats as "delete permanently without recycle").
                VL_DBG(L"Hook_NtSetInformationFile: cross-volume recycle FAILED "
                       L"err=%u -- falling through to native rename",
                       GetLastError());
            }
        }

        VL_DBG(L"Hook_NtSetInformationFile: no redirect for %s dest",
               isLink ? L"hardlink" : L"rename");
        return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                          FileInformation, Length,
                                          FileInformationClass);
    }

    VL_DBG(L"Hook_NtSetInformationFile: %s dest -> %s",
           isLink ? L"hardlink" : L"rename", redName.c_str());

    // ---- Sandboxie-style: strict merged namespace collision for rename ----
    //
    // ReplaceIfExists (the first BOOLEAN in the rename/link info structure)
    // tells the kernel whether to overwrite an existing destination.
    //
    // Under a merged namespace the destination "exists" if it is present
    // in EITHER the virtual OR the real store (unless a tombstone hides it).
    // Without this check, renaming over a real-only destination succeeds
    // silently (the virtual store is empty, so the kernel sees no conflict).
    // That causes:
    //   • "move c v" in cmd.exe to complete without the "Overwrite?" prompt.
    //   • Atomic safe-write patterns (write tmp → rename over original) to
    //     silently shadow the real original without the app knowing.
    //
    // If ReplaceIfExists=FALSE and the destination exists only in the real
    // store (not tombstoned), we return STATUS_OBJECT_NAME_COLLISION.
    // MoveFileEx / cmd.exe then handle this the same way they would for a
    // real collision: cmd prompts, Explorer copies with a new name, etc.
    //
    // If ReplaceIfExists=TRUE the caller has already accepted the overwrite;
    // we let the rename proceed.  The renamed virtual file lands at redName
    // and naturally shadows the real file at targetLogicalPath — no extra
    // tombstone needed because the virtual file is already there.
    //
    // Hardlinks (isLink=true) always create a new name; ReplaceIfExists
    // semantics apply the same way, so we check them too.
    {
        BOOLEAN replaceIfExists = *(BOOLEAN*)p;
        if (!replaceIfExists) {
            // Does the destination exist in the virtual store already?
            // If so the kernel will return STATUS_OBJECT_NAME_COLLISION
            // on its own — we don't need to do anything extra.
            VL_UNICODE_STRING virtDstUs; MakeUStr(&virtDstUs, redName);
            VL_OBJECT_ATTRIBUTES virtDstOa; MakeOA(&virtDstOa, &virtDstUs);
            BYTE virtDstBuf[48] = {0};
            bool virtDstExists = !IsFsNotFound(
                Real_NtQueryAttributesFile(&virtDstOa, virtDstBuf));

            if (!virtDstExists) {
                // Virtual store has no file at the destination.
                // Check whether a tombstone is hiding a deleted real file
                // (tombstone = caller already deleted it in the sandbox).
                if (!TombstoneExists(redName)) {
                    // Check the real store.
                    VL_UNICODE_STRING realDstUs;
                    MakeUStr(&realDstUs, targetLogicalPath);
                    VL_OBJECT_ATTRIBUTES realDstOa;
                    MakeOA(&realDstOa, &realDstUs);
                    BYTE realDstBuf[48] = {0};
                    if (!IsFsNotFound(
                            Real_NtQueryAttributesFile(&realDstOa, realDstBuf))) {
                        VL_DBG(L"Hook_NtSetInformationFile: %s dest exists in "
                               L"real merged NS, ReplaceIfExists=FALSE -> COLLISION",
                               isLink ? L"hardlink" : L"rename");
                        return VL_STATUS_OBJECT_NAME_COLLISION;
                    }
                }
            }
        }
    }

    // Ensure the virtual destination directory exists before the rename/link.
    EnsureVirtualFsPath(redName);

    // ---- Capture source logical path BEFORE the rename ----
    //
    // After Real_NtSetInformationFile returns, the kernel has already updated
    // the file object's internal name to the new (destination) name.
    // GetHandleLogicalPath(FileHandle) would therefore return the NEW path,
    // not the old one — making tombstone placement impossible.
    //
    // Solution: look up the file entry now (before the rename) to capture
    // e.logPath, which still holds the source's logical path (e.g. \??\c:\test11_merged_write\cc).
    // We also derive its virtual-store path (redSrcPath) here for the same reason.
    std::wstring preSrcLogical, preSrcRedPath;
    if (!isLink) {
        VirtFileEntry srcEntry;
        if (GetFileEntry(FileHandle, srcEntry) && !srcEntry.logPath.empty()) {
            preSrcLogical = srcEntry.logPath;
            preSrcRedPath = ApplyFsRedirect(preSrcLogical);
        } else {
            // Fall back to NtQueryObject (works before rename)
            preSrcLogical = GetHandleLogicalPath(FileHandle);
            preSrcRedPath = ApplyFsRedirect(preSrcLogical);
        }
    }

    ULONG newNameBytes = (ULONG)(redName.size() * sizeof(WCHAR));
    ULONG newLength    = RENAME_INFO_NAME_OFFSET + newNameBytes;
    std::vector<BYTE> buf(newLength, 0);
    memcpy(&buf[0], p, RENAME_INFO_NAME_OFFSET);
    // CRITICAL: clear RootDirectory -- our rewritten name is now absolute,
    // so the kernel must not apply any root-directory anchor.
    *(HANDLE*)(&buf[0] + RENAME_INFO_HANDLE_OFFSET) = NULL;
    *(ULONG*)(&buf[0] + RENAME_INFO_NAMELEN_OFFSET) = newNameBytes;
    memcpy(&buf[0] + RENAME_INFO_NAME_OFFSET, redName.c_str(), newNameBytes);

    NTSTATUS stRename = Real_NtSetInformationFile(FileHandle, IoStatusBlock,
                                                   &buf[0], newLength,
                                                   FileInformationClass);

    // ---- Post-rename tombstone management (rename only, not hardlink) ----
    //
    // After a successful rename the virtual source entry no longer exists at
    // its old name (it was atomically moved to the destination in the virtual
    // store).  But if the source name also exists in the REAL store, it will
    // re-emerge in the merged view immediately.
    //
    // Sandbox principle: real files are NEVER moved or deleted.  We only place
    // a tombstone so the real source is hidden from the merged namespace.
    // This applies uniformly to both files and directories — no special-casing.
    //
    // We use preSrcLogical / preSrcRedPath captured BEFORE the rename call
    // (not GetHandleLogicalPath after), because the kernel updates the file
    // object's name atomically during the rename — any post-rename query
    // returns the NEW name, not the old one.
    if (NT_SUCCESS(stRename) && !isLink && !preSrcLogical.empty()
        && preSrcRedPath != preSrcLogical)
    {
        // Probe the real store to see if the old source name still exists.
        // For real-only entries it always will; for virtual-only entries
        // the probe returns NOT_FOUND and we correctly skip the tombstone.
        VL_UNICODE_STRING realSrcUs; MakeUStr(&realSrcUs, preSrcLogical);
        VL_OBJECT_ATTRIBUTES realSrcOa; MakeOA(&realSrcOa, &realSrcUs);
        BYTE realSrcBuf[48] = {0};
        if (!IsFsNotFound(Real_NtQueryAttributesFile(&realSrcOa, realSrcBuf))) {
            VL_DBG(L"Hook_NtSetInformationFile: rename OK, tombstoning real source %s",
                   preSrcRedPath.c_str());
            EnsureVirtualFsPath(preSrcRedPath);
            CreateTombstone(preSrcRedPath);
        }
        // Remove any stale tombstone on the destination — it now exists in virtual.
        DeleteTombstoneIfPresent(redName);
    }

    return stRename;
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

    // ---------------------------------------------------------------
    // Prefix STARTUPINFO.lpTitle so the child console window starts
    // with the "@" marker from its very first moment — no un-prefixed
    // flash even before the child's DLL injection fires.
    //
    // CRITICAL SAFETY GUARD: when EXTENDED_STARTUPINFO_PRESENT is set
    // the caller passes a STARTUPINFOEXW* cast to LPSTARTUPINFOW.
    // Doing `modifiedSIW = *lpStartupInfo` would copy only
    // sizeof(STARTUPINFOW) bytes, silently dropping the
    // lpAttributeList pointer that lives immediately after it.
    // Windows would then read garbage as the attribute list and crash.
    // When the extended flag is present we leave lpStartupInfo
    // completely untouched; the child still gets the DLL injected and
    // Hook_SetConsoleTitleW will prefix its title on the first call.
    // ---------------------------------------------------------------
    STARTUPINFOW modifiedSIW;
    std::wstring  titledStartupW;
    LPSTARTUPINFOW pSIW = lpStartupInfo;
    if (!(dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) &&
        lpStartupInfo && lpStartupInfo->lpTitle &&
        lpStartupInfo->lpTitle[0] != L'\0' &&
        lpStartupInfo->lpTitle[0] != L'@')
    {
        modifiedSIW           = *lpStartupInfo;
        titledStartupW        = std::wstring(L"@ ") + lpStartupInfo->lpTitle;
        modifiedSIW.lpTitle   = const_cast<LPWSTR>(titledStartupW.c_str());
        pSIW                  = &modifiedSIW;
        VL_DBG(L"Hook_CreateProcessW: prefixed lpTitle -> %s", modifiedSIW.lpTitle);
    }
    else if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) {
        VL_DBG(L"Hook_CreateProcessW: EXTENDED_STARTUPINFO_PRESENT -- skipping lpTitle patch (safe)");
    }

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
        lpCurrentDirectory, pSIW, lpProcessInformation,
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

    // Prefix STARTUPINFO.lpTitle for the child console window (ANSI version).
    // Same EXTENDED_STARTUPINFO_PRESENT guard as the W variant — see above.
    STARTUPINFOA modifiedSIA;
    std::string   titledStartupA;
    LPSTARTUPINFOA pSIA = lpStartupInfo;
    if (!(dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) &&
        lpStartupInfo && lpStartupInfo->lpTitle &&
        lpStartupInfo->lpTitle[0] != '\0' &&
        lpStartupInfo->lpTitle[0] != '@')
    {
        modifiedSIA           = *lpStartupInfo;
        titledStartupA        = std::string("@ ") + lpStartupInfo->lpTitle;
        modifiedSIA.lpTitle   = const_cast<LPSTR>(titledStartupA.c_str());
        pSIA                  = &modifiedSIA;
        VL_DBG(L"Hook_CreateProcessA: prefixed lpTitle -> %S", modifiedSIA.lpTitle);
    }
    else if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT) {
        VL_DBG(L"Hook_CreateProcessA: EXTENDED_STARTUPINFO_PRESENT -- skipping lpTitle patch (safe)");
    }

    PVOID wow64Old = NULL;
    bool  wow64Off = DisableWow64Redir(&wow64Old);
    const char* dlls[1] = { dllPath };
    BOOL ok = DetourCreateProcessWithDllsA(
        lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, pSIA, lpProcessInformation,
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

// ============================================================
// Window title prefixing
//
// Every top-level window created or renamed inside the virtualized
// process gets its title prefixed with "@" so the user can instantly
// tell it is running sandboxed — the same visual cue Sandboxie uses
// (which prefixes "#").
//
// We hook SIX entry points:
//   SetWindowTextW / SetWindowTextA    — title changes after creation (GUI apps)
//   CreateWindowExW / CreateWindowExA  — initial title at creation time (GUI apps)
//   SetConsoleTitleW / SetConsoleTitleA — console title changes (cmd, PowerShell, etc.)
//
// Why SetConsoleTitle* is required:
//   cmd.exe never calls SetWindowTextW. Its console window is owned by
//   conhost.exe (a separate process). cmd.exe calls SetConsoleTitleW in
//   kernel32, which serialises the title into an undocumented LPC message
//   sent to conhost via NtRequestWaitReplyPort; conhost then calls
//   SetWindowTextW in *its own* process — where our hooks are invisible.
//   Hooking SetConsoleTitleW/A in kernel32 is the correct interception layer.
//
// Three-part strategy for full console coverage:
//   1. Hook SetConsoleTitleW/A  — catches all dynamic title changes.
//   2. Fix initial title in DllMain after InstallHooks() — conhost may have
//      already set the window title before our DLL was injected.
//   3. Prefix STARTUPINFO.lpTitle in Hook_CreateProcessW/A — child console
//      processes inherit the prefixed title from the very first moment,
//      eliminating any un-prefixed flash.
//
// Rules (apply to all six hooks equally):
//   • NULL or empty title  → pass through unchanged (no bare "@" title)
//   • title already starts with '@' → pass through (avoid double-prefix)
//   • otherwise → prepend "@ " for readability
// ============================================================

static BOOL WINAPI Hook_SetWindowTextW(HWND hWnd, LPCWSTR lpString) {
    if (lpString && lpString[0] != L'\0' && lpString[0] != L'@') {
        std::wstring titled = std::wstring(L"@ ") + lpString;
        return Real_SetWindowTextW(hWnd, titled.c_str());
    }
    return Real_SetWindowTextW(hWnd, lpString);
}

static BOOL WINAPI Hook_SetWindowTextA(HWND hWnd, LPCSTR lpString) {
    if (lpString && lpString[0] != '\0' && lpString[0] != '@') {
        std::string titled = std::string("@ ") + lpString;
        return Real_SetWindowTextA(hWnd, titled.c_str());
    }
    return Real_SetWindowTextA(hWnd, lpString);
}

static HWND WINAPI Hook_CreateWindowExW(
    DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName,
    DWORD dwStyle, int X, int Y, int nWidth, int nHeight,
    HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    if (lpWindowName && lpWindowName[0] != L'\0' && lpWindowName[0] != L'@') {
        std::wstring titled = std::wstring(L"@ ") + lpWindowName;
        return Real_CreateWindowExW(dwExStyle, lpClassName, titled.c_str(),
                                    dwStyle, X, Y, nWidth, nHeight,
                                    hWndParent, hMenu, hInstance, lpParam);
    }
    return Real_CreateWindowExW(dwExStyle, lpClassName, lpWindowName,
                                dwStyle, X, Y, nWidth, nHeight,
                                hWndParent, hMenu, hInstance, lpParam);
}

static HWND WINAPI Hook_CreateWindowExA(
    DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,
    DWORD dwStyle, int X, int Y, int nWidth, int nHeight,
    HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    if (lpWindowName && lpWindowName[0] != '\0' && lpWindowName[0] != '@') {
        std::string titled = std::string("@ ") + lpWindowName;
        return Real_CreateWindowExA(dwExStyle, lpClassName, titled.c_str(),
                                    dwStyle, X, Y, nWidth, nHeight,
                                    hWndParent, hMenu, hInstance, lpParam);
    }
    return Real_CreateWindowExA(dwExStyle, lpClassName, lpWindowName,
                                dwStyle, X, Y, nWidth, nHeight,
                                hWndParent, hMenu, hInstance, lpParam);
}

// ---- Console title hooks (kernel32) ----
// cmd.exe, PowerShell, and any console application call SetConsoleTitleW/A
// (not SetWindowTextW) to change their window title.  conhost.exe owns the
// actual HWND, so our SetWindowTextW hook never fires for those callers.
// These hooks intercept the kernel32 call before it reaches conhost.

static BOOL WINAPI Hook_SetConsoleTitleW(LPCWSTR lpConsoleTitle) {
    VL_DBG(L"Hook_SetConsoleTitleW: title=%s", lpConsoleTitle ? lpConsoleTitle : L"(null)");
    if (lpConsoleTitle && lpConsoleTitle[0] != L'\0' && lpConsoleTitle[0] != L'@') {
        std::wstring titled = std::wstring(L"@ ") + lpConsoleTitle;
        return Real_SetConsoleTitleW(titled.c_str());
    }
    return Real_SetConsoleTitleW(lpConsoleTitle);
}

static BOOL WINAPI Hook_SetConsoleTitleA(LPCSTR lpConsoleTitle) {
    VL_DBG(L"Hook_SetConsoleTitleA: title=%S", lpConsoleTitle ? lpConsoleTitle : "(null)");
    if (lpConsoleTitle && lpConsoleTitle[0] != '\0' && lpConsoleTitle[0] != '@') {
        std::string titled = std::string("@ ") + lpConsoleTitle;
        return Real_SetConsoleTitleA(titled.c_str());
    }
    return Real_SetConsoleTitleA(lpConsoleTitle);
}

static void InstallHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    if (!ntdll || !k32) return;

    // Always needed
    VL_GETPROC(ntdll, NtClose);
    VL_GETPROC(ntdll, NtQueryObject);
    VL_GETPROC(k32,   CreateProcessW);
    VL_GETPROC(k32,   CreateProcessA);

    // Window title prefixing — user32.dll
    {
        HMODULE u32 = GetModuleHandleA("user32.dll");
        if (!u32) u32 = LoadLibraryA("user32.dll");
        if (u32) {
            VL_GETPROC(u32, SetWindowTextW);
            VL_GETPROC(u32, SetWindowTextA);
            VL_GETPROC(u32, CreateWindowExW);
            VL_GETPROC(u32, CreateWindowExA);
        }
    }
    // Console title prefixing — kernel32.dll (always loaded, no NULL check needed)
    // SetConsoleTitleW/A are present on all supported Windows versions.
    VL_GETPROC(k32, SetConsoleTitleW);
    VL_GETPROC(k32, SetConsoleTitleA);

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

    // Window title prefixing
    if (Real_SetWindowTextW)  VL_ATTACH(SetWindowTextW);
    if (Real_SetWindowTextA)  VL_ATTACH(SetWindowTextA);
    if (Real_CreateWindowExW) VL_ATTACH(CreateWindowExW);
    if (Real_CreateWindowExA) VL_ATTACH(CreateWindowExA);
    // Console title prefixing (cmd.exe, PowerShell, any console app)
    if (Real_SetConsoleTitleW) VL_ATTACH(SetConsoleTitleW);
    if (Real_SetConsoleTitleA) VL_ATTACH(SetConsoleTitleA);

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

    // Window title prefixing
    if (Real_SetWindowTextW)  VL_DETACH(SetWindowTextW);
    if (Real_SetWindowTextA)  VL_DETACH(SetWindowTextA);
    if (Real_CreateWindowExW) VL_DETACH(CreateWindowExW);
    if (Real_CreateWindowExA) VL_DETACH(CreateWindowExA);
    // Console title prefixing
    if (Real_SetConsoleTitleW) VL_DETACH(SetConsoleTitleW);
    if (Real_SetConsoleTitleA) VL_DETACH(SetConsoleTitleA);

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

        VL_DBG(L"DllMain: DLL_PROCESS_ATTACH -- VirtHook loading (v12 console title fix)");

        LoadConfig();
        InstallHooks();

        // ---------------------------------------------------------------
        // Fix the initial console title.
        //
        // conhost.exe sets the window title from STARTUPINFO.lpTitle (or
        // the executable name) *before* our DLL is injected.  By the time
        // DllMain runs the title is already visible without the "@" prefix.
        // Read whatever conhost put there and re-set it through our now-
        // active hook so the prefix is applied immediately.
        //
        // GetConsoleTitle returns 0 for non-console (GUI-only) processes,
        // so this block is a safe no-op for them.
        // ---------------------------------------------------------------
        {
            wchar_t existingTitle[1024] = {0};
            DWORD titleLen = GetConsoleTitleW(existingTitle, 1024);
            if (titleLen > 0 && existingTitle[0] != L'\0' && existingTitle[0] != L'@') {
                std::wstring prefixed = std::wstring(L"@ ") + existingTitle;
                // Call through the trampoline (Real_) so we don't re-enter
                // the hook; the title we pass already carries the prefix.
                if (Real_SetConsoleTitleW)
                    Real_SetConsoleTitleW(prefixed.c_str());
                else
                    SetConsoleTitleW(prefixed.c_str());
                VL_DBG(L"DllMain: fixed initial console title -> %s", prefixed.c_str());
            }
        }

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