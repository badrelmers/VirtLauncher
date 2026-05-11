/*
 * test_bug1.c  -  BUG1: The Relative Path Bug: GetHandleLogicalPath never checks g_FileMap
 *                 This code reproduces Bug 1: COW read failure via NT-relative open
 *                 through a write-CoW virtual directory handle.
 *
 *
 * Usage (run under VirtLauncher):
 *   VirtLauncher64.exe -f -e test_bug1_64.exe <dir_path> <filename>
 *
 * What it does:
 *   1. Opens <dir_path> via Win32 CreateFileW.
 *      VirtHook intercepts this, redirects to the virtual store, and returns
 *      the VIRTUAL-STORE handle to the caller (not the real dir handle).
 *   2. Opens <filename> RELATIVE to that handle via raw NtOpenFile --
 *      NO Win32 wrapper that would resolve the path to an absolute string.
 *   3. Reads and prints the file content.
 *
 * Expected with Bug 1 PRESENT : FAIL  0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND)
 * Expected with Bug 1 FIXED   : OK    content=[...]
 *
 * Why cmd.exe tests never catch this:
 *   cmd/CreateFile/fopen always call GetFullPathNameW first, so the hook
 *   always sees a full \??\C:\... path with RootDirectory=NULL.
 *   Bug 1 only fires when RootDirectory is a virtual-store handle and
 *   ObjectName is a bare relative name -- exactly what this program does.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

/* ---- minimal NT type definitions ---- */
typedef LONG NTSTATUS;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} VL_USTR;

typedef struct {
    ULONG   Length;
    HANDLE  Root;
    VL_USTR *Name;
    ULONG   Attr;
    PVOID   SD;
    PVOID   SQoS;
} VL_OA;

typedef struct {
    union { NTSTATUS Status; PVOID Ptr; };
    ULONG_PTR Info;
} VL_IOSB;

typedef NTSTATUS (NTAPI *PfnNtOpenFile)(
    PHANDLE, ULONG, VL_OA *, VL_IOSB *, ULONG, ULONG);

#define SYNCH        0x00100000L
#define SHARE_ALL    0x00000007L
#define OBJ_CI       0x00000040L
#define FILE_NON_DIR 0x00000040L
#define FILE_SYNC_IO 0x00000020L
#define NT_OK(s)     ((NTSTATUS)(s) >= 0)

int wmain(int argc, wchar_t **argv)
{
    /* C89: ALL declarations must come before any statement */
    PfnNtOpenFile pNtOpenFile;
    HANDLE        hDir;
    HANDLE        hFile;
    VL_USTR       us;
    VL_OA         oa;
    VL_IOSB       iosb;
    NTSTATUS      st;
    char          buf[256];
    DWORD         rd;
    int           i;

    if (argc < 3) {
        wprintf(L"Usage: test_bug1 <dir_path> <filename>\n");
        wprintf(L"\n");
        wprintf(L"Opens dir_path via Win32 (VirtHook returns virtual-store handle),\n");
        wprintf(L"then opens <filename> relative to it via raw NtOpenFile.\n");
        wprintf(L"File must exist only in REAL path, NOT in the virtual store.\n");
        return 2;
    }

    pNtOpenFile = (PfnNtOpenFile)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtOpenFile");
    if (!pNtOpenFile) {
        wprintf(L"FAIL: NtOpenFile not found in ntdll\n");
        return 1;
    }

    /*
     * Step 1: open the directory via Win32.
     * VirtHook intercepts NtCreateFile internally, redirects to the virtual
     * store (the virtual dir exists because we created it via cmd mkdir),
     * and hands us back the VIRTUAL-STORE handle.
     */
    hDir = CreateFileW(argv[1],
                       GENERIC_READ | 0x1 /* FILE_LIST_DIRECTORY */,
                       SHARE_ALL,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS,
                       NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        wprintf(L"FAIL: cannot open dir '%s'  err=%u\n",
                argv[1], GetLastError());
        return 1;
    }

    wprintf(L"Dir handle:  %p\n", (void *)hDir);
    wprintf(L"  (if VirtHook is active this is a VIRTUAL-STORE handle;\n");
    wprintf(L"   NtQueryObject on it returns the physical sandbox path)\n");

    /*
     * Step 2: open the file RELATIVE to the dir handle using NtOpenFile
     * directly -- no Win32 wrapper, no GetFullPathNameW, no absolute path.
     *
     * Bug 1 path inside VirtHook:
     *   GetHandleLogicalPath(hDir)
     *     -> misses g_FileMap  (only checks g_KeyMap for registry)
     *     -> falls through to NtQueryObject
     *     -> NtQueryObject returns PHYSICAL path e.g. \??\D:\sandbox\c\mydir
     *   GetFullNtPath builds  \??\D:\sandbox\c\mydir\<filename>
     *   ApplyFsRedirect sees  StartsWithI(ntPath, g_FsDirNtBase) == true
     *     -> no redirect  (already inside virtual store)
     *   redirected = false  -> Real_NtOpenFile called with the original OA
     *     -> RootDirectory = <virtual-store handle>
     *     -> ObjectName    = <filename>
     *     -> file not in virtual store  -> STATUS_OBJECT_NAME_NOT_FOUND
     *   COW fallback to real NEVER runs.
     *
     * After the fix (g_FileMap lookup first):
     *   GetHandleLogicalPath(hDir)
     *     -> finds VirtFileEntry in g_FileMap  -> returns logPath = \??\C:\mydir
     *   GetFullNtPath builds  \??\C:\mydir\<filename>
     *   ApplyFsRedirect redirects to  \??\D:\sandbox\C\mydir\<filename>
     *   Try virtual  -> not found
     *   Tombstone?   -> no
     *   Real exists? -> yes
     *   isWrite?     -> no  -> serve real directly  -> OK
     */
    us.Buffer        = argv[2];
    us.Length        = (USHORT)(wcslen(argv[2]) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);

    oa.Length = sizeof(oa);
    oa.Root   = hDir;
    oa.Name   = &us;
    oa.Attr   = OBJ_CI;
    oa.SD     = NULL;
    oa.SQoS   = NULL;

    iosb.Status = 0;
    iosb.Info   = 0;
    hFile = NULL;

    st = pNtOpenFile(&hFile,
                     GENERIC_READ | SYNCH,
                     &oa, &iosb,
                     SHARE_ALL,
                     FILE_NON_DIR | FILE_SYNC_IO);

    CloseHandle(hDir);

    if (NT_OK(st) && hFile) {
        rd = 0;
        memset(buf, 0, sizeof(buf));
        ReadFile(hFile, buf, sizeof(buf) - 1, &rd, NULL);
        CloseHandle(hFile);

        /* strip trailing CR / LF */
        for (i = (int)rd - 1; i >= 0; --i) {
            if (buf[i] == '\r' || buf[i] == '\n')
                buf[i] = '\0';
            else
                break;
        }
        printf("OK:   content=[%s]\n", buf);
        return 0;
    }

    wprintf(L"FAIL: NtOpenFile returned 0x%08X\n", (unsigned long)st);
    wprintf(L"      0xC0000034 = STATUS_OBJECT_NAME_NOT_FOUND  -> Bug 1 is PRESENT\n");
    wprintf(L"      0xC000003A = STATUS_OBJECT_PATH_NOT_FOUND  -> virtual dir not created yet\n");
    return 1;
}
