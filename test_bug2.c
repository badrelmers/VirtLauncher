/*
 * test_bug2.c  -  Reproduces Bug 2: isRealOnly directory handle missing
 *                 virtual-only files created after the handle was opened.
 *
 * WHY CMD CANNOT REPRODUCE THIS:
 *   cmd.exe opens a directory, enumerates it, and closes the handle all
 *   within a single "dir" command. There is no way in batch to hold a
 *   directory handle open, create a file via a separate handle, and then
 *   enumerate the original handle again. The bug requires fine-grained
 *   handle lifetime control -- hence this C program.
 *
 * Usage (run inside the sandbox):
 *   VirtLauncher64.exe -f -e test_bug2_64.exe <real_dir>
 *
 *   <real_dir> must be a directory that EXISTS on the REAL filesystem
 *   but does NOT yet have a counterpart in the virtual store.
 *   Example:  VirtLauncher64.exe -f -e test_bug2_64.exe c:\vl_bug2_testdir
 *
 * What the program does (step by step):
 *   1. Opens <real_dir> via CreateFile with FILE_FLAG_BACKUP_SEMANTICS
 *      and read-only access.
 *      VirtHook: virtual store has no counterpart -> isRealOnly=true.
 *      The caller receives the REAL directory handle (hDir).
 *
 *   2. Creates <real_dir>\virt_only.txt via a separate CreateFile call.
 *      VirtHook: write access -> EnsureVirtualFsPath creates virtual dir
 *      -> file lands in VIRTL\...\<real_dir>\virt_only.txt.
 *      The REAL filesystem is never touched.
 *
 *   3. Enumerates <real_dir> using FindFirstFileEx on hDir via the
 *      NtQueryDirectoryFile path. Checks if virt_only.txt appears.
 *
 *      Bug 2 PRESENT:  isRealOnly guard skips merge -> virt_only.txt
 *                      invisible -> FAIL
 *      Bug 2 FIXED:    upgrade block detects virtual dir -> merged view
 *                      -> virt_only.txt visible -> OK
 *
 *   4. Cleans up.
 *
 * Note: step 3 uses NtQueryDirectoryFile directly (via the hooked
 * ntdll export) because Win32 FindFirstFile always opens a NEW handle
 * internally and would therefore never trigger the stale-handle bug.
 * We must enumerate the exact same handle opened in step 1.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ---- minimal NT type definitions (C89 compatible) ---- */
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

/* FILE_BOTH_DIR_INFORMATION (class 3) */
typedef struct {
    ULONG  NextEntryOffset;
    ULONG  FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG  FileAttributes;
    ULONG  FileNameLength;
    ULONG  EaSize;
    CHAR   ShortNameLength;
    WCHAR  ShortName[12];
    WCHAR  FileName[1];
} MY_FBDI;

typedef NTSTATUS (NTAPI *PfnNtOpenFile)(
    PHANDLE, ULONG, VL_OA*, VL_IOSB*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PfnNtQueryDirectoryFile)(
    HANDLE, HANDLE, PVOID, PVOID, VL_IOSB*,
    PVOID, ULONG, ULONG, BOOLEAN, VL_USTR*, BOOLEAN);

#define SYNCH          0x00100000L
#define SHARE_ALL      0x00000007L
#define OBJ_CI         0x00000040L
#define FILE_DIR_FILE  0x00000001L
#define FILE_SYNC_IO   0x00000020L
#define FILE_LIST_DIR  0x00000001L
#define NT_OK(s)       ((NTSTATUS)(s) >= 0)
#define STATUS_NO_MORE_FILES  ((NTSTATUS)0x80000006L)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#define FILE_CLASS_BOTH_DIR  3

static void MakeUStr(VL_USTR *us, const wchar_t *s)
{
    us->Buffer        = (PWSTR)s;
    us->Length        = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

static void MakeOA(VL_OA *oa, VL_USTR *name)
{
    memset(oa, 0, sizeof(*oa));
    oa->Length = sizeof(*oa);
    oa->Name   = name;
    oa->Attr   = OBJ_CI;
}

/* Build \??\C:\path  from  C:\path */
static void ToNtPath(const wchar_t *win32, wchar_t *nt, int ntMax)
{
    _snwprintf(nt, ntMax, L"\\??\\%s", win32);
    nt[ntMax - 1] = L'\0';
}

int wmain(int argc, wchar_t **argv)
{
    /* C89: all declarations at the top */
    PfnNtOpenFile            pNtOpenFile;
    PfnNtQueryDirectoryFile  pNtQueryDirectoryFile;
    HANDLE    hDir;
    HANDLE    hFile;
    NTSTATUS  st;
    VL_USTR   us;
    VL_OA     oa;
    VL_IOSB   iosb;
    wchar_t   ntDirPath[1024];
    wchar_t   virtFilePath[1024];
    BYTE      buf[4096];
    MY_FBDI   *entry;
    int       found;
    int       step;
    DWORD     wr;

    if (argc < 2) {
        wprintf(L"Usage: test_bug2 <real_dir>\n");
        wprintf(L"\n");
        wprintf(L"  <real_dir>  must exist on the REAL filesystem.\n");
        wprintf(L"  Run inside the sandbox: VirtLauncher64.exe -f -e test_bug2_64.exe <real_dir>\n");
        return 2;
    }

    pNtOpenFile = (PfnNtOpenFile)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtOpenFile");
    pNtQueryDirectoryFile = (PfnNtQueryDirectoryFile)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryFile");

    if (!pNtOpenFile || !pNtQueryDirectoryFile) {
        wprintf(L"FAIL: could not find NT functions in ntdll\n");
        return 1;
    }

    ToNtPath(argv[1], ntDirPath, 1024);
    _snwprintf(virtFilePath, 1024, L"%s\\virt_only.txt", argv[1]);
    virtFilePath[1023] = L'\0';

    /* ----------------------------------------------------------------
     * Step 1: open the directory read-only with FILE_DIRECTORY_FILE.
     *
     * VirtHook path:
     *   - Tries to open virtual counterpart -> not found (doesn't exist yet)
     *   - Tombstone? No.
     *   - Real exists? Yes.
     *   - isWrite? No.  -> isRealOnly=true, returns real handle.
     *
     * The handle hDir IS a real-filesystem directory handle.
     * ---------------------------------------------------------------- */
    wprintf(L"Step 1: open '%s' read-only (expect isRealOnly=true in hook)\n", argv[1]);

    MakeUStr(&us, ntDirPath);
    MakeOA(&oa, &us);
    iosb.Status = 0; iosb.Info = 0;
    hDir = NULL;

    st = pNtOpenFile(&hDir,
                     FILE_LIST_DIR | SYNCH,
                     &oa, &iosb,
                     SHARE_ALL,
                     FILE_DIR_FILE | FILE_SYNC_IO);

    if (!NT_OK(st) || !hDir) {
        wprintf(L"FAIL: cannot open directory, NTSTATUS=0x%08X\n", (unsigned long)st);
        return 1;
    }
    wprintf(L"  hDir = %p\n", (void*)hDir);

    /* ----------------------------------------------------------------
     * Step 2: create a VIRTUAL-ONLY file in that directory.
     *
     * VirtHook path for write access:
     *   - FILE_CREATE/write -> EnsureVirtualFsPath creates virtual dir
     *   - File written to VIRTL\...\<dir>\virt_only.txt
     *   - REAL filesystem untouched.
     *
     * After this, the virtual store has the directory and the file.
     * The old hDir is still isRealOnly -- it was opened before the
     * virtual dir existed.
     * ---------------------------------------------------------------- */
    wprintf(L"Step 2: create '%s' (virtual-only, triggers EnsureVirtualFsPath)\n",
            virtFilePath);

    /* Delete any leftover from a previous run */
    DeleteFileW(virtFilePath);

    hFile = CreateFileW(virtFilePath,
                        GENERIC_WRITE,
                        0, NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"FAIL: cannot create virtual file, err=%u\n", GetLastError());
        CloseHandle(hDir);
        return 1;
    }
    /* Write something so it's not an empty file */
    WriteFile(hFile, "bug2test\r\n", 10, &wr, NULL);
    CloseHandle(hFile);
    wprintf(L"  Created OK. Virtual dir should now exist in sandbox.\n");

    /* ----------------------------------------------------------------
     * Step 3: enumerate the OLD hDir handle via NtQueryDirectoryFile.
     *
     * We call NtQueryDirectoryFile directly on hDir (the stale handle).
     * Win32 FindFirstFile is NOT used here because it always opens a
     * NEW handle internally -- that would trivially work even with Bug 2
     * since the new handle would see the virtual dir and not be isRealOnly.
     *
     * Bug 2 PRESENT: guard sees isRealOnly=true -> passes to real
     *   NtQueryDirectoryFile -> virt_only.txt invisible.
     * Bug 2 FIXED:   upgrade block opens virtual handle on-demand ->
     *   merged view -> virt_only.txt visible.
     * ---------------------------------------------------------------- */
    wprintf(L"Step 3: enumerate hDir via NtQueryDirectoryFile (same handle from step 1)\n");
    wprintf(L"  Looking for 'virt_only.txt' in the merged listing...\n");

    found = 0;
    step  = 0;

    while (1) {
        BOOLEAN restart = (step == 0) ? TRUE : FALSE;
        ++step;

        memset(buf, 0, sizeof(buf));
        iosb.Status = 0; iosb.Info = 0;

        st = pNtQueryDirectoryFile(
            hDir,
            NULL, NULL, NULL,
            &iosb,
            buf, sizeof(buf),
            FILE_CLASS_BOTH_DIR,
            FALSE,   /* ReturnSingleEntry=FALSE: fill buffer */
            NULL,    /* FileName=NULL: enumerate all */
            restart);

        if (st == STATUS_NO_MORE_FILES || st == STATUS_NO_MORE_ENTRIES)
            break;

        if (!NT_OK(st)) {
            wprintf(L"  NtQueryDirectoryFile returned 0x%08X\n", (unsigned long)st);
            break;
        }

        /* Walk the returned entries */
        {
            BYTE *p = buf;
            while (p) {
                wchar_t name[512];
                int     len;
                ULONG   nx;

                entry = (MY_FBDI*)p;
                len   = (int)(entry->FileNameLength / sizeof(WCHAR));
                if (len > 511) len = 511;
                memcpy(name, entry->FileName, len * sizeof(WCHAR));
                name[len] = L'\0';

                if (_wcsicmp(name, L"virt_only.txt") == 0) {
                    found = 1;
                }

                nx = entry->NextEntryOffset;
                if (nx == 0) break;
                p += nx;
            }
        }

        if (found) break;
    }

    CloseHandle(hDir);

    /* ----------------------------------------------------------------
     * Step 4: cleanup -- delete the virtual file we created.
     * ---------------------------------------------------------------- */
    DeleteFileW(virtFilePath);

    /* ----------------------------------------------------------------
     * Result
     * ---------------------------------------------------------------- */
    if (found) {
        wprintf(L"\nOK:   virt_only.txt found in directory listing.\n");
        wprintf(L"      Bug 2 is FIXED: isRealOnly handle upgraded to merged view.\n");
        return 0;
    } else {
        wprintf(L"\nFAIL: virt_only.txt NOT found in directory listing.\n");
        wprintf(L"      Bug 2 is PRESENT: isRealOnly handle skipped merge entirely.\n");
        wprintf(L"      The virtual-only file is invisible through the stale handle.\n");
        return 1;
    }
}
