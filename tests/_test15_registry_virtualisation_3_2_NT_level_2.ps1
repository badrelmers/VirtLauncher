#Requires -Version 5.1
<#
.SYNOPSIS
    VirtRegTest-NtLevel.ps1  -  Direct NT-API Registry Virtualisation Tests
    for VirtLauncher / VirtHook

.DESCRIPTION
    Calls ntdll.dll NT functions directly via P/Invoke (NtCreateKey, NtOpenKey,
    NtQueryKey, NtEnumerateKey, NtEnumerateValueKey, NtQueryValueKey,
    NtSetValueKey, NtDeleteKey, NtDeleteValueKey, NtQueryMultipleValueKey).

    This bypasses advapi32 entirely, which is exactly the layer that
    VirtHook intercepts. Tests here verify hook correctness at the raw
    NT API level rather than through reg.exe or the .NET RegistryKey API.

    MUST be run inside VirtLauncher:
        VirtLauncher64.exe -r HKCU\VirtRegTest_Store_2026 --exec ^
            powershell.exe -NoProfile -ExecutionPolicy Bypass ^
            -File VirtRegTest-NtLevel.ps1

    Or combined with VirtRegTest.bat by adding inside the batch:
        VirtLauncher64.exe -r HKCU\VirtRegTest_Store_2026 --exec ^
            powershell.exe -NoProfile -ExecutionPolicy Bypass ^
            -File VirtRegTest-NtLevel.ps1

.PARAMETER RBase
    Real-registry base path for pre-seeded keys (Win32 form).
    Default: HKCU\Software\VirtRegTestReal_2026

.PARAMETER NtBase
    NT path of the real base for seeded keys. Derived from RBase if omitted.
    Example: \Registry\User\S-1-5-21-...\Software\VirtRegTestReal_2026

.PARAMETER VirtNtBase
    NT path of the virtual store. Read from env VIRTLAUNCHER_REG if omitted.

.PARAMETER LogFile
    Path to write test result log. Default: %TEMP%\VirtRegTest_NtLevel.log

.NOTES
    Areas probed (all fixed unless noted):
      - NtCreateKey disposition (two cases, both fixed):
        * Pure-virtual new key (no real counterpart): EnsureVirtualPath is called
          on the parent path only so the leaf does not exist when Real_NtCreateKey
          runs → REG_CREATED_NEW_KEY (1) returned correctly (NA-01).
        * CoW over a pre-existing real key: disposition is overridden to
          REG_OPENED_EXISTING_KEY (2) after the real handle is confirmed open,
          so the app sees the key as already existing rather than newly created
          (NA-04).
      - NtQueryKey SubKeys/Values: Hook_NtQueryKey merges counts from both the
        virtual and real handles via set-union deduplication.
      - NtQueryMultipleValueKey: per-value fallback merge implemented. Each value
        is tried on the virtual handle first; if NOT_FOUND and not tombstoned, the
        real handle is consulted. Virtual overrides are preserved for overridden
        values while real-only values are served from the real handle.
      - NtDeleteKey/NtDeleteValueKey: tombstone markers prevent real values/keys
        from re-appearing after a virtual delete.
      - NtEnumerateKey/NtEnumerateValueKey: index-continuity and merge correctness.
      - Buffer-too-small handling in merge path.
      - Relative-path opens via OBJECT_ATTRIBUTES.RootDirectory.
      - HKCU\..._Classes hive routing to HKEY_USERS virtual store.
#>

param(
    [string]$RBase     = "HKCU\Software\VirtRegTestReal_2026",
    [string]$NtBase    = "",
    [string]$VirtNtBase = "",
    [string]$LogFile   = "$env:TEMP\VirtRegTest_NtLevel.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# 0.  Verify running inside VirtLauncher
# ─────────────────────────────────────────────────────────────────────────────
if (-not $env:VIRTLAUNCHER_REG -and -not $VirtNtBase) {
    Write-Host "[ERROR] VIRTLAUNCHER_REG is not set." -ForegroundColor Red
    Write-Host "        Run this script inside VirtLauncher, e.g.:"
    Write-Host "        VirtLauncher64.exe -r HKCU\VirtStore --exec powershell -File VirtRegTest-NtLevel.ps1"
    exit 1
}
if ($VirtNtBase -eq "") { $VirtNtBase = $env:VIRTLAUNCHER_REG }

# ─────────────────────────────────────────────────────────────────────────────
# 1.  Resolve NT path of the real seeded-key base
# ─────────────────────────────────────────────────────────────────────────────
if ($NtBase -eq "") {
    # Derive from HKCU path: get current user SID
    $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $id.User.Value
    $sub = $RBase -replace '^HKCU\\','' -replace '^HKEY_CURRENT_USER\\',''
    $NtBase = "\Registry\User\$sid\$sub"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2.  P/Invoke - NT API definitions
# ─────────────────────────────────────────────────────────────────────────────
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public int    Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;   // pointer to UNICODE_STRING
    public uint   Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
    public const uint OBJ_CASE_INSENSITIVE = 0x40u;
}

// KEY_INFORMATION_CLASS
public enum KEY_INFORMATION_CLASS : int {
    KeyBasicInformation    = 0,
    KeyNodeInformation     = 1,
    KeyFullInformation     = 2,
    KeyNameInformation     = 3,
    KeyCachedInformation   = 4
}

// KEY_VALUE_INFORMATION_CLASS
public enum KEY_VALUE_INFORMATION_CLASS : int {
    KeyValueBasicInformation   = 0,
    KeyValueFullInformation    = 1,
    KeyValuePartialInformation = 2
}

// KeyFullInformation layout (fixed part)
[StructLayout(LayoutKind.Sequential)]
public struct KEY_FULL_INFORMATION_FIXED {
    public long LastWriteTime;
    public uint TitleIndex;
    public uint ClassOffset;
    public uint ClassLength;
    public uint SubKeys;
    public uint MaxNameLen;
    public uint MaxClassLen;
    public uint Values;
    public uint MaxValueNameLen;
    public uint MaxValueDataLen;
    // WCHAR Class[1] follows
}

// KeyValuePartialInformation fixed part
[StructLayout(LayoutKind.Sequential)]
public struct KEY_VALUE_PARTIAL_INFORMATION_FIXED {
    public uint TitleIndex;
    public uint Type;
    public uint DataLength;
    // BYTE Data[1] follows
}

// KEY_VALUE_ENTRY for NtQueryMultipleValueKey
[StructLayout(LayoutKind.Sequential)]
public struct KEY_VALUE_ENTRY {
    public IntPtr ValueName;   // pointer to UNICODE_STRING (must be pinned)
    public uint   DataLength;
    public uint   DataOffset;
    public uint   Type;
}

public static class NtReg {
    const string NTDLL = "ntdll.dll";
    const uint KEY_READ  = 0x20019u;
    const uint KEY_WRITE = 0x20006u;
    const uint KEY_ALL   = 0xF003Fu;
    const uint REG_CREATED_NEW_KEY  = 1u;
    const uint REG_OPENED_EXISTING_KEY = 2u;

    [DllImport(NTDLL)]
    public static extern int NtCreateKey(
        out IntPtr  KeyHandle,
        uint        DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        uint        TitleIndex,
        IntPtr      Class,         // UNICODE_STRING* or NULL
        uint        CreateOptions,
        out uint    Disposition);

    [DllImport(NTDLL)]
    public static extern int NtOpenKey(
        out IntPtr  KeyHandle,
        uint        DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport(NTDLL)]
    public static extern int NtQueryKey(
        IntPtr   KeyHandle,
        int      KeyInformationClass,
        IntPtr   KeyInformation,
        int      Length,
        out int  ResultLength);

    [DllImport(NTDLL)]
    public static extern int NtEnumerateKey(
        IntPtr   KeyHandle,
        uint     Index,
        int      KeyInformationClass,
        IntPtr   KeyInformation,
        int      Length,
        out int  ResultLength);

    [DllImport(NTDLL)]
    public static extern int NtEnumerateValueKey(
        IntPtr   KeyHandle,
        uint     Index,
        int      KeyValueInformationClass,
        IntPtr   KeyValueInformation,
        int      Length,
        out int  ResultLength);

    [DllImport(NTDLL)]
    public static extern int NtQueryValueKey(
        IntPtr   KeyHandle,
        ref UNICODE_STRING ValueName,
        int      KeyValueInformationClass,
        IntPtr   KeyValueInformation,
        int      Length,
        out int  ResultLength);

    [DllImport(NTDLL)]
    public static extern int NtSetValueKey(
        IntPtr   KeyHandle,
        ref UNICODE_STRING ValueName,
        uint     TitleIndex,
        uint     Type,
        byte[]   Data,
        uint     DataSize);

    [DllImport(NTDLL)]
    public static extern int NtDeleteKey(IntPtr KeyHandle);

    [DllImport(NTDLL)]
    public static extern int NtDeleteValueKey(
        IntPtr   KeyHandle,
        ref UNICODE_STRING ValueName);

    [DllImport(NTDLL)]
    public static extern int NtClose(IntPtr Handle);

    [DllImport(NTDLL)]
    public static extern int NtQueryMultipleValueKey(
        IntPtr          KeyHandle,
        [In, Out] KEY_VALUE_ENTRY[] ValueEntries,
        uint            EntryCount,
        IntPtr          ValueBuffer,
        ref uint        BufferLength,
        out uint        RequiredBufferLength);

    [DllImport(NTDLL)]
    public static extern int NtFlushKey(IntPtr KeyHandle);

    [DllImport(NTDLL)]
    public static extern int NtRenameKey(
        IntPtr KeyHandle,
        ref UNICODE_STRING NewName);

    // Helpers
    public static uint KeyRead  { get { return KEY_READ; } }
    public static uint KeyWrite { get { return KEY_WRITE; } }
    public static uint KeyAll   { get { return KEY_ALL; } }
    public static uint RegCreatedNew { get { return REG_CREATED_NEW_KEY; } }
    public static uint RegOpenedExisting { get { return REG_OPENED_EXISTING_KEY; } }
}
'@ -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# 3.  Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

# Test counters
$script:PASS = 0
$script:FAIL = 0
$script:SKIP = 0
$log = [System.Collections.Generic.List[string]]::new()

function Log([string]$msg) {
    Write-Host $msg
    $script:log.Add($msg)
}

function Pass([string]$id, [string]$desc) {
    $script:PASS++
    Log("[PASS] $id : $desc")
}
function Fail([string]$id, [string]$desc) {
    $script:FAIL++
    Log("[FAIL] $id : $desc")
}
function Skip([string]$id, [string]$desc) {
    $script:SKIP++
    Log("[SKIP] $id : $desc")
}
function Section([string]$id, [string]$title) {
    Log("")
    Log("-- SECTION $id : $title ")
}

# NT status helpers
function NT_SUCCESS([int]$s) { $s -ge 0 }
$STATUS_NO_MORE_ENTRIES     = [int]0x8000001A
$STATUS_BUFFER_TOO_SMALL    = [int]0xC0000023
$STATUS_BUFFER_OVERFLOW     = [int]0x80000005
$STATUS_OBJECT_NAME_NOT_FOUND = [int]0xC0000034
$STATUS_OBJECT_PATH_NOT_FOUND = [int]0xC000003A

# Pin a string as a UNICODE_STRING on the heap; returns [IntPtr] to pinned block
# Caller must free with Marshal.FreeHGlobal
function MakeUS([string]$s) {
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($s)
    $bufPtr  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 2)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $bufPtr, $bytes.Length)
    [System.Runtime.InteropServices.Marshal]::WriteInt16($bufPtr, $bytes.Length, 0)  # NUL

    $us = [UNICODE_STRING]::new()
    $us.Length        = [uint16]$bytes.Length
    $us.MaximumLength = [uint16]($bytes.Length + 2)
    $us.Buffer        = $bufPtr

    # $usPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
                # [System.Runtime.InteropServices.Marshal]::SizeOf([UNICODE_STRING]))
    $usPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
                [System.Runtime.InteropServices.Marshal]::SizeOf($us))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($us, $usPtr, $false)
    return $usPtr, $bufPtr   # both must be freed
}

# Build an OBJECT_ATTRIBUTES structure
# Returns [IntPtr] to pinned OA; caller must free all pointers returned
function MakeOA([string]$ntPath, [IntPtr]$root = [IntPtr]::Zero) {
    $usPtrs  = MakeUS $ntPath
    $usPtr   = $usPtrs[0]
    $bufPtr  = $usPtrs[1]

    $oa = [OBJECT_ATTRIBUTES]::new()
    # $oa.Length                   = [System.Runtime.InteropServices.Marshal]::SizeOf([OBJECT_ATTRIBUTES])
    $oa.Length                   = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory            = $root
    $oa.ObjectName               = $usPtr
    $oa.Attributes               = [OBJECT_ATTRIBUTES]::OBJ_CASE_INSENSITIVE
    $oa.SecurityDescriptor       = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero

    $oaPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa.Length)
    
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa, $oaPtr, $false)
    return $oaPtr, $usPtr, $bufPtr  # caller frees all three
}

function FreeAll([IntPtr[]]$ptrs) {
    foreach ($p in $ptrs) {
        if ($p -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($p)
        }
    }
}

# Open an NT registry key; returns handle or [IntPtr]::Zero on failure
# function NtOpen([string]$ntPath, [uint32]$access = 0x20019) {
#     $ptrs = MakeOA $ntPath
#     try {
#         $h = [IntPtr]::Zero
#         $st = [NtReg]::NtOpenKey([ref]$h, $access, [ref][System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [OBJECT_ATTRIBUTES]))
#         if (NT_SUCCESS $st) { return $h }
#         return [IntPtr]::Zero
#     } finally {
#         FreeAll $ptrs
#     }
# }

# Open an NT registry key; returns handle or [IntPtr]::Zero on failure
function NtOpen([string]$ntPath, [uint32]$access = 0x20019) {
    $ptrs = MakeOA $ntPath
    try {
        $h = [IntPtr]::Zero
        # Force the Type overload and extract to a variable
        $oa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [type][OBJECT_ATTRIBUTES])
        $st = [NtReg]::NtOpenKey([ref]$h, $access, [ref]$oa)
        if (NT_SUCCESS $st) { return $h }
        return [IntPtr]::Zero
    } finally {
        FreeAll $ptrs
    }
}

# Create an NT key; returns [handle, disposition] or [Zero, 0] on failure
# function NtCreate([string]$ntPath, [uint32]$access = 0xF003F) {
#     $ptrs = MakeOA $ntPath
#     try {
#         $h    = [IntPtr]::Zero
#         $disp = [uint32]0
#         $st   = [NtReg]::NtCreateKey([ref]$h, $access, [ref][System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [OBJECT_ATTRIBUTES]),
#                                       0, [IntPtr]::Zero, 0, [ref]$disp)
#         if (NT_SUCCESS $st) { return $h, $disp }
#         # return [IntPtr]::Zero, 0u
#         return [IntPtr]::Zero, [uint32]0
#     } finally {
#         FreeAll $ptrs
#     }
# }

# Create an NT key; returns [handle, disposition] or [Zero, 0] on failure
function NtCreate([string]$ntPath, [uint32]$access = 0xF003F) {
    $ptrs = MakeOA $ntPath
    try {
        $h    = [IntPtr]::Zero
        $disp = [uint32]0
        # Force the Type overload and extract to a variable
        $oa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [type][OBJECT_ATTRIBUTES])
        $st   = [NtReg]::NtCreateKey([ref]$h, $access, [ref]$oa, 0, [IntPtr]::Zero, 0, [ref]$disp)
        if (NT_SUCCESS $st) { return $h, $disp }
        return [IntPtr]::Zero, [uint32]0
    } finally {
        FreeAll $ptrs
    }
}

# Close an NT handle safely
function NtSafeClose([IntPtr]$h) {
    if ($h -ne [IntPtr]::Zero) { [NtReg]::NtClose($h) | Out-Null }
}

# Get KeyFullInformation for an open handle; returns hashtable or $null
function QueryKeyFull([IntPtr]$h) {
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(512)
    try {
        $resLen = 0
        $st = [NtReg]::NtQueryKey($h, [int][KEY_INFORMATION_CLASS]::KeyFullInformation,
                                    $buf, 512, [ref]$resLen)
        if ($st -eq $STATUS_BUFFER_TOO_SMALL -or $st -eq $STATUS_BUFFER_OVERFLOW) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
            $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
            $st  = [NtReg]::NtQueryKey($h, [int][KEY_INFORMATION_CLASS]::KeyFullInformation,
                                         $buf, $resLen + 8, [ref]$resLen)
        }
        if (-not (NT_SUCCESS $st)) { return $null }
        $fi = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buf, [type][KEY_FULL_INFORMATION_FIXED])
        return @{ SubKeys = $fi.SubKeys; Values = $fi.Values
                  MaxNameLen = $fi.MaxNameLen; MaxValueNameLen = $fi.MaxValueNameLen
                  MaxValueDataLen = $fi.MaxValueDataLen }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
}

# Collect all subkey names via NtEnumerateKey
function EnumSubkeys([IntPtr]$h) {
    $names = [System.Collections.Generic.List[string]]::new()
    $buf   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(2048)
    try {
        for ($idx = [uint32]0; ; $idx++) {
            $resLen = 0
            $st = [NtReg]::NtEnumerateKey($h, $idx,
                    [int][KEY_INFORMATION_CLASS]::KeyBasicInformation,
                    $buf, 2048, [ref]$resLen)
            if ($st -eq $STATUS_BUFFER_TOO_SMALL -or $st -eq $STATUS_BUFFER_OVERFLOW) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
                $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
                $st  = [NtReg]::NtEnumerateKey($h, $idx,
                         [int][KEY_INFORMATION_CLASS]::KeyBasicInformation,
                         $buf, $resLen + 8, [ref]$resLen)
            }
            if (-not (NT_SUCCESS $st)) { break }
            # KeyBasicInformation: [LARGE_INTEGER LastWriteTime][ULONG TitleIndex][ULONG NameLength][WCHAR Name[1]]
            $nameLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 12)  # offset 12 = sizeof(LARGE_INTEGER)+sizeof(ULONG)
            $namePtr = [IntPtr]($buf.ToInt64() + 16)  # offset 16
            $name    = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr, $nameLen / 2)
            $names.Add($name)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
    return $names
}

# Collect all value names via NtEnumerateValueKey
function EnumValues([IntPtr]$h) {
    $names = [System.Collections.Generic.List[string]]::new()
    $buf   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(2048)
    try {
        for ($idx = [uint32]0; ; $idx++) {
            $resLen = 0
            $st = [NtReg]::NtEnumerateValueKey($h, $idx,
                    [int][KEY_VALUE_INFORMATION_CLASS]::KeyValueBasicInformation,
                    $buf, 2048, [ref]$resLen)
            if ($st -eq $STATUS_BUFFER_TOO_SMALL -or $st -eq $STATUS_BUFFER_OVERFLOW) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
                $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
                $st  = [NtReg]::NtEnumerateValueKey($h, $idx,
                         [int][KEY_VALUE_INFORMATION_CLASS]::KeyValueBasicInformation,
                         $buf, $resLen + 8, [ref]$resLen)
            }
            if (-not (NT_SUCCESS $st)) { break }
            # KeyValueBasicInformation: [ULONG TitleIndex][ULONG Type][ULONG NameLength][WCHAR Name[1]]
            $nameLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 8)  # offset 8
            $namePtr = [IntPtr]($buf.ToInt64() + 12)
            $name    = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr, $nameLen / 2)
            $names.Add($name)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
    return $names
}

# Query a named value (KeyValuePartialInformation); returns [type, bytes] or $null
function QueryValue([IntPtr]$h, [string]$valueName) {
    $usPtrs = MakeUS $valueName
    try {
        $us = [System.Runtime.InteropServices.Marshal]::PtrToStructure($usPtrs[0], [type][UNICODE_STRING])
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
        try {
            $resLen = 0
            $st = [NtReg]::NtQueryValueKey($h, [ref]$us,
                    [int][KEY_VALUE_INFORMATION_CLASS]::KeyValuePartialInformation,
                    $buf, 1024, [ref]$resLen)
            if ($st -eq $STATUS_BUFFER_TOO_SMALL -or $st -eq $STATUS_BUFFER_OVERFLOW) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
                $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
                $st  = [NtReg]::NtQueryValueKey($h, [ref]$us,
                         [int][KEY_VALUE_INFORMATION_CLASS]::KeyValuePartialInformation,
                         $buf, $resLen + 8, [ref]$resLen)
            }
            if (-not (NT_SUCCESS $st)) { return $null }
            # Partial: [ULONG TitleIndex][ULONG Type][ULONG DataLength][BYTE Data[1]]
            $type    = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 4)
            $dataLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 8)
            $data    = [byte[]]::new([Math]::Max(0, $dataLen))
            if ($dataLen -gt 0) {
                [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($buf.ToInt64() + 12), $data, 0, $dataLen)
            }
            return @{ Type = $type; Data = $data }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    } finally {
        FreeAll $usPtrs
    }
}

# Write a REG_SZ value
function SetValueSZ([IntPtr]$h, [string]$name, [string]$value) {
    $usPtrs = MakeUS $name
    try {
        $us = [System.Runtime.InteropServices.Marshal]::PtrToStructure($usPtrs[0], [type][UNICODE_STRING])
        $data = [System.Text.Encoding]::Unicode.GetBytes($value + "`0")  # include NUL terminator
        return [NtReg]::NtSetValueKey($h, [ref]$us, 0, 1, $data, [uint32]$data.Length)  # type 1 = REG_SZ
    } finally {
        FreeAll $usPtrs
    }
}

# Delete a named value
function DeleteValue([IntPtr]$h, [string]$name) {
    $usPtrs = MakeUS $name
    try {
        $us = [System.Runtime.InteropServices.Marshal]::PtrToStructure($usPtrs[0], [type][UNICODE_STRING])
        return [NtReg]::NtDeleteValueKey($h, [ref]$us)
    } finally {
        FreeAll $usPtrs
    }
}

# Read REG_SZ value as string
function ReadSZ([IntPtr]$h, [string]$name) {
    $res = QueryValue $h $name
    if ($null -eq $res) { return $null }
    if ($res.Type -ne 1) { return $null }   # not REG_SZ
    $s = [System.Text.Encoding]::Unicode.GetString($res.Data)
    return $s.TrimEnd([char]0)
}

# ─────────────────────────────────────────────────────────────────────────────
# 4.  Test execution
# ─────────────────────────────────────────────────────────────────────────────

Log "================================================================"
Log "  VirtRegTest-NtLevel.ps1 - Direct NT API Tests"
Log "  VirtStore (NT): $VirtNtBase"
Log "  NtBase   (NT): $NtBase"
Log "================================================================"
Log ""

# ─── SECTION NA: NtCreateKey / NtOpenKey ─────────────────────────────────────
Section "NA" "NtCreateKey and NtOpenKey"

# NA-01: Create a brand-new virtual key and confirm disposition = REG_CREATED_NEW_KEY
$newPath = "$NtBase\NtNewKey_NA01"
$res = NtCreate $newPath
$hNew = $res[0]; $disp = $res[1]
if ($hNew -ne [IntPtr]::Zero) {
    if ($disp -eq [NtReg]::RegCreatedNew) {
        Pass "NA-01" "NtCreateKey new key: disposition=REG_CREATED_NEW_KEY ($disp)"
    } else {
        Fail "NA-01" "NtCreateKey new key: disposition=$disp (expected REG_CREATED_NEW_KEY=$([NtReg]::RegCreatedNew))"
    }
    NtSafeClose $hNew
} else {
    Fail "NA-01" "NtCreateKey new key: FAILED (handle is null)"
}

# NA-02: Re-open the same virtual key, disposition = REG_OPENED_EXISTING_KEY
$res2 = NtCreate $newPath
$hExist = $res2[0]; $disp2 = $res2[1]
if ($hExist -ne [IntPtr]::Zero) {
    if ($disp2 -eq [NtReg]::RegOpenedExisting) {
        Pass "NA-02" "NtCreateKey existing virtual key: disposition=REG_OPENED_EXISTING_KEY ($disp2)"
    } else {
        Fail "NA-02" "NtCreateKey existing virtual key: disposition=$disp2 (expected $([NtReg]::RegOpenedExisting))"
    }
    NtSafeClose $hExist
} else {
    Fail "NA-02" "NtCreateKey existing virtual key: FAILED"
}

# NA-03: NtOpenKey on new virtual key succeeds
$hOpen = NtOpen $newPath
if ($hOpen -ne [IntPtr]::Zero) {
    Pass "NA-03" "NtOpenKey on newly created virtual key: OK"
    NtSafeClose $hOpen
} else {
    Fail "NA-03" "NtOpenKey on newly created virtual key: FAILED"
}

# NA-04: NtCreateKey on an EXISTING REAL key → CoW → disposition = REG_OPENED_EXISTING_KEY
$realSeedPath = "$NtBase\SeedKey"
$res3 = NtCreate $realSeedPath
$hCoW = $res3[0]; $disp3 = $res3[1]
if ($hCoW -ne [IntPtr]::Zero) {
    if ($disp3 -eq [NtReg]::RegOpenedExisting) {
        Pass "NA-04" "NtCreateKey on real key (CoW): disposition=REG_OPENED_EXISTING_KEY"
    } else {
        Fail "NA-04" "NtCreateKey on real key (CoW): disposition=$disp3 (expected REG_OPENED_EXISTING_KEY)"
    }
    NtSafeClose $hCoW
} else {
    Fail "NA-04" "NtCreateKey on real key (CoW): FAILED (key should be openable)"
}

# NA-05: NtOpenKey on a non-existent virtual key returns NOT_FOUND (not 0)
$missingPath = "$NtBase\NtNonExistentKey_99999"
$hMiss = NtOpen $missingPath
if ($hMiss -eq [IntPtr]::Zero) {
    Pass "NA-05" "NtOpenKey on non-existent key: returns failure (handle is null)"
} else {
    Fail "NA-05" "NtOpenKey on non-existent key: unexpectedly SUCCEEDED"
    NtSafeClose $hMiss
}

# NA-06: Hive root itself must NOT be virtualized (HKCU root = \Registry\User\<SID>)
#         Opening the hive root returns the REAL hive root handle, not a virtual one.
#         If the root were virtualized, it would return the VirtStore root, which
#         would have completely wrong metadata (wrong subkeys, etc.)
$id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $id.User.Value
$hkcuRoot = "\Registry\User\$sid"
$hRoot = NtOpen $hkcuRoot
if ($hRoot -ne [IntPtr]::Zero) {
    # Query name - must contain the actual SID, NOT VirtStore prefix
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
    $resLen = 0
    $st = [NtReg]::NtQueryKey($hRoot, [int][KEY_INFORMATION_CLASS]::KeyNameInformation,
                               $buf, 1024, [ref]$resLen)
    if (NT_SUCCESS $st) {
        # KeyNameInformation: [ULONG NameLength][WCHAR Name[1]]
        $nameLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
        $namePtr = [IntPtr]($buf.ToInt64() + 4)
        $keyName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr, $nameLen / 2)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        if ($keyName -imatch [System.Text.RegularExpressions.Regex]::Escape($sid)) {
            Pass "NA-06" "HKCU root handle is NOT virtualized (NtQueryKey name contains SID)"
        } else {
            Fail "NA-06" "HKCU root handle may be virtualized: NtQueryKey name='$keyName' (expected SID $sid)"
        }
    } else {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        Skip "NA-06" "NtQueryKey on HKCU root failed (st=0x$($st.ToString('X8')))"
    }
    NtSafeClose $hRoot
} else {
    Fail "NA-06" "NtOpenKey on HKCU root FAILED (should always succeed)"
}

# ─── SECTION NB: NtSetValueKey / NtQueryValueKey ─────────────────────────────
Section "NB" "NtSetValueKey and NtQueryValueKey"

# NB-01: Write REG_SZ to a virtual-only key, read back
$wPath = "$NtBase\NtWriteTest_NB"
$res = NtCreate $wPath
$hW = $res[0]
if ($hW -ne [IntPtr]::Zero) {
    $st = SetValueSZ $hW "NtTestVal" "NtWritten_Value_1"
    if (NT_SUCCESS $st) {
        $val = ReadSZ $hW "NtTestVal"
        if ($val -eq "NtWritten_Value_1") {
            Pass "NB-01" "NtSetValueKey + NtQueryValueKey same handle: write+read OK"
        } else {
            Fail "NB-01" "NtQueryValueKey returned '$val' (expected 'NtWritten_Value_1')"
        }
    } else {
        Fail "NB-01" "NtSetValueKey FAILED (st=0x$($st.ToString('X8')))"
    }
    NtSafeClose $hW

    # Re-open the key and verify value persisted (close/reopen cycle)
    $hR2 = NtOpen $wPath
    if ($hR2 -ne [IntPtr]::Zero) {
        $val2 = ReadSZ $hR2 "NtTestVal"
        if ($val2 -eq "NtWritten_Value_1") {
            Pass "NB-02" "NtQueryValueKey after close+reopen: value persisted"
        } else {
            Fail "NB-02" "NtQueryValueKey after close+reopen: got '$val2'"
        }
        NtSafeClose $hR2
    } else {
        Fail "NB-02" "NtOpenKey after close: FAILED"
    }
} else {
    Fail "NB-01" "NtCreateKey for write test FAILED"
    Skip "NB-02" "Skipped (NB-01 failed)"
}

# NB-03: Write to a real key (CoW) - virtual value overrides real
$hCoW = (NtCreate $realSeedPath)[0]
if ($hCoW -ne [IntPtr]::Zero) {
    $st = SetValueSZ $hCoW "NtCoWVal" "NtCoW_Override"
    if (NT_SUCCESS $st) {
        $val = ReadSZ $hCoW "NtCoWVal"
        if ($val -eq "NtCoW_Override") {
            Pass "NB-03" "NtSetValueKey on CoW handle: write+read from same handle OK"
        } else {
            Fail "NB-03" "NtSetValueKey on CoW: got '$val'"
        }
    } else {
        Fail "NB-03" "NtSetValueKey on CoW handle FAILED (st=0x$($st.ToString('X8')))"
    }

    # NB-04: Real-only value still readable via CoW handle
    $realVal = ReadSZ $hCoW "RealStrVal"
    if ($realVal -eq "REAL_STRING_ORIGINAL") {
        Pass "NB-04" "NtQueryValueKey: real-only value readable via CoW handle (merge fallback works)"
    } else {
        Fail "NB-04" "NtQueryValueKey CoW fallback: got '$realVal' (expected 'REAL_STRING_ORIGINAL')"
    }

    # NB-05: Re-open and virtual value (NtCoWVal) persists; real value still readable
    NtSafeClose $hCoW
    $hReopen = NtOpen $realSeedPath
    if ($hReopen -ne [IntPtr]::Zero) {
        $cowPersist = ReadSZ $hReopen "NtCoWVal"
        $realPersist = ReadSZ $hReopen "RealStrVal"
        if ($cowPersist -eq "NtCoW_Override") {
            Pass "NB-05a" "CoW value persists after close+reopen of key"
        } else {
            Fail "NB-05a" "CoW value LOST after close+reopen (got '$cowPersist')"
        }
        if ($realPersist -eq "REAL_STRING_ORIGINAL") {
            Pass "NB-05b" "Real value still readable after close+reopen of CoW key"
        } else {
            Fail "NB-05b" "Real value changed after close+reopen (got '$realPersist')"
        }
        NtSafeClose $hReopen
    } else {
        Fail "NB-05a" "NtOpenKey for reopen check FAILED"
        Skip "NB-05b" "Skipped"
    }
} else {
    Fail "NB-03" "NtCreateKey on real SeedKey FAILED"
    Skip "NB-04" "Skipped"; Skip "NB-05a" "Skipped"; Skip "NB-05b" "Skipped"
}

# NB-06: NtQueryValueKey on a key opened READ-ONLY works for real values
$hRO = NtOpen $realSeedPath ([NtReg]::KeyRead)
if ($hRO -ne [IntPtr]::Zero) {
    $roVal = ReadSZ $hRO "RealStrVal"
    if ($roVal -eq "REAL_STRING_ORIGINAL") {
        Pass "NB-06" "NtQueryValueKey on read-only handle: real value readable"
    } else {
        Fail "NB-06" "NtQueryValueKey read-only: got '$roVal'"
    }
    NtSafeClose $hRO
} else {
    Fail "NB-06" "NtOpenKey read-only on real key FAILED"
}

# ─── SECTION NC: NtEnumerateKey - Merge correctness ──────────────────────────
Section "NC" "NtEnumerateKey - Merge Correctness"

# Setup: ensure MergeParent has RealSubA, RealSubB in real; create VirtSubD, VirtSubE in virt
$mpPath = "$NtBase\MergeParent"
$hMP = (NtCreate $mpPath)[0]
if ($hMP -ne [IntPtr]::Zero) {
    # Create virtual subkeys via NT (not reg.exe)
    @("VirtSubD_NT","VirtSubE_NT") | ForEach-Object {
        $sub = (NtCreate "$mpPath\$_")
        NtSafeClose $sub[0]
    }

    $names = EnumSubkeys $hMP
    NtSafeClose $hMP

    # NC-01: Both real subkeys visible
    $hasRA = $names | Where-Object { $_ -ieq "RealSubA" }
    $hasRB = $names | Where-Object { $_ -ieq "RealSubB" }
    if ($hasRA -and $hasRB) {
        Pass "NC-01" "NtEnumerateKey: real subkeys RealSubA and RealSubB visible in merged listing"
    } else {
        Fail "NC-01" "NtEnumerateKey: real subkeys missing (RealSubA=$($null -ne $hasRA) RealSubB=$($null -ne $hasRB)). Found: $($names -join ', ')"
    }

    # NC-02: Virtual subkeys visible
    $hasVD = $names | Where-Object { $_ -ieq "VirtSubD_NT" }
    $hasVE = $names | Where-Object { $_ -ieq "VirtSubE_NT" }
    if ($hasVD -and $hasVE) {
        Pass "NC-02" "NtEnumerateKey: virtual subkeys VirtSubD_NT and VirtSubE_NT visible"
    } else {
        Fail "NC-02" "NtEnumerateKey: virtual subkeys missing (D=$($null -ne $hasVD) E=$($null -ne $hasVE))"
    }

    # NC-03: No duplicates
    $dupes = $names | Group-Object { $_.ToUpper() } | Where-Object { $_.Count -gt 1 }
    if (-not $dupes) {
        Pass "NC-03" "NtEnumerateKey: no duplicate subkey names in merged listing"
    } else {
        Fail "NC-03" "NtEnumerateKey: DUPLICATES found: $($dupes.Name -join ', ')"
    }

    # NC-04: Total count is real (2) + virt (2) = 4 minimum
    if ($names.Count -ge 4) {
        Pass "NC-04" "NtEnumerateKey: total count $($names.Count) >= 4 (merged 2 real + 2 virt)"
    } else {
        Fail "NC-04" "NtEnumerateKey: total count $($names.Count) < 4 (merge incomplete)"
    }

    # NC-05: Index continuity - no index should return NOT_FOUND before all names are exhausted
    $hMP2 = NtOpen $mpPath
    if ($hMP2 -ne [IntPtr]::Zero) {
        $gapFound = $false
        $prevFailed = $false
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
        for ($i = [uint32]0; $i -lt [uint32]($names.Count + 2); $i++) {
            $resLen = 0
            $st = [NtReg]::NtEnumerateKey($hMP2, $i,
                    [int][KEY_INFORMATION_CLASS]::KeyBasicInformation,
                    $buf, 1024, [ref]$resLen)
            $isEnd = ($st -eq $STATUS_NO_MORE_ENTRIES)
            if ($isEnd -and $i -lt [uint32]$names.Count) {
                $gapFound = $true
                break
            }
            if ($isEnd) { break }
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        NtSafeClose $hMP2
        if (-not $gapFound) {
            Pass "NC-05" "NtEnumerateKey index continuity: no gap before end marker"
        } else {
            Fail "NC-05" "NtEnumerateKey index gap: NO_MORE_ENTRIES at index < $($names.Count)"
        }
    } else {
        Skip "NC-05" "NtOpenKey for continuity check failed"
    }
} else {
    Fail "NC-01" "NtCreateKey MergeParent FAILED - cannot run NC-0x tests"
    "NC-02","NC-03","NC-04","NC-05" | ForEach-Object { Skip $_ "Skipped (NC-01 failed)" }
}

# ─── SECTION ND: NtEnumerateValueKey - Merge correctness ─────────────────────
Section "ND" "NtEnumerateValueKey - Merge Correctness"

# ShadowKey has: ShadowedVal (real+virt), RealOnlyVal (real), AnotherReal (real), VirtOnlyInShadow (virt)
$skPath = "$NtBase\ShadowKey"

# Write the virtual values first (they may have been written by the .bat already, but re-do to be safe)
$hSK = (NtCreate $skPath)[0]
if ($hSK -ne [IntPtr]::Zero) {
    SetValueSZ $hSK "ShadowedVal"     "VIRT_SHADOW_OVERRIDE" | Out-Null
    SetValueSZ $hSK "VirtOnlyInShadow" "VIRT_ONLY_NT"        | Out-Null
    NtSafeClose $hSK
}

$hSK2 = NtOpen $skPath
if ($hSK2 -ne [IntPtr]::Zero) {
    $vnames = EnumValues $hSK2
    NtSafeClose $hSK2

    $hasSV  = $vnames | Where-Object { $_ -ieq "ShadowedVal" }
    $hasRO  = $vnames | Where-Object { $_ -ieq "RealOnlyVal" }
    $hasAR  = $vnames | Where-Object { $_ -ieq "AnotherReal" }
    $hasVO  = $vnames | Where-Object { $_ -ieq "VirtOnlyInShadow" }

    if ($hasSV) { Pass "ND-01" "NtEnumerateValueKey: ShadowedVal present" }
    else         { Fail "ND-01" "NtEnumerateValueKey: ShadowedVal MISSING" }

    if ($hasRO) { Pass "ND-02" "NtEnumerateValueKey: RealOnlyVal present (real fallback)" }
    else         { Fail "ND-02" "NtEnumerateValueKey: RealOnlyVal MISSING (merge broken)" }

    if ($hasAR) { Pass "ND-03" "NtEnumerateValueKey: AnotherReal present (real fallback)" }
    else         { Fail "ND-03" "NtEnumerateValueKey: AnotherReal MISSING (merge broken)" }

    if ($hasVO) { Pass "ND-04" "NtEnumerateValueKey: VirtOnlyInShadow present (virt-only)" }
    else         { Fail "ND-04" "NtEnumerateValueKey: VirtOnlyInShadow MISSING" }

    # ND-05: ShadowedVal must appear ONCE (no duplicate for virtual+real)
    $svCount = @($vnames | Where-Object { $_ -ieq "ShadowedVal" }).Count
    if ($svCount -le 1) {
        Pass "ND-05" "NtEnumerateValueKey: ShadowedVal appears $svCount time (no duplicate)"
    } else {
        Fail "ND-05" "NtEnumerateValueKey: ShadowedVal DUPLICATED (appears $svCount times!)"
    }

    # ND-06: Total count: expect 4 (ShadowedVal, RealOnlyVal, AnotherReal, VirtOnlyInShadow)
    if ($vnames.Count -ge 4) {
        Pass "ND-06" "NtEnumerateValueKey: total $($vnames.Count) values >= 4 (merged)"
    } else {
        Fail "ND-06" "NtEnumerateValueKey: only $($vnames.Count) values (expected >=4, merge broken)"
    }
} else {
    "ND-01","ND-02","ND-03","ND-04","ND-05","ND-06" | ForEach-Object {
        Fail $_ "NtOpenKey ShadowKey FAILED - cannot test"
    }
}

# ─── SECTION NE: NtQueryKey - Count Accuracy ─────────────────────────────────
Section "NE" "NtQueryKey - SubKeys/Values Count Accuracy"
# Log "  NOTE: NtQueryKey KeyFullInformation count merge is implemented."
# Log "  Hook_NtQueryKey deduplicates subkey and value names across both"
# Log "  the virtual and real handles and reports the merged count."
# Log "  RegQueryInfoKey / RegistryKey.SubKeyCount now return correct merged"
# Log "  counts when real and virtual entries coexist."
# Log ""

# NE-01: ShadowKey - merged handle should report all values (virt+real dedup)
$hNE1 = NtOpen $skPath
if ($hNE1 -ne [IntPtr]::Zero) {
    $fi = QueryKeyFull $hNE1
    NtSafeClose $hNE1
    if ($null -ne $fi) {
        $reportedVals = $fi.Values
        Log "  [NE-01] NtQueryKey(ShadowKey).Values = $reportedVals  (merged should be >=4)"
        if ($reportedVals -ge 4) {
            Pass "NE-01" "NtQueryKey: ShadowKey value count=$reportedVals >= 4 (merged count correct)"
        } elseif ($reportedVals -eq 2) {
            Fail "NE-01" "NtQueryKey: ShadowKey.Values=$reportedVals < 4 (merged count wrong)"
        } else {
            Fail "NE-01" "NtQueryKey: ShadowKey.Values=$reportedVals (unexpected partial count; expected >=4)"
        }
    } else {
        Fail "NE-01" "QueryKeyFull on ShadowKey FAILED"
    }
}

# NE-02: MergeParent - merged handle should report all subkeys (VirtSubD_NT, VirtSubE_NT + real)
$hNE2 = NtOpen $mpPath
if ($hNE2 -ne [IntPtr]::Zero) {
    $fi2 = QueryKeyFull $hNE2
    NtSafeClose $hNE2
    if ($null -ne $fi2) {
        $reportedSubs = $fi2.SubKeys
        Log "  [NE-02] NtQueryKey(MergeParent).SubKeys = $reportedSubs  (merged should be >=4)"
        if ($reportedSubs -ge 4) {
            Pass "NE-02" "NtQueryKey: MergeParent SubKeys=$reportedSubs >= 4 (merged count correct)"
        } elseif ($reportedSubs -le 2) {
            Fail "NE-02" "NtQueryKey: MergeParent.SubKeys=$reportedSubs < 4 (merged count wrong)"
        } else {
            Fail "NE-02" "NtQueryKey: MergeParent.SubKeys=$reportedSubs (partial, expected >=4)"
        }
    } else {
        Fail "NE-02" "QueryKeyFull on MergeParent FAILED"
    }
}

# NE-03: KeyNameInformation on virtual handle returns logical path (not virtual store path)
$hNE3 = NtOpen $realSeedPath
if ($hNE3 -ne [IntPtr]::Zero) {
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(2048)
    $resLen = 0
    $st = [NtReg]::NtQueryKey($hNE3, [int][KEY_INFORMATION_CLASS]::KeyNameInformation,
                               $buf, 2048, [ref]$resLen)
    if (NT_SUCCESS $st) {
        $nameLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
        $namePtr = [IntPtr]($buf.ToInt64() + 4)
        $keyName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr, $nameLen / 2)
        Log "  [NE-03] NtQueryKey(SeedKey, KeyNameInformation) = '$keyName'"
        # The hook passes NtQueryKey through to the virtual handle, so the name
        # is the virtual store path. The test also accepts the logical path in case
        # a future implementation translates it back; either correctly identifies the key.
        $isVirtPath   = $keyName -imatch [System.Text.RegularExpressions.Regex]::Escape("VirtRegTest_Store_2026")
        $isLogicPath  = $keyName -imatch [System.Text.RegularExpressions.Regex]::Escape("VirtRegTestReal_2026")
        if ($isVirtPath) {
            Pass "NE-03" "NtQueryKey KeyNameInformation returns virtual store path (expected for virtual handle)"
        } elseif ($isLogicPath) {
            Pass "NE-03" "NtQueryKey KeyNameInformation returns logical path - hook translates name back"
        } else {
            Fail "NE-03" "NtQueryKey KeyNameInformation: unexpected path '$keyName'"
        }
    } else {
        Fail "NE-03" "NtQueryKey KeyNameInformation FAILED (st=0x$($st.ToString('X8')))"
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    NtSafeClose $hNE3
} else {
    Fail "NE-03" "NtOpenKey SeedKey for NE-03 FAILED"
}

# ─── SECTION NF: NtDeleteKey and NtDeleteValueKey ────────────────────────────
Section "NF" "NtDeleteKey and NtDeleteValueKey"

# NF-01: Delete a virtual-only key via NT API
$delVirtPath = "$NtBase\NtDeleteVirtOnly"
$hDV = (NtCreate $delVirtPath)[0]
if ($hDV -ne [IntPtr]::Zero) {
    $stDel = [NtReg]::NtDeleteKey($hDV)
    NtSafeClose $hDV
    if (NT_SUCCESS $stDel) {
        $hCheck = NtOpen $delVirtPath
        if ($hCheck -eq [IntPtr]::Zero) {
            Pass "NF-01" "NtDeleteKey on virtual-only key: key gone after delete"
        } else {
            Fail "NF-01" "NtDeleteKey on virtual-only key: key STILL ACCESSIBLE after delete!"
            NtSafeClose $hCheck
        }
    } else {
        Fail "NF-01" "NtDeleteKey on virtual-only key: delete FAILED (st=0x$($stDel.ToString('X8')))"
    }
} else {
    Fail "NF-01" "NtCreateKey for NF-01 FAILED"
}

# NF-02: Delete a virtual-only value
$delValPath = "$NtBase\NtDeleteValTest"
$hDVV = (NtCreate $delValPath)[0]
if ($hDVV -ne [IntPtr]::Zero) {
    SetValueSZ $hDVV "ToDelete" "delete_me" | Out-Null
    $stDelV = DeleteValue $hDVV "ToDelete"
    if (NT_SUCCESS $stDelV) {
        $gone = QueryValue $hDVV "ToDelete"
        if ($null -eq $gone) {
            Pass "NF-02" "NtDeleteValueKey on virtual-only value: value gone same handle"
        } else {
            Fail "NF-02" "NtDeleteValueKey: virtual-only value STILL READABLE same handle"
        }
    } else {
        Fail "NF-02" "NtDeleteValueKey FAILED (st=0x$($stDelV.ToString('X8')))"
    }
    NtSafeClose $hDVV

    # NF-02b: after close+reopen, value must still be gone
    $hDVV2 = NtOpen $delValPath
    if ($hDVV2 -ne [IntPtr]::Zero) {
        $gone2 = QueryValue $hDVV2 "ToDelete"
        if ($null -eq $gone2) {
            Pass "NF-02b" "NtDeleteValueKey: value stays gone after close+reopen"
        } else {
            Fail "NF-02b" "NtDeleteValueKey: value REAPPEARS after close+reopen (ToDelete)"
        }
        NtSafeClose $hDVV2
    }
} else {
    Fail "NF-02" "NtCreateKey for NF-02 FAILED"
    Skip "NF-02b" "Skipped"
}

# NF-03: NtDeleteValueKey on a value that exists only in real (via CoW handle)
$hCoWDel = (NtCreate $realSeedPath)[0]
if ($hCoWDel -ne [IntPtr]::Zero) {
    $stDelReal = DeleteValue $hCoWDel "RealDwordVal"
    if (NT_SUCCESS $stDelReal) {
        # Immediate check via same handle (NtQueryValueKey on same virtual handle)
        $imm = QueryValue $hCoWDel "RealDwordVal"
        if ($null -eq $imm) {
            Pass "NF-03" "NtDeleteValueKey on real-only value: not found via same handle (immediate)"
        } else {
            Fail "NF-03" "NtDeleteValueKey on real-only value: still found via same handle!"
        }
    } else {
        Fail "NF-03" "NtDeleteValueKey on real-only value: delete FAILED (st=0x$($stDelReal.ToString('X8')))"
    }
    NtSafeClose $hCoWDel

    # NF-03b: After close+reopen, tombstone ensures RealDwordVal stays deleted
    $hReopenDel = NtOpen $realSeedPath
    if ($hReopenDel -ne [IntPtr]::Zero) {
        $reapp = QueryValue $hReopenDel "RealDwordVal"
        if ($null -eq $reapp) {
            Pass "NF-03b" "NtDeleteValueKey real-only: stays deleted on re-open (tombstone works)"
        } else {
            Fail "NF-03b" "NtDeleteValueKey real-only: value reappears on re-open (tombstone broken)"
        }
        NtSafeClose $hReopenDel
    } else {
        Skip "NF-03b" "NtOpenKey for reopen check FAILED"
    }
} else {
    Fail "NF-03" "NtCreateKey on real SeedKey for NF-03 FAILED"
    Skip "NF-03b" "Skipped"
}

# NF-04: NtDeleteKey on a real-only key - tombstone prevents re-appearance on re-open
$realOnlyKeyPath = "$NtBase\DeleteTarget"
$hDelRK = NtOpen $realOnlyKeyPath
if ($hDelRK -ne [IntPtr]::Zero) {
    $stDelRK = [NtReg]::NtDeleteKey($hDelRK)
    NtSafeClose $hDelRK
    if (NT_SUCCESS $stDelRK) {
        # Immediate: new open attempt
        $hCheckRK = NtOpen $realOnlyKeyPath
        if ($hCheckRK -eq [IntPtr]::Zero) {
            Pass "NF-04" "NtDeleteKey real-only key: gone on immediate re-open"
        } else {
            Fail "NF-04" "NtDeleteKey real-only key: still visible after delete (tombstone broken)"
            NtSafeClose $hCheckRK
        }
    } else {
        Fail "NF-04" "NtDeleteKey on real-only key: delete FAILED (st=0x$($stDelRK.ToString('X8')))"
    }
} else {
    Skip "NF-04" "NtOpenKey on DeleteTarget FAILED (may have been deleted by .bat tests)"
}

# ─── SECTION NG: NtQueryMultipleValueKey ─────────────────────────────────────
Section "NG" "NtQueryMultipleValueKey - Per-Value Merge"
# Log "  NtQueryMultipleValueKey uses per-value fallback merge (fixed)."
# Log "  For each requested value: virtual handle is tried first; if NOT_FOUND"
# Log "  on virtual and value is not tombstoned, the real handle is consulted."
# Log "  A mixed query (some virt-overridden + some real-only) is now handled"
# Log "  correctly: virtual overrides are preserved for overridden values while"
# Log "  real-only values are served from the real handle."
# Log ""

# ShadowKey was populated in Section ND; open it and query two of its values
# via NtQueryMultipleValueKey to verify the per-value merge path.
$mqPath = "$NtBase\ShadowKey"
$hMQ = NtOpen $mqPath
if ($hMQ -ne [IntPtr]::Zero) {
    # Query: ShadowedVal (virt override) and RealOnlyVal (real only)
    # Expected with per-value merge (fixed):
    #   ShadowedVal = VIRT_SHADOW_OVERRIDE  (served from virtual handle)
    #   RealOnlyVal = REAL_ONLY_VALUE        (served from real handle)

    # Build UNICODE_STRING structs for the two value names
    $name1 = "ShadowedVal"
    $name2 = "RealOnlyVal"

    $usPtr1, $bufPtr1 = MakeUS $name1
    $usPtr2, $bufPtr2 = MakeUS $name2

    try {
        $entries = [KEY_VALUE_ENTRY[]]::new(2)
        
        # FIX: Create local struct instances, populate them, THEN assign to the array
        # This bypasses the PowerShell struct-in-array mutation bug.
        $entry0 = [KEY_VALUE_ENTRY]::new()
        $entry0.ValueName  = $usPtr1
        $entry0.DataLength = 0
        $entry0.DataOffset = 0
        $entry0.Type       = 0
        $entries[0] = $entry0

        $entry1 = [KEY_VALUE_ENTRY]::new()
        $entry1.ValueName  = $usPtr2
        $entry1.DataLength = 0
        $entry1.DataOffset = 0
        $entry1.Type       = 0
        $entries[1] = $entry1

        $bufLen = [uint32]512
        $valBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$bufLen)
        $reqLen = [uint32]0

        $stMQ = [NtReg]::NtQueryMultipleValueKey($hMQ, $entries, 2, $valBuf, [ref]$bufLen, [ref]$reqLen)

        if (NT_SUCCESS $stMQ) {
            # Read ShadowedVal data (entries[0].DataOffset, entries[0].DataLength)
            $off1 = $entries[0].DataOffset
            $len1 = $entries[0].DataLength
            $data1 = [byte[]]::new($len1)
            [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($valBuf.ToInt64() + $off1), $data1, 0, $len1)
            $str1 = [System.Text.Encoding]::Unicode.GetString($data1).TrimEnd([char]0)

            $off2 = $entries[1].DataOffset
            $len2 = $entries[1].DataLength
            $data2 = [byte[]]::new($len2)
            [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($valBuf.ToInt64() + $off2), $data2, 0, $len2)
            $str2 = [System.Text.Encoding]::Unicode.GetString($data2).TrimEnd([char]0)

            Log "  [NG-01] NtQueryMultipleValueKey results:"
            Log "          ShadowedVal = '$str1' (virt='VIRT_SHADOW_OVERRIDE', real='REAL_SHADOW_ORIGINAL')"
            Log "          RealOnlyVal = '$str2' (should be 'REAL_ONLY_VALUE')"

            if ($str1 -eq "VIRT_SHADOW_OVERRIDE") {
                Pass "NG-01" "NtQueryMultipleValueKey: ShadowedVal returned virtual override value (per-value merge correct)"
            } else {
                Fail "NG-01" "NtQueryMultipleValueKey: ShadowedVal='$str1' (expected VIRT_SHADOW_OVERRIDE - per-value merge failed)"
            }

            if ($str2 -eq "REAL_ONLY_VALUE") {
                Pass "NG-02" "NtQueryMultipleValueKey: RealOnlyVal returned correct real value"
            } else {
                Fail "NG-02" "NtQueryMultipleValueKey: RealOnlyVal='$str2' (expected 'REAL_ONLY_VALUE')"
            }
        } elseif ($stMQ -eq $STATUS_BUFFER_TOO_SMALL) {
            Fail "NG-01" "NtQueryMultipleValueKey: BUFFER_TOO_SMALL (need $reqLen bytes)"
            Skip "NG-02" "Skipped (NG-01 buffer too small)"
        } else {
            Fail "NG-01" "NtQueryMultipleValueKey FAILED (st=0x$($stMQ.ToString('X8')))"
            Skip "NG-02" "Skipped"
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($valBuf)
    } finally {
        FreeAll @($usPtr1, $bufPtr1, $usPtr2, $bufPtr2)
        NtSafeClose $hMQ
    }
} else {
    Fail "NG-01" "NtOpenKey on ShadowKey FAILED"
    Skip "NG-02" "Skipped"
}

# ─── SECTION NH: Buffer-too-small handling ────────────────────────────────────
Section "NH" "Buffer-Too-Small Handling in Merge Path"

# NH-01: NtEnumerateKey with 1-byte buffer → BUFFER_TOO_SMALL, then retry with result size
$hBuf = NtOpen $mpPath
if ($hBuf -ne [IntPtr]::Zero) {
    $tinyBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
    $resLen = 0
    $st1 = [NtReg]::NtEnumerateKey($hBuf, 0,
              [int][KEY_INFORMATION_CLASS]::KeyBasicInformation,
              $tinyBuf, 1, [ref]$resLen)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tinyBuf)

    $isSmall = ($st1 -eq $STATUS_BUFFER_TOO_SMALL -or $st1 -eq $STATUS_BUFFER_OVERFLOW)
    if ($isSmall) {
        # Retry with the reported size
        $propBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
        $resLen2 = 0
        $st2 = [NtReg]::NtEnumerateKey($hBuf, 0,
                   [int][KEY_INFORMATION_CLASS]::KeyBasicInformation,
                   $propBuf, $resLen + 8, [ref]$resLen2)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($propBuf)
        if (NT_SUCCESS $st2) {
            Pass "NH-01" "NtEnumerateKey: tiny-buffer → BUFFER_TOO_SMALL, retry with correct size → OK"
        } else {
            Fail "NH-01" "NtEnumerateKey: tiny-buffer retry with correct size FAILED (st=0x$($st2.ToString('X8')))"
        }
    } else {
        Fail "NH-01" "NtEnumerateKey: 1-byte buffer did NOT return BUFFER_TOO_SMALL (st=0x$($st1.ToString('X8')))"
    }
    NtSafeClose $hBuf
} else {
    Skip "NH-01" "NtOpenKey MergeParent FAILED"
}

# NH-02: NtQueryValueKey with tiny buffer → BUFFER_TOO_SMALL, retry → correct value
$hBuf2 = NtOpen $skPath
if ($hBuf2 -ne [IntPtr]::Zero) {
    $usPtrs = MakeUS "ShadowedVal"
    try {
        $us = [System.Runtime.InteropServices.Marshal]::PtrToStructure($usPtrs[0], [type][UNICODE_STRING])
        $tiny = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
        $resLen = 0
        $stT = [NtReg]::NtQueryValueKey($hBuf2, [ref]$us,
                    [int][KEY_VALUE_INFORMATION_CLASS]::KeyValuePartialInformation,
                    $tiny, 1, [ref]$resLen)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tiny)
        $isSmallV = ($stT -eq $STATUS_BUFFER_TOO_SMALL -or $stT -eq $STATUS_BUFFER_OVERFLOW)
        if ($isSmallV) {
            $propBuf2 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($resLen + 8)
            $resLen3 = 0
            $stR = [NtReg]::NtQueryValueKey($hBuf2, [ref]$us,
                        [int][KEY_VALUE_INFORMATION_CLASS]::KeyValuePartialInformation,
                        $propBuf2, $resLen + 8, [ref]$resLen3)
            if (NT_SUCCESS $stR) {
                $type    = [System.Runtime.InteropServices.Marshal]::ReadInt32($propBuf2, 4)
                $dataLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($propBuf2, 8)
                $data    = [byte[]]::new($dataLen)
                [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($propBuf2.ToInt64() + 12), $data, 0, $dataLen)
                $str = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($propBuf2)
                if ($str -eq "VIRT_SHADOW_OVERRIDE") {
                    Pass "NH-02" "NtQueryValueKey: tiny-buffer → retry → correct value (VIRT_SHADOW_OVERRIDE)"
                } else {
                    Fail "NH-02" "NtQueryValueKey: retry returned wrong value '$str'"
                }
            } else {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($propBuf2)
                Fail "NH-02" "NtQueryValueKey: retry with correct size FAILED (st=0x$($stR.ToString('X8')))"
            }
        } else {
            Fail "NH-02" "NtQueryValueKey: 1-byte buffer did NOT return BUFFER_TOO_SMALL (st=0x$($stT.ToString('X8')))"
        }
    } finally {
        FreeAll $usPtrs
        NtSafeClose $hBuf2
    }
} else {
    Skip "NH-02" "NtOpenKey ShadowKey FAILED"
}

# ─── SECTION NI: Relative-Path Opens (RootDirectory in OBJECT_ATTRIBUTES) ────
Section "NI" "Relative-Path Opens (OBJECT_ATTRIBUTES.RootDirectory)"

# Open a parent key, then use it as RootDirectory to open a child
$hParent = NtOpen $mpPath
if ($hParent -ne [IntPtr]::Zero) {
    # Open "RealSubA" relative to MergeParent handle
    $usPtrs = MakeUS "RealSubA"
    $oa = [OBJECT_ATTRIBUTES]::new()
    $oa.Length                   = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory            = $hParent      # relative to parent
    $oa.ObjectName               = $usPtrs[0]
    $oa.Attributes               = [OBJECT_ATTRIBUTES]::OBJ_CASE_INSENSITIVE
    $oa.SecurityDescriptor       = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero
    $oaPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa, $oaPtr, $false)

    $hChild  = [IntPtr]::Zero
    # Force the Type overload and extract to a variable (PS5.1 binder fix)
    $oa_ni01 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($oaPtr, [type][OBJECT_ATTRIBUTES])
    $stRel   = [NtReg]::NtOpenKey([ref]$hChild, [NtReg]::KeyRead, [ref]$oa_ni01)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oaPtr)
    FreeAll $usPtrs

    if ($hChild -ne [IntPtr]::Zero) {
        Pass "NI-01" "Relative-path open: NtOpenKey(RootDirectory=MergeParent, Name='RealSubA') succeeded"
        NtSafeClose $hChild
    } else {
        Fail "NI-01" "Relative-path open: NtOpenKey(RootDirectory=MergeParent, Name='RealSubA') FAILED (st=0x$($stRel.ToString('X8')))"
    }

    # NI-02: Open a virtual-only subkey via relative open
    $usPtrs2 = MakeUS "VirtSubD_NT"
    $oa2 = [OBJECT_ATTRIBUTES]::new()
    $oa2.Length                   = [System.Runtime.InteropServices.Marshal]::SizeOf($oa2)
    $oa2.RootDirectory            = $hParent
    $oa2.ObjectName               = $usPtrs2[0]
    $oa2.Attributes               = [OBJECT_ATTRIBUTES]::OBJ_CASE_INSENSITIVE
    $oa2.SecurityDescriptor       = [IntPtr]::Zero
    $oa2.SecurityQualityOfService = [IntPtr]::Zero
    $oa2Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa2.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa2, $oa2Ptr, $false)

    $hVirtChild  = [IntPtr]::Zero
    # Force the Type overload and extract to a variable (PS5.1 binder fix)
    $oa2_ni02 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($oa2Ptr, [type][OBJECT_ATTRIBUTES])
    [NtReg]::NtOpenKey([ref]$hVirtChild, [NtReg]::KeyRead, [ref]$oa2_ni02) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oa2Ptr)
    FreeAll $usPtrs2

    if ($hVirtChild -ne [IntPtr]::Zero) {
        Pass "NI-02" "Relative-path open: NtOpenKey(RootDirectory=MergeParent, Name='VirtSubD_NT') succeeded"
        NtSafeClose $hVirtChild
    } else {
        Fail "NI-02" "Relative-path open: NtOpenKey(RootDirectory=MergeParent, Name='VirtSubD_NT') FAILED"
    }

    NtSafeClose $hParent
} else {
    Fail "NI-01" "NtOpenKey MergeParent FAILED - cannot test relative opens"
    Skip "NI-02" "Skipped"
}

# ─── SECTION NJ: NtFlushKey ───────────────────────────────────────────────────
Section "NJ" "NtFlushKey on Virtual Handle"

# NJ-01: NtFlushKey on a virtual key handle must succeed (redirected to virt handle)
$hFlush = NtOpen $mpPath
if ($hFlush -ne [IntPtr]::Zero) {
    $stFlush = [NtReg]::NtFlushKey($hFlush)
    NtSafeClose $hFlush
    if (NT_SUCCESS $stFlush) {
        Pass "NJ-01" "NtFlushKey on virtual key handle: succeeded (st=0x$($stFlush.ToString('X8')))"
    } else {
        Fail "NJ-01" "NtFlushKey on virtual key handle: FAILED (st=0x$($stFlush.ToString('X8')))"
    }
} else {
    Skip "NJ-01" "NtOpenKey MergeParent FAILED"
}

# ─── SECTION NK: HKCU _Classes (per-user HKCR backing hive) ─────────────────
Section "NK" "HKCU\\..._Classes Hive (per-user HKCR backing)"
# Log "  NOTE: HKCR writes go to \Registry\User\<SID>_Classes at NT level."
# Log "  LogicalToVirtual must route <SID>_Classes to HKEY_USERS (catch-all),"
# Log "  NOT to HKEY_CURRENT_USER (SID match with component-boundary check)."
# Log ""

$classPath = "\Registry\User\$sid`_Classes\VirtRegTest_Classes_2026"
$hClass = (NtCreate $classPath)[0]
if ($hClass -ne [IntPtr]::Zero) {
    SetValueSZ $hClass "ClassVal" "class_virt_data" | Out-Null
    NtSafeClose $hClass

    $hClass2 = NtOpen $classPath
    if ($hClass2 -ne [IntPtr]::Zero) {
        $cv = ReadSZ $hClass2 "ClassVal"
        NtSafeClose $hClass2
        if ($cv -eq "class_virt_data") {
            Pass "NK-01" "_Classes hive virtualized: write+read via \Registry\User\<SID>_Classes OK"
        } else {
            Fail "NK-01" "_Classes hive: read back '$cv' (expected 'class_virt_data')"
        }
    } else {
        Fail "NK-01" "_Classes hive: NtOpenKey after write FAILED"
    }
} else {
    # May fail if _Classes hive doesn't exist on the system
    Skip "NK-01" "NtCreateKey \Registry\User\<SID>_Classes FAILED (hive may not exist on this system)"
}

# NK-02: Verify _Classes path went to HKEY_USERS namespace in virtual store (not HKEY_CURRENT_USER)
$virtClassPath = "$VirtNtBase\HKEY_USERS\$sid`_Classes\VirtRegTest_Classes_2026"
$hVC = NtOpen $virtClassPath
if ($hVC -ne [IntPtr]::Zero) {
    Pass "NK-02" "_Classes routed to HKEY_USERS in virtual store (correct)"
    NtSafeClose $hVC
} else {
    # Check if it went to HKEY_CURRENT_USER instead (wrong)
    $virtCUPath = "$VirtNtBase\HKEY_CURRENT_USER\VirtRegTest_Classes_2026"
    $hVCU = NtOpen $virtCUPath
    if ($hVCU -ne [IntPtr]::Zero) {
        Fail "NK-02" "_Classes routed to HKEY_CURRENT_USER (wrong!) - should be HKEY_USERS"
        NtSafeClose $hVCU
    } else {
        Skip "NK-02" "Cannot verify _Classes routing (NK-01 may have skipped or failed)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5.  Summary and log write
# ─────────────────────────────────────────────────────────────────────────────
Log ""
Log "================================================================"
Log "  NT-LEVEL TEST SUMMARY"
Log "  PASS : $($script:PASS)"
Log "  FAIL : $($script:FAIL)"
Log "  SKIP : $($script:SKIP)"
Log "================================================================"

# Write log to file
$script:log | Set-Content -Encoding UTF8 $LogFile -Force
Write-Host ""
Write-Host "Log written to: $LogFile" -ForegroundColor Cyan

exit $script:FAIL
