#Requires -Version 5.1
param(
    [string]$RBase     = "HKCU\Software\VirtRegTestReal_2026",
    [string]$NtBase    = "",
    [string]$VirtNtBase = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 1. Resolve NT path of the real seeded-key base
if ($NtBase -eq "") {
    $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $id.User.Value
    $sub = $RBase -replace '^HKCU\\','' -replace '^HKEY_CURRENT_USER\\',''
    $NtBase = "\Registry\User\$sid\$sub"
}

# 2. Minimal P/Invoke definitions for NA-04
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

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
    public IntPtr ObjectName; 
    public uint   Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
    public const uint OBJ_CASE_INSENSITIVE = 0x40u;
}

public static class NtReg {
    const string NTDLL = "ntdll.dll";
    const uint KEY_ALL   = 0xF003Fu;
    const uint REG_CREATED_NEW_KEY  = 1u;
    const uint REG_OPENED_EXISTING_KEY = 2u;

    [DllImport(NTDLL)]
    public static extern int NtCreateKey(
        out IntPtr  KeyHandle,
        uint        DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        uint        TitleIndex,
        IntPtr      Class,         
        uint        CreateOptions,
        out uint    Disposition);

    [DllImport(NTDLL)]
    public static extern int NtClose(IntPtr Handle);

    public static uint KeyAll   { get { return KEY_ALL; } }
    public static uint RegCreatedNew { get { return REG_CREATED_NEW_KEY; } }
    public static uint RegOpenedExisting { get { return REG_OPENED_EXISTING_KEY; } }
}
'@ -ErrorAction Stop

# 3. Helper utilities
function NT_SUCCESS([int]$s) { $s -ge 0 }

function MakeUS([string]$s) {
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($s)
    $bufPtr  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 2)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $bufPtr, $bytes.Length)
    [System.Runtime.InteropServices.Marshal]::WriteInt16($bufPtr, $bytes.Length, 0)

    $us = [UNICODE_STRING]::new()
    $us.Length        = [uint16]$bytes.Length
    $us.MaximumLength = [uint16]($bytes.Length + 2)
    $us.Buffer        = $bufPtr

    $usPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($us))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($us, $usPtr, $false)
    return $usPtr, $bufPtr
}

function MakeOA([string]$ntPath, [IntPtr]$root = [IntPtr]::Zero) {
    $usPtrs  = MakeUS $ntPath
    $usPtr   = $usPtrs[0]
    $bufPtr  = $usPtrs[1]

    $oa = [OBJECT_ATTRIBUTES]::new()
    $oa.Length                   = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory            = $root
    $oa.ObjectName               = $usPtr
    $oa.Attributes               = [OBJECT_ATTRIBUTES]::OBJ_CASE_INSENSITIVE
    $oa.SecurityDescriptor       = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero

    $oaPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa, $oaPtr, $false)
    return $oaPtr, $usPtr, $bufPtr 
}

function FreeAll([IntPtr[]]$ptrs) {
    foreach ($p in $ptrs) {
        if ($p -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($p)
        }
    }
}

function NtCreate([string]$ntPath, [uint32]$access = 0xF003F) {
    $ptrs = MakeOA $ntPath
    try {
        $h    = [IntPtr]::Zero
        $disp = [uint32]0
        $oa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [type][OBJECT_ATTRIBUTES])
        $st   = [NtReg]::NtCreateKey([ref]$h, $access, [ref]$oa, 0, [IntPtr]::Zero, 0, [ref]$disp)
        if (NT_SUCCESS $st) { return $h, $disp }
        return [IntPtr]::Zero, [uint32]0
    } finally {
        FreeAll $ptrs
    }
}

function NtSafeClose([IntPtr]$h) {
    if ($h -ne [IntPtr]::Zero) { [NtReg]::NtClose($h) | Out-Null }
}

# 4. NA-04 Test Execution
Write-Host "================================================================"
Write-Host "  ISOLATED TEST: NA-04 (NtCreateKey on real key CoW)"
Write-Host "  Target NtBase: $NtBase"
Write-Host "================================================================"
Write-Host ""

$realSeedPath = "$NtBase\SeedKey"
$res3 = NtCreate $realSeedPath
$hCoW = $res3[0]
$disp3 = $res3[1]

if ($hCoW -ne [IntPtr]::Zero) {
    if ($disp3 -eq [NtReg]::RegOpenedExisting) {
        Write-Host "[PASS] NA-04 : NtCreateKey on real key (CoW): disposition=REG_OPENED_EXISTING_KEY ($disp3)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] NA-04 : NtCreateKey on real key (CoW): disposition=$disp3 (expected REG_OPENED_EXISTING_KEY=2)" -ForegroundColor Red
    }
    NtSafeClose $hCoW
} else {
    Write-Host "[FAIL] NA-04 : NtCreateKey on real key (CoW): FAILED (handle is null)" -ForegroundColor Red
}

Write-Host ""