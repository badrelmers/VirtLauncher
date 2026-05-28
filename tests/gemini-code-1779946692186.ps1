#Requires -Version 5.1
<#
.SYNOPSIS
    Isolated Failing Tests for VirtLauncher / VirtHook
    Focuses solely on NA-01 (Disposition) and NG-01 (NtQueryMultipleValueKey)
#>

param(
    [string]$RBase      = "HKCU\Software\VirtRegTestReal_2026",
    [string]$NtBase     = "",
    [string]$VirtNtBase = "",
    [string]$LogFile    = "$env:TEMP\VirtRegTest_Isolated_Fails.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $env:VIRTLAUNCHER_REG -and -not $VirtNtBase) {
    Write-Host "[ERROR] VIRTLAUNCHER_REG is not set." -ForegroundColor Red
    exit 1
}
if ($VirtNtBase -eq "") { $VirtNtBase = $env:VIRTLAUNCHER_REG }

if ($NtBase -eq "") {
    $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $id.User.Value
    $sub = $RBase -replace '^HKCU\\','' -replace '^HKEY_CURRENT_USER\\',''
    $NtBase = "\Registry\User\$sid\$sub"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. P/Invoke - NT API definitions (Reduced)
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
    public IntPtr ObjectName;
    public uint   Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
    public const uint OBJ_CASE_INSENSITIVE = 0x40u;
}

public enum KEY_VALUE_INFORMATION_CLASS : int {
    KeyValueBasicInformation   = 0,
    KeyValueFullInformation    = 1,
    KeyValuePartialInformation = 2
}

[StructLayout(LayoutKind.Sequential)]
public struct KEY_VALUE_ENTRY {
    public IntPtr ValueName;
    public uint   DataLength;
    public uint   DataOffset;
    public uint   Type;
}

public static class NtReg {
    const string NTDLL = "ntdll.dll";
    
    [DllImport(NTDLL)]
    public static extern int NtCreateKey(out IntPtr KeyHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, uint TitleIndex, IntPtr Class, uint CreateOptions, out uint Disposition);

    [DllImport(NTDLL)]
    public static extern int NtOpenKey(out IntPtr KeyHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport(NTDLL)]
    public static extern int NtSetValueKey(IntPtr KeyHandle, ref UNICODE_STRING ValueName, uint TitleIndex, uint Type, byte[] Data, uint DataSize);

    [DllImport(NTDLL)]
    public static extern int NtClose(IntPtr Handle);

    [DllImport(NTDLL)]
    public static extern int NtQueryMultipleValueKey(IntPtr KeyHandle, [In, Out] KEY_VALUE_ENTRY[] ValueEntries, uint EntryCount, IntPtr ValueBuffer, ref uint BufferLength, out uint RequiredBufferLength);

    public static uint KeyRead  { get { return 0x20019u; } }
    public static uint KeyWrite { get { return 0x20006u; } }
    public static uint KeyAll   { get { return 0xF003Fu; } }
    public static uint RegCreatedNew { get { return 1u; } }
    public static uint RegOpenedExisting { get { return 2u; } }
}
'@ -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# 3. Helper utilities
# ─────────────────────────────────────────────────────────────────────────────
$script:PASS = 0; $script:FAIL = 0
$log = [System.Collections.Generic.List[string]]::new()

function Log([string]$msg) { Write-Host $msg; $script:log.Add($msg) }
function Pass([string]$id, [string]$desc) { $script:PASS++; Log("[PASS] $id : $desc") }
function Fail([string]$id, [string]$desc) { $script:FAIL++; Log("[FAIL] $id : $desc") }
function Section([string]$id, [string]$title) { Log(""); Log("-- SECTION $id : $title ") }
function NT_SUCCESS([int]$s) { $s -ge 0 }

function MakeUS([string]$s) {
    $bytes  = [System.Text.Encoding]::Unicode.GetBytes($s)
    $bufPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 2)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $bufPtr, $bytes.Length)
    [System.Runtime.InteropServices.Marshal]::WriteInt16($bufPtr, $bytes.Length, 0)
    $us = [UNICODE_STRING]::new()
    $us.Length = [uint16]$bytes.Length
    $us.MaximumLength = [uint16]($bytes.Length + 2)
    $us.Buffer = $bufPtr
    $usPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($us))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($us, $usPtr, $false)
    return $usPtr, $bufPtr
}

function MakeOA([string]$ntPath, [IntPtr]$root = [IntPtr]::Zero) {
    $usPtrs = MakeUS $ntPath
    $oa = [OBJECT_ATTRIBUTES]::new()
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory = $root
    $oa.ObjectName = $usPtrs[0]
    $oa.Attributes = [OBJECT_ATTRIBUTES]::OBJ_CASE_INSENSITIVE
    $oaPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa, $oaPtr, $false)
    return $oaPtr, $usPtrs[0], $usPtrs[1]
}

function FreeAll([IntPtr[]]$ptrs) {
    foreach ($p in $ptrs) { if ($p -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($p) } }
}

function NtOpen([string]$ntPath, [uint32]$access = 0x20019) {
    $ptrs = MakeOA $ntPath
    try {
        $h = [IntPtr]::Zero
        $oa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [type][OBJECT_ATTRIBUTES])
        if (NT_SUCCESS ([NtReg]::NtOpenKey([ref]$h, $access, [ref]$oa))) { return $h }
        return [IntPtr]::Zero
    } finally { FreeAll $ptrs }
}

function NtCreate([string]$ntPath, [uint32]$access = 0xF003F) {
    $ptrs = MakeOA $ntPath
    try {
        $h = [IntPtr]::Zero; $disp = [uint32]0
        $oa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrs[0], [type][OBJECT_ATTRIBUTES])
        if (NT_SUCCESS ([NtReg]::NtCreateKey([ref]$h, $access, [ref]$oa, 0, [IntPtr]::Zero, 0, [ref]$disp))) { return $h, $disp }
        return [IntPtr]::Zero, [uint32]0
    } finally { FreeAll $ptrs }
}

function NtSafeClose([IntPtr]$h) { if ($h -ne [IntPtr]::Zero) { [NtReg]::NtClose($h) | Out-Null } }

function SetValueSZ([IntPtr]$h, [string]$name, [string]$value) {
    $usPtrs = MakeUS $name
    try {
        $us = [System.Runtime.InteropServices.Marshal]::PtrToStructure($usPtrs[0], [type][UNICODE_STRING])
        $data = [System.Text.Encoding]::Unicode.GetBytes($value + "`0")
        return [NtReg]::NtSetValueKey($h, [ref]$us, 0, 1, $data, [uint32]$data.Length)
    } finally { FreeAll $usPtrs }
}


# ─────────────────────────────────────────────────────────────────────────────
# 4. Test execution
# ─────────────────────────────────────────────────────────────────────────────
Log "================================================================"
Log "  VirtRegTest-NtLevel.ps1 - ISOLATED FAILING TESTS"
Log "================================================================"

# ─── SECTION NA: NtCreateKey ─────────────────────────────────────────────────
Section "NA" "NtCreateKey - Disposition Check"

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


# ─── SECTION NG: NtQueryMultipleValueKey ─────────────────────────────────────
Section "NG" "NtQueryMultipleValueKey - Per-Value Merge"

$mqPath = "$NtBase\ShadowKey"

# 1. SETUP: We must manually write the virtual override here since we stripped Section ND
$hSetup = (NtCreate $mqPath)[0]
if ($hSetup -ne [IntPtr]::Zero) {
    SetValueSZ $hSetup "ShadowedVal" "VIRT_SHADOW_OVERRIDE" | Out-Null
    NtSafeClose $hSetup
}

# 2. TEST: Attempt to query both the virtual override and the real-only value
$hMQ = NtOpen $mqPath
if ($hMQ -ne [IntPtr]::Zero) {
    $name1 = "ShadowedVal"
    $name2 = "RealOnlyVal"

    $usPtr1, $bufPtr1 = MakeUS $name1
    $usPtr2, $bufPtr2 = MakeUS $name2

    try {
        $entries = [KEY_VALUE_ENTRY[]]::new(2)
        
        # Local struct instantiation to bypass PS array-boxing mutation bug
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
            Log "          ShadowedVal = '$str1' (expected 'VIRT_SHADOW_OVERRIDE')"
            Log "          RealOnlyVal = '$str2' (expected 'REAL_ONLY_VALUE')"

            if ($str1 -eq "VIRT_SHADOW_OVERRIDE") {
                Pass "NG-01" "NtQueryMultipleValueKey: ShadowedVal returned virtual override value"
            } else {
                Fail "NG-01" "NtQueryMultipleValueKey: ShadowedVal='$str1' (expected VIRT_SHADOW_OVERRIDE)"
            }
        } else {
            Fail "NG-01" "NtQueryMultipleValueKey FAILED (st=0x$($stMQ.ToString('X8')))"
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($valBuf)
    } finally {
        FreeAll @($usPtr1, $bufPtr1, $usPtr2, $bufPtr2)
        NtSafeClose $hMQ
    }
} else {
    Fail "NG-01" "NtOpenKey on ShadowKey FAILED"
}

Log ""
Log "  ISOLATED TEST SUMMARY"
Log "  PASS : $($script:PASS)"
Log "  FAIL : $($script:FAIL)"