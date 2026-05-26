# VirtRegTest – Registry Virtualisation Test Suite
## for VirtLauncher / VirtHook

---

## Files

| File | Description |
|---|---|
| `VirtRegTest.bat` | Main orchestrator. Runs all phases: seed → launch → isolate → inspect → cleanup |
| `VirtRegTest-NtLevel.ps1` | Companion: Direct NT API tests via P/Invoke (ntdll.dll) |

---

## Quick Start

```batch
REM Put VirtLauncher64.exe and VirtHook64.dll in PATH or same folder as these files.
REM Run as Administrator for full HKLM coverage.

VirtRegTest.bat

REM NT-level deep tests (run separately inside VirtLauncher):
VirtLauncher64.exe -r HKCU\VirtRegTest_Store_2026 --exec ^
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File VirtRegTest-NtLevel.ps1
```

---

## How It Works

```
OUTSIDE VirtLauncher
  │
  ├─ Phase 0: Pre-flight (find launcher, check admin, detect bitness)
  ├─ Phase 1: Seed real registry under HKCU\Software\VirtRegTestReal_2026
  │           (5 seed keys with values, subkeys, deep nesting)
  │
  ├─ Phase 2: Launch VirtLauncher -r HKCU\VirtRegTest_Store_2026
  │           The batch re-dispatches itself with --inside flag
  │           ┌─ INSIDE VirtLauncher ─────────────────────────────┐
  │           │  All reg ops virtualized. Sections A–Q run here.  │
  │           │  Results logged to %TEMP%\VirtRegTest_Inner.log   │
  │           └───────────────────────────────────────────────────┘
  │
  ├─ Phase 3: Isolation checks – verify real registry untouched
  ├─ Phase 4: Virtual store inspection – verify writes landed in VHIVE
  └─ Phase 5: Cleanup + Phase 6: Final report
```

---

## Test Sections (VirtRegTest.bat)

| Section | What is tested |
|---|---|
| **A** | Basic read/write: HKCU new key, CoW write to real key, HKLM write, real HKLM read |
| **B** | Value merge: virtual shadows real; real-only visible; no duplicates; type override |
| **C** | Subkey merge: real+virt all visible; no duplicates; 5-way merge |
| **D** | Delete: virtual-only key/value, CoW-written value, **real-only key/value (known bug)**, subtree |
| **E** | Nested keys: 5-level pure virt, deep real key via merge, CoW at depth 5, HKLM deep |
| **F** | All value types: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE |
| **G** | Default (unnamed) value: `/ve` write, override, enumeration coexistence |
| **H** | Handle lifecycle: close+reopen persistence, 2-cycle overwrite |
| **I** | Disposition: REG_CREATED_NEW_KEY vs REG_OPENED_EXISTING_KEY; CoW disposition |
| **J** | Special names: spaces in key/value, numbers/underscores, 72-char key, large binary/SZ |
| **K** | NtQueryKey count accuracy: documents virtual-only vs merged count discrepancy |
| **L** | Recursive: `reg export`, `reg query /s`, recursive `reg delete /f` |
| **M** | HKCU vs HKLM independence; no cross-contamination; HKLM delete |
| **N** | HKCR virtualisation (routes via HKLM+HKCU backing hives) |
| **O** | NtRenameKey via `RegRenameKey` (PowerShell P/Invoke) |
| **P** | NtQueryMultipleValueKey: per-value fallback check (known all-or-nothing limitation) |
| **Q** | Stress: 20 subkeys, 25 values, spot-check enumeration |

---

## Test Sections (VirtRegTest-NtLevel.ps1)

| Section | What is tested |
|---|---|
| **NA** | NtCreateKey disposition; NtOpenKey success/fail; hive root NOT virtualized |
| **NB** | NtSetValueKey + NtQueryValueKey: same handle; close+reopen; CoW; read-only handle |
| **NC** | NtEnumerateKey merge: real+virt all present, no duplicates, index continuity |
| **ND** | NtEnumerateValueKey merge: shadowed, real-only, virt-only, no duplicates |
| **NE** | NtQueryKey KeyFullInformation: SubKeys/Values count accuracy **(known bug)** |
| **NF** | NtDeleteKey/NtDeleteValueKey: virtual-only clean; **real-only re-appears (known bug)** |
| **NG** | NtQueryMultipleValueKey: shadow+real mix **(known all-or-nothing bug)** |
| **NH** | Buffer-too-small handling: BUFFER_TOO_SMALL → retry with correct size |
| **NI** | Relative-path opens (OBJECT_ATTRIBUTES.RootDirectory != NULL) |
| **NJ** | NtFlushKey on virtual handle |
| **NK** | `<SID>_Classes` hive routes to HKEY_USERS, not HKEY_CURRENT_USER |

---

## Known Bugs Explicitly Tested

### 1. No Registry Tombstone (D-05b, D-06b, NF-03b, NF-04)
**What:** Deleting a key or value that exists only in the real registry (inside the sandbox)
does not persist. On the next open the hook does a fresh CoW open, finds the real key still
exists, and returns it — the deletion is invisible.

**File virtualisation** uses `.vl_deleted` tombstone files to solve this. The registry
virtualisation layer has no equivalent mechanism.

**Test markers:** `[KNOWN BUG]` in FAIL messages for D-05b, D-06b, NF-03b, NF-04.

---

### 2. NtQueryKey Reports Virtual-Only Counts (NE-01, NE-02, K-01, K-02)
**What:** `NtQueryKey(KeyFullInformation)` is called on the virtual handle. It returns
`SubKeys` and `Values` counts from the virtual key only, not the merged (real+virtual) count.

This makes `RegQueryInfoKey`, `RegistryKey.SubKeyCount`, and `RegistryKey.ValueCount` wrong
whenever a key has real entries not yet CoW-copied into the virtual store.

**Test markers:** Tests K-01, K-02 (bat) and NE-01, NE-02 (PS1) log the reported vs expected count.

---

### 3. NtQueryMultipleValueKey: All-or-Nothing Fallback (P-01, NG-01)
**What:** `NtQueryMultipleValueKey` tries the virtual handle for all entries. If even one value
is missing from virtual, the entire query falls back to the real handle — losing virtual
overrides for the other values.

A key with some virtual-overridden values and some real-only values cannot be correctly
served by a single `NtQueryMultipleValueKey` call.

**Fix direction:** Per-value fallback: for each entry that the virtual handle returns
NOT_FOUND, retry that entry on the real handle.

**Test markers:** P-01 (bat) and NG-01 (PS1).

---

## Options (VirtRegTest.bat)

```
/launcher:<path>    Path to VirtLauncher64.exe (default: PATH or same folder)
/vhive:<key>        Virtual store hive root    (default: HKCU\VirtRegTest_Store_2026)
/rbase:<key>        Real seeded-key base       (default: HKCU\Software\VirtRegTestReal_2026)
/nocleanup          Do not remove test registry keys after run
/32                 Use VirtLauncher32.exe
/verbose            Extra diagnostic output
```

---

## Virtual Store Layout

When `-r HKCU\VirtRegTest_Store_2026` is used, VirtHook maps:

```
HKLM\SOFTWARE\Foo          →  HKCU\VirtRegTest_Store_2026\HKEY_LOCAL_MACHINE\SOFTWARE\Foo
HKCU\Software\Bar          →  HKCU\VirtRegTest_Store_2026\HKEY_CURRENT_USER\Software\Bar
HKU\<SID>_Classes\...      →  HKCU\VirtRegTest_Store_2026\HKEY_USERS\<SID>_Classes\...
```

Phase 4 of the batch verifies the virtual store directly by querying these translated paths
from outside VirtLauncher.

---

## Requirements

- Windows 10 / 11 (x64 recommended)
- VirtLauncher64.exe + VirtHook64.dll (both from your build)
- PowerShell 5.1+ (for NT-level tests and some inner-virt checks)
- Administrator is **optional** but enables HKLM seed creation and isolation checks
- `reg.exe` must be in PATH (it is by default on all Windows versions)
