# RAMAT Vision™ H1B-J1 — Jetson UEFI Storage-Visibility Governed State

**Record date:** 15 August 2026  
**Status:** `PUBLIC_DOCUMENTARY_PROVENANCE_ONLY`  
**Scope:** bounded RAMAT Vision / COBIT-Chain™ integration-readiness governance record; no implementation files are published here.

## Governed execution state

The original H1B-J1 local Jetson Linux/read-only readiness power-on was executed and consumed. The expected existing Ubuntu/Jetson Linux runtime was **not reached**. The system instead entered the existing EDK II UEFI Interactive Shell.

Accordingly:

- `H1B_J1 = CLOSED_CONSUMED`
- `JETSON_LINUX_EXISTING_RUNTIME_REACHED = FALSE`
- `AUTHORIZED_READINESS_SCRIPT_COPIED = FALSE`
- `AUTHORIZED_READINESS_SCRIPT_EXECUTED = FALSE`
- `H1B_J1_READINESS_INSPECTION_COMPLETED = FALSE`
- `H1B_J1_SOFTWARE_READINESS = NOT_ESTABLISHED`

No camera, environmental sensor, RFID/NFC, IMU/serial, network, Azure, Platform B1, driver, package, OS-configuration, or frame-acquisition activity was admitted under that consumed readiness authority.

## Closed read-only UEFI inventory

A separately bounded UEFI storage-inventory power-on and exactly one read-only diagnostic command, `map`, were subsequently executed and consumed.

The resulting mapping state showed only:

```text
FS1: MemoryMapped(...)
FS0: Fv(...)
```

and established:

- `UEFI_BLK_MAPPING_COUNT = 0`
- `UEFI_NON_FIRMWARE_STORAGE_FILESYSTEM_MAPPING_COUNT = 0`
- `PRESENTLY_UEFI_VISIBLE_USABLE_BOOT_STORAGE = NOT_OBSERVED`

The evidence does **not** establish that physical storage is absent, failed, or requires imaging. It also does not establish whether a storage medium is absent, unrecognized, uninitialized/unbootable, affected by an interface/device-discovery condition, or otherwise outside the current UEFI mapping state.

Therefore:

- `EXISTING_BOOTABLE_JETSON_LINUX_STORAGE = NOT_ESTABLISHED`
- `PHYSICAL_STORAGE_ABSENCE = NOT_ESTABLISHED`
- `PHYSICAL_STORAGE_FAILURE = NOT_ESTABLISHED`
- `STORAGE_IMAGING_REQUIREMENT = NOT_YET_ESTABLISHED`

## Current follow-on gate

Independent Control has authorized one further bounded diagnostic solely to answer whether UEFI presently detects any physical boot-capable storage device or controller despite the absence of `BLK*` and OS/storage filesystem mappings.

The authorized method is exactly:

```text
POWER_ON_ONCE
-> reach existing UEFI Interactive Shell
-> execute exactly: devices
-> capture complete photographic evidence
-> STOP
```

Current status:

- `H1B_J1_FOLLOW_ON_STORAGE_VISIBILITY_POWER_ON = AUTHORIZED_ONCE`
- `H1B_J1_FOLLOW_ON_STORAGE_VISIBILITY_DIAGNOSTIC = AUTHORIZED_ONCE`
- `AUTHORIZED_UEFI_COMMAND_COUNT = 1`
- `AUTHORIZED_UEFI_COMMAND = devices`
- `FOLLOW_ON_DIAGNOSTIC_EXECUTED = FALSE`
- `RETRY = NOT_AUTHORIZED`
- `RERUN = NOT_AUTHORIZED`
- `FALLBACK = NOT_AUTHORIZED`

No substitute UEFI command is authorized.

## Preserved non-authorities

This record does **not** authorize or represent implementation of any of the following:

- JetPack or Jetson Linux installation;
- microSD/NVMe imaging or storage formatting;
- boot repair, firmware update, recovery mode, boot-order or UEFI-variable change;
- camera/sensor/network/Azure/Platform B1 activity;
- H1B-J2, H1B-J3, H1B-J4, or Canonical Audit R3-E06.

`NO_BIND = TRUE`

`WITNESS_AUTHORITY = NONE`

## Provenance interpretation

This milestone is a governance/evidence-state record, not a claim that a storage defect, hardware absence, or installation requirement has been established. The current architecture continues to require evidence-bounded classification, single-use authority consumption, fail-closed STOP behavior, and separate authorization for any future write-capable installation or recovery activity.
