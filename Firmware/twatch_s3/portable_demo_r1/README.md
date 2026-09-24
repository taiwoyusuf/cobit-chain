# RAMAT Portable Watch Demo R1

This folder defines the first portable RAMAT Vision demonstration for the T-WATCH-S3 workstream.

## Intended user flow
Home → Mission → Witness → Authority → History → Sync

## Built-in synthetic scenarios
1. Nominal / SUPPORTED
2. Measurement applicability expired / HOLD
3. Physical-digital conflict / CONFLICTING
4. Recovery without restoration / HOLD

## Core separation
watch = display / witness / request / review

COBIT-Chain / VSA = assurance evaluator

human/accountable authority = separate

## Offline rule
Loss of connectivity must not create or imply a new SUPPORTED state. The watch retains the last known state, marks it as cached/offline, preserves last-sync time, and distinguishes local state from a fresh evaluator response.

## First physical test gate
Before firmware flashing, freeze the exact T-WATCH-S3 board/revision and the supported display, input, power, storage, and network libraries for the physical unit.

The first physical demonstration should:
- boot into the RAMAT demo shell;
- show device ID;
- cycle through all four scenarios;
- visibly show HOLD;
- visibly show CONFLICTING;
- show OFFLINE mode;
- show last-sync state;
- reboot and preserve demo version/state.

## Claim ceiling
This is a synthetic engineering demonstration only. It is not production validation, clinical validation, regulatory acceptance, autonomous authority, or evidence that the watch itself is a source of decision authority.
