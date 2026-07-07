# Platform B Decision Receive Model

## Purpose

Define how a RAMAT Vision device may receive and display Platform B decisions without becoming the decision engine.

## Platform rule

RAMAT Vision devices receive, display, translate, relay, and review Platform B decision outputs.

Platform B decides.

## Decision outputs available for display

- PROCEED
- HOLD
- ESCALATE
- CONFIRM NFC
- CAPTURE EVIDENCE
- REVIEWER REQUIRED
- TASK CONTEXT MISSING
- AUTHORITY NOT CONFIRMED
- EVIDENCE INCOMPLETE
- CONTEXT MISMATCH
- STOP-LINE RECORDED
- RELEASE APPROVED
- HOLD MAINTAINED
- TRANSLATION SUPPORT ACTIVE
- HUMAN CONFIRMATION REQUIRED
- APPROVED LANGUAGE VERSION REQUIRED
- CONTROLLED DOCUMENT REMAINS SOURCE OF TRUTH
- PRIVACY BOUNDARY ACTIVE
- SAFETY SHARE ACKNOWLEDGED
- INSPECTION PACKAGE READY

## Display rules

- Display decision state
- Display evidence reason
- Display required next action
- Display whether human confirmation is required
- Display whether translation support is active
- Display whether controlled document remains source of truth
- Display whether privacy boundary is active
- Display whether reviewer action is required

## Forbidden actions

- The device must not approve work
- The device must not release batches
- The device must not close deviations
- The device must not close CAPA
- The device must not modify audit trails
- The device must not modify GMP records
