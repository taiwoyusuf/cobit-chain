# Platform B v1.1 - Traceability and Guardrail Matrix

## Purpose

Trace RAMAT Vision, RAMAT Vision Pro Audit Mode, translation, SafetyShare, deviation/CAPA capture, stop-line, and context witness backlog items to Platform B guardrails.

## Architecture boundary

Backlog only.

Do not reopen Platform B v1 architecture.

Platform B v1 remains frozen.

## Core rule

Any device may witness. Only Platform B decides.

## Matrix

| Backlog area | Primary feature group | Guardrail | Decision authority |
|---|---|---|---|
| Wearable context capture | RAMAT Vision Wearable Assurance Features | Wearable capture is not approval | Platform B |
| Micro-decision display | RAMAT Vision Wearable Assurance Features | Display is not decisioning | Platform B |
| Human intent capture | RAMAT Vision Wearable Assurance Features | Human intent is evidence, not automatic approval | Platform B with accountability rules |
| Regulated translation | RAMAT Live Interpreter Mode | Translation is not approval | Platform B |
| SafetyShare | Multilingual SafetyShare Mode | Acknowledgement is not competence proof | Platform B and human review |
| Controlled document viewing | Controlled Document Lens | Controlled document remains source of truth | QMS and Platform B boundary |
| Gowning and cleanroom boundary | Gowning and Cleanroom Boundary Check | Context mismatch may holdMS and Platform B boundary |
| Gowning and cleanroom boundary | Gown action | Platform B |
| Line clearance | Line-Clearance Lens | Visual confirmation alone is insufficient | Platform B |
| Material identity | Label and Material Identity Check | NFC or approved confirmation may be required | Platform B |
| Batch and equipment passport | Batch Passport View, Equipment Passport View | Passport view is evidence context, not release | Platform B and authorized reviewers |
| Sterile preparation | Sterile Preparation / Compounding Mode | Capture supports review, not release | Platform B and quality system |
| Remote expert | Remote Expert With Evidence Boundary | Privacy and evidence boundaries apply | Platform B |
| AI recommendation | AI Recommendation Governance Mode | AI output is not approval | Platform B and accountable human |
| Deviation and CAPA | Deviation / CAPA Capture Mode | Capture does not close deviation or CAPA | Quality system and Platform B boundary |
| Trust decay | Trust Decay Reminder | Alert does not restore trust | Platform B |
| Regulated memory | Regulated Memory Mode | Memory must respect privacy and evidence boundary | Platform B boundary |
| Stop-line | Stop-Line by Button / Voice | Stop-line capture does not release action | Platform B and accountable human |
| Audit reconstruction | RAMAT Vision Pro Audit Mode | Audit Mode is read-only by default | Platform B and QA authority boundary |

## Non-negotiable guardrails

- Translation is not approval.
- AI output is not approval.
- Wearable capture is not approval.
- Audit reconstruction is not approval.
- Read-only audit mode does not modify GMP records.
- Platform B remains the assurance decision engine.
- Quality systems remain the system of record where applicable.
