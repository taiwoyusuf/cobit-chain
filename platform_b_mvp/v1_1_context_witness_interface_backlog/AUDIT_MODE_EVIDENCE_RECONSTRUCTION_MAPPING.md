# Audit Mode Evidence Reconstruction Mapping

## Purpose

Map RAMAT Vision Pro Audit Mode backlog features to evidence reconstruction objects and read-only outputs.

## Platform rule

RAMAT Vision Pro Audit Mode is read-only by default.

It may display, reconstruct, request, and draft observations.

It does not approve work, release batches, close deviations, close CAPA, alter audit trails, or modify GMP records.

## Mapping

| Audit Mode feature | Primary objects | Output examples |
|---|---|---|
| Audit Scope Passport | AuditScopePassport, AuditorIdentity | AUDIT SCOPE ACTIVE |
| Look-and-Audit Mode | AuditorSession, AuditEvidenceRequest | READ-ONLY AUDIT MODE ACTIVE |
| Evidence Reconstruction Mode | EvidenceReconstructionRecord, EvidenceGapFinding | EVIDENCE RECONSTRUCTION READY |
| Deviation Reconstruction Mode | DeviationTimelineRecord, DataIntegrityFlag | DEVIATION TIMELINE READY |
| CAPA Effectiveness Mode | CAPAEffectivenessRecord, QAtriageRoute | CAPA EFFECTIVENESS NOT VERIFIED |
| Change Control Reconstruction | ChangeControlReconstruction | CHANGE CONTROL COMPLETE |
| Batch Evidence Replay | BatchEvidenceReplay, EvidenceReconstructionRecord | INSPECTION PACKAGE READY |
| Audit Trail Lens | AuditTrailLensRecord, DataIntegrityFlag | AUDIT TRAIL GAP |
| Question-to-Evidence Mode | QuestionToEvidenceQuery, AuditEvidenceRequest | NO APPROVED EVIDENCE FOUND |
| Observation Capture Mode | AuditObservationDraft | AUDIT OBSERVATION DRAFTED |
| Finding-to-CAPA Bridge | FindingToCAPABridge, CAPAEffectivenessRecord | FINDING LINKED TO CAPA DRAFT |
| Inspection Replay Package | InspectionReplayPackage, EvidenceReconstructionRecord | INSPECTION PACKAGE READY |
| Auditor Read-Only Guardrail | AuditorReadOnlyGuardrail, AuditorSession | ACTION BLOCKED - AUDITOR ROLE |

## Guardrail

Audit Mode reconstructs evidence. It does not replace QA authority, GMP records, quality systems, or Platform B decisioning.
