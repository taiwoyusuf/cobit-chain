# RAMAT Feature to Object Mapping

## Purpose

Map RAMAT Vision wearable assurance features to required Platform B backlog objects.

## Mapping

| Feature | Primary objects | Platform B output examples |
|---|---|---|
| Ask-the-Asset Mode | EquipmentPassportSnapshot, WearableContextEvent, VisualCandidateRecord | CAPTURE EVIDENCE, REVIEWER REQUIRED |
| Controlled Document Lens | ControlledDocumentCheck, ApprovedLanguageVersionRecord | CONTROLLED DOCUMENT REMAINS SOURCE OF TRUTH |
| RAMAT Live Interpreter Mode | LiveInterpreterEvent, TranslationEvidenceRecord, LanguagePreferenceProfile | TRANSLATION SUPPORT ACTIVE |
| Multilingual SafetyShare Mode | SafetyShareCard, SafetyShareAcknowledgement, TranslationEvidenceRecord | SAFETY SHARE ACKNOWLEDGED |
| Gowning and Cleanroom Boundary Check | GowningReadinessCheck, ZoneAssuranceRecord | HOLD, HUMAN CONFIRMATION REQUIRED |
| Line-Clearance Lens | LineClearanceRecord, VisualCandidateRecord | PROCEED, HOLD, CONTEXT MISMATCH |
| Label and Material Identity Check | MaterialIdentityCheck, VisualCandidateRecord | CONFIRM NFC, HOLD |
| Batch Passport View | BatchPassportSnapshot, ActionAdmissibilityRecord | REVIEWER REQUIRED, INSPECTION PACKAGE READY |
| Equipment Passport View | EquipmentPassportSnapshot, DeviceReadinessPassport | PROCEED, HOLD |
| Sterile Preparation / Compounding Mode | SterilePrepEvidenceRecord, ALCOAEvidenceRecord | CAPTURE EVIDENCE, HOLD |
| Remote Expert With Evidence Boundary | RemoteExpertSessionRecord, PrivacyBoundaryRecord | PRIVACY BOUNDARY ACTIVE |
| Thermal / Invisible Risk Mode | ThermalRiskSignal, ZoneAssuranceRecord | ESCALATE, HOLD |
| Guided SOP Overlay | GuidedSOPStepRecord, ControlledDocumentCheck | CONTROLLED DOCUMENT REMAINS SOURCE OF TRUTH |
| ALCOA+ Evidence Capture | ALCOAEvidenceRecord, WearableContextEvent | CAPTURE EVIDENCE |
| AI Recommendation Governance Mode | AIRecommendationGovernanceRecord, HumanIntentConfirmation | HUMAN CONFIRMATION REQUIRED |
| Deviation / CAPA Capture Mode | DeviationDraftRecord, CAPAEvidenceRecord | REVIEWER REQUIRED |
| Trust Decay Reminder | TrustDecayAlert, DeviceReadinessPassport | HOLD MAINTAINED |
| Vendor / Inspector Conversation Handoff | VendorConversationHandoff, InspectorConversationHandoff | INSPECTION PACKAGE READY |
| Regulated Memory Mode | RegulatedMemoryRecord, PrivacyBoundaryRecord | PRIVACY BOUNDARY ACTIVE |
| Location / Zone-Aware Assurance | ZoneAssuranceRecord, WearableContextEvent | CONTEXT MISMATCH |
| Stop-Line by Button / Voice | StopLineEvent, VoiceIntentRecord | STOP-LINE RECORDED |

## Guardrail

The mapping supports backlog traceability. It does not implement approval authority.
