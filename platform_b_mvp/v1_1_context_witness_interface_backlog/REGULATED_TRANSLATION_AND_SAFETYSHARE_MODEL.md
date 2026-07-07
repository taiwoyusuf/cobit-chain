# Regulated Translation and SafetyShare Model

## Purpose

Define how RAMAT Vision may support live interpretation, multilingual safety communication, and controlled-language display without replacing controlled documents.

## Platform rule

Translation is not approval.

Controlled documents remain the source of truth.

Platform B decides.

## Supported functions

- RAMAT Live Interpreter Mode
- Multilingual SafetyShare Mode
- Conversation Clarity Mode
- Vendor Conversation Handoff
- Inspector Conversation Handoff
- Approved Language Version warning

## Required objects

- LiveInterpreterEvent
- TranslationEvidenceRecord
- LanguagePreferenceProfile
- ApprovedLanguageVersionRecord
- SafetyShareCard
- SafetyShareAcknowledgement
- ConversationClarityEvent
- VendorConversationHandoff
- InspectorConversationHandoff
- ControlledDocumentCheck

## Output states

- TRANSLATION SUPPORT ACTIVE
- APPROVED LANGUAGE VERSION REQUIRED
- CONTROLLED DOCUMENT REMAINS SOURCE OF TRUTH
- SAFETY SHARE ACKNOWLEDGED
- HUMAN CONFIRMATION REQUIRED
- REVIEWER REQUIRED

## Guardrails

- Translation does not replace the controlled document.
- Live interpretation does not approve the action.
- SafetyShare acknowledgement is evidence of communication, not proof of competence.
- If approved-language content is required, the wearable must show APPROVED LANGUAGE VERSION REQUIRED.
