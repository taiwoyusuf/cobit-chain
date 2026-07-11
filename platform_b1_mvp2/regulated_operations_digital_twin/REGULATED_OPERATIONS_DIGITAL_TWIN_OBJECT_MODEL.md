# Regulated Operations Digital Twin Object Model

Status: LOCKED OBJECT MODEL ONLY

Workstream: Platform B1 / MVP2

## Purpose

This object model defines a shared software-defined regulated operations digital twin for:

- Compound Pharmacy
- IRLT / Radiopharma Operations
- DSCSA Evidence Integrity & Exception Assurance
- MES and workflow dependency assurance
- equipment and CI readiness
- quality dependency assurance
- AI governance
- evidence integrity
- RAMAT Vision / Thread D2 display

This does not deploy Azure Digital Twins.

This does not connect to real production systems.

## Core doctrine

The digital twin is a regulated operations state model, not a source system.

The twin represents evidence, dependency, identity, quality, AI, equipment, supply-chain, and workflow state for assurance evaluation.

The twin does not replace MES, LIS, ERP, eQMS, VRS, EPCIS, ServiceNow, QMS, LIMS, SCADA, PLC, historian, BMS, or pharmacy systems.

Official records remain in source systems.

Platform B1 evaluates.

Thread D2 displays.

RAMAT Vision displays only.

Humans remain accountable.

## Object families

### Identity, Role, and Persona State

Represents user, device, role, persona, entitlement, and session context.

Example outputs:

- USER SIGN-IN REQUIRED
- ROLE VERIFIED
- ROLE NOT VERIFIED
- ACTION NOT PERMITTED FOR ROLE
- AUDITOR READ-ONLY VIEW ACTIVE

### Equipment, CI, and Asset State

Represents equipment identity, CI identity, lifecycle, support group, ownership, validation, calibration, PM, and operational-readiness state.

Example outputs:

- EQUIPMENT CI READY
- CI READINESS GAP
- SUPPORT GROUP MISSING
- CALIBRATION EXPIRED
- PM OVERDUE

### Workflow Dependency Chain State

Represents hidden dependencies across workflow steps, source systems, required evidence, review gates, and blocking states.

Example outputs:

- WORKFLOW COMPLETE
- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- DEPENDENCY MISSING
- SECONDARY REVIEW REQUIRED
- RELEASE NOT ADMISSIBLE

### Evidence Integrity and Chain-of-Custody State

Represents evidence objects, source references, hash state, rehash triggers, provenance, custody, and audit-readiness state.

Example outputs:

- EVIDENCE SEALED
- HASH VERIFIED
- REHASH REQUIRED
- CHAIN OF CUSTODY GAP
- AUDIT EVIDENCE READY

### Quality, Deviation, CAPA, and Review State

Represents quality dependency, deviation impact, CAPA linkage, review state, SOP alignment, validation, and Quality Unit accountability.

Example outputs:

- QUALITY DEPENDENCY VERIFIED
- QUALITY DEPENDENCY BLOCKED
- DEVIATION IMPACT REVIEW REQUIRED
- CAPA LINK REVIEW REQUIRED
- QUALITY REVIEW REQUIRED

### Material, Product, Serialization, and Supply-Chain State

Represents material genealogy, lot state, supplier evidence, serialized product identity, DSCSA event state, EPCIS evidence, VRS response, and trading-partner trust.

Example outputs:

- MATERIAL LOT TRACEABLE
- DSCSA EVIDENCE SEALED
- EPCIS FILE MISMATCH
- VRS RESPONSE MISSING
- TRADING PARTNER VERIFIED
- QUARANTINE REQUIRED

### Manufacturing, Compounding, and Radiopharma Execution Context

Represents batch, preparation, formula, BUD, execution context, timing sensitivity, handoff state, and operational readiness.

Example outputs:

- COMPOUNDING EVIDENCE SEALED
- BUD EVIDENCE REVIEW REQUIRED
- IRLT EVIDENCE SEALED
- TIME-SENSITIVE HANDOFF REVIEW REQUIRED
- CONTROLLED HANDOFF VERIFIED

### AI Agent, Recommendation, and Content State

Represents AI-generated summaries, recommendations, classifications, prompts, model versions, tool calls, human review, output hash, and recommendation-versus-approval boundary.

Example outputs:

- AI OUTPUT HASHED
- MODEL VERSION RECORDED
- AI RECOMMENDATION REVIEW REQUIRED
- AI CONTENT REVIEW REQUIRED
- HUMAN REVIEW REQUIRED
- AGENT ACTION NOT ADMISSIBLE

### RAMAT Vision / Thread D2 Display State

Represents field display, role-based view, read-only review state, evidence prompts, readiness display, and Platform B1 decision display without approving regulated work.

Example outputs:

- RAMAT VISION DISPLAY READY
- PLATFORM B1 DECISION DISPLAYED
- READ-ONLY REVIEW ACTIVE
- FIELD REVIEW REQUIRED
- RAMAT Vision displays only

## Key relationship types

- equipment_has_ci
- workflow_step_depends_on_evidence
- evidence_has_hash_record
- ai_output_requires_human_review
- dscsa_event_has_epcis_evidence
- serialized_product_has_vrs_response
- compound_preparation_has_formula
- irlt_context_has_handoff_record
- platform_decision_displayed_by_ramat_vision

## Track alignment

### Compound Pharmacy

Example twin state:

- formula selected
- ingredient lots entered
- BUD evidence incomplete
- AI generated preparation summary
- human review required
- quality review not complete

Example outputs:

- COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED
- BUD EVIDENCE REVIEW REQUIRED
- AI CONTENT REVIEW REQUIRED
- QUALITY REVIEW REQUIRED

### IRLT / Radiopharma Operations

Example twin state:

- equipment record exists
- CI record exists
- support group missing
- incident impact not reviewed
- quality dependency blocked
- RAMAT Vision field user requests readiness state

Example outputs:

- CI READINESS GAP
- SUPPORT GROUP MISSING
- QUALITY DEPENDENCY BLOCKED
- RAMAT VISION DISPLAY READY
- IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED

### DSCSA Evidence Integrity & Exception Assurance

Example twin state:

- serialized shipment received
- physical scan captured
- EPCIS data late or incomplete
- VRS response missing
- trading partner evidence stale
- AI classifies exception as review required

Example outputs:

- DSCSA EXCEPTION DETECTED
- EPCIS FILE MISMATCH
- VRS RESPONSE MISSING
- TRADING PARTNER EVIDENCE STALE
- QUARANTINE REQUIRED

## Boundary

Object model only.

Do not deploy Azure Digital Twins now.

Do not deploy Azure resources now.

Do not modify Platform B v1.

Do not reopen Thread D v1.

Do not activate MVP3.

Do not connect to real production systems now.

No real ServiceNow production data.

No real LIS, MES, ERP, eQMS, QMS, VRS, EPCIS, pharmacy, or radiopharma production data.

No PHI.

No company production data.

No product release decision.

No GMP approval decision.

No source-system override.

No Quality Unit replacement.

Platform B1 evaluates.

Thread D2 displays.

RAMAT Vision displays only.

Official records remain in source systems.

Humans remain accountable.

## Next order of work

1. Commit Regulated Operations Digital Twin object model.
2. Merge Regulated Operations Digital Twin object model.
3. Create first mock object fixtures for Compound Pharmacy, IRLT / Radiopharma, and DSCSA.
4. Create digital twin state validator after mock fixtures are locked.
