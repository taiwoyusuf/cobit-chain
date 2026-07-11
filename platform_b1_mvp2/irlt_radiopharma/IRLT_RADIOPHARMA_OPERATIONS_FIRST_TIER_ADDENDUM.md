# IRLT / Radiopharma Operations First-Tier Addendum

Status: LOCKED FIRST-TIER OPERATIONS ADDENDUM

Workstream: Platform B1 / MVP2

Track: IRLT / Radiopharma Operations

Priority: FIRST TIER

Commercial position: First-tier regulated operations and radiopharma demonstration track for COBIT-Chain.

## Purpose

This addendum defines the IRLT / Radiopharma Operations first-tier track as a regulated-operations assurance scenario covering equipment readiness, CI readiness, ServiceNow operational evidence, manufacturing handoffs, quality dependencies, AI-governed recommendations, and RAMAT Vision display.

This does not build real production integrations.

## Core question

Can IRLT / radiopharma operational execution be trusted, reconstructed, and defended across equipment, CI readiness, controlled handoffs, quality dependencies, ServiceNow operational state, AI-assisted recommendations, and evidence state?

## Operational package

Package name:

IRLT / Radiopharma Operations Assurance Package

Status:

DEFINED NOT BUILT

Target users:

- radiopharma operations leader
- GMP manufacturing technology owner
- quality reviewer
- IT / LCM / CMDB owner
- ServiceNow process owner
- maintenance or engineering owner
- auditor or inspector
- RAMAT Vision field user

Operational pain points:

- equipment readiness uncertainty
- CI and CMDB ownership gaps
- ServiceNow change or incident evidence not aligned with execution
- quality dependency not visible at execution time
- handoff ambiguity between IT, manufacturing, quality, vendor, and engineering
- AI recommendation without clear accountability
- manual evidence reconstruction burden
- late discovery of operational blockers
- difficulty proving what was known at the time of action

Positioning statement:

COBIT-Chain helps IRLT / radiopharma operations determine whether equipment, CI, ServiceNow, quality, AI, and workflow evidence can be trusted before regulated execution, audit review, deviation assessment, or operational handoff.

## Assurance components

### Equipment and CI Readiness Assurance

Purpose:

Check whether equipment identity, CI state, ownership, lifecycle, support group, validation status, and operational readiness are sufficient for regulated use.

Example outputs:

- EQUIPMENT CI READY
- CI READINESS GAP
- LCM OWNER MISSING
- SUPPORT GROUP MISSING
- VALIDATION STATUS REVIEW REQUIRED
- EQUIPMENT NOT READY FOR REGULATED EXECUTION

### ServiceNow Operational Assurance

Purpose:

Check whether change, incident, problem, CMDB, LCM, access, and operational records support the execution state.

Example outputs:

- SERVICENOW EVIDENCE FOUND
- CHANGE CONTROL REVIEW REQUIRED
- INCIDENT IMPACT REVIEW REQUIRED
- CMDB RELATIONSHIP GAP
- ACCESS ROUTING REVIEW REQUIRED
- OPERATIONAL RECORD NOT DEFENSIBLE

### Controlled Handoff Assurance

Purpose:

Check whether manufacturing, IT, quality, maintenance, vendor, and engineering handoffs are clear, accountable, and evidence-backed.

Example outputs:

- CONTROLLED HANDOFF VERIFIED
- HANDOFF OWNER MISSING
- SHIFT HANDOFF REVIEW REQUIRED
- VENDOR HANDOFF RESTRICTED
- RESPONSIBILITY GAP DETECTED

### Quality Dependency Assurance

Purpose:

Check whether quality dependencies such as deviation state, CAPA linkage, validation state, audit trail review, SOP alignment, and release-support evidence are acceptable.

Example outputs:

- QUALITY DEPENDENCY VERIFIED
- QUALITY DEPENDENCY BLOCKED
- DEVIATION IMPACT REVIEW REQUIRED
- CAPA LINK REVIEW REQUIRED
- SOP ALIGNMENT REVIEW REQUIRED
- QUALITY REVIEW REQUIRED

### Radiopharma Execution Context Assurance

Purpose:

Check whether the execution context, equipment state, timing sensitivity, operational readiness, environmental state, and evidence package support the radiopharma operation.

Example outputs:

- RADIOPHARMA EXECUTION CONTEXT VERIFIED
- EXECUTION CONTEXT INCOMPLETE
- TIME-SENSITIVE HANDOFF REVIEW REQUIRED
- ENVIRONMENTAL STATE REVIEW REQUIRED
- OPERATIONAL BLOCKER DETECTED

### RAMAT Vision Field Display Assurance

Purpose:

Define what RAMAT Vision / Thread D2 may display to field users without approving regulated work.

Example outputs:

- RAMAT VISION DISPLAY READY
- ROLE VERIFIED
- READ-ONLY REVIEW ACTIVE
- ACTION NOT PERMITTED FOR ROLE
- FIELD REVIEW REQUIRED
- PLATFORM B1 DECISION DISPLAYED

### AI Recommendation Boundary Assurance

Purpose:

Check whether AI-assisted operational recommendations are traceable, reviewed, bounded, hashed, and not mistaken for approval.

Example outputs:

- AI RECOMMENDATION GENERATED
- AI RECOMMENDATION REVIEW REQUIRED
- AI OUTPUT HASHED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- AGENT ACTION NOT ADMISSIBLE

## IRLT / Radiopharma Operations Evidence Integrity Seal

Hashing required: yes

Rehashing required: yes

Sealed evidence objects include:

- equipment identifier
- CI identifier
- application service reference
- owner and support group
- LCM status
- validation status
- change record reference
- incident record reference
- access or entitlement evidence
- handoff record
- quality dependency status
- deviation or CAPA reference where applicable
- SOP or procedure reference
- environmental or facility context where applicable
- RAMAT Vision display event
- AI output hash where AI assisted
- human reviewer
- final evidence package hash

Example outputs:

- IRLT EVIDENCE SEALED
- HASH VERIFIED
- REHASH REQUIRED
- CI RECORD CHANGED
- SERVICE NOW EVIDENCE CHANGED
- QUALITY REVIEW STATE CHANGED
- RAMAT DISPLAY EVENT SEALED

## IRLT / Radiopharma Workflow Dependency Assurance Lens

Example outputs:

- IRLT WORKFLOW COMPLETE
- IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED
- EQUIPMENT DEPENDENCY MISSING
- CI DEPENDENCY MISSING
- SERVICENOW DEPENDENCY MISSING
- QUALITY DEPENDENCY BLOCKED
- ACCESS DEPENDENCY REVIEW REQUIRED
- HANDOFF REVIEW REQUIRED
- IRLT PACKAGE DEFENSIBLE

## RAMAT Vision display boundary

RAMAT Vision may display:

- readiness state
- CI readiness state
- ServiceNow evidence state
- quality dependency state
- handoff status
- role-based view
- AI recommendation review state
- evidence package status
- field review prompt

RAMAT Vision may not:

- approve GMP work
- release product
- override ServiceNow, QMS, LIS, MES, ERP, or source-system records
- replace Quality Unit review
- replace human accountability
- convert AI recommendation into approval

Example outputs:

- RAMAT VISION DISPLAY READY
- USER SIGN-IN REQUIRED
- ROLE VERIFIED
- PRODUCTION MANAGER VIEW ACTIVE
- QA REVIEW VIEW ACTIVE
- AUDITOR READ-ONLY VIEW ACTIVE
- ACTION NOT PERMITTED FOR ROLE
- PLATFORM B1 DECISION DISPLAYED

## AI operational recommendation boundary

AI may:

- summarize operational readiness evidence
- identify missing CI or equipment evidence
- draft change or incident impact summary
- classify quality dependency review state
- recommend review routing
- prepare field guidance for RAMAT Vision display
- prepare audit package draft

AI may not:

- release product
- approve GMP work
- override ServiceNow, QMS, LIS, MES, ERP, or source-system records
- replace Quality Unit review
- authorize regulated execution without accountable human governance
- convert recommendation into approval

Example outputs:

- AI RECOMMENDATION GENERATED
- AI RECOMMENDATION REVIEW REQUIRED
- AI OUTPUT HASHED
- MODEL VERSION RECORDED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- AGENT ACTION NOT ADMISSIBLE

## First demo direction

Scenario:

IRLT Equipment / CI / Quality Handoff Review

Status:

DEFINED NOT BUILT

Expected outputs:

- IRLT EVIDENCE SEALED
- HASH VERIFIED
- CI READINESS GAP
- SUPPORT GROUP MISSING
- INCIDENT IMPACT REVIEW REQUIRED
- QUALITY DEPENDENCY BLOCKED
- AI RECOMMENDATION REVIEW REQUIRED
- RAMAT VISION DISPLAY READY
- HUMAN REVIEW REQUIRED
- IRLT WORKFLOW APPEARS COMPLETE BUT BLOCKED

## Boundary

Addendum only.

Do not modify Platform B v1.

Do not reopen Thread D v1.

Do not activate MVP3.

Do not build new commercial module now.

Do not connect to real ServiceNow production data now.

Do not connect to real LIS, MES, ERP, eQMS, or QMS production systems now.

No PHI.

No company production data.

No product release decision.

No GMP approval decision.

No Quality Unit replacement.

No source-system override.

No real radiopharma production data.

Platform B1 evaluates.

Thread D2 displays.

RAMAT Vision displays only.

Official records remain in source systems.

Humans remain accountable.

## Next order of work

1. Commit IRLT / Radiopharma Operations first-tier addendum.
2. Merge IRLT / Radiopharma Operations first-tier addendum.
3. Create shared Regulated Operations Digital Twin object model.
4. Build first IRLT / Radiopharma mock demo after addenda are locked.
