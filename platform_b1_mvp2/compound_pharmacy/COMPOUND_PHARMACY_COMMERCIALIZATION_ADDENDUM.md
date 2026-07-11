# Compound Pharmacy Commercialization Addendum

Status: LOCKED FIRST-TIER COMMERCIALIZATION ADDENDUM

Workstream: Platform B1 / MVP2

Track: Compound Pharmacy

Priority: FIRST TIER

Commercial position: One of the first commercial target groups for COBIT-Chain.

## Purpose

This addendum defines the Compound Pharmacy first-tier commercialization track as a packaged evidence-integrity, workflow-dependency, preparation-readiness, quality-review, and AI-governance assurance offering.

This does not build a new uncontrolled module.

## Core question

Can a compounded preparation workflow be trusted, reconstructed, reviewed, and defended from order intake, formula, ingredients, lot traceability, calculations, equipment, preparation, quality review, BUD evidence, and final evidence package?

## Commercial package

Package name:

Compound Pharmacy Assurance Package

Status:

DEFINED NOT BUILT

Target buyers:

- compounding pharmacy owner
- pharmacist in charge
- quality manager
- compliance consultant
- multi-site pharmacy operator
- specialty pharmacy operator
- inspection readiness advisor

Buyer pain points:

- paper-heavy evidence review
- formula and preparation record inconsistency
- ingredient lot traceability gaps
- beyond-use-date evidence uncertainty
- manual calculation review burden
- operator accountability gaps
- quality review delays
- inspection readiness anxiety
- AI-generated SOP or procedure content risk
- difficulty reconstructing what happened after the fact

Positioning statement:

COBIT-Chain helps compound pharmacies determine whether preparation evidence, workflow dependencies, AI-assisted content, and quality-review readiness can be trusted before audit, inspection, release-support review, or internal quality review.

## Assurance components

### Formula Evidence Assurance

Purpose:

Check whether the formula, version, calculation basis, ingredients, and preparation instructions are traceable and defensible.

Example outputs:

- FORMULA EVIDENCE VERIFIED
- FORMULA VERSION MISMATCH
- CALCULATION REVIEW REQUIRED
- APPROVED FORMULA NOT FOUND

### Ingredient and Lot Traceability Assurance

Purpose:

Check whether ingredients, lots, expiry, status, and supplier evidence support the preparation.

Example outputs:

- MATERIAL LOT TRACEABLE
- INGREDIENT STATUS NOT VERIFIED
- LOT EXPIRY REVIEW REQUIRED
- SUPPLIER EVIDENCE MISSING

### Preparation Record Integrity Assurance

Purpose:

Check whether preparation steps, timestamps, operator identity, equipment, and verification evidence form a defensible record.

Example outputs:

- PREPARATION RECORD COMPLETE
- PREPARATION STEP EVIDENCE MISSING
- OPERATOR ACCOUNTABILITY GAP
- SECOND CHECK REQUIRED

### BUD Evidence Assurance

Purpose:

Check whether beyond-use-date evidence is documented, reviewable, and consistent with the preparation context.

Example outputs:

- BUD EVIDENCE VERIFIED
- BUD EVIDENCE REVIEW REQUIRED
- BUD RATIONALE MISSING
- BUD CONFLICT DETECTED

### Quality Review Readiness Assurance

Purpose:

Check whether the preparation evidence package is ready for pharmacist, quality, or compliance review.

Example outputs:

- QUALITY REVIEW READY
- QUALITY REVIEW REQUIRED
- REVIEW PACKAGE INCOMPLETE
- COMPOUNDING PACKAGE DEFENSIBLE

### AI-GMP Content Review Assurance

Purpose:

Check whether AI-generated or AI-assisted SOPs, preparation summaries, discrepancy summaries, or review notes are disclosed, traceable, hashed, and human-reviewed.

Example outputs:

- AI CONTENT DISCLOSED
- AI CONTENT REVIEW REQUIRED
- AI OUTPUT HASHED
- HUMAN REVIEW REQUIRED
- AI CONTENT NOT CLEARED FOR USE

## Compound Pharmacy Evidence Integrity Seal

Hashing required: yes

Rehashing required: yes

Sealed evidence objects include:

- order or preparation request reference
- formula identifier
- formula version
- ingredient list
- ingredient lot numbers
- ingredient expiry dates
- supplier evidence reference
- calculation evidence
- equipment reference
- operator identity
- verifier identity
- preparation timestamps
- BUD evidence
- quality review status
- AI output hash where AI assisted
- final evidence package hash

Rehash triggers include:

- formula changed
- ingredient lot changed
- calculation corrected
- BUD rationale updated
- preparation record updated
- operator or verifier correction added
- quality review disposition changed
- AI-generated summary updated
- supporting evidence added or replaced

Example outputs:

- COMPOUNDING EVIDENCE SEALED
- HASH VERIFIED
- REHASH REQUIRED
- FORMULA RECORD CHANGED
- MATERIAL LOT TRACEABILITY GAP
- QUALITY REVIEW STATE CHANGED

## Compound Pharmacy Workflow Dependency Assurance Lens

Dependency checks include:

- order or preparation request present
- approved formula present
- ingredient lots verified
- calculation reviewed
- equipment readiness checked
- operator identity captured
- second check captured where required
- BUD evidence present
- quality review status present
- AI content review completed where AI assisted
- final package sealed

Example outputs:

- COMPOUNDING WORKFLOW COMPLETE
- COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED
- FORMULA DEPENDENCY MISSING
- MATERIAL LOT DEPENDENCY MISSING
- CALCULATION REVIEW REQUIRED
- SECOND CHECK REQUIRED
- BUD EVIDENCE REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- COMPOUNDING PACKAGE DEFENSIBLE

## Compound Pharmacy AI Content and Review Boundary

AI may:

- summarize preparation evidence
- identify missing evidence fields
- draft discrepancy summary
- draft training or readiness checklist
- draft SOP or procedure content for human review
- classify evidence readiness state
- prepare audit package draft

AI may not:

- release compounded preparation
- approve preparation record
- replace pharmacist review
- replace Quality Unit or quality reviewer oversight
- override source-system evidence
- assign BUD without governed human review
- create uncontrolled instructions for direct regulated use

Required AI controls:

- AI agent identity
- model version
- prompt version
- approved context of use
- input source traceability
- tool-call evidence
- human reviewer
- pharmacist or quality reviewer where required
- AI output hash
- rehash status when source evidence changes
- recommendation-versus-approval boundary

Example outputs:

- AI CONTENT DISCLOSED
- AI CONTENT REVIEW REQUIRED
- AI OUTPUT HASHED
- MODEL VERSION RECORDED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- AI CONTENT NOT CLEARED FOR USE
- AGENT ACTION NOT ADMISSIBLE

## First commercial demo direction

Scenario:

Compound Pharmacy Preparation Package Review

Status:

DEFINED NOT BUILT

Input state:

- preparation request exists
- formula selected
- ingredient lots entered
- calculation evidence present
- BUD evidence incomplete
- AI generated preparation summary
- human review required
- quality review not yet complete

Expected outputs:

- COMPOUNDING EVIDENCE SEALED
- HASH VERIFIED
- BUD EVIDENCE REVIEW REQUIRED
- AI CONTENT REVIEW REQUIRED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- COMPOUNDING WORKFLOW APPEARS COMPLETE BUT BLOCKED
- COMPOUNDING PACKAGE NOT YET DEFENSIBLE

## Commercialization notes

Package existing compound pharmacy module before expanding build scope.

Lead with evidence integrity, workflow dependency, AI content review, and inspection-readiness value.

Use mock data and simulator-first demo only.

Do not claim regulatory approval, release authority, or replacement of pharmacist or quality judgment.

Preserve cross-track alignment with DSCSA and IRLT where supply-chain, material traceability, or radiopharma contexts overlap.

## Boundary

Addendum only.

Do not modify Platform B v1.

Do not reopen Thread D v1.

Do not activate MVP3.

Do not build new commercial module now.

Do not connect to real pharmacy systems now.

Do not use real pharmacy production data.

Do not use real patient data.

No PHI.

No company production data.

No preparation release decision.

No pharmacist replacement.

No quality reviewer replacement.

No source-system override.

Platform B1 evaluates.

Thread D2 displays.

Official records remain in source systems.

Humans remain accountable.

## Next order of work

1. Commit Compound Pharmacy commercialization addendum.
2. Merge Compound Pharmacy commercialization addendum.
3. Create IRLT / Radiopharma Operations first-tier addendum.
4. Create shared Regulated Operations Digital Twin object model.
5. Build first compound pharmacy mock commercial demo after addenda are locked.
