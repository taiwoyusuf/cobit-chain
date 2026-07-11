# DSCSA Evidence Integrity and Exception Assurance Addendum

Status: LOCKED TOP-TIER EXTENSION ADDENDUM

Workstream: Platform B1 / MVP2

Track: DSCSA Evidence Integrity & Exception Assurance

Priority: FIRST TIER

## Purpose

This addendum defines the DSCSA top-tier extension for COBIT-Chain as an evidence-integrity, exception-assurance, chain-of-custody, and AI-governance layer.

This does not build a real DSCSA integration yet.

## Core question

Can serialized prescription-drug supply-chain evidence be trusted, reconstructed, and defended across trading-partner handoffs, EPCIS evidence, VRS response, exception resolution, and AI-assisted triage?

## Doctrine

Serialization is not enough.

Traceability is not enough.

A DSCSA event is trustworthy only when product identity, trading partner identity, EPCIS evidence, VRS response state, exception history, resolution evidence, and source-system records agree.

COBIT-Chain does not move product.

COBIT-Chain does not become EPCIS.

COBIT-Chain does not become VRS.

COBIT-Chain does not become ERP or WMS.

COBIT-Chain does not replace trading partner systems.

COBIT-Chain verifies whether the DSCSA evidence chain can be trusted.

## DSCSA Evidence Integrity Seal

Each DSCSA event should be capable of being sealed with a hash and later rehashed when source evidence changes.

Sealed evidence objects include:

- GTIN
- serial number
- lot
- expiry
- event type
- source trading partner
- receiving trading partner
- EPCIS file reference
- EPCIS file hash
- shipment reference
- aggregation hierarchy
- event timestamp
- system source
- actor identity
- exception status
- VRS response state
- resolution evidence
- human reviewer
- AI output hash where AI assisted

Rehash triggers include:

- EPCIS file changed
- serial event corrected
- aggregation hierarchy changed
- trading partner evidence updated
- VRS response received or changed
- exception classification changed
- resolution evidence added
- AI-generated summary updated
- human reviewer disposition changed

Example outputs:

- DSCSA EVIDENCE SEALED
- HASH VERIFIED
- REHASH REQUIRED
- SERIAL EVENT CHANGED
- EPCIS FILE MISMATCH
- CHAIN OF CUSTODY GAP
- TRADING PARTNER EVIDENCE MISSING
- AGGREGATION CONFLICT

## DSCSA Exception Assurance Passport

The DSCSA Exception Assurance Passport classifies and reconstructs exception evidence.

Exception types include:

- missing EPCIS data
- late EPCIS data
- unreadable 2D barcode
- serial number mismatch
- lot mismatch
- expiry mismatch
- aggregation error
- duplicate serial
- unknown trading partner
- VRS no response
- suspect product trigger
- illegitimate product trigger
- quarantine required
- clerical exception likely

Exception passport fields include:

- exception type
- risk level
- product impact
- patient access impact
- trading partner contacted
- evidence received
- resolution path
- human reviewer
- final disposition
- hash status
- rehash status
- audit-ready record

Example outputs:

- DSCSA EXCEPTION DETECTED
- CLERICAL EXCEPTION LIKELY
- SUSPECT PRODUCT REVIEW REQUIRED
- QUARANTINE REQUIRED
- PATIENT ACCESS RISK
- EXCEPTION RESOLUTION EVIDENCE COMPLETE
- EXCEPTION NOT DEFENSIBLE

## Authorized Trading Partner Trust Passport

Checks include:

- trading partner identity present
- authorized status evidence present
- license evidence current
- credential evidence current
- last successful transaction available
- open unresolved exceptions checked
- exception history reviewed
- VRS reachable or response evidence available
- EPCIS exchange state available

Example outputs:

- TRADING PARTNER VERIFIED
- TRADING PARTNER EVIDENCE STALE
- AUTHORIZED STATUS NOT VERIFIED
- VRS RESPONSE MISSING
- PARTNER EXCEPTION HISTORY HIGH
- SHIPMENT ACCEPTANCE REVIEW REQUIRED

## EPCIS Data Quality Assurance Lens

Checks include:

- EPCIS format valid
- required fields present
- event choreography consistent
- source and destination match
- parent-child aggregation valid
- serials match physical scan
- shipping event matches receiving event
- lot and expiry consistent
- duplicate serial not found

Example outputs:

- EPCIS VALID
- EPCIS FORMAT ERROR
- EPCIS REQUIRED FIELD MISSING
- SOURCE DESTINATION MISMATCH
- PARENT CHILD AGGREGATION BROKEN
- PHYSICAL DIGITAL SERIAL MISMATCH
- DOWNSTREAM EXCEPTION LIKELY

## AI-Governed DSCSA Exception Copilot Boundary

AI may:

- classify exception type
- summarize EPCIS mismatch
- draft trading partner outreach
- recommend review routing
- summarize VRS response state
- summarize exception trend
- prepare audit package draft

AI may not:

- release product
- override quarantine
- declare DSCSA compliance
- declare product legitimate or illegitimate without responsible human review
- replace required regulatory, quality, or trading-partner processes
- alter EPCIS, VRS, ERP, WMS, or source-system truth without governed human action

Required AI controls:

- AI agent identity
- model version
- prompt version
- approved context of use
- input source traceability
- tool-call evidence
- human reviewer
- quality or compliance reviewer where required
- AI output hash
- rehash status when source evidence changes
- recommendation-versus-execution boundary

Example outputs:

- AI EXCEPTION CLASSIFICATION GENERATED
- AI CONFIDENCE LOW
- AI RECOMMENDATION REVIEW REQUIRED
- AI CONTEXT NOT APPROVED
- AI OUTPUT HASHED
- MODEL VERSION RECORDED
- HUMAN REVIEW REQUIRED
- QUALITY REVIEW REQUIRED
- AGENT ACTION NOT ADMISSIBLE

## First mock scenario direction

Scenario:

Late EPCIS / VRS No Response Exception

Status:

DEFINED NOT BUILT

Input state:

- serialized shipment received
- physical scan captured
- EPCIS data late or incomplete
- VRS response missing
- trading partner evidence stale
- AI classifies exception as review required
- human reviewer required before disposition

Expected outputs:

- DSCSA EXCEPTION DETECTED
- EPCIS FILE MISMATCH
- VRS RESPONSE MISSING
- TRADING PARTNER EVIDENCE STALE
- AI EXCEPTION CLASSIFICATION GENERATED
- HUMAN REVIEW REQUIRED
- QUARANTINE REQUIRED
- EXCEPTION NOT DEFENSIBLE

## Commercial relevance

This addendum supports:

- compound pharmacy first-tier track
- IRLT / radiopharma operations first-tier track
- manufacturer
- repackager
- wholesaler
- dispenser
- supply-chain quality reviewer
- trading partner compliance owner
- consultant or compliance advisor

## Boundary

Addendum only.

Do not modify Platform B v1.

Do not reopen Thread D v1.

Do not activate MVP3.

Do not build real EPCIS integration now.

Do not build real VRS integration now.

Do not connect to real trading partner systems now.

Do not use real DSCSA production data.

Do not use real ServiceNow production data.

No PHI.

No company production data.

No product release decision.

No quarantine override.

Platform B1 evaluates.

Thread D2 displays.

Official records remain in source systems.

Humans remain accountable.

Quality or compliance reviewer remains authoritative where required.

## Next order of work

1. Commit DSCSA addendum.
2. Merge DSCSA addendum.
3. Create Compound Pharmacy commercialization addendum.
4. Create IRLT / Radiopharma Operations first-tier addendum.
5. Create shared Regulated Operations Digital Twin object model.
6. Build first DSCSA mock scenario after addenda are locked.

