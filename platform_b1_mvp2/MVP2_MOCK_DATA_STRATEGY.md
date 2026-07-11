# MVP2 Mock Data Strategy — Platform B1

## Purpose

Define the first mock data strategy for Platform B1 / MVP2 before building evaluator logic.

## Mock Data Categories

1. Evidence records
2. AI-GMP content review records
3. SOP reality records
4. Action admissibility records
5. Workflow dependency records
6. Regulatory inspection passport records
7. Claim-to-proof records
8. Source-of-truth records
9. Role/persona session records
10. Enterprise Azure signal records

## Mock Systems

Use simulated examples only:

- Mock LIS
- Mock middleware
- Mock instrument server
- Mock SOP repository
- Mock CAPA/deviation system
- Mock eQMS
- Mock ServiceNow/CMDB
- Mock Azure security posture
- Mock Sentinel incident
- Mock Purview lineage
- Mock AI Search result
- Mock Document Intelligence extraction

## Prakriti Mock Case

Case name:

Middleware Verified / LIS Held

Scenario:

A lab result is verified in middleware, but the workflow is still held in LIS because a mandatory audit/accountability field is missing.

Expected output:

WORKFLOW APPEARS COMPLETE BUT BLOCKED

Reason:

LIS HOLD DETECTED

Missing:

Mandatory audit/accountability field

Action:

SECONDARY REVIEW REQUIRED

Evidence state:

AUDIT EVIDENCE NOT READY
