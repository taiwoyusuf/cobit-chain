# MVP2 Feature Registry — Platform B1

Status: PLANNING LOCK  
Workstream: Platform B1 — Advanced Assurance Preview MVP  
Companion Display Layer: Thread D2 — RAMAT Vision Advanced Assurance Preview

## Depth Legend

| Depth | Meaning |
|---|---|
| Deep now | Build MVP2 logic, input model, output result, mock evidence object, and dashboard/API result. |
| Medium now | Build simplified logic and UI result, with deeper backend later. |
| Shallow now | Preview/demo card only. |
| MVP3 later | Roadmap only. Do not build now. |

---

# Deep MVP2 Features

| # | Feature | Plain-English Purpose | Depth |
|---:|---|---|---|
| 1 | SERAPH Lite — Evidence Integrity Seal | Seal evidence with hash/proof metadata and detect stale, changed, or missing evidence. | Deep now |
| 2 | Evidence Reconstruction Lite | Rebuild one regulated event: who, what, when, system, evidence, AI involvement, reviewer, decision. | Deep now |
| 3 | Assurance Black Box Lite | Create a minimum proof packet for one critical regulated event. | Deep now |
| 4 | AI-GMP Content Review Passport | Check whether AI-generated or AI-assisted GMP content had human and Quality Unit review before use. | Deep now |
| 5 | AI-Generated Content Disclosure Lens | Show whether AI created, summarized, edited, translated, corrected, classified, or influenced regulated content. | Deep now |
| 6 | Human Oversight Effectiveness Assurance | Check whether human review is real, competent, timely, and evidenced. | Deep now |
| 7 | Living SOP Assurance Lite | Check whether a SOP still matches operational reality. | Deep now |
| 8 | Action-to-SOP Admissibility | Check whether a human or AI action is allowed under current SOP, training, and context. | Deep now |
| 9 | Workflow Dependency Assurance Lens | Detect hidden workflow blockers across LIS, middleware, instruments, fields, mappings, identity, latency, firewall/timeouts, and audit requirements. | Deep now |
| 10 | Regulatory AI Inspection Passport Lite | Create an inspection-readiness passport for one regulated object, record, SOP, CAPA, deviation, AI output, or equipment. | Deep now |
| 11 | Claim-to-Proof Scanner | Check whether a regulated claim is supported by evidence. | Deep now |
| 12 | Source-of-Truth Compass | Identify the approved source of truth when records, systems, or documents conflict. | Deep now |
| 13 | Assurance Persona & Role-Based Interface Passport | Verify user, device, role/persona, and role-based interface authority. | Deep now |

---

# Medium MVP2 Features

| # | Feature | Plain-English Purpose | Depth |
|---:|---|---|---|
| 1 | CAPA-to-SOP Impact Oracle | Check whether CAPA should trigger SOP, training, validation, system, or process updates. | Medium now |
| 2 | Deviation-to-SOP Truth Check | Check whether a deviation means the SOP was wrong, unclear, outdated, or not followed. | Medium now |
| 3 | CAPA Effectiveness Mode Lite | Check whether CAPA worked after closure using recurrence, monitoring, and evidence status. | Medium now |
| 4 | Change Control Reconstruction Lite | Reconstruct why a change happened, who approved it, and what records were impacted. | Medium now |
| 5 | GxP AI Boundary Assurance | Check whether AI stayed in decision-support mode and did not write into regulated systems without approval. | Medium now |
| 6 | Service Workflow No-Bind Lens | Check whether AI routing/remediation in ITSM/CMDB creates operational consequence without approval. | Medium now |
| 7 | AI Artifact Transition Seal | Track AI artifacts across creation, use, transformation, storage, and disposition. | Medium now |
| 8 | Artifact-to-Action Bridge | Show that an AI artifact can inform an action but does not authorize it. | Medium now |
| 9 | Gesture-to-Intent Control Layer | Capture voice/tap/look/gesture intent without treating gesture as GMP approval. | Medium now |

---

# Shallow MVP2 Preview Cards

| # | Feature | Plain-English Purpose | Depth |
|---:|---|---|---|
| 1 | Evidence Weather | Visual evidence health: clear, cloudy, fog, storm, drought. | Shallow now |
| 2 | Regulatory Question Simulator | Generate inspection-style questions from evidence gaps. | Shallow now |
| 3 | Regulatory Response Passport | Track inspection question, response, SME, QA reviewer, evidence, commitment, closure. | Shallow now |
| 4 | Executive AI Governance Dashboard | Leadership view of AI use cases, controls, risks, overdue reviews, and trust state. | Shallow now |

---

# MVP3 Later Features

Do not build these now.

1. ARCHANGEL Full Assurance Ledger
2. CAPA Covenant Chain
3. Deviation Truth Timeline Full
4. Regulated Object Identity Full
5. Autopilot Agent Assurance Passport
6. Always-On Agent Black Box
7. Work Context Boundary Passport
8. Digital Twin-to-GMP Action Lens
9. Bioprocess Scale-Up Assurance Passport
10. Reimbursement Evidence Passport
11. Compliant Engagement Passport
12. Knowledge Graph Evidence Assurance
13. Private AI Runtime Control Passport
14. AI RMF-to-Assurance Evidence Bridge
15. Audit Trail Lens Full
16. Microsoft Scout-to-Assurance Gateway
17. Agent 365 Governance Bridge
18. Work IQ Boundary Assurance

---

# Prakriti Priority Feature

## Workflow Dependency Assurance Lens

MVP2 Depth: Deep now.

This feature detects when a workflow appears complete in one system but is actually blocked, incomplete, delayed, mismatched, or not defensible because of hidden dependencies across connected systems.

## Required Components

1. Dependency Chain Map
2. Hidden Blocker Detector
3. LIS/Middleware Hold Check
4. Mandatory Field Gate
5. Mapping Conflict Check
6. Identity Match Check
7. Interface Latency Signal
8. Communication Path Check
9. Shift/Site Drift Signal
10. Manual Entry Risk Check
11. Secondary Review Gate
12. Audit Evidence Readiness
13. Root Cause Trace Path

## Required Outputs

- WORKFLOW COMPLETE
- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- DEPENDENCY MISSING
- LIS HOLD DETECTED
- MIDDLEWARE VERIFIED ONLY
- MANDATORY FIELD MISSING
- MAPPING CONFLICT
- IDENTITY MISMATCH
- INTERFACE LATENCY DETECTED
- COMMUNICATION PATH BLOCKED
- SHIFT/SITE PROCESS DRIFT
- MANUAL ENTRY REVIEW REQUIRED
- SECONDARY REVIEW REQUIRED
- RESULT RELEASE NOT ADMISSIBLE
- DEPENDENCY CHAIN RECONSTRUCTED
- AUDIT EVIDENCE READY

## Guardrail

Official records remain in source systems.

Platform B1 evaluates dependency assurance.

Thread D2 displays the dependency state.

The glasses do not release results.
