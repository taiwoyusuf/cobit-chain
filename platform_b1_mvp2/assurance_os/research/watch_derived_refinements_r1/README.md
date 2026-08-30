# Watch-Derived Assurance Refinements R1

Status: **EXPERIMENTAL / BRANCH-ONLY**

This package implements assurance refinements identified in the Aug. 29 watch/backfill material that were not found as first-class constructs on current `main` (`26cca1695bcbc0ad3139f7b655b6bd0adf257f4f`). It intentionally reuses the existing Step 178+ shared assurance core rather than creating duplicate modules.

## Implemented refinements

1. Non-Compensatory Assurance Standing / Critical-Gate Integrity
2. Human Oversight Queue Standing (signal quality + meaningful review depth)
3. Claim Identity and Discharge Standing
4. Independent Evidence Plane Standing
5. Recovery Path Noninterference
6. Assessor Independence Standing
7. Revocation Propagation & Delegation Attenuation
8. Residual Obligation Liveness / Duty Horizon Continuity
9. Governed Interoperability Seam Standing
10. Retrospective Reliance Exposure
11. Shared-Condition / Common-Cause Exposure Standing
12. Document Parse Fidelity Standing
13. Tool Sequence & Information-Flow Standing
14. Source-to-Artifact Correspondence
15. Test Semantic Correspondence
16. Claim Strength Ceiling
17. Normative Completeness Standing
18. Control Failure Cause Classification
19. Agency Justification / Maximum Delegation Class
20. Registry Resolution Standing
21. Instance-Bound Evidence Sufficiency
22. Physical-Digital Temporal Correspondence
23. Institutional Independence Standing

## Existing concepts deliberately not duplicated

Current main already contains, among other controls, assurance-control capacity, epistemic-class preservation, boundary assurance capsules, typed recovery standing, Processing Authority Standing, and Disposition Standing. Those remain authoritative shared-core dependencies for this package rather than being reimplemented here.

## Core non-substitution rules

- `HIGH_AGGREGATE_SCORE != CRITICAL_GATE_STANDING`
- `SUPPORTED_CLAIM_A != DISCHARGE_OF_CLAIM_B`
- `SYSTEM_LOG != INDEPENDENT_WITNESS_EVIDENCE`
- `PREVENTIVE_CONTROL != PERMISSION_TO_BLOCK_AUTHORIZED_RECOVERY`
- `ASSESSOR_METHOD_GUIDANCE != ASSESSOR_SOLUTION_SHAPING`
- `DERIVED_SCOPE <= PARENT_CURRENT_SCOPE`
- `CUSTODY_TRANSFER != NEW_DUTY_CLOCK`
- `ENDPOINT_A_STANDING + ENDPOINT_B_STANDING != INTERFACE_STANDING`
- `HISTORICAL_EXPOSURE_REVIEW != RETROACTIVE_INVALIDATION`
- `COMMON_CONDITION_CHANGED != ALL_DEPENDENTS_FAILED`
- `PARSED_TEXT != SOURCE_MEANING_PRESERVED`
- `TOOL_A_AUTHORIZED + TOOL_B_AUTHORIZED != A_TO_B_FLOW_AUTHORIZED`
- `ARTIFACT_DIGEST != SOURCE_TO_ARTIFACT_CORRESPONDENCE`
- `TEST_LABEL != ACTUAL_TESTED_PROPERTY`
- `REPEATED_SUCCESS != UNIVERSAL_CLAIM`
- `FACTUAL_CORRECTNESS != NORMATIVE_COMPLETENESS`
- `SYSTEM_STANDING != INSTANCE_STANDING`
- `CLOCK_SYNCHRONIZATION != PHYSICAL_DIGITAL_CORRESPONDENCE`
- `ROLE_SEPARATION_ON_DIAGRAM != INSTITUTIONAL_INDEPENDENCE`

## Evidence / provenance boundary

The attached watch documents are external research and public-landscape inputs. They are not implementation evidence for COBIT-Chain. This R1 package is an independent COBIT-Chain implementation of generic assurance problems extracted from those inputs. Similar terminology does not establish derivation, ownership, architectural equivalence, certification, regulatory acceptance, or production validity.

## Test status

Two deterministic test files exercise **23 bounded invariants total; 23/23 PASS** in the pre-publication local run.

## Deferred rather than implemented as runtime gates

Research/productization items such as `CAUSAL_WORLD_MODEL_ASSURANCE`, `ENTERPRISE_AUTONOMY_EXPOSURE_STANDING`, federated assurance productization, public Assurance Corpus/Mission Control, Academy/competency surfaces, and independent eBPF/network enforcement remain research/demo/v2 work. They are not silently promoted into current runtime authority.

## Merge status

Do not merge to `main` merely because these tests pass. Each refinement remains bounded experimental work until reconciled with the numbered Step sequence, publication chronology, Step 183 recovery/re-closure work, and domain-profile acceptance criteria.
