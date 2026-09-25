# Watch-Derived Assurance Refinements R1

Status: **EXPERIMENTAL / RECONCILED RESEARCH SURFACE**

This package implements assurance refinements identified in the Aug. 29–Sept. 2 watch/backfill material that were not already first-class constructs on the reconciled `main`. It intentionally reuses the existing Step 175–183 shared assurance core rather than creating duplicate modules.

## Implemented refinements

### Initial R1 set

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

### Aug. 31 additive set

24. Refusal Survivability Standing
25. Repairability Routing Standing
26. Intent Constitution Artifact Standing
27. Consequence Incapacity Challenge Pattern
28. Digital Proxy Non-Authority
29. Evidence Plane Survivability
30. Lifecycle Exit / Retirement Standing
31. Persistent Memory Admissibility + Retrieval Custody
32. Definition / Evidence Correspondence
33. Outcome-to-Next-Cycle Inheritance Standing
34. Measurement Semantic Standing
35. Measurement Context Representativeness
36. Lineage Challenge Record
37. Architecture Influence Provenance Ledger
38. Demonstration Participation Record
39. Framework-Neutral Qualification Envelope

### Sept. 2 additive set

40. Independent Reproduction Standing
41. Assurance Test-Harness Integrity
42. Challenge Population & Selection Provenance Standing
43. Evidence Reconstruction Provenance / Non-Retroactive Recovery
44. Criteria Standing
45. Active Mandate Re-attestation
46. Human Oversight Capability Preservation Standing
47. Human Oversight Standing & Credential Disposition Separation
48. Gate Discrimination Health / Population-Level Control Effectiveness
49. Institutional State Origin Standing
50. Physical Authorization Context Standing
51. Observation / Measurement Event Existence Standing

See `AUG31_RECONCILIATION.md` and `SEP02_RECONCILIATION.md` for detailed mappings, non-duplication decisions, provenance corrections, and deferred items.

## Existing concepts deliberately not duplicated

Current main already contains, among other controls, assurance-control capacity, epistemic-class preservation, Boundary Assurance Capsules, typed recovery standing, Processing Authority Standing, Disposition Standing, Action Admissibility, No-Bind, proposition-specific VSA reassessment/selective restoration, physical evidence standing, execution-time revalidation, atomic commit binding, outcome correspondence, and recovery/re-closure. Those remain authoritative dependencies rather than being reimplemented here.

R3A/C02 configured physical-witness evidence remains a separate frozen experimental/evidence lineage and is not reimplemented by this package.

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
- `VETO_EXISTS != VETO_IS_PRACTICALLY_EXERCISABLE`
- `FAST_EXECUTION_CAPABILITY != FAST_EXECUTION_ADMISSIBILITY`
- `AGENT_INSTRUCTION_EXISTS != GOVERNED_INTENT_ESTABLISHED`
- `BLOCK_LOGGED != CONSEQUENCE_PREVENTED`
- `PERSON_MODEL_OR_PREDICTION != HUMAN_AUTHORITY`
- `EVIDENCE_SERVICE_UNAVAILABLE != NO_CONTRADICTION_FOUND`
- `SYSTEM_RETIRED != RESIDUAL_ROUTES_CLOSED`
- `MEMORY_VALID_WHEN_WRITTEN != MEMORY_ADMISSIBLE_NOW`
- `HISTORICAL_EVIDENCE_VALID != CURRENT_DEFINITION_CORRESPONDENCE`
- `PRIOR_SUCCESS != NEXT_CYCLE_AUTHORIZATION`
- `NUMERIC_VALUE != DECISION_GRADE_MEASUREMENT`
- `CALIBRATED_SENSOR != REPRESENTATIVE_MEASUREMENT`
- `CHRONOLOGY != DERIVATION != AUTHORSHIP != OWNERSHIP`
- `PARTICIPATION != AUTHORSHIP != OWNERSHIP != CERTIFICATION != AUTHORITY`
- `QUALIFICATION != AUTHORITY`
- `CROSS_ARCHITECTURE_REVIEW != ONTOLOGY_CONVERGENCE`
- `REPRODUCIBLE_PACKAGE != INDEPENDENTLY_REPRODUCED`
- `CONTROL_TEST_PASS != TEST_HARNESS_TRUSTWORTHY`
- `PASS_ON_SELECTED_CHALLENGES != SUPPORT_FOR_UNEXAMINED_CLAIM_SURFACE`
- `RECONSTRUCTED_RECORD != ORIGINAL_RECORD`
- `QUALIFIED_UNDER_K1 + CURRENT_CRITERIA_K2 != CURRENTLY_QUALIFIED`
- `MANDATE_RECORD_CURRENT != MANDATE_STANDING_DEMONSTRATED`
- `APPROVAL_EVENT != MEANINGFUL_HUMAN_OVERSIGHT`
- `CREDENTIAL_VALID != CURRENT_SCOPE_VALID`
- `GATE_PRESENT != GATE_MEANINGFULLY_DISCRIMINATING`
- `CLIENT_STATE != INSTITUTIONAL_STATE`
- `PRIOR_AUTHORIZATION != PRESENT_EXECUTION_PERMISSION`
- `RECORD_EXISTS != SAMPLE_COLLECTED != MEASUREMENT_PERFORMED != DECISION_SUPPORTED`

## Evidence / provenance boundary

The watch documents are external research and public-landscape inputs. They are not implementation evidence for COBIT-Chain. This package is an independent COBIT-Chain implementation of generic assurance problems extracted from those inputs. Similar terminology does not establish derivation, ownership, architectural equivalence, certification, regulatory acceptance, or production validity.

The Sept. 2 reconciliation also records the S3DVS registry-ID correction and explicitly prohibits carrying the withdrawn `TA-14-AIGR-000027` association forward as current S3DVS provenance.

## Test status

The Aug. 29–31 baseline documented **39 bounded refinement/test propositions** before the Sept. 2 additions.

The Sept. 2 module adds **12 deterministic test cases** across 12 difference-first refinements. CI status must be observed on the feature branch/PR before these additions can be represented as GitHub-hosted passing evidence.

Combined experimental inventory: **51 bounded refinement propositions**. A passing test remains evidence only for the exercised software property; it is not certification, regulatory acceptance, production validation, or deployment authority.

## Deferred rather than duplicated

Items such as federated standing declarations, assurance throughput/headroom benchmarking, OEM/data-center witness demonstrations, public corpus/Mission Control, Academy/competency surfaces, hardware/eBPF/network enforcement, and production cross-architecture interoperability remain research/demo/v2 work unless separately authorized and implemented.

The future R4 physical-witness proposition should compose existing Step 176, Step 180–183, and Sept. 2 authorization-context refinements rather than create a parallel runtime engine.
