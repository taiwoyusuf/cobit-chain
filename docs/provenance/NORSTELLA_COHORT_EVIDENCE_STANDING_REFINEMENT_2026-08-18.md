# COBIT-Chain™ Source-Informed Cohort Evidence Standing Refinement

**Record date:** 18 August 2026 UTC  
**Status:** `SOURCE_INFORMED_REFINEMENT / PARTIAL_OR_EXPAND`  
**New top-level families:** `0`  
**Authority effect:** none  
**Canonical Audit R3 effect:** none

## 1. Purpose

A newly surfaced Norstella real-world-data signal sharpens an existing COBIT-Chain architecture point: cohort membership is not merely a query result or an AI output. It is a governed derived assertion whose support depends on the semantics, completeness, recency, traceability, relevance and interpretability of multiple upstream sources.

This refinement is subordinate to and composes existing control areas including:

- `DATA_SEMANTIC_STANDING`
- `PRE_INFERENCE_CONTEXT_ADMISSIBILITY`
- `BOUNDED_EVIDENCE_TO_CLAIM_RELIANCE`
- `AI_MEDIATED_WORK_PRODUCT_LINEAGE`
- `REGULATORY_DETERMINATION_RELIANCE_STANDING`

It does not create a new umbrella family.

## 2. Source normalization

User-provided backfill identified Norstella / Kris Kaneta / Theodore Search, “Real-World Data After Dark, S2E2: Finding the Right Patients Faster,” as a newly surfaced July 2026 full-source transcript.

Current first-party Norstella indexing separately surfaces **“Finding the Right Patients Faster: AI and Real-World Data in Practice”**, dated **30 July 2026**, with Kris Kaneta and Ted Search, and describes rapid cohort generation as dependent on trusted, explainable data, transparency, regulatory-grade data and human oversight.

The date/title/name presentation difference is preserved as a provenance-normalization issue rather than silently collapsed.

Norstella also separately states that more than 60% of clinically obese patients may not be identifiable using diagnosis codes alone, supporting a broader coding-coverage control.

FDA remains the authoritative comparator for regulated AI credibility: credibility is evaluated for a specific **Context of Use (COU)** and the evidence burden is tied to that use.

Axendia’s reported AI-in-PLM material is retained here as a **competitive/industry signal only**. It is not used as implementation evidence and does not create a new control family in this increment.

## 3. Refinement A — COHORT_MEMBERSHIP_EVIDENCE_STANDING

**Classification:** `SOURCE_INFORMED_REFINEMENT / PARTIAL_OR_EXPAND`

### Assurance question

For a specific patient cohort and Context of Use, what evidence supports the assertion that a patient belongs—or does not belong—to the cohort, given the available and unavailable source classes, semantic fit, recency, derived rules, AI contribution, human review and uncertainty?

### Governed fields

- `cohort_definition`
- `inclusion_criteria`
- `exclusion_criteria`
- `criteria_version`
- `source_classes_used`
- `source_classes_not_available`
- `claims_evidence`
- `lab_evidence`
- `ehr_emr_evidence`
- `clinical_note_evidence`
- `biomarker_evidence`
- `source_recency`
- `source_semantic_fit`
- `derived_membership_rule`
- `ai_generated_membership_assertion`
- `human_clinical_review`
- `membership_uncertainty`
- `cohort_representativeness`
- `evidence_generation_context`
- `context_of_use`

### Core invariants

`PATIENT_NOT_CODED != PATIENT_NOT_IN_PHENOTYPE`

`CLAIMS_ONLY_COHORT != CLINICALLY_COMPLETE_COHORT`

`MULTIPLE_SOURCES_LINKED != SEMANTIC_ALIGNMENT_ESTABLISHED`

`AI_GENERATED_COHORT != COHORT_MEMBERSHIP_ESTABLISHED`

`COHORT_GENERATED_FASTER != COHORT_EVIDENCE_MORE_CREDIBLE`

`COHORT_MEMBERSHIP_EVIDENCE_STANDING -> MUST_BIND_TO_CONTEXT_OF_USE`

### Required interpretation

A cohort generated in minutes can still have weaker evidence standing than a slower cohort if source completeness, semantic fit, recency, traceability, representativeness, model behavior or clinical review are inadequate.

Likewise, a cohort adequate for market exploration is not automatically adequate for clinical-trial eligibility, regulatory evidence generation, pharmacovigilance, HEOR or another higher-consequence use.

## 4. Refinement B — SEMANTIC_CODING_COVERAGE_STANDING

**Classification:** `SOURCE_INFORMED_REFINEMENT / PARTIAL_OR_EXPAND`

### Assurance question

How completely do available structured codes represent the underlying clinical phenomenon being inferred, and what known coding gaps create bias or false-negative risk?

### Core invariants

`CODE_ABSENT != CLINICAL_CONDITION_ABSENT`

`STRUCTURED_CODE_COVERAGE MUST_BE_EVALUATED_AGAINST THE_CLINICAL_PHENOMENON_BEING_INFERRED`

`KNOWN_CODING_GAP -> COHORT_BIAS_RISK -> REPRESENTATIVENESS_REASSESSMENT_REQUIRED`

### Reuse scope

This control can apply beyond obesity to:

- clinical-trial recruitment and eligibility;
- RWE / RWD evidence generation;
- HEOR;
- pharmacovigilance;
- patient finding;
- disease phenotyping;
- treatment-eligibility inference;
- other workflows where coded data are a lossy proxy for underlying clinical state.

## 5. Axendia competitive signal — no new control

The reported Axendia signal is classified:

`ALREADY_COVERED / COMPETITIVE_SIGNAL`

It reinforces rather than expands the present architecture:

`SYSTEM_OF_RECORD -> SYSTEM_OF_INTELLIGENCE`

only when the operating basis includes:

- connected data;
- workflow context;
- governance;
- evidence;
- user adoption.

Existing COBIT-Chain families already cover connected-data standing, workflow consequence, governance evidence, traceability, current-source standing and human review. `DUPLICATE_CAPABILITY_CREATION = SUPPRESSED`.

## 6. FDA authoritative comparator

The FDA AI credibility framework remains authoritative for regulated drug-development AI use. This refinement therefore preserves:

`COHORT_MEMBERSHIP_EVIDENCE_STANDING -> MUST_BIND_TO_CONTEXT_OF_USE`

and:

`EVIDENCE_ADEQUATE_FOR_ONE_COU != EVIDENCE_ADEQUATE_FOR_ANOTHER_COU`

The relevant risk, credibility evidence, acceptance criteria, oversight and documentation must be evaluated against the specific use for which the AI-derived cohort assertion will be relied upon.

## 7. Controlled registry increment

`NEW_TOP_LEVEL_FAMILIES = 0`

`SOURCE_INFORMED_REFINEMENT_COUNT_THIS_INCREMENT = 2`

`SOURCE_INFORMED_REFINEMENT = COHORT_MEMBERSHIP_EVIDENCE_STANDING`

`SOURCE_INFORMED_REFINEMENT = SEMANTIC_CODING_COVERAGE_STANDING`

`AUTHORITATIVE_COMPARATOR = FDA_CONTEXT_OF_USE_CREDIBILITY_FRAMEWORK`

`COMPETITIVE_SIGNAL = AXENDIA_AI_IN_PLM_LIFECYCLE_SCALE`

`ALREADY_COVERED = CONNECTED_DATA + WORKFLOW_CONTEXT + GOVERNANCE_EVIDENCE + HUMAN_REVIEW + TRACEABILITY + CURRENT_SOURCE_STANDING`

`DUPLICATE_CAPABILITY_CREATION = SUPPRESSED`

`EXTERNAL_SOURCE_MATERIAL != IMPLEMENTATION_EVIDENCE`

The prior aggregate reconciled-control count is not silently rewritten by this documentary increment unless and until the authoritative reconciliation registry is updated in its governed tranche.

## 8. Preserved boundaries

- `AUTHORITY = NONE`
- `NO_BIND = TRUE`
- frozen Canonical Audit state remains untouched;
- `R3-E06 = NOT_AUTHORIZED`;
- no hardware authority is created;
- no Azure authority is created;
- no Platform B1 execution authority is created;
- Norstella public claims are not COBIT-Chain or RAMAT Vision implementation evidence;
- Axendia public/competitive claims are not COBIT-Chain or RAMAT Vision implementation evidence;
- public web and LinkedIn indexing completeness remains `NOT_ESTABLISHED`.

This record is a controlled architecture/provenance refinement only.