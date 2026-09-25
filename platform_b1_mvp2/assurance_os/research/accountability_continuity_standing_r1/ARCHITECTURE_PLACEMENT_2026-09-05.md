# Accountability Continuity Standing R1 — Architecture Placement

**Date:** 2026-09-05  
**Decision:** `FORMAL_CANDIDATE_JUSTIFIED`  
**Research status:** `MATERIAL_DISTINCTNESS_ESTABLISHED_AT_RESEARCH_LEVEL`  
**Canonical status:** `NOT_CANONICAL / NOT_FROZEN / NOT_MERGED`

## Question

Where should Accountability Continuity Standing sit relative to existing COBIT-Chain responsibility/RACI, ownership, handoff, Authority Standing, Action Admissibility, boundary enforcement, and execution-time revalidation controls?

## Comparison

| Existing capability | Existing purpose | Why Accountability Continuity Standing is not a duplicate |
|---|---|---|
| AI Accountability RACI Matrix Engine | Assign Responsible, Accountable, Consulted, and Informed roles and decision rights across lifecycle phases. | Role assignment does not prove that accountable ownership is still current, accepted, unambiguous, and continuous through later organizational/system/vendor/agent handoffs. |
| Production Ownership Continuity Assurance | Deepens Platform B governance from pilot through production across business, support, adoption, platform, data, security, lifecycle, incident, KPI, and retirement ownership. | This is a Platform B operational/application capability. Accountability Continuity Standing is a reusable fail-closed shared Assurance OS standing proposition for a declared consequence scope. |
| ShiftTrust Escalation Lineage | Preserves escalation ownership and acknowledgement across shift handoffs. | This is a shift/escalation-specific continuity mechanism. Accountability Continuity Standing generalizes the same class of seam risk across teams, systems, vendors, agents, institutions, and shifts. |
| Step 170 Authority / No-Bind | Verifies current authority conditions and requires `human_accountability_identified`. | `human_accountability_identified` is currently a boolean prerequisite; Step 170 does not establish continuity, successor acceptance, obligation preservation, scope continuity, or current accountability evidence. |
| Step 178 Disposition Standing | Requires a governed owner, deadline, interim posture, escalation rule, and closure evidence for a detected condition. | Disposition ownership governs the path for a detected condition; it does not establish continuity of the accountable outcome owner for the declared consequence scope. |
| Step 179 Boundary Enforcement | Prevents failed upstream authority/boundary assurances from being bypassed by a downstream caller. | Step 179 enforces upstream standing but does not create Accountability Continuity Standing. A future integration can consume Accountability Continuity as another non-bypass prerequisite without rewriting Step 179. |
| Step 180 Execution-Time Revalidation | Rechecks current authority, object identity, evidence, criteria, configuration, context, and decision freshness before commit. | It checks `authority_current` but not continuity/currentness of the accountability basis. Accountability Continuity already has a material-change/revalidation proposition that can be composed without duplicating Step 180. |

## Placement decision

Accountability Continuity Standing is a **shared-core standing primitive**.

Its semantic position is:

`Responsibility / RACI evidence`

→ `Accountability Continuity Standing`

→ `Authority Standing`

→ `Action Admissibility / No-Bind`

→ `Execution-Time Revalidation`

→ `Commit / Execution`

This ordering is semantic, not a statement about repository Step numbering.

## Step-number decision

A formal candidate may use **Step 185** because Step 184 R1/R2 already establish the prior implementation chronology in their isolated frozen lanes.

`STEP_NUMBER = IMPLEMENTATION_CHRONOLOGY`

`STEP_NUMBER != SEMANTIC_LIFECYCLE_ORDER`

Therefore Step 185 may be implemented later in repository chronology while remaining semantically upstream of Authority Standing and Action Admissibility whenever composed into a governed decision path.

## Candidate integration invariants

A formal candidate should preserve:

`RESPONSIBILITY != ACCOUNTABILITY != AUTHORITY != CAPABILITY`

`ACCOUNTABILITY_CONTINUITY_SUPPORTABLE != AUTHORITY_GRANTED`

`VALID_AUTHORITY != ACCOUNTABILITY_CONTINUITY`

`ACCOUNTABILITY_CONTINUITY_NOT_SUPPORTABLE -> ACTION_ADMISSIBILITY_NOT_SUPPORTABLE_ON_ACCOUNTABILITY_BASIS`

`ACCOUNTABILITY_HANDOFF -> IDENTIFIED_SUCCESSOR + ACCEPTED_SCOPE + CURRENT_MANDATE + PRESERVED_OBLIGATIONS + TRACEABLE_TRANSFER`

`MATERIAL_CHANGE_AFTER_ACCOUNTABILITY_ASSIGNMENT -> ACCOUNTABILITY_REVALIDATION_REQUIRED`

A failed Accountability Continuity result must not claim that legal/institutional authority ceases to exist. It establishes only that the declared accountability basis is not supportable for reliance/admissibility in the evaluated scope.

## Non-duplication rule

The formal candidate must not:

- create another RACI engine;
- replace Production Ownership Continuity Assurance;
- replace ShiftTrust escalation lineage;
- replace Step 170 Authority Standing/No-Bind;
- replace Step 178 Disposition Standing;
- replace Step 179 enforcement;
- duplicate Step 180 execution-time currentness logic;
- manufacture accountable ownership from incomplete evidence.

The candidate should expose a bounded Accountability Continuity result that downstream authority/admissibility/enforcement compositions can consume.

## Promotion decision

Architecture placement, 32-test adversarial evidence, and research static review justify a **formal bounded candidate**.

Current decision:

`FORMAL_CANDIDATE_JUSTIFIED`

Proposed implementation path:

`platform_b1_mvp2/assurance_os/implementation/step_185_accountability_continuity_standing_r1/`

Promotion to a frozen/canonical configuration requires a separate candidate implementation, integration regression suite, CI result, and candidate static review.

## Protected boundaries

This placement decision does not modify or unfreeze:

- Step 184 R1;
- Step 184 R2;
- PR #95;
- PR #96;
- PR #97;
- PR #98;
- IRLT-MAG.

`AUTHORITY = NONE` for the research/candidate evaluator itself. RAMAT remains witness/context only.

## Provenance boundary

External public discussion remains a challenge/validation signal only:

- `EXTERNAL_CHALLENGE_SIGNAL != COBIT_CHAIN_IMPLEMENTATION_EVIDENCE`
- `CONCEPTUAL_SIMILARITY != DERIVATION`
- `CHRONOLOGY != DERIVATION != AUTHORSHIP != OWNERSHIP`
