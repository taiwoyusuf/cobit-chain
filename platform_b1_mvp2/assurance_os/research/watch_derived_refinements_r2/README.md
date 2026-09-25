# Watch-Derived Assurance Refinements R2

Status: **EXPERIMENTAL / BRANCH-ONLY**

Branch: `research/watch-derived-assurance-r2-sep4`

This package implements only the September 2026 watch-derived assurance gaps that remain materially absent after reconciliation with the existing shared core and the R1 watch-derived package. It deliberately avoids creating duplicate top-level modules.

## Implemented R2 refinements

1. **Applicability Exclusion Standing**
   - `NOT_APPLICABLE` is a consequential exclusion claim and must be supported by current evidence.
   - `NOT_OBSERVED`, `UNKNOWN`, `NOT_PRESENT`, and `NOT_APPLICABLE` remain distinct states.

2. **Condition Coverage Standing**
   - All declared conditions passing does not establish that all material conditions are known.
   - Coverage may be bounded, unknown, or show a discovered material-dependency gap; absolute completeness is never claimed.

3. **Observation Cadence Standing**
   - Two truthful/current endpoints do not establish continuity between them.
   - Observation interval plus decision-update latency must be adequate for the material change horizon.

4. **Authority Basis Standing**
   - A cryptographically intact grant/delegation chain does not by itself establish that the terminal issuer was entitled to grant the authority.
   - Terminal legal/institutional/procedural basis must be independently supportable within scope.

5. **Material Change Reachability**
   - Recording an invalidating change is not enough; the change must reach the governing gate and trigger reassessment before commitment.
   - `CHANGE_RECORDED != CHANGE_REACHED_EXECUTION`.

6. **Partial Evidence Bound Soundness**
   - A valid evidence fragment may support only the claims established within that fragment's boundary.
   - Later evidence may narrow uncertainty but must not retroactively upgrade what the earlier fragment established.

7. **Evidence Failure Independence**
   - Different witness channels do not establish independent assurance when they share failure-critical dependencies.
   - Declared dependencies include examples such as power, clock, calibration lineage, network path, upstream source, normalization logic, policy/specification, identity provider, or evaluator.

8. **Aggregate Consequence Assurance**
   - Every local action may be admissible while the aggregate pattern or cumulative consequence becomes unacceptable.
   - Historical local actions are not retroactively falsified merely because systemic reassessment is required.

## Why these eight were implemented first

They directly strengthen the most important current research lanes without duplicating existing R1 controls:

| Research lane | R2 additions that materially help |
| --- | --- |
| Runtime Residual-Consequence Assurance | Applicability Exclusion, Condition Coverage, Observation Cadence, Material Change Reachability, Evidence Failure Independence |
| Revocation / Effect Closure | Authority Basis, Material Change Reachability, Condition Coverage |
| Canonical Audit R3 | Applicability Exclusion, Partial Evidence Bound Soundness, Condition Coverage |
| RAMAT physical/context witnessing | Observation Cadence, Condition Coverage, Evidence Failure Independence, Material Change Reachability |
| Human/systemic governance | Aggregate Consequence Assurance |

## Existing work deliberately reused rather than duplicated

The current repository already contains or records experimental constructs for, among other things:

- Human Oversight Queue Standing
- Assessor Independence
- Revocation Propagation & Delegation Attenuation
- Independent Evidence Plane Standing
- Shared-Condition / Common-Cause Exposure
- Framework-Neutral Qualification Envelope
- Refusal Survivability Standing
- Repairability Routing Standing
- Intent Constitution Artifact
- Consequence Incapacity Challenge Pattern
- Digital Proxy Non-Authority
- Measurement Semantic Standing
- Measurement Context Representativeness
- Demonstration Participation Record
- Architecture Influence Provenance Ledger

This R2 package composes with those rather than creating competing engines.

## Important items reviewed but not promoted into this R2 runtime package

The uploaded watch material also contained valuable ideas that are deliberately held as experiments, methodology, or future roadmap rather than duplicated runtime controls:

- Examiner Qualification / Review Object Closure for Canonical Audit R3
- Examiner Freeze / Redesign Closure Criterion
- Consequence-Carrier Enforcement / enforcement-strata challenge
- Revocation effect-closure / unknown-route experiments
- Interrupt Common-Mode Isolation
- Control Relevance Standing
- Processing Rights Standing on normative-source metadata
- Determination Entitlement at governed interoperability seams
- Independent Reproduction Standing
- Assurance Test Harness Integrity
- Distributed Intervention Path Test
- Cross-organizational record-existence standing
- Mixed-version capability correspondence for Niagara/BMS
- observer-effect / intrusive-witness representativeness challenge
- acceptance-criterion fitness challenge
- machine-actionable SI / metrological semantic binding

These remain useful, but implementing all of them at once would create unnecessary duplication and blur experimental boundaries.

## Core R2 non-substitution rules

- `NOT_OBSERVED != NOT_APPLICABLE`
- `ALL_DECLARED_CONDITIONS_PASS != ALL_MATERIAL_CONDITIONS_KNOWN`
- `TWO_CURRENT_ENDPOINTS != CONTINUITY_ESTABLISHED`
- `AUTHENTIC_GRANT != LEGITIMATE_GRANT`
- `CHANGE_RECORDED != CHANGE_REACHED_EXECUTION`
- `VALID_FRAGMENT != COMPLETE_HISTORY`
- `DIFFERENT_WITNESS != INDEPENDENT_FAILURE_PATH`
- `EACH_ACTION_ADMISSIBLE != AGGREGATE_BEHAVIOR_ACCEPTABLE`

## Provenance / external-source boundary

The watch material is external research and comparative landscape input. External authors, architectures, products, standards, regulatory cases, and examinations are not implementation evidence for COBIT-Chain, Platform B1, VSA, or RAMAT Vision. This package independently implements neutral assurance problems after reconciliation against existing COBIT-Chain work.

## Authority / safety boundary

These evaluators produce bounded assurance states only. They do not create release authority, clinical authority, pharmacist authority, radiation-safety authority, legal authority, environmental regulatory authority, or autonomous physical execution permission.

RAMAT remains an observation/context witness. It does not acquire binding regulated authority through these controls.

## IRLT-MAG controlled STOP

This branch does **not** alter IRLT-MAG controlled-stop state. In particular, it does not authorize R1-03, Mission Covenant Evaluator, shared-engine implementation, live integration, or any competing authoritative current-estate baseline. The existing 176-row reconciliation record and stop conditions remain untouched.

## Test intent

`test_assurance_refinements_r2.py` contains deterministic bounded tests for all eight refinements, including both positive and adversarial cases. Passing tests demonstrate only the behavior of these experimental functions; they do not establish certification, production validation, regulatory acceptance, independent reproduction, or patentability.

## Merge status

Do not merge to `main` solely because bounded tests pass. Reconcile first with the numbered Step sequence, current Platform B1 shared-core contracts, Canonical Audit R3 status, domain-profile acceptance criteria, and publication/IP chronology.
