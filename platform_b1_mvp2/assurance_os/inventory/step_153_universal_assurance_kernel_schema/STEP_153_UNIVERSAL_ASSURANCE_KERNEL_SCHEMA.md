# Step 153 - Universal Assurance Kernel Schema

**Step 153 defines a universal assurance schema baseline. It does not implement runtime services, modify architecture, validate production systems, certify controls, or authorize regulated execution.**

The Universal Assurance Kernel extracts reusable identity, evidence, integrity, provenance, authority, dependency, accountability, admissibility, reconstruction, and display primitives from the life-sciences and cross-industry assurance registers.

## Locked architecture doctrine

- Platform B v1 remains ARCHITECTURE LOCKED.
- Thread D v1 remains ARCHITECTURE LOCKED.
- Platform B1 may evaluate advanced assurance state without reopening Platform B v1.
- Thread D and Thread D2 remain DISPLAY / WITNESS ONLY.
- RAMAT Vision does not approve, release, override, resolve, execute, or become evidence authority.
- Qualified humans and authorized organizational roles remain accountable.
- Official records remain in governed source systems.
- Admissibility evaluation is not execution.
- Unknown, missing, delayed, conflicting, and unresolved states remain explicit.

## Kernel invariants

| ID | Invariant | Rule |
|---|---|---|
| KINV-001 | Official Source-System Authority | Official records remain in governed source systems. The kernel does not replace the official record. |
| KINV-002 | Human Binding Authority | Qualified humans and authorized organizational roles remain accountable for binding decisions. |
| KINV-003 | No Evidence Without Provenance | Evidence cannot support an assurance decision unless origin, object linkage, time, and source are known. |
| KINV-004 | Hash and Rehash Verifiability | Integrity seals must identify the algorithm and evidence scope and must support later rehash verification. |
| KINV-005 | Silence Is Not Consent | Missed alerts, absent objection, unavailable approvers, and silent dashboards must not create authority. |
| KINV-006 | Dependency Agreement Before Trust | A workflow is not trustworthy when required dependencies, evidence, identity, controls, reviews, and source states disagree. |
| KINV-007 | Display Is Not Decision | Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display state but may not decide or execute. |
| KINV-008 | Explicit Unknown State | Missing, unresolved, delayed, conflicting, and unknown states must be explicit and must not be treated as satisfied. |
| KINV-009 | Admissibility Is Not Execution | An admissibility record evaluates whether an action may proceed; it does not itself execute the action. |
| KINV-010 | Architecture Lock Preservation | Platform B v1 and Thread D v1 remain architecture locked. The kernel does not reopen either architecture. |

## Kernel state enumerations

### AssuranceState

- `UNKNOWN`
- `UNVERIFIED`
- `VERIFIED`
- `WARNING`
- `HOLD`
- `NO-BIND`
- `BLOCKED`
- `INADMISSIBLE`
- `ADMISSIBLE`

### EvidenceState

- `MISSING`
- `PRESENT`
- `HASHED`
- `REHASH_VERIFIED`
- `MISMATCHED`
- `SUPERSEDED`
- `UNAVAILABLE`

### DependencyState

- `UNKNOWN`
- `SATISFIED`
- `UNSATISFIED`
- `MISMATCHED`
- `DELAYED`
- `HELD`
- `NOT_APPLICABLE`

### AuthorityState

- `UNKNOWN`
- `PRESENT`
- `ABSENT`
- `INVALID`
- `EXPIRED`
- `DELEGATED`
- `APPROVER_UNAVAILABLE`
- `ESCALATION_REQUIRED`

### ActionState

- `PROPOSED`
- `EVALUATED`
- `HELD`
- `ESCALATED`
- `REJECTED`
- `ADMISSIBLE`
- `EXECUTED_IN_SOURCE_SYSTEM`
- `CANCELLED`

### IdentityState

- `UNKNOWN`
- `UNVERIFIED`
- `VERIFIED`
- `DUPLICATE`
- `MISMATCHED`
- `SUPERSEDED`
- `RETIRED`

### IntegrityState

- `UNSEALED`
- `SEALED`
- `REHASH_VERIFIED`
- `HASH_MISMATCH`
- `ALGORITHM_UNSUPPORTED`
- `SOURCE_UNAVAILABLE`

## Primitive-category summary

| Primitive category | Primitive count |
|---|---:|
| ACCOUNTABILITY | 1 |
| AUTHORITY | 1 |
| CONTROL | 1 |
| CUSTODY | 1 |
| DECISION SUPPORT | 1 |
| DEPENDENCY | 1 |
| DISPLAY | 1 |
| EVALUATION | 1 |
| EVIDENCE | 1 |
| GOVERNANCE | 1 |
| IDENTITY | 1 |
| INTEGRITY | 2 |
| OBJECT | 1 |
| PROVENANCE | 1 |
| RECONSTRUCTION | 1 |
| SOURCE OF TRUTH | 1 |
| STATE | 1 |

## Universal Assurance Kernel primitive register

| ID | Primitive | Category | Owner layer | Failure state |
|---|---|---|---|---|
| UK-001 | Assurance Object | OBJECT | CROSS-CUTTING ASSURANCE OS | OBJECT_IDENTITY_UNRESOLVED |
| UK-002 | Regulated Object Identity Reference | IDENTITY | CROSS-CUTTING ASSURANCE OS | IDENTITY_MISMATCH_OR_DUPLICATE |
| UK-003 | Evidence Item | EVIDENCE | CROSS-CUTTING ASSURANCE OS | EVIDENCE_MISSING_OR_UNATTRIBUTED |
| UK-004 | Evidence Integrity Seal | INTEGRITY | CROSS-CUTTING ASSURANCE OS | EVIDENCE_SEAL_INVALID |
| UK-005 | Rehash Verification | INTEGRITY | CROSS-CUTTING ASSURANCE OS | REHASH_MISMATCH |
| UK-006 | Provenance Link | PROVENANCE | CROSS-CUTTING ASSURANCE OS | PROVENANCE_CHAIN_INCOMPLETE |
| UK-007 | Source-System Reference | SOURCE OF TRUTH | CROSS-CUTTING ASSURANCE OS | SOURCE_OF_TRUTH_UNRESOLVED |
| UK-008 | Chain-of-Custody Event | CUSTODY | CROSS-CUTTING ASSURANCE OS | CUSTODY_CHAIN_BROKEN |
| UK-009 | Workflow Dependency | DEPENDENCY | PLATFORM B1 / MVP2 | DEPENDENCY_UNSATISFIED_OR_MISMATCHED |
| UK-010 | Control Requirement | CONTROL | PLATFORM A / CROSS-CUTTING ASSURANCE OS | CONTROL_UNMAPPED_OR_UNTESTED |
| UK-011 | Authority Record | AUTHORITY | PLATFORM B1 / MVP2 | AUTHORITY_ABSENT_OR_INVALID |
| UK-012 | No-Bind Governance State | GOVERNANCE | PLATFORM B1 / MVP2 | NO_BIND_STATE_ACTIVE |
| UK-013 | Human Accountability Record | ACCOUNTABILITY | PLATFORM B1 / MVP2 | HUMAN_ACCOUNTABILITY_NOT_IDENTIFIED |
| UK-014 | Assurance Evaluation | EVALUATION | PLATFORM B v1 / PLATFORM B1 | ASSURANCE_EVALUATION_INCOMPLETE |
| UK-015 | Action Admissibility Record | DECISION SUPPORT | PLATFORM B v1 / PLATFORM B1 | ACTION_INADMISSIBLE_OR_HELD |
| UK-016 | Assurance State Snapshot | STATE | PLATFORM B1 / MVP2 | STATE_UNKNOWN_OR_CONFLICTED |
| UK-017 | Evidence Reconstruction Package | RECONSTRUCTION | PLATFORM B1 / MVP2 | RECONSTRUCTION_INCOMPLETE_OR_NONDEFENSIBLE |
| UK-018 | Display and Witness Contract | DISPLAY | THREAD D / THREAD D2 | DISPLAY_CONTRACT_INVALID_OR_OVERPERMISSIVE |

## Kernel primitive details

### UK-001 - Assurance Object

- Category: OBJECT
- Purpose: Defines the universal object being governed, evaluated, referenced, witnessed, reconstructed, or linked to evidence.
- Required fields: `object_id; object_type; object_name; lifecycle_state; owner_role; source_system_id; created_at_utc; updated_at_utc`
- Validation rule: Every assurance evaluation must reference one uniquely identified assurance object.
- Failure state: **OBJECT_IDENTITY_UNRESOLVED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Clinical subjects, samples, batches, equipment, CIs, devices, shipments, transactions, AI agents, documents, cases, and assets.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Step 154 must define the full Regulated Object Identity schema.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-002 - Regulated Object Identity Reference

- Category: IDENTITY
- Purpose: Provides a stable identity reference connecting an assurance object to its official source-system identity.
- Required fields: `object_id; source_system_id; source_record_id; identity_type; identity_status; identity_verified_at_utc`
- Validation rule: An object identity must be unique within its declared source system and must not be inferred only from display text.
- Failure state: **IDENTITY_MISMATCH_OR_DUPLICATE**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: All regulated, critical, operational, digital, physical, human, AI, document, and evidence objects.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Step 154 will expand aliases, identity bindings, canonical IDs, source-system keys, lifecycle states, and duplicate resolution.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-003 - Evidence Item

- Category: EVIDENCE
- Purpose: Represents one governed item of evidence supporting or contradicting an assurance claim.
- Required fields: `evidence_id; object_id; evidence_type; source_system_id; source_record_id; captured_at_utc; captured_by; evidence_status`
- Validation rule: Evidence must have identifiable origin, time, object linkage, and status before it can support an assurance decision.
- Failure state: **EVIDENCE_MISSING_OR_UNATTRIBUTED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Files, records, events, logs, approvals, sensor readings, audit trails, images, reports, signatures, and attestations.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Evidence must reference a valid regulated object identity.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-004 - Evidence Integrity Seal

- Category: INTEGRITY
- Purpose: Stores the cryptographic integrity value calculated for a governed evidence item.
- Required fields: `seal_id; evidence_id; hash_algorithm; hash_value; hashed_at_utc; hashed_by; content_length; seal_status`
- Validation rule: A seal is valid only when the declared algorithm, hash value, evidence reference, and calculation context are complete.
- Failure state: **EVIDENCE_SEAL_INVALID**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Documents, structured records, event payloads, files, exports, images, logs, and evidence packages.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The sealed evidence item must resolve to a governed object identity.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-005 - Rehash Verification

- Category: INTEGRITY
- Purpose: Verifies whether current evidence content still matches its previously recorded integrity seal.
- Required fields: `verification_id; seal_id; recalculated_hash; verified_at_utc; verified_by; comparison_result; verification_status`
- Validation rule: The recalculated hash must be compared against the stored seal using the same algorithm and declared evidence scope.
- Failure state: **REHASH_MISMATCH**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Evidence reconstruction, audit preparation, inspection readiness, transfer verification, archive checks, and chain-of-custody review.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The related evidence and assurance object identities must remain resolvable.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-006 - Provenance Link

- Category: PROVENANCE
- Purpose: Connects evidence, decisions, transformations, actors, and source records into a traceable provenance path.
- Required fields: `provenance_id; parent_object_id; child_object_id; relation_type; source_system_id; recorded_at_utc; recorded_by`
- Validation rule: Every derived or transformed item must identify its parent, relationship, actor, source, and time.
- Failure state: **PROVENANCE_CHAIN_INCOMPLETE**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Derived data, AI outputs, transformed records, reports, submissions, investigations, reconstructions, and decisions.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Parent and child objects must use canonical regulated object identities.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-007 - Source-System Reference

- Category: SOURCE OF TRUTH
- Purpose: Identifies the governed system and official record location from which evidence or state originated.
- Required fields: `source_system_id; system_name; system_type; environment; record_id; record_version; record_status; reference_uri_or_key`
- Validation rule: An assurance record must not claim official-record authority without a governed source-system reference.
- Failure state: **SOURCE_OF_TRUTH_UNRESOLVED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: LIMS, MES, ERP, eQMS, EHR, CMDB, historians, identity systems, document repositories, and other official systems.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Step 154 must define how source-system identities bind to objects.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-008 - Chain-of-Custody Event

- Category: CUSTODY
- Purpose: Records custody, control, possession, transfer, or responsibility changes for a governed object.
- Required fields: `custody_event_id; object_id; from_custodian; to_custodian; event_type; event_at_utc; location; condition_status; evidence_id`
- Validation rule: Every custody transfer must identify the object, parties, time, location, condition, and supporting evidence.
- Failure state: **CUSTODY_CHAIN_BROKEN**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Applies to: Samples, materials, doses, products, shipments, devices, documents, digital evidence, serialized goods, and assets.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The transferred item must have one canonical object identity.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-009 - Workflow Dependency

- Category: DEPENDENCY
- Purpose: Defines a condition that must agree or be satisfied before execution, release, reporting, transfer, or audit exposure.
- Required fields: `dependency_id; object_id; dependency_type; required_state; observed_state; source_system_id; evaluated_at_utc; dependency_status`
- Validation rule: A workflow cannot be considered trustworthy when required and observed dependency states disagree or remain unknown.
- Failure state: **DEPENDENCY_UNSATISFIED_OR_MISMATCHED**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: Clinical, laboratory, manufacturing, quality, supply-chain, IT, equipment, AI-agent, financial, and infrastructure workflows.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Every dependency must identify the regulated objects it constrains.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-010 - Control Requirement

- Category: CONTROL
- Purpose: Defines the governed requirement, policy, obligation, or control that an assurance evaluation tests.
- Required fields: `control_id; control_name; control_source; obligation_reference; applicable_object_type; evaluation_method; control_owner; control_status`
- Validation rule: A control result must identify the requirement tested, evaluation method, owner, applicable object, and result.
- Failure state: **CONTROL_UNMAPPED_OR_UNTESTED**
- Primary owner layer: PLATFORM A / CROSS-CUTTING ASSURANCE OS
- Applies to: Policies, regulations, standards, SOPs, technical controls, quality controls, AI controls, and operational requirements.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Control applicability must resolve to governed object types and identities.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-011 - Authority Record

- Category: AUTHORITY
- Purpose: Represents the authority required for a person, role, rule, or delegated actor to bind an action.
- Required fields: `authority_id; actor_id; role_id; authority_type; scope; valid_from_utc; valid_to_utc; delegated_by; authority_status`
- Validation rule: Authority must be present, valid, current, in scope, and linked to an accountable actor before an action may be admissible.
- Failure state: **AUTHORITY_ABSENT_OR_INVALID**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: Approvals, releases, overrides, delegated decisions, AI actions, clinical decisions, quality decisions, and operational authorizations.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The actor and governed action object must have canonical identities.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-012 - No-Bind Governance State

- Category: GOVERNANCE
- Purpose: Creates an explicit governed hold when binding authority, evidence, review, timing, or escalation is insufficient.
- Required fields: `no_bind_id; object_id; action_id; reason_code; authority_state; evidence_state; approver_state; escalation_state; activated_at_utc; status`
- Validation rule: Silence, missed alerts, unavailable approvers, or absent objection must never be interpreted as authorization.
- Failure state: **NO_BIND_STATE_ACTIVE**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: AI actions, quality approvals, clinical decisions, release decisions, financial actions, public-sector decisions, and critical operations.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The held object, proposed action, actor, and authority record must be identifiable.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-013 - Human Accountability Record

- Category: ACCOUNTABILITY
- Purpose: Identifies the qualified human or authorized organizational role responsible for review, approval, escalation, or binding action.
- Required fields: `accountability_id; actor_id; role_id; responsibility_type; object_id; action_id; assigned_at_utc; accepted_at_utc; status`
- Validation rule: A high-consequence action must not become admissible without an identifiable accountable human or authorized role.
- Failure state: **HUMAN_ACCOUNTABILITY_NOT_IDENTIFIED**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: Regulated decisions, critical actions, approvals, releases, escalations, investigations, and AI-mediated workflows.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The accountable actor, governed object, and action must use stable identities.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-014 - Assurance Evaluation

- Category: EVALUATION
- Purpose: Records the result of evaluating evidence, controls, dependencies, identity, authority, timing, and source agreement.
- Required fields: `evaluation_id; object_id; evaluation_type; evaluated_at_utc; evaluated_by; evidence_ids; control_ids; result; rationale`
- Validation rule: An evaluation result must be reproducible from declared evidence, controls, states, and evaluation logic.
- Failure state: **ASSURANCE_EVALUATION_INCOMPLETE**
- Primary owner layer: PLATFORM B v1 / PLATFORM B1
- Applies to: Assurance checks, integrity reviews, dependency reviews, authority checks, release readiness, audit readiness, and risk reviews.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Every evaluation must resolve to the governed object being evaluated.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-015 - Action Admissibility Record

- Category: DECISION SUPPORT
- Purpose: Records whether a proposed action is admissible based on evaluated evidence, controls, dependencies, authority, timing, and accountability.
- Required fields: `admissibility_id; action_id; object_id; evaluation_id; authority_id; accountability_id; decision_state; rationale; decided_at_utc`
- Validation rule: Admissibility must not equal execution. The record evaluates whether an action may proceed subject to valid human and source-system authority.
- Failure state: **ACTION_INADMISSIBLE_OR_HELD**
- Primary owner layer: PLATFORM B v1 / PLATFORM B1
- Applies to: Release, approval, transfer, submission, execution, override, access, payment, treatment, and autonomous-agent actions.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The action target, actor, authority, and governed object identities must resolve.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-016 - Assurance State Snapshot

- Category: STATE
- Purpose: Captures the evaluated assurance state of an object at a specific time without replacing the object's official source-system state.
- Required fields: `snapshot_id; object_id; snapshot_at_utc; assurance_state; evidence_state; dependency_state; authority_state; source_state`
- Validation rule: A snapshot must identify its time, source references, evaluation basis, and whether any state remains unknown.
- Failure state: **STATE_UNKNOWN_OR_CONFLICTED**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: Dashboards, inspections, release readiness, audit reconstruction, wearable displays, and operational assurance views.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: The snapshot must reference one canonical assurance object identity.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-017 - Evidence Reconstruction Package

- Category: RECONSTRUCTION
- Purpose: Assembles the governed sequence of objects, evidence, integrity checks, states, actors, controls, and decisions for audit or inspection.
- Required fields: `reconstruction_id; object_id; scope; start_at_utc; end_at_utc; evidence_ids; event_ids; evaluation_ids; generated_at_utc; generated_by`
- Validation rule: A reconstruction package must preserve chronology, provenance, integrity status, source references, gaps, and unresolved conflicts.
- Failure state: **RECONSTRUCTION_INCOMPLETE_OR_NONDEFENSIBLE**
- Primary owner layer: PLATFORM B1 / MVP2
- Applies to: Inspections, audits, deviations, CAPA, clinical investigations, batch review, recalls, incidents, complaints, and submissions.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: All reconstructed objects and events must use stable governed identities.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### UK-018 - Display and Witness Contract

- Category: DISPLAY
- Purpose: Defines the limited assurance-state payload that a display, wearable, dashboard, or device witness may present.
- Required fields: `display_contract_id; object_id; snapshot_id; allowed_fields; redaction_rule; display_mode; generated_at_utc; expires_at_utc`
- Validation rule: A display contract may communicate evaluated state only and must not create approval, release, override, or execution authority.
- Failure state: **DISPLAY_CONTRACT_INVALID_OR_OVERPERMISSIVE**
- Primary owner layer: THREAD D / THREAD D2
- Applies to: RAMAT Vision, glasses, wearables, dashboards, mobile displays, device witnesses, regulator views, and audit views.
- Runtime authority: SCHEMA AND ASSURANCE-EVALUATION SUPPORT ONLY. NO INDEPENDENT APPROVAL, RELEASE, OVERRIDE, OR EXECUTION AUTHORITY.
- Source-of-truth rule: Official records remain in governed source systems. The kernel stores governed references, integrity values, evaluations, and reconstruction links without replacing the official record.
- Human-accountability rule: Qualified humans and authorized organizational roles remain accountable for binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display or witness evaluated state but may not approve, release, override, resolve, or execute actions.
- Step 154 dependency: Displayed state must reference the correct governed object identity.
- Maturity statement: Kernel primitive registration is a schema baseline, not runtime implementation, production readiness, regulatory validation, certification, or operational release.

## Step 154 review gate

Before Step 154 begins, review all 18 kernel primitives, confirm the required fields, validation rules, failure states, owner layers, enumerations, and invariants, and verify that the kernel does not create approval, release, override, execution, or official-record authority.

Step 154 will define the Regulated Object Identity schema, including canonical identity, aliases, source-system bindings, lifecycle state, identity verification, duplicate resolution, and object relationships.

**STEP 153 UNIVERSAL ASSURANCE KERNEL SCHEMA COMPLETE**

**STEP 154: READY AFTER REVIEW**

