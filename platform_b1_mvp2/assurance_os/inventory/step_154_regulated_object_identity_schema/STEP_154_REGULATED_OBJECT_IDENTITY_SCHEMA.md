# Step 154 - Regulated Object Identity Schema

**Step 154 defines a Regulated Object Identity schema baseline. It does not implement runtime identity services, modify existing architecture, validate production systems, merge real records, or authorize regulated execution.**

The schema provides a universal identity foundation for regulated, critical, physical, digital, human, AI, document, transaction, device, evidence, and operational objects.

## Locked architecture doctrine

- Platform B v1 remains ARCHITECTURE LOCKED.
- Thread D v1 remains ARCHITECTURE LOCKED.
- Platform B1 may evaluate identity assurance without reopening Platform B v1.
- Thread D and Thread D2 remain DISPLAY / WITNESS ONLY.
- RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display identity state but may not create, merge, retire, approve, or override identity.
- Qualified humans and authorized organizational roles remain accountable.
- Official object records remain in governed source systems.
- Identity conflicts remain explicit and may activate a governance hold.
- Aliases, names, routes, filenames, and display text do not replace canonical identity.

## Identity invariants

| ID | Invariant | Rule |
|---|---|---|
| ROI-INV-001 | One Canonical Object Identity | Every governed object must resolve to one stable canonical object_id. |
| ROI-INV-002 | Canonical Identity Is Not Display Text | Names, labels, filenames, routes, and display values must not serve as the sole canonical identity. |
| ROI-INV-003 | Source Binding Required | Official-state claims must include a governed source-system identity binding. |
| ROI-INV-004 | Aliases Do Not Replace Canonical Identity | Aliases may resolve to a canonical object but must not silently create or replace canonical identity. |
| ROI-INV-005 | Duplicate State Remains Explicit | Suspected duplicates remain unresolved until a governed human or rule-based resolution is completed and recorded. |
| ROI-INV-006 | Lifecycle State Is Explicit | Active, held, suspended, superseded, retired, recalled, archived, and other lifecycle states must not be inferred from absence. |
| ROI-INV-007 | Identity Relationships Are Evidence-Backed | Object relationships must reference valid canonical identities and supporting evidence. |
| ROI-INV-008 | Physical-Digital Binding Requires Evidence | QR, NFC, RFID, barcode, BLE, certificate, sensor, and wearable bindings must be governed, attributable, current, and evidence-backed. |
| ROI-INV-009 | Identity Conflict Creates Hold | Material identity mismatch, duplication, ambiguity, or source conflict must create an explicit governance hold. |
| ROI-INV-010 | Human Identity Stewardship | Active regulated objects require an identifiable owner, steward, or authorized organizational role. |
| ROI-INV-011 | Official Records Remain Authoritative | The identity schema does not replace official records in governed source systems. |
| ROI-INV-012 | Display Does Not Create Identity Authority | Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and witnesses may display identity state but may not create, merge, retire, approve, or override canonical identity. |

## Identity state enumerations

### ObjectIdentityStatus

- `UNKNOWN`
- `UNVERIFIED`
- `VERIFIED`
- `CONFLICTED`
- `DUPLICATE_CANDIDATE`
- `HELD`
- `SUPERSEDED`
- `RETIRED`

### ObjectLifecycleState

- `DRAFT`
- `REGISTERED`
- `ACTIVE`
- `QUALIFIED`
- `RELEASED`
- `HELD`
- `SUSPENDED`
- `SUPERSEDED`
- `RETIRED`
- `RECALLED`
- `DESTROYED`
- `ARCHIVED`
- `CANCELLED`

### SourceBindingStatus

- `PENDING`
- `ACTIVE`
- `VERIFIED`
- `CONFLICTED`
- `STALE`
- `SUPERSEDED`
- `RETIRED`

### AliasStatus

- `ACTIVE`
- `HISTORICAL`
- `SUPERSEDED`
- `REJECTED`
- `AMBIGUOUS`
- `RETIRED`

### VerificationResult

- `PASS`
- `FAIL`
- `PARTIAL`
- `UNKNOWN`
- `MANUAL_REVIEW_REQUIRED`

### DuplicateResolutionType

- `MERGE_TO_CANONICAL`
- `RETAIN_SEPARATELY`
- `SUPERSEDE`
- `RETIRE_ALIAS`
- `REDIRECT`
- `REJECT_MATCH`

### RelationshipType

- `PARENT_OF`
- `CHILD_OF`
- `CONTAINS`
- `COMPONENT_OF`
- `PRODUCES`
- `DERIVED_FROM`
- `DEPENDS_ON`
- `ASSIGNED_TO`
- `OWNED_BY`
- `CUSTODIAN_OF`
- `SUPPORTS`
- `CONTRADICTS`
- `SUPERSEDES`
- `BOUND_TO`

### PhysicalBindingType

- `QR`
- `BARCODE`
- `NFC`
- `RFID`
- `BLE_BEACON`
- `DEVICE_CERTIFICATE`
- `SENSOR_IDENTITY`
- `SECURE_LABEL`
- `MANUAL_GOVERNED_BINDING`

### IdentityConflictType

- `MISSING_IDENTITY`
- `DUPLICATE_IDENTITY`
- `SOURCE_MISMATCH`
- `ALIAS_AMBIGUITY`
- `STALE_BINDING`
- `UNVERIFIED_BINDING`
- `CONFLICTING_SERIAL`
- `RELATIONSHIP_CONFLICT`
- `LIFECYCLE_CONFLICT`
- `INTEGRITY_MISMATCH`

## Identity-component summary

| Component category | Component count |
|---|---:|
| ALIAS | 1 |
| CANONICAL KEY | 1 |
| CANONICAL OBJECT | 1 |
| DUPLICATE DETECTION | 1 |
| DUPLICATE RESOLUTION | 1 |
| GOVERNANCE | 1 |
| IDENTITY HOLD | 1 |
| IDENTITY INTEGRITY | 1 |
| IDENTITY PASSPORT | 1 |
| LIFECYCLE | 1 |
| OBJECT TYPE | 1 |
| PHYSICAL-DIGITAL BINDING | 1 |
| RELATIONSHIP | 1 |
| SOURCE BINDING | 1 |
| VERIFICATION | 1 |
| VERSIONING | 1 |

## Regulated Object Identity component register

| ID | Component | Category | Owner layer | Failure state |
|---|---|---|---|---|
| ROI-001 | Canonical Regulated Object | CANONICAL OBJECT | CROSS-CUTTING ASSURANCE OS | CANONICAL_OBJECT_IDENTITY_UNRESOLVED |
| ROI-002 | Regulated Object Type Definition | OBJECT TYPE | CROSS-CUTTING ASSURANCE OS | OBJECT_TYPE_UNDEFINED_OR_INACTIVE |
| ROI-003 | Canonical Identity Key | CANONICAL KEY | CROSS-CUTTING ASSURANCE OS | CANONICAL_KEY_DUPLICATE_OR_REASSIGNED |
| ROI-004 | Source-System Identity Binding | SOURCE BINDING | CROSS-CUTTING ASSURANCE OS | SOURCE_BINDING_MISSING_OR_CONFLICTED |
| ROI-005 | Alias and Alternate Identifier | ALIAS | CROSS-CUTTING ASSURANCE OS | ALIAS_AMBIGUOUS_OR_MULTI_BOUND |
| ROI-006 | Identity Verification Event | VERIFICATION | PLATFORM B1 / CROSS-CUTTING ASSURANCE OS | IDENTITY_VERIFICATION_INCOMPLETE |
| ROI-007 | Duplicate Identity Candidate | DUPLICATE DETECTION | PLATFORM B1 / CROSS-CUTTING ASSURANCE OS | DUPLICATE_IDENTITY_REVIEW_REQUIRED |
| ROI-008 | Duplicate Resolution Record | DUPLICATE RESOLUTION | HUMAN GOVERNANCE / CROSS-CUTTING ASSURANCE OS | DUPLICATE_RESOLUTION_INVALID_OR_UNAPPROVED |
| ROI-009 | Regulated Object Relationship | RELATIONSHIP | CROSS-CUTTING ASSURANCE OS | OBJECT_RELATIONSHIP_INVALID_OR_UNRESOLVED |
| ROI-010 | Object Lifecycle State Record | LIFECYCLE | SOURCE SYSTEM / CROSS-CUTTING ASSURANCE OS | LIFECYCLE_STATE_CONFLICT_OR_INVALID_TRANSITION |
| ROI-011 | Object Version and Supersession Record | VERSIONING | CROSS-CUTTING ASSURANCE OS | OBJECT_VERSION_OR_SUPERSESSION_CONFLICT |
| ROI-012 | Identity Ownership and Stewardship Record | GOVERNANCE | HUMAN GOVERNANCE / PLATFORM A | OBJECT_OWNER_OR_STEWARD_NOT_IDENTIFIED |
| ROI-013 | Physical-Digital Identity Binding | PHYSICAL-DIGITAL BINDING | CROSS-CUTTING ASSURANCE OS / DEVICE WITNESS | PHYSICAL_DIGITAL_BINDING_INVALID |
| ROI-014 | Identity Integrity Seal | IDENTITY INTEGRITY | CROSS-CUTTING ASSURANCE OS | IDENTITY_INTEGRITY_SEAL_INVALID |
| ROI-015 | Identity Conflict and Governance Hold | IDENTITY HOLD | PLATFORM B1 / CROSS-CUTTING ASSURANCE OS | IDENTITY_GOVERNANCE_HOLD_ACTIVE |
| ROI-016 | Regulated Object Identity Passport | IDENTITY PASSPORT | PLATFORM B1 / CROSS-CUTTING ASSURANCE OS | IDENTITY_PASSPORT_INCOMPLETE_OR_STALE |

## Identity-component details

### ROI-001 - Canonical Regulated Object

- Category: CANONICAL OBJECT
- Purpose: Defines the single governed identity record representing a regulated, critical, operational, physical, digital, human, AI, document, transactional, or evidence-bearing object.
- Required fields: `object_id; object_type_id; canonical_name; lifecycle_state; identity_status; owner_role_id; steward_role_id; created_at_utc; updated_at_utc`
- Validation rule: Every governed object must have one stable canonical object_id that does not depend only on a mutable name, label, route, display value, filename, or local alias.
- Failure state: **CANONICAL_OBJECT_IDENTITY_UNRESOLVED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: Clinical subject, specimen, batch, equipment item, CI, AI agent, shipment, serialized product, document, transaction, dose, or case.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence, authority, No-Bind, accountability, and admissibility records must reference a valid canonical object_id.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-002 - Regulated Object Type Definition

- Category: OBJECT TYPE
- Purpose: Defines the governed taxonomy and required identity attributes for each class of regulated or critical object.
- Required fields: `object_type_id; object_type_name; domain; parent_object_type_id; required_identity_fields; allowed_relationship_types; owner_role; status`
- Validation rule: Every canonical object must resolve to one active object type whose required identity attributes and allowed relationships are defined.
- Failure state: **OBJECT_TYPE_UNDEFINED_OR_INACTIVE**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: SUBJECT, SAMPLE, BATCH, MATERIAL, EQUIPMENT, APPLICATION_CI, AI_AGENT, DOCUMENT, SHIPMENT, PRODUCT_SERIAL, TRANSACTION, DEVICE, or CASE.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence and authority rules may use object_type_id to determine applicability, consequence level, and required controls.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-003 - Canonical Identity Key

- Category: CANONICAL KEY
- Purpose: Defines the stable technical key used to distinguish one governed object from every other object.
- Required fields: `identity_key_id; object_id; key_namespace; key_value; key_version; issued_at_utc; issued_by; key_status`
- Validation rule: A canonical key must be unique within its declared namespace and must not be reassigned to a different object after issuance.
- Failure state: **CANONICAL_KEY_DUPLICATE_OR_REASSIGNED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: UUID, governed enterprise object key, canonical batch key, canonical sample key, device identity key, or agent identity key.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 must use canonical keys when linking evidence, actors, actions, authority, holds, and accountability.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-004 - Source-System Identity Binding

- Category: SOURCE BINDING
- Purpose: Binds a canonical regulated object to its corresponding official record identity in a governed source system.
- Required fields: `binding_id; object_id; source_system_id; source_record_id; source_record_type; source_record_version; binding_status; verified_at_utc`
- Validation rule: A source binding must identify the canonical object, governed source system, official record key, record type, record version, and status.
- Failure state: **SOURCE_BINDING_MISSING_OR_CONFLICTED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: LIMS sample ID, MES batch ID, ServiceNow sys_id, EHR encounter ID, ERP material ID, EPCIS serial ID, or eQMS deviation ID.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence and authority records must preserve the source-system record reference supporting the evaluated state.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-005 - Alias and Alternate Identifier

- Category: ALIAS
- Purpose: Records legacy, local, external, human-readable, renamed, supplier, partner, or historical identifiers associated with one canonical object.
- Required fields: `alias_id; object_id; alias_type; alias_value; namespace; valid_from_utc; valid_to_utc; alias_status; source_system_id`
- Validation rule: An alias may resolve to one canonical object but must never silently replace or create a second canonical identity.
- Failure state: **ALIAS_AMBIGUOUS_OR_MULTI_BOUND**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: Previous CI name, local equipment number, supplier lot number, external accession number, legacy document ID, or renamed application.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence submitted under an alias must resolve to the correct canonical object before it can support an assurance evaluation.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-006 - Identity Verification Event

- Category: VERIFICATION
- Purpose: Records how, when, by whom, and against which evidence an object identity or source binding was verified.
- Required fields: `verification_id; object_id; verification_type; evidence_ids; verified_by_actor_id; verified_at_utc; verification_result; rationale`
- Validation rule: Identity cannot be marked VERIFIED without identifiable verification evidence, verification method, accountable verifier, time, result, and rationale.
- Failure state: **IDENTITY_VERIFICATION_INCOMPLETE**
- Primary owner layer: PLATFORM B1 / CROSS-CUTTING ASSURANCE OS
- Examples: Barcode verification, source-record comparison, human review, digital-certificate verification, device attestation, or partner confirmation.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Authority and admissibility evaluations may require current identity verification for the object and accountable actor.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-007 - Duplicate Identity Candidate

- Category: DUPLICATE DETECTION
- Purpose: Records a suspected duplicate, overlapping, renamed, cloned, or conflicting object identity requiring governed review.
- Required fields: `duplicate_candidate_id; primary_object_id; candidate_object_id; match_basis; confidence_level; detected_at_utc; detected_by; review_status`
- Validation rule: A duplicate candidate must remain explicit and unresolved until a qualified human or governed rule completes the review.
- Failure state: **DUPLICATE_IDENTITY_REVIEW_REQUIRED**
- Primary owner layer: PLATFORM B1 / CROSS-CUTTING ASSURANCE OS
- Examples: Duplicate CI, duplicate patient identity candidate, duplicate sample, renamed application, repeated batch record, or cloned device identity.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence and authority binding must be held when object identity is subject to unresolved duplicate review.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-008 - Duplicate Resolution Record

- Category: DUPLICATE RESOLUTION
- Purpose: Records the governed decision to merge, retain separately, supersede, retire, redirect, or reject a duplicate identity candidate.
- Required fields: `resolution_id; duplicate_candidate_id; resolution_type; canonical_object_id; affected_object_ids; decided_by_actor_id; decided_at_utc; rationale; status`
- Validation rule: Duplicate resolution must identify the accountable decision maker, canonical object, affected identities, resolution type, evidence, and rationale.
- Failure state: **DUPLICATE_RESOLUTION_INVALID_OR_UNAPPROVED**
- Primary owner layer: HUMAN GOVERNANCE / CROSS-CUTTING ASSURANCE OS
- Examples: Merge duplicate CIs, retain two legitimate devices, retire a historical alias, redirect a renamed application, or reject an incorrect match.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 must prevent evidence, authority, or action admissibility from binding to retired or non-canonical duplicate identities.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-009 - Regulated Object Relationship

- Category: RELATIONSHIP
- Purpose: Defines governed relationships between canonical objects, including parent, child, component, source, destination, ownership, custody, derivation, dependency, and evidence relationships.
- Required fields: `relationship_id; source_object_id; target_object_id; relationship_type; direction; valid_from_utc; valid_to_utc; relationship_status; evidence_id`
- Validation rule: Every relationship must reference two resolvable canonical objects, an allowed relationship type, validity period, status, and supporting evidence.
- Failure state: **OBJECT_RELATIONSHIP_INVALID_OR_UNRESOLVED**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: Batch CONTAINS material, device PRODUCES result, application DEPENDS_ON server, dose ASSIGNED_TO patient, shipment CONTAINS product, or evidence SUPPORTS claim.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence, authority, and No-Bind rules may use object relationships to determine affected scope and dependency consequences.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-010 - Object Lifecycle State Record

- Category: LIFECYCLE
- Purpose: Records the governed lifecycle state of an object and the evidence supporting each lifecycle transition.
- Required fields: `lifecycle_record_id; object_id; previous_state; new_state; transition_reason; effective_at_utc; changed_by_actor_id; evidence_id; status`
- Validation rule: Lifecycle transitions must be explicit, chronological, authorized, evidence-backed, and valid for the object type.
- Failure state: **LIFECYCLE_STATE_CONFLICT_OR_INVALID_TRANSITION**
- Primary owner layer: SOURCE SYSTEM / CROSS-CUTTING ASSURANCE OS
- Examples: Draft, active, qualified, released, suspended, held, superseded, retired, destroyed, recalled, archived, or cancelled.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 must consider object lifecycle state when determining evidence applicability, authority validity, and action admissibility.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-011 - Object Version and Supersession Record

- Category: VERSIONING
- Purpose: Distinguishes versions, revisions, replacements, and superseded forms of the same governed object without losing identity history.
- Required fields: `version_record_id; object_id; version_number; revision_number; effective_at_utc; supersedes_object_id; superseded_by_object_id; version_status`
- Validation rule: Current, superseded, and historical versions must remain distinguishable, chronological, and traceable to the canonical identity lineage.
- Failure state: **OBJECT_VERSION_OR_SUPERSESSION_CONFLICT**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: Protocol revision, SOP version, recipe version, software version, formulation version, model version, or equipment configuration revision.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence and controls must bind to the correct effective object version.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-012 - Identity Ownership and Stewardship Record

- Category: GOVERNANCE
- Purpose: Identifies the human and organizational roles responsible for object ownership, identity stewardship, verification, correction, and escalation.
- Required fields: `stewardship_id; object_id; owner_actor_or_role_id; steward_actor_or_role_id; responsibility_scope; valid_from_utc; valid_to_utc; assignment_status`
- Validation rule: Every active regulated object must have an identifiable owner or accountable role and a governed route for identity correction and escalation.
- Failure state: **OBJECT_OWNER_OR_STEWARD_NOT_IDENTIFIED**
- Primary owner layer: HUMAN GOVERNANCE / PLATFORM A
- Examples: Application owner, equipment owner, specimen custodian, batch owner, clinical investigator, AI-agent owner, document owner, or data steward.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Authority and accountability records must resolve to current owners, stewards, and authorized roles.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-013 - Physical-Digital Identity Binding

- Category: PHYSICAL-DIGITAL BINDING
- Purpose: Binds a physical object to its digital identity using controlled labels, tags, device credentials, sensors, or other governed identifiers.
- Required fields: `physical_binding_id; object_id; binding_type; tag_or_device_id; binding_evidence_id; bound_at_utc; bound_by_actor_id; binding_status`
- Validation rule: A physical-digital binding must identify the canonical object, binding method, tag or device, accountable binder, time, evidence, and current status.
- Failure state: **PHYSICAL_DIGITAL_BINDING_INVALID**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS / DEVICE WITNESS
- Examples: QR label, NFC tag, RFID tag, barcode, BLE beacon, secure device certificate, equipment label, shipment seal, or wearable-observed object marker.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Evidence captured by devices or wearables must resolve through a valid physical-digital binding before supporting assurance decisions.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-014 - Identity Integrity Seal

- Category: IDENTITY INTEGRITY
- Purpose: Creates a cryptographic seal over the selected identity attributes, source bindings, aliases, relationships, and lifecycle state.
- Required fields: `identity_seal_id; object_id; sealed_field_scope; hash_algorithm; hash_value; sealed_at_utc; sealed_by; content_length; seal_status`
- Validation rule: An identity seal is valid only when the field scope, algorithm, hash, object, calculation context, time, and responsible actor are complete.
- Failure state: **IDENTITY_INTEGRITY_SEAL_INVALID**
- Primary owner layer: CROSS-CUTTING ASSURANCE OS
- Examples: Seal over object type, canonical key, source-system bindings, active aliases, lifecycle state, and critical relationships.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 may require a valid identity seal or successful rehash verification before evidence or authority may bind to the object.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-015 - Identity Conflict and Governance Hold

- Category: IDENTITY HOLD
- Purpose: Creates an explicit governance hold when object identity is missing, duplicated, mismatched, stale, unverified, disputed, or bound to conflicting sources.
- Required fields: `identity_hold_id; object_id; conflict_type; affected_bindings; reason_code; activated_at_utc; escalation_route; resolution_status`
- Validation rule: Identity conflict must remain explicit and must prevent silent evidence, authority, release, or execution binding until governed resolution.
- Failure state: **IDENTITY_GOVERNANCE_HOLD_ACTIVE**
- Primary owner layer: PLATFORM B1 / CROSS-CUTTING ASSURANCE OS
- Examples: Patient mismatch, accession mismatch, duplicate CI, conflicting serial number, renamed application ambiguity, stale identity, or disputed custody object.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 must activate No-Bind or inadmissibility when a material identity conflict remains unresolved.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

### ROI-016 - Regulated Object Identity Passport

- Category: IDENTITY PASSPORT
- Purpose: Provides a governed, reviewable identity summary containing canonical identity, source bindings, aliases, lifecycle state, owner, verification, integrity, relationships, conflicts, and current assurance status.
- Required fields: `passport_id; object_id; canonical_key; object_type_id; current_bindings; active_aliases; lifecycle_state; owner_role_id; verification_state; integrity_state; conflict_state; generated_at_utc`
- Validation rule: An identity passport must be generated from current governed records, must expose unresolved conflicts, and must not become the official source record.
- Failure state: **IDENTITY_PASSPORT_INCOMPLETE_OR_STALE**
- Primary owner layer: PLATFORM B1 / CROSS-CUTTING ASSURANCE OS
- Examples: Batch identity passport, sample identity passport, equipment CI passport, AI-agent identity passport, shipment passport, dose passport, or document passport.
- Identity-authority boundary: The schema identifies, binds, verifies, relates, and governs regulated objects. It does not independently approve, release, override, execute, or authorize regulated actions.
- Source-of-truth rule: Official object records remain in governed source systems. The identity schema stores canonical references, bindings, aliases, verification results, integrity values, relationships, and governance states without replacing the official source record.
- Human-accountability rule: A designated object owner, data steward, system owner, process owner, Quality Unit, clinical authority, or other authorized human role remains accountable for identity verification and binding decisions.
- Display boundary: Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, and device witnesses may display object identity state but may not create, approve, merge, retire, release, or override canonical identity.
- Data boundary: Schema-only, simulator-first, mock-data-first, and local-validation-first. No PHI, company production data, classified data, or real regulated production integration is authorized by this step.
- Step 155 dependency: Step 155 may use the identity passport as a governed input to evidence, authority, No-Bind, and accountability evaluation.
- Maturity statement: Identity schema registration is not runtime implementation, production readiness, regulatory validation, certification, or operational release.

## Step 155 review gate

Before Step 155 begins, review all 16 identity components, confirm canonical-key rules, source-system bindings, aliases, verification, duplicate resolution, lifecycle states, object relationships, ownership, physical-digital bindings, integrity seals, identity holds, and identity passports.

Verify that no component grants approval, release, merge, override, execution, or official-record authority to Platform displays, Thread D, Thread D2, RAMAT Vision, glasses, wearables, dashboards, or device witnesses.

Step 155 will define the Evidence, Authority, Accountability, Action, and No-Bind Governance schema using canonical regulated-object identity.

**STEP 154 REGULATED OBJECT IDENTITY SCHEMA COMPLETE**

**STEP 155: READY AFTER REVIEW**

