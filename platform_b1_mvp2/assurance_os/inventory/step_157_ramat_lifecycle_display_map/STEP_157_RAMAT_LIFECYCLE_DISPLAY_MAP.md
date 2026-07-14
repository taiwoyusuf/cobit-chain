# Step 157 - RAMAT Lifecycle Display Map

**Step 157 defines a design-only RAMAT lifecycle display map. It does not implement wearable software, expose production data, create runtime approvals, execute regulated actions, or modify existing platform architecture.**

The map converts the 17-stage fictional AURORA-17 molecule-to-market journey into limited RAMAT Vision display contracts for identity, evidence integrity, workflow dependency, authority, human accountability, timing, No-Bind Governance, admissibility, source-system execution, and reconstruction.

## Locked display doctrine

- Platform B v1 remains ARCHITECTURE LOCKED.
- Thread D v1 remains ARCHITECTURE LOCKED.
- Platform B1 remains the advanced assurance evaluation layer.
- Thread D, Thread D2, and RAMAT Vision remain DISPLAY / WITNESS ONLY.
- RAMAT Vision does not approve, release, override, resolve, execute, or become evidence authority.
- RAMAT Vision may display Platform B1 evaluated No-Bind states but may not resolve the governance hold.
- Qualified humans and authorized organizational roles remain accountable.
- Official records and executed actions remain in governed source systems.
- Admissibility is not execution.
- Silence is a governance state.
- Silence is not consent.
- Offline, stale, unknown, missing, delayed, and conflicted states remain explicit.

## Approved RAMAT display states

- `AUTHORITY ABSENT`
- `AUTHORITY INVALID`
- `AUTHORITY EXPIRED`
- `AUTHORITY OUT OF SCOPE`
- `NO-BIND STATE ACTIVE`
- `ACTION HELD`
- `ESCALATION REQUIRED`
- `ESCALATION AVAILABLE`
- `DOCUMENTED PAUSE CREATED`
- `APPROVER UNAVAILABLE`
- `EVIDENCE INSUFFICIENT`
- `TIMING INVALID`
- `HUMAN ACCOUNTABILITY MISSING`
- `HUMAN AUTHORITY REQUIRED`
- `ACTION INADMISSIBLE`
- `ACTION ADMISSIBLE`
- `SOURCE-SYSTEM EXECUTION REQUIRED`
- `DEPENDENCY UNSATISFIED`
- `IDENTITY CONFLICT`

## RAMAT assurance lenses

| Lens ID | Lens | Purpose |
|---|---|---|
| RAMAT-LENS-001 | Regulated Object Identity Lens | Displays canonical object identity, source-system bindings, aliases, verification state, lifecycle state, and active identity conflicts. |
| RAMAT-LENS-002 | Evidence Integrity Lens | Displays evidence presence, provenance, hash state, rehash result, currency, sufficiency, and integrity mismatch. |
| RAMAT-LENS-003 | Workflow Dependency Assurance Lens | Displays required dependency state, observed state, mismatch, delay, unknown state, hold, source, owner, and resolution route. |
| RAMAT-LENS-004 | Authority and Accountability Lens | Displays authority presence, validity, currency, delegation, scope, approver availability, accountable role, and escalation state. |
| RAMAT-LENS-005 | No-Bind Governance Lens | Displays No-Bind activation, reason, action hold, documented pause, required resolution, escalation, and human-authority prompt. |
| RAMAT-LENS-006 | Timing and Decay Window Lens | Displays evidence currency, authority validity, expiry, execution window, radiopharmaceutical decay timing, and time-critical risk. |
| RAMAT-LENS-007 | Source-of-Truth and Execution Lens | Displays official source-system references, observed state, last verification, admissibility state, and source-system execution requirement. |
| RAMAT-LENS-008 | Inspection and Reconstruction Lens | Displays lifecycle chronology, evidence gaps, integrity status, human decisions, No-Bind events, source execution references, and reconstruction readiness. |

## RAMAT display invariants

| ID | Invariant | Rule |
|---|---|---|
| RAMAT-INV-001 | Display Is Not Decision | RAMAT Vision displays evaluated assurance state and does not decide, approve, release, override, resolve, or execute. |
| RAMAT-INV-002 | Platform B1 Owns Advanced Evaluation | Advanced identity, evidence, dependency, authority, No-Bind, and admissibility states originate from Platform B1 evaluation. |
| RAMAT-INV-003 | Human Authority Remains Required | Qualified humans and authorized organizational roles remain responsible for binding decisions. |
| RAMAT-INV-004 | Official Records Remain Authoritative | RAMAT Vision does not become the official record or source of truth. |
| RAMAT-INV-005 | No-Bind Is Preview Only | RAMAT Vision may display an active No-Bind state but may not resolve, dismiss, bypass, or override the governance hold. |
| RAMAT-INV-006 | Silence Is Not Consent | A missed alert, absent objection, unavailable approver, delayed review, or silent display does not create authorization. |
| RAMAT-INV-007 | Unknown State Is Explicit | Unknown, stale, disconnected, missing, delayed, and conflicted states must remain explicit and must not appear verified. |
| RAMAT-INV-008 | Admissibility Is Not Execution | ACTION ADMISSIBLE indicates evaluated preconditions only. It does not execute the action. |
| RAMAT-INV-009 | Minimum Necessary Display | Only the minimum authorized information required for the assurance decision may be displayed. |
| RAMAT-INV-010 | Display Contracts Expire | Display state expires when its validity period ends, source state changes, authority changes, evaluation changes, or the session ends. |
| RAMAT-INV-011 | Offline State Is Stale | Offline or cached state must be marked stale or unknown and must not be presented as current approval or authority. |
| RAMAT-INV-012 | Prohibited Controls Are Absent | RAMAT lifecycle displays must not expose approval, release, override, No-Bind resolution, execution, identity merge, or source-record edit controls. |
| RAMAT-INV-013 | Architecture Locks Remain Preserved | Platform B v1 and Thread D v1 remain architecture locked. |
| RAMAT-INV-014 | Fictional Demonstration Boundary | AURORA-17 display contracts use synthetic records, mock identities, and no PHI or company production data. |

## Lifecycle display-contract map

| Contract | Stage | Display mode | Consequence | Allowed states |
|---|---|---|---|---|
| RAMAT-A17-01 | A17-01 - Target Discovery and Unmet-Need Definition | RESEARCH AND DISCOVERY ASSURANCE MODE | MODERATE | EVIDENCE INSUFFICIENT; HUMAN AUTHORITY REQUIRED; ACTION HELD; ACTION ADMISSIBLE |
| RAMAT-A17-02 | A17-02 - AI-Assisted Candidate and Ligand Design | RESEARCH AND DISCOVERY ASSURANCE MODE | HIGH | AUTHORITY ABSENT; EVIDENCE INSUFFICIENT; HUMAN ACCOUNTABILITY MISSING; NO-BIND STATE ACTIVE; ACTION ADMISSIBLE |
| RAMAT-A17-03 | A17-03 - Preclinical Characterization and Translational Evidence | RESEARCH AND DISCOVERY ASSURANCE MODE | HIGH | EVIDENCE INSUFFICIENT; TIMING INVALID; ACTION HELD; ESCALATION REQUIRED; ACTION ADMISSIBLE |
| RAMAT-A17-04 | A17-04 - Clinical-Supply and Investigational Manufacturing Readiness | CLINICAL-SUPPLY MANUFACTURING READINESS MODE | CRITICAL | NO-BIND STATE ACTIVE; ACTION HELD; APPROVER UNAVAILABLE; DOCUMENTED PAUSE CREATED; HUMAN AUTHORITY REQUIRED |
| RAMAT-A17-05 | A17-05 - IND or CTA Readiness and Submission Authorization | AGENTIC SUBMISSION ASSURANCE MODE | CRITICAL | AUTHORITY ABSENT; EVIDENCE INSUFFICIENT; NO-BIND STATE ACTIVE; ESCALATION REQUIRED; SOURCE-SYSTEM EXECUTION REQUIRED |
| RAMAT-A17-06 | A17-06 - Phase I First-in-Human Readiness | CLINICAL TRIAL ASSURANCE MODE | CRITICAL | HUMAN ACCOUNTABILITY MISSING; APPROVER UNAVAILABLE; NO-BIND STATE ACTIVE; ACTION HELD; HUMAN AUTHORITY REQUIRED |
| RAMAT-A17-07 | A17-07 - Phase II Dose and Efficacy Progression | CLINICAL TRIAL ASSURANCE MODE | CRITICAL | EVIDENCE INSUFFICIENT; ESCALATION REQUIRED; ACTION INADMISSIBLE; NO-BIND STATE ACTIVE; ACTION ADMISSIBLE |
| RAMAT-A17-08 | A17-08 - Phase III Confirmatory Evidence and Data-Lock Readiness | CLINICAL TRIAL ASSURANCE MODE | CRITICAL | ACTION HELD; DOCUMENTED PAUSE CREATED; APPROVER UNAVAILABLE; ESCALATION REQUIRED; ACTION ADMISSIBLE |
| RAMAT-A17-09 | A17-09 - Marketing Application and AI-Native Inspection Passport | REGULATOR AI READINESS AND INSPECTION PASSPORT MODE | CRITICAL | EVIDENCE INSUFFICIENT; AUTHORITY ABSENT; NO-BIND STATE ACTIVE; ACTION HELD; SOURCE-SYSTEM EXECUTION REQUIRED |
| RAMAT-A17-10 | A17-10 - Approval, Label, and Commercial Authorization Baseline | APPROVED PRODUCT BASELINE MODE | CRITICAL | SOURCE-SYSTEM EXECUTION REQUIRED; AUTHORITY OUT OF SCOPE; ACTION HELD; ACTION ADMISSIBLE |
| RAMAT-A17-11 | A17-11 - Technology Transfer and Site Readiness | TECHNOLOGY TRANSFER DEPENDENCY MODE | HIGH | DEPENDENCY UNSATISFIED; ACTION HELD; ESCALATION REQUIRED; DOCUMENTED PAUSE CREATED; ACTION ADMISSIBLE |
| RAMAT-A17-12 | A17-12 - Commercial Radiopharmaceutical Manufacturing Execution | IRLT MANUFACTURING EXECUTION ASSURANCE MODE | CRITICAL | NO-BIND STATE ACTIVE; ACTION HELD; TIMING INVALID; HUMAN AUTHORITY REQUIRED; DOCUMENTED PAUSE CREATED |
| RAMAT-A17-13 | A17-13 - QC Completion and Human Batch Release | QC AND HUMAN BATCH-RELEASE ASSURANCE MODE | CRITICAL | EVIDENCE INSUFFICIENT; AUTHORITY EXPIRED; NO-BIND STATE ACTIVE; ACTION INADMISSIBLE; ACTION ADMISSIBLE |
| RAMAT-A17-14 | A17-14 - Serialization, DSCSA, and Trading-Partner Readiness | DSCSA SERIALIZATION AND TRADING-PARTNER MODE | HIGH | AUTHORITY OUT OF SCOPE; EVIDENCE INSUFFICIENT; ACTION HELD; ESCALATION REQUIRED; ACTION ADMISSIBLE |
| RAMAT-A17-15 | A17-15 - Cold-Chain Distribution and Custody Transfer | CHAIN-OF-CUSTODY AND COLD-CHAIN MODE | CRITICAL | TIMING INVALID; APPROVER UNAVAILABLE; ACTION HELD; DOCUMENTED PAUSE CREATED; ESCALATION REQUIRED |
| RAMAT-A17-16 | A17-16 - Pharmacy Preparation, Patient-Specific Dose, and Administration Readiness | PATIENT-SPECIFIC DOSE AND COMPOUNDING ASSURANCE MODE | CRITICAL | IDENTITY CONFLICT; NO-BIND STATE ACTIVE; ACTION HELD; HUMAN AUTHORITY REQUIRED; SOURCE-SYSTEM EXECUTION REQUIRED |
| RAMAT-A17-17 | A17-17 - Post-Market Safety, Complaint, Recall, and Lifecycle Reconstruction | POST-MARKET SAFETY, CAPA, AND RECALL MODE | CRITICAL | ESCALATION REQUIRED; HUMAN AUTHORITY REQUIRED; NO-BIND STATE ACTIVE; ACTION HELD; ACTION ADMISSIBLE |

## Lifecycle display-contract details

### RAMAT-A17-01 - Target Discovery and Unmet-Need Definition

- Lifecycle phase: DISCOVERY
- Primary regulated object: AURORA-17 discovery program
- Proposed action: Authorize progression from disease hypothesis to governed discovery program.
- Consequence level: **MODERATE**
- Display mode: **RESEARCH AND DISCOVERY ASSURANCE MODE**
- Primary view: Research provenance, candidate identity, AI-use governance, evidence integrity, scientific accountability, and progression readiness.
- Context prompt: Review the governed evidence and accountable scientific authority before lifecycle progression.
- Refresh policy: REFRESH ON NEW EVIDENCE, MODEL VERSION, OR REVIEW STATE
- Allowed display states: `EVIDENCE INSUFFICIENT; HUMAN AUTHORITY REQUIRED; ACTION HELD; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-02 - AI-Assisted Candidate and Ligand Design

- Lifecycle phase: DISCOVERY
- Primary regulated object: AURORA-17 candidate design and AI recommendation set
- Proposed action: Select the fictional AURORA-17 radioligand candidate for experimental evaluation.
- Consequence level: **HIGH**
- Display mode: **RESEARCH AND DISCOVERY ASSURANCE MODE**
- Primary view: Research provenance, candidate identity, AI-use governance, evidence integrity, scientific accountability, and progression readiness.
- Context prompt: Review the governed evidence and accountable scientific authority before lifecycle progression.
- Refresh policy: REFRESH ON NEW EVIDENCE, MODEL VERSION, OR REVIEW STATE
- Allowed display states: `AUTHORITY ABSENT; EVIDENCE INSUFFICIENT; HUMAN ACCOUNTABILITY MISSING; NO-BIND STATE ACTIVE; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-03 - Preclinical Characterization and Translational Evidence

- Lifecycle phase: PRECLINICAL
- Primary regulated object: AURORA-17 preclinical evidence package
- Proposed action: Authorize progression to regulated clinical-development preparation.
- Consequence level: **HIGH**
- Display mode: **RESEARCH AND DISCOVERY ASSURANCE MODE**
- Primary view: Research provenance, candidate identity, AI-use governance, evidence integrity, scientific accountability, and progression readiness.
- Context prompt: Review the governed evidence and accountable scientific authority before lifecycle progression.
- Refresh policy: REFRESH ON NEW EVIDENCE, MODEL VERSION, OR REVIEW STATE
- Allowed display states: `EVIDENCE INSUFFICIENT; TIMING INVALID; ACTION HELD; ESCALATION REQUIRED; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: DISPLAY AUTHORITY PRESENT, VALID, CURRENT, DELEGATED, IN-SCOPE, AND ACCOUNTABLE-HUMAN STATE
- Timing: TIMING INVALID - DISPLAY DEADLINE, VALIDITY WINDOW, DECAY WINDOW, EXPIRY, AND TIME-CRITICAL RISK
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-04 - Clinical-Supply and Investigational Manufacturing Readiness

- Lifecycle phase: CLINICAL SUPPLY
- Primary regulated object: AURORA-17 investigational clinical-supply batch
- Proposed action: Authorize manufacture of investigational AURORA-17 clinical supply.
- Consequence level: **CRITICAL**
- Display mode: **CLINICAL-SUPPLY MANUFACTURING READINESS MODE**
- Primary view: Material, equipment, operator, recipe, facility, change-control, and Quality approval dependencies.
- Context prompt: Do not begin manufacturing while any required readiness dependency is unknown, held, mismatched, or unapproved.
- Refresh policy: REFRESH ON MATERIAL, EQUIPMENT, TRAINING, OR QUALITY STATE CHANGE
- Allowed display states: `NO-BIND STATE ACTIVE; ACTION HELD; APPROVER UNAVAILABLE; DOCUMENTED PAUSE CREATED; HUMAN AUTHORITY REQUIRED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-05 - IND or CTA Readiness and Submission Authorization

- Lifecycle phase: REGULATORY ENTRY
- Primary regulated object: AURORA-17 investigational regulatory submission package
- Proposed action: Authorize submission of the fictional AURORA-17 IND or CTA package.
- Consequence level: **CRITICAL**
- Display mode: **AGENTIC SUBMISSION ASSURANCE MODE**
- Primary view: Claim-to-proof traceability, document provenance, signatory authority, AI-generated content review, and submission admissibility.
- Context prompt: Submission remains held until evidence, signatory authority, and source-document agreement are positively verified.
- Refresh policy: REFRESH ON DOCUMENT, CLAIM, APPROVAL, OR SIGNATORY STATE CHANGE
- Allowed display states: `AUTHORITY ABSENT; EVIDENCE INSUFFICIENT; NO-BIND STATE ACTIVE; ESCALATION REQUIRED; SOURCE-SYSTEM EXECUTION REQUIRED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-06 - Phase I First-in-Human Readiness

- Lifecycle phase: CLINICAL PHASE I
- Primary regulated object: AURORA-17 Phase I protocol and first-patient readiness state
- Proposed action: Authorize first-patient enrollment and dosing readiness.
- Consequence level: **CRITICAL**
- Display mode: **CLINICAL TRIAL ASSURANCE MODE**
- Primary view: Participant identity, consent, delegation, site readiness, data review, safety, laboratory, imaging, and accountable clinical authority.
- Context prompt: Clinical progression requires current identity, consent, evidence, safety review, and qualified human authority.
- Refresh policy: REFRESH ON SUBJECT, SITE, SAFETY, DATA, OR REVIEW STATE CHANGE
- Allowed display states: `HUMAN ACCOUNTABILITY MISSING; APPROVER UNAVAILABLE; NO-BIND STATE ACTIVE; ACTION HELD; HUMAN AUTHORITY REQUIRED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-07 - Phase II Dose and Efficacy Progression

- Lifecycle phase: CLINICAL PHASE II
- Primary regulated object: AURORA-17 Phase II dose and efficacy evidence package
- Proposed action: Authorize progression of the selected dose and trial strategy.
- Consequence level: **CRITICAL**
- Display mode: **CLINICAL TRIAL ASSURANCE MODE**
- Primary view: Participant identity, consent, delegation, site readiness, data review, safety, laboratory, imaging, and accountable clinical authority.
- Context prompt: Clinical progression requires current identity, consent, evidence, safety review, and qualified human authority.
- Refresh policy: REFRESH ON SUBJECT, SITE, SAFETY, DATA, OR REVIEW STATE CHANGE
- Allowed display states: `EVIDENCE INSUFFICIENT; ESCALATION REQUIRED; ACTION INADMISSIBLE; NO-BIND STATE ACTIVE; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: DISPLAY AUTHORITY PRESENT, VALID, CURRENT, DELEGATED, IN-SCOPE, AND ACCOUNTABLE-HUMAN STATE
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-08 - Phase III Confirmatory Evidence and Data-Lock Readiness

- Lifecycle phase: CLINICAL PHASE III
- Primary regulated object: AURORA-17 pivotal-trial evidence package
- Proposed action: Authorize pivotal-trial data lock and regulatory-evidence finalization.
- Consequence level: **CRITICAL**
- Display mode: **CLINICAL TRIAL ASSURANCE MODE**
- Primary view: Participant identity, consent, delegation, site readiness, data review, safety, laboratory, imaging, and accountable clinical authority.
- Context prompt: Clinical progression requires current identity, consent, evidence, safety review, and qualified human authority.
- Refresh policy: REFRESH ON SUBJECT, SITE, SAFETY, DATA, OR REVIEW STATE CHANGE
- Allowed display states: `ACTION HELD; DOCUMENTED PAUSE CREATED; APPROVER UNAVAILABLE; ESCALATION REQUIRED; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: DISPLAY AUTHORITY PRESENT, VALID, CURRENT, DELEGATED, IN-SCOPE, AND ACCOUNTABLE-HUMAN STATE
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-09 - Marketing Application and AI-Native Inspection Passport

- Lifecycle phase: REGULATORY SUBMISSION
- Primary regulated object: AURORA-17 marketing application and inspection passport
- Proposed action: Authorize marketing-application submission and inspection-readiness state.
- Consequence level: **CRITICAL**
- Display mode: **REGULATOR AI READINESS AND INSPECTION PASSPORT MODE**
- Primary view: Connected submission evidence, integrity seals, rehash status, claim-to-proof links, unresolved gaps, and inspection reconstruction.
- Context prompt: Display the current inspection passport and all unresolved evidence, integrity, authority, or consistency gaps.
- Refresh policy: REFRESH ON EVIDENCE, REHASH, CLAIM, APPROVAL, OR PASSPORT CHANGE
- Allowed display states: `EVIDENCE INSUFFICIENT; AUTHORITY ABSENT; NO-BIND STATE ACTIVE; ACTION HELD; SOURCE-SYSTEM EXECUTION REQUIRED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-10 - Approval, Label, and Commercial Authorization Baseline

- Lifecycle phase: APPROVAL
- Primary regulated object: AURORA-17 approved product and label baseline
- Proposed action: Register the approved commercial baseline and authorized conditions of use.
- Consequence level: **CRITICAL**
- Display mode: **APPROVED PRODUCT BASELINE MODE**
- Primary view: Approved label, product identity, site scope, specifications, regulatory commitments, and authorized commercial baseline.
- Context prompt: Confirm the displayed baseline against the official regulatory and product-master source records.
- Refresh policy: REFRESH ON APPROVAL, LABEL, SITE, SPECIFICATION, OR COMMITMENT CHANGE
- Allowed display states: `SOURCE-SYSTEM EXECUTION REQUIRED; AUTHORITY OUT OF SCOPE; ACTION HELD; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-11 - Technology Transfer and Site Readiness

- Lifecycle phase: TECHNOLOGY TRANSFER
- Primary regulated object: AURORA-17 commercial process and receiving-site transfer package
- Proposed action: Authorize transfer acceptance and commercial-site readiness.
- Consequence level: **HIGH**
- Display mode: **TECHNOLOGY TRANSFER DEPENDENCY MODE**
- Primary view: Sending-site and receiving-site agreement, equipment mapping, method transfer, training, validation, change control, and acceptance readiness.
- Context prompt: Transfer acceptance remains held until all mandatory receiving-site dependencies are positively satisfied.
- Refresh policy: REFRESH ON TRANSFER, METHOD, EQUIPMENT, TRAINING, OR VALIDATION CHANGE
- Allowed display states: `DEPENDENCY UNSATISFIED; ACTION HELD; ESCALATION REQUIRED; DOCUMENTED PAUSE CREATED; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DEPENDENCY UNSATISFIED - DISPLAY REQUIRED STATE, OBSERVED STATE, SOURCE, OWNER, AND RESOLUTION ROUTE
- Authority: DISPLAY AUTHORITY PRESENT, VALID, CURRENT, DELEGATED, IN-SCOPE, AND ACCOUNTABLE-HUMAN STATE
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-12 - Commercial Radiopharmaceutical Manufacturing Execution

- Lifecycle phase: COMMERCIAL MANUFACTURING
- Primary regulated object: AURORA-17 commercial radiopharmaceutical batch
- Proposed action: Authorize execution of the commercial manufacturing batch.
- Consequence level: **CRITICAL**
- Display mode: **IRLT MANUFACTURING EXECUTION ASSURANCE MODE**
- Primary view: Radionuclide identity, decay timing, material genealogy, recipe, equipment, operator, environmental, automation, and execution readiness.
- Context prompt: Do not proceed when identity, timing, material, equipment, environmental, automation, or authority conditions are unresolved.
- Refresh policy: EVENT-DRIVEN REFRESH FOR TIME-CRITICAL MANUFACTURING STATE
- Allowed display states: `NO-BIND STATE ACTIVE; ACTION HELD; TIMING INVALID; HUMAN AUTHORITY REQUIRED; DOCUMENTED PAUSE CREATED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: TIMING INVALID - DISPLAY DEADLINE, VALIDITY WINDOW, DECAY WINDOW, EXPIRY, AND TIME-CRITICAL RISK
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-13 - QC Completion and Human Batch Release

- Lifecycle phase: QUALITY CONTROL AND RELEASE
- Primary regulated object: AURORA-17 finished batch and release decision
- Proposed action: Determine whether the commercial batch is admissible for authorized human release.
- Consequence level: **CRITICAL**
- Display mode: **QC AND HUMAN BATCH-RELEASE ASSURANCE MODE**
- Primary view: Sample identity, laboratory-source agreement, raw-data integrity, deviation disposition, release authority, timing, and admissibility.
- Context prompt: Platform admissibility does not release the batch. Authorized human release and official source-system execution are required.
- Refresh policy: REFRESH ON RESULT, REVIEW, DEVIATION, AUTHORITY, OR TIMING CHANGE
- Allowed display states: `EVIDENCE INSUFFICIENT; AUTHORITY EXPIRED; NO-BIND STATE ACTIVE; ACTION INADMISSIBLE; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-14 - Serialization, DSCSA, and Trading-Partner Readiness

- Lifecycle phase: SERIALIZATION AND SUPPLY CHAIN
- Primary regulated object: AURORA-17 serialized commercial product and transaction package
- Proposed action: Authorize product transfer into the governed pharmaceutical supply chain.
- Consequence level: **HIGH**
- Display mode: **DSCSA SERIALIZATION AND TRADING-PARTNER MODE**
- Primary view: Product identifier, serial, lot, expiration, EPCIS state, aggregation, trading-partner authority, transaction evidence, and suspect-product state.
- Context prompt: Hold transfer when serialization, trading-partner, transaction, or suspect-product conditions are incomplete or conflicted.
- Refresh policy: REFRESH ON SERIALIZATION, EPCIS, PARTNER, OR TRANSACTION CHANGE
- Allowed display states: `AUTHORITY OUT OF SCOPE; EVIDENCE INSUFFICIENT; ACTION HELD; ESCALATION REQUIRED; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: EVIDENCE INSUFFICIENT - DISPLAY MISSING, STALE, CONFLICTED, UNSEALED, OR REHASH-FAILED EVIDENCE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: DISPLAY ACCOUNTABLE HUMAN OR ROLE, ASSIGNMENT STATE, CURRENT ELIGIBILITY, AND REVIEW STATUS
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-15 - Cold-Chain Distribution and Custody Transfer

- Lifecycle phase: DISTRIBUTION
- Primary regulated object: AURORA-17 shipment and custody chain
- Proposed action: Authorize custody transfer and delivery to the treatment or pharmacy site.
- Consequence level: **CRITICAL**
- Display mode: **CHAIN-OF-CUSTODY AND COLD-CHAIN MODE**
- Primary view: Shipment identity, custody sequence, temperature, carrier authority, location, delivery readiness, and time-critical decay window.
- Context prompt: Do not transfer custody when product identity, condition, carrier, timing, or receiving authority is unresolved.
- Refresh policy: EVENT-DRIVEN REFRESH FOR LOCATION, CONDITION, CUSTODY, AND TIMING
- Allowed display states: `TIMING INVALID; APPROVER UNAVAILABLE; ACTION HELD; DOCUMENTED PAUSE CREATED; ESCALATION REQUIRED`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: DISPLAY AUTHORITY PRESENT, VALID, CURRENT, DELEGATED, IN-SCOPE, AND ACCOUNTABLE-HUMAN STATE
- Timing: TIMING INVALID - DISPLAY DEADLINE, VALIDITY WINDOW, DECAY WINDOW, EXPIRY, AND TIME-CRITICAL RISK
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-16 - Pharmacy Preparation, Patient-Specific Dose, and Administration Readiness

- Lifecycle phase: PHARMACY AND PATIENT USE
- Primary regulated object: AURORA-17 patient-specific prepared dose
- Proposed action: Determine whether the patient-specific dose is admissible for authorized administration.
- Consequence level: **CRITICAL**
- Display mode: **PATIENT-SPECIFIC DOSE AND COMPOUNDING ASSURANCE MODE**
- Primary view: Mock patient identity, order, product, lot, dose calculation, preparation, label, pharmacist authority, administration window, and clinical readiness.
- Context prompt: Identity, dose, label, pharmacist authority, and timing must agree before an authorized clinician may proceed.
- Refresh policy: EVENT-DRIVEN REFRESH FOR IDENTITY, DOSE, LABEL, AUTHORITY, AND TIMING
- Allowed display states: `IDENTITY CONFLICT; NO-BIND STATE ACTIVE; ACTION HELD; HUMAN AUTHORITY REQUIRED; SOURCE-SYSTEM EXECUTION REQUIRED`

**Assurance signals**

- Identity: IDENTITY CONFLICT ACTIVE - VERIFY CANONICAL OBJECT, SOURCE BINDING, ALIASES, AND PHYSICAL-DIGITAL BINDING
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

### RAMAT-A17-17 - Post-Market Safety, Complaint, Recall, and Lifecycle Reconstruction

- Lifecycle phase: POST-MARKET
- Primary regulated object: AURORA-17 post-market evidence and product-lifecycle record
- Proposed action: Authorize governed safety action, corrective action, field communication, or recall escalation.
- Consequence level: **CRITICAL**
- Display mode: **POST-MARKET SAFETY, CAPA, AND RECALL MODE**
- Primary view: Safety signal, complaint, product identity, lot and serial traceability, investigation, CAPA, distribution history, escalation, and recall authority.
- Context prompt: Critical safety or recall action requires identifiable authority, complete traceability, explicit escalation, and governed source-system execution.
- Refresh policy: REFRESH ON SAFETY, COMPLAINT, INVESTIGATION, CAPA, OR RECALL CHANGE
- Allowed display states: `ESCALATION REQUIRED; HUMAN AUTHORITY REQUIRED; NO-BIND STATE ACTIVE; ACTION HELD; ACTION ADMISSIBLE`

**Assurance signals**

- Identity: DISPLAY CANONICAL OBJECT IDENTITY, SOURCE BINDING, VERIFICATION STATE, AND CONFLICT STATE
- Evidence integrity: DISPLAY EVIDENCE PRESENCE, PROVENANCE, HASH, REHASH, CURRENCY, AND SUFFICIENCY STATE
- Workflow dependency: DISPLAY WORKFLOW DEPENDENCY AGREEMENT, UNKNOWN STATE, MISMATCH, HOLD, AND DELAY STATUS
- Authority: AUTHORITY DEFICIENCY ACTIVE - DISPLAY REQUIRED ROLE, CURRENT AUTHORITY STATE, SCOPE, VALIDITY, AND ESCALATION
- Timing: DISPLAY CURRENT TIME, EVIDENCE CURRENCY, AUTHORITY VALIDITY, EXECUTION WINDOW, AND EXPIRY STATE
- Human accountability: HUMAN REVIEW REQUIRED - DISPLAY ACCOUNTABLE ROLE, APPROVER AVAILABILITY, RESPONSE WINDOW, AND ESCALATION ROUTE
- No-Bind: NO-BIND OR HOLD STATE MAY BE DISPLAYED. DISPLAY REASON, ACTIVATION TIME, REQUIRED RESOLUTION, ESCALATION, AND HUMAN AUTHORITY PROMPT.
- Source-system state: DISPLAY GOVERNED SOURCE-SYSTEM NAME, RECORD REFERENCE, RECORD VERSION, OBSERVED STATE, AND LAST-VERIFIED TIME. DO NOT DISPLAY RAMAT VISION AS THE SOURCE OF TRUTH.

**Human prompt**

- STOP: GOVERNANCE HOLD ACTIVE. REVIEW THE DISPLAYED REASON, VERIFY EVIDENCE AND AUTHORITY, USE THE GOVERNED ESCALATION ROUTE, AND DO NOT PROCEED UNTIL AUTHORIZED RESOLUTION IS RECORDED.

**Display contract controls**

- Allowed fields: `display_contract_id; stage_id; stage_name; lifecycle_phase; primary_regulated_object; action_consequence_level; identity_state; evidence_state; integrity_state; dependency_state; authority_state; approver_state; escalation_state; timing_state; accountability_state; no_bind_state; admissibility_state; source_system_reference; rationale_summary; generated_at_utc; expires_at_utc`
- Prohibited controls: `approve; release; override; resolve_no_bind; execute_action; submit_regulatory_package; administer_dose; dispense; transfer_custody; sign_record; merge_identity; retire_identity; edit_source_record; dismiss_hold_without_reason; create_binding_authority`
- Redaction rule: DISPLAY ONLY THE MINIMUM AUTHORIZED INFORMATION. MASK OR OMIT PERSONAL, CONFIDENTIAL, PROPRIETARY, SECURITY-SENSITIVE, OR REGULATED DATA NOT REQUIRED FOR THE CURRENT ASSURANCE DECISION.
- Expiry rule: THE DISPLAY CONTRACT EXPIRES WHEN ITS DECLARED EXPIRY TIME IS REACHED, WHEN SOURCE STATE CHANGES, WHEN AUTHORITY CHANGES, WHEN A NEW EVALUATION IS ISSUED, OR WHEN THE DISPLAY SESSION ENDS.
- Offline rule: OFFLINE OR DISCONNECTED DISPLAY STATE MUST BE MARKED STALE OR UNKNOWN. CACHED STATE MUST NOT BE PRESENTED AS CURRENT AUTHORITY OR CURRENT APPROVAL.
- No-Bind preview rule: RAMAT VISION MAY DISPLAY AUTHORITY ABSENT, NO-BIND STATE ACTIVE, ACTION HELD, ESCALATION REQUIRED, DOCUMENTED PAUSE CREATED, APPROVER UNAVAILABLE, HUMAN AUTHORITY REQUIRED, AND RELATED PLATFORM B1 EVALUATED STATES. RAMAT VISION MAY NOT RESOLVE THE HOLD.

**Mandatory boundaries**

- Display authority: DISPLAY / WITNESS ONLY. RAMAT VISION, THREAD D, THREAD D2, GLASSES, WEARABLES, DASHBOARDS, AND DEVICE WITNESSES HAVE NO ASSURANCE-DECISION, APPROVAL, RELEASE, OVERRIDE, RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Decision boundary: PLATFORM B AND PLATFORM B1 MAY EVALUATE ASSURANCE STATE. QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES MAKE BINDING DECISIONS.
- Execution boundary: ACTION ADMISSIBILITY IS NOT EXECUTION. OFFICIAL EXECUTION OCCURS ONLY THROUGH THE AUTHORIZED HUMAN PROCESS AND GOVERNED SOURCE SYSTEM.
- Source-of-truth boundary: OFFICIAL RECORDS REMAIN IN GOVERNED SOURCE SYSTEMS. RAMAT VISION DISPLAYS REFERENCES AND EVALUATED STATE ONLY.
- Data boundary: FICTIONAL AURORA-17 DATA, SYNTHETIC RECORDS, MOCK IDENTITIES, NO PHI, NO COMPANY PRODUCTION DATA, AND NO REAL REGULATED PRODUCTION INTEGRATION.

## Step 158 review gate

Before Step 158 begins, review all 17 lifecycle display contracts, 8 assurance lenses, 14 display invariants, approved display states, allowed fields, prohibited controls, redaction, expiry, offline behavior, No-Bind preview behavior, human prompts, and source-system references.

Confirm that RAMAT Vision cannot approve, release, override, resolve No-Bind, execute actions, modify source records, merge identities, or create binding authority.

Step 158 will create the Azure, on-premises, edge, wearable, and offline deployment plan while preserving the evaluation, display, human-authority, source-of-truth, security, and data boundaries.

**STEP 157 RAMAT LIFECYCLE DISPLAY MAP COMPLETE**

**STEP 158: READY AFTER REVIEW**

