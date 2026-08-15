# COBIT-Chain™ Architecture Reconciliation Roadmap

## Governance status
- Canonical Audit R3 frozen artifacts: `PRESERVED`
- R3-E05 runtime acceptance: `NOT_ESTABLISHED`
- R3-E06: `NOT_AUTHORIZED`
- Reconciliation-layer implementation into frozen R3: `NOT_AUTHORIZED`
- Documentation/provenance capture: permitted as a separate repository layer

## Proposed implementation tranches after authoritative repository reconciliation

### AR-01 — Basis & Assumption Standing
Model the authority, currency, scope, applicability, and evidentiary basis on which a rule, assumption, or decision depends.

### AR-02 — Governed Memory Standing
Implement memory admissibility before inference, including provenance, authority, consent, freshness, retention, applicability, quarantine, revocation, and correction reachability.

### AR-03 — Retrieve / Infer / Act Authority Separation
A system may be permitted to retrieve information but prohibited from inferring, or permitted to infer but prohibited from binding action.

Refinement: Agent-Consumable Data Contract.
For agent-readable enterprise data, separately govern:
- data object identity;
- canonical meaning / semantic version;
- source authority;
- owner;
- freshness;
- purpose limitation;
- inference permission;
- retention rule;
- disclosure rule;
- action-use permission;
- dependencies.

Preserve the invariant:
`DISCOVERABLE != RETRIEVABLE != ACCESS_AUTHORIZED != AUTHORIZED_FOR_PURPOSE != PERMITTED_FOR_INFERENCE != PERMITTED_FOR_RETENTION != PERMITTED_FOR_ACTION`.

Making data machine-readable or API-accessible must not silently make it agent-actionable.

### AR-04 — Duty Horizon & Non-Resettable Aging
Preserve original obligation age and due-state across reassignment or custodial transfer.

### AR-05 — Revocation Consequence Propagation
Determine what descendant decisions, standing states, and actions require review, quarantine, re-closure, or invalidation when an upstream authority or memory is revoked or corrected.

Refinement: Authority-Loss Exposure Window.
Treat the interval from authority/standing loss to effective enforcement as a governed interval, including:
- loss effective time;
- loss detection time;
- loss propagation time;
- enforcement effective time;
- last accepted commit;
- first rejected commit;
- dependent agents;
- objects touched during the interval;
- consequences formed;
- reversibility class;
- required disposition.

Possible dispositions include:
- UNAFFECTED;
- REVIEW_REQUIRED;
- QUARANTINED;
- ROLLBACK_CANDIDATE;
- RECONCILIATION_REQUIRED;
- REVALIDATION_REQUIRED;
- IRREVERSIBLE_CONSEQUENCE;
- HUMAN_DISPOSITION_REQUIRED.

Preserve the distinction:
`REVOCATION_EFFECTIVE != CONSEQUENCES_RECONCILED`.

### AR-06 — Delegation Monotonicity & Authority Contraction
Delegation cannot silently expand authority beyond the delegator or survive expiration/revocation without explicit standing.

Refinement: Derived-Authority Propagation Test.
Dependent authority must not silently outlive the authority from which it derives unless independently re-established. Parent-authority loss should trigger dependent-grant identification, suspension as applicable, consequence-route restraint, exposure-window inventory, and governed re-establishment where continuation is justified.

### AR-07 — Trajectory / Continuing Consequence Assurance
Evaluate not only admissibility at T0 but whether continuing consequences remain supportable as conditions change.

Preserve trigger-vs-determination separation:
`REQUALIFICATION_TRIGGERED != AUTHORITY_INVALID != VALIDATION_STANDING_LOST != ACTION_DENIED`.

Also preserve:
`NO_TRIGGER_DETECTED != STANDING_CURRENT`.

### AR-08 — Graduated Restraint & Out-of-Band Containment
Define non-binding warnings, holds, quarantine, escalation, restraint, and separately authorized enforcement surfaces.

Refinement: agent-capable API enablement should trigger execution-surface discovery and admissibility-enforcement review. Technical API reachability is not equivalent to operation authority, and authority for one operation is not authority for all operations exposed by the same API.

### AR-09 — Meta-Assurance
Provide evidence that the assurance mechanism itself was current, applicable, correctly configured, and independently reconstructable when relied upon.

## Additional implementation/challenge invariants

- `DATA_ACCESSIBLE != DATA_SEMANTICALLY_UNDERSTOOD != DATA_AUTHORIZED_FOR_PURPOSE != DATA_SUITABLE_FOR_INFERENCE != ACTION_ADMISSIBLE`.
- `API_AVAILABLE != AGENT_AUTHORIZED_TO_USE_API`.
- `AGENT_AUTHORIZED_FOR_ONE_OPERATION != AGENT_AUTHORIZED_FOR_ALL_OPERATIONS_EXPOSED_BY_API`.
- `AUTHORIZED_AT_T0 != AUTHORIZED_AT_T1`.
- `NOT_REVOKED != CURRENTLY_AUTHORIZED`.
- parent authority loss must not silently leave derivative authority alive;
- `REASSESSMENT_TRIGGER != STANDING_LOST`;
- `AUTHORIZED_COMMIT != SUCCESSFUL_EXECUTION != INTENDED_OUTCOME`.

## Required gate before coding
Each tranche must first be reconciled against authoritative current first-party repository evidence and classified as one of:
- `ALREADY_COVERED`
- `PRESENT_NOT_WIRED`
- `PARTIAL`
- `COMPATIBLE_EXTENSION`
- `ROADMAP_ONLY`
- `CONFLICTING_AUTHORITY`

No implementation status is inferred solely from this roadmap.