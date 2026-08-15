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

### AR-04 — Duty Horizon & Non-Resettable Aging
Preserve original obligation age and due-state across reassignment or custodial transfer.

### AR-05 — Revocation Consequence Propagation
Determine what descendant decisions, standing states, and actions require review, quarantine, re-closure, or invalidation when an upstream authority or memory is revoked or corrected.

### AR-06 — Delegation Monotonicity & Authority Contraction
Delegation cannot silently expand authority beyond the delegator or survive expiration/revocation without explicit standing.

### AR-07 — Trajectory / Continuing Consequence Assurance
Evaluate not only admissibility at T0 but whether continuing consequences remain supportable as conditions change.

### AR-08 — Graduated Restraint & Out-of-Band Containment
Define non-binding warnings, holds, quarantine, escalation, restraint, and separately authorized enforcement surfaces.

### AR-09 — Meta-Assurance
Provide evidence that the assurance mechanism itself was current, applicable, correctly configured, and independently reconstructable when relied upon.

## Required gate before coding
Each tranche must first be reconciled against authoritative current first-party repository evidence and classified as one of:
- `ALREADY_COVERED`
- `PRESENT_NOT_WIRED`
- `PARTIAL`
- `COMPATIBLE_EXTENSION`
- `ROADMAP_ONLY`
- `CONFLICTING_AUTHORITY`

No implementation status is inferred solely from this roadmap.