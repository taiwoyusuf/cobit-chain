# Step 176 — Physical Evidence Standing R2

This bounded executable candidate turns selected cross-domain Thread D refinements into deterministic assurance evaluations without creating a new authority, release, radiation-safety, clinical, compounding, or product-disposition engine.

## Implemented invariants

1. **State-conditioned operating-envelope standing** — calibrated/authenticated/healthy does not establish support when the instrument or model is outside its validated physical state space.
2. **Observation-channel fidelity** — transport loss and witness perturbation can invalidate otherwise healthy sensing.
3. **Temporal-resolution standing** — correct timestamps do not cure slow response, sparse sampling, or aggregation that can erase transients.
4. **Detectability/quantification standing** — `NOT_DETECTED_WITH_LIMIT` is not numeric zero and detected does not automatically mean reliably quantified.
5. **Comparability/bridge standing** — valid Regime A plus valid Regime B does not establish longitudinal equivalence across a change boundary.
6. **Interface/composition standing** — trustworthy components do not automatically create a trustworthy composed measurement system.
7. **Fusion standing** — fused states retain dependency/covariance and uncertainty obligations.
8. **Source-attribution standing** — an established condition does not establish its cause while competing sources remain plausible.
9. **Time-indexed standing** — standing can expire because physical truth is time-dependent even without an external event.
10. **Decision-policy standing** — model/prediction validity does not establish that the rule or action policy using it is validated.
11. **Human-oversight-capacity standing** — human presence is insufficient when meaningful review or timely intervention is not feasible.
12. **Transfer/delivery fidelity** — intended, prepared, commanded, or pre-transfer quantity is not automatically the quantity that reached the destination.

## Domain applicability

These primitives are deliberately domain-independent and are intended to be reused by domain profiles including Clinical Trial Assurance, CompoundSafe, Radiopharma Assurance, ALARA/Radiological Operations Assurance, LabTrust, RAMAT Vision physical/contextual witness workflows, and future regulated physical domains.

## Architectural boundary

- Reuse existing COBIT-Chain identity, evidence, dependency, authority, Action Admissibility and No-Bind semantics.
- RAMAT Vision remains a contextual/physical witness and does not become a substitute for qualified radiation, laboratory, environmental, clinical, or product instruments.
- These evaluators produce non-binding assurance states only.
- No regulated release, stop-work, administration, product disposition, radiation decision, clinical decision, or autonomous physical action is authorized here.
- Historical evidence is preserved; changed standing does not rewrite history.

## Maturity

`IMPLEMENTED_BOUNDED_CANDIDATE`

Deterministic tests accompany this step. Repository CI evidence and wider integration/non-bypassability remain separate maturity gates.
