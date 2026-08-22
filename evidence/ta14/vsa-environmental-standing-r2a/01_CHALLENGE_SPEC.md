# 01 — Challenge Specification

## Question

Can VSA preserve historical qualification truth while independently recalculating current proposition-specific environmental validation standing when physical/context conditions change?

## Synthetic environment

A controlled regulated work environment, `ENV-01`, supports intended use `U1`.

At baseline, the qualification basis is:

- Geometry: `G1`
- Airflow configuration: `A1`
- Sensor topology: `S1`
- Process load: `L1`
- Occupancy profile: `O1`
- Operating state: `STEADY_STATE`
- Critical work zone: `CWZ-01`
- Monitoring point: `MP-01`
- Intended use: `U1`

The baseline evidence package `E1` establishes the relationship between `MP-01` and `CWZ-01` under `G1/A1/L1/O1`.

## Deliberate challenge

A later equipment installation changes geometry and local airflow from `G1/A1` to `G2/A2`.

Critically:

- `MP-01` does not move.
- Its identity remains established.
- Calibration remains current.
- Timestamps remain valid.
- All monitored values remain inside their synthetic acceptance ranges.
- No alarm occurs.

But the original evidence establishing `MP-01 -> CWZ-01` representativeness was generated under `G1/A1`, not `G2/A2`.

The challenge therefore asks whether VSA can preserve the truth of the historical baseline without silently treating that historical evidence as sufficient for the new physical context.

## Immaterial control

Before the material change, an asset-display label is changed. It does not alter geometry, airflow, sensor topology, process load, occupancy, operating state, intended use, or the sensor-to-critical-zone relationship.

Expected result: change detected, but no standing withdrawal.

## Partial restoration

New evidence `E2` re-establishes critical-zone representativeness and environmental-monitoring representativeness for intended use `U1` under `G2/A2/L2`, but does not include a dynamic recovery study under the new load.

Expected result: only the propositions actually supported by `E2` are restored.

## Final restoration

Evidence `E3` supplies the missing recovery evidence under the changed configuration.

Expected result: the remaining required proposition and overall intended-use environmental standing may then return to `SUPPORTABLE`.

## Epistemic boundary

This package distinguishes:

- authentic evidence from currently applicable evidence;
- calibrated measurement from representative measurement;
- in-limit values from validated environmental standing;
- historical qualification from present standing;
- selective restoration from contagious restoration.
