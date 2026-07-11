# Tests — Platform B1 MVP2

This folder holds local validation tests and smoke runners for Platform B1 / MVP2.

## Current test coverage

- Workflow Dependency Assurance evaluator unit tests
- Workflow Dependency smoke runner
- Thread D2 display fixture unit tests
- Evaluator registry unit tests
- MVP2 orchestration smoke runner

## MVP2 orchestration chain

The orchestration smoke runner proves the first local MVP2 chain:

mock data -> evaluator registry -> evaluator -> Thread D2 display fixture

Current runner:

- `run_mvp2_orchestration_smoke.py`

Current unit test:

- `test_mvp2_orchestration_smoke.py`

## Current active evaluator

Workflow Dependency Assurance Lens

Primary case:

Middleware Verified / LIS Held

Primary output:

WORKFLOW APPEARS COMPLETE BUT BLOCKED

Reason:

LIS HOLD DETECTED

Required action:

SECONDARY REVIEW REQUIRED

Evidence state:

AUDIT EVIDENCE NOT READY

## Boundary

Local tests only.

No Azure deployment.

No Platform B v1 modification.

No Thread D v1 modification.

No MVP3 activation.

No real ServiceNow, LIS, middleware, eQMS, PHI, GMP production data, or company production data.
