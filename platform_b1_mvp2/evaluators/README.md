# Evaluators — Platform B1 MVP2

This folder holds local evaluator logic for Platform B1 / MVP2.

## Registry

- `evaluator_registry.json`
- `evaluator_registry.py`
- `EVALUATOR_REGISTRY.md`

The evaluator registry maps each MVP2 feature to:

- evaluator module
- evaluator function
- mock record
- schema
- Thread D2 display contract
- Thread D2 display fixture
- primary outputs
- guardrail

## Current evaluators

- `workflow_dependency_evaluator.py`

## Workflow Dependency Assurance Lens

The first MVP2 evaluator checks whether a regulated workflow appears complete in one system but is actually blocked by hidden dependencies.

Initial mock case:

- Middleware Verified / LIS Held

Expected output:

- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- LIS HOLD DETECTED
- MIDDLEWARE VERIFIED ONLY
- MANDATORY FIELD MISSING
- SECONDARY REVIEW REQUIRED
- RESULT RELEASE NOT ADMISSIBLE

## Boundary

Local evaluator only.

No Azure deployment.

No Platform B v1 modification.

No Thread D v1 modification.

No real PHI.

No real GMP production data.

No real company production data.

Official records remain in source systems.

Thread D2 displays; Platform B1 evaluates.
