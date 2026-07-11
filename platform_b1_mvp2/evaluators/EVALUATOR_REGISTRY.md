# Platform B1 MVP2 Evaluator Registry

Status: MVP2 LOCAL PREVIEW

This registry connects Platform B1 / MVP2 evaluators to:

- mock records
- schemas
- evaluator modules
- evaluator functions
- Thread D2 display contracts
- Thread D2 display fixtures
- guardrails

## Current active MVP2 evaluator

### Workflow Dependency Assurance Lens

Feature ID:

`workflow_dependency_assurance_lens`

Depth:

`deep`

Status:

`ACTIVE_MVP2_LOCAL`

Primary case:

`Middleware Verified / LIS Held`

Evaluator:

`platform_b1_mvp2/evaluators/workflow_dependency_evaluator.py`

Mock record:

`platform_b1_mvp2/mock_data/prakriti_middleware_verified_lis_held.json`

D2 display contract:

`platform_b1_mvp2/ui_contracts/WORKFLOW_DEPENDENCY_D2_DISPLAY_CONTRACT.md`

D2 display fixture:

`platform_b1_mvp2/ui_contracts/workflow_dependency_d2_display_fixture.json`

Primary outputs:

- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- LIS HOLD DETECTED
- MIDDLEWARE VERIFIED ONLY
- MANDATORY FIELD MISSING
- SECONDARY REVIEW REQUIRED
- RESULT RELEASE NOT ADMISSIBLE

## Doctrine

Platform B1 evaluates.

Thread D2 displays.

Official records remain in source systems.

Glasses do not approve GMP work.

Glasses do not release results.

## Boundary

Local registry only.

No Azure deployment.

No Platform B v1 modification.

No Thread D v1 modification.

No MVP3 activation.

No real ServiceNow, LIS, middleware, eQMS, PHI, GMP production data, or company production data.
