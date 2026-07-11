# Workflow Dependency Assurance Lens — Thread D2 Display Contract

Status: MVP2 DISPLAY FIXTURE  
Workstream: Platform B1 / MVP2  
Companion display layer: Thread D2 — RAMAT Vision Advanced Assurance Preview

## Core doctrine

Platform B1 thinks.

Thread D2 shows.

RAMAT Vision displays the assurance state.

The glasses do not approve GMP work.

The glasses do not release results.

Official records remain in source systems.

## Source evaluator

- `platform_b1_mvp2/evaluators/workflow_dependency_evaluator.py`

## Primary mock case

Prakriti Middleware Verified / LIS Held

## Required D2 card fields

Each Thread D2 display card should support:

- `card_id`
- `feature_name`
- `display_mode`
- `headline`
- `reason`
- `required_action`
- `evidence_state`
- `severity`
- `badge`
- `outputs`
- `context`
- `guardrail`

## Primary display

Headline:

WORKFLOW APPEARS COMPLETE BUT BLOCKED

Reason:

LIS HOLD DETECTED

Required action:

SECONDARY REVIEW REQUIRED

Evidence state:

AUDIT EVIDENCE NOT READY

Severity:

red

Badge:

MVP2 PREVIEW

## Required outputs

- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- LIS HOLD DETECTED
- MIDDLEWARE VERIFIED ONLY
- MANDATORY FIELD MISSING
- SECONDARY REVIEW REQUIRED
- RESULT RELEASE NOT ADMISSIBLE

## Display guardrail

Thread D2 displays Platform B1 output.

Thread D2 does not evaluate source-system truth.

Thread D2 does not release results.

Thread D2 does not replace LIS, middleware, eQMS, ServiceNow, Quality Unit, or human accountability.

## Example wearer prompt

Is this workflow really complete?

## Example RAMAT Vision D2 response

WORKFLOW APPEARS COMPLETE BUT BLOCKED

Reason:

LIS HOLD DETECTED

Action:

SECONDARY REVIEW REQUIRED

Evidence:

AUDIT EVIDENCE NOT READY
