# Role-Based Wearable Interface Model

## Purpose

Define how RAMAT Vision family devices support different regulated roles without becoming the Platform B decision engine.

## Architecture boundary

Backlog only.

Do not reopen Platform B v1 architecture.

## Core rule

Any device may witness. Only Platform B decides.

## Role interfaces

| Product role | Primary user | Interface function | Decision authority |
|---|---|---|---|
| ELSA 22.4 | Field technician or operator | Capture context, display task micro-decisions, request confirmation | None |
| OMA 5.4 | Operations, shift, room, and area readiness lead | Display area readiness, room state, shift coordination, zone assurance | None |
| RAMAT Vision Pro | Reviewer, QA, supervisor, EHS, inspector | Review evidence, reconstruct context, draft observations | None by wearable |
| JEFERY | Developer, relay, prototype, field-test user | Test adapters, validate witness flows, relay technical diagnostics | None |

## Forbidden actions

- The wearable does not approve work.
- The wearable does not release a batch.
- The wearable does not close a deviation.
- The wearable does not close CAPA.
- The wearable does not modify GMP records.
- The wearable does not alter audit trails.

## Allowed actions

- Display Platform B decision state.
- Capture visual context.
- Capture voice intent.
- Capture human confirmation.
- Relay evidence boundary state.
- Display controlled document warning.
- Display translation support state.
- Draft review observations.
- Trigger stop-line event capture.

## Guardrail

Role-based wearable interaction supports accountability. It does not replace accountable human review or Platform B decisioning.
