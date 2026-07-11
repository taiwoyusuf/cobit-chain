# MVP2 Build Boundary — Platform B1

## Hard Boundary

Do not modify Platform B v1.

Do not reopen Platform B v1 architecture.

Do not modify Thread D v1.

Do not change the validated Thread D to Platform B MVP connector.

Do not activate MVP3 features.

Do not build real Halo integration.

Do not connect to real ServiceNow, LIS, middleware, eQMS, GMP records, PHI, or real production systems.

## Implementation Rule

Use mock data first.

Use simulated records first.

Use local files first.

Use docs and schemas first.

Build evaluator logic only after registry and schema are committed.

Provision Azure services only after architecture and local MVP2 contracts are stable.

## Security Rule

No secrets in code.

No secrets in browser.

No `.env` commits.

No Azure Function keys in GitHub.

No API keys in GitHub.

No real patient data.

No real GMP production data.

## Role Rule

A device does not equal a role.

A signed-in verified user session determines the active role/persona.

Voice may request a role.

Voice does not grant a role.

## Glasses Rule

RAMAT Vision displays state.

Thread D2 shows.

Platform B1 evaluates.

The glasses do not approve GMP work.

The glasses do not release results.

The glasses do not replace Quality Unit, source systems, or human accountability.
