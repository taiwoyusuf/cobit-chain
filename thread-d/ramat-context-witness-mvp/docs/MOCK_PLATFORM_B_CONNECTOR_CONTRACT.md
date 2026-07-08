# Mock Platform B Connector Contract

## Current state

Local mock only. No live API call.

## Future placeholder route

POST /api/platform-b/action-admissibility/check

## Request purpose

RAMAT Vision, ELSA, OMA, Halo, or JEFERY sends context to Platform B.

## Request includes

- source endpoint
- wearable node
- relay node
- timestamp
- asset identity
- visual candidate ID
- technician
- voice intent
- work order context
- validation context
- source-of-truth context
- physical witness state
- privacy boundary

## Response purpose

Platform B returns the action admissibility decision.

## Response includes

- decision: PROCEED, HOLD, or ESCALATE
- reason
- evidence hash
- micro-display instruction
- reviewer required flag
- wearable may override decision: false
- audit record available flag

## Boundary

RAMAT Vision displays the decision. Platform B makes the decision.
