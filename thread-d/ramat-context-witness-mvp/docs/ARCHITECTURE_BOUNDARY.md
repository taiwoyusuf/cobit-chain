# Thread D Architecture Boundary

## Role of Thread D

Thread D is the context witness, wearable endpoint, display, relay, and audit reconstruction layer.

It captures operational context and presents Platform B output to the user.

## Role of Platform B

Platform B remains the assurance decision engine.

Platform B answers the question:

Can this action proceed?

## What Thread D can do

- Capture asset context
- Capture voice intent
- Capture human intent signal
- Display PROCEED / HOLD / ESCALATE
- Request reviewer
- Create stop-line evidence event
- Package evidence
- Reconstruct event story
- Prepare future API payloads

## What Thread D cannot do

- Approve work
- Release batch
- Close deviation
- Close CAPA
- Modify GMP record
- Modify CMDB record
- Modify validation record
- Override Platform B
- Replace human accountability
- Replace QMS or CSV requirements

## Architecture rule

Any device may witness. Only Platform B decides.
