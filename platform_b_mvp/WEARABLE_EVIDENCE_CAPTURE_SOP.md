# Wearable Evidence Capture SOP

## Document status

PLATFORM B V0.3 DEMO SOP ONLY

## Generated at

2026-07-04T18:54:52Z

## Branch

feature/platform-b-v0.3-meta-glass-field-demo

## Source commit before SOP commit

4c2447f

## Purpose

This SOP defines how wearable-captured evidence may be collected for the Platform B v0.3 Meta Glass Wearable Field Demo.

This SOP supports a non-confidential, non-production, non-regulated field demo only.

## Scope

This SOP applies only to the Platform B v0.3 demo workflow:

Ray-Ban Meta smart glasses capture real-world context -> media imports to phone -> user uploads evidence to Platform B -> context-assurance signal is created -> action admissibility is checked -> operational trust record is updated -> exportable evidence summary is generated.

## Frozen prior versions

Platform B v0.1 remains frozen as the evidence/proof package.

Platform B v0.2 remains frozen as the demo console.

This SOP does not modify v0.1 or v0.2 tags.

## Demo-only boundary

This SOP does not support:

- production use
- GMP use
- clinical use
- patient use
- validation evidence
- regulatory submission evidence
- autonomous execution
- real batch release
- real operational decision-making
- confidential company information capture

## Allowed demo evidence

Allowed evidence includes:

- demo photo captured using Ray-Ban Meta glasses
- demo video captured using Ray-Ban Meta glasses
- non-confidential demo environment
- fake equipment ID
- fake operator ID
- fake SOP step
- fake work order or demo context

## Prohibited evidence

Do not capture or upload:

- patient information
- employee personal information
- confidential company information
- real GMP batch data
- real manufacturing records
- real quality records
- real validation records
- real customer data
- restricted facility images
- security-sensitive images
- credentials, badges, screens, passwords, QR codes, or access tokens
- proprietary equipment configuration
- third-party confidential content

## Demo scenario

| Field | Demo value |
|---|---|
| Operator | Demo Operator 001 |
| Location | Demo Lab Room |
| Equipment | EQP-DEMO-1803 |
| SOP step | Step 4 — Visual context check |
| AI recommendation | Proceed / Review Required |
| Evidence type | Photo or short video |
| Capture device | Ray-Ban Meta smart glasses |
| Platform B output | Green / Yellow / Red context-assurance signal |

## Capture procedure

1. Confirm the demo area is non-confidential.
2. Confirm no patient, employee, customer, company, facility, credential, badge, or restricted information is visible.
3. Put on Ray-Ban Meta smart glasses.
4. Capture one demo photo or short demo video.
5. Import the media into the phone through the official Meta AI app workflow.
6. Review the media on the phone before upload.
7. Delete and recapture if restricted or confidential content appears.
8. Upload the approved demo media into Platform B v0.3 wearable capture page.
9. Complete required demo fields.
10. Generate context-assurance signal.
11. Generate action admissibility result.
12. Generate operational trust score update.
13. Export wearable evidence summary.

## Required upload fields

The upload page should collect:

- operator ID
- location
- equipment ID
- SOP step
- work order or demo context
- evidence file
- AI recommendation
- human reviewer
- requested action
- reviewer decision: proceed, review, or stop

## Context-assurance signal expectation

Platform B should generate one of the following demo signals:

- Green: context appears admissible for demo action
- Yellow: context requires review before demo action
- Red: context is not admissible for demo action

## Action admissibility expectation

Platform B should generate one demo action result:

- Proceed
- Pause for review
- Stop / escalate

## Reviewer expectation

The reviewer should be able to see:

1. uploaded wearable evidence
2. context-assurance signal
3. action admissibility result
4. trust score update
5. exportable evidence summary

## Doctrine

Wearables are not the product. Context-assured evidence is the product.

## Strong phrase

Smart glasses capture the scene. Platform B proves whether the scene was admissible for action.

## Final SOP guardrail

This SOP is for Platform B v0.3 demo use only.

It does not authorize regulated use.

It does not authorize production use.

It does not authorize capture of confidential information.

It does not create a compliance, validation, GMP, clinical, or regulatory claim.
