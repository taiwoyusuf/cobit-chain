# Wearable Capture Route Manifest

## Document status

PLATFORM B V0.3 ROUTE MANIFEST

## Generated at

2026-07-04T19:07:59Z

## Branch

feature/platform-b-v0.3-meta-glass-field-demo

## Source commit before route manifest commit

5e42ad0

## Purpose

This manifest defines the Platform B v0.3 mobile-friendly wearable capture route target.

## Route target

/wearable-capture

## Current implementation file

platform_b_mvp/v0_3_meta_glass_demo/wearable_capture.html

## Demo purpose

The page supports the Platform B v0.3 Meta Glass Wearable Field Demo.

It allows a user to upload a photo or video imported from Ray-Ban Meta smart glasses and generate a demo context-assurance signal.

## Required fields

The page captures:

- operator ID
- location
- equipment ID
- SOP step
- work order or demo context
- evidence file upload
- AI recommendation
- human reviewer
- requested action: proceed, review, or stop

## Current Day 3 behavior

The page generates a client-side demo draft record only.

It does not yet persist evidence.

It does not yet link to the v0.2 evidence console.

It does not yet create a final exportable report.

Those are Day 4 and Day 5 tasks.

## Direct mobile use

Open the HTML file directly on a phone or host it behind the future route:

/wearable-capture

A QR code can point to the hosted route after the route is deployed.

## Demo guardrail

Do not upload patient data, real GMP batch data, confidential company information, credentials, badges, restricted facility images, or regulated operational evidence.

## Doctrine

Wearables are not the product. Context-assured evidence is the product.

## Strong phrase

Smart glasses capture the scene. Platform B proves whether the scene was admissible for action.
