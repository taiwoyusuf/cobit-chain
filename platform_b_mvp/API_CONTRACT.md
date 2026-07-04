# Platform B MVP API Contract

## Capability 1: AI Use Case Registry

### POST /api/usecases

Creates an AI use case record.

Example body:

{
  "name": "AI-assisted batch deviation triage",
  "owner": "Quality Operations",
  "domain": "GMP Manufacturing",
  "context_of_use": "Supports triage of deviation narratives before human QA review",
  "risk_class": "medium",
  "lifecycle_stage": "Governance"
}

### GET /api/usecases/{use_case_id}

Retrieves a registered AI use case.

## Capability 2: Assurance Check API

### POST /api/assurance/check

Runs a lightweight MVP assurance check and writes an assurance evidence record.

Example body:

{
  "use_case_id": "USECASE-ID",
  "check_type": "governance_readiness",
  "control_context": "AI output requires qualified human review before GMP use",
  "evidence_refs": ["EV-ID-1"],
  "human_review_required": true
}

## Capability 3: Evidence Upload

### POST /api/evidence/upload

Uploads a base64-encoded evidence file to Blob Storage and writes metadata to Table Storage.

Example body:

{
  "use_case_id": "USECASE-ID",
  "file_name": "qa_review_note.txt",
  "content_type": "text/plain",
  "content_base64": "SGVsbG8="
}

## Capability 4: Operational Trust Score

### GET /api/trust-score/{use_case_id}

Calculates and stores a simple MVP operational trust score.

## Capability 5: Action Admissibility Record

### POST /api/action-admissibility

Creates a pre-execution action admissibility record.

Example body:

{
  "use_case_id": "USECASE-ID",
  "actor": "ai-agent-demo",
  "action": "Generate draft deviation summary",
  "purpose": "Quality triage support",
  "policy_status": "allowed",
  "approval_state": "approved",
  "data_lineage_available": true,
  "recovery_available": true
}

## Capability 6: Wearable Endpoint Simulator

### POST /api/wearable/simulate

Creates a simulated context-assurance signal. This is not hardware-first.

Example body:

{
  "use_case_id": "USECASE-ID",
  "operator_id": "operator-demo-001",
  "location_zone": "GMP suite simulated",
  "ppe_detected": true,
  "fatigue_risk": "low",
  "restricted_zone": false
}
