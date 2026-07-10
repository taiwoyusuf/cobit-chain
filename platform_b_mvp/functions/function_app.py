import base64
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import azure.functions as func
from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings


app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Platform B MVP storage defaults.
# These are the six active MVP storage objects only.
# Future v1.1 backlog capabilities are intentionally not active here.
MVP_STORAGE_DEFAULTS = {
    "PLATFORMB_USECASE_TABLE": "UseCaseRegistry",
    "PLATFORMB_EVIDENCE_TABLE": "EvidenceMetadata",
    "PLATFORMB_TRUST_TABLE": "TrustScores",
    "PLATFORMB_ACTION_TABLE": "ActionAdmissibilityRecords",
    "PLATFORMB_WEARABLE_TABLE": "WearableSignals",
    "PLATFORMB_ASSURANCE_TABLE": "AssuranceChecks",
    "PLATFORMB_EVIDENCE_CONTAINER": "evidence-files",
}

LOCKED_LIFECYCLE = [
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Manufacturing Monitoring",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust",
]

MVP_CAPABILITIES = [
    "AI Use Case Registry",
    "Assurance Check API",
    "Evidence Upload",
    "Operational Trust Score",
    "Action Admissibility Record",
    "Wearable Endpoint Simulator",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def json_response(payload: Dict[str, Any], status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(payload, indent=2, default=str),
        status_code=status_code,
        mimetype="application/json",
    )


def parse_json(req: func.HttpRequest) -> Dict[str, Any]:
    try:
        return req.get_json()
    except ValueError:
        return {}


def required(value: Optional[str], field_name: str) -> Optional[func.HttpResponse]:
    if not value:
        return json_response(
            {
                "error": "missing_required_field",
                "field": field_name,
                "message": f"{field_name} is required.",
            },
            400,
        )
    return None


def storage_account() -> str:
    account = os.environ.get("PLATFORMB_STORAGE_ACCOUNT", "").strip()
    if not account:
        raise RuntimeError("PLATFORMB_STORAGE_ACCOUNT is not configured.")
    return account


def credential() -> DefaultAzureCredential:
    return DefaultAzureCredential(exclude_interactive_browser_credential=False)


def table_service() -> TableServiceClient:
    endpoint = f"https://{storage_account()}.table.core.windows.net"
    return TableServiceClient(endpoint=endpoint, credential=credential())


def blob_service() -> BlobServiceClient:
    account_url = f"https://{storage_account()}.blob.core.windows.net"
    return BlobServiceClient(account_url=account_url, credential=credential())


def table_client(setting_name: str):
    table_name = os.environ.get(setting_name, "").strip()
    if not table_name:
        raise RuntimeError(f"{setting_name} is not configured.")
    return table_service().get_table_client(table_name)


def safe_entity(entity: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = {}
    for key, value in entity.items():
        if value is None:
            cleaned[key] = ""
        elif isinstance(value, (dict, list)):
            cleaned[key] = json.dumps(value, default=str)
        elif isinstance(value, bool):
            cleaned[key] = value
        elif isinstance(value, (int, float)):
            cleaned[key] = value
        else:
            cleaned[key] = str(value)
    return cleaned


def upsert(setting_name: str, entity: Dict[str, Any]) -> Dict[str, Any]:
    client = table_client(setting_name)
    cleaned = safe_entity(entity)
    client.upsert_entity(cleaned)
    return cleaned


def get_entity(setting_name: str, partition_key: str, row_key: str) -> Optional[Dict[str, Any]]:
    client = table_client(setting_name)
    try:
        return dict(client.get_entity(partition_key=partition_key, row_key=row_key))
    except ResourceNotFoundError:
        return None


def query_by_partition(setting_name: str, partition_key: str) -> List[Dict[str, Any]]:
    client = table_client(setting_name)
    query_filter = "PartitionKey eq @partition_key"
    parameters = {"partition_key": partition_key}
    return [dict(item) for item in client.query_entities(query_filter, parameters=parameters)]


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    return json_response(
        {
            "status": "ok",
            "platform": "Platform B MVP",
            "platform_b_v1_frozen": os.environ.get("PLATFORMB_V1_FROZEN", "true"),
            "mode": os.environ.get("PLATFORMB_MODE", "mvp"),
            "mvp_capabilities": MVP_CAPABILITIES,
            "timestamp_utc": utc_now(),
        }
    )


@app.route(route="usecases", methods=["POST"])
def create_use_case(req: func.HttpRequest) -> func.HttpResponse:
    body = parse_json(req)

    name = body.get("name")
    missing = required(name, "name")
    if missing:
        return missing

    lifecycle_stage = body.get("lifecycle_stage", "Governance")
    if lifecycle_stage not in LOCKED_LIFECYCLE:
        return json_response(
            {
                "error": "invalid_lifecycle_stage",
                "allowed_lifecycle": LOCKED_LIFECYCLE,
                "message": "Do not add new lifecycle stages. Platform B v1 lifecycle is frozen.",
            },
            400,
        )

    use_case_id = body.get("use_case_id") or new_id("UC")

    entity = {
        "PartitionKey": "USECASE",
        "RowKey": use_case_id,
        "use_case_id": use_case_id,
        "name": name,
        "owner": body.get("owner", ""),
        "domain": body.get("domain", ""),
        "context_of_use": body.get("context_of_use", ""),
        "risk_class": body.get("risk_class", "unclassified"),
        "lifecycle_stage": lifecycle_stage,
        "status": "registered",
        "created_utc": utc_now(),
        "platform_b_v1_frozen": True,
    }

    upsert("PLATFORMB_USECASE_TABLE", entity)

    return json_response(
        {
            "capability": "AI Use Case Registry",
            "message": "AI use case registered.",
            "record": entity,
        },
        201,
    )


@app.route(route="usecases/{use_case_id}", methods=["GET"])
def get_use_case(req: func.HttpRequest) -> func.HttpResponse:
    use_case_id = req.route_params.get("use_case_id")
    entity = get_entity("PLATFORMB_USECASE_TABLE", "USECASE", use_case_id)

    if not entity:
        return json_response(
            {"error": "not_found", "message": f"Use case not found: {use_case_id}"},
            404,
        )

    return json_response(
        {
            "capability": "AI Use Case Registry",
            "record": entity,
        }
    )


@app.route(route="assurance/check", methods=["POST"])
def assurance_check(req: func.HttpRequest) -> func.HttpResponse:
    body = parse_json(req)

    use_case_id = body.get("use_case_id")
    missing = required(use_case_id, "use_case_id")
    if missing:
        return missing

    check_id = body.get("assurance_check_id") or new_id("CHK")
    evidence_refs = body.get("evidence_refs", [])
    human_review_required = bool(body.get("human_review_required", True))
    control_context = body.get("control_context", "")

    readiness_points = 0
    readiness_points += 25 if control_context else 0
    readiness_points += 25 if evidence_refs else 0
    readiness_points += 25 if human_review_required else 0
    readiness_points += 25 if body.get("check_type") else 0

    status = "assurance_ready_for_review" if readiness_points >= 75 else "trust_evidence_incomplete"

    entity = {
        "PartitionKey": use_case_id,
        "RowKey": check_id,
        "assurance_check_id": check_id,
        "use_case_id": use_case_id,
        "check_type": body.get("check_type", "general_assurance_check"),
        "control_context": control_context,
        "evidence_refs": evidence_refs,
        "human_review_required": human_review_required,
        "readiness_points": readiness_points,
        "status": status,
        "created_utc": utc_now(),
    }

    upsert("PLATFORMB_ASSURANCE_TABLE", entity)

    return json_response(
        {
            "capability": "Assurance Check API",
            "message": "Assurance check recorded.",
            "record": entity,
        },
        201,
    )


@app.route(route="evidence/upload", methods=["POST"])
def evidence_upload(req: func.HttpRequest) -> func.HttpResponse:
    body = parse_json(req)

    use_case_id = body.get("use_case_id")
    missing = required(use_case_id, "use_case_id")
    if missing:
        return missing

    file_name = body.get("file_name")
    missing = required(file_name, "file_name")
    if missing:
        return missing

    content_base64 = body.get("content_base64")
    missing = required(content_base64, "content_base64")
    if missing:
        return missing

    evidence_id = body.get("evidence_id") or new_id("EV")
    content_type = body.get("content_type", "application/octet-stream")

    try:
        content = base64.b64decode(content_base64)
    except Exception:
        return json_response(
            {
                "error": "invalid_base64",
                "message": "content_base64 must be valid base64.",
            },
            400,
        )

    container_name = os.environ.get("PLATFORMB_EVIDENCE_CONTAINER", "evidence-files")
    blob_name = f"{use_case_id}/{evidence_id}/{file_name}"

    blob_client = blob_service().get_blob_client(container=container_name, blob=blob_name)
    blob_client.upload_blob(
        content,
        overwrite=True,
        content_settings=ContentSettings(content_type=content_type),
    )

    entity = {
        "PartitionKey": use_case_id,
        "RowKey": evidence_id,
        "evidence_id": evidence_id,
        "use_case_id": use_case_id,
        "file_name": file_name,
        "content_type": content_type,
        "blob_container": container_name,
        "blob_name": blob_name,
        "size_bytes": len(content),
        "evidence_status": "uploaded",
        "created_utc": utc_now(),
    }

    upsert("PLATFORMB_EVIDENCE_TABLE", entity)

    return json_response(
        {
            "capability": "Evidence Upload",
            "message": "Evidence uploaded and metadata recorded.",
            "record": entity,
        },
        201,
    )


@app.route(route="trust-score/{use_case_id}", methods=["GET"])
def trust_score(req: func.HttpRequest) -> func.HttpResponse:
    use_case_id = req.route_params.get("use_case_id")

    evidence = query_by_partition("PLATFORMB_EVIDENCE_TABLE", use_case_id)
    checks = query_by_partition("PLATFORMB_ASSURANCE_TABLE", use_case_id)
    actions = query_by_partition("PLATFORMB_ACTION_TABLE", use_case_id)
    wearable = query_by_partition("PLATFORMB_WEARABLE_TABLE", use_case_id)

    score = 0
    score += min(len(evidence) * 20, 30)
    score += min(len(checks) * 20, 30)
    score += min(len(actions) * 15, 25)
    score += min(len(wearable) * 5, 15)

    if score >= 80:
        trust_state = "operational_trust_supported"
    elif score >= 50:
        trust_state = "partial_trust_evidence"
    else:
        trust_state = "trust_evidence_insufficient"

    score_id = new_id("TS")
    entity = {
        "PartitionKey": use_case_id,
        "RowKey": score_id,
        "trust_score_id": score_id,
        "use_case_id": use_case_id,
        "score": score,
        "trust_state": trust_state,
        "evidence_count": len(evidence),
        "assurance_check_count": len(checks),
        "action_admissibility_count": len(actions),
        "wearable_signal_count": len(wearable),
        "created_utc": utc_now(),
    }

    upsert("PLATFORMB_TRUST_TABLE", entity)

    return json_response(
        {
            "capability": "Operational Trust Score",
            "message": "Operational trust score calculated.",
            "record": entity,
        }
    )


@app.route(route="action-admissibility", methods=["POST"])
def action_admissibility(req: func.HttpRequest) -> func.HttpResponse:
    body = parse_json(req)

    use_case_id = body.get("use_case_id")
    missing = required(use_case_id, "use_case_id")
    if missing:
        return missing

    action = body.get("action")
    missing = required(action, "action")
    if missing:
        return missing

    record_id = body.get("action_record_id") or new_id("AAR")

    policy_status = str(body.get("policy_status", "")).lower()
    approval_state = str(body.get("approval_state", "")).lower()
    data_lineage_available = bool(body.get("data_lineage_available", False))
    recovery_available = bool(body.get("recovery_available", False))

    admitted = (
        policy_status == "allowed"
        and approval_state in ["approved", "preapproved"]
        and data_lineage_available
        and recovery_available
    )

    entity = {
        "PartitionKey": use_case_id,
        "RowKey": record_id,
        "action_record_id": record_id,
        "use_case_id": use_case_id,
        "actor": body.get("actor", ""),
        "action": action,
        "purpose": body.get("purpose", ""),
        "policy_status": policy_status,
        "approval_state": approval_state,
        "data_lineage_available": data_lineage_available,
        "recovery_available": recovery_available,
        "admitted": admitted,
        "admissibility_state": "admitted_before_execution" if admitted else "blocked_or_requires_review",
        "created_utc": utc_now(),
    }

    upsert("PLATFORMB_ACTION_TABLE", entity)

    return json_response(
        {
            "capability": "Action Admissibility Record",
            "message": "Action admissibility record created.",
            "record": entity,
        },
        201,
    )


@app.route(route="wearable/simulate", methods=["POST"])
def wearable_simulate(req: func.HttpRequest) -> func.HttpResponse:
    body = parse_json(req)

    use_case_id = body.get("use_case_id")
    missing = required(use_case_id, "use_case_id")
    if missing:
        return missing

    signal_id = body.get("wearable_signal_id") or new_id("WRS")
    ppe_detected = bool(body.get("ppe_detected", False))
    fatigue_risk = str(body.get("fatigue_risk", "unknown")).lower()
    restricted_zone = bool(body.get("restricted_zone", False))

    context_assured = ppe_detected and fatigue_risk in ["low", "normal"] and not restricted_zone

    entity = {
        "PartitionKey": use_case_id,
        "RowKey": signal_id,
        "wearable_signal_id": signal_id,
        "use_case_id": use_case_id,
        "operator_id": body.get("operator_id", ""),
        "location_zone": body.get("location_zone", ""),
        "ppe_detected": ppe_detected,
        "fatigue_risk": fatigue_risk,
        "restricted_zone": restricted_zone,
        "context_assured": context_assured,
        "context_assurance_state": "context_assured" if context_assured else "context_not_assured",
        "created_utc": utc_now(),
        "simulated_endpoint": True,
    }

    upsert("PLATFORMB_WEARABLE_TABLE", entity)

    return json_response(
        {
            "capability": "Wearable Endpoint Simulator",
            "message": "Simulated wearable context signal recorded.",
            "record": entity,
        },
        201,
    )
