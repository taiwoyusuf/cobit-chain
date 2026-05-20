from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_RADIOACTIVE_MATERIAL_ACCOUNTABILITY_LEDGER_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Radioactive Material Accountability Ledger already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_RADIOACTIVE_MATERIAL_ACCOUNTABILITY_LEDGER_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Radioactive Material Accountability Ledger™
# Purpose: Govern radioactive material receipt, use, transfer, decay, waste, disposal,
#          reconciliation, evidence integrity, and inspection defensibility.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request
import hashlib
import json
from datetime import datetime

def _rlttrust_rm_num(value, default, minimum=0, maximum=999999):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_rm_int(value, default, minimum=0, maximum=1000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_hash_record(record, previous_hash="GENESIS"):
    payload = dict(record)
    payload["previous_hash"] = previous_hash
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rlttrust_radioactive_material_ledger_data(payload=None):
    payload = payload or {}

    receipt_activity = _rlttrust_rm_num(payload.get("receipt_activity_mci"), 150.0, 0, 100000)
    administered_activity = _rlttrust_rm_num(payload.get("administered_activity_mci"), 108.0, 0, 100000)
    qc_sample_activity = _rlttrust_rm_num(payload.get("qc_sample_activity_mci"), 4.0, 0, 100000)
    waste_activity = _rlttrust_rm_num(payload.get("waste_activity_mci"), 9.5, 0, 100000)
    decay_loss_activity = _rlttrust_rm_num(payload.get("decay_loss_activity_mci"), 26.0, 0, 100000)
    residual_activity = _rlttrust_rm_num(payload.get("residual_activity_mci"), 2.5, 0, 100000)

    missing_evidence = _rlttrust_rm_int(payload.get("missing_evidence"), 2, 0, 100)
    open_exceptions = _rlttrust_rm_int(payload.get("open_exceptions"), 1, 0, 100)
    unreconciled_variance = _rlttrust_rm_num(payload.get("unreconciled_variance_mci"), 0.0, 0, 100000)
    stale_records = _rlttrust_rm_int(payload.get("stale_records"), 1, 0, 100)
    unapproved_transfers = _rlttrust_rm_int(payload.get("unapproved_transfers"), 0, 0, 100)

    accounted_activity = administered_activity + qc_sample_activity + waste_activity + decay_loss_activity + residual_activity
    calculated_variance = round(receipt_activity - accounted_activity, 3)
    total_variance = round(abs(calculated_variance) + unreconciled_variance, 3)

    base_score = 100
    base_score -= min(missing_evidence * 4, 28)
    base_score -= min(open_exceptions * 7, 28)
    base_score -= min(stale_records * 3, 18)
    base_score -= min(unapproved_transfers * 12, 36)
    base_score -= min(total_variance * 1.8, 30)
    accountability_score = max(0, round(base_score))

    if accountability_score >= 90 and open_exceptions == 0 and total_variance <= 0.5:
        ledger_status = "Inspection-Defensible"
        status_class = "ready"
        executive_answer = "Radioactive material accountability appears inspection-defensible, subject to final radiation safety, QA, and human governance review."
    elif accountability_score >= 80:
        ledger_status = "Governed Warning"
        status_class = "warning"
        executive_answer = "Radioactive material accountability is promising but requires evidence closure, reconciliation review, or exception disposition before full confidence."
    elif accountability_score >= 65:
        ledger_status = "At Risk"
        status_class = "gap"
        executive_answer = "Radioactive material accountability has unresolved gaps that could weaken inspection defensibility."
    else:
        ledger_status = "Not Defensible"
        status_class = "blocked"
        executive_answer = "Radioactive material accountability is not currently defensible. Immediate reconciliation and evidence closure are required."

    ledger_events_raw = [
        {
            "event_id": "RM-001",
            "stage": "Receipt",
            "title": "Radioactive Material Receipt",
            "event_type": "Receive",
            "owner": "Radiation Safety / Supply Chain",
            "activity_mci": receipt_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "If receipt evidence is weak, every downstream material movement becomes harder to defend.",
            "evidence": [
                "Supplier certificate",
                "Receipt log",
                "Activity confirmation",
                "Initial custody record"
            ]
        },
        {
            "event_id": "RM-002",
            "stage": "Storage",
            "title": "Controlled Storage / Hot Cell Entry",
            "event_type": "Store",
            "owner": "Manufacturing / Radiation Safety",
            "activity_mci": receipt_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "Storage control gaps can create radioactive material accountability exposure.",
            "evidence": [
                "Controlled storage log",
                "Hot cell entry record",
                "Shielding/location confirmation",
                "Operator accountability"
            ]
        },
        {
            "event_id": "RM-003",
            "stage": "Preparation",
            "title": "Radiolabeling / Dose Preparation",
            "event_type": "Use",
            "owner": "Manufacturing",
            "activity_mci": administered_activity + qc_sample_activity + waste_activity + residual_activity,
            "evidence_status": "Present",
            "status": "Governed Warning",
            "risk": "Preparation evidence must align with batch record, operator training, SOP version, and QC sampling.",
            "evidence": [
                "Batch manufacturing record",
                "Operator role confirmation",
                "SOP version evidence",
                "Equipment readiness"
            ]
        },
        {
            "event_id": "RM-004",
            "stage": "QC Sampling",
            "title": "QC Sample Activity Allocation",
            "event_type": "Sample",
            "owner": "QC",
            "activity_mci": qc_sample_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "QC sample consumption must be reconciled to total received activity.",
            "evidence": [
                "QC sample log",
                "Test request",
                "Result packet",
                "Sample disposition"
            ]
        },
        {
            "event_id": "RM-005",
            "stage": "Release",
            "title": "QA Release / Material Disposition",
            "event_type": "Release",
            "owner": "QA Release",
            "activity_mci": administered_activity,
            "evidence_status": "Warning",
            "status": "Governed Warning",
            "risk": "Release may be approved but weak if radioactive material disposition is not fully reconciled.",
            "evidence": [
                "QA release decision",
                "Release rationale",
                "Deviation/CAPA disposition",
                "Human approval lineage"
            ]
        },
        {
            "event_id": "RM-006",
            "stage": "Transfer",
            "title": "Shipment / Custody Transfer",
            "event_type": "Transfer",
            "owner": "Logistics / Supply Chain",
            "activity_mci": administered_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "Transfer evidence must prove custody and controlled movement.",
            "evidence": [
                "Courier dispatch record",
                "Transfer confirmation",
                "Cold-chain record",
                "Shipment custody record"
            ]
        },
        {
            "event_id": "RM-007",
            "stage": "Receipt at Site",
            "title": "Treatment-Site Receipt",
            "event_type": "Receive",
            "owner": "Treatment Site / Nuclear Medicine",
            "activity_mci": administered_activity,
            "evidence_status": "Warning",
            "status": "Governed Warning",
            "risk": "Treatment-site receipt must align with patient-slot readiness and authorized handling.",
            "evidence": [
                "Site receipt confirmation",
                "Authorized user readiness",
                "Treatment appointment match",
                "Dose-to-slot confirmation"
            ]
        },
        {
            "event_id": "RM-008",
            "stage": "Waste",
            "title": "Residual / Waste Activity Log",
            "event_type": "Waste",
            "owner": "Manufacturing / Radiation Safety",
            "activity_mci": waste_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "Waste activity must be logged and reconciled against original receipt activity.",
            "evidence": [
                "Waste log",
                "Residual activity measurement",
                "Container/location record",
                "Handler attestation"
            ]
        },
        {
            "event_id": "RM-009",
            "stage": "Decay",
            "title": "Decay-in-Storage Accountability",
            "event_type": "Decay",
            "owner": "Radiation Safety",
            "activity_mci": decay_loss_activity,
            "evidence_status": "Present",
            "status": "Complete",
            "risk": "Decay must be explained, time-linked, and reconciled to the radioactive material lifecycle.",
            "evidence": [
                "Decay calculation",
                "Time reference",
                "Storage location evidence",
                "Radiation safety review"
            ]
        },
        {
            "event_id": "RM-010",
            "stage": "Residual",
            "title": "Residual Activity Closure",
            "event_type": "Residual",
            "owner": "Radiation Safety / QA",
            "activity_mci": residual_activity,
            "evidence_status": "Warning",
            "status": "Governed Warning",
            "risk": "Residual activity must be dispositioned before final reconciliation closes.",
            "evidence": [
                "Residual measurement",
                "Disposition decision",
                "Closure approval",
                "Reconciliation attachment"
            ]
        },
        {
            "event_id": "RM-011",
            "stage": "Reconciliation",
            "title": "Final Material Reconciliation",
            "event_type": "Reconcile",
            "owner": "Radiation Safety / QA / Compliance",
            "activity_mci": total_variance,
            "evidence_status": "Warning" if total_variance > 0.5 or missing_evidence > 0 else "Present",
            "status": "At Risk" if total_variance > 2 or missing_evidence > 2 else "Governed Warning",
            "risk": "Final reconciliation must explain all received, used, transferred, wasted, decayed, residual, and disposed material.",
            "evidence": [
                "Final reconciliation worksheet",
                "Variance explanation",
                "QA/radiation safety approval",
                "AuditVault™ verification"
            ]
        }
    ]

    previous_hash = "GENESIS"
    ledger_events = []
    for event in ledger_events_raw:
        event_hash = _rlttrust_hash_record(event, previous_hash)
        event["previous_hash"] = previous_hash
        event["record_hash"] = event_hash
        event["short_hash"] = event_hash[:14]
        previous_hash = event_hash
        ledger_events.append(event)

    red_flags = []
    if missing_evidence > 0:
        red_flags.append({
            "flag": "Missing evidence",
            "impact": f"{missing_evidence} evidence item(s) missing from the material accountability file.",
            "action": "Upload, hash, and link missing evidence into AuditVault™."
        })
    if open_exceptions > 0:
        red_flags.append({
            "flag": "Open exception",
            "impact": f"{open_exceptions} radioactive material exception(s) remain open.",
            "action": "Assign owner and close exception with QA/radiation safety disposition."
        })
    if stale_records > 0:
        red_flags.append({
            "flag": "Stale record",
            "impact": f"{stale_records} material record(s) may no longer reflect current status.",
            "action": "Refresh stale records and rerun Evidence Expiry Engine™."
        })
    if unapproved_transfers > 0:
        red_flags.append({
            "flag": "Unapproved transfer",
            "impact": f"{unapproved_transfers} transfer(s) lack complete approval lineage.",
            "action": "Resolve transfer approval lineage and regenerate custody packet."
        })
    if total_variance > 0.5:
        red_flags.append({
            "flag": "Reconciliation variance",
            "impact": f"{total_variance} mCi remains unexplained or outside expected tolerance.",
            "action": "Reconcile received, administered, sampled, wasted, decayed, residual, and transferred activity."
        })

    if not red_flags:
        red_flags.append({
            "flag": "No critical material accountability flags",
            "impact": "Ledger appears stable under this scenario.",
            "action": "Proceed to final human governance review and passport generation."
        })

    inspector_questions = [
        {
            "persona": "Radiation Safety Reviewer",
            "question": "Can you prove receipt, storage, handling, use, transfer, decay, waste, and final reconciliation?",
            "best_evidence": "Radioactive Material Accountability Ledger™, receipt log, storage log, use record, transfer record, decay calculation, waste log, final reconciliation.",
            "readiness": "Strong" if accountability_score >= 88 else "Warning"
        },
        {
            "persona": "QA / GMP Inspector",
            "question": "Can you prove radioactive material disposition supports batch release defensibility?",
            "best_evidence": "QA release rationale, material disposition packet, deviation/CAPA disposition, batch record linkage, AuditVault™ verification.",
            "readiness": "Strong" if accountability_score >= 85 and missing_evidence <= 1 else "Warning"
        },
        {
            "persona": "Data Integrity Reviewer",
            "question": "Can you prove the material record was not altered or disconnected from approvals?",
            "best_evidence": "Hash chain, previous-hash linkage, approval lineage, evidence timestamps, system-owner/radiation safety attestation.",
            "readiness": "Strong" if evidence_integrity if 'evidence_integrity' in payload else True else "Warning"
        },
        {
            "persona": "Commercial Readiness Leader",
            "question": "Can leadership trust that material accountability will survive inspection tomorrow?",
            "best_evidence": "Ledger score, reconciliation status, red-flag closure, Governance Passport™, Inspection Tomorrow Simulator™.",
            "readiness": "Strong" if accountability_score >= 90 else "Warning"
        }
    ]

    # Correct any overly optimistic data-integrity readiness using the calculated score.
    inspector_questions[2]["readiness"] = "Strong" if accountability_score >= 85 and missing_evidence <= 1 and stale_records <= 1 else "Warning"

    reconciliation = {
        "receipt_activity_mci": round(receipt_activity, 3),
        "administered_activity_mci": round(administered_activity, 3),
        "qc_sample_activity_mci": round(qc_sample_activity, 3),
        "waste_activity_mci": round(waste_activity, 3),
        "decay_loss_activity_mci": round(decay_loss_activity, 3),
        "residual_activity_mci": round(residual_activity, 3),
        "accounted_activity_mci": round(accounted_activity, 3),
        "calculated_variance_mci": calculated_variance,
        "unreconciled_variance_mci": round(unreconciled_variance, 3),
        "total_variance_mci": total_variance
    }

    passport_outputs = [
        "Radioactive Material Accountability Passport",
        "Material Receipt and Use Passport",
        "Waste / Decay / Disposal Passport",
        "Transfer and Custody Passport",
        "Final Reconciliation Passport",
        "Inspection Evidence Packet"
    ]

    return {
        "accountability_score": accountability_score,
        "ledger_status": ledger_status,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "ledger_events": ledger_events,
        "red_flags": red_flags,
        "inspector_questions": inspector_questions,
        "reconciliation": reconciliation,
        "passport_outputs": passport_outputs,
        "inputs": {
            "receipt_activity_mci": receipt_activity,
            "administered_activity_mci": administered_activity,
            "qc_sample_activity_mci": qc_sample_activity,
            "waste_activity_mci": waste_activity,
            "decay_loss_activity_mci": decay_loss_activity,
            "residual_activity_mci": residual_activity,
            "missing_evidence": missing_evidence,
            "open_exceptions": open_exceptions,
            "unreconciled_variance_mci": unreconciled_variance,
            "stale_records": stale_records,
            "unapproved_transfers": unapproved_transfers
        },
        "governance_note": "This ledger is a governance assurance overlay. It does not replace radiation safety systems, LIMS, MES, ERP, Veeva, ServiceNow, shipping platforms, or required human review."
    }


@app.route("/irlt-commercial-readiness/radioactive-material-ledger")
@app.route("/rlttrust/radioactive-material-ledger")
@app.route("/rlttrust/material-accountability")
def rlttrust_radioactive_material_accountability_ledger():
    payload = {
        "receipt_activity_mci": request.args.get("receipt_activity_mci", 150),
        "administered_activity_mci": request.args.get("administered_activity_mci", 108),
        "qc_sample_activity_mci": request.args.get("qc_sample_activity_mci", 4),
        "waste_activity_mci": request.args.get("waste_activity_mci", 9.5),
        "decay_loss_activity_mci": request.args.get("decay_loss_activity_mci", 26),
        "residual_activity_mci": request.args.get("residual_activity_mci", 2.5),
        "missing_evidence": request.args.get("missing_evidence", 2),
        "open_exceptions": request.args.get("open_exceptions", 1),
        "unreconciled_variance_mci": request.args.get("unreconciled_variance_mci", 0),
        "stale_records": request.args.get("stale_records", 1),
        "unapproved_transfers": request.args.get("unapproved_transfers", 0),
    }

    data = _rlttrust_radioactive_material_ledger_data(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Radioactive Material Accountability Ledger™ | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --charcoal: #07080c;
                --graphite: #151922;
                --panel: rgba(20, 24, 33, 0.88);
                --line: rgba(255,255,255,0.12);
                --text: #f4f7fb;
                --muted: #aeb6c6;
                --green: #37d67a;
                --red: #ff5c7a;
            }

            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.24), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.16), transparent 34%),
                    radial-gradient(circle at 50% 32%, rgba(255,255,255,0.055), transparent 30%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1900px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero {
                position: relative;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.32);
                border-radius: 36px;
                padding: 36px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.20), rgba(20,24,33,0.93) 38%, rgba(7,8,12,0.96)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 76px);
                box-shadow: 0 34px 120px rgba(0,0,0,0.56);
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -150px;
                top: -190px;
                width: 600px;
                height: 600px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.25);
                box-shadow: inset 0 0 80px rgba(255,122,24,0.10), 0 0 100px rgba(255,122,24,0.12);
            }

            .hero-grid {
                position: relative;
                z-index: 2;
                display: grid;
                grid-template-columns: minmax(0, 1.65fr) minmax(380px, 0.72fr);
                gap: 30px;
                align-items: stretch;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .16em;
                font-weight: 950;
                text-shadow: 0 0 18px rgba(255,122,24,0.28);
            }

            h1 {
                margin: 12px 0;
                font-size: clamp(42px, 4.8vw, 84px);
                line-height: .92;
                letter-spacing: -.06em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 36px);
                letter-spacing: -.03em;
                margin: 0 0 16px;
            }

            h3 {
                margin: 0 0 8px;
                letter-spacing: -.02em;
            }

            p {
                color: var(--muted);
                line-height: 1.55;
            }

            .score-card {
                border-radius: 30px;
                padding: 26px;
                background: linear-gradient(180deg, rgba(255,122,24,0.12), rgba(15,18,26,0.92));
                border: 1px solid rgba(255,122,24,0.34);
                box-shadow: 0 22px 80px rgba(0,0,0,0.42);
            }

            .score {
                font-size: clamp(76px, 7vw, 132px);
                line-height: .85;
                font-weight: 950;
                letter-spacing: -.07em;
                color: var(--orange2);
                text-shadow: 0 0 35px rgba(255,122,24,0.34);
                margin: 18px 0;
            }

            .status-pill {
                display: inline-block;
                padding: 10px 14px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: 950;
                text-transform: uppercase;
                letter-spacing: .08em;
            }

            .ready {
                background: rgba(55,214,122,0.12);
                border: 1px solid rgba(55,214,122,0.40);
                color: #b9ffd0;
            }

            .warning, .gap {
                background: rgba(255,209,102,0.12);
                border: 1px solid rgba(255,209,102,0.40);
                color: #ffe6a8;
            }

            .blocked {
                background: rgba(255,92,122,0.12);
                border: 1px solid rgba(255,92,122,0.40);
                color: #ffc2c2;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }

            .nav a {
                text-decoration: none;
                color: #f4f7fb;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,122,24,0.25);
                transition: transform .18s ease, border-color .18s ease, background .18s ease;
            }

            .nav a:hover {
                transform: translateY(-2px);
                border-color: rgba(255,122,24,0.72);
                background: rgba(255,122,24,0.13);
            }

            .section {
                margin-top: 32px;
            }

            .grid {
                display: grid;
                grid-template-columns: minmax(420px, .55fr) minmax(0, 1fr);
                gap: 22px;
                align-items: start;
            }

            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 18px;
            }

            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 16px;
            }

            .panel, .form-panel, .metric, .event-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .metric strong {
                display: block;
                font-size: 32px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 8px;
            }

            .metric span {
                color: var(--muted);
                font-size: 13px;
            }

            label {
                display: block;
                color: #d8dde8;
                font-weight: 850;
                font-size: 12px;
                margin-bottom: 7px;
            }

            input {
                width: 100%;
                box-sizing: border-box;
                border: 1px solid rgba(255,122,24,0.25);
                background: rgba(5,6,8,0.72);
                color: white;
                border-radius: 14px;
                padding: 11px 12px;
                font-size: 14px;
                outline: none;
            }

            .form-grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 14px;
            }

            .button {
                margin-top: 18px;
                width: 100%;
                border: 0;
                border-radius: 18px;
                padding: 14px 16px;
                font-weight: 950;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                cursor: pointer;
                box-shadow: 0 16px 45px rgba(255,122,24,0.26);
            }

            .ledger-flow {
                display: grid;
                grid-template-columns: repeat(11, minmax(210px, 1fr));
                gap: 14px;
                overflow-x: auto;
                padding-bottom: 8px;
            }

            .event-card {
                position: relative;
                min-height: 370px;
            }

            .event-card:after {
                content: "→";
                position: absolute;
                right: -20px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--orange2);
                font-size: 32px;
                font-weight: 950;
                text-shadow: 0 0 20px rgba(255,122,24,0.40);
                z-index: 5;
            }

            .event-card:last-child:after {
                display: none;
            }

            .event-id {
                color: #ffd7ad;
                font-size: 11px;
                font-weight: 950;
                letter-spacing: .11em;
                text-transform: uppercase;
            }

            .stage {
                display: inline-block;
                margin: 10px 0;
                padding: 7px 10px;
                border-radius: 999px;
                color: #fff2e6;
                background: rgba(255,122,24,0.12);
                border: 1px solid rgba(255,122,24,0.30);
                font-size: 11px;
                font-weight: 900;
            }

            .hash {
                display: block;
                margin-top: 10px;
                color: #ffd7ad;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
                overflow-wrap: anywhere;
            }

            ul {
                margin: 10px 0 0 20px;
                padding: 0;
                color: var(--muted);
                line-height: 1.6;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                overflow: hidden;
                border-radius: 24px;
                background: rgba(20,24,33,0.88);
                border: 1px solid rgba(255,255,255,0.12);
            }

            th, td {
                padding: 15px;
                border-bottom: 1px solid rgba(255,255,255,0.10);
                text-align: left;
                vertical-align: top;
                color: var(--muted);
                font-size: 14px;
            }

            th {
                color: #fff2e6;
                background: rgba(255,122,24,0.10);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: .09em;
            }

            td strong {
                color: #fff2e6;
            }

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            .passport {
                display: inline-block;
                margin: 6px;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(255,122,24,0.10);
                border: 1px solid rgba(255,122,24,0.32);
                color: #ffd7ad;
                font-weight: 850;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid, .grid-2, .grid-3, .form-grid {
                    grid-template-columns: 1fr;
                }
                .wrap {
                    padding: 24px;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">RLTTrust™ Radiopharma-Specific Governance</div>
                        <h1>Radioactive Material Accountability Ledger™</h1>
                        <p>
                            A governed ledger for radioactive material receipt, controlled storage, preparation, QC sampling,
                            release, transfer, treatment-site receipt, waste, decay, residual activity, disposal, and final reconciliation.
                        </p>
                        <p>
                            This makes RLTTrust™ more than a readiness dashboard. It becomes a defensible material accountability layer
                            for commercial IRLT operations.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/passport">Governance Passport</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Material Accountability Score</div>
                        <div class="score">{{ data.accountability_score }}%</div>
                        <span class="status-pill {{ data.status_class }}">{{ data.ledger_status }}</span>
                        <p>{{ data.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Material Reconciliation Inputs</h2>
                    <p>Adjust the material-accountability scenario and recalculate the ledger defensibility.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Receipt Activity mCi</label><input name="receipt_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.receipt_activity_mci }}"></div>
                            <div><label>Administered / Released Activity mCi</label><input name="administered_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.administered_activity_mci }}"></div>
                            <div><label>QC Sample Activity mCi</label><input name="qc_sample_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.qc_sample_activity_mci }}"></div>
                            <div><label>Waste Activity mCi</label><input name="waste_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.waste_activity_mci }}"></div>
                            <div><label>Decay Loss Activity mCi</label><input name="decay_loss_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.decay_loss_activity_mci }}"></div>
                            <div><label>Residual Activity mCi</label><input name="residual_activity_mci" type="number" step="0.1" min="0" value="{{ data.inputs.residual_activity_mci }}"></div>
                            <div><label>Missing Evidence Items</label><input name="missing_evidence" type="number" min="0" value="{{ data.inputs.missing_evidence }}"></div>
                            <div><label>Open Exceptions</label><input name="open_exceptions" type="number" min="0" value="{{ data.inputs.open_exceptions }}"></div>
                            <div><label>Unreconciled Variance mCi</label><input name="unreconciled_variance_mci" type="number" step="0.1" min="0" value="{{ data.inputs.unreconciled_variance_mci }}"></div>
                            <div><label>Stale Records</label><input name="stale_records" type="number" min="0" value="{{ data.inputs.stale_records }}"></div>
                            <div><label>Unapproved Transfers</label><input name="unapproved_transfers" type="number" min="0" value="{{ data.inputs.unapproved_transfers }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Material Accountability</button>
                    </form>
                </div>

                <div>
                    <h2>Reconciliation Summary</h2>
                    <div class="grid-3">
                        <div class="metric"><strong>{{ data.reconciliation.receipt_activity_mci }}</strong><span>Received mCi</span></div>
                        <div class="metric"><strong>{{ data.reconciliation.accounted_activity_mci }}</strong><span>Accounted mCi</span></div>
                        <div class="metric"><strong>{{ data.reconciliation.total_variance_mci }}</strong><span>Total Variance mCi</span></div>
                        <div class="metric"><strong>{{ data.reconciliation.administered_activity_mci }}</strong><span>Administered / Released mCi</span></div>
                        <div class="metric"><strong>{{ data.reconciliation.waste_activity_mci }}</strong><span>Waste mCi</span></div>
                        <div class="metric"><strong>{{ data.reconciliation.decay_loss_activity_mci }}</strong><span>Decay Loss mCi</span></div>
                    </div>

                    <div class="panel" style="margin-top:18px;">
                        <h2>Red Flags</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Flag</th>
                                    <th>Impact</th>
                                    <th>Required Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for flag in data.red_flags %}
                                <tr>
                                    <td><strong>{{ flag.flag }}</strong></td>
                                    <td>{{ flag.impact }}</td>
                                    <td>{{ flag.action }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">Hash-Chained Accountability Timeline</div>
                    <h2>Receipt → Use → Transfer → Waste → Decay → Reconciliation</h2>
                    <p>
                        Each ledger event includes a simulated record hash and previous-hash link.
                        This demonstrates how AuditVault™ can make radioactive material accountability tamper-evident.
                    </p>

                    <div class="ledger-flow">
                        {% for event in data.ledger_events %}
                        <div class="event-card">
                            <div class="event-id">{{ event.event_id }}</div>
                            <span class="stage">{{ event.stage }}</span>
                            <h3>{{ event.title }}</h3>
                            <p><strong style="color:#fff2e6;">Type:</strong> {{ event.event_type }}</p>
                            <p><strong style="color:#fff2e6;">Owner:</strong> {{ event.owner }}</p>
                            <p><strong style="color:#fff2e6;">Activity:</strong> {{ event.activity_mci }} mCi</p>
                            <p><strong style="color:#fff2e6;">Status:</strong> {{ event.status }}</p>
                            <p><strong style="color:#fff2e6;">Risk:</strong> {{ event.risk }}</p>
                            <h4>Evidence</h4>
                            <ul>
                                {% for item in event.evidence %}
                                <li>{{ item }}</li>
                                {% endfor %}
                            </ul>
                            <span class="hash">Hash: {{ event.short_hash }}</span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Inspector Question-to-Evidence Mapping™</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Persona</th>
                                <th>Question</th>
                                <th>Best Evidence</th>
                                <th>Readiness</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in data.inspector_questions %}
                            <tr>
                                <td><strong>{{ q.persona }}</strong></td>
                                <td>{{ q.question }}</td>
                                <td>{{ q.best_evidence }}</td>
                                <td>{{ q.readiness }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Passport Outputs</h2>
                    <p>These are the leadership and inspection artifacts this ledger can generate.</p>
                    {% for p in data.passport_outputs %}
                    <span class="passport">{{ p }}</span>
                    {% endfor %}
                    <div class="note">{{ data.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, data=data)


@app.route("/irlt-commercial-readiness/radioactive-material-ledger/api")
@app.route("/rlttrust/radioactive-material-ledger/api")
@app.route("/rlttrust/material-accountability/api")
def rlttrust_radioactive_material_accountability_ledger_api():
    payload = {
        "receipt_activity_mci": request.args.get("receipt_activity_mci", 150),
        "administered_activity_mci": request.args.get("administered_activity_mci", 108),
        "qc_sample_activity_mci": request.args.get("qc_sample_activity_mci", 4),
        "waste_activity_mci": request.args.get("waste_activity_mci", 9.5),
        "decay_loss_activity_mci": request.args.get("decay_loss_activity_mci", 26),
        "residual_activity_mci": request.args.get("residual_activity_mci", 2.5),
        "missing_evidence": request.args.get("missing_evidence", 2),
        "open_exceptions": request.args.get("open_exceptions", 1),
        "unreconciled_variance_mci": request.args.get("unreconciled_variance_mci", 0),
        "stale_records": request.args.get("stale_records", 1),
        "unapproved_transfers": request.args.get("unapproved_transfers", 0),
    }
    return jsonify(_rlttrust_radioactive_material_ledger_data(payload))

# ============================================================
# End Radioactive Material Accountability Ledger™
# ============================================================

'''

    # Add Radioactive Material Ledger link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_RADIOACTIVE_MATERIAL_LEDGER_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_RADIOACTIVE_MATERIAL_LEDGER_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>',
            1
        )
        print("Added Radioactive Material Ledger link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Radioactive Material Accountability Ledger successfully.")

