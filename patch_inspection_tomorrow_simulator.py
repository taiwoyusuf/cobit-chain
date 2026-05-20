from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_INSPECTION_TOMORROW_SIMULATOR_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Inspection Tomorrow Simulator already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_INSPECTION_TOMORROW_SIMULATOR_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Inspection Tomorrow Simulator™
# Purpose: Simulate inspection survivability for commercial IRLT readiness.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_inspection_num(value, default, minimum=0, maximum=100):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_inspection_int(value, default, minimum=0, maximum=100):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_inspection_tomorrow_assessment(payload=None):
    payload = payload or {}

    qa_release = _rlttrust_inspection_num(payload.get("qa_release"), 78)
    qc_packet = _rlttrust_inspection_num(payload.get("qc_packet"), 84)
    batch_record = _rlttrust_inspection_num(payload.get("batch_record"), 86)
    em_readiness = _rlttrust_inspection_num(payload.get("em_readiness"), 76)
    capa_closure = _rlttrust_inspection_num(payload.get("capa_closure"), 74)
    sop_training = _rlttrust_inspection_num(payload.get("sop_training"), 84)
    access_review = _rlttrust_inspection_num(payload.get("access_review"), 80)
    custody_trace = _rlttrust_inspection_num(payload.get("custody_trace"), 86)
    material_accountability = _rlttrust_inspection_num(payload.get("material_accountability"), 79)
    evidence_integrity = _rlttrust_inspection_num(payload.get("evidence_integrity"), 91)
    backup_restore = _rlttrust_inspection_num(payload.get("backup_restore"), 88)
    treatment_coordination = _rlttrust_inspection_num(payload.get("treatment_coordination"), 81)
    passport_completeness = _rlttrust_inspection_num(payload.get("passport_completeness"), 83)
    data_integrity = _rlttrust_inspection_num(payload.get("data_integrity"), 87)

    missing_evidence = _rlttrust_inspection_int(payload.get("missing_evidence"), 3, 0, 50)
    stale_evidence = _rlttrust_inspection_int(payload.get("stale_evidence"), 4, 0, 50)
    open_critical_capa = _rlttrust_inspection_int(payload.get("open_critical_capa"), 1, 0, 20)
    open_em_exceptions = _rlttrust_inspection_int(payload.get("open_em_exceptions"), 1, 0, 20)
    custody_breaks = _rlttrust_inspection_int(payload.get("custody_breaks"), 0, 0, 20)
    material_recon_gaps = _rlttrust_inspection_int(payload.get("material_recon_gaps"), 1, 0, 20)
    unapproved_changes = _rlttrust_inspection_int(payload.get("unapproved_changes"), 0, 0, 20)

    evidence_penalty = min((missing_evidence * 3) + (stale_evidence * 2), 35)
    capa_penalty = min(open_critical_capa * 8, 30)
    em_penalty = min(open_em_exceptions * 7, 28)
    custody_penalty = min(custody_breaks * 12, 36)
    material_penalty = min(material_recon_gaps * 8, 32)
    change_penalty = min(unapproved_changes * 10, 30)

    evidence_survivability = max(0, evidence_integrity - evidence_penalty)
    deviation_survivability = max(0, ((capa_closure + em_readiness) / 2) - capa_penalty - em_penalty)
    custody_survivability = max(0, custody_trace - custody_penalty)
    material_survivability = max(0, material_accountability - material_penalty)
    data_survivability = max(0, data_integrity - change_penalty)

    inspection_score = round(
        qa_release * 0.12 +
        qc_packet * 0.10 +
        batch_record * 0.09 +
        deviation_survivability * 0.12 +
        sop_training * 0.08 +
        access_review * 0.07 +
        custody_survivability * 0.10 +
        material_survivability * 0.10 +
        evidence_survivability * 0.11 +
        backup_restore * 0.05 +
        treatment_coordination * 0.05 +
        passport_completeness * 0.06 +
        data_survivability * 0.05
    )

    findings = []

    def add_finding(area, severity, finding, evidence_gap, business_impact, corrective_action, engine):
        severity_class = "critical" if severity == "Critical" else "major" if severity == "Major" else "minor"
        findings.append({
            "area": area,
            "severity": severity,
            "severity_class": severity_class,
            "finding": finding,
            "evidence_gap": evidence_gap,
            "business_impact": business_impact,
            "corrective_action": corrective_action,
            "engine": engine
        })

    if qa_release < 80:
        add_finding(
            "QA Release",
            "Major",
            "Release decision may not be fully defensible under inspection questioning.",
            "QA release rationale, dependency disposition, and final human approval lineage need strengthening.",
            "Commercial release confidence could be challenged.",
            "Run Release Defensibility Engine™ and require QA release rationale packet.",
            "Release Defensibility Engine™"
        )

    if qc_packet < 80:
        add_finding(
            "QC Readiness",
            "Major",
            "QC evidence packet may be incomplete or difficult to defend.",
            "QC method readiness, result approval, and exception review are not fully connected.",
            "QC release timing could affect isotope usability and QA confidence.",
            "Create QC readiness packet and link it to QA release.",
            "QC Readiness Governance"
        )

    if em_readiness < 80 or open_em_exceptions > 0:
        add_finding(
            "Environmental Monitoring",
            "Major" if open_em_exceptions <= 1 else "Critical",
            "Environmental monitoring exception may affect release defensibility.",
            "EM exception assessment and QA impact review are not fully closed.",
            "Batch release may be delayed, blocked, or weakened under inspection.",
            "Link EM exception to CAPATrust™ and QA impact disposition.",
            "CAPATrust™"
        )

    if capa_closure < 80 or open_critical_capa > 0:
        add_finding(
            "Deviation / CAPA",
            "Major" if open_critical_capa <= 1 else "Critical",
            "Open or weak CAPA/deviation closure may create inspection exposure.",
            "CAPA closure evidence, effectiveness check, or dependency mapping is incomplete.",
            "Auditor may challenge whether the operation is commercially ready.",
            "Run CAPATrust™ closure defensibility review.",
            "CAPATrust™"
        )

    if sop_training < 82:
        add_finding(
            "SOP / Training",
            "Major",
            "Operator training may not be fully aligned to effective SOP versions.",
            "Training evidence is not fully linked to current SOPs and execution roles.",
            "Inspection may identify training-to-SOP drift.",
            "Run SOPTrust™ drift and training alignment check.",
            "SOPTrust™"
        )

    if access_review < 82:
        add_finding(
            "Access Governance",
            "Minor",
            "Access review may need stronger owner attestation.",
            "Role appropriateness, privileged access, or orphaned access evidence may be incomplete.",
            "Audit trail accountability may be challenged.",
            "Run AccessTrust™ owner attestation and privileged access review.",
            "AccessTrust™"
        )

    if custody_trace < 82 or custody_breaks > 0:
        add_finding(
            "Chain of Custody",
            "Major" if custody_breaks <= 1 else "Critical",
            "Custody traceability may not fully survive inspection.",
            "Custody transfer, courier dispatch, cold-chain, or receipt confirmation needs stronger linkage.",
            "Dose journey defensibility may be weakened.",
            "Generate shipment custody evidence packet and link to Dose Journey Passport.",
            "Isotope-to-Patient Evidence Graph™"
        )

    if material_accountability < 82 or material_recon_gaps > 0:
        add_finding(
            "Radioactive Material Accountability",
            "Major" if material_recon_gaps <= 1 else "Critical",
            "Radioactive material reconciliation may not be fully defensible.",
            "Receipt, use, waste, decay, transfer, disposal, or reconciliation evidence is incomplete.",
            "Radiation safety and controlled-material governance may be challenged.",
            "Run Radioactive Material Accountability Ledger™ reconciliation.",
            "Radioactive Material Accountability Ledger™"
        )

    if evidence_survivability < 82 or missing_evidence > 0 or stale_evidence > 2:
        add_finding(
            "Evidence Survivability",
            "Major",
            "Evidence may exist but may be missing, stale, scattered, or difficult to retrieve.",
            "Evidence packets are not fully current, linked, or passported.",
            "Inspection response may become manual, slow, and inconsistent.",
            "Run AuditVault™ verification and Evidence Expiry Engine™.",
            "AuditVault™"
        )

    if data_survivability < 82 or unapproved_changes > 0:
        add_finding(
            "Data Integrity / Change Governance",
            "Major" if unapproved_changes <= 1 else "Critical",
            "Unapproved change or weak data-governance linkage may reduce data integrity confidence.",
            "Change approval evidence, audit trail, or system-owner approval lineage is incomplete.",
            "Data integrity challenge could escalate into broader compliance risk.",
            "Link change evidence, system-owner approval, and audit trail into AuditVault™.",
            "AuditVault™ + AccessTrust™"
        )

    if treatment_coordination < 80:
        add_finding(
            "Treatment Coordination",
            "Major",
            "Treatment-site readiness may not be fully aligned to dose availability.",
            "Receipt readiness, patient slot, authorized user readiness, or treatment coordination evidence is incomplete.",
            "A technically released dose could still fail operationally.",
            "Run Patient Slot Protection Engine™ and treatment-site readiness attestation.",
            "Patient Slot Protection Engine™"
        )

    if passport_completeness < 85:
        add_finding(
            "Governance Passport",
            "Minor",
            "Dose Journey Passport is not fully complete.",
            "End-to-end readiness evidence has not been packaged into one defensible artifact.",
            "Leadership may lack a single commercial-readiness record.",
            "Generate Dose Journey Passport and Commercial Readiness Passport.",
            "Governance Passport™"
        )

    critical_count = sum(1 for f in findings if f["severity"] == "Critical")
    major_count = sum(1 for f in findings if f["severity"] == "Major")
    minor_count = sum(1 for f in findings if f["severity"] == "Minor")

    if critical_count > 0:
        verdict = "NO — critical inspection exposure"
        verdict_class = "blocked"
        executive_answer = "The operation should not be represented as inspection-ready tomorrow. Critical exposure remains and requires human-governed closure."
    elif inspection_score >= 90 and major_count == 0:
        verdict = "YES — inspection-defensible"
        verdict_class = "ready"
        executive_answer = "The operation appears inspection-defensible, subject to final QA, compliance, system-owner, and leadership review."
    elif inspection_score >= 82 and major_count <= 2:
        verdict = "YES — but with inspection warnings"
        verdict_class = "warning"
        executive_answer = "The operation may survive inspection, but leadership should close warnings before commercial confidence is claimed."
    elif inspection_score >= 70:
        verdict = "NO — evidence gaps remain"
        verdict_class = "gap"
        executive_answer = "The operation has enough structure to improve quickly, but evidence gaps and unresolved dependencies prevent full inspection defensibility."
    else:
        verdict = "NO — not inspection-survivable"
        verdict_class = "blocked"
        executive_answer = "The operation is not ready for an inspection tomorrow under a defensible governance posture."

    inspector_questions = [
        {
            "persona": "FDA / GMP Inspector",
            "question": "Show me the evidence that this batch was manufactured, tested, reviewed, and released under controlled procedures.",
            "best_evidence": "Batch record, QC packet, QA release rationale, SOP/training packet, deviation/CAPA disposition, AuditVault™ verification.",
            "readiness": "Strong" if min(batch_record, qc_packet, qa_release, sop_training) >= 85 else "Warning"
        },
        {
            "persona": "Radiation Safety / NRC-style Review",
            "question": "Show me how radioactive material was received, used, transferred, decayed, wasted, disposed, and reconciled.",
            "best_evidence": "Radioactive Material Accountability Ledger™, receipt log, use record, waste/decay/disposal evidence, reconciliation signoff.",
            "readiness": "Strong" if material_survivability >= 85 else "Warning"
        },
        {
            "persona": "QA Auditor",
            "question": "Show me why release was defensible despite timing pressure, EM exceptions, or open dependencies.",
            "best_evidence": "Release Defensibility Engine™ output, QA rationale, EM review, CAPA disposition, human approval lineage.",
            "readiness": "Strong" if qa_release >= 85 and deviation_survivability >= 85 else "Warning"
        },
        {
            "persona": "Data Integrity Reviewer",
            "question": "Show me that evidence was not altered, stale, missing, or disconnected from the approved process.",
            "best_evidence": "AuditVault™ hash verification, evidence expiry results, approval lineage, system-owner attestation.",
            "readiness": "Strong" if evidence_survivability >= 88 and data_survivability >= 85 else "Warning"
        },
        {
            "persona": "Commercial Readiness Leader",
            "question": "Can we operationally defend treatment readiness tomorrow?",
            "best_evidence": "Can We Treat Tomorrow? Engine™, Dose Journey Passport, Isotope-to-Patient Evidence Graph™, risk closure plan.",
            "readiness": "Strong" if inspection_score >= 88 else "Warning"
        }
    ]

    survivability_domains = [
        {"name": "QA Release", "score": round(qa_release), "description": "Release rationale, approval lineage, dependency disposition."},
        {"name": "QC Packet", "score": round(qc_packet), "description": "QC results, method readiness, exception review."},
        {"name": "Batch Record", "score": round(batch_record), "description": "Manufacturing record, operator accountability, equipment readiness."},
        {"name": "Deviation / EM", "score": round(deviation_survivability), "description": "CAPA closure, EM exception review, QA impact disposition."},
        {"name": "SOP / Training", "score": round(sop_training), "description": "Effective SOP alignment and operator readiness."},
        {"name": "Access Review", "score": round(access_review), "description": "Role appropriateness, privileged access, owner attestation."},
        {"name": "Custody Trace", "score": round(custody_survivability), "description": "Shipment, courier, cold-chain, receipt confirmation."},
        {"name": "Material Accountability", "score": round(material_survivability), "description": "Radioactive material receipt, use, waste, decay, disposal, reconciliation."},
        {"name": "Evidence Integrity", "score": round(evidence_survivability), "description": "Hash verification, freshness, completeness, retrievability."},
        {"name": "Backup / Restore", "score": round(backup_restore), "description": "Continuity evidence and restore defensibility."},
        {"name": "Treatment Coordination", "score": round(treatment_coordination), "description": "Patient slot readiness and treatment-site confirmation."},
        {"name": "Passport Completeness", "score": round(passport_completeness), "description": "Dose Journey Passport and Commercial Readiness Passport completeness."},
        {"name": "Data Integrity", "score": round(data_survivability), "description": "Change governance, audit trail trust, system-owner approval lineage."}
    ]

    top_actions = []
    if critical_count > 0:
        top_actions.append("Open executive inspection war-room immediately and assign owners to all critical findings.")
    if major_count > 0:
        top_actions.append("Close major findings before claiming commercial inspection readiness.")
    if missing_evidence > 0:
        top_actions.append("Retrieve, upload, hash, and link missing evidence into AuditVault™.")
    if stale_evidence > 0:
        top_actions.append("Refresh stale evidence and rerun Evidence Expiry Engine™.")
    if open_critical_capa > 0:
        top_actions.append("Complete CAPATrust™ closure defensibility review for open CAPA/deviation dependencies.")
    if open_em_exceptions > 0:
        top_actions.append("Complete EM impact review and QA disposition before release confidence improves.")
    if material_recon_gaps > 0:
        top_actions.append("Reconcile radioactive material lifecycle: receipt, use, transfer, decay, waste, disposal, and closure.")
    if custody_breaks > 0:
        top_actions.append("Resolve custody breaks and regenerate Dose Journey Passport.")
    if passport_completeness < 90:
        top_actions.append("Generate final Commercial Readiness Passport and Dose Journey Passport.")
    if not top_actions:
        top_actions.append("Proceed to final human governance review and export inspection packet.")

    return {
        "inspection_score": inspection_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "executive_answer": executive_answer,
        "critical_count": critical_count,
        "major_count": major_count,
        "minor_count": minor_count,
        "findings": findings,
        "inspector_questions": inspector_questions,
        "survivability_domains": survivability_domains,
        "top_actions": top_actions,
        "inputs": {
            "qa_release": qa_release,
            "qc_packet": qc_packet,
            "batch_record": batch_record,
            "em_readiness": em_readiness,
            "capa_closure": capa_closure,
            "sop_training": sop_training,
            "access_review": access_review,
            "custody_trace": custody_trace,
            "material_accountability": material_accountability,
            "evidence_integrity": evidence_integrity,
            "backup_restore": backup_restore,
            "treatment_coordination": treatment_coordination,
            "passport_completeness": passport_completeness,
            "data_integrity": data_integrity,
            "missing_evidence": missing_evidence,
            "stale_evidence": stale_evidence,
            "open_critical_capa": open_critical_capa,
            "open_em_exceptions": open_em_exceptions,
            "custody_breaks": custody_breaks,
            "material_recon_gaps": material_recon_gaps,
            "unapproved_changes": unapproved_changes
        },
        "governance_note": "This simulator is advisory only. It does not replace QA release, regulatory judgment, radiation safety authority, or human governance approval."
    }


@app.route("/irlt-commercial-readiness/inspection-tomorrow")
@app.route("/rlttrust/inspection-tomorrow")
@app.route("/rlttrust/inspection-simulator")
def rlttrust_inspection_tomorrow_simulator():
    payload = {
        "qa_release": request.args.get("qa_release", 78),
        "qc_packet": request.args.get("qc_packet", 84),
        "batch_record": request.args.get("batch_record", 86),
        "em_readiness": request.args.get("em_readiness", 76),
        "capa_closure": request.args.get("capa_closure", 74),
        "sop_training": request.args.get("sop_training", 84),
        "access_review": request.args.get("access_review", 80),
        "custody_trace": request.args.get("custody_trace", 86),
        "material_accountability": request.args.get("material_accountability", 79),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "backup_restore": request.args.get("backup_restore", 88),
        "treatment_coordination": request.args.get("treatment_coordination", 81),
        "passport_completeness": request.args.get("passport_completeness", 83),
        "data_integrity": request.args.get("data_integrity", 87),
        "missing_evidence": request.args.get("missing_evidence", 3),
        "stale_evidence": request.args.get("stale_evidence", 4),
        "open_critical_capa": request.args.get("open_critical_capa", 1),
        "open_em_exceptions": request.args.get("open_em_exceptions", 1),
        "custody_breaks": request.args.get("custody_breaks", 0),
        "material_recon_gaps": request.args.get("material_recon_gaps", 1),
        "unapproved_changes": request.args.get("unapproved_changes", 0),
    }

    result = _rlttrust_inspection_tomorrow_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Inspection Tomorrow Simulator™ | RLTTrust™</title>
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
                    radial-gradient(circle at 90% 8%, rgba(255,159,28,0.16), transparent 34%),
                    radial-gradient(circle at 50% 30%, rgba(255,255,255,0.055), transparent 30%),
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

            .verdict {
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

            .kpi-strip {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 16px;
            }

            .kpi {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 26px;
                padding: 20px;
                background:
                    radial-gradient(circle at top right, rgba(255,122,24,0.16), transparent 35%),
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 22px 70px rgba(0,0,0,0.34);
            }

            .kpi strong {
                display: block;
                font-size: 36px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 8px;
            }

            .kpi span {
                color: var(--muted);
                font-size: 13px;
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

            .panel, .form-panel, .domain-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .domain-card strong {
                display: block;
                font-size: 30px;
                color: #fff2e6;
                margin-bottom: 8px;
            }

            .bar {
                height: 10px;
                border-radius: 999px;
                overflow: hidden;
                background: rgba(255,255,255,0.08);
                border: 1px solid rgba(255,255,255,0.06);
                margin: 12px 0;
            }

            .bar span {
                display: block;
                height: 100%;
                border-radius: 999px;
                background: linear-gradient(90deg, #ff4d4d, #ff7a18, #ffd166, #37d67a);
                box-shadow: 0 0 18px rgba(255,122,24,0.30);
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

            .severity {
                display: inline-block;
                padding: 7px 10px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 950;
                text-transform: uppercase;
            }

            .critical {
                color: #ffc2c2;
                border: 1px solid rgba(255,92,122,0.40);
                background: rgba(255,92,122,0.12);
            }

            .major {
                color: #ffe6a8;
                border: 1px solid rgba(255,209,102,0.40);
                background: rgba(255,209,102,0.12);
            }

            .minor {
                color: #b9ffd0;
                border: 1px solid rgba(55,214,122,0.40);
                background: rgba(55,214,122,0.12);
            }

            ul {
                margin: 10px 0 0 20px;
                padding: 0;
                color: var(--muted);
                line-height: 1.65;
            }

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid, .grid-2, .grid-3, .kpi-strip, .form-grid {
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
                        <div class="eyebrow">RLTTrust™ Inspection Survivability</div>
                        <h1>Inspection Tomorrow Simulator™</h1>
                        <p>
                            A governance simulator that asks the hard question before an inspector does:
                            if FDA, NRC, QA, corporate quality, or a partner auditor walked in tomorrow,
                            what fails, what survives, and what evidence do we show?
                        </p>
                        <p>
                            The simulator maps operational readiness to inspection questions, evidence packets,
                            findings, severity, corrective actions, and governance engines.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/passport">Governance Passport</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Inspection Survivability Score</div>
                        <div class="score">{{ result.inspection_score }}%</div>
                        <span class="verdict {{ result.verdict_class }}">{{ result.verdict }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section kpi-strip">
                <div class="kpi">
                    <strong>{{ result.critical_count }}</strong>
                    <span>Critical findings requiring immediate leadership attention.</span>
                </div>
                <div class="kpi">
                    <strong>{{ result.major_count }}</strong>
                    <span>Major findings affecting inspection defensibility.</span>
                </div>
                <div class="kpi">
                    <strong>{{ result.minor_count }}</strong>
                    <span>Minor findings or improvement opportunities.</span>
                </div>
                <div class="kpi">
                    <strong>{{ result.findings|length }}</strong>
                    <span>Total simulated inspection observations.</span>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Inspection Scenario Inputs</h2>
                    <p>Adjust the readiness controls and simulate the inspection outcome.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>QA Release %</label><input name="qa_release" type="number" min="0" max="100" value="{{ result.inputs.qa_release }}"></div>
                            <div><label>QC Packet %</label><input name="qc_packet" type="number" min="0" max="100" value="{{ result.inputs.qc_packet }}"></div>
                            <div><label>Batch Record %</label><input name="batch_record" type="number" min="0" max="100" value="{{ result.inputs.batch_record }}"></div>
                            <div><label>EM Readiness %</label><input name="em_readiness" type="number" min="0" max="100" value="{{ result.inputs.em_readiness }}"></div>
                            <div><label>CAPA Closure %</label><input name="capa_closure" type="number" min="0" max="100" value="{{ result.inputs.capa_closure }}"></div>
                            <div><label>SOP / Training %</label><input name="sop_training" type="number" min="0" max="100" value="{{ result.inputs.sop_training }}"></div>
                            <div><label>Access Review %</label><input name="access_review" type="number" min="0" max="100" value="{{ result.inputs.access_review }}"></div>
                            <div><label>Custody Trace %</label><input name="custody_trace" type="number" min="0" max="100" value="{{ result.inputs.custody_trace }}"></div>
                            <div><label>Material Accountability %</label><input name="material_accountability" type="number" min="0" max="100" value="{{ result.inputs.material_accountability }}"></div>
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Backup / Restore %</label><input name="backup_restore" type="number" min="0" max="100" value="{{ result.inputs.backup_restore }}"></div>
                            <div><label>Treatment Coordination %</label><input name="treatment_coordination" type="number" min="0" max="100" value="{{ result.inputs.treatment_coordination }}"></div>
                            <div><label>Passport Completeness %</label><input name="passport_completeness" type="number" min="0" max="100" value="{{ result.inputs.passport_completeness }}"></div>
                            <div><label>Data Integrity %</label><input name="data_integrity" type="number" min="0" max="100" value="{{ result.inputs.data_integrity }}"></div>
                            <div><label>Missing Evidence Items</label><input name="missing_evidence" type="number" min="0" max="50" value="{{ result.inputs.missing_evidence }}"></div>
                            <div><label>Stale Evidence Items</label><input name="stale_evidence" type="number" min="0" max="50" value="{{ result.inputs.stale_evidence }}"></div>
                            <div><label>Open Critical CAPA</label><input name="open_critical_capa" type="number" min="0" max="20" value="{{ result.inputs.open_critical_capa }}"></div>
                            <div><label>Open EM Exceptions</label><input name="open_em_exceptions" type="number" min="0" max="20" value="{{ result.inputs.open_em_exceptions }}"></div>
                            <div><label>Custody Breaks</label><input name="custody_breaks" type="number" min="0" max="20" value="{{ result.inputs.custody_breaks }}"></div>
                            <div><label>Material Reconciliation Gaps</label><input name="material_recon_gaps" type="number" min="0" max="20" value="{{ result.inputs.material_recon_gaps }}"></div>
                            <div><label>Unapproved Changes</label><input name="unapproved_changes" type="number" min="0" max="20" value="{{ result.inputs.unapproved_changes }}"></div>
                        </div>
                        <button class="button" type="submit">Run Inspection Tomorrow Simulation</button>
                    </form>
                </div>

                <div>
                    <h2>Inspection Survivability Domains</h2>
                    <div class="grid-3">
                        {% for d in result.survivability_domains %}
                        <div class="domain-card">
                            <strong>{{ d.score }}%</strong>
                            <h3>{{ d.name }}</h3>
                            <div class="bar"><span style="width: {{ d.score }}%;"></span></div>
                            <p>{{ d.description }}</p>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Simulated Inspection Findings</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Area</th>
                                <th>Severity</th>
                                <th>Finding</th>
                                <th>Evidence Gap</th>
                                <th>Business Impact</th>
                                <th>Corrective Action</th>
                                <th>Engine</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for f in result.findings %}
                            <tr>
                                <td><strong>{{ f.area }}</strong></td>
                                <td><span class="severity {{ f.severity_class }}">{{ f.severity }}</span></td>
                                <td>{{ f.finding }}</td>
                                <td>{{ f.evidence_gap }}</td>
                                <td>{{ f.business_impact }}</td>
                                <td>{{ f.corrective_action }}</td>
                                <td>{{ f.engine }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    {% if not result.findings %}
                    <p>No findings detected in this scenario. Proceed to final human governance review.</p>
                    {% endif %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Inspector Question-to-Evidence Engine™</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Inspector Persona</th>
                                <th>Question</th>
                                <th>Best Evidence Packet</th>
                                <th>Readiness</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in result.inspector_questions %}
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
                    <h2>Inspection War-Room Actions</h2>
                    <ul>
                        {% for a in result.top_actions %}
                        <li>{{ a }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/inspection-tomorrow/api")
@app.route("/rlttrust/inspection-tomorrow/api")
@app.route("/rlttrust/inspection-simulator/api")
def rlttrust_inspection_tomorrow_simulator_api():
    payload = {
        "qa_release": request.args.get("qa_release", 78),
        "qc_packet": request.args.get("qc_packet", 84),
        "batch_record": request.args.get("batch_record", 86),
        "em_readiness": request.args.get("em_readiness", 76),
        "capa_closure": request.args.get("capa_closure", 74),
        "sop_training": request.args.get("sop_training", 84),
        "access_review": request.args.get("access_review", 80),
        "custody_trace": request.args.get("custody_trace", 86),
        "material_accountability": request.args.get("material_accountability", 79),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "backup_restore": request.args.get("backup_restore", 88),
        "treatment_coordination": request.args.get("treatment_coordination", 81),
        "passport_completeness": request.args.get("passport_completeness", 83),
        "data_integrity": request.args.get("data_integrity", 87),
        "missing_evidence": request.args.get("missing_evidence", 3),
        "stale_evidence": request.args.get("stale_evidence", 4),
        "open_critical_capa": request.args.get("open_critical_capa", 1),
        "open_em_exceptions": request.args.get("open_em_exceptions", 1),
        "custody_breaks": request.args.get("custody_breaks", 0),
        "material_recon_gaps": request.args.get("material_recon_gaps", 1),
        "unapproved_changes": request.args.get("unapproved_changes", 0),
    }
    return jsonify(_rlttrust_inspection_tomorrow_assessment(payload))

# ============================================================
# End Inspection Tomorrow Simulator™
# ============================================================

'''

    # Add Inspection Tomorrow link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_INSPECTION_TOMORROW_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_INSPECTION_TOMORROW_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>',
            1
        )
        print("Added Inspection Tomorrow link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Inspection Tomorrow Simulator successfully.")

