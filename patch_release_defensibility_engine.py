from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_RELEASE_DEFENSIBILITY_ENGINE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Release Defensibility Engine already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_RELEASE_DEFENSIBILITY_ENGINE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Release Defensibility Engine™
# Purpose: QA-facing release decision-support layer for commercial IRLT readiness.
# AI is advisory only. Human QA/compliance governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_release_num(value, default, minimum=0, maximum=100):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_release_int(value, default, minimum=0, maximum=100):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_release_defensibility_assessment(payload=None):
    payload = payload or {}

    qc_readiness = _rlttrust_release_num(payload.get("qc_readiness"), 84)
    qa_review = _rlttrust_release_num(payload.get("qa_review"), 78)
    batch_record = _rlttrust_release_num(payload.get("batch_record"), 86)
    em_readiness = _rlttrust_release_num(payload.get("em_readiness"), 76)
    capa_closure = _rlttrust_release_num(payload.get("capa_closure"), 74)
    sop_training = _rlttrust_release_num(payload.get("sop_training"), 84)
    access_governance = _rlttrust_release_num(payload.get("access_governance"), 80)
    custody_readiness = _rlttrust_release_num(payload.get("custody_readiness"), 86)
    material_accountability = _rlttrust_release_num(payload.get("material_accountability"), 82)
    evidence_integrity = _rlttrust_release_num(payload.get("evidence_integrity"), 91)
    data_integrity = _rlttrust_release_num(payload.get("data_integrity"), 87)
    patient_slot_readiness = _rlttrust_release_num(payload.get("patient_slot_readiness"), 81)

    open_critical_deviations = _rlttrust_release_int(payload.get("open_critical_deviations"), 1, 0, 20)
    unresolved_oos = _rlttrust_release_int(payload.get("unresolved_oos"), 0, 0, 20)
    em_excursions = _rlttrust_release_int(payload.get("em_excursions"), 1, 0, 20)
    training_gaps = _rlttrust_release_int(payload.get("training_gaps"), 1, 0, 20)
    access_exceptions = _rlttrust_release_int(payload.get("access_exceptions"), 1, 0, 20)
    custody_exceptions = _rlttrust_release_int(payload.get("custody_exceptions"), 0, 0, 20)
    stale_evidence = _rlttrust_release_int(payload.get("stale_evidence"), 3, 0, 50)
    missing_evidence = _rlttrust_release_int(payload.get("missing_evidence"), 2, 0, 50)
    material_variance = _rlttrust_release_num(payload.get("material_variance"), 1.0, 0, 100)

    deviation_penalty = min(open_critical_deviations * 8, 32)
    oos_penalty = min(unresolved_oos * 14, 42)
    em_penalty = min(em_excursions * 7, 28)
    training_penalty = min(training_gaps * 5, 25)
    access_penalty = min(access_exceptions * 4, 20)
    custody_penalty = min(custody_exceptions * 10, 30)
    evidence_penalty = min((stale_evidence * 2) + (missing_evidence * 4), 36)
    material_penalty = min(material_variance * 4, 28)

    deviation_control_score = max(0, ((capa_closure + em_readiness) / 2) - deviation_penalty - em_penalty - oos_penalty)
    people_control_score = max(0, sop_training - training_penalty)
    access_control_score = max(0, access_governance - access_penalty)
    custody_control_score = max(0, custody_readiness - custody_penalty)
    material_control_score = max(0, material_accountability - material_penalty)
    evidence_control_score = max(0, evidence_integrity - evidence_penalty)

    release_score = round(
        qc_readiness * 0.14 +
        qa_review * 0.14 +
        batch_record * 0.10 +
        deviation_control_score * 0.13 +
        people_control_score * 0.08 +
        access_control_score * 0.06 +
        custody_control_score * 0.09 +
        material_control_score * 0.09 +
        evidence_control_score * 0.10 +
        data_integrity * 0.04 +
        patient_slot_readiness * 0.03
    )

    blockers = []
    warnings = []

    if qc_readiness < 70:
        blockers.append("QC readiness is below release-defensible threshold.")
    elif qc_readiness < 85:
        warnings.append("QC readiness has governance warnings.")

    if qa_review < 70:
        blockers.append("QA review package is not defensible.")
    elif qa_review < 85:
        warnings.append("QA review package needs stronger release rationale.")

    if unresolved_oos > 0:
        blockers.append("Unresolved OOS/OOT condition blocks defensible release unless QA disposition is complete.")

    if open_critical_deviations >= 2:
        blockers.append("Multiple critical deviations/CAPA dependencies remain open.")
    elif open_critical_deviations == 1:
        warnings.append("One critical deviation/CAPA dependency requires QA disposition.")

    if em_excursions >= 2:
        blockers.append("Multiple environmental monitoring excursions require impact assessment before release confidence.")
    elif em_excursions == 1:
        warnings.append("Environmental monitoring excursion requires QA impact review.")

    if custody_exceptions > 0:
        warnings.append("Custody exception must be reconciled before final release passport closure.")

    if material_control_score < 75:
        blockers.append("Radioactive material accountability is below defensible release threshold.")
    elif material_control_score < 85:
        warnings.append("Radioactive material accountability requires reconciliation review.")

    if evidence_control_score < 75:
        blockers.append("Evidence integrity/completeness is below release-defensible threshold.")
    elif evidence_control_score < 88:
        warnings.append("Evidence packet has missing or stale records.")

    if people_control_score < 80:
        warnings.append("SOP/training alignment may weaken release defensibility.")

    if access_control_score < 80:
        warnings.append("Access governance requires owner attestation.")

    if patient_slot_readiness < 80:
        warnings.append("Treatment coordination / patient-slot readiness may affect release-to-treatment confidence.")

    if blockers:
        decision = "HOLD — release not defensible"
        status_class = "blocked"
        executive_answer = "QA should not treat this release as defensible until blockers are resolved and human governance approves closure evidence."
    elif release_score >= 90 and len(warnings) <= 1:
        decision = "RELEASE DEFENSIBLE — subject to final QA approval"
        status_class = "ready"
        executive_answer = "The release package appears defensible, subject to final QA, compliance, and operational leadership approval."
    elif release_score >= 82:
        decision = "RELEASE POSSIBLE — governance warnings"
        status_class = "warning"
        executive_answer = "The release may be possible, but QA should review warnings and strengthen evidence before final release confidence."
    elif release_score >= 70:
        decision = "HOLD — evidence gaps remain"
        status_class = "gap"
        executive_answer = "The release package has enough structure to improve quickly, but gaps remain before it can be called defensible."
    else:
        decision = "HOLD — not inspection-defensible"
        status_class = "blocked"
        executive_answer = "The release package is not inspection-defensible under the current governance posture."

    gates = [
        {
            "gate": "QC Result Gate",
            "score": round(qc_readiness),
            "status": "Pass" if qc_readiness >= 85 and unresolved_oos == 0 else "Warning" if qc_readiness >= 75 else "Fail",
            "evidence": "QC result packet, method readiness, result approval, OOS/OOT status.",
            "owner": "QC / QA"
        },
        {
            "gate": "QA Release Rationale Gate",
            "score": round(qa_review),
            "status": "Pass" if qa_review >= 85 else "Warning" if qa_review >= 75 else "Fail",
            "evidence": "QA release decision, rationale, risk disposition, human approval lineage.",
            "owner": "QA Release"
        },
        {
            "gate": "Batch Record Gate",
            "score": round(batch_record),
            "status": "Pass" if batch_record >= 85 else "Warning" if batch_record >= 75 else "Fail",
            "evidence": "Batch manufacturing record, operator accountability, equipment readiness.",
            "owner": "Manufacturing / QA"
        },
        {
            "gate": "Deviation / CAPA / EM Gate",
            "score": round(deviation_control_score),
            "status": "Pass" if deviation_control_score >= 85 and open_critical_deviations == 0 and em_excursions == 0 else "Warning" if deviation_control_score >= 70 else "Fail",
            "evidence": "Deviation disposition, CAPA closure, EM impact review, QA approval.",
            "owner": "QA / CAPA / EM"
        },
        {
            "gate": "SOP / Training Gate",
            "score": round(people_control_score),
            "status": "Pass" if people_control_score >= 85 and training_gaps == 0 else "Warning" if people_control_score >= 75 else "Fail",
            "evidence": "Effective SOP version, training completion, role alignment.",
            "owner": "Training / SOP Governance"
        },
        {
            "gate": "Access Governance Gate",
            "score": round(access_control_score),
            "status": "Pass" if access_control_score >= 85 and access_exceptions == 0 else "Warning" if access_control_score >= 75 else "Fail",
            "evidence": "Access review, privileged role attestation, system-owner approval.",
            "owner": "IAM / System Owner"
        },
        {
            "gate": "Custody / Shipment Gate",
            "score": round(custody_control_score),
            "status": "Pass" if custody_control_score >= 85 and custody_exceptions == 0 else "Warning" if custody_control_score >= 75 else "Fail",
            "evidence": "Custody transfer, courier dispatch, cold-chain, receipt confirmation.",
            "owner": "Supply Chain / Logistics"
        },
        {
            "gate": "Radioactive Material Gate",
            "score": round(material_control_score),
            "status": "Pass" if material_control_score >= 85 and material_variance <= 0.5 else "Warning" if material_control_score >= 75 else "Fail",
            "evidence": "Receipt, use, transfer, decay, waste, residual, final reconciliation.",
            "owner": "Radiation Safety / QA"
        },
        {
            "gate": "Evidence Integrity Gate",
            "score": round(evidence_control_score),
            "status": "Pass" if evidence_control_score >= 88 and missing_evidence == 0 else "Warning" if evidence_control_score >= 75 else "Fail",
            "evidence": "AuditVault™ hashes, evidence completeness, stale-record review, approval lineage.",
            "owner": "QA / Compliance / AuditVault™"
        },
        {
            "gate": "Treatment Readiness Gate",
            "score": round(patient_slot_readiness),
            "status": "Pass" if patient_slot_readiness >= 85 else "Warning" if patient_slot_readiness >= 75 else "Fail",
            "evidence": "Treatment-site readiness, appointment match, dose-to-slot confirmation.",
            "owner": "Treatment Coordination"
        }
    ]

    findings = []

    def add_finding(area, severity, issue, impact, required_action, engine):
        css = "critical" if severity == "Critical" else "major" if severity == "Major" else "minor"
        findings.append({
            "area": area,
            "severity": severity,
            "severity_class": css,
            "issue": issue,
            "impact": impact,
            "required_action": required_action,
            "engine": engine
        })

    if qc_readiness < 85 or unresolved_oos > 0:
        add_finding(
            "QC",
            "Critical" if unresolved_oos > 0 or qc_readiness < 70 else "Major",
            "QC packet may not fully support defensible release.",
            "QA release may be challenged if QC evidence, OOS/OOT disposition, or method readiness is incomplete.",
            "Complete QC readiness packet and confirm OOS/OOT disposition before release confidence.",
            "QC Readiness Governance"
        )

    if qa_review < 85:
        add_finding(
            "QA Release",
            "Major" if qa_review >= 70 else "Critical",
            "QA release rationale needs stronger governance evidence.",
            "Release may be approved procedurally but weak under inspection questioning.",
            "Document release rationale, unresolved dependency disposition, and human approval lineage.",
            "Release Defensibility Engine™"
        )

    if open_critical_deviations > 0 or capa_closure < 85:
        add_finding(
            "Deviation / CAPA",
            "Critical" if open_critical_deviations >= 2 else "Major",
            "Deviation/CAPA closure is not fully release-defensible.",
            "Open or weak CAPA dependencies can block or weaken commercial release confidence.",
            "Run CAPATrust™ closure defensibility check and link QA disposition.",
            "CAPATrust™"
        )

    if em_excursions > 0 or em_readiness < 85:
        add_finding(
            "Environmental Monitoring",
            "Major",
            "EM readiness or excursion impact requires QA visibility.",
            "EM exceptions can propagate into release defensibility and audit readiness.",
            "Attach EM impact assessment and QA release impact decision.",
            "CAPATrust™ / EM Governance"
        )

    if sop_training < 85 or training_gaps > 0:
        add_finding(
            "SOP / Training",
            "Major" if training_gaps > 0 else "Minor",
            "Training may not fully align to the effective SOP and execution role.",
            "Operator readiness may be challenged during inspection.",
            "Run SOPTrust™ drift and training alignment verification.",
            "SOPTrust™"
        )

    if access_governance < 85 or access_exceptions > 0:
        add_finding(
            "Access Governance",
            "Minor",
            "Access attestation or privileged access review needs strengthening.",
            "Audit trail accountability may be challenged.",
            "Run AccessTrust™ owner attestation and privileged-role review.",
            "AccessTrust™"
        )

    if custody_readiness < 85 or custody_exceptions > 0:
        add_finding(
            "Custody / Shipment",
            "Major" if custody_exceptions > 0 else "Minor",
            "Custody evidence is not fully release-to-treatment defensible.",
            "A released product may still fail operationally if custody or shipment evidence is weak.",
            "Link shipment, cold-chain, custody transfer, and receipt evidence to Dose Journey Passport.",
            "Isotope-to-Patient Evidence Graph™"
        )

    if material_control_score < 85:
        add_finding(
            "Radioactive Material Accountability",
            "Major" if material_control_score >= 70 else "Critical",
            "Radioactive material reconciliation weakens release defensibility.",
            "Material receipt/use/waste/decay/residual variance may create inspection exposure.",
            "Run Radioactive Material Accountability Ledger™ and reconcile variance.",
            "Radioactive Material Accountability Ledger™"
        )

    if evidence_control_score < 88 or missing_evidence > 0:
        add_finding(
            "Evidence Integrity",
            "Major" if evidence_control_score >= 70 else "Critical",
            "Release evidence may be missing, stale, scattered, or hard to retrieve.",
            "Inspection response may be slow or inconsistent.",
            "Hash, link, refresh, and passport release evidence in AuditVault™.",
            "AuditVault™"
        )

    release_packet = [
        "QC result packet",
        "QA release rationale",
        "Batch manufacturing record",
        "Deviation/CAPA disposition",
        "Environmental monitoring impact assessment",
        "Effective SOP and training alignment packet",
        "Access governance attestation",
        "Chain-of-custody and shipment evidence",
        "Radioactive material reconciliation packet",
        "AuditVault™ evidence verification",
        "Dose Journey Passport",
        "Release Defensibility Passport"
    ]

    recommended_actions = []
    for b in blockers:
        recommended_actions.append("Resolve blocker: " + b)
    for w in warnings[:5]:
        recommended_actions.append("Review warning: " + w)

    if not recommended_actions:
        recommended_actions.append("Proceed to final QA release review and generate Release Defensibility Passport.")

    passport_outputs = [
        "Release Defensibility Passport",
        "QA Release Rationale Packet",
        "QC-to-Release Evidence Packet",
        "Deviation/CAPA Release Impact Packet",
        "EM Release Impact Packet",
        "Radioactive Material Release Reconciliation Packet",
        "Dose Journey Passport",
        "AuditVault™ Release Evidence Packet"
    ]

    component_scores = {
        "QC Readiness": round(qc_readiness),
        "QA Review": round(qa_review),
        "Batch Record": round(batch_record),
        "Deviation / CAPA / EM": round(deviation_control_score),
        "SOP / Training": round(people_control_score),
        "Access Governance": round(access_control_score),
        "Custody Readiness": round(custody_control_score),
        "Material Accountability": round(material_control_score),
        "Evidence Integrity": round(evidence_control_score),
        "Data Integrity": round(data_integrity),
        "Treatment Readiness": round(patient_slot_readiness)
    }

    return {
        "release_score": release_score,
        "decision": decision,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "blockers": blockers,
        "warnings": warnings,
        "gates": gates,
        "findings": findings,
        "release_packet": release_packet,
        "recommended_actions": recommended_actions,
        "passport_outputs": passport_outputs,
        "component_scores": component_scores,
        "inputs": {
            "qc_readiness": qc_readiness,
            "qa_review": qa_review,
            "batch_record": batch_record,
            "em_readiness": em_readiness,
            "capa_closure": capa_closure,
            "sop_training": sop_training,
            "access_governance": access_governance,
            "custody_readiness": custody_readiness,
            "material_accountability": material_accountability,
            "evidence_integrity": evidence_integrity,
            "data_integrity": data_integrity,
            "patient_slot_readiness": patient_slot_readiness,
            "open_critical_deviations": open_critical_deviations,
            "unresolved_oos": unresolved_oos,
            "em_excursions": em_excursions,
            "training_gaps": training_gaps,
            "access_exceptions": access_exceptions,
            "custody_exceptions": custody_exceptions,
            "stale_evidence": stale_evidence,
            "missing_evidence": missing_evidence,
            "material_variance": material_variance
        },
        "governance_note": "This engine is advisory only. It does not approve release. Final release authority remains with QA, compliance, system owners, radiation safety, and authorized human governance."
    }


@app.route("/irlt-commercial-readiness/release-defensibility")
@app.route("/rlttrust/release-defensibility")
@app.route("/rlttrust/release-defensibility-engine")
def rlttrust_release_defensibility_engine():
    payload = {
        "qc_readiness": request.args.get("qc_readiness", 84),
        "qa_review": request.args.get("qa_review", 78),
        "batch_record": request.args.get("batch_record", 86),
        "em_readiness": request.args.get("em_readiness", 76),
        "capa_closure": request.args.get("capa_closure", 74),
        "sop_training": request.args.get("sop_training", 84),
        "access_governance": request.args.get("access_governance", 80),
        "custody_readiness": request.args.get("custody_readiness", 86),
        "material_accountability": request.args.get("material_accountability", 82),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "data_integrity": request.args.get("data_integrity", 87),
        "patient_slot_readiness": request.args.get("patient_slot_readiness", 81),
        "open_critical_deviations": request.args.get("open_critical_deviations", 1),
        "unresolved_oos": request.args.get("unresolved_oos", 0),
        "em_excursions": request.args.get("em_excursions", 1),
        "training_gaps": request.args.get("training_gaps", 1),
        "access_exceptions": request.args.get("access_exceptions", 1),
        "custody_exceptions": request.args.get("custody_exceptions", 0),
        "stale_evidence": request.args.get("stale_evidence", 3),
        "missing_evidence": request.args.get("missing_evidence", 2),
        "material_variance": request.args.get("material_variance", 1.0),
    }

    result = _rlttrust_release_defensibility_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Release Defensibility Engine™ | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --charcoal: #07080c;
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

            .decision {
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

            .panel, .form-panel, .metric, .gate-card {
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

            .gate-status {
                display: inline-block;
                padding: 7px 10px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 950;
                text-transform: uppercase;
                margin-bottom: 10px;
            }

            .pass {
                color: #b9ffd0;
                border: 1px solid rgba(55,214,122,0.40);
                background: rgba(55,214,122,0.12);
            }

            .gate-warning {
                color: #ffe6a8;
                border: 1px solid rgba(255,209,102,0.40);
                background: rgba(255,209,102,0.12);
            }

            .fail {
                color: #ffc2c2;
                border: 1px solid rgba(255,92,122,0.40);
                background: rgba(255,92,122,0.12);
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

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
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
                        <div class="eyebrow">RLTTrust™ QA Release Assurance</div>
                        <h1>Release Defensibility Engine™</h1>
                        <p>
                            A QA-facing governance engine that evaluates whether a commercial IRLT release decision can survive inspection.
                            It connects QC, QA review, batch records, deviations/CAPA, environmental monitoring, SOP/training,
                            access, custody, radioactive material accountability, evidence integrity, and treatment readiness.
                        </p>
                        <p>
                            This engine does not approve release. It explains whether the release decision is defensible with governed evidence.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>
                            <a href="/irlt-commercial-readiness/release-defensibility/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Release Defensibility Score</div>
                        <div class="score">{{ result.release_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.decision }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Release Scenario Inputs</h2>
                    <p>Adjust release-readiness values and recalculate defensibility.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>QC Readiness %</label><input name="qc_readiness" type="number" min="0" max="100" value="{{ result.inputs.qc_readiness }}"></div>
                            <div><label>QA Review %</label><input name="qa_review" type="number" min="0" max="100" value="{{ result.inputs.qa_review }}"></div>
                            <div><label>Batch Record %</label><input name="batch_record" type="number" min="0" max="100" value="{{ result.inputs.batch_record }}"></div>
                            <div><label>EM Readiness %</label><input name="em_readiness" type="number" min="0" max="100" value="{{ result.inputs.em_readiness }}"></div>
                            <div><label>CAPA Closure %</label><input name="capa_closure" type="number" min="0" max="100" value="{{ result.inputs.capa_closure }}"></div>
                            <div><label>SOP / Training %</label><input name="sop_training" type="number" min="0" max="100" value="{{ result.inputs.sop_training }}"></div>
                            <div><label>Access Governance %</label><input name="access_governance" type="number" min="0" max="100" value="{{ result.inputs.access_governance }}"></div>
                            <div><label>Custody Readiness %</label><input name="custody_readiness" type="number" min="0" max="100" value="{{ result.inputs.custody_readiness }}"></div>
                            <div><label>Material Accountability %</label><input name="material_accountability" type="number" min="0" max="100" value="{{ result.inputs.material_accountability }}"></div>
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Data Integrity %</label><input name="data_integrity" type="number" min="0" max="100" value="{{ result.inputs.data_integrity }}"></div>
                            <div><label>Patient Slot Readiness %</label><input name="patient_slot_readiness" type="number" min="0" max="100" value="{{ result.inputs.patient_slot_readiness }}"></div>
                            <div><label>Open Critical Deviations</label><input name="open_critical_deviations" type="number" min="0" max="20" value="{{ result.inputs.open_critical_deviations }}"></div>
                            <div><label>Unresolved OOS / OOT</label><input name="unresolved_oos" type="number" min="0" max="20" value="{{ result.inputs.unresolved_oos }}"></div>
                            <div><label>EM Excursions</label><input name="em_excursions" type="number" min="0" max="20" value="{{ result.inputs.em_excursions }}"></div>
                            <div><label>Training Gaps</label><input name="training_gaps" type="number" min="0" max="20" value="{{ result.inputs.training_gaps }}"></div>
                            <div><label>Access Exceptions</label><input name="access_exceptions" type="number" min="0" max="20" value="{{ result.inputs.access_exceptions }}"></div>
                            <div><label>Custody Exceptions</label><input name="custody_exceptions" type="number" min="0" max="20" value="{{ result.inputs.custody_exceptions }}"></div>
                            <div><label>Stale Evidence Items</label><input name="stale_evidence" type="number" min="0" max="50" value="{{ result.inputs.stale_evidence }}"></div>
                            <div><label>Missing Evidence Items</label><input name="missing_evidence" type="number" min="0" max="50" value="{{ result.inputs.missing_evidence }}"></div>
                            <div><label>Material Variance mCi</label><input name="material_variance" type="number" step="0.1" min="0" max="100" value="{{ result.inputs.material_variance }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Release Defensibility</button>
                    </form>
                </div>

                <div>
                    <h2>Component Scores</h2>
                    <div class="grid-3">
                        {% for name, score in result.component_scores.items() %}
                        <div class="metric">
                            <strong>{{ score }}%</strong>
                            <span>{{ name }}</span>
                            <div class="bar"><span style="width: {{ score }}%;"></span></div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Release Governance Gates</h2>
                <div class="grid-3">
                    {% for gate in result.gates %}
                    <div class="gate-card">
                        {% if gate.status == "Pass" %}
                            <span class="gate-status pass">{{ gate.status }}</span>
                        {% elif gate.status == "Warning" %}
                            <span class="gate-status gate-warning">{{ gate.status }}</span>
                        {% else %}
                            <span class="gate-status fail">{{ gate.status }}</span>
                        {% endif %}
                        <h3>{{ gate.gate }}</h3>
                        <div class="metric" style="padding:14px; margin:12px 0;">
                            <strong>{{ gate.score }}%</strong>
                            <span>{{ gate.owner }}</span>
                            <div class="bar"><span style="width: {{ gate.score }}%;"></span></div>
                        </div>
                        <p>{{ gate.evidence }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Blockers and Warnings</h2>
                    {% if result.blockers %}
                    <h3>Blockers</h3>
                    <ul>
                        {% for b in result.blockers %}
                        <li>{{ b }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if result.warnings %}
                    <h3 style="margin-top:18px;">Warnings</h3>
                    <ul>
                        {% for w in result.warnings %}
                        <li>{{ w }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if not result.blockers and not result.warnings %}
                    <p>No blockers or warnings detected in this scenario.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Recommended QA Actions</h2>
                    <ul>
                        {% for action in result.recommended_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Simulated Release Defensibility Findings</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Area</th>
                                <th>Severity</th>
                                <th>Issue</th>
                                <th>Impact</th>
                                <th>Required Action</th>
                                <th>Engine</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for f in result.findings %}
                            <tr>
                                <td><strong>{{ f.area }}</strong></td>
                                <td><span class="severity {{ f.severity_class }}">{{ f.severity }}</span></td>
                                <td>{{ f.issue }}</td>
                                <td>{{ f.impact }}</td>
                                <td>{{ f.required_action }}</td>
                                <td>{{ f.engine }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    {% if not result.findings %}
                    <p>No simulated findings detected. Proceed to final QA release review.</p>
                    {% endif %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Release Evidence Packet</h2>
                    <ul>
                        {% for item in result.release_packet %}
                        <li>{{ item }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div class="panel">
                    <h2>Passport Outputs</h2>
                    <p>These are the QA/compliance artifacts this engine can generate.</p>
                    {% for p in result.passport_outputs %}
                    <span class="passport">{{ p }}</span>
                    {% endfor %}
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/release-defensibility/api")
@app.route("/rlttrust/release-defensibility/api")
@app.route("/rlttrust/release-defensibility-engine/api")
def rlttrust_release_defensibility_engine_api():
    payload = {
        "qc_readiness": request.args.get("qc_readiness", 84),
        "qa_review": request.args.get("qa_review", 78),
        "batch_record": request.args.get("batch_record", 86),
        "em_readiness": request.args.get("em_readiness", 76),
        "capa_closure": request.args.get("capa_closure", 74),
        "sop_training": request.args.get("sop_training", 84),
        "access_governance": request.args.get("access_governance", 80),
        "custody_readiness": request.args.get("custody_readiness", 86),
        "material_accountability": request.args.get("material_accountability", 82),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "data_integrity": request.args.get("data_integrity", 87),
        "patient_slot_readiness": request.args.get("patient_slot_readiness", 81),
        "open_critical_deviations": request.args.get("open_critical_deviations", 1),
        "unresolved_oos": request.args.get("unresolved_oos", 0),
        "em_excursions": request.args.get("em_excursions", 1),
        "training_gaps": request.args.get("training_gaps", 1),
        "access_exceptions": request.args.get("access_exceptions", 1),
        "custody_exceptions": request.args.get("custody_exceptions", 0),
        "stale_evidence": request.args.get("stale_evidence", 3),
        "missing_evidence": request.args.get("missing_evidence", 2),
        "material_variance": request.args.get("material_variance", 1.0),
    }
    return jsonify(_rlttrust_release_defensibility_assessment(payload))

# ============================================================
# End Release Defensibility Engine™
# ============================================================

'''

    # Add Release Defensibility link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_RELEASE_DEFENSIBILITY_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_RELEASE_DEFENSIBILITY_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>',
            1
        )
        print("Added Release Defensibility link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Release Defensibility Engine successfully.")

