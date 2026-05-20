from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_CAN_WE_TREAT_TOMORROW_ENGINE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Can We Treat Tomorrow engine already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_CAN_WE_TREAT_TOMORROW_ENGINE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Can We Treat Tomorrow? Engine™
# Purpose: Decision-support engine for decay-aware IRLT readiness.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_number(value, default, minimum=0, maximum=100):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_int(value, default, minimum=0, maximum=999):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_can_we_treat_assessment(payload=None):
    payload = payload or {}

    isotope_hours_remaining = _rlttrust_number(payload.get("isotope_hours_remaining"), 24, 0, 96)
    qc_readiness = _rlttrust_number(payload.get("qc_readiness"), 86)
    qa_release_defensibility = _rlttrust_number(payload.get("qa_release_defensibility"), 78)
    custody_readiness = _rlttrust_number(payload.get("custody_readiness"), 84)
    cold_chain_readiness = _rlttrust_number(payload.get("cold_chain_readiness"), 88)
    treatment_site_readiness = _rlttrust_number(payload.get("treatment_site_readiness"), 82)
    sop_training_alignment = _rlttrust_number(payload.get("sop_training_alignment"), 85)
    evidence_integrity = _rlttrust_number(payload.get("evidence_integrity"), 91)
    access_governance = _rlttrust_number(payload.get("access_governance"), 80)
    backup_restore_readiness = _rlttrust_number(payload.get("backup_restore_readiness"), 88)

    open_critical_capa = _rlttrust_int(payload.get("open_critical_capa"), 1, 0, 20)
    open_em_exception = _rlttrust_int(payload.get("open_em_exception"), 1, 0, 20)
    shipment_exception = _rlttrust_int(payload.get("shipment_exception"), 0, 0, 20)
    stale_evidence_items = _rlttrust_int(payload.get("stale_evidence_items"), 2, 0, 100)

    # Time-readiness scoring:
    # This does not make a regulated release decision.
    # It provides operational governance pressure based on remaining time.
    if isotope_hours_remaining >= 36:
        isotope_time_score = 100
        time_pressure = "Low"
    elif isotope_hours_remaining >= 24:
        isotope_time_score = 90
        time_pressure = "Moderate"
    elif isotope_hours_remaining >= 16:
        isotope_time_score = 76
        time_pressure = "High"
    elif isotope_hours_remaining >= 8:
        isotope_time_score = 58
        time_pressure = "Severe"
    else:
        isotope_time_score = 35
        time_pressure = "Critical"

    capa_penalty = min(open_critical_capa * 8, 30)
    em_penalty = min(open_em_exception * 7, 28)
    shipment_penalty = min(shipment_exception * 10, 30)
    stale_penalty = min(stale_evidence_items * 2, 20)

    deviation_environment_score = max(0, 100 - capa_penalty - em_penalty)
    shipment_custody_score = max(0, ((custody_readiness + cold_chain_readiness) / 2) - shipment_penalty)
    evidence_score = max(0, evidence_integrity - stale_penalty)

    weighted_score = (
        isotope_time_score * 0.15 +
        qc_readiness * 0.13 +
        qa_release_defensibility * 0.14 +
        shipment_custody_score * 0.12 +
        treatment_site_readiness * 0.10 +
        deviation_environment_score * 0.10 +
        sop_training_alignment * 0.08 +
        access_governance * 0.06 +
        backup_restore_readiness * 0.04 +
        evidence_score * 0.08
    )

    score = round(weighted_score)

    blockers = []
    warnings = []

    if isotope_hours_remaining < 8:
        blockers.append("Isotope time remaining is critically low.")
    elif isotope_hours_remaining < 16:
        warnings.append("Isotope time window is under severe pressure.")

    if qc_readiness < 70:
        blockers.append("QC readiness is below defensible release threshold.")
    elif qc_readiness < 85:
        warnings.append("QC readiness needs strengthened evidence before release confidence improves.")

    if qa_release_defensibility < 70:
        blockers.append("QA release defensibility is weak.")
    elif qa_release_defensibility < 85:
        warnings.append("QA release defensibility has governance warnings.")

    if shipment_custody_score < 70:
        blockers.append("Shipment/custody readiness is not defensible.")
    elif shipment_custody_score < 85:
        warnings.append("Shipment/custody readiness needs closer monitoring.")

    if treatment_site_readiness < 70:
        blockers.append("Treatment-site readiness is below safe governance threshold.")
    elif treatment_site_readiness < 85:
        warnings.append("Treatment-site readiness is not fully mature.")

    if open_critical_capa >= 2:
        blockers.append("Multiple critical CAPA/deviation dependencies remain open.")
    elif open_critical_capa == 1:
        warnings.append("One critical CAPA/deviation dependency remains open.")

    if open_em_exception >= 2:
        blockers.append("Multiple environmental monitoring exceptions remain open.")
    elif open_em_exception == 1:
        warnings.append("One environmental monitoring exception requires QA visibility.")

    if shipment_exception >= 1:
        warnings.append("Shipment exception exists and must be linked to custody evidence.")

    if sop_training_alignment < 80:
        warnings.append("SOP/training alignment may weaken inspection defensibility.")

    if access_governance < 80:
        warnings.append("Access governance requires owner attestation.")

    if stale_evidence_items >= 5:
        warnings.append("Multiple stale evidence items may create false readiness.")

    if evidence_score < 75:
        blockers.append("Evidence integrity/staleness score is below defensible threshold.")
    elif evidence_score < 88:
        warnings.append("Evidence package has staleness or completeness warnings.")

    if blockers:
        decision = "NO — release/treatment dependency blocked"
        decision_class = "blocked"
        executive_answer = "The operation should not be treated as tomorrow-ready until critical blockers are resolved and human governance approves the closure evidence."
    elif score >= 88 and len(warnings) <= 2:
        decision = "YES — inspection-defensible"
        decision_class = "ready"
        executive_answer = "The operation appears tomorrow-ready with strong governed evidence, subject to final QA and operational leadership approval."
    elif score >= 78:
        decision = "YES — but with governance warnings"
        decision_class = "warning"
        executive_answer = "The operation may be tomorrow-ready, but leadership should review warnings before treating readiness as defensible."
    elif score >= 65:
        decision = "NO — evidence gaps remain"
        decision_class = "gap"
        executive_answer = "The operation is not yet defensible because evidence or dependency gaps remain."
    else:
        decision = "NO — not commercially defensible"
        decision_class = "blocked"
        executive_answer = "The operation is not ready for tomorrow treatment support under a defensible governance posture."

    recommended_actions = []

    if isotope_hours_remaining < 16:
        recommended_actions.append("Escalate decay-aware readiness review with QC, QA release, logistics, and treatment coordination.")
    if qc_readiness < 85:
        recommended_actions.append("Complete QC evidence packet and confirm test-result readiness before QA release confidence is raised.")
    if qa_release_defensibility < 85:
        recommended_actions.append("Document QA release rationale, open dependencies, and human approval lineage.")
    if shipment_custody_score < 85:
        recommended_actions.append("Reconcile custody, cold-chain, courier timing, receipt, and shipment exception evidence.")
    if treatment_site_readiness < 85:
        recommended_actions.append("Confirm treatment-site receipt readiness, staffing, scheduling, and nuclear medicine coordination.")
    if open_critical_capa > 0:
        recommended_actions.append("Link open CAPA/deviation dependencies to release decision and confirm QA risk disposition.")
    if open_em_exception > 0:
        recommended_actions.append("Confirm environmental monitoring exception assessment and release impact review.")
    if sop_training_alignment < 85:
        recommended_actions.append("Run SOPTrust™ training-to-effective-SOP alignment check.")
    if access_governance < 85:
        recommended_actions.append("Run AccessTrust™ owner attestation for critical systems and privileged roles.")
    if stale_evidence_items > 0:
        recommended_actions.append("Run Evidence Expiry Engine™ and refresh stale evidence before inspection-readiness signoff.")

    if not recommended_actions:
        recommended_actions.append("Proceed to final human governance review and generate Treatment Readiness Passport.")

    evidence_packets = [
        "QC readiness packet",
        "QA release defensibility packet",
        "Isotope timing and decay-window assessment",
        "Shipment/cold-chain/custody packet",
        "Treatment-site readiness packet",
        "SOP and training alignment packet",
        "CAPA/deviation dependency packet",
        "Environmental monitoring impact packet",
        "Access governance attestation",
        "AuditVault™ hash/evidence verification",
        "Governance Passport™ output"
    ]

    return {
        "decision": decision,
        "decision_class": decision_class,
        "score": score,
        "executive_answer": executive_answer,
        "time_pressure": time_pressure,
        "inputs": {
            "isotope_hours_remaining": isotope_hours_remaining,
            "qc_readiness": qc_readiness,
            "qa_release_defensibility": qa_release_defensibility,
            "custody_readiness": custody_readiness,
            "cold_chain_readiness": cold_chain_readiness,
            "treatment_site_readiness": treatment_site_readiness,
            "sop_training_alignment": sop_training_alignment,
            "evidence_integrity": evidence_integrity,
            "access_governance": access_governance,
            "backup_restore_readiness": backup_restore_readiness,
            "open_critical_capa": open_critical_capa,
            "open_em_exception": open_em_exception,
            "shipment_exception": shipment_exception,
            "stale_evidence_items": stale_evidence_items
        },
        "component_scores": {
            "isotope_time_score": round(isotope_time_score),
            "shipment_custody_score": round(shipment_custody_score),
            "deviation_environment_score": round(deviation_environment_score),
            "evidence_score": round(evidence_score),
            "qc_readiness": round(qc_readiness),
            "qa_release_defensibility": round(qa_release_defensibility),
            "treatment_site_readiness": round(treatment_site_readiness),
            "sop_training_alignment": round(sop_training_alignment),
            "access_governance": round(access_governance),
            "backup_restore_readiness": round(backup_restore_readiness)
        },
        "blockers": blockers,
        "warnings": warnings,
        "recommended_actions": recommended_actions,
        "evidence_packets": evidence_packets,
        "governance_note": "AI and scoring are advisory only. QA, compliance, system owners, and operational leadership remain the authoritative control layer."
    }


@app.route("/irlt-commercial-readiness/can-we-treat-tomorrow")
@app.route("/rlttrust/can-we-treat-tomorrow")
def rlttrust_can_we_treat_tomorrow():
    payload = {
        "isotope_hours_remaining": request.args.get("isotope_hours_remaining", 24),
        "qc_readiness": request.args.get("qc_readiness", 86),
        "qa_release_defensibility": request.args.get("qa_release_defensibility", 78),
        "custody_readiness": request.args.get("custody_readiness", 84),
        "cold_chain_readiness": request.args.get("cold_chain_readiness", 88),
        "treatment_site_readiness": request.args.get("treatment_site_readiness", 82),
        "sop_training_alignment": request.args.get("sop_training_alignment", 85),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "access_governance": request.args.get("access_governance", 80),
        "backup_restore_readiness": request.args.get("backup_restore_readiness", 88),
        "open_critical_capa": request.args.get("open_critical_capa", 1),
        "open_em_exception": request.args.get("open_em_exception", 1),
        "shipment_exception": request.args.get("shipment_exception", 0),
        "stale_evidence_items": request.args.get("stale_evidence_items", 2),
    }

    result = _rlttrust_can_we_treat_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Can We Treat Tomorrow? | RLTTrust™</title>
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
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.22), transparent 30%),
                    radial-gradient(circle at 90% 10%, rgba(255,159,28,0.16), transparent 35%),
                    linear-gradient(135deg, #050608 0%, #10131b 45%, #06070b 100%);
            }

            .wrap {
                max-width: 1840px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero {
                border: 1px solid rgba(255,122,24,0.32);
                border-radius: 34px;
                padding: 34px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.20), rgba(20,24,33,0.92) 38%, rgba(7,8,12,0.96)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 72px);
                box-shadow: 0 34px 120px rgba(0,0,0,0.55);
                position: relative;
                overflow: hidden;
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -130px;
                top: -170px;
                width: 540px;
                height: 540px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.24);
                box-shadow: inset 0 0 75px rgba(255,122,24,0.10), 0 0 90px rgba(255,122,24,0.13);
            }

            .hero-grid {
                display: grid;
                grid-template-columns: minmax(0, 1.6fr) minmax(380px, 0.72fr);
                gap: 28px;
                position: relative;
                z-index: 2;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .16em;
                font-weight: 900;
            }

            h1 {
                margin: 12px 0;
                font-size: clamp(44px, 5vw, 86px);
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

            .decision-card {
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
                font-weight: 900;
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
            }

            .section {
                margin-top: 30px;
            }

            .grid {
                display: grid;
                grid-template-columns: minmax(420px, .58fr) minmax(0, 1fr);
                gap: 22px;
                align-items: start;
            }

            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 16px;
            }

            .panel, .metric, .form-panel {
                border: 1px solid var(--line);
                border-radius: 26px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    var(--panel);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .panel, .form-panel {
                padding: 22px;
            }

            .metric {
                padding: 18px;
            }

            .metric strong {
                display: block;
                font-size: 28px;
                color: #fff2e6;
                margin-bottom: 8px;
            }

            .metric span {
                color: var(--muted);
                font-size: 13px;
            }

            .bar {
                height: 11px;
                border-radius: 999px;
                overflow: hidden;
                background: rgba(255,255,255,0.08);
                border: 1px solid rgba(255,255,255,0.07);
                margin-top: 12px;
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
                font-weight: 800;
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

            ul {
                margin: 10px 0 0 20px;
                padding: 0;
                color: var(--muted);
                line-height: 1.6;
            }

            li strong {
                color: #fff2e6;
            }

            .split {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 16px;
            }

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            @media (max-width: 1180px) {
                .hero-grid, .grid, .grid-3, .split, .form-grid {
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
                        <div class="eyebrow">RLTTrust™ Decision Engine</div>
                        <h1>Can We Treat Tomorrow?</h1>
                        <p>
                            A decay-aware governance engine that evaluates whether an IRLT operation can manufacture,
                            release, ship, receive, and support treatment tomorrow with defensible governed evidence.
                        </p>
                        <p>
                            This is advisory intelligence only. Final authority remains with QA, compliance,
                            system owners, and operational leadership.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Back to Command Center</a>
                            <a href="/irlt-commercial-readiness/passport">Governance Passport</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow/api">API Output</a>
                        </div>
                    </div>

                    <div class="decision-card">
                        <div class="eyebrow">Executive Answer</div>
                        <div class="score">{{ result.score }}%</div>
                        <span class="decision {{ result.decision_class }}">{{ result.decision }}</span>
                        <p>{{ result.executive_answer }}</p>
                        <p><strong style="color:#ffd7ad;">Time Pressure:</strong> {{ result.time_pressure }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Scenario Inputs</h2>
                    <p>Adjust the scenario and recalculate the treatment-readiness answer.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div>
                                <label>Isotope Hours Remaining</label>
                                <input name="isotope_hours_remaining" type="number" step="1" min="0" max="96" value="{{ result.inputs.isotope_hours_remaining }}">
                            </div>
                            <div>
                                <label>QC Readiness %</label>
                                <input name="qc_readiness" type="number" step="1" min="0" max="100" value="{{ result.inputs.qc_readiness }}">
                            </div>
                            <div>
                                <label>QA Release Defensibility %</label>
                                <input name="qa_release_defensibility" type="number" step="1" min="0" max="100" value="{{ result.inputs.qa_release_defensibility }}">
                            </div>
                            <div>
                                <label>Custody Readiness %</label>
                                <input name="custody_readiness" type="number" step="1" min="0" max="100" value="{{ result.inputs.custody_readiness }}">
                            </div>
                            <div>
                                <label>Cold Chain Readiness %</label>
                                <input name="cold_chain_readiness" type="number" step="1" min="0" max="100" value="{{ result.inputs.cold_chain_readiness }}">
                            </div>
                            <div>
                                <label>Treatment Site Readiness %</label>
                                <input name="treatment_site_readiness" type="number" step="1" min="0" max="100" value="{{ result.inputs.treatment_site_readiness }}">
                            </div>
                            <div>
                                <label>SOP / Training Alignment %</label>
                                <input name="sop_training_alignment" type="number" step="1" min="0" max="100" value="{{ result.inputs.sop_training_alignment }}">
                            </div>
                            <div>
                                <label>Evidence Integrity %</label>
                                <input name="evidence_integrity" type="number" step="1" min="0" max="100" value="{{ result.inputs.evidence_integrity }}">
                            </div>
                            <div>
                                <label>Access Governance %</label>
                                <input name="access_governance" type="number" step="1" min="0" max="100" value="{{ result.inputs.access_governance }}">
                            </div>
                            <div>
                                <label>Backup / Restore Readiness %</label>
                                <input name="backup_restore_readiness" type="number" step="1" min="0" max="100" value="{{ result.inputs.backup_restore_readiness }}">
                            </div>
                            <div>
                                <label>Open Critical CAPA / Deviation Count</label>
                                <input name="open_critical_capa" type="number" step="1" min="0" max="20" value="{{ result.inputs.open_critical_capa }}">
                            </div>
                            <div>
                                <label>Open EM Exception Count</label>
                                <input name="open_em_exception" type="number" step="1" min="0" max="20" value="{{ result.inputs.open_em_exception }}">
                            </div>
                            <div>
                                <label>Shipment Exception Count</label>
                                <input name="shipment_exception" type="number" step="1" min="0" max="20" value="{{ result.inputs.shipment_exception }}">
                            </div>
                            <div>
                                <label>Stale Evidence Items</label>
                                <input name="stale_evidence_items" type="number" step="1" min="0" max="100" value="{{ result.inputs.stale_evidence_items }}">
                            </div>
                        </div>

                        <button class="button" type="submit">Recalculate Tomorrow Readiness</button>
                    </form>
                </div>

                <div>
                    <div class="grid-3">
                        {% for name, value in result.component_scores.items() %}
                        <div class="metric">
                            <strong>{{ value }}%</strong>
                            <span>{{ name.replace("_", " ").title() }}</span>
                            <div class="bar"><span style="width: {{ value }}%;"></span></div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section split">
                <div class="panel">
                    <h2>Critical Blockers</h2>
                    {% if result.blockers %}
                    <ul>
                        {% for b in result.blockers %}
                        <li><strong>Blocker:</strong> {{ b }}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>No hard blockers detected in this scenario.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Governance Warnings</h2>
                    {% if result.warnings %}
                    <ul>
                        {% for w in result.warnings %}
                        <li><strong>Warning:</strong> {{ w }}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>No governance warnings detected in this scenario.</p>
                    {% endif %}
                </div>
            </section>

            <section class="section split">
                <div class="panel">
                    <h2>Recommended Actions</h2>
                    <ul>
                        {% for a in result.recommended_actions %}
                        <li>{{ a }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div class="panel">
                    <h2>Evidence Packets Needed</h2>
                    <ul>
                        {% for e in result.evidence_packets %}
                        <li>{{ e }}</li>
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


@app.route("/irlt-commercial-readiness/can-we-treat-tomorrow/api")
@app.route("/rlttrust/can-we-treat-tomorrow/api")
def rlttrust_can_we_treat_tomorrow_api():
    payload = {
        "isotope_hours_remaining": request.args.get("isotope_hours_remaining", 24),
        "qc_readiness": request.args.get("qc_readiness", 86),
        "qa_release_defensibility": request.args.get("qa_release_defensibility", 78),
        "custody_readiness": request.args.get("custody_readiness", 84),
        "cold_chain_readiness": request.args.get("cold_chain_readiness", 88),
        "treatment_site_readiness": request.args.get("treatment_site_readiness", 82),
        "sop_training_alignment": request.args.get("sop_training_alignment", 85),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "access_governance": request.args.get("access_governance", 80),
        "backup_restore_readiness": request.args.get("backup_restore_readiness", 88),
        "open_critical_capa": request.args.get("open_critical_capa", 1),
        "open_em_exception": request.args.get("open_em_exception", 1),
        "shipment_exception": request.args.get("shipment_exception", 0),
        "stale_evidence_items": request.args.get("stale_evidence_items", 2),
    }
    return jsonify(_rlttrust_can_we_treat_assessment(payload))

# ============================================================
# End Can We Treat Tomorrow? Engine™
# ============================================================

'''

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Can We Treat Tomorrow engine successfully.")

