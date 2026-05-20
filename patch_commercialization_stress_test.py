from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_COMMERCIALIZATION_STRESS_TEST_SIMULATOR_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Commercialization Stress Test Simulator already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_COMMERCIALIZATION_STRESS_TEST_SIMULATOR_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Commercialization Stress Test Simulator™
# Purpose: Executive what-if simulator for IRLT commercial scale-up failure scenarios.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_stress_num(value, default, minimum=0, maximum=1000):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_stress_int(value, default, minimum=0, maximum=1000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_commercialization_stress_assessment(payload=None):
    payload = payload or {}

    baseline_readiness = _rlttrust_stress_num(payload.get("baseline_readiness"), 84, 0, 100)
    qc_delay_hours = _rlttrust_stress_num(payload.get("qc_delay_hours"), 4, 0, 72)
    qa_release_delay_hours = _rlttrust_stress_num(payload.get("qa_release_delay_hours"), 3, 0, 72)
    hot_cell_outage_hours = _rlttrust_stress_num(payload.get("hot_cell_outage_hours"), 6, 0, 168)
    isotope_supply_delay_hours = _rlttrust_stress_num(payload.get("isotope_supply_delay_hours"), 5, 0, 168)
    courier_delay_minutes = _rlttrust_stress_num(payload.get("courier_delay_minutes"), 45, 0, 1440)
    treatment_hub_capacity_loss = _rlttrust_stress_num(payload.get("treatment_hub_capacity_loss"), 18, 0, 100)
    fallback_capacity = _rlttrust_stress_num(payload.get("fallback_capacity"), 68, 0, 100)
    evidence_integrity = _rlttrust_stress_num(payload.get("evidence_integrity"), 90, 0, 100)
    network_redundancy = _rlttrust_stress_num(payload.get("network_redundancy"), 72, 0, 100)
    communication_readiness = _rlttrust_stress_num(payload.get("communication_readiness"), 80, 0, 100)
    patient_slot_resilience = _rlttrust_stress_num(payload.get("patient_slot_resilience"), 76, 0, 100)
    release_defensibility = _rlttrust_stress_num(payload.get("release_defensibility"), 82, 0, 100)

    em_excursions = _rlttrust_stress_int(payload.get("em_excursions"), 1, 0, 50)
    open_capa = _rlttrust_stress_int(payload.get("open_capa"), 2, 0, 50)
    evidence_loss_items = _rlttrust_stress_int(payload.get("evidence_loss_items"), 3, 0, 100)
    custody_exceptions = _rlttrust_stress_int(payload.get("custody_exceptions"), 1, 0, 50)
    access_failures = _rlttrust_stress_int(payload.get("access_failures"), 1, 0, 50)
    backup_restore_gap = _rlttrust_stress_int(payload.get("backup_restore_gap"), 1, 0, 20)

    qc_penalty = min(qc_delay_hours * 2.1, 28)
    qa_penalty = min(qa_release_delay_hours * 2.4, 30)
    hot_cell_penalty = min(hot_cell_outage_hours * 1.6, 32)
    isotope_penalty = min(isotope_supply_delay_hours * 1.8, 32)
    courier_penalty = min(courier_delay_minutes / 8, 32)
    hub_penalty = min(treatment_hub_capacity_loss * 0.7, 30)
    em_penalty = min(em_excursions * 6, 30)
    capa_penalty = min(open_capa * 5, 30)
    evidence_penalty = min(evidence_loss_items * 4, 36)
    custody_penalty = min(custody_exceptions * 8, 32)
    access_penalty = min(access_failures * 5, 25)
    backup_penalty = min(backup_restore_gap * 8, 32)

    total_raw_stress = (
        qc_penalty + qa_penalty + hot_cell_penalty + isotope_penalty + courier_penalty +
        hub_penalty + em_penalty + capa_penalty + evidence_penalty + custody_penalty +
        access_penalty + backup_penalty
    )

    resilience_buffer = (
        fallback_capacity * 0.22 +
        network_redundancy * 0.20 +
        evidence_integrity * 0.18 +
        communication_readiness * 0.14 +
        patient_slot_resilience * 0.14 +
        release_defensibility * 0.12
    )

    buffer_credit = min(resilience_buffer * 0.42, 38)
    stress_penalty = max(0, min(total_raw_stress - buffer_credit, 72))

    survival_score = round(max(0, min(100, baseline_readiness - stress_penalty)))

    operational_damage = round(min(100, total_raw_stress))
    absorbed_damage = round(min(100, buffer_credit))
    unabsorbed_damage = round(max(0, total_raw_stress - buffer_credit))

    blockers = []
    warnings = []

    if qc_delay_hours >= 8:
        blockers.append("QC delay is severe enough to threaten isotope timing and release confidence.")
    elif qc_delay_hours >= 3:
        warnings.append("QC delay compresses QA release and treatment-window timing.")

    if qa_release_delay_hours >= 8:
        blockers.append("QA release delay threatens commercial release defensibility.")
    elif qa_release_delay_hours >= 2:
        warnings.append("QA release delay requires release war-room attention.")

    if hot_cell_outage_hours >= 12:
        blockers.append("Hot-cell outage threatens production continuity.")
    elif hot_cell_outage_hours > 0:
        warnings.append("Hot-cell outage may reduce commercial throughput.")

    if isotope_supply_delay_hours >= 10:
        blockers.append("Isotope supply delay threatens commercial dose availability.")
    elif isotope_supply_delay_hours > 0:
        warnings.append("Isotope supply delay creates downstream readiness pressure.")

    if courier_delay_minutes >= 180:
        blockers.append("Courier delay threatens patient-slot protection and dose viability.")
    elif courier_delay_minutes >= 30:
        warnings.append("Courier delay requires custody and ETA escalation.")

    if treatment_hub_capacity_loss >= 35:
        blockers.append("Treatment hub capacity loss threatens patient-slot availability.")
    elif treatment_hub_capacity_loss >= 10:
        warnings.append("Treatment hub capacity loss may constrain patient-slot protection.")

    if em_excursions >= 3:
        blockers.append("Multiple EM excursions create release and inspection exposure.")
    elif em_excursions > 0:
        warnings.append("EM excursion requires QA impact review before full readiness confidence.")

    if open_capa >= 4:
        blockers.append("Open CAPA volume is too high for clean commercial readiness claim.")
    elif open_capa > 0:
        warnings.append("Open CAPA items require closure defensibility review.")

    if evidence_loss_items >= 6:
        blockers.append("Evidence loss is material enough to weaken inspection survivability.")
    elif evidence_loss_items > 0:
        warnings.append("Evidence loss requires AuditVault™ recovery and evidence packet refresh.")

    if custody_exceptions >= 3:
        blockers.append("Custody exceptions threaten shipment and chain-of-custody defensibility.")
    elif custody_exceptions > 0:
        warnings.append("Custody exception must be reconciled before release-to-treatment confidence.")

    if access_failures >= 3:
        blockers.append("Access failures threaten accountability and audit trail trust.")
    elif access_failures > 0:
        warnings.append("Access issue requires AccessTrust™ owner attestation.")

    if backup_restore_gap >= 2:
        blockers.append("Backup/restore governance gap threatens operational continuity.")
    elif backup_restore_gap > 0:
        warnings.append("Backup/restore proof should be refreshed for continuity confidence.")

    if fallback_capacity < 55:
        warnings.append("Fallback capacity is weak if the primary node fails.")
    if network_redundancy < 65:
        warnings.append("Network redundancy is not strong enough for high-stress scale-up.")
    if communication_readiness < 75:
        warnings.append("Communication readiness may slow escalation and recovery.")
    if patient_slot_resilience < 75:
        warnings.append("Patient-slot resilience may not absorb release or logistics disruption.")

    if blockers:
        verdict = "FAIL — commercial stress not survivable"
        status_class = "blocked"
        executive_answer = "The commercial readiness model fails under this stress scenario. Critical operational or evidence controls must be recovered before leadership can defend readiness."
    elif survival_score >= 88 and len(warnings) <= 2:
        verdict = "PASS — stress survivable"
        status_class = "ready"
        executive_answer = "The IRLT network appears capable of surviving this stress scenario with defensible governance, subject to human leadership review."
    elif survival_score >= 78:
        verdict = "PASS WITH WARNINGS"
        status_class = "warning"
        executive_answer = "The network may survive the stress scenario, but leadership should review warnings and strengthen weak controls."
    elif survival_score >= 65:
        verdict = "AT RISK — recovery required"
        status_class = "gap"
        executive_answer = "The network may recover, but readiness is not defensible without corrective actions and evidence closure."
    else:
        verdict = "FAIL — not commercially defensible"
        status_class = "blocked"
        executive_answer = "The network is not commercially defensible under this stress scenario."

    stress_scenarios = [
        {
            "scenario": "QC Delay Shock",
            "score": round(max(0, 100 - qc_penalty - qa_penalty + (release_defensibility * 0.15))),
            "trigger": f"{qc_delay_hours}h QC delay and {qa_release_delay_hours}h QA delay.",
            "propagation": "QC delay → QA compression → isotope decay pressure → release confidence reduction → treatment-slot risk.",
            "control": "Activate Release Defensibility Engine™, QC readiness packet, and Can We Treat Tomorrow? Engine™."
        },
        {
            "scenario": "Hot-Cell Capacity Shock",
            "score": round(max(0, 100 - hot_cell_penalty - hub_penalty + (fallback_capacity * 0.18))),
            "trigger": f"{hot_cell_outage_hours}h hot-cell outage and {treatment_hub_capacity_loss}% treatment hub capacity loss.",
            "propagation": "Hot-cell outage → production queue → dose availability pressure → treatment hub re-planning.",
            "control": "Activate Network Readiness Mesh™, fallback production review, and capacity war-room."
        },
        {
            "scenario": "Isotope Supply Shock",
            "score": round(max(0, 100 - isotope_penalty - qc_penalty + (network_redundancy * 0.16))),
            "trigger": f"{isotope_supply_delay_hours}h isotope supply delay.",
            "propagation": "Isotope delay → manufacturing start delay → QC/QA compression → patient-slot pressure.",
            "control": "Trigger isotope contingency route, supplier readiness review, and treatment-slot protection."
        },
        {
            "scenario": "Courier / Cold-Chain Shock",
            "score": round(max(0, 100 - courier_penalty - custody_penalty + (communication_readiness * 0.14))),
            "trigger": f"{courier_delay_minutes} min courier delay and {custody_exceptions} custody exception(s).",
            "propagation": "Courier delay → custody uncertainty → treatment-site ETA risk → dose activity margin risk.",
            "control": "Run Isotope-to-Patient Evidence Graph™, custody escalation, and Patient Slot Protection Engine™."
        },
        {
            "scenario": "Inspection Evidence Shock",
            "score": round(max(0, 100 - evidence_penalty - backup_penalty + (evidence_integrity * 0.20))),
            "trigger": f"{evidence_loss_items} evidence gap(s) and {backup_restore_gap} backup/restore gap(s).",
            "propagation": "Evidence loss → audit response delay → release defensibility weakness → inspection survivability risk.",
            "control": "Run AuditVault™, Evidence Expiry Engine™, and Inspection Tomorrow Simulator™."
        },
        {
            "scenario": "Quality Event Shock",
            "score": round(max(0, 100 - em_penalty - capa_penalty + (release_defensibility * 0.18))),
            "trigger": f"{em_excursions} EM excursion(s) and {open_capa} open CAPA item(s).",
            "propagation": "Quality event → QA impact review → release risk → audit readiness warning.",
            "control": "Run CAPATrust™, EM impact review, and Release Defensibility Engine™."
        },
        {
            "scenario": "Access / Accountability Shock",
            "score": round(max(0, 100 - access_penalty - evidence_penalty + (network_data_integrity if 'network_data_integrity' in payload else 85) * 0.16)),
            "trigger": f"{access_failures} access/accountability failure(s).",
            "propagation": "Access failure → audit trail weakness → accountability challenge → release evidence exposure.",
            "control": "Run AccessTrust™, owner attestation, and AuditVault™ evidence verification."
        }
    ]

    stress_domains = [
        {
            "name": "Overall Stress Survival",
            "score": survival_score,
            "description": "Commercial readiness after stress penalties and resilience buffer."
        },
        {
            "name": "Raw Operational Damage",
            "score": operational_damage,
            "description": "Total modeled stress load across QC, QA, hot-cell, isotope, logistics, quality, access, and evidence."
        },
        {
            "name": "Resilience Absorption",
            "score": absorbed_damage,
            "description": "Damage absorbed by fallback capacity, redundancy, evidence integrity, communication, patient-slot resilience, and release defensibility."
        },
        {
            "name": "Unabsorbed Damage",
            "score": unabsorbed_damage,
            "description": "Remaining stress that leadership must mitigate through governance action."
        },
        {
            "name": "Fallback Capacity",
            "score": round(fallback_capacity),
            "description": "Ability to shift work, release, logistics, or treatment coordination when primary path is constrained."
        },
        {
            "name": "Evidence Integrity",
            "score": round(evidence_integrity),
            "description": "Ability to preserve audit-ready evidence despite disruption."
        },
        {
            "name": "Patient-Slot Resilience",
            "score": round(patient_slot_resilience),
            "description": "Ability to protect treatment windows under release, logistics, or site disruptions."
        },
        {
            "name": "Release Defensibility",
            "score": round(release_defensibility),
            "description": "Ability to defend QA release under timing, quality, and evidence pressure."
        }
    ]

    war_room_actions = []
    for b in blockers:
        war_room_actions.append("Critical recovery action: " + b)
    for w in warnings[:8]:
        war_room_actions.append("Governance action: " + w)

    if qc_delay_hours > 0 or qa_release_delay_hours > 0:
        war_room_actions.append("Open QC/QA release war-room and generate release delay impact packet.")
    if hot_cell_outage_hours > 0:
        war_room_actions.append("Run hot-cell capacity recovery plan and fallback manufacturing readiness review.")
    if isotope_supply_delay_hours > 0:
        war_room_actions.append("Trigger isotope supply contingency and downstream timing reforecast.")
    if courier_delay_minutes > 0 or custody_exceptions > 0:
        war_room_actions.append("Escalate courier/custody route and regenerate shipment evidence packet.")
    if evidence_loss_items > 0:
        war_room_actions.append("Run AuditVault™ evidence recovery and produce inspection survivability packet.")
    if treatment_hub_capacity_loss > 0:
        war_room_actions.append("Run Patient Slot Protection Engine™ for affected treatment hubs.")

    if not war_room_actions:
        war_room_actions.append("Proceed to executive commercialization readiness confirmation and export stress test passport.")

    leadership_questions = [
        {
            "question": "Can commercial release survive a QC/QA delay?",
            "answer": "Yes with warnings" if survival_score >= 78 and not blockers else "Not fully defensible",
            "evidence": "QC delay model, QA release delay model, Release Defensibility Engine™, and Can We Treat Tomorrow? output."
        },
        {
            "question": "Can the network absorb a hot-cell or site disruption?",
            "answer": "Depends on fallback strength" if fallback_capacity < 80 else "Fallback coverage appears credible",
            "evidence": "Hot-cell outage scenario, fallback capacity, network redundancy, and Network Readiness Mesh™."
        },
        {
            "question": "Can patient treatment windows still be protected?",
            "answer": "Warning" if patient_slot_resilience < 82 or courier_delay_minutes > 30 else "Currently protected",
            "evidence": "Patient Slot Protection Engine™, courier delay model, custody exceptions, and treatment hub capacity."
        },
        {
            "question": "Can we defend readiness if evidence is lost or stale?",
            "answer": "Warning" if evidence_loss_items > 0 else "Currently defensible",
            "evidence": "AuditVault™ verification, evidence loss count, backup/restore gap, and Inspection Tomorrow Simulator™."
        },
        {
            "question": "Should leadership claim commercial readiness under this stress?",
            "answer": verdict,
            "evidence": "Stress survival score, blockers, warnings, resilience absorption, and war-room action list."
        }
    ]

    passport_outputs = [
        "Commercialization Stress Test Passport",
        "Executive Stress Survival Packet",
        "QC/QA Delay Impact Packet",
        "Hot-Cell Outage Recovery Packet",
        "Isotope Supply Disruption Packet",
        "Courier / Cold-Chain Stress Packet",
        "Quality Event Stress Packet",
        "Evidence Loss Recovery Packet",
        "Patient Slot Resilience Packet",
        "Commercial Readiness War-Room Packet"
    ]

    return {
        "survival_score": survival_score,
        "verdict": verdict,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "operational_damage": operational_damage,
        "absorbed_damage": absorbed_damage,
        "unabsorbed_damage": unabsorbed_damage,
        "stress_penalty": round(stress_penalty),
        "resilience_buffer": round(buffer_credit),
        "blockers": blockers,
        "warnings": warnings,
        "stress_scenarios": stress_scenarios,
        "stress_domains": stress_domains,
        "war_room_actions": war_room_actions,
        "leadership_questions": leadership_questions,
        "passport_outputs": passport_outputs,
        "inputs": {
            "baseline_readiness": baseline_readiness,
            "qc_delay_hours": qc_delay_hours,
            "qa_release_delay_hours": qa_release_delay_hours,
            "hot_cell_outage_hours": hot_cell_outage_hours,
            "isotope_supply_delay_hours": isotope_supply_delay_hours,
            "courier_delay_minutes": courier_delay_minutes,
            "treatment_hub_capacity_loss": treatment_hub_capacity_loss,
            "fallback_capacity": fallback_capacity,
            "evidence_integrity": evidence_integrity,
            "network_redundancy": network_redundancy,
            "communication_readiness": communication_readiness,
            "patient_slot_resilience": patient_slot_resilience,
            "release_defensibility": release_defensibility,
            "em_excursions": em_excursions,
            "open_capa": open_capa,
            "evidence_loss_items": evidence_loss_items,
            "custody_exceptions": custody_exceptions,
            "access_failures": access_failures,
            "backup_restore_gap": backup_restore_gap
        },
        "governance_note": "This simulator is advisory operational governance support. It does not replace QA release, radiation safety authority, clinical decisions, logistics control systems, regulatory judgment, or human leadership approval."
    }


@app.route("/irlt-commercial-readiness/commercialization-stress-test")
@app.route("/rlttrust/commercialization-stress-test")
@app.route("/rlttrust/stress-test-simulator")
def rlttrust_commercialization_stress_test_simulator():
    payload = {
        "baseline_readiness": request.args.get("baseline_readiness", 84),
        "qc_delay_hours": request.args.get("qc_delay_hours", 4),
        "qa_release_delay_hours": request.args.get("qa_release_delay_hours", 3),
        "hot_cell_outage_hours": request.args.get("hot_cell_outage_hours", 6),
        "isotope_supply_delay_hours": request.args.get("isotope_supply_delay_hours", 5),
        "courier_delay_minutes": request.args.get("courier_delay_minutes", 45),
        "treatment_hub_capacity_loss": request.args.get("treatment_hub_capacity_loss", 18),
        "fallback_capacity": request.args.get("fallback_capacity", 68),
        "evidence_integrity": request.args.get("evidence_integrity", 90),
        "network_redundancy": request.args.get("network_redundancy", 72),
        "communication_readiness": request.args.get("communication_readiness", 80),
        "patient_slot_resilience": request.args.get("patient_slot_resilience", 76),
        "release_defensibility": request.args.get("release_defensibility", 82),
        "em_excursions": request.args.get("em_excursions", 1),
        "open_capa": request.args.get("open_capa", 2),
        "evidence_loss_items": request.args.get("evidence_loss_items", 3),
        "custody_exceptions": request.args.get("custody_exceptions", 1),
        "access_failures": request.args.get("access_failures", 1),
        "backup_restore_gap": request.args.get("backup_restore_gap", 1),
    }

    result = _rlttrust_commercialization_stress_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Commercialization Stress Test Simulator™ | RLTTrust™</title>
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
                max-width: 1920px;
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

            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 16px;
            }

            .panel, .form-panel, .metric, .scenario-card {
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

            .scenario-score {
                font-size: 42px;
                font-weight: 950;
                color: var(--orange2);
                letter-spacing: -.06em;
                margin: 10px 0;
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
                .hero-grid, .grid, .grid-2, .grid-3, .grid-4, .form-grid {
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
                        <div class="eyebrow">RLTTrust™ Executive What-If Failure Lab</div>
                        <h1>Commercialization Stress Test Simulator™</h1>
                        <p>
                            A stress-test engine for commercial IRLT scale-up. It simulates QC delay, QA release delay,
                            hot-cell outage, isotope supply delay, courier/cold-chain disruption, EM excursion, CAPA pressure,
                            treatment hub constraint, access failure, backup gap, and evidence loss.
                        </p>
                        <p>
                            It answers whether the commercial readiness model survives disruption with governed evidence,
                            patient-slot protection, release defensibility, and inspection survivability.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/patient-slot-protection">Patient Slot Protection</a>
                            <a href="/irlt-commercial-readiness/network-readiness-mesh">Network Mesh</a>
                            <a href="/irlt-commercial-readiness/commercialization-stress-test/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Stress Survival Score</div>
                        <div class="score">{{ result.survival_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.verdict }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Stress Scenario Inputs</h2>
                    <p>Adjust disruption values and rerun the commercialization stress test.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Baseline Readiness %</label><input name="baseline_readiness" type="number" min="0" max="100" value="{{ result.inputs.baseline_readiness }}"></div>
                            <div><label>QC Delay Hours</label><input name="qc_delay_hours" type="number" step="0.1" min="0" max="72" value="{{ result.inputs.qc_delay_hours }}"></div>
                            <div><label>QA Release Delay Hours</label><input name="qa_release_delay_hours" type="number" step="0.1" min="0" max="72" value="{{ result.inputs.qa_release_delay_hours }}"></div>
                            <div><label>Hot-Cell Outage Hours</label><input name="hot_cell_outage_hours" type="number" step="0.1" min="0" max="168" value="{{ result.inputs.hot_cell_outage_hours }}"></div>
                            <div><label>Isotope Supply Delay Hours</label><input name="isotope_supply_delay_hours" type="number" step="0.1" min="0" max="168" value="{{ result.inputs.isotope_supply_delay_hours }}"></div>
                            <div><label>Courier Delay Minutes</label><input name="courier_delay_minutes" type="number" step="1" min="0" max="1440" value="{{ result.inputs.courier_delay_minutes }}"></div>
                            <div><label>Treatment Hub Capacity Loss %</label><input name="treatment_hub_capacity_loss" type="number" min="0" max="100" value="{{ result.inputs.treatment_hub_capacity_loss }}"></div>
                            <div><label>Fallback Capacity %</label><input name="fallback_capacity" type="number" min="0" max="100" value="{{ result.inputs.fallback_capacity }}"></div>
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Network Redundancy %</label><input name="network_redundancy" type="number" min="0" max="100" value="{{ result.inputs.network_redundancy }}"></div>
                            <div><label>Communication Readiness %</label><input name="communication_readiness" type="number" min="0" max="100" value="{{ result.inputs.communication_readiness }}"></div>
                            <div><label>Patient Slot Resilience %</label><input name="patient_slot_resilience" type="number" min="0" max="100" value="{{ result.inputs.patient_slot_resilience }}"></div>
                            <div><label>Release Defensibility %</label><input name="release_defensibility" type="number" min="0" max="100" value="{{ result.inputs.release_defensibility }}"></div>
                            <div><label>EM Excursions</label><input name="em_excursions" type="number" min="0" max="50" value="{{ result.inputs.em_excursions }}"></div>
                            <div><label>Open CAPA Count</label><input name="open_capa" type="number" min="0" max="50" value="{{ result.inputs.open_capa }}"></div>
                            <div><label>Evidence Loss Items</label><input name="evidence_loss_items" type="number" min="0" max="100" value="{{ result.inputs.evidence_loss_items }}"></div>
                            <div><label>Custody Exceptions</label><input name="custody_exceptions" type="number" min="0" max="50" value="{{ result.inputs.custody_exceptions }}"></div>
                            <div><label>Access Failures</label><input name="access_failures" type="number" min="0" max="50" value="{{ result.inputs.access_failures }}"></div>
                            <div><label>Backup / Restore Gap</label><input name="backup_restore_gap" type="number" min="0" max="20" value="{{ result.inputs.backup_restore_gap }}"></div>
                        </div>
                        <button class="button" type="submit">Run Commercialization Stress Test</button>
                    </form>
                </div>

                <div>
                    <h2>Stress Survival Domains</h2>
                    <div class="grid-4">
                        {% for d in result.stress_domains %}
                        <div class="metric">
                            <strong>{{ d.score }}%</strong>
                            <span>{{ d.name }}</span>
                            <div class="bar"><span style="width: {{ d.score }}%;"></span></div>
                            <p>{{ d.description }}</p>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section grid-3">
                {% for s in result.stress_scenarios %}
                <div class="scenario-card">
                    <div class="eyebrow">{{ s.scenario }}</div>
                    <div class="scenario-score">{{ s.score }}%</div>
                    <p><strong style="color:#fff2e6;">Trigger:</strong> {{ s.trigger }}</p>
                    <p><strong style="color:#fff2e6;">Propagation:</strong> {{ s.propagation }}</p>
                    <p><strong style="color:#fff2e6;">Control:</strong> {{ s.control }}</p>
                    <div class="bar"><span style="width: {{ s.score }}%;"></span></div>
                </div>
                {% endfor %}
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
                    <p>No blockers or warnings detected in this stress scenario.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Commercial Readiness War-Room Actions</h2>
                    <ul>
                        {% for action in result.war_room_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Leadership Question-to-Evidence Layer</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Leadership Question</th>
                                <th>Answer</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in result.leadership_questions %}
                            <tr>
                                <td><strong>{{ q.question }}</strong></td>
                                <td>{{ q.answer }}</td>
                                <td>{{ q.evidence }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Stress Test Passport Outputs</h2>
                    <p>These are the artifacts this simulator can generate for executive review and audit defensibility.</p>
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


@app.route("/irlt-commercial-readiness/commercialization-stress-test/api")
@app.route("/rlttrust/commercialization-stress-test/api")
@app.route("/rlttrust/stress-test-simulator/api")
def rlttrust_commercialization_stress_test_simulator_api():
    payload = {
        "baseline_readiness": request.args.get("baseline_readiness", 84),
        "qc_delay_hours": request.args.get("qc_delay_hours", 4),
        "qa_release_delay_hours": request.args.get("qa_release_delay_hours", 3),
        "hot_cell_outage_hours": request.args.get("hot_cell_outage_hours", 6),
        "isotope_supply_delay_hours": request.args.get("isotope_supply_delay_hours", 5),
        "courier_delay_minutes": request.args.get("courier_delay_minutes", 45),
        "treatment_hub_capacity_loss": request.args.get("treatment_hub_capacity_loss", 18),
        "fallback_capacity": request.args.get("fallback_capacity", 68),
        "evidence_integrity": request.args.get("evidence_integrity", 90),
        "network_redundancy": request.args.get("network_redundancy", 72),
        "communication_readiness": request.args.get("communication_readiness", 80),
        "patient_slot_resilience": request.args.get("patient_slot_resilience", 76),
        "release_defensibility": request.args.get("release_defensibility", 82),
        "em_excursions": request.args.get("em_excursions", 1),
        "open_capa": request.args.get("open_capa", 2),
        "evidence_loss_items": request.args.get("evidence_loss_items", 3),
        "custody_exceptions": request.args.get("custody_exceptions", 1),
        "access_failures": request.args.get("access_failures", 1),
        "backup_restore_gap": request.args.get("backup_restore_gap", 1),
    }
    return jsonify(_rlttrust_commercialization_stress_assessment(payload))

# ============================================================
# End Commercialization Stress Test Simulator™
# ============================================================

'''

    # Add Commercialization Stress Test link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_COMMERCIALIZATION_STRESS_TEST_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/network-readiness-mesh">Network Readiness Mesh</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_COMMERCIALIZATION_STRESS_TEST_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/commercialization-stress-test">Stress Test</a>',
            1
        )
        print("Added Commercialization Stress Test link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Commercialization Stress Test Simulator successfully.")

