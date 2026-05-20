from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_PATIENT_SLOT_PROTECTION_ENGINE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Patient Slot Protection Engine already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_PATIENT_SLOT_PROTECTION_ENGINE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Patient Slot Protection Engine™
# Purpose: Protect treatment-slot readiness using isotope timing, release readiness,
#          logistics, treatment-site readiness, and governed evidence.
# AI is advisory only. Human clinical, QA, radiation safety, and operational governance remain authoritative.
# No PHI is stored or required in this prototype.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_slot_num(value, default, minimum=0, maximum=1000):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_slot_int(value, default, minimum=0, maximum=1000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_patient_slot_protection_assessment(payload=None):
    payload = payload or {}

    isotope_hours_remaining = _rlttrust_slot_num(payload.get("isotope_hours_remaining"), 22, 0, 96)
    treatment_window_hours = _rlttrust_slot_num(payload.get("treatment_window_hours"), 18, 0, 96)
    courier_delay_minutes = _rlttrust_slot_num(payload.get("courier_delay_minutes"), 35, 0, 1440)

    release_defensibility = _rlttrust_slot_num(payload.get("release_defensibility"), 82, 0, 100)
    site_readiness = _rlttrust_slot_num(payload.get("site_readiness"), 84, 0, 100)
    authorized_user_readiness = _rlttrust_slot_num(payload.get("authorized_user_readiness"), 86, 0, 100)
    appointment_confirmation = _rlttrust_slot_num(payload.get("appointment_confirmation"), 88, 0, 100)
    custody_arrival_confidence = _rlttrust_slot_num(payload.get("custody_arrival_confidence"), 83, 0, 100)
    dose_activity_margin = _rlttrust_slot_num(payload.get("dose_activity_margin"), 78, 0, 100)
    evidence_integrity = _rlttrust_slot_num(payload.get("evidence_integrity"), 91, 0, 100)
    communication_readiness = _rlttrust_slot_num(payload.get("communication_readiness"), 82, 0, 100)
    backup_slot_availability = _rlttrust_slot_num(payload.get("backup_slot_availability"), 62, 0, 100)
    patient_admin_clearance = _rlttrust_slot_num(payload.get("patient_admin_clearance"), 87, 0, 100)

    open_site_exceptions = _rlttrust_slot_int(payload.get("open_site_exceptions"), 1, 0, 50)
    scheduling_conflicts = _rlttrust_slot_int(payload.get("scheduling_conflicts"), 1, 0, 50)
    missing_slot_evidence = _rlttrust_slot_int(payload.get("missing_slot_evidence"), 2, 0, 100)
    custody_exceptions = _rlttrust_slot_int(payload.get("custody_exceptions"), 0, 0, 50)
    communication_breaks = _rlttrust_slot_int(payload.get("communication_breaks"), 1, 0, 50)

    # Time alignment logic:
    # If remaining isotope window is smaller than the treatment window, the dose journey becomes time-compressed.
    time_margin_hours = round(isotope_hours_remaining - treatment_window_hours, 2)

    if time_margin_hours >= 8:
        time_alignment_score = 100
        time_pressure = "Low"
    elif time_margin_hours >= 4:
        time_alignment_score = 90
        time_pressure = "Moderate"
    elif time_margin_hours >= 1:
        time_alignment_score = 76
        time_pressure = "High"
    elif time_margin_hours >= 0:
        time_alignment_score = 62
        time_pressure = "Severe"
    else:
        time_alignment_score = 38
        time_pressure = "Critical"

    delay_penalty = min(courier_delay_minutes / 6, 35)
    site_penalty = min(open_site_exceptions * 7, 35)
    schedule_penalty = min(scheduling_conflicts * 8, 40)
    evidence_penalty = min(missing_slot_evidence * 4, 32)
    custody_penalty = min(custody_exceptions * 10, 40)
    communication_penalty = min(communication_breaks * 6, 30)

    logistics_score = max(0, custody_arrival_confidence - delay_penalty - custody_penalty)
    site_operational_score = max(0, ((site_readiness + authorized_user_readiness) / 2) - site_penalty)
    schedule_score = max(0, ((appointment_confirmation + patient_admin_clearance) / 2) - schedule_penalty)
    evidence_score = max(0, evidence_integrity - evidence_penalty)
    communication_score = max(0, communication_readiness - communication_penalty)

    protection_score = round(
        time_alignment_score * 0.16 +
        release_defensibility * 0.14 +
        logistics_score * 0.13 +
        site_operational_score * 0.13 +
        schedule_score * 0.12 +
        dose_activity_margin * 0.10 +
        evidence_score * 0.10 +
        communication_score * 0.07 +
        backup_slot_availability * 0.05
    )

    blockers = []
    warnings = []

    if time_margin_hours < 0:
        blockers.append("Treatment window is outside the remaining isotope readiness window.")
    elif time_margin_hours < 1:
        warnings.append("Treatment window is under severe timing pressure.")
    elif time_margin_hours < 4:
        warnings.append("Treatment window has limited timing margin.")

    if release_defensibility < 70:
        blockers.append("QA release defensibility is too weak to protect the treatment slot.")
    elif release_defensibility < 85:
        warnings.append("QA release defensibility needs strengthening before slot confidence improves.")

    if logistics_score < 70:
        blockers.append("Courier/custody arrival confidence is below protected-slot threshold.")
    elif logistics_score < 85:
        warnings.append("Courier/custody readiness has timing or exception warnings.")

    if site_operational_score < 70:
        blockers.append("Treatment-site operational readiness is below threshold.")
    elif site_operational_score < 85:
        warnings.append("Treatment-site readiness needs confirmation.")

    if schedule_score < 70:
        blockers.append("Appointment/admin readiness is not sufficiently aligned.")
    elif schedule_score < 85:
        warnings.append("Appointment or administrative readiness has governance warnings.")

    if dose_activity_margin < 70:
        blockers.append("Dose activity margin is too weak for protected treatment-slot confidence.")
    elif dose_activity_margin < 85:
        warnings.append("Dose activity margin is under pressure.")

    if evidence_score < 75:
        blockers.append("Patient-slot evidence package is incomplete or weak.")
    elif evidence_score < 88:
        warnings.append("Patient-slot evidence packet has missing records.")

    if communication_score < 75:
        warnings.append("Communication readiness has breakdown risk.")

    if backup_slot_availability < 50:
        warnings.append("Backup slot availability is weak if the primary slot fails.")

    if open_site_exceptions >= 2:
        blockers.append("Multiple open treatment-site exceptions remain unresolved.")
    elif open_site_exceptions == 1:
        warnings.append("One treatment-site exception requires owner disposition.")

    if scheduling_conflicts >= 2:
        blockers.append("Multiple scheduling conflicts threaten treatment-slot protection.")
    elif scheduling_conflicts == 1:
        warnings.append("One scheduling conflict requires coordination closure.")

    if blockers:
        decision = "NOT PROTECTED — treatment slot at risk"
        status_class = "blocked"
        executive_answer = "The treatment slot should not be considered protected until blockers are resolved and human governance approves the evidence."
    elif protection_score >= 90 and len(warnings) <= 1:
        decision = "PROTECTED — ready for final human review"
        status_class = "ready"
        executive_answer = "The treatment slot appears protected with strong timing, release, logistics, site, schedule, and evidence readiness."
    elif protection_score >= 82:
        decision = "PROTECTED WITH WARNINGS"
        status_class = "warning"
        executive_answer = "The treatment slot may be protectable, but leadership should review governance warnings before final confidence."
    elif protection_score >= 70:
        decision = "AT RISK — evidence or timing gaps remain"
        status_class = "gap"
        executive_answer = "The treatment slot has enough structure to recover, but gaps remain before it can be considered protected."
    else:
        decision = "NOT PROTECTED — operationally fragile"
        status_class = "blocked"
        executive_answer = "The treatment slot is not protected under the current operational governance posture."

    slot_gates = [
        {
            "gate": "Isotope Timing Gate",
            "score": round(time_alignment_score),
            "status": "Pass" if time_alignment_score >= 85 else "Warning" if time_alignment_score >= 70 else "Fail",
            "evidence": "Remaining isotope window, treatment window, time-margin calculation, decay-aware readiness status.",
            "owner": "Radiopharma Operations / QA"
        },
        {
            "gate": "Release-to-Treatment Gate",
            "score": round(release_defensibility),
            "status": "Pass" if release_defensibility >= 85 else "Warning" if release_defensibility >= 70 else "Fail",
            "evidence": "QA release defensibility, QC packet, CAPA/EM disposition, release rationale.",
            "owner": "QA Release"
        },
        {
            "gate": "Courier / Custody Arrival Gate",
            "score": round(logistics_score),
            "status": "Pass" if logistics_score >= 85 else "Warning" if logistics_score >= 70 else "Fail",
            "evidence": "Courier ETA, custody transfer, shipment exception log, cold-chain evidence, receipt forecast.",
            "owner": "Logistics / Supply Chain"
        },
        {
            "gate": "Treatment-Site Readiness Gate",
            "score": round(site_operational_score),
            "status": "Pass" if site_operational_score >= 85 else "Warning" if site_operational_score >= 70 else "Fail",
            "evidence": "Site readiness attestation, authorized user readiness, nuclear medicine readiness, site exception status.",
            "owner": "Treatment Site / Nuclear Medicine"
        },
        {
            "gate": "Appointment / Admin Gate",
            "score": round(schedule_score),
            "status": "Pass" if schedule_score >= 85 else "Warning" if schedule_score >= 70 else "Fail",
            "evidence": "Appointment confirmation, admin clearance, dose-to-slot match, scheduling conflict closure.",
            "owner": "Treatment Coordination"
        },
        {
            "gate": "Dose Activity Margin Gate",
            "score": round(dose_activity_margin),
            "status": "Pass" if dose_activity_margin >= 85 else "Warning" if dose_activity_margin >= 70 else "Fail",
            "evidence": "Dose activity margin, decay-aware timing assessment, release-to-arrival confidence.",
            "owner": "Radiopharma Operations / Radiation Safety"
        },
        {
            "gate": "Evidence Integrity Gate",
            "score": round(evidence_score),
            "status": "Pass" if evidence_score >= 88 and missing_slot_evidence == 0 else "Warning" if evidence_score >= 75 else "Fail",
            "evidence": "AuditVault™ evidence verification, missing evidence review, slot readiness packet, passport linkage.",
            "owner": "QA / Compliance"
        },
        {
            "gate": "Communication Gate",
            "score": round(communication_score),
            "status": "Pass" if communication_score >= 85 and communication_breaks == 0 else "Warning" if communication_score >= 75 else "Fail",
            "evidence": "Manufacturing-QA-logistics-site communication record, escalation acknowledgement, owner response.",
            "owner": "Operations Coordination"
        },
        {
            "gate": "Backup Slot Gate",
            "score": round(backup_slot_availability),
            "status": "Pass" if backup_slot_availability >= 80 else "Warning" if backup_slot_availability >= 50 else "Fail",
            "evidence": "Backup slot availability, contingency plan, escalation criteria, leadership approval.",
            "owner": "Treatment Coordination / Leadership"
        }
    ]

    risk_chains = [
        {
            "trigger": "QC or QA release delay",
            "propagation": "Release delay → isotope time margin shrinks → courier window compresses → treatment slot risk increases.",
            "control": "Activate Release Defensibility Engine™ and Decay-Aware Commercial Readiness Twin™."
        },
        {
            "trigger": "Courier delay",
            "propagation": "Courier delay → site receipt uncertainty → dose activity margin pressure → appointment risk.",
            "control": "Escalate custody ETA, confirm site readiness, and activate backup slot review."
        },
        {
            "trigger": "Treatment-site readiness gap",
            "propagation": "Site gap → receipt/authorized-user uncertainty → treatment slot cannot be protected.",
            "control": "Require site readiness attestation and treatment coordination closure."
        },
        {
            "trigger": "Missing slot evidence",
            "propagation": "Missing evidence → passport incomplete → leadership cannot defend treatment-readiness status.",
            "control": "Upload and hash evidence into AuditVault™ and regenerate Treatment Readiness Passport."
        },
        {
            "trigger": "Scheduling conflict",
            "propagation": "Schedule conflict → patient-slot mismatch → viable dose may become operationally unusable.",
            "control": "Resolve dose-to-slot match and document coordination approval."
        }
    ]

    slot_scenarios = [
        {
            "slot_id": "SLOT-001",
            "status": "Protected with Warnings",
            "dose_window": "22h remaining",
            "treatment_window": "18h target",
            "risk": "Limited timing margin and one site exception.",
            "action": "Confirm site readiness and strengthen release rationale."
        },
        {
            "slot_id": "SLOT-002",
            "status": "At Risk",
            "dose_window": "12h remaining",
            "treatment_window": "14h target",
            "risk": "Treatment window exceeds dose-readiness window.",
            "action": "Escalate to treatment coordination and evaluate backup slot."
        },
        {
            "slot_id": "SLOT-003",
            "status": "Protected",
            "dose_window": "30h remaining",
            "treatment_window": "20h target",
            "risk": "No major timing risk.",
            "action": "Proceed to final human governance review."
        }
    ]

    evidence_packets = [
        "Treatment-slot readiness packet",
        "Dose-to-slot match evidence",
        "QA release-to-treatment linkage",
        "Courier ETA and custody evidence",
        "Treatment-site receipt/readiness attestation",
        "Authorized user readiness evidence",
        "Appointment/admin clearance evidence",
        "Dose activity margin assessment",
        "Communication and escalation record",
        "Backup slot contingency plan",
        "AuditVault™ evidence verification",
        "Treatment Readiness Passport"
    ]

    recommended_actions = []
    for b in blockers:
        recommended_actions.append("Resolve blocker: " + b)
    for w in warnings[:6]:
        recommended_actions.append("Review warning: " + w)

    if not recommended_actions:
        recommended_actions.append("Proceed to final treatment-readiness review and generate Treatment Readiness Passport.")

    component_scores = {
        "Time Alignment": round(time_alignment_score),
        "Release Defensibility": round(release_defensibility),
        "Courier / Custody": round(logistics_score),
        "Treatment Site": round(site_operational_score),
        "Appointment / Admin": round(schedule_score),
        "Dose Activity Margin": round(dose_activity_margin),
        "Evidence Integrity": round(evidence_score),
        "Communication": round(communication_score),
        "Backup Slot": round(backup_slot_availability)
    }

    passport_outputs = [
        "Treatment Readiness Passport",
        "Patient Slot Protection Passport",
        "Dose-to-Slot Match Packet",
        "Release-to-Treatment Evidence Packet",
        "Courier / Custody Arrival Packet",
        "Treatment-Site Readiness Packet",
        "Slot Risk Escalation Packet",
        "AuditVault™ Slot Evidence Packet"
    ]

    return {
        "protection_score": protection_score,
        "decision": decision,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "time_margin_hours": time_margin_hours,
        "time_pressure": time_pressure,
        "blockers": blockers,
        "warnings": warnings,
        "slot_gates": slot_gates,
        "risk_chains": risk_chains,
        "slot_scenarios": slot_scenarios,
        "evidence_packets": evidence_packets,
        "recommended_actions": recommended_actions,
        "component_scores": component_scores,
        "passport_outputs": passport_outputs,
        "inputs": {
            "isotope_hours_remaining": isotope_hours_remaining,
            "treatment_window_hours": treatment_window_hours,
            "courier_delay_minutes": courier_delay_minutes,
            "release_defensibility": release_defensibility,
            "site_readiness": site_readiness,
            "authorized_user_readiness": authorized_user_readiness,
            "appointment_confirmation": appointment_confirmation,
            "custody_arrival_confidence": custody_arrival_confidence,
            "dose_activity_margin": dose_activity_margin,
            "evidence_integrity": evidence_integrity,
            "communication_readiness": communication_readiness,
            "backup_slot_availability": backup_slot_availability,
            "patient_admin_clearance": patient_admin_clearance,
            "open_site_exceptions": open_site_exceptions,
            "scheduling_conflicts": scheduling_conflicts,
            "missing_slot_evidence": missing_slot_evidence,
            "custody_exceptions": custody_exceptions,
            "communication_breaks": communication_breaks
        },
        "governance_note": "This engine is operational governance support only. It does not make clinical decisions, does not process PHI, and does not replace QA, radiation safety, clinical, or treatment-site authority."
    }


@app.route("/irlt-commercial-readiness/patient-slot-protection")
@app.route("/rlttrust/patient-slot-protection")
@app.route("/rlttrust/patient-slot-protection-engine")
def rlttrust_patient_slot_protection_engine():
    payload = {
        "isotope_hours_remaining": request.args.get("isotope_hours_remaining", 22),
        "treatment_window_hours": request.args.get("treatment_window_hours", 18),
        "courier_delay_minutes": request.args.get("courier_delay_minutes", 35),
        "release_defensibility": request.args.get("release_defensibility", 82),
        "site_readiness": request.args.get("site_readiness", 84),
        "authorized_user_readiness": request.args.get("authorized_user_readiness", 86),
        "appointment_confirmation": request.args.get("appointment_confirmation", 88),
        "custody_arrival_confidence": request.args.get("custody_arrival_confidence", 83),
        "dose_activity_margin": request.args.get("dose_activity_margin", 78),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "communication_readiness": request.args.get("communication_readiness", 82),
        "backup_slot_availability": request.args.get("backup_slot_availability", 62),
        "patient_admin_clearance": request.args.get("patient_admin_clearance", 87),
        "open_site_exceptions": request.args.get("open_site_exceptions", 1),
        "scheduling_conflicts": request.args.get("scheduling_conflicts", 1),
        "missing_slot_evidence": request.args.get("missing_slot_evidence", 2),
        "custody_exceptions": request.args.get("custody_exceptions", 0),
        "communication_breaks": request.args.get("communication_breaks", 1),
    }

    result = _rlttrust_patient_slot_protection_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Patient Slot Protection Engine™ | RLTTrust™</title>
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

            .panel, .form-panel, .metric, .gate-card, .slot-card {
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
                        <div class="eyebrow">RLTTrust™ Patient-Impact Governance</div>
                        <h1>Patient Slot Protection Engine™</h1>
                        <p>
                            A decay-aware operational governance engine that checks whether isotope timing, QA release,
                            courier/custody movement, treatment-site readiness, appointment alignment, dose activity margin,
                            and governed evidence still protect the scheduled treatment window.
                        </p>
                        <p>
                            This prototype does not use PHI and does not make clinical decisions. It protects operational readiness,
                            evidence defensibility, and treatment-slot coordination.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/patient-slot-protection/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Slot Protection Score</div>
                        <div class="score">{{ result.protection_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.decision }}</span>
                        <p>{{ result.executive_answer }}</p>
                        <p><strong style="color:#ffd7ad;">Time Margin:</strong> {{ result.time_margin_hours }} hours</p>
                        <p><strong style="color:#ffd7ad;">Time Pressure:</strong> {{ result.time_pressure }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Slot Protection Scenario Inputs</h2>
                    <p>Adjust timing, logistics, site, release, and evidence values to recalculate slot protection.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Isotope Hours Remaining</label><input name="isotope_hours_remaining" type="number" step="0.1" min="0" max="96" value="{{ result.inputs.isotope_hours_remaining }}"></div>
                            <div><label>Treatment Window Hours</label><input name="treatment_window_hours" type="number" step="0.1" min="0" max="96" value="{{ result.inputs.treatment_window_hours }}"></div>
                            <div><label>Courier Delay Minutes</label><input name="courier_delay_minutes" type="number" step="1" min="0" max="1440" value="{{ result.inputs.courier_delay_minutes }}"></div>
                            <div><label>Release Defensibility %</label><input name="release_defensibility" type="number" min="0" max="100" value="{{ result.inputs.release_defensibility }}"></div>
                            <div><label>Treatment-Site Readiness %</label><input name="site_readiness" type="number" min="0" max="100" value="{{ result.inputs.site_readiness }}"></div>
                            <div><label>Authorized User Readiness %</label><input name="authorized_user_readiness" type="number" min="0" max="100" value="{{ result.inputs.authorized_user_readiness }}"></div>
                            <div><label>Appointment Confirmation %</label><input name="appointment_confirmation" type="number" min="0" max="100" value="{{ result.inputs.appointment_confirmation }}"></div>
                            <div><label>Custody Arrival Confidence %</label><input name="custody_arrival_confidence" type="number" min="0" max="100" value="{{ result.inputs.custody_arrival_confidence }}"></div>
                            <div><label>Dose Activity Margin %</label><input name="dose_activity_margin" type="number" min="0" max="100" value="{{ result.inputs.dose_activity_margin }}"></div>
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Communication Readiness %</label><input name="communication_readiness" type="number" min="0" max="100" value="{{ result.inputs.communication_readiness }}"></div>
                            <div><label>Backup Slot Availability %</label><input name="backup_slot_availability" type="number" min="0" max="100" value="{{ result.inputs.backup_slot_availability }}"></div>
                            <div><label>Patient Admin Clearance %</label><input name="patient_admin_clearance" type="number" min="0" max="100" value="{{ result.inputs.patient_admin_clearance }}"></div>
                            <div><label>Open Site Exceptions</label><input name="open_site_exceptions" type="number" min="0" max="50" value="{{ result.inputs.open_site_exceptions }}"></div>
                            <div><label>Scheduling Conflicts</label><input name="scheduling_conflicts" type="number" min="0" max="50" value="{{ result.inputs.scheduling_conflicts }}"></div>
                            <div><label>Missing Slot Evidence</label><input name="missing_slot_evidence" type="number" min="0" max="100" value="{{ result.inputs.missing_slot_evidence }}"></div>
                            <div><label>Custody Exceptions</label><input name="custody_exceptions" type="number" min="0" max="50" value="{{ result.inputs.custody_exceptions }}"></div>
                            <div><label>Communication Breaks</label><input name="communication_breaks" type="number" min="0" max="50" value="{{ result.inputs.communication_breaks }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Patient Slot Protection</button>
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
                <h2>Slot Protection Gates</h2>
                <div class="grid-3">
                    {% for gate in result.slot_gates %}
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
                    <h2>Recommended Coordination Actions</h2>
                    <ul>
                        {% for action in result.recommended_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Patient Slot Risk Propagation</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Trigger</th>
                                <th>Propagation</th>
                                <th>Governance Control</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for chain in result.risk_chains %}
                            <tr>
                                <td><strong>{{ chain.trigger }}</strong></td>
                                <td>{{ chain.propagation }}</td>
                                <td>{{ chain.control }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Slot Scenario Board</h2>
                    <div class="grid-3">
                        {% for slot in result.slot_scenarios %}
                        <div class="slot-card">
                            <div class="eyebrow">{{ slot.slot_id }}</div>
                            <h3>{{ slot.status }}</h3>
                            <p><strong style="color:#fff2e6;">Dose Window:</strong> {{ slot.dose_window }}</p>
                            <p><strong style="color:#fff2e6;">Treatment Window:</strong> {{ slot.treatment_window }}</p>
                            <p><strong style="color:#fff2e6;">Risk:</strong> {{ slot.risk }}</p>
                            <p><strong style="color:#fff2e6;">Action:</strong> {{ slot.action }}</p>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Evidence Packets Needed</h2>
                    <ul>
                        {% for item in result.evidence_packets %}
                        <li>{{ item }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div class="panel">
                    <h2>Passport Outputs</h2>
                    <p>These are the treatment-coordination and inspection artifacts this engine can generate.</p>
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


@app.route("/irlt-commercial-readiness/patient-slot-protection/api")
@app.route("/rlttrust/patient-slot-protection/api")
@app.route("/rlttrust/patient-slot-protection-engine/api")
def rlttrust_patient_slot_protection_engine_api():
    payload = {
        "isotope_hours_remaining": request.args.get("isotope_hours_remaining", 22),
        "treatment_window_hours": request.args.get("treatment_window_hours", 18),
        "courier_delay_minutes": request.args.get("courier_delay_minutes", 35),
        "release_defensibility": request.args.get("release_defensibility", 82),
        "site_readiness": request.args.get("site_readiness", 84),
        "authorized_user_readiness": request.args.get("authorized_user_readiness", 86),
        "appointment_confirmation": request.args.get("appointment_confirmation", 88),
        "custody_arrival_confidence": request.args.get("custody_arrival_confidence", 83),
        "dose_activity_margin": request.args.get("dose_activity_margin", 78),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "communication_readiness": request.args.get("communication_readiness", 82),
        "backup_slot_availability": request.args.get("backup_slot_availability", 62),
        "patient_admin_clearance": request.args.get("patient_admin_clearance", 87),
        "open_site_exceptions": request.args.get("open_site_exceptions", 1),
        "scheduling_conflicts": request.args.get("scheduling_conflicts", 1),
        "missing_slot_evidence": request.args.get("missing_slot_evidence", 2),
        "custody_exceptions": request.args.get("custody_exceptions", 0),
        "communication_breaks": request.args.get("communication_breaks", 1),
    }
    return jsonify(_rlttrust_patient_slot_protection_assessment(payload))

# ============================================================
# End Patient Slot Protection Engine™
# ============================================================

'''

    # Add Patient Slot Protection link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_PATIENT_SLOT_PROTECTION_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_PATIENT_SLOT_PROTECTION_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/patient-slot-protection">Patient Slot Protection</a>',
            1
        )
        print("Added Patient Slot Protection link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Patient Slot Protection Engine successfully.")

