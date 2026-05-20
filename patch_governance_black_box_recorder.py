from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_GOVERNANCE_BLACK_BOX_RECORDER_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Governance Black Box Recorder already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_GOVERNANCE_BLACK_BOX_RECORDER_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Governance Black Box Recorder™
# Purpose: Capture critical IRLT readiness signals, evidence events, release decisions,
#          custody movements, AI advisories, and human approvals into a tamper-evident
#          inspection-survivable governance timeline.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request
import hashlib
import json
from datetime import datetime

def _rlttrust_bbr_num(value, default, minimum=0, maximum=1000):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_bbr_int(value, default, minimum=0, maximum=1000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_bbr_hash(record, previous_hash="GENESIS"):
    payload = dict(record)
    payload["previous_hash"] = previous_hash
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rlttrust_governance_black_box_data(payload=None):
    payload = payload or {}

    evidence_integrity = _rlttrust_bbr_num(payload.get("evidence_integrity"), 92, 0, 100)
    human_approval_completeness = _rlttrust_bbr_num(payload.get("human_approval_completeness"), 86, 0, 100)
    ai_governance_separation = _rlttrust_bbr_num(payload.get("ai_governance_separation"), 94, 0, 100)
    event_traceability = _rlttrust_bbr_num(payload.get("event_traceability"), 88, 0, 100)
    custody_traceability = _rlttrust_bbr_num(payload.get("custody_traceability"), 84, 0, 100)
    release_decision_traceability = _rlttrust_bbr_num(payload.get("release_decision_traceability"), 81, 0, 100)
    inspection_retrievability = _rlttrust_bbr_num(payload.get("inspection_retrievability"), 87, 0, 100)
    data_integrity = _rlttrust_bbr_num(payload.get("data_integrity"), 89, 0, 100)

    missing_decision_links = _rlttrust_bbr_int(payload.get("missing_decision_links"), 2, 0, 100)
    tamper_alerts = _rlttrust_bbr_int(payload.get("tamper_alerts"), 0, 0, 100)
    ai_without_human_approval = _rlttrust_bbr_int(payload.get("ai_without_human_approval"), 0, 0, 100)
    orphan_events = _rlttrust_bbr_int(payload.get("orphan_events"), 2, 0, 100)
    stale_events = _rlttrust_bbr_int(payload.get("stale_events"), 3, 0, 100)
    unresolved_escalations = _rlttrust_bbr_int(payload.get("unresolved_escalations"), 2, 0, 100)

    decision_penalty = min(missing_decision_links * 5, 35)
    tamper_penalty = min(tamper_alerts * 20, 60)
    ai_penalty = min(ai_without_human_approval * 18, 54)
    orphan_penalty = min(orphan_events * 4, 28)
    stale_penalty = min(stale_events * 3, 24)
    escalation_penalty = min(unresolved_escalations * 5, 35)

    timeline_completeness = max(0, event_traceability - orphan_penalty - stale_penalty)
    decision_defensibility = max(0, ((human_approval_completeness + release_decision_traceability) / 2) - decision_penalty)
    ai_control_score = max(0, ai_governance_separation - ai_penalty)
    evidence_survivability = max(0, evidence_integrity - tamper_penalty)
    escalation_closure_score = max(0, 100 - escalation_penalty)

    black_box_score = round(
        evidence_survivability * 0.17 +
        decision_defensibility * 0.16 +
        ai_control_score * 0.13 +
        timeline_completeness * 0.14 +
        custody_traceability * 0.10 +
        inspection_retrievability * 0.12 +
        data_integrity * 0.10 +
        escalation_closure_score * 0.08
    )

    blockers = []
    warnings = []

    if tamper_alerts > 0:
        blockers.append("Tamper alert detected in governed evidence or event chain.")
    if ai_without_human_approval > 0:
        blockers.append("AI advisory was not clearly separated from human authority.")
    if evidence_survivability < 75:
        blockers.append("Evidence survivability is below inspection-defensible threshold.")
    elif evidence_survivability < 90:
        warnings.append("Evidence survivability has governance warnings.")

    if decision_defensibility < 75:
        blockers.append("Human decision lineage is below defensible threshold.")
    elif decision_defensibility < 88:
        warnings.append("Human decision lineage needs stronger approval linkage.")

    if timeline_completeness < 75:
        blockers.append("Governance timeline contains too many orphan or stale events.")
    elif timeline_completeness < 88:
        warnings.append("Governance timeline contains orphan or stale event warnings.")

    if custody_traceability < 80:
        warnings.append("Custody traceability needs stronger event linkage.")
    if release_decision_traceability < 82:
        warnings.append("Release decision traceability needs stronger rationale linkage.")
    if inspection_retrievability < 82:
        warnings.append("Inspection retrievability should be improved before audit response.")
    if unresolved_escalations > 0:
        warnings.append("Unresolved escalations remain open in the black box timeline.")
    if missing_decision_links > 0:
        warnings.append("Some decision events are missing explicit human approval links.")
    if stale_events > 0:
        warnings.append("Some black box events are stale and should be refreshed.")

    if blockers:
        verdict = "BLACK BOX NOT DEFENSIBLE"
        status_class = "blocked"
        executive_answer = "The governance black box contains critical defects that could weaken inspection survivability or human-governed AI defensibility."
    elif black_box_score >= 90 and len(warnings) <= 2:
        verdict = "BLACK BOX INSPECTION-DEFENSIBLE"
        status_class = "ready"
        executive_answer = "The governance black box appears inspection-defensible with strong evidence integrity, human approval lineage, and event traceability."
    elif black_box_score >= 82:
        verdict = "BLACK BOX READY WITH WARNINGS"
        status_class = "warning"
        executive_answer = "The governance black box is usable, but leadership should close warnings before relying on it as the final inspection timeline."
    elif black_box_score >= 70:
        verdict = "BLACK BOX AT RISK"
        status_class = "gap"
        executive_answer = "The governance black box has a credible foundation, but missing links, stale events, or unresolved escalations reduce defensibility."
    else:
        verdict = "BLACK BOX NOT INSPECTION-SURVIVABLE"
        status_class = "blocked"
        executive_answer = "The governance black box is not yet inspection-survivable and requires evidence, approval, and event-lineage remediation."

    raw_events = [
        {
            "event_id": "BBR-001",
            "timestamp": "2026-05-18T07:15:00",
            "event_type": "Readiness Signal",
            "domain": "Commercial Readiness",
            "source_system": "RLTTrust™ Command Center",
            "signal": "Commercial readiness score generated",
            "governance_action": "Recorded baseline readiness posture",
            "human_owner": "Operations Leadership",
            "ai_advisory": "AI suggested monitoring release, EM, CAPA, and custody dependencies.",
            "human_decision": "Leadership review required before readiness claim.",
            "evidence_packet": "Commercial Readiness Passport",
            "risk": "Leadership may over-trust a score without evidence traceability.",
            "status": "Recorded"
        },
        {
            "event_id": "BBR-002",
            "timestamp": "2026-05-18T07:42:00",
            "event_type": "Decision Support",
            "domain": "Can We Treat Tomorrow",
            "source_system": "Can We Treat Tomorrow? Engine™",
            "signal": "Treatment-readiness decision generated",
            "governance_action": "Converted operational inputs into governed treatment-readiness status",
            "human_owner": "QA / Operations / Treatment Coordination",
            "ai_advisory": "AI recommended review of isotope timing, QA release, custody, and site readiness.",
            "human_decision": "Human approval required before treatment-readiness claim.",
            "evidence_packet": "Treatment Readiness Packet",
            "risk": "Advisory output must not become clinical or QA approval.",
            "status": "Recorded"
        },
        {
            "event_id": "BBR-003",
            "timestamp": "2026-05-18T08:05:00",
            "event_type": "Evidence Graph",
            "domain": "Isotope-to-Patient Traceability",
            "source_system": "Isotope-to-Patient Evidence Graph™",
            "signal": "Dose journey mapped from isotope source to treatment slot",
            "governance_action": "Linked isotope, manufacturing, QC, QA release, shipment, receipt, slot, and passport events",
            "human_owner": "QA / Supply Chain / Treatment Coordination",
            "ai_advisory": "AI identified patient-slot and release defensibility as watch areas.",
            "human_decision": "Owners must confirm evidence packets and custody links.",
            "evidence_packet": "Dose Journey Passport",
            "risk": "Traceability gap could weaken inspection response.",
            "status": "Recorded"
        },
        {
            "event_id": "BBR-004",
            "timestamp": "2026-05-18T08:33:00",
            "event_type": "Inspection Simulation",
            "domain": "Inspection Survivability",
            "source_system": "Inspection Tomorrow Simulator™",
            "signal": "Inspection findings simulated",
            "governance_action": "Mapped inspector questions to evidence packets and findings",
            "human_owner": "QA / Compliance",
            "ai_advisory": "AI suggested closing CAPA, EM, material accountability, and evidence gaps.",
            "human_decision": "QA must disposition findings before inspection readiness is claimed.",
            "evidence_packet": "Inspection Survivability Packet",
            "risk": "Simulated findings may become real inspection exposure if not closed.",
            "status": "Open Warning"
        },
        {
            "event_id": "BBR-005",
            "timestamp": "2026-05-18T09:02:00",
            "event_type": "Material Accountability",
            "domain": "Radioactive Material",
            "source_system": "Radioactive Material Accountability Ledger™",
            "signal": "Material receipt, use, waste, decay, residual, and reconciliation ledger generated",
            "governance_action": "Created hash-chained material accountability events",
            "human_owner": "Radiation Safety / QA",
            "ai_advisory": "AI recommended final reconciliation and variance review.",
            "human_decision": "Radiation safety and QA approval required before closure.",
            "evidence_packet": "Radioactive Material Accountability Passport",
            "risk": "Material reconciliation gap could weaken inspection defensibility.",
            "status": "Open Warning"
        },
        {
            "event_id": "BBR-006",
            "timestamp": "2026-05-18T09:34:00",
            "event_type": "Release Decision Support",
            "domain": "QA Release",
            "source_system": "Release Defensibility Engine™",
            "signal": "Release defensibility score and gate results generated",
            "governance_action": "Mapped QC, QA, CAPA, EM, SOP, access, custody, material, and evidence controls to release gates",
            "human_owner": "QA Release",
            "ai_advisory": "AI recommended strengthening QA release rationale and evidence packet closure.",
            "human_decision": "QA remains final release authority.",
            "evidence_packet": "Release Defensibility Passport",
            "risk": "Release could be procedurally approved but weak under inspection questioning.",
            "status": "Recorded"
        },
        {
            "event_id": "BBR-007",
            "timestamp": "2026-05-18T10:10:00",
            "event_type": "Patient Slot Protection",
            "domain": "Treatment Coordination",
            "source_system": "Patient Slot Protection Engine™",
            "signal": "Treatment slot protection score generated",
            "governance_action": "Connected isotope window, release, courier, site readiness, appointment, and evidence status",
            "human_owner": "Treatment Coordination / QA / Operations",
            "ai_advisory": "AI recommended resolving scheduling and site-readiness warnings.",
            "human_decision": "Treatment coordination and clinical/site authority remain authoritative.",
            "evidence_packet": "Patient Slot Protection Passport",
            "risk": "Operationally released dose may still miss the treatment window.",
            "status": "Open Warning"
        },
        {
            "event_id": "BBR-008",
            "timestamp": "2026-05-18T10:45:00",
            "event_type": "Network Readiness",
            "domain": "Cross-Site Commercial Scale-Up",
            "source_system": "Cross-Site RLT Network Readiness Mesh™",
            "signal": "Network readiness mesh generated",
            "governance_action": "Mapped manufacturing, release, logistics, treatment hubs, fallback capacity, and evidence readiness",
            "human_owner": "Commercialization Leadership",
            "ai_advisory": "AI recommended review of hot-cell, release, fallback, and evidence gaps.",
            "human_decision": "Leadership review required before cross-site readiness claim.",
            "evidence_packet": "Cross-Site Commercial Readiness Passport",
            "risk": "Single-site readiness may not prove commercial network readiness.",
            "status": "Recorded"
        },
        {
            "event_id": "BBR-009",
            "timestamp": "2026-05-18T11:20:00",
            "event_type": "Stress Event",
            "domain": "Commercialization Stress Test",
            "source_system": "Commercialization Stress Test Simulator™",
            "signal": "Stress test scenario executed",
            "governance_action": "Tested QC delay, QA delay, hot-cell outage, isotope supply delay, courier delay, evidence loss, and treatment hub pressure",
            "human_owner": "Operations Leadership / QA / Supply Chain",
            "ai_advisory": "AI recommended war-room actions and evidence recovery plan.",
            "human_decision": "Leadership must approve recovery plan and readiness claim.",
            "evidence_packet": "Commercialization Stress Test Passport",
            "risk": "Readiness may fail under commercial pressure despite normal-state status.",
            "status": "Open Warning"
        },
        {
            "event_id": "BBR-010",
            "timestamp": "2026-05-18T11:55:00",
            "event_type": "Human Approval Gate",
            "domain": "Governance Control",
            "source_system": "Governance Black Box Recorder™",
            "signal": "Human decision authority checkpoint created",
            "governance_action": "Separated AI advisory recommendations from human approval requirements",
            "human_owner": "QA / Compliance / Operations Leadership",
            "ai_advisory": "AI cannot approve release, treatment readiness, inspection readiness, or commercial readiness.",
            "human_decision": "Human governance remains authoritative control layer.",
            "evidence_packet": "Human Governance Control Packet",
            "risk": "AI output must not be mistaken for regulated decision authority.",
            "status": "Recorded"
        }
    ]

    previous_hash = "GENESIS"
    black_box_events = []
    for event in raw_events:
        event_hash = _rlttrust_bbr_hash(event, previous_hash)
        enriched = dict(event)
        enriched["previous_hash"] = previous_hash
        enriched["record_hash"] = event_hash
        enriched["short_hash"] = event_hash[:16]
        previous_hash = event_hash
        black_box_events.append(enriched)

    domains = [
        {
            "name": "Evidence Survivability",
            "score": round(evidence_survivability),
            "description": "Evidence integrity after tamper, missing-record, and inspection-survivability pressure."
        },
        {
            "name": "Human Decision Lineage",
            "score": round(decision_defensibility),
            "description": "Strength of approval linkage, release rationale, and human governance control."
        },
        {
            "name": "AI Governance Separation",
            "score": round(ai_control_score),
            "description": "Proof that AI is advisory and humans remain authoritative."
        },
        {
            "name": "Timeline Completeness",
            "score": round(timeline_completeness),
            "description": "Completeness of event chain and reduction of orphan or stale events."
        },
        {
            "name": "Custody Traceability",
            "score": round(custody_traceability),
            "description": "Ability to connect custody events to shipment, receipt, and treatment readiness."
        },
        {
            "name": "Inspection Retrievability",
            "score": round(inspection_retrievability),
            "description": "Ability to retrieve evidence quickly during inspection or leadership review."
        },
        {
            "name": "Data Integrity",
            "score": round(data_integrity),
            "description": "Trust in source data, event history, approvals, and change lineage."
        },
        {
            "name": "Escalation Closure",
            "score": round(escalation_closure_score),
            "description": "Closure strength for open warnings, escalation actions, and governance follow-up."
        }
    ]

    inspection_questions = [
        {
            "question": "Who made the readiness decision and what evidence supported it?",
            "answer": "The black box links readiness events to human owners, evidence packets, and record hashes.",
            "evidence": "Commercial Readiness Passport, human decision event, record hash chain."
        },
        {
            "question": "Did AI make any regulated decision?",
            "answer": "No. AI advisories are recorded separately from human decisions.",
            "evidence": "Human Governance Control Packet and AI advisory separation events."
        },
        {
            "question": "Can you prove the release decision was defensible?",
            "answer": "The release event links QA release rationale, gates, evidence packets, and QA owner review.",
            "evidence": "Release Defensibility Passport and QA release event chain."
        },
        {
            "question": "Can you prove material accountability and custody movement?",
            "answer": "The black box links material ledger, custody evidence, dose journey, and treatment slot events.",
            "evidence": "Radioactive Material Accountability Passport and Dose Journey Passport."
        },
        {
            "question": "What happened when the stress test identified weaknesses?",
            "answer": "Stress events, AI recommendations, war-room actions, and human decision requirements are recorded.",
            "evidence": "Commercialization Stress Test Passport and governance action timeline."
        }
    ]

    remediation_actions = []
    for b in blockers:
        remediation_actions.append("Critical remediation: " + b)
    for w in warnings[:7]:
        remediation_actions.append("Governance remediation: " + w)

    if missing_decision_links > 0:
        remediation_actions.append("Link missing decision events to named human owner, approval record, and evidence packet.")
    if orphan_events > 0:
        remediation_actions.append("Resolve orphan events by linking each signal to a source system, owner, and evidence artifact.")
    if stale_events > 0:
        remediation_actions.append("Refresh stale timeline events and rerun evidence expiry check.")
    if unresolved_escalations > 0:
        remediation_actions.append("Assign closure owner and target closure date for unresolved escalations.")
    if tamper_alerts == 0 and not remediation_actions:
        remediation_actions.append("Proceed to final Governance Black Box Passport generation.")

    passport_outputs = [
        "Governance Black Box Passport",
        "Human Decision Lineage Packet",
        "AI Advisory Separation Packet",
        "Inspection Timeline Packet",
        "Release Decision Timeline Packet",
        "Material and Custody Event Packet",
        "Commercialization Stress Event Packet",
        "Evidence Hash Chain Packet",
        "AuditVault™ Black Box Export"
    ]

    return {
        "black_box_score": black_box_score,
        "verdict": verdict,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "domains": domains,
        "black_box_events": black_box_events,
        "blockers": blockers,
        "warnings": warnings,
        "inspection_questions": inspection_questions,
        "remediation_actions": remediation_actions,
        "passport_outputs": passport_outputs,
        "inputs": {
            "evidence_integrity": evidence_integrity,
            "human_approval_completeness": human_approval_completeness,
            "ai_governance_separation": ai_governance_separation,
            "event_traceability": event_traceability,
            "custody_traceability": custody_traceability,
            "release_decision_traceability": release_decision_traceability,
            "inspection_retrievability": inspection_retrievability,
            "data_integrity": data_integrity,
            "missing_decision_links": missing_decision_links,
            "tamper_alerts": tamper_alerts,
            "ai_without_human_approval": ai_without_human_approval,
            "orphan_events": orphan_events,
            "stale_events": stale_events,
            "unresolved_escalations": unresolved_escalations
        },
        "governance_note": "The Governance Black Box Recorder™ is an inspection-survivability and evidence-lineage layer. It does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics systems, treatment scheduling, QA release authority, radiation safety authority, or human leadership decision-making."
    }


@app.route("/irlt-commercial-readiness/governance-black-box")
@app.route("/rlttrust/governance-black-box")
@app.route("/rlttrust/governance-black-box-recorder")
def rlttrust_governance_black_box_recorder():
    payload = {
        "evidence_integrity": request.args.get("evidence_integrity", 92),
        "human_approval_completeness": request.args.get("human_approval_completeness", 86),
        "ai_governance_separation": request.args.get("ai_governance_separation", 94),
        "event_traceability": request.args.get("event_traceability", 88),
        "custody_traceability": request.args.get("custody_traceability", 84),
        "release_decision_traceability": request.args.get("release_decision_traceability", 81),
        "inspection_retrievability": request.args.get("inspection_retrievability", 87),
        "data_integrity": request.args.get("data_integrity", 89),
        "missing_decision_links": request.args.get("missing_decision_links", 2),
        "tamper_alerts": request.args.get("tamper_alerts", 0),
        "ai_without_human_approval": request.args.get("ai_without_human_approval", 0),
        "orphan_events": request.args.get("orphan_events", 2),
        "stale_events": request.args.get("stale_events", 3),
        "unresolved_escalations": request.args.get("unresolved_escalations", 2),
    }

    result = _rlttrust_governance_black_box_data(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Governance Black Box Recorder™ | RLTTrust™</title>
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

            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
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

            .timeline {
                display: grid;
                grid-template-columns: repeat(10, minmax(270px, 1fr));
                gap: 14px;
                overflow-x: auto;
                padding-bottom: 8px;
            }

            .event-card {
                min-height: 430px;
                position: relative;
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
                z-index: 4;
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

            .event-type {
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
                .hero-grid, .grid, .grid-2, .grid-4, .form-grid {
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
                        <div class="eyebrow">RLTTrust™ Inspection-Survivable Event Memory</div>
                        <h1>Governance Black Box Recorder™</h1>
                        <p>
                            An aircraft-style governance recorder for commercial IRLT readiness. It captures critical readiness signals,
                            evidence changes, release decisions, custody events, inspection simulations, stress tests, AI advisories,
                            and human approval checkpoints into a tamper-evident timeline.
                        </p>
                        <p>
                            The black box proves what happened, when it happened, who owned it, what evidence supported it,
                            what AI recommended, what humans decided, and whether the timeline can survive inspection.
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
                            <a href="/irlt-commercial-readiness/commercialization-stress-test">Stress Test</a>
                            <a href="/irlt-commercial-readiness/governance-black-box/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Black Box Defensibility Score</div>
                        <div class="score">{{ result.black_box_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.verdict }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Black Box Control Inputs</h2>
                    <p>Adjust evidence integrity, decision lineage, AI separation, and traceability controls.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Human Approval Completeness %</label><input name="human_approval_completeness" type="number" min="0" max="100" value="{{ result.inputs.human_approval_completeness }}"></div>
                            <div><label>AI Governance Separation %</label><input name="ai_governance_separation" type="number" min="0" max="100" value="{{ result.inputs.ai_governance_separation }}"></div>
                            <div><label>Event Traceability %</label><input name="event_traceability" type="number" min="0" max="100" value="{{ result.inputs.event_traceability }}"></div>
                            <div><label>Custody Traceability %</label><input name="custody_traceability" type="number" min="0" max="100" value="{{ result.inputs.custody_traceability }}"></div>
                            <div><label>Release Decision Traceability %</label><input name="release_decision_traceability" type="number" min="0" max="100" value="{{ result.inputs.release_decision_traceability }}"></div>
                            <div><label>Inspection Retrievability %</label><input name="inspection_retrievability" type="number" min="0" max="100" value="{{ result.inputs.inspection_retrievability }}"></div>
                            <div><label>Data Integrity %</label><input name="data_integrity" type="number" min="0" max="100" value="{{ result.inputs.data_integrity }}"></div>
                            <div><label>Missing Decision Links</label><input name="missing_decision_links" type="number" min="0" max="100" value="{{ result.inputs.missing_decision_links }}"></div>
                            <div><label>Tamper Alerts</label><input name="tamper_alerts" type="number" min="0" max="100" value="{{ result.inputs.tamper_alerts }}"></div>
                            <div><label>AI Without Human Approval</label><input name="ai_without_human_approval" type="number" min="0" max="100" value="{{ result.inputs.ai_without_human_approval }}"></div>
                            <div><label>Orphan Events</label><input name="orphan_events" type="number" min="0" max="100" value="{{ result.inputs.orphan_events }}"></div>
                            <div><label>Stale Events</label><input name="stale_events" type="number" min="0" max="100" value="{{ result.inputs.stale_events }}"></div>
                            <div><label>Unresolved Escalations</label><input name="unresolved_escalations" type="number" min="0" max="100" value="{{ result.inputs.unresolved_escalations }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Black Box Defensibility</button>
                    </form>
                </div>

                <div>
                    <h2>Black Box Control Domains</h2>
                    <div class="grid-4">
                        {% for d in result.domains %}
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

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">Hash-Chained Governance Timeline</div>
                    <h2>Critical IRLT Readiness Events</h2>
                    <p>
                        Each event below has a simulated record hash and previous-hash link.
                        This shows how RLTTrust™ can preserve an inspection-survivable chain of readiness evidence.
                    </p>

                    <div class="timeline">
                        {% for e in result.black_box_events %}
                        <div class="event-card">
                            <div class="event-id">{{ e.event_id }}</div>
                            <span class="event-type">{{ e.event_type }}</span>
                            <h3>{{ e.domain }}</h3>
                            <p><strong style="color:#fff2e6;">Time:</strong> {{ e.timestamp }}</p>
                            <p><strong style="color:#fff2e6;">Source:</strong> {{ e.source_system }}</p>
                            <p><strong style="color:#fff2e6;">Signal:</strong> {{ e.signal }}</p>
                            <p><strong style="color:#fff2e6;">Action:</strong> {{ e.governance_action }}</p>
                            <p><strong style="color:#fff2e6;">Human Owner:</strong> {{ e.human_owner }}</p>
                            <p><strong style="color:#fff2e6;">AI Advisory:</strong> {{ e.ai_advisory }}</p>
                            <p><strong style="color:#fff2e6;">Human Decision:</strong> {{ e.human_decision }}</p>
                            <p><strong style="color:#fff2e6;">Evidence:</strong> {{ e.evidence_packet }}</p>
                            <p><strong style="color:#fff2e6;">Risk:</strong> {{ e.risk }}</p>
                            <span class="hash">Hash: {{ e.short_hash }}</span>
                        </div>
                        {% endfor %}
                    </div>
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
                    <p>No blockers or warnings detected in this black box scenario.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Remediation Actions</h2>
                    <ul>
                        {% for action in result.remediation_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Inspector Question-to-Black-Box Evidence</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Inspector Question</th>
                                <th>Black Box Answer</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in result.inspection_questions %}
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
                    <h2>Black Box Passport Outputs</h2>
                    <p>These are the inspection and leadership artifacts this recorder can generate.</p>
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


@app.route("/irlt-commercial-readiness/governance-black-box/api")
@app.route("/rlttrust/governance-black-box/api")
@app.route("/rlttrust/governance-black-box-recorder/api")
def rlttrust_governance_black_box_recorder_api():
    payload = {
        "evidence_integrity": request.args.get("evidence_integrity", 92),
        "human_approval_completeness": request.args.get("human_approval_completeness", 86),
        "ai_governance_separation": request.args.get("ai_governance_separation", 94),
        "event_traceability": request.args.get("event_traceability", 88),
        "custody_traceability": request.args.get("custody_traceability", 84),
        "release_decision_traceability": request.args.get("release_decision_traceability", 81),
        "inspection_retrievability": request.args.get("inspection_retrievability", 87),
        "data_integrity": request.args.get("data_integrity", 89),
        "missing_decision_links": request.args.get("missing_decision_links", 2),
        "tamper_alerts": request.args.get("tamper_alerts", 0),
        "ai_without_human_approval": request.args.get("ai_without_human_approval", 0),
        "orphan_events": request.args.get("orphan_events", 2),
        "stale_events": request.args.get("stale_events", 3),
        "unresolved_escalations": request.args.get("unresolved_escalations", 2),
    }
    return jsonify(_rlttrust_governance_black_box_data(payload))

# ============================================================
# End Governance Black Box Recorder™
# ============================================================

'''

    # Add Governance Black Box link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_GOVERNANCE_BLACK_BOX_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/commercialization-stress-test">Stress Test</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_GOVERNANCE_BLACK_BOX_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/governance-black-box">Black Box Recorder</a>',
            1
        )
        print("Added Governance Black Box Recorder link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Governance Black Box Recorder successfully.")

