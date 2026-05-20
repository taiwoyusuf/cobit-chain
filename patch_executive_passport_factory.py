from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_EXECUTIVE_GOVERNANCE_PASSPORT_FACTORY_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Executive IRLT Governance Passport Factory already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_EXECUTIVE_GOVERNANCE_PASSPORT_FACTORY_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Executive IRLT Governance Passport Factory™
# Purpose: Convert RLTTrust™ engines into executive-readable, inspection-ready
#          governance passports for leadership, QA, compliance, and audit defense.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request
from datetime import datetime
import hashlib
import json

def _rlttrust_passport_hash(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rlttrust_passport_status(score):
    if score >= 90:
        return "Executive Defensible", "ready"
    if score >= 82:
        return "Defensible with Warnings", "warning"
    if score >= 70:
        return "At Risk — Closure Needed", "gap"
    return "Not Defensible", "blocked"


def _rlttrust_executive_passport_factory_data(passport_type=None):
    passport_type = (passport_type or "commercial_readiness").strip().lower()

    passport_types = [
        {"key": "commercial_readiness", "label": "Commercial Readiness Passport"},
        {"key": "dose_journey", "label": "Dose Journey Passport"},
        {"key": "release_defensibility", "label": "Release Defensibility Passport"},
        {"key": "inspection_survivability", "label": "Inspection Survivability Passport"},
        {"key": "radioactive_material", "label": "Radioactive Material Accountability Passport"},
        {"key": "patient_slot", "label": "Patient Slot Protection Passport"},
        {"key": "network_readiness", "label": "Cross-Site Network Readiness Passport"},
        {"key": "stress_test", "label": "Commercialization Stress Test Passport"},
        {"key": "black_box", "label": "Governance Black Box Passport"},
        {"key": "auditor_evidence", "label": "Auditor Question-to-Evidence Passport"}
    ]

    profiles = {
        "commercial_readiness": {
            "title": "Commercial Readiness Passport",
            "subtitle": "Executive evidence artifact for IRLT commercial scale-up readiness.",
            "executive_question": "Can leadership operationally defend commercialization readiness with governed evidence?",
            "owner": "Commercialization Leadership / QA / Operations",
            "score": 84,
            "summary": "Commercial readiness is promising but still requires closure of release, CAPA, EM, evidence, and dependency warnings before full defensibility.",
            "source_engines": [
                "IRLT Commercial Readiness Governance Command Center™",
                "IntegrityLens™",
                "Governance Passport™",
                "AuditVault™"
            ],
            "evidence_packets": [
                "QC readiness packet",
                "Validation readiness packet",
                "SOP governance packet",
                "Deviation/CAPA readiness packet",
                "Training readiness packet",
                "Access governance packet",
                "Backup review packet",
                "Chain-of-custody packet",
                "Release governance packet",
                "Audit readiness packet"
            ],
            "control_domains": [
                {"name": "QC Readiness", "score": 87, "status": "Warning"},
                {"name": "Validation Readiness", "score": 82, "status": "Warning"},
                {"name": "SOP Governance", "score": 91, "status": "Strong"},
                {"name": "Deviation / CAPA", "score": 76, "status": "At Risk"},
                {"name": "Release Governance", "score": 78, "status": "At Risk"},
                {"name": "Audit Readiness", "score": 83, "status": "Warning"}
            ],
            "warnings": [
                "Release defensibility requires stronger QA rationale.",
                "Deviation/CAPA dependencies require closure evidence.",
                "Evidence must be passported into one leadership artifact."
            ],
            "blockers": [],
            "approval_chain": [
                "Operations Leadership",
                "QA Leadership",
                "Compliance",
                "System Owners",
                "Commercialization Leadership"
            ],
            "audit_questions": [
                "Are we truly ready?",
                "Which readiness domains remain weak?",
                "Which dependencies are unresolved?",
                "Can leadership defend readiness tomorrow?"
            ],
            "passport_outputs": [
                "Commercial Readiness Passport",
                "Leadership Readiness Summary",
                "Domain Evidence Map",
                "Inspection Readiness Packet"
            ]
        },
        "dose_journey": {
            "title": "Dose Journey Passport",
            "subtitle": "End-to-end governed evidence from isotope source to patient-slot readiness.",
            "executive_question": "Can we prove the dose journey from isotope source to treatment readiness?",
            "owner": "QA / Supply Chain / Treatment Coordination",
            "score": 83,
            "summary": "The dose journey is traceable, but final treatment-site receipt and slot-readiness evidence should be strengthened before full closure.",
            "source_engines": [
                "Isotope-to-Patient Evidence Graph™",
                "Patient Slot Protection Engine™",
                "Radioactive Material Accountability Ledger™",
                "AuditVault™"
            ],
            "evidence_packets": [
                "Isotope source packet",
                "Batch manufacturing record",
                "QC result packet",
                "QA release packet",
                "Shipment custody packet",
                "Cold-chain evidence",
                "Treatment-site receipt",
                "Patient-slot readiness packet",
                "Final dose journey evidence graph"
            ],
            "control_domains": [
                {"name": "Isotope Source", "score": 92, "status": "Strong"},
                {"name": "Manufacturing", "score": 86, "status": "Warning"},
                {"name": "QC Testing", "score": 84, "status": "Warning"},
                {"name": "QA Release", "score": 78, "status": "At Risk"},
                {"name": "Shipment", "score": 88, "status": "Strong"},
                {"name": "Patient Slot", "score": 79, "status": "At Risk"}
            ],
            "warnings": [
                "Patient-slot readiness remains below fully defensible level.",
                "QA release defensibility needs stronger evidence linkage.",
                "Final treatment-site receipt should be explicitly linked to passport closure."
            ],
            "blockers": [],
            "approval_chain": [
                "Radiation Safety",
                "Manufacturing",
                "QC",
                "QA Release",
                "Supply Chain",
                "Treatment Coordination"
            ],
            "audit_questions": [
                "Can you show isotope source to treatment-readiness traceability?",
                "Can you prove custody movement?",
                "Can you prove dose-to-slot alignment?"
            ],
            "passport_outputs": [
                "Dose Journey Passport",
                "Shipment Governance Passport",
                "Treatment Readiness Passport",
                "Isotope-to-Patient Evidence Packet"
            ]
        },
        "release_defensibility": {
            "title": "Release Defensibility Passport",
            "subtitle": "QA-facing evidence artifact proving whether release can survive inspection.",
            "executive_question": "Can QA defend this release decision with complete governed evidence?",
            "owner": "QA Release / QC / Compliance",
            "score": 81,
            "summary": "Release may be possible, but QA should close governance warnings before final defensibility is claimed.",
            "source_engines": [
                "Release Defensibility Engine™",
                "CAPATrust™",
                "SOPTrust™",
                "AccessTrust™",
                "AuditVault™"
            ],
            "evidence_packets": [
                "QC result packet",
                "QA release rationale",
                "Batch manufacturing record",
                "Deviation/CAPA disposition",
                "Environmental monitoring impact assessment",
                "SOP and training alignment packet",
                "Access governance attestation",
                "Custody evidence",
                "Radioactive material reconciliation",
                "AuditVault™ verification"
            ],
            "control_domains": [
                {"name": "QC Readiness", "score": 84, "status": "Warning"},
                {"name": "QA Review", "score": 78, "status": "At Risk"},
                {"name": "Batch Record", "score": 86, "status": "Warning"},
                {"name": "Deviation / CAPA / EM", "score": 69, "status": "At Risk"},
                {"name": "Evidence Integrity", "score": 83, "status": "Warning"},
                {"name": "Material Accountability", "score": 78, "status": "At Risk"}
            ],
            "warnings": [
                "QA release rationale requires strengthening.",
                "CAPA/EM impact review must be explicitly linked.",
                "Evidence packet contains stale or missing records."
            ],
            "blockers": [],
            "approval_chain": [
                "QC",
                "QA Release",
                "CAPA Owner",
                "EM Owner",
                "Radiation Safety",
                "Compliance"
            ],
            "audit_questions": [
                "Why was this released?",
                "What evidence supported release?",
                "Were deviations, CAPA, EM, and OOS/OOT risks dispositioned?"
            ],
            "passport_outputs": [
                "Release Defensibility Passport",
                "QA Release Rationale Packet",
                "QC-to-Release Evidence Packet",
                "AuditVault™ Release Evidence Packet"
            ]
        },
        "inspection_survivability": {
            "title": "Inspection Survivability Passport",
            "subtitle": "Inspection-readiness artifact showing what survives and what fails tomorrow.",
            "executive_question": "If an inspector walked in tomorrow, what would fail and what evidence would we show?",
            "owner": "QA / Compliance / Internal Audit",
            "score": 80,
            "summary": "The operation has a credible inspection foundation, but major findings must be closed before full inspection defensibility.",
            "source_engines": [
                "Inspection Tomorrow Simulator™",
                "AuditVault™",
                "Governance Black Box Recorder™",
                "Auditor Question-to-Evidence Engine™"
            ],
            "evidence_packets": [
                "Inspection findings packet",
                "QA release packet",
                "QC packet",
                "Batch record packet",
                "SOP/training packet",
                "CAPA/EM packet",
                "Material accountability packet",
                "Access governance packet",
                "AuditVault™ evidence verification"
            ],
            "control_domains": [
                {"name": "QA Release", "score": 78, "status": "At Risk"},
                {"name": "QC Packet", "score": 84, "status": "Warning"},
                {"name": "Batch Record", "score": 86, "status": "Warning"},
                {"name": "Deviation / EM", "score": 68, "status": "At Risk"},
                {"name": "Evidence Integrity", "score": 79, "status": "At Risk"},
                {"name": "Data Integrity", "score": 87, "status": "Warning"}
            ],
            "warnings": [
                "Major simulated findings remain open.",
                "Evidence retrievability must be improved.",
                "CAPA/EM and material reconciliation require stronger closure."
            ],
            "blockers": [],
            "approval_chain": [
                "QA",
                "Compliance",
                "Internal Audit",
                "System Owners",
                "Radiation Safety"
            ],
            "audit_questions": [
                "What would fail tomorrow?",
                "What evidence would we show?",
                "Which findings are critical, major, or minor?"
            ],
            "passport_outputs": [
                "Inspection Survivability Passport",
                "Inspector Question-to-Evidence Packet",
                "Audit Response Packet",
                "Inspection War-Room Action Log"
            ]
        },
        "radioactive_material": {
            "title": "Radioactive Material Accountability Passport",
            "subtitle": "Governed artifact for receipt, use, transfer, decay, waste, disposal, and reconciliation.",
            "executive_question": "Can we prove radioactive material accountability across the full lifecycle?",
            "owner": "Radiation Safety / QA / Compliance",
            "score": 82,
            "summary": "Radioactive material accountability is promising but requires final reconciliation and evidence closure before full inspection confidence.",
            "source_engines": [
                "Radioactive Material Accountability Ledger™",
                "AuditVault™",
                "Governance Black Box Recorder™"
            ],
            "evidence_packets": [
                "Receipt activity log",
                "Controlled storage log",
                "Preparation/use record",
                "QC sample activity log",
                "Waste activity log",
                "Decay calculation",
                "Residual activity record",
                "Transfer/custody record",
                "Final reconciliation worksheet",
                "Radiation safety approval"
            ],
            "control_domains": [
                {"name": "Receipt", "score": 92, "status": "Strong"},
                {"name": "Storage", "score": 88, "status": "Strong"},
                {"name": "Use / Preparation", "score": 84, "status": "Warning"},
                {"name": "Transfer", "score": 86, "status": "Warning"},
                {"name": "Waste / Decay", "score": 87, "status": "Warning"},
                {"name": "Reconciliation", "score": 76, "status": "At Risk"}
            ],
            "warnings": [
                "Final reconciliation has warning status.",
                "Some evidence items may be missing or stale.",
                "Variance explanation should be attached to closure."
            ],
            "blockers": [],
            "approval_chain": [
                "Radiation Safety",
                "Manufacturing",
                "QA",
                "Compliance"
            ],
            "audit_questions": [
                "Where did the radioactive material come from?",
                "Who handled it?",
                "What was used, wasted, decayed, disposed, and reconciled?"
            ],
            "passport_outputs": [
                "Radioactive Material Accountability Passport",
                "Material Reconciliation Packet",
                "Waste / Decay / Disposal Packet",
                "Radiation Safety Evidence Packet"
            ]
        },
        "patient_slot": {
            "title": "Patient Slot Protection Passport",
            "subtitle": "Patient-impact governance artifact for protecting scheduled treatment windows.",
            "executive_question": "Can the dose still protect the scheduled treatment slot?",
            "owner": "Treatment Coordination / Nuclear Medicine / QA",
            "score": 79,
            "summary": "The slot may be protectable, but site readiness, timing margin, and dose-to-slot evidence require closure.",
            "source_engines": [
                "Patient Slot Protection Engine™",
                "Can We Treat Tomorrow? Engine™",
                "Isotope-to-Patient Evidence Graph™"
            ],
            "evidence_packets": [
                "Treatment-slot readiness packet",
                "Dose-to-slot match evidence",
                "QA release-to-treatment linkage",
                "Courier ETA and custody evidence",
                "Treatment-site readiness attestation",
                "Authorized user readiness",
                "Appointment/admin clearance",
                "Dose activity margin assessment",
                "Backup slot contingency plan"
            ],
            "control_domains": [
                {"name": "Time Alignment", "score": 76, "status": "Warning"},
                {"name": "Release Defensibility", "score": 82, "status": "Warning"},
                {"name": "Courier / Custody", "score": 77, "status": "At Risk"},
                {"name": "Treatment Site", "score": 78, "status": "At Risk"},
                {"name": "Appointment / Admin", "score": 80, "status": "Warning"},
                {"name": "Evidence Integrity", "score": 83, "status": "Warning"}
            ],
            "warnings": [
                "Treatment window has limited timing margin.",
                "Site readiness needs confirmation.",
                "Slot evidence packet contains missing records."
            ],
            "blockers": [],
            "approval_chain": [
                "Treatment Coordination",
                "Nuclear Medicine Site",
                "QA",
                "Supply Chain",
                "Operations"
            ],
            "audit_questions": [
                "Can you prove dose-to-slot alignment?",
                "Can you prove the site was ready?",
                "Can you prove the slot was protected despite timing pressure?"
            ],
            "passport_outputs": [
                "Patient Slot Protection Passport",
                "Treatment Readiness Passport",
                "Dose-to-Slot Match Packet",
                "Slot Risk Escalation Packet"
            ]
        },
        "network_readiness": {
            "title": "Cross-Site Network Readiness Passport",
            "subtitle": "Executive artifact for multi-site commercial radiopharma scale-up readiness.",
            "executive_question": "Can the RLT network support commercial demand if one node becomes constrained?",
            "owner": "Commercialization Leadership / QA / Operations / Supply Chain",
            "score": 78,
            "summary": "Network readiness is credible but not fully defensible due to hot-cell capacity, QA/QC release bottlenecks, fallback capacity, and evidence gaps.",
            "source_engines": [
                "Cross-Site RLT Network Readiness Mesh™",
                "Commercialization Stress Test Simulator™",
                "IntegrityLens™",
                "AuditVault™"
            ],
            "evidence_packets": [
                "Primary site readiness packet",
                "Secondary/fallback site packet",
                "QC/QA release capacity packet",
                "Hot-cell capacity packet",
                "Isotope supply resilience packet",
                "Courier/cold-chain mesh packet",
                "Treatment hub readiness packet",
                "Cross-site evidence integrity packet"
            ],
            "control_domains": [
                {"name": "Manufacturing Mesh", "score": 76, "status": "At Risk"},
                {"name": "QC/QA Release Mesh", "score": 68, "status": "At Risk"},
                {"name": "Logistics Mesh", "score": 74, "status": "At Risk"},
                {"name": "Fallback Mesh", "score": 69, "status": "At Risk"},
                {"name": "Evidence Mesh", "score": 82, "status": "Warning"},
                {"name": "Demand Absorption", "score": 88, "status": "Strong"}
            ],
            "warnings": [
                "Release bottlenecks may constrain demand.",
                "Fallback capacity is below strong redundancy level.",
                "Cross-site evidence gaps need closure before executive signoff."
            ],
            "blockers": [],
            "approval_chain": [
                "Commercialization Leadership",
                "Manufacturing Leadership",
                "QA/QC Leadership",
                "Supply Chain",
                "Treatment Hub Leadership"
            ],
            "audit_questions": [
                "Can the network absorb site failure?",
                "Where is the bottleneck?",
                "Can leadership defend cross-site readiness?"
            ],
            "passport_outputs": [
                "Cross-Site Commercial Readiness Passport",
                "Network Release Capacity Passport",
                "Manufacturing Redundancy Passport",
                "Treatment Hub Readiness Passport"
            ]
        },
        "stress_test": {
            "title": "Commercialization Stress Test Passport",
            "subtitle": "Executive what-if artifact showing whether readiness survives disruption.",
            "executive_question": "Can the commercial readiness model survive disruption?",
            "owner": "Operations Leadership / QA / Supply Chain",
            "score": 76,
            "summary": "The model can recover from some stress, but QC delay, hot-cell outage, courier delay, evidence loss, and fallback weaknesses create risk.",
            "source_engines": [
                "Commercialization Stress Test Simulator™",
                "Cross-Site RLT Network Readiness Mesh™",
                "Patient Slot Protection Engine™",
                "Release Defensibility Engine™"
            ],
            "evidence_packets": [
                "QC/QA delay impact packet",
                "Hot-cell outage recovery packet",
                "Isotope supply disruption packet",
                "Courier/cold-chain stress packet",
                "Quality event stress packet",
                "Evidence loss recovery packet",
                "Patient slot resilience packet",
                "Commercial readiness war-room packet"
            ],
            "control_domains": [
                {"name": "Stress Survival", "score": 76, "status": "At Risk"},
                {"name": "Raw Operational Damage", "score": 84, "status": "Warning"},
                {"name": "Resilience Absorption", "score": 35, "status": "At Risk"},
                {"name": "Fallback Capacity", "score": 68, "status": "At Risk"},
                {"name": "Evidence Integrity", "score": 90, "status": "Strong"},
                {"name": "Patient-Slot Resilience", "score": 76, "status": "At Risk"}
            ],
            "warnings": [
                "Fallback capacity needs strengthening.",
                "QC/QA delay can create treatment-window compression.",
                "War-room actions require owner assignment and closure evidence."
            ],
            "blockers": [],
            "approval_chain": [
                "Operations Leadership",
                "QA",
                "Supply Chain",
                "Treatment Coordination",
                "Commercialization Leadership"
            ],
            "audit_questions": [
                "What happens if QC is delayed?",
                "What happens if a hot cell goes down?",
                "Can the network recover with governed evidence?"
            ],
            "passport_outputs": [
                "Commercialization Stress Test Passport",
                "Executive Stress Survival Packet",
                "War-Room Action Packet",
                "Stress Scenario Evidence Packet"
            ]
        },
        "black_box": {
            "title": "Governance Black Box Passport",
            "subtitle": "Tamper-evident timeline artifact for readiness signals, AI advisories, and human decisions.",
            "executive_question": "Can we prove what happened, when, who owned it, what AI recommended, and what humans decided?",
            "owner": "QA / Compliance / Operations Leadership",
            "score": 86,
            "summary": "The black box is usable with warnings. Decision links, stale events, and open escalations should be closed before final inspection reliance.",
            "source_engines": [
                "Governance Black Box Recorder™",
                "AuditVault™",
                "Auditor Question-to-Evidence Engine™"
            ],
            "evidence_packets": [
                "Readiness signal event chain",
                "AI advisory separation packet",
                "Human decision lineage packet",
                "Release decision timeline",
                "Custody movement timeline",
                "Stress event timeline",
                "Evidence hash chain",
                "Inspection timeline packet"
            ],
            "control_domains": [
                {"name": "Evidence Survivability", "score": 92, "status": "Strong"},
                {"name": "Human Decision Lineage", "score": 77, "status": "At Risk"},
                {"name": "AI Governance Separation", "score": 94, "status": "Strong"},
                {"name": "Timeline Completeness", "score": 71, "status": "At Risk"},
                {"name": "Inspection Retrievability", "score": 87, "status": "Warning"},
                {"name": "Data Integrity", "score": 89, "status": "Warning"}
            ],
            "warnings": [
                "Some decision events need explicit human approval links.",
                "Some events are stale or orphaned.",
                "Open escalations should be closed before final inspection reliance."
            ],
            "blockers": [],
            "approval_chain": [
                "QA",
                "Compliance",
                "Operations Leadership",
                "System Owners",
                "Audit Owner"
            ],
            "audit_questions": [
                "Who made the decision?",
                "Did AI approve anything?",
                "What evidence was used?",
                "Can the event timeline be trusted?"
            ],
            "passport_outputs": [
                "Governance Black Box Passport",
                "Human Decision Lineage Packet",
                "AI Advisory Separation Packet",
                "Evidence Hash Chain Packet"
            ]
        },
        "auditor_evidence": {
            "title": "Auditor Question-to-Evidence Passport",
            "subtitle": "Inspection-response artifact mapping questions to evidence, owners, engines, gaps, and passports.",
            "executive_question": "Can RLTTrust™ answer auditor questions with governed evidence?",
            "owner": "QA / Compliance / Audit Response Team",
            "score": 85,
            "summary": "Auditor questions can be mapped to governed evidence packets and source engines, but all responses require human confirmation before use.",
            "source_engines": [
                "Auditor Question-to-Evidence Engine™",
                "Inspection Tomorrow Simulator™",
                "Governance Black Box Recorder™",
                "AuditVault™"
            ],
            "evidence_packets": [
                "Question-to-evidence map",
                "Evidence packet list",
                "Owner assignment list",
                "Readiness gap list",
                "Source engine map",
                "Passport output map",
                "Human response approval record"
            ],
            "control_domains": [
                {"name": "Evidence Mapping", "score": 88, "status": "Strong"},
                {"name": "Owner Clarity", "score": 84, "status": "Warning"},
                {"name": "Source Engine Traceability", "score": 87, "status": "Warning"},
                {"name": "Gap Visibility", "score": 82, "status": "Warning"},
                {"name": "Passport Linkage", "score": 85, "status": "Warning"},
                {"name": "Human Confirmation", "score": 80, "status": "Warning"}
            ],
            "warnings": [
                "Evidence answer must be confirmed by accountable human owner.",
                "Some readiness gaps may require closure before auditor response.",
                "AuditVault™ verification should be run before evidence is presented."
            ],
            "blockers": [],
            "approval_chain": [
                "QA",
                "Compliance",
                "Audit Response Owner",
                "Evidence Owner",
                "System Owner"
            ],
            "audit_questions": [
                "Where is the evidence?",
                "Who owns the answer?",
                "Which system or engine supports the answer?",
                "What is missing?"
            ],
            "passport_outputs": [
                "Auditor Question-to-Evidence Passport",
                "Inspection Response Packet",
                "Evidence Owner Packet",
                "AuditVault™ Verification Packet"
            ]
        }
    }

    if passport_type not in profiles:
        passport_type = "commercial_readiness"

    passport = profiles[passport_type]
    status, status_class = _rlttrust_passport_status(passport["score"])

    passport_id_source = {
        "passport_type": passport_type,
        "title": passport["title"],
        "score": passport["score"],
        "owner": passport["owner"],
        "generated_on": "2026-05-18",
        "source_engines": passport["source_engines"],
        "evidence_packets": passport["evidence_packets"]
    }

    passport_hash = _rlttrust_passport_hash(passport_id_source)
    passport_id = "RLT-PASS-" + passport_hash[:10].upper()

    readiness_summary = {
        "passport_id": passport_id,
        "passport_hash": passport_hash,
        "short_hash": passport_hash[:18],
        "status": status,
        "status_class": status_class,
        "generated_on": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "governance_mode": "Advisory intelligence; human approval required",
        "platform": "COBIT-Chain™ / AssuranceLayer™ Platform A",
        "product": "RLTTrust™ / IRLT Commercial Readiness Governance Command Center™"
    }

    recommended_actions = []
    for b in passport["blockers"]:
        recommended_actions.append("Resolve blocker: " + b)
    for w in passport["warnings"]:
        recommended_actions.append("Review warning: " + w)

    recommended_actions.extend([
        "Confirm accountable human owner approval before using this passport externally.",
        "Verify linked evidence through AuditVault™ before inspection or leadership signoff.",
        "Record final approval or rejection in the Governance Black Box Recorder™.",
        "Refresh the passport after evidence gaps, stale records, or warnings are closed."
    ])

    executive_signoff = [
        {"role": role, "status": "Pending Human Approval", "note": "Required before final regulated or executive reliance."}
        for role in passport["approval_chain"]
    ]

    return {
        "selected_type": passport_type,
        "passport_types": passport_types,
        "passport": passport,
        "readiness_summary": readiness_summary,
        "recommended_actions": recommended_actions,
        "executive_signoff": executive_signoff,
        "governance_note": "This passport is an executive governance artifact generated from advisory intelligence. It does not replace QA release authority, compliance judgment, radiation safety authority, clinical authority, regulatory judgment, or human leadership approval."
    }


@app.route("/irlt-commercial-readiness/passport-factory")
@app.route("/rlttrust/passport-factory")
@app.route("/rlttrust/executive-passport-factory")
def rlttrust_executive_governance_passport_factory():
    passport_type = request.args.get("passport_type", "commercial_readiness")
    result = _rlttrust_executive_passport_factory_data(passport_type)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Executive IRLT Governance Passport Factory™ | RLTTrust™</title>
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

            .panel, .form-panel, .metric, .passport-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .passport-document {
                border: 1px solid rgba(255,122,24,0.34);
                border-radius: 34px;
                padding: 30px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.12), rgba(255,255,255,0.035)),
                    rgba(20,24,33,0.92);
                box-shadow: 0 28px 90px rgba(0,0,0,0.42);
            }

            .passport-header {
                display: grid;
                grid-template-columns: minmax(0, 1fr) 280px;
                gap: 22px;
                align-items: start;
                border-bottom: 1px solid rgba(255,255,255,0.12);
                padding-bottom: 22px;
                margin-bottom: 22px;
            }

            .passport-id {
                color: #ffd7ad;
                font-family: Consolas, Monaco, monospace;
                font-size: 13px;
                overflow-wrap: anywhere;
            }

            .seal {
                border-radius: 26px;
                padding: 18px;
                border: 1px solid rgba(255,122,24,0.32);
                background: rgba(255,122,24,0.08);
                text-align: center;
            }

            .seal strong {
                display: block;
                font-size: 34px;
                color: var(--orange2);
                letter-spacing: -.05em;
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

            select {
                width: 100%;
                box-sizing: border-box;
                border: 1px solid rgba(255,122,24,0.25);
                background: rgba(5,6,8,0.72);
                color: white;
                border-radius: 14px;
                padding: 13px 14px;
                font-size: 15px;
                outline: none;
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

            .pill {
                display: inline-block;
                margin: 5px 6px 5px 0;
                padding: 8px 10px;
                border-radius: 999px;
                background: rgba(255,122,24,0.10);
                border: 1px solid rgba(255,122,24,0.30);
                color: #ffd7ad;
                font-size: 12px;
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

            @media print {
                body {
                    background: white;
                    color: black;
                }
                .nav, .form-panel, .button {
                    display: none;
                }
                .wrap {
                    padding: 0;
                }
                .passport-document, .panel, .metric {
                    box-shadow: none;
                    border-color: #ccc;
                    background: white;
                    color: black;
                }
                p, td, li {
                    color: #333;
                }
                h1, h2, h3, th {
                    color: #111;
                }
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid, .grid-2, .grid-3, .passport-header {
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
                        <div class="eyebrow">RLTTrust™ Executive Artifact Layer</div>
                        <h1>Executive IRLT Governance Passport Factory™</h1>
                        <p>
                            Converts RLTTrust™ engines into executive-readable, inspection-ready governance passports.
                            Each passport summarizes the readiness score, owner, evidence packets, control domains,
                            warnings, blockers, approval chain, audit questions, and hash-backed artifact identity.
                        </p>
                        <p>
                            This is the artifact layer buyers can understand: not just dashboards, but defensible readiness documents.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/governance-black-box">Black Box Recorder</a>
                            <a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence Engine</a>
                            <a href="/irlt-commercial-readiness/passport-factory/api?passport_type={{ result.selected_type }}">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Selected Passport Score</div>
                        <div class="score">{{ result.passport.score }}%</div>
                        <span class="decision {{ result.readiness_summary.status_class }}">{{ result.readiness_summary.status }}</span>
                        <p>{{ result.passport.summary }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Select Passport Type</h2>
                    <form method="get">
                        <label>Governance Passport</label>
                        <select name="passport_type">
                            {% for p in result.passport_types %}
                                <option value="{{ p.key }}" {% if p.key == result.selected_type %}selected{% endif %}>{{ p.label }}</option>
                            {% endfor %}
                        </select>
                        <button class="button" type="submit">Generate Passport</button>
                    </form>

                    <div class="note">{{ result.governance_note }}</div>

                    <h3 style="margin-top:24px;">Available Passport Outputs</h3>
                    {% for p in result.passport_types %}
                    <span class="pill">{{ p.label }}</span>
                    {% endfor %}
                </div>

                <div class="passport-document">
                    <div class="passport-header">
                        <div>
                            <div class="eyebrow">Executive Governance Passport</div>
                            <h2>{{ result.passport.title }}</h2>
                            <p>{{ result.passport.subtitle }}</p>
                            <p><strong style="color:#fff2e6;">Executive Question:</strong> {{ result.passport.executive_question }}</p>
                            <p><strong style="color:#fff2e6;">Accountable Owner:</strong> {{ result.passport.owner }}</p>
                            <p class="passport-id"><strong>Passport ID:</strong> {{ result.readiness_summary.passport_id }}</p>
                            <p class="passport-id"><strong>Hash:</strong> {{ result.readiness_summary.short_hash }}</p>
                        </div>

                        <div class="seal">
                            <div class="eyebrow">Readiness Score</div>
                            <strong>{{ result.passport.score }}%</strong>
                            <span class="decision {{ result.readiness_summary.status_class }}">{{ result.readiness_summary.status }}</span>
                            <p>{{ result.readiness_summary.generated_on }}</p>
                        </div>
                    </div>

                    <h3>Executive Summary</h3>
                    <p>{{ result.passport.summary }}</p>

                    <h3>Source Engines</h3>
                    {% for engine in result.passport.source_engines %}
                    <span class="pill">{{ engine }}</span>
                    {% endfor %}

                    <h3 style="margin-top:22px;">Evidence Packets</h3>
                    {% for packet in result.passport.evidence_packets %}
                    <span class="pill">{{ packet }}</span>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <h2>Control Domain Readiness</h2>
                <div class="grid-3">
                    {% for d in result.passport.control_domains %}
                    <div class="metric">
                        <strong>{{ d.score }}%</strong>
                        <span>{{ d.name }} — {{ d.status }}</span>
                        <div class="bar"><span style="width: {{ d.score }}%;"></span></div>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Warnings and Blockers</h2>
                    {% if result.passport.blockers %}
                    <h3>Blockers</h3>
                    <ul>
                        {% for blocker in result.passport.blockers %}
                        <li>{{ blocker }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if result.passport.warnings %}
                    <h3 style="margin-top:18px;">Warnings</h3>
                    <ul>
                        {% for warning in result.passport.warnings %}
                        <li>{{ warning }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if not result.passport.blockers and not result.passport.warnings %}
                    <p>No blockers or warnings listed for this passport.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Recommended Actions</h2>
                    <ul>
                        {% for action in result.recommended_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Audit Questions Covered</h2>
                    <ul>
                        {% for q in result.passport.audit_questions %}
                        <li>{{ q }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div class="panel">
                    <h2>Passport Artifacts Produced</h2>
                    {% for output in result.passport.passport_outputs %}
                    <span class="pill">{{ output }}</span>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Executive Signoff Chain</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Role</th>
                                <th>Status</th>
                                <th>Note</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for signoff in result.executive_signoff %}
                            <tr>
                                <td><strong>{{ signoff.role }}</strong></td>
                                <td>{{ signoff.status }}</td>
                                <td>{{ signoff.note }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/passport-factory/api")
@app.route("/rlttrust/passport-factory/api")
@app.route("/rlttrust/executive-passport-factory/api")
def rlttrust_executive_governance_passport_factory_api():
    passport_type = request.args.get("passport_type", "commercial_readiness")
    return jsonify(_rlttrust_executive_passport_factory_data(passport_type))

# ============================================================
# End Executive IRLT Governance Passport Factory™
# ============================================================

'''

    # Add Executive Passport Factory link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_EXECUTIVE_PASSPORT_FACTORY_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence Engine</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_EXECUTIVE_PASSPORT_FACTORY_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>',
            1
        )
        print("Added Executive Passport Factory link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Executive IRLT Governance Passport Factory successfully.")

