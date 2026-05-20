from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_AUDITOR_QUESTION_TO_EVIDENCE_ENGINE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Auditor Question-to-Evidence Engine already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_AUDITOR_QUESTION_TO_EVIDENCE_ENGINE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Auditor Question-to-Evidence Engine™
# Purpose: Map inspection/auditor/leadership questions to governed evidence packets,
#          owners, source engines, readiness gaps, and passport outputs.
# AI is advisory only. Human QA/compliance governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_auditor_question_engine_data(question=None):
    question = (question or "").strip()
    if not question:
        question = "Can you prove this IRLT dose journey was manufactured, released, shipped, received, and treatment-ready with governed evidence?"

    q_lower = question.lower()

    evidence_catalog = [
        {
            "area": "Commercial Readiness",
            "triggers": ["commercial", "readiness", "launch", "scale", "leadership", "ready", "prepared"],
            "auditor_question": "Can leadership defend commercial readiness with governed evidence?",
            "evidence_packet": "Commercial Readiness Passport",
            "owner": "Commercialization Leadership / QA / Operations",
            "source_engine": "IRLT Commercial Readiness Governance Command Center™",
            "readiness": 84,
            "answer": "Commercial readiness is supported by domain scores across QC, validation, SOP, CAPA, access, backup, chain of custody, release, audit readiness, and operational trust.",
            "gap": "Readiness must not be claimed unless release, CAPA, EM, evidence, and dependency gaps are closed.",
            "passport": "Commercial Readiness Passport"
        },
        {
            "area": "Can We Treat Tomorrow",
            "triggers": ["treat tomorrow", "tomorrow", "treatment tomorrow", "can we treat", "operationally ready"],
            "auditor_question": "Can the operation support treatment tomorrow with defensible evidence?",
            "evidence_packet": "Treatment Readiness Packet",
            "owner": "QA / Operations / Treatment Coordination",
            "source_engine": "Can We Treat Tomorrow? Engine™",
            "readiness": 82,
            "answer": "Treatment readiness is assessed using isotope timing, QC readiness, QA release, custody, cold-chain, treatment-site readiness, SOP/training, access, backup, and evidence integrity.",
            "gap": "Open CAPA, EM exceptions, release warnings, or stale evidence can prevent a defensible tomorrow-ready answer.",
            "passport": "Treatment Readiness Passport"
        },
        {
            "area": "Isotope-to-Patient Traceability",
            "triggers": ["isotope", "patient", "dose journey", "traceability", "source to patient", "journey", "end-to-end"],
            "auditor_question": "Can you prove the dose journey from isotope source to patient-slot readiness?",
            "evidence_packet": "Dose Journey Evidence Graph",
            "owner": "QA / Supply Chain / Treatment Coordination",
            "source_engine": "Isotope-to-Patient Evidence Graph™",
            "readiness": 83,
            "answer": "The dose journey is mapped from isotope source, manufacturing, QC, QA release, shipment, treatment-site receipt, patient-slot readiness, and final Governance Passport.",
            "gap": "Treatment-site receipt, final custody confirmation, or dose-to-slot evidence may require stronger linkage.",
            "passport": "Dose Journey Passport"
        },
        {
            "area": "QA Release Defensibility",
            "triggers": ["release", "qa", "qc", "batch release", "defensible release", "release decision", "oos", "oot"],
            "auditor_question": "Can QA defend this release decision?",
            "evidence_packet": "QA Release Defensibility Packet",
            "owner": "QA Release / QC / Compliance",
            "source_engine": "Release Defensibility Engine™",
            "readiness": 81,
            "answer": "Release defensibility is supported by QC result packets, QA release rationale, batch records, CAPA/deviation disposition, EM impact review, SOP/training evidence, access attestation, custody evidence, radioactive material reconciliation, and AuditVault™ verification.",
            "gap": "Release is not defensible if unresolved OOS/OOT, CAPA, EM excursion, missing evidence, or weak QA rationale remains.",
            "passport": "Release Defensibility Passport"
        },
        {
            "area": "Inspection Survivability",
            "triggers": ["inspection", "fda", "nrc", "auditor", "audit", "survive inspection", "inspection tomorrow"],
            "auditor_question": "If an inspector walked in tomorrow, what would fail and what evidence would we show?",
            "evidence_packet": "Inspection Survivability Packet",
            "owner": "QA / Compliance / Internal Audit",
            "source_engine": "Inspection Tomorrow Simulator™",
            "readiness": 80,
            "answer": "Inspection survivability is assessed across QA release, QC packet, batch record, deviation/CAPA, EM, SOP/training, access, custody, radioactive material, evidence integrity, backup/restore, treatment coordination, and data integrity.",
            "gap": "Major or critical findings must be closed before readiness can be represented as inspection-defensible.",
            "passport": "Inspection Survivability Passport"
        },
        {
            "area": "Radioactive Material Accountability",
            "triggers": ["radioactive", "material", "receipt", "waste", "decay", "disposal", "reconciliation", "activity", "mci"],
            "auditor_question": "Can you prove radioactive material receipt, use, transfer, decay, waste, disposal, and reconciliation?",
            "evidence_packet": "Radioactive Material Accountability Ledger",
            "owner": "Radiation Safety / QA / Compliance",
            "source_engine": "Radioactive Material Accountability Ledger™",
            "readiness": 82,
            "answer": "Material accountability is supported by receipt activity, controlled storage, radiolabeling/preparation, QC sampling, release disposition, transfer, treatment-site receipt, waste, decay, residual activity, and final reconciliation.",
            "gap": "Variance, missing evidence, open exceptions, stale records, or unapproved transfers weaken material accountability.",
            "passport": "Radioactive Material Accountability Passport"
        },
        {
            "area": "Patient Slot Protection",
            "triggers": ["patient slot", "appointment", "treatment window", "authorized user", "site readiness", "dose to slot", "slot"],
            "auditor_question": "Can you prove the dose was aligned to the treatment slot?",
            "evidence_packet": "Patient Slot Protection Packet",
            "owner": "Treatment Coordination / Nuclear Medicine / QA",
            "source_engine": "Patient Slot Protection Engine™",
            "readiness": 79,
            "answer": "Patient-slot protection links isotope timing, treatment window, courier ETA, QA release, site readiness, authorized-user readiness, appointment confirmation, dose activity margin, and evidence integrity.",
            "gap": "Scheduling conflicts, weak site readiness, courier delay, or missing slot evidence can create patient-impact governance risk.",
            "passport": "Patient Slot Protection Passport"
        },
        {
            "area": "Chain of Custody / Shipment",
            "triggers": ["shipment", "custody", "courier", "cold chain", "temperature", "transport", "delivery", "receipt"],
            "auditor_question": "Can you prove controlled shipment and chain of custody?",
            "evidence_packet": "Shipment and Custody Evidence Packet",
            "owner": "Supply Chain / Logistics / QA",
            "source_engine": "Isotope-to-Patient Evidence Graph™ + Patient Slot Protection Engine™",
            "readiness": 85,
            "answer": "Custody evidence includes courier dispatch, custody transfer, cold-chain record, shipment exception log, treatment-site receipt confirmation, and dose-to-slot linkage.",
            "gap": "Custody exceptions, courier delay, or weak receipt evidence can reduce release-to-treatment defensibility.",
            "passport": "Shipment Governance Passport"
        },
        {
            "area": "CAPA / Deviation / EM",
            "triggers": ["capa", "deviation", "environmental", "em", "excursion", "impact assessment", "quality event"],
            "auditor_question": "Can you prove CAPA, deviation, or EM exceptions were assessed before release?",
            "evidence_packet": "CAPA / Deviation / EM Impact Packet",
            "owner": "QA / CAPA Owner / Environmental Monitoring",
            "source_engine": "CAPATrust™ + Inspection Tomorrow Simulator™ + Release Defensibility Engine™",
            "readiness": 76,
            "answer": "CAPA, deviation, and EM governance require documented impact assessment, QA disposition, closure evidence, effectiveness review, and release-impact linkage.",
            "gap": "Open CAPA, unresolved deviation, or EM excursion without QA impact disposition can block defensible release.",
            "passport": "Deviation / CAPA Release Impact Passport"
        },
        {
            "area": "SOP / Training",
            "triggers": ["sop", "training", "operator", "procedure", "version", "trained", "qualification"],
            "auditor_question": "Can you prove operators were trained on the effective SOP version?",
            "evidence_packet": "SOP and Training Alignment Packet",
            "owner": "QA / Training / SOP Governance",
            "source_engine": "SOPTrust™",
            "readiness": 84,
            "answer": "SOP/training defensibility requires effective SOP version, role-based training evidence, operator accountability, and execution alignment.",
            "gap": "Training on outdated SOPs or missing role alignment weakens inspection defensibility.",
            "passport": "SOP / Training Governance Passport"
        },
        {
            "area": "Access Governance",
            "triggers": ["access", "user", "privileged", "role", "orphan", "iam", "login", "accountability"],
            "auditor_question": "Can you prove system access and role accountability were appropriate?",
            "evidence_packet": "Access Governance Attestation Packet",
            "owner": "IAM / System Owner / QA",
            "source_engine": "AccessTrust™",
            "readiness": 80,
            "answer": "Access governance is supported by role appropriateness, privileged access review, owner attestation, orphaned access detection, and audit trail accountability.",
            "gap": "Unreviewed privileged access, orphaned users, or weak owner attestation can weaken audit-trail trust.",
            "passport": "Access Governance Passport"
        },
        {
            "area": "Evidence Integrity / AuditVault",
            "triggers": ["evidence", "hash", "tamper", "auditvault", "integrity", "stale", "missing", "audit trail", "record"],
            "auditor_question": "Can you prove evidence was complete, current, retrievable, and not altered?",
            "evidence_packet": "AuditVault™ Evidence Verification Packet",
            "owner": "QA / Compliance / System Owner",
            "source_engine": "AuditVault™ + Governance Black Box Recorder™",
            "readiness": 88,
            "answer": "Evidence integrity is supported by hash verification, previous-hash linkage, evidence completeness, approval lineage, stale-record detection, and inspection retrievability.",
            "gap": "Missing evidence, stale records, tamper alerts, or orphan events reduce inspection survivability.",
            "passport": "AuditVault™ Evidence Integrity Passport"
        },
        {
            "area": "Governance Black Box",
            "triggers": ["black box", "timeline", "what happened", "when", "who approved", "ai", "human decision", "decision lineage"],
            "auditor_question": "Can you prove what happened, when it happened, who owned it, what AI recommended, and what humans decided?",
            "evidence_packet": "Governance Black Box Timeline Packet",
            "owner": "QA / Compliance / Operations Leadership",
            "source_engine": "Governance Black Box Recorder™",
            "readiness": 86,
            "answer": "The black box records readiness signals, evidence events, release decisions, custody movement, AI advisories, human decisions, and record hashes into an inspection-survivable timeline.",
            "gap": "Missing decision links, orphan events, stale events, or AI outputs without human approval weaken defensibility.",
            "passport": "Governance Black Box Passport"
        },
        {
            "area": "Cross-Site Network Readiness",
            "triggers": ["network", "site", "multi-site", "primary site", "secondary site", "fallback", "capacity", "commercial scale"],
            "auditor_question": "Can the commercial RLT network support demand if one site or release lane fails?",
            "evidence_packet": "Cross-Site Commercial Readiness Packet",
            "owner": "Commercialization Leadership / QA / Operations",
            "source_engine": "Cross-Site RLT Network Readiness Mesh™",
            "readiness": 78,
            "answer": "Network readiness is assessed across primary, secondary, and tertiary sites; QC/QA release capacity; hot-cell capacity; isotope supply; courier network; treatment hubs; fallback capacity; and cross-site evidence integrity.",
            "gap": "Weak fallback capacity, release bottlenecks, hot-cell constraints, or cross-site evidence gaps reduce commercial scale-up defensibility.",
            "passport": "Cross-Site Commercial Readiness Passport"
        },
        {
            "area": "Commercialization Stress Test",
            "triggers": ["stress", "what if", "failure", "outage", "delay", "disruption", "recovery", "war room"],
            "auditor_question": "Can the operation survive commercial disruption and recover with governed evidence?",
            "evidence_packet": "Commercialization Stress Test Packet",
            "owner": "Operations Leadership / QA / Supply Chain",
            "source_engine": "Commercialization Stress Test Simulator™",
            "readiness": 77,
            "answer": "Stress testing simulates QC delay, QA delay, hot-cell outage, isotope supply delay, courier delay, EM excursion, CAPA pressure, evidence loss, treatment hub constraints, and access failures.",
            "gap": "Stress scenarios that produce blockers require war-room actions, owner assignment, and evidence closure before commercial readiness is claimed.",
            "passport": "Commercialization Stress Test Passport"
        },
        {
            "area": "Backup / Restore / Continuity",
            "triggers": ["backup", "restore", "continuity", "disaster", "recovery", "rto", "rpo", "system down"],
            "auditor_question": "Can you prove operational continuity and restore readiness?",
            "evidence_packet": "Backup and Restore Readiness Packet",
            "owner": "IT / System Owner / QA",
            "source_engine": "AuditVault™ + Future DR Governance Branch",
            "readiness": 82,
            "answer": "Continuity defensibility requires backup evidence, restore proof, system-owner approval, RTO/RPO governance, restart gates, and evidence lineage.",
            "gap": "Backup success without restore proof or owner approval is weak for inspection and continuity assurance.",
            "passport": "Operational Continuity Passport"
        }
    ]

    matches = []
    for item in evidence_catalog:
        score = 0
        matched_terms = []
        for trig in item["triggers"]:
            if trig in q_lower:
                score += 1
                matched_terms.append(trig)
        if score > 0:
            enriched = dict(item)
            enriched["match_score"] = score
            enriched["matched_terms"] = matched_terms
            matches.append(enriched)

    if not matches:
        # Default to the most cross-cutting evidence areas when the question is broad or unfamiliar.
        default_areas = [
            "Commercial Readiness",
            "Inspection Survivability",
            "Evidence Integrity / AuditVault",
            "Governance Black Box",
            "QA Release Defensibility"
        ]
        for item in evidence_catalog:
            if item["area"] in default_areas:
                enriched = dict(item)
                enriched["match_score"] = 0
                enriched["matched_terms"] = ["broad governance question"]
                matches.append(enriched)

    matches = sorted(matches, key=lambda x: (x["match_score"], x["readiness"]), reverse=True)
    top_matches = matches[:6]

    confidence_score = round(sum(m["readiness"] for m in top_matches) / len(top_matches)) if top_matches else 0

    if confidence_score >= 88:
        status = "Evidence answer appears strong"
        status_class = "ready"
    elif confidence_score >= 80:
        status = "Evidence answer available with warnings"
        status_class = "warning"
    elif confidence_score >= 70:
        status = "Evidence answer needs closure"
        status_class = "gap"
    else:
        status = "Evidence answer not defensible yet"
        status_class = "blocked"

    owners = []
    packets = []
    engines = []
    passports = []
    gaps = []
    for m in top_matches:
        if m["owner"] not in owners:
            owners.append(m["owner"])
        if m["evidence_packet"] not in packets:
            packets.append(m["evidence_packet"])
        if m["source_engine"] not in engines:
            engines.append(m["source_engine"])
        if m["passport"] not in passports:
            passports.append(m["passport"])
        if m["gap"] not in gaps:
            gaps.append(m["gap"])

    executive_answer = (
        "RLTTrust™ can map this question to governed evidence, source engines, accountable owners, and passport outputs. "
        "The answer is advisory until QA, compliance, radiation safety, operations leadership, or the relevant human owner confirms the evidence."
    )

    recommended_actions = [
        "Open the highest-ranked evidence packet and confirm it is current, complete, approved, and retrievable.",
        "Confirm the named human owner has reviewed and accepted the evidence answer.",
        "Verify AuditVault™ hash/evidence integrity before using the answer in inspection response.",
        "Generate or refresh the relevant Governance Passport output.",
        "Record the auditor question, evidence answer, AI advisory, and human decision in the Governance Black Box Recorder™."
    ]

    canned_questions = [
        "Can you prove this IRLT dose journey from isotope source to patient-slot readiness?",
        "Can QA defend the release decision with complete governed evidence?",
        "Can you prove radioactive material receipt, use, decay, waste, disposal, and reconciliation?",
        "If FDA or NRC walked in tomorrow, what would fail and what evidence would we show?",
        "Can you prove operators were trained on the effective SOP version?",
        "Can you prove custody and cold-chain control from dispatch to treatment-site receipt?",
        "Can you prove AI did not make a regulated decision?",
        "Can the commercial network support demand if a site or release lane fails?",
        "Can the operation survive a QC delay, hot-cell outage, courier failure, or evidence loss?",
        "Can you prove evidence was complete, current, retrievable, and tamper-evident?"
    ]

    return {
        "question": question,
        "confidence_score": confidence_score,
        "status": status,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "top_matches": top_matches,
        "owners": owners,
        "evidence_packets": packets,
        "source_engines": engines,
        "passport_outputs": passports,
        "gaps": gaps,
        "recommended_actions": recommended_actions,
        "canned_questions": canned_questions,
        "governance_note": "This engine provides advisory evidence mapping only. It does not replace QA, compliance, radiation safety, clinical authority, regulatory judgment, or human approval."
    }


@app.route("/irlt-commercial-readiness/auditor-question-evidence")
@app.route("/rlttrust/auditor-question-evidence")
@app.route("/rlttrust/auditor-question-to-evidence")
def rlttrust_auditor_question_to_evidence_engine():
    question = request.args.get("question", "")
    result = _rlttrust_auditor_question_engine_data(question)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Auditor Question-to-Evidence Engine™ | RLTTrust™</title>
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

            .panel, .form-panel, .match-card, .packet {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
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

            .match-score {
                font-size: 42px;
                font-weight: 950;
                color: var(--orange2);
                letter-spacing: -.06em;
                margin: 10px 0;
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

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid, .grid-2, .grid-3 {
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
                        <div class="eyebrow">RLTTrust™ Inspection Response Intelligence</div>
                        <h1>Auditor Question-to-Evidence Engine™</h1>
                        <p>
                            Type an auditor, FDA, NRC, QA, compliance, or leadership question. RLTTrust™ maps it to the correct
                            evidence packet, accountable owner, source engine, readiness gap, and Governance Passport output.
                        </p>
                        <p>
                            This turns inspection response from manual searching into governed evidence retrieval.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/governance-black-box">Black Box Recorder</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>
                            <a href="/irlt-commercial-readiness/auditor-question-evidence/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Evidence Answer Confidence</div>
                        <div class="score">{{ result.confidence_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.status }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Ask an Inspection Question</h2>
                    <form method="get">
                        <label>Auditor / QA / Leadership Question</label>
                        <input name="question" value="{{ result.question }}">
                        <button class="button" type="submit">Map Question to Governed Evidence</button>
                    </form>

                    <div class="note">{{ result.governance_note }}</div>

                    <h3 style="margin-top:24px;">Example Questions</h3>
                    <ul>
                        {% for q in result.canned_questions %}
                        <li>{{ q }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div>
                    <h2>Evidence Answer Summary</h2>
                    <div class="grid-3">
                        <div class="packet">
                            <h3>Accountable Owners</h3>
                            {% for owner in result.owners %}
                            <span class="pill">{{ owner }}</span>
                            {% endfor %}
                        </div>
                        <div class="packet">
                            <h3>Source Engines</h3>
                            {% for engine in result.source_engines %}
                            <span class="pill">{{ engine }}</span>
                            {% endfor %}
                        </div>
                        <div class="packet">
                            <h3>Passport Outputs</h3>
                            {% for passport in result.passport_outputs %}
                            <span class="pill">{{ passport }}</span>
                            {% endfor %}
                        </div>
                    </div>

                    <div class="panel" style="margin-top:18px;">
                        <h2>Evidence Packets Needed</h2>
                        {% for packet in result.evidence_packets %}
                        <span class="pill">{{ packet }}</span>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Top Evidence Matches</h2>
                <div class="grid-3">
                    {% for m in result.top_matches %}
                    <div class="match-card">
                        <div class="eyebrow">{{ m.area }}</div>
                        <div class="match-score">{{ m.readiness }}%</div>
                        <div class="bar"><span style="width: {{ m.readiness }}%;"></span></div>
                        <h3>{{ m.auditor_question }}</h3>
                        <p><strong style="color:#fff2e6;">Answer:</strong> {{ m.answer }}</p>
                        <p><strong style="color:#fff2e6;">Evidence Packet:</strong> {{ m.evidence_packet }}</p>
                        <p><strong style="color:#fff2e6;">Owner:</strong> {{ m.owner }}</p>
                        <p><strong style="color:#fff2e6;">Source Engine:</strong> {{ m.source_engine }}</p>
                        <p><strong style="color:#fff2e6;">Gap:</strong> {{ m.gap }}</p>
                        <p><strong style="color:#fff2e6;">Passport:</strong> {{ m.passport }}</p>
                        <p><strong style="color:#fff2e6;">Matched Terms:</strong>
                            {% for term in m.matched_terms %}
                            <span class="pill">{{ term }}</span>
                            {% endfor %}
                        </p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Readiness Gaps to Check</h2>
                    <ul>
                        {% for gap in result.gaps %}
                        <li>{{ gap }}</li>
                        {% endfor %}
                    </ul>
                </div>

                <div class="panel">
                    <h2>Recommended Evidence Response Actions</h2>
                    <ul>
                        {% for action in result.recommended_actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Auditor Response Table</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Mapped Area</th>
                                <th>Auditor Question</th>
                                <th>Evidence Packet</th>
                                <th>Owner</th>
                                <th>Source Engine</th>
                                <th>Passport</th>
                                <th>Readiness</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for m in result.top_matches %}
                            <tr>
                                <td><strong>{{ m.area }}</strong></td>
                                <td>{{ m.auditor_question }}</td>
                                <td>{{ m.evidence_packet }}</td>
                                <td>{{ m.owner }}</td>
                                <td>{{ m.source_engine }}</td>
                                <td>{{ m.passport }}</td>
                                <td>{{ m.readiness }}%</td>
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


@app.route("/irlt-commercial-readiness/auditor-question-evidence/api")
@app.route("/rlttrust/auditor-question-evidence/api")
@app.route("/rlttrust/auditor-question-to-evidence/api")
def rlttrust_auditor_question_to_evidence_engine_api():
    question = request.args.get("question", "")
    return jsonify(_rlttrust_auditor_question_engine_data(question))

# ============================================================
# End Auditor Question-to-Evidence Engine™
# ============================================================

'''

    # Add Auditor Question-to-Evidence link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_AUDITOR_QUESTION_EVIDENCE_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/governance-black-box">Black Box Recorder</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_AUDITOR_QUESTION_EVIDENCE_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence Engine</a>',
            1
        )
        print("Added Auditor Question-to-Evidence Engine link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Auditor Question-to-Evidence Engine successfully.")

