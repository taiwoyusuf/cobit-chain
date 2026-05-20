from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust IRLT Commercial Readiness Command Center already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Purpose: Operational Governance Assurance for Commercial IRLT Scale-Up
# Safe additive module: does not overwrite protected modules/routes.
# ============================================================

from flask import render_template_string, jsonify

def _rlttrust_command_center_data():
    domains = [
        {
            "name": "QC Readiness",
            "score": 87,
            "status": "Governed Warning",
            "signal": "QC evidence exists, but release timing and method readiness need continuous monitoring.",
            "owner": "QC / QA",
            "risk": "Late QC result can consume isotope usability window."
        },
        {
            "name": "Validation Readiness",
            "score": 82,
            "status": "Governed Warning",
            "signal": "Core validation package is progressing, but dependency evidence must remain linked to release processes.",
            "owner": "Validation",
            "risk": "Unlinked validation evidence weakens inspection defensibility."
        },
        {
            "name": "Environmental Monitoring",
            "score": 79,
            "status": "At Risk",
            "signal": "EM controls are active, but unresolved excursion lineage would affect release defensibility.",
            "owner": "Manufacturing / QA",
            "risk": "EM exception can propagate to batch release and treatment confidence."
        },
        {
            "name": "SOP Governance",
            "score": 91,
            "status": "Strong",
            "signal": "SOP control layer is suitable for SOPTrust™ drift detection and execution-readiness mapping.",
            "owner": "QA / SOP Governance",
            "risk": "SOP drift can create training and execution gaps."
        },
        {
            "name": "Deviation / CAPA",
            "score": 76,
            "status": "At Risk",
            "signal": "Open deviation dependencies need CAPATrust™ closure defensibility before commercial release confidence.",
            "owner": "QA / CAPA",
            "risk": "Open CAPA dependency can block audit-ready release."
        },
        {
            "name": "Training Readiness",
            "score": 84,
            "status": "Governed Warning",
            "signal": "Training evidence must stay current against SOP versions, roles, access, and treatment-chain tasks.",
            "owner": "Training / QA",
            "risk": "Trained-on-old-SOP issue can become inspection finding."
        },
        {
            "name": "Backup Review",
            "score": 88,
            "status": "Strong",
            "signal": "Backup review should feed AuditVault™ and disaster recovery governance lineage.",
            "owner": "IT / System Owner",
            "risk": "Restore proof gap weakens operational continuity."
        },
        {
            "name": "Access Governance",
            "score": 81,
            "status": "Governed Warning",
            "signal": "AccessTrust™ should confirm role appropriateness, privileged access, and orphaned access exposure.",
            "owner": "IAM / System Owner",
            "risk": "Incorrect access can invalidate accountability and audit trail trust."
        },
        {
            "name": "Chain of Custody",
            "score": 86,
            "status": "Governed Warning",
            "signal": "Isotope-to-patient custody chain must be continuously verified across manufacturing, release, shipment, and receipt.",
            "owner": "Supply Chain / QA",
            "risk": "Custody gap can damage patient delivery confidence and inspection survivability."
        },
        {
            "name": "Release Governance",
            "score": 78,
            "status": "At Risk",
            "signal": "Release can be approved only when QC, QA, EM, deviation, training, and custody evidence converge.",
            "owner": "QA Release",
            "risk": "Release approval without full evidence lineage creates defensibility risk."
        },
        {
            "name": "Audit Readiness",
            "score": 83,
            "status": "Governed Warning",
            "signal": "AuditVault™ should assemble evidence into inspection-survivable packets and passports.",
            "owner": "QA / Compliance",
            "risk": "Evidence may exist but remain scattered, stale, or hard to retrieve."
        },
        {
            "name": "Operational Trust Scoring",
            "score": 85,
            "status": "Governed Warning",
            "signal": "IntegrityLens™ converts domain-level evidence into leadership-level readiness intelligence.",
            "owner": "Operations Leadership",
            "risk": "Leadership may see status without understanding evidence strength."
        }
    ]

    overall_score = round(sum(d["score"] for d in domains) / len(domains))

    executive_answer = "Commercial readiness is promising, but not yet fully inspection-defensible without closing release, CAPA, EM, and dependency evidence gaps."

    flagship_features = [
        {
            "name": "Decay-Aware Commercial Readiness Twin™",
            "level": "Flagship",
            "pain_point": "IRLT readiness decays with time because isotope activity, QC release, courier timing, and treatment windows are perishable.",
            "capability": "Calculates whether manufacturing, QC, QA release, shipment, receipt, and treatment coordination remain defensible inside the isotope window.",
            "buyer_value": "Leadership can see whether a dose can still reach the patient safely, compliantly, and on time."
        },
        {
            "name": "Isotope-to-Patient Evidence Graph™",
            "level": "Flagship",
            "pain_point": "Evidence is scattered across manufacturing, QC, QA, logistics, treatment coordination, and compliance systems.",
            "capability": "Connects isotope source, batch, QC result, QA release, shipment custody, receipt, treatment readiness, and final governance passport.",
            "buyer_value": "Creates one governed trace from isotope origin to patient-treatment readiness."
        },
        {
            "name": "Release Defensibility Engine™",
            "level": "Critical",
            "pain_point": "Release status alone does not prove that release can survive inspection.",
            "capability": "Scores whether QA can defend release using QC evidence, EM evidence, deviation/CAPA status, SOP version, training, access, and custody evidence.",
            "buyer_value": "Turns release from a checkbox into an evidence-backed governance decision."
        },
        {
            "name": "Inspection Tomorrow Simulator™",
            "level": "Critical",
            "pain_point": "Organizations often do not know what would fail until an auditor asks.",
            "capability": "Runs a simulated FDA/NRC/QA inspection and identifies missing evidence, weak approvals, stale records, open deviations, and custody breaks.",
            "buyer_value": "Shows whether the operation can survive inspection tomorrow."
        },
        {
            "name": "Dependency Propagation Map™",
            "level": "Critical",
            "pain_point": "A small issue in SOP, EM, access, QC, or CAPA can silently affect release readiness.",
            "capability": "Maps how one weak control propagates across batch release, shipment, treatment, and commercial readiness.",
            "buyer_value": "Makes hidden operational risk visible before it becomes a launch blocker."
        },
        {
            "name": "Governed Dose Journey Passport™",
            "level": "Critical",
            "pain_point": "There is often no single defensible file for the full dose journey.",
            "capability": "Generates a passport showing source, batch, QC, release, custody, shipment, treatment readiness, approvals, and evidence integrity.",
            "buyer_value": "Creates an audit-ready story for every governed dose journey."
        },
        {
            "name": "Radioactive Material Accountability Ledger™",
            "level": "Critical",
            "pain_point": "Radioactive material must be governed from receipt through use, decay, waste, transfer, and reconciliation.",
            "capability": "Tracks governed events for receipt, preparation, use, transfer, decay, waste, disposal, reconciliation, and closure evidence.",
            "buyer_value": "Strengthens radioactive material accountability and inspection defensibility."
        },
        {
            "name": "Evidence Expiry / Staleness Engine™",
            "level": "Important",
            "pain_point": "Evidence can exist but still be stale, expired, mismatched, or no longer tied to the correct SOP or role.",
            "capability": "Flags expired training, outdated SOPs, overdue access reviews, stale backup reviews, and aged QC evidence.",
            "buyer_value": "Prevents false readiness caused by outdated evidence."
        },
        {
            "name": "Commercial Readiness Confidence Score™",
            "level": "Executive",
            "pain_point": "Executives need one defensible readiness answer, not twelve disconnected departmental reports.",
            "capability": "Aggregates QC, validation, SOP, CAPA, access, backup, custody, release, audit, and operational trust into one score.",
            "buyer_value": "Gives leadership a single governed answer: ready, warning, or not defensible."
        },
        {
            "name": "AI Governance Reasoning Panel™",
            "level": "Governed AI",
            "pain_point": "AI cannot be allowed to become the regulated source of truth.",
            "capability": "Explains risk, blockers, and evidence gaps while preserving human approval as the authoritative control layer.",
            "buyer_value": "Provides explainable intelligence without replacing QA, compliance, or system-owner accountability."
        },
        {
            "name": "Readiness-to-Release War Room™",
            "level": "Launch Mode",
            "pain_point": "Commercial launch readiness fails when blockers, owners, and dependencies are unclear.",
            "capability": "Shows launch-week blockers, owners, due dates, evidence gaps, release risks, and dependency impact.",
            "buyer_value": "Gives commercialization teams one operational command surface."
        }
    ]

    futuristic_features = [
        {
            "name": "Patient Slot Protection Engine™",
            "vision": "Protects scheduled patient treatment windows by linking isotope timing, batch release, courier status, receiving readiness, and treatment-site readiness.",
            "why_it_wows": "Moves the product from batch governance to patient-impact governance."
        },
        {
            "name": "Cross-Site RLT Network Readiness Mesh™",
            "vision": "Compares readiness across multiple RLT manufacturing sites, QC labs, hot cells, couriers, and treatment territories.",
            "why_it_wows": "Creates a network-level governance brain for commercial radiopharma scale-up."
        },
        {
            "name": "Auditor Question-to-Evidence Engine™",
            "vision": "Allows a QA leader to type an inspection question and instantly retrieve the governed evidence trail, approval chain, hash status, and passport link.",
            "why_it_wows": "Turns inspection response from manual searching into evidence-driven audit survivability."
        },
        {
            "name": "Governance Black Box Recorder™",
            "vision": "Records every critical readiness signal, evidence change, approval event, custody movement, release dependency, and AI recommendation as a governed timeline.",
            "why_it_wows": "Gives radiopharma operations an aircraft-style black box for inspection, deviation investigation, and leadership review."
        },
        {
            "name": "Physics-Aware Readiness Decay Model™",
            "vision": "Models readiness as a perishable asset affected by isotope decay, QC delay, courier latency, treatment appointment risk, and evidence staleness.",
            "why_it_wows": "Applies the physics of radiopharma directly to operational governance."
        },
        {
            "name": "Commercialization Stress Test Simulator™",
            "vision": "Runs scenarios such as QC delay, hot-cell outage, EM excursion, courier failure, SOP mismatch, or QA release bottleneck.",
            "why_it_wows": "Lets leadership test commercial scale-up resilience before failure happens."
        },
        {
            "name": "Human-Controlled AI Governance Firewall™",
            "vision": "Separates AI insight from regulated decision-making by requiring human approval, evidence confirmation, and controlled escalation.",
            "why_it_wows": "Makes the AI safe for GxP and inspection-sensitive environments."
        }
    ]

    propagation_scenarios = [
        {
            "trigger": "QC release delay",
            "propagation": "QC delay → QA release compression → courier dispatch risk → treatment window risk → patient slot exposure",
            "severity": "Critical",
            "control": "Activate Decay-Aware Twin and Release Defensibility Engine."
        },
        {
            "trigger": "Environmental monitoring excursion",
            "propagation": "EM exception → batch impact assessment → QA hold → release defensibility reduction → audit readiness warning",
            "severity": "High",
            "control": "Require CAPATrust™ linkage and QA closure evidence before release confidence improves."
        },
        {
            "trigger": "SOP version drift",
            "propagation": "SOP mismatch → training mismatch → operator execution risk → audit finding exposure",
            "severity": "High",
            "control": "Run SOPTrust™ drift check and Evidence Expiry Engine."
        },
        {
            "trigger": "Privileged access not reviewed",
            "propagation": "Access gap → accountability weakness → audit trail trust reduction → release evidence challenge",
            "severity": "Medium",
            "control": "Run AccessTrust™ review and owner attestation."
        },
        {
            "trigger": "Courier cold-chain exception",
            "propagation": "Temperature/custody alert → shipment risk → receipt investigation → treatment readiness risk",
            "severity": "Critical",
            "control": "Activate custody governance and dose journey passport escalation."
        }
    ]

    inspection_findings = [
        {
            "question": "Can you prove this dose journey from isotope source to treatment readiness?",
            "answer": "Partially defensible",
            "gap": "Treatment-site receipt and final custody confirmation need stronger evidence linkage.",
            "engine": "Isotope-to-Patient Evidence Graph™"
        },
        {
            "question": "Can QA defend release if QC was delayed?",
            "answer": "Warning",
            "gap": "Release rationale must explicitly document decay-window impact and QA risk acceptance.",
            "engine": "Release Defensibility Engine™"
        },
        {
            "question": "Are all operators trained on the effective SOP version?",
            "answer": "Needs verification",
            "gap": "Training-to-SOP version matching should be confirmed before launch readiness signoff.",
            "engine": "Evidence Expiry / Staleness Engine™"
        },
        {
            "question": "Can radioactive material reconciliation survive inspection?",
            "answer": "Buildable control",
            "gap": "Ledger should show receipt, use, waste, decay, disposal, reconciliation, and approval closure.",
            "engine": "Radioactive Material Accountability Ledger™"
        }
    ]

    passports = [
        "Commercial Readiness Passport",
        "Batch Governance Passport",
        "Dose Journey Passport",
        "Shipment Governance Passport",
        "Treatment Readiness Passport",
        "Release Defensibility Passport",
        "Radioactive Material Accountability Passport",
        "Inspection Survivability Passport"
    ]

    return {
        "overall_score": overall_score,
        "executive_answer": executive_answer,
        "domains": domains,
        "flagship_features": flagship_features,
        "futuristic_features": futuristic_features,
        "propagation_scenarios": propagation_scenarios,
        "inspection_findings": inspection_findings,
        "passports": passports
    }


@app.route("/irlt-commercial-readiness")
@app.route("/irlt-commercial-readiness/command-center")
@app.route("/rlttrust-command-center")
@app.route("/rlttrust/commercial-readiness")
def rlttrust_irlt_commercial_readiness_command_center():
    data = _rlttrust_command_center_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>RLTTrust™ | IRLT Commercial Readiness Governance Command Center™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --bg: #05070f;
                --panel: #101827;
                --panel2: #141f33;
                --line: rgba(255,255,255,0.12);
                --text: #edf4ff;
                --muted: #a8b8d8;
                --green: #37d67a;
                --yellow: #ffd166;
                --red: #ff5c7a;
                --blue: #56ccf2;
                --purple: #a78bfa;
                --orange: #ffb86b;
            }
            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(86,204,242,0.22), transparent 32%),
                    radial-gradient(circle at top right, rgba(167,139,250,0.18), transparent 30%),
                    linear-gradient(180deg, #05070f 0%, #08101f 45%, #05070f 100%);
                color: var(--text);
            }
            .wrap { max-width: 1440px; margin: 0 auto; padding: 30px; }
            .hero {
                border: 1px solid var(--line);
                border-radius: 28px;
                padding: 34px;
                background:
                    linear-gradient(135deg, rgba(86,204,242,0.16), rgba(167,139,250,0.10)),
                    rgba(16,24,39,0.92);
                box-shadow: 0 24px 80px rgba(0,0,0,0.42);
            }
            .eyebrow {
                text-transform: uppercase;
                letter-spacing: 0.16em;
                font-size: 12px;
                color: var(--blue);
                font-weight: 800;
            }
            h1 { font-size: 42px; line-height: 1.05; margin: 12px 0; }
            h2 { font-size: 25px; margin: 0 0 16px; }
            h3 { font-size: 17px; margin: 0 0 8px; }
            p { color: var(--muted); line-height: 1.55; }
            .hero-grid {
                display: grid;
                grid-template-columns: 1.45fr 0.8fr;
                gap: 24px;
                align-items: stretch;
            }
            .score-card {
                background: rgba(5,7,15,0.56);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 24px;
            }
            .score {
                font-size: 72px;
                font-weight: 900;
                color: var(--yellow);
                letter-spacing: -0.06em;
            }
            .label-pill {
                display: inline-flex;
                padding: 8px 12px;
                border-radius: 999px;
                background: rgba(255,209,102,0.12);
                border: 1px solid rgba(255,209,102,0.32);
                color: var(--yellow);
                font-weight: 800;
                font-size: 12px;
                margin: 5px 7px 5px 0;
            }
            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }
            .nav a {
                color: var(--text);
                text-decoration: none;
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.05);
                border-radius: 999px;
                padding: 9px 13px;
                font-size: 13px;
            }
            .section { margin-top: 30px; }
            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
            }
            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
            }
            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 16px;
            }
            .card {
                background: rgba(16,24,39,0.88);
                border: 1px solid var(--line);
                border-radius: 22px;
                padding: 18px;
                box-shadow: 0 16px 50px rgba(0,0,0,0.25);
            }
            .metric {
                display: flex;
                justify-content: space-between;
                gap: 12px;
                align-items: center;
                margin-bottom: 10px;
            }
            .bar {
                height: 9px;
                background: rgba(255,255,255,0.08);
                border-radius: 999px;
                overflow: hidden;
                margin: 12px 0;
            }
            .bar span {
                display: block;
                height: 100%;
                background: linear-gradient(90deg, var(--red), var(--yellow), var(--green));
                border-radius: 999px;
            }
            .tag {
                display: inline-block;
                padding: 5px 9px;
                border-radius: 999px;
                background: rgba(86,204,242,0.10);
                border: 1px solid rgba(86,204,242,0.22);
                color: var(--blue);
                font-size: 11px;
                font-weight: 800;
                margin-bottom: 10px;
            }
            .tag.red { color: var(--red); border-color: rgba(255,92,122,0.28); background: rgba(255,92,122,0.10); }
            .tag.yellow { color: var(--yellow); border-color: rgba(255,209,102,0.28); background: rgba(255,209,102,0.10); }
            .tag.green { color: var(--green); border-color: rgba(55,214,122,0.28); background: rgba(55,214,122,0.10); }
            .feature {
                min-height: 238px;
                position: relative;
                overflow: hidden;
            }
            .feature:after {
                content: "";
                position: absolute;
                width: 130px;
                height: 130px;
                right: -50px;
                top: -50px;
                border-radius: 50%;
                background: radial-gradient(circle, rgba(86,204,242,0.18), transparent 70%);
            }
            .timeline {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                margin-top: 16px;
            }
            .step {
                padding: 14px;
                border-radius: 18px;
                border: 1px solid var(--line);
                background: rgba(255,255,255,0.045);
                min-height: 105px;
            }
            .step b { display: block; margin-bottom: 8px; color: var(--text); }
            .step small { color: var(--muted); }
            .warning-panel {
                border: 1px solid rgba(255,209,102,0.38);
                background: linear-gradient(135deg, rgba(255,209,102,0.13), rgba(16,24,39,0.92));
                border-radius: 24px;
                padding: 22px;
            }
            .critical-panel {
                border: 1px solid rgba(255,92,122,0.38);
                background: linear-gradient(135deg, rgba(255,92,122,0.13), rgba(16,24,39,0.92));
                border-radius: 24px;
                padding: 22px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                overflow: hidden;
                border-radius: 18px;
                background: rgba(16,24,39,0.88);
                border: 1px solid var(--line);
            }
            th, td {
                padding: 14px;
                border-bottom: 1px solid var(--line);
                text-align: left;
                vertical-align: top;
                color: var(--muted);
                font-size: 14px;
            }
            th {
                color: var(--text);
                background: rgba(255,255,255,0.045);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }
            td strong { color: var(--text); }
            .passport-list {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
            }
            .passport {
                border: 1px solid rgba(55,214,122,0.28);
                background: rgba(55,214,122,0.09);
                color: #d7ffe7;
                padding: 10px 12px;
                border-radius: 14px;
                font-weight: 800;
                font-size: 13px;
            }
            .ai-box {
                border: 1px solid rgba(167,139,250,0.42);
                background: linear-gradient(135deg, rgba(167,139,250,0.16), rgba(86,204,242,0.08));
                border-radius: 24px;
                padding: 22px;
            }
            .footer {
                color: var(--muted);
                font-size: 12px;
                margin: 34px 0 10px;
                border-top: 1px solid var(--line);
                padding-top: 18px;
            }
            @media (max-width: 1100px) {
                .hero-grid, .grid-4, .grid-3, .grid-2, .timeline {
                    grid-template-columns: 1fr;
                }
                h1 { font-size: 32px; }
            }
        </style>
    </head>
    <body>
        <div class="wrap">

            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">COBIT-Chain™ / AssuranceLayer™ Platform A</div>
                        <h1>RLTTrust™ / IRLT Commercial Readiness Governance Command Center™</h1>
                        <p>
                            A governance assurance and operational trust overlay for commercial radioligand therapy scale-up.
                            It does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, or manufacturing systems.
                            It validates readiness, evidence, dependencies, release defensibility, chain-of-custody integrity,
                            and inspection survivability across the IRLT lifecycle.
                        </p>
                        <div>
                            <span class="label-pill">Decay-Aware</span>
                            <span class="label-pill">Evidence-Governed</span>
                            <span class="label-pill">Inspection-Survivable</span>
                            <span class="label-pill">Human-Controlled AI</span>
                        </div>
                        <div class="nav">
                            <a href="#domains">Readiness Domains</a>
                            <a href="#decay">Decay-Aware Twin</a>
                            <a href="#features">World-Class Features</a>
                            <a href="#futuristic">Futuristic Layer</a>
                            <a href="#inspection">Inspection Simulator</a>
                            <a href="#warroom">Release War Room</a>
                            <a href="#passports">Governance Passports</a>
                            <a href="/irlt-commercial-readiness/api">API Summary</a>
                        </div>
                    </div>
                    <div class="score-card">
                        <div class="eyebrow">Commercial Readiness Confidence</div>
                        <div class="score">{{ overall_score }}%</div>
                        <h3>Executive Answer</h3>
                        <p>{{ executive_answer }}</p>
                        <div class="bar"><span style="width: {{ overall_score }}%;"></span></div>
                        <p><strong style="color:#ffd166;">Status:</strong> Governed Warning — strong foundation, but release defensibility and dependency closure must improve before full commercial confidence.</p>
                    </div>
                </div>
            </section>

            <section class="section" id="decay">
                <div class="warning-panel">
                    <div class="eyebrow">Flagship Invention</div>
                    <h2>Decay-Aware Commercial Readiness Twin™</h2>
                    <p>
                        In IRLT, readiness is perishable. The command center treats readiness as a time-sensitive governed asset
                        affected by isotope decay, QC delay, QA release compression, courier latency, custody confirmation,
                        patient slot timing, and evidence staleness.
                    </p>
                    <div class="timeline">
                        <div class="step"><b>1. Isotope Source</b><small>Origin, activity, receipt evidence, radioactive material accountability.</small></div>
                        <div class="step"><b>2. Radiolabeling</b><small>Batch process, operator accountability, SOP version, manufacturing evidence.</small></div>
                        <div class="step"><b>3. QC Testing</b><small>Test completion, method readiness, deviation impact, release timer pressure.</small></div>
                        <div class="step"><b>4. QA Release</b><small>Release defensibility, approvals, evidence completeness, CAPA dependencies.</small></div>
                        <div class="step"><b>5. Shipment</b><small>Custody, cold-chain, courier timing, Class 7 control evidence.</small></div>
                        <div class="step"><b>6. Treatment Readiness</b><small>Receipt, patient slot, nuclear medicine readiness, final governance passport.</small></div>
                    </div>
                </div>
            </section>

            <section class="section" id="domains">
                <h2>Commercial Readiness Domains</h2>
                <div class="grid-4">
                    {% for d in domains %}
                    <div class="card">
                        {% if d.score >= 88 %}
                            <span class="tag green">{{ d.status }}</span>
                        {% elif d.score >= 80 %}
                            <span class="tag yellow">{{ d.status }}</span>
                        {% else %}
                            <span class="tag red">{{ d.status }}</span>
                        {% endif %}
                        <div class="metric">
                            <h3>{{ d.name }}</h3>
                            <strong>{{ d.score }}%</strong>
                        </div>
                        <div class="bar"><span style="width: {{ d.score }}%;"></span></div>
                        <p>{{ d.signal }}</p>
                        <p><strong>Owner:</strong> {{ d.owner }}</p>
                        <p><strong>Risk:</strong> {{ d.risk }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section" id="features">
                <h2>World-Class Product Features Added</h2>
                <div class="grid-3">
                    {% for f in flagship_features %}
                    <div class="card feature">
                        <span class="tag">{{ f.level }}</span>
                        <h3>{{ f.name }}</h3>
                        <p><strong>Pain point:</strong> {{ f.pain_point }}</p>
                        <p><strong>Capability:</strong> {{ f.capability }}</p>
                        <p><strong>Buyer value:</strong> {{ f.buyer_value }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section" id="futuristic">
                <div class="ai-box">
                    <div class="eyebrow">Novartis-Grade Future Layer</div>
                    <h2>Advanced IRLT Governance Intelligence Layer</h2>
                    <p>
                        These features position RLTTrust™ beyond ordinary compliance dashboards. The product becomes a
                        radiopharma operating intelligence layer that protects patient slots, release timing, network capacity,
                        inspection response, and human-governed AI decision support.
                    </p>
                </div>
                <div class="grid-3" style="margin-top:16px;">
                    {% for f in futuristic_features %}
                    <div class="card">
                        <span class="tag">{{ f.name }}</span>
                        <p><strong>Vision:</strong> {{ f.vision }}</p>
                        <p><strong>Why it wows:</strong> {{ f.why_it_wows }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <h2>Dependency Propagation Map™</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Trigger</th>
                            <th>Propagation</th>
                            <th>Severity</th>
                            <th>Governance Control</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for s in propagation_scenarios %}
                        <tr>
                            <td><strong>{{ s.trigger }}</strong></td>
                            <td>{{ s.propagation }}</td>
                            <td>{{ s.severity }}</td>
                            <td>{{ s.control }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </section>

            <section class="section" id="inspection">
                <h2>Inspection Tomorrow Simulator™</h2>
                <div class="critical-panel">
                    <p>
                        One executive question: <strong style="color:#fff;">If FDA, NRC, QA, or a partner auditor walked in tomorrow,
                        what would fail, what would survive, and what evidence would we show?</strong>
                    </p>
                </div>
                <table style="margin-top:16px;">
                    <thead>
                        <tr>
                            <th>Inspection Question</th>
                            <th>Current Answer</th>
                            <th>Evidence Gap</th>
                            <th>Engine</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for i in inspection_findings %}
                        <tr>
                            <td><strong>{{ i.question }}</strong></td>
                            <td>{{ i.answer }}</td>
                            <td>{{ i.gap }}</td>
                            <td>{{ i.engine }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </section>

            <section class="section" id="warroom">
                <h2>Readiness-to-Release War Room™</h2>
                <div class="grid-2">
                    <div class="card">
                        <span class="tag red">Critical Launch Blockers</span>
                        <h3>Release Defensibility Watchlist</h3>
                        <p>Open deviation/CAPA dependencies, EM exception status, QC timing pressure, QA release rationale, custody evidence, and patient slot exposure must converge before commercial confidence can be marked defensible.</p>
                    </div>
                    <div class="card">
                        <span class="tag yellow">Leadership Question</span>
                        <h3>Can We Treat Tomorrow?</h3>
                        <p>The command center produces a governed answer: Yes, Yes with warnings, No due to evidence gaps, or No due to release/treatment dependency blockage.</p>
                    </div>
                    <div class="card">
                        <span class="tag">AI Advisory Only</span>
                        <h3>Human-Controlled AI Governance Firewall™</h3>
                        <p>AI may explain risk and recommend actions, but QA, compliance, system owners, and operational leadership remain the authoritative decision layer.</p>
                    </div>
                    <div class="card">
                        <span class="tag green">AuditVault™ Ready</span>
                        <h3>Governance Black Box Recorder™</h3>
                        <p>Records readiness signals, evidence changes, approval lineage, custody events, AI recommendations, and human decisions into an inspection-survivable timeline.</p>
                    </div>
                </div>
            </section>

            <section class="section" id="passports">
                <h2>Governance Passport Factory™</h2>
                <p>
                    The passport layer converts operational readiness into defensible artifacts for leadership, QA, compliance,
                    inspections, partners, and commercialization teams.
                </p>
                <div class="passport-list">
                    {% for p in passports %}
                    <div class="passport">{{ p }}</div>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <div class="ai-box">
                    <div class="eyebrow">Positioning</div>
                    <h2>What Makes This Different</h2>
                    <p>
                        RLTTrust™ is not another dashboard. It is a governed operational trust layer that combines physics-aware readiness,
                        evidence integrity, release defensibility, inspection survivability, dependency intelligence, radioactive material
                        accountability, and human-controlled AI into one commercial readiness command center.
                    </p>
                </div>
            </section>

            <div class="footer">
                RLTTrust™ / IRLT Commercial Readiness Governance Command Center™ — COBIT-Chain™ / AssuranceLayer™ Platform A.
                Advisory AI only. Human governance remains the authoritative control layer.
            </div>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, **data)


@app.route("/irlt-commercial-readiness/api")
@app.route("/rlttrust/commercial-readiness/api")
def rlttrust_irlt_commercial_readiness_api():
    return jsonify(_rlttrust_command_center_data())


@app.route("/irlt-commercial-readiness/passport")
@app.route("/rlttrust/commercial-readiness/passport")
def rlttrust_irlt_commercial_readiness_passport():
    data = _rlttrust_command_center_data()
    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>RLTTrust™ Governance Passport Factory™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                background: #05070f;
                color: #edf4ff;
            }
            .wrap { max-width: 1100px; margin: 0 auto; padding: 34px; }
            .panel {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 26px;
                padding: 28px;
                background: linear-gradient(135deg, rgba(86,204,242,0.13), rgba(167,139,250,0.09)), #101827;
                box-shadow: 0 24px 80px rgba(0,0,0,0.42);
            }
            .eyebrow {
                text-transform: uppercase;
                letter-spacing: 0.16em;
                color: #56ccf2;
                font-weight: 900;
                font-size: 12px;
            }
            h1 { font-size: 36px; margin: 10px 0; }
            p { color: #a8b8d8; line-height: 1.55; }
            .score {
                font-size: 64px;
                font-weight: 900;
                color: #ffd166;
            }
            .grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 16px;
                margin-top: 18px;
            }
            .card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 20px;
                padding: 18px;
                background: rgba(255,255,255,0.045);
            }
            .passport {
                display: inline-block;
                margin: 6px;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(55,214,122,0.09);
                border: 1px solid rgba(55,214,122,0.28);
                color: #d7ffe7;
                font-weight: 800;
            }
            a { color: #56ccf2; }
            @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="panel">
                <div class="eyebrow">Governance Passport Factory™</div>
                <h1>RLTTrust™ Commercial Readiness Passport</h1>
                <p>
                    This passport is a leadership-facing readiness artifact that summarizes commercial readiness,
                    evidence defensibility, release confidence, custody governance, and inspection survivability.
                </p>
                <div class="score">{{ overall_score }}%</div>
                <p><strong>Executive Answer:</strong> {{ executive_answer }}</p>

                <h2>Available Passport Types</h2>
                {% for p in passports %}
                    <span class="passport">{{ p }}</span>
                {% endfor %}

                <div class="grid">
                    <div class="card">
                        <h3>Evidence Integrity</h3>
                        <p>Designed to connect with AuditVault™ for evidence hashing, tamper detection, immutable lineage, and inspection survivability.</p>
                    </div>
                    <div class="card">
                        <h3>Release Defensibility</h3>
                        <p>Designed to connect with QA release evidence, QC results, deviations/CAPA, SOP version, training, access, and chain-of-custody confirmation.</p>
                    </div>
                    <div class="card">
                        <h3>Decay-Aware Readiness</h3>
                        <p>Designed to evaluate whether isotope, batch, QC, release, courier, and treatment-site readiness remain aligned inside the operational window.</p>
                    </div>
                    <div class="card">
                        <h3>Human Governance</h3>
                        <p>AI remains advisory. Final control authority remains with QA, compliance, system owners, and operational leadership.</p>
                    </div>
                </div>

                <p style="margin-top:24px;"><a href="/irlt-commercial-readiness">Back to Command Center</a></p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, **data)

# ============================================================
# End RLTTrust™ / IRLT Commercial Readiness Command Center
# ============================================================

'''

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust IRLT Commercial Readiness Governance Command Center successfully.")

