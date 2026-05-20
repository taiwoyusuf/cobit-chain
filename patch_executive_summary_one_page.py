from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_EXECUTIVE_SUMMARY_ONE_PAGE_VIEW_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Executive Summary One-Page View already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_EXECUTIVE_SUMMARY_ONE_PAGE_VIEW_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Executive Summary One-Page View™
# Purpose: Boardroom-ready one-page executive summary for screenshots,
#          buyer pitching, internal storytelling, and leadership alignment.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify

def _rlttrust_executive_summary_one_page_data():
    headline = {
        "title": "RLTTrust™",
        "subtitle": "IRLT Commercial Readiness Governance Command Center™",
        "category": "Enterprise Governance Assurance Platform for regulated radiopharma and IRLT operations",
        "one_sentence": "RLTTrust™ gives radiopharma leadership one governed command layer to defend commercialization readiness, release confidence, isotope-to-patient traceability, radioactive material accountability, inspection survivability, patient-slot protection, and commercial scale-up.",
        "core_question": "Can leadership operationally defend IRLT commercialization readiness with governed evidence?",
        "positioning": "RLTTrust™ does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics systems, treatment scheduling, or manufacturing systems. It overlays them with governed evidence, operational trust scoring, inspection-survivable lineage, and executive readiness passports."
    }

    boardroom_metrics = [
        {"label": "Product Modules", "value": "16", "note": "Unified IRLT governance assurance modules"},
        {"label": "Radiopharma Specificity", "value": "96%", "note": "Built around isotope, release, custody, material, and patient-slot realities"},
        {"label": "Inspection Value", "value": "94%", "note": "Maps questions to evidence, owners, gaps, and passports"},
        {"label": "Buyer Demo Readiness", "value": "93%", "note": "Ready for leadership-style product storytelling"},
        {"label": "Pilot Readiness", "value": "86%", "note": "Clear focused pilot path and ROI logic"},
        {"label": "Governance Maturity", "value": "91%", "note": "Human-controlled AI, evidence lineage, and audit survivability"}
    ]

    executive_pains = [
        {
            "pain": "Commercial readiness is scattered.",
            "impact": "Leadership struggles to know what is truly ready, what is weak, and what evidence supports the readiness claim.",
            "rlttrust_answer": "One command center connects readiness signals, owners, evidence packets, dependencies, and passports."
        },
        {
            "pain": "IRLT readiness is time-sensitive.",
            "impact": "Isotope timing, QC delay, QA release delay, courier ETA, site readiness, and treatment windows can quickly change operational confidence.",
            "rlttrust_answer": "Decay-aware readiness engines show whether treatment, release, shipment, and patient slots remain protectable."
        },
        {
            "pain": "Release approval is not always release defensibility.",
            "impact": "QA may approve release while evidence remains scattered across QC, CAPA, EM, SOP, access, custody, and material records.",
            "rlttrust_answer": "Release Defensibility Engine™ creates QA-facing release evidence gates and passports."
        },
        {
            "pain": "Radioactive material accountability is inspection-critical.",
            "impact": "Receipt, use, transfer, decay, waste, residual, disposal, and reconciliation must be provable.",
            "rlttrust_answer": "Radioactive Material Accountability Ledger™ creates a governed lifecycle and reconciliation view."
        },
        {
            "pain": "Inspection response is reactive.",
            "impact": "Teams manually search documents, trackers, emails, systems, and folders during audit pressure.",
            "rlttrust_answer": "Auditor Question-to-Evidence Engine™ maps questions directly to evidence packets, owners, gaps, and passports."
        },
        {
            "pain": "AI creates regulatory concern.",
            "impact": "Regulated teams fear AI may appear to make quality, release, or clinical decisions.",
            "rlttrust_answer": "Governance Black Box Recorder™ separates AI advisory output from human decision authority."
        }
    ]

    product_stack = [
        {
            "layer": "Executive Trust Layer",
            "modules": "Command Center, Buyer Demo, Pilot ROI, Product Launchpad, Executive Summary",
            "value": "Helps leadership understand readiness, business value, pilot scope, and executive decision logic."
        },
        {
            "layer": "Operational Readiness Layer",
            "modules": "Can We Treat Tomorrow?, Patient Slot Protection, Network Readiness Mesh, Stress Test",
            "value": "Shows whether the operation can actually support treatment readiness, release, logistics, and scale-up."
        },
        {
            "layer": "Radiopharma Evidence Layer",
            "modules": "Isotope-to-Patient Graph, Radioactive Material Ledger, Release Defensibility",
            "value": "Makes RLTTrust™ unmistakably specific to IRLT/radiopharma operations."
        },
        {
            "layer": "Inspection Survivability Layer",
            "modules": "Inspection Tomorrow, Auditor Evidence Engine, Black Box Recorder, Passport Factory",
            "value": "Turns readiness into defensible evidence and audit-ready artifacts."
        },
        {
            "layer": "Human-Governed AI Layer",
            "modules": "AI advisory separation, human decision lineage, black box event capture",
            "value": "Uses AI safely while preserving human authority as the regulated control layer."
        }
    ]

    module_snapshot = [
        {"name": "Command Center", "route": "/irlt-commercial-readiness", "purpose": "Executive readiness cockpit"},
        {"name": "Can We Treat Tomorrow?", "route": "/irlt-commercial-readiness/can-we-treat-tomorrow", "purpose": "Tomorrow treatment readiness"},
        {"name": "Isotope-to-Patient Graph", "route": "/irlt-commercial-readiness/isotope-to-patient", "purpose": "Dose journey traceability"},
        {"name": "Inspection Tomorrow", "route": "/irlt-commercial-readiness/inspection-tomorrow", "purpose": "Inspection failure simulation"},
        {"name": "Material Ledger", "route": "/irlt-commercial-readiness/radioactive-material-ledger", "purpose": "Radioactive material accountability"},
        {"name": "Release Defensibility", "route": "/irlt-commercial-readiness/release-defensibility", "purpose": "QA release evidence defense"},
        {"name": "Patient Slot Protection", "route": "/irlt-commercial-readiness/patient-slot-protection", "purpose": "Treatment window protection"},
        {"name": "Network Mesh", "route": "/irlt-commercial-readiness/network-readiness-mesh", "purpose": "Cross-site scale-up readiness"},
        {"name": "Stress Test", "route": "/irlt-commercial-readiness/commercialization-stress-test", "purpose": "Failure scenario simulation"},
        {"name": "Black Box Recorder", "route": "/irlt-commercial-readiness/governance-black-box", "purpose": "Event, evidence, AI, and human decision timeline"},
        {"name": "Auditor Evidence", "route": "/irlt-commercial-readiness/auditor-question-evidence", "purpose": "Inspection question-to-evidence mapping"},
        {"name": "Passport Factory", "route": "/irlt-commercial-readiness/passport-factory", "purpose": "Executive and inspection artifacts"},
        {"name": "Buyer Demo", "route": "/irlt-commercial-readiness/buyer-demo", "purpose": "Commercial buyer storytelling"},
        {"name": "Pilot ROI", "route": "/irlt-commercial-readiness/pilot-roi", "purpose": "Pilot scope and ROI justification"},
        {"name": "Product Launchpad", "route": "/irlt-commercial-readiness/launchpad", "purpose": "Unified product navigation"},
        {"name": "Executive Summary", "route": "/irlt-commercial-readiness/executive-summary", "purpose": "One-page boardroom view"}
    ]

    strongest_pilot = {
        "title": "Recommended First Pilot",
        "scope": "One site, one product/dose journey, one release pathway, one shipment path, one treatment-site readiness scenario, and one inspection-readiness evidence pack.",
        "modules": [
            "Release Defensibility Engine™",
            "Isotope-to-Patient Evidence Graph™",
            "Radioactive Material Accountability Ledger™",
            "Auditor Question-to-Evidence Engine™",
            "Executive Governance Passport Factory™"
        ],
        "why": "This proves the highest buyer value without replacing existing enterprise systems."
    }

    buyer_targets = [
        "Radiopharma manufacturers",
        "IRLT operations leadership",
        "QA and compliance leadership",
        "QC leadership",
        "Radiation safety teams",
        "Supply chain and cold-chain logistics teams",
        "Treatment coordination teams",
        "Commercialization readiness teams",
        "Operational excellence leadership",
        "Digital / IT governance teams"
    ]

    executive_close = {
        "headline": "RLTTrust™ makes commercial IRLT readiness defensible.",
        "message": "The platform does not simply show dashboards. It creates an operational governance layer that explains whether readiness can be trusted, what evidence supports it, which risks remain, who owns closure, and whether leadership can defend the answer under inspection or commercial pressure.",
        "sales_line": "For a radiopharma company scaling IRLT, RLTTrust™ becomes the governed readiness layer between operational execution systems and executive confidence.",
        "next_step": "Use the Product Launchpad for full demo navigation, then close with Pilot ROI and Passport Factory."
    }

    fast_demo_path = [
        {"step": "1", "page": "Executive Summary", "route": "/irlt-commercial-readiness/executive-summary"},
        {"step": "2", "page": "Buyer Demo", "route": "/irlt-commercial-readiness/buyer-demo"},
        {"step": "3", "page": "Command Center", "route": "/irlt-commercial-readiness"},
        {"step": "4", "page": "Isotope-to-Patient", "route": "/irlt-commercial-readiness/isotope-to-patient"},
        {"step": "5", "page": "Material Ledger", "route": "/irlt-commercial-readiness/radioactive-material-ledger"},
        {"step": "6", "page": "Release Defensibility", "route": "/irlt-commercial-readiness/release-defensibility"},
        {"step": "7", "page": "Auditor Evidence", "route": "/irlt-commercial-readiness/auditor-question-evidence"},
        {"step": "8", "page": "Passport Factory", "route": "/irlt-commercial-readiness/passport-factory"},
        {"step": "9", "page": "Pilot ROI", "route": "/irlt-commercial-readiness/pilot-roi"}
    ]

    return {
        "headline": headline,
        "boardroom_metrics": boardroom_metrics,
        "executive_pains": executive_pains,
        "product_stack": product_stack,
        "module_snapshot": module_snapshot,
        "strongest_pilot": strongest_pilot,
        "buyer_targets": buyer_targets,
        "executive_close": executive_close,
        "fast_demo_path": fast_demo_path,
        "governance_note": "Executive Summary One-Page View™ is a boardroom storytelling layer. AI remains advisory only. Human governance remains authoritative."
    }


@app.route("/irlt-commercial-readiness/executive-summary")
@app.route("/irlt-commercial-readiness/one-page")
@app.route("/rlttrust/executive-summary")
def rlttrust_executive_summary_one_page_view():
    result = _rlttrust_executive_summary_one_page_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Executive Summary One-Page View™ | RLTTrust™</title>
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
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.30), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.18), transparent 34%),
                    radial-gradient(circle at 50% 32%, rgba(255,255,255,0.065), transparent 30%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1960px;
                margin: 0 auto;
                padding: 30px 42px;
            }

            .hero {
                position: relative;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.36);
                border-radius: 40px;
                padding: 38px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.23), rgba(20,24,33,0.94) 39%, rgba(7,8,12,0.97)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.026) 0 1px, transparent 1px 76px);
                box-shadow: 0 38px 130px rgba(0,0,0,0.58);
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -180px;
                top: -220px;
                width: 680px;
                height: 680px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.28);
                box-shadow: inset 0 0 90px rgba(255,122,24,0.12), 0 0 110px rgba(255,122,24,0.14);
            }

            .hero-grid {
                position: relative;
                z-index: 2;
                display: grid;
                grid-template-columns: minmax(0, 1.55fr) minmax(420px, .82fr);
                gap: 34px;
                align-items: stretch;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .18em;
                font-weight: 950;
                text-shadow: 0 0 18px rgba(255,122,24,0.30);
            }

            h1 {
                margin: 10px 0;
                font-size: clamp(54px, 6vw, 110px);
                line-height: .86;
                letter-spacing: -.08em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 34px);
                letter-spacing: -.03em;
                margin: 0 0 14px;
            }

            h3 {
                margin: 0 0 8px;
                letter-spacing: -.02em;
            }

            p {
                color: var(--muted);
                line-height: 1.55;
            }

            .hero-line {
                font-size: clamp(18px, 1.4vw, 25px);
                color: #fff2e6;
                max-width: 1100px;
            }

            .score-card {
                border-radius: 32px;
                padding: 28px;
                background: linear-gradient(180deg, rgba(255,122,24,0.14), rgba(15,18,26,0.94));
                border: 1px solid rgba(255,122,24,0.38);
                box-shadow: 0 24px 86px rgba(0,0,0,0.44);
            }

            .big-answer {
                font-size: clamp(34px, 3.6vw, 62px);
                font-weight: 950;
                line-height: .95;
                letter-spacing: -.06em;
                color: var(--orange2);
                text-shadow: 0 0 34px rgba(255,122,24,0.34);
                margin: 14px 0;
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
                border-color: rgba(255,122,24,0.75);
                background: rgba(255,122,24,0.14);
            }

            .section {
                margin-top: 28px;
            }

            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 16px;
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

            .grid-6 {
                display: grid;
                grid-template-columns: repeat(6, minmax(0, 1fr));
                gap: 14px;
            }

            .panel, .metric, .pain-card, .module-card, .path-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 26px;
                padding: 20px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 22px 64px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .metric strong {
                display: block;
                font-size: 34px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 6px;
            }

            .metric span {
                color: var(--orange2);
                font-size: 12px;
                font-weight: 900;
                text-transform: uppercase;
                letter-spacing: .08em;
            }

            .metric p {
                margin: 8px 0 0;
                font-size: 13px;
            }

            .pain-card {
                min-height: 260px;
            }

            .pain-card h3 {
                color: #fff2e6;
                font-size: 20px;
            }

            .module-grid {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 14px;
            }

            .module-card {
                min-height: 150px;
                position: relative;
                overflow: hidden;
            }

            .module-card:before {
                content: "";
                position: absolute;
                inset: 0;
                background: radial-gradient(circle at top right, rgba(255,122,24,0.16), transparent 34%);
                pointer-events: none;
            }

            .module-card a {
                color: #ffd7ad;
                text-decoration: none;
                font-weight: 950;
            }

            .module-card small {
                display: block;
                color: var(--muted);
                margin-top: 6px;
                line-height: 1.45;
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

            .path-flow {
                display: grid;
                grid-template-columns: repeat(9, minmax(220px, 1fr));
                gap: 14px;
                overflow-x: auto;
                padding-bottom: 8px;
            }

            .path-card {
                position: relative;
                min-height: 155px;
            }

            .path-card:after {
                content: "→";
                position: absolute;
                right: -20px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--orange2);
                font-size: 30px;
                font-weight: 950;
                text-shadow: 0 0 20px rgba(255,122,24,0.40);
                z-index: 4;
            }

            .path-card:last-child:after {
                display: none;
            }

            .path-card a {
                color: #ffd7ad;
                text-decoration: none;
                font-weight: 950;
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
                padding: 14px;
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
                margin-top: 14px;
            }

            @media print {
                .nav { display: none; }
                body { background: white; color: #111; }
                .hero, .panel, .metric, .pain-card, .module-card, .path-card {
                    box-shadow: none;
                    background: white;
                    color: #111;
                    border-color: #ccc;
                }
                p, td, small { color: #333 !important; }
                h1, h2, h3, th { color: #111 !important; }
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-3, .grid-4, .grid-6, .module-grid {
                    grid-template-columns: 1fr;
                }
                .wrap {
                    padding: 22px;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">COBIT-Chain™ / AssuranceLayer™ Platform A</div>
                        <h1>{{ result.headline.title }}</h1>
                        <p class="hero-line">{{ result.headline.one_sentence }}</p>
                        <p><strong style="color:#ffd7ad;">Core Executive Question:</strong> {{ result.headline.core_question }}</p>
                        <p>{{ result.headline.positioning }}</p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>
                            <a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>
                            <a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>
                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                            <a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence</a>
                            <a href="/irlt-commercial-readiness/executive-summary/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Boardroom Answer</div>
                        <div class="big-answer">Defensible IRLT Readiness</div>
                        <p>{{ result.executive_close.message }}</p>
                        <div class="note">{{ result.executive_close.sales_line }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="grid-6">
                    {% for metric in result.boardroom_metrics %}
                    <div class="metric">
                        <strong>{{ metric.value }}</strong>
                        <span>{{ metric.label }}</span>
                        <p>{{ metric.note }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <h2>Major Pain Points Solved</h2>
                <div class="grid-3">
                    {% for pain in result.executive_pains %}
                    <div class="pain-card">
                        <h3>{{ pain.pain }}</h3>
                        <p><strong style="color:#fff2e6;">Impact:</strong> {{ pain.impact }}</p>
                        <p><strong style="color:#ffd7ad;">RLTTrust™ Answer:</strong> {{ pain.rlttrust_answer }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Product Stack</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Layer</th>
                                <th>Modules</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for layer in result.product_stack %}
                            <tr>
                                <td><strong>{{ layer.layer }}</strong></td>
                                <td>{{ layer.modules }}</td>
                                <td>{{ layer.value }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Strongest First Pilot</h2>
                    <p><strong style="color:#fff2e6;">Scope:</strong> {{ result.strongest_pilot.scope }}</p>
                    {% for module in result.strongest_pilot.modules %}
                    <span class="pill">{{ module }}</span>
                    {% endfor %}
                    <div class="note">{{ result.strongest_pilot.why }}</div>

                    <h3 style="margin-top:22px;">Target Buyers</h3>
                    {% for buyer in result.buyer_targets %}
                    <span class="pill">{{ buyer }}</span>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">Fast Demo Path</div>
                    <h2>9-Step Executive Demo Sequence</h2>
                    <div class="path-flow">
                        {% for step in result.fast_demo_path %}
                        <div class="path-card">
                            <div class="eyebrow">Step {{ step.step }}</div>
                            <h3><a href="{{ step.route }}">{{ step.page }}</a></h3>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Module Snapshot</h2>
                <div class="module-grid">
                    {% for module in result.module_snapshot %}
                    <div class="module-card">
                        <h3><a href="{{ module.route }}">{{ module.name }}</a></h3>
                        <small>{{ module.purpose }}</small>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Executive Close</h2>
                    <p><strong style="color:#fff2e6;">{{ result.executive_close.headline }}</strong></p>
                    <p>{{ result.executive_close.message }}</p>
                    <p><strong style="color:#ffd7ad;">Next Step:</strong> {{ result.executive_close.next_step }}</p>
                </div>

                <div class="panel">
                    <h2>Governance Guardrail</h2>
                    <p>{{ result.governance_note }}</p>
                    <div class="note">
                        AI is advisory only. QA, compliance, radiation safety, clinical authority, operations leadership, and system owners remain the authoritative decision-makers.
                    </div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/executive-summary/api")
@app.route("/irlt-commercial-readiness/one-page/api")
@app.route("/rlttrust/executive-summary/api")
def rlttrust_executive_summary_one_page_api():
    return jsonify(_rlttrust_executive_summary_one_page_data())

# ============================================================
# End Executive Summary One-Page View™
# ============================================================

'''

    # Add Executive Summary link to navigation where Product Launchpad link exists.
    nav_marker = "RLTTRUST_NAV_EXECUTIVE_SUMMARY_ONE_PAGE_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_EXECUTIVE_SUMMARY_ONE_PAGE_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>',
            1
        )
        print("Added Executive Summary link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Executive Summary One-Page View successfully.")

