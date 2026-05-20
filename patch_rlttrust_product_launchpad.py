from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_PRODUCT_HOME_LAUNCHPAD_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Product Home / Launchpad already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_PRODUCT_HOME_LAUNCHPAD_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: RLTTrust™ Product Home / Launchpad
# Purpose: Unified product navigation and executive launchpad for all RLTTrust™ modules.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify

def _rlttrust_product_launchpad_data():
    modules = [
        {
            "number": "01",
            "name": "IRLT Commercial Readiness Command Center™",
            "route": "/irlt-commercial-readiness",
            "category": "Executive Readiness",
            "score": 86,
            "status": "Core Cockpit",
            "buyer_value": "One executive cockpit for commercial readiness, operational trust, readiness weaknesses, and leadership defensibility.",
            "executive_question": "Can leadership operationally defend commercialization readiness with governed evidence?"
        },
        {
            "number": "02",
            "name": "Can We Treat Tomorrow? Engine™",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "category": "Treatment Readiness",
            "score": 82,
            "status": "Operational Decision Support",
            "buyer_value": "Checks whether isotope timing, QC, QA release, custody, site readiness, and evidence support tomorrow treatment readiness.",
            "executive_question": "Can we manufacture, release, ship, receive, and support treatment tomorrow?"
        },
        {
            "number": "03",
            "name": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "category": "Dose Journey Traceability",
            "score": 83,
            "status": "Evidence Graph",
            "buyer_value": "Maps the governed dose journey from isotope source through manufacturing, QC, QA release, shipment, receipt, and treatment-slot readiness.",
            "executive_question": "Can we prove the full dose journey from isotope source to patient-slot readiness?"
        },
        {
            "number": "04",
            "name": "Inspection Tomorrow Simulator™",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "category": "Inspection Survivability",
            "score": 80,
            "status": "Inspection Simulation",
            "buyer_value": "Shows what would fail, what would survive, and which evidence packets are needed if an inspector walked in tomorrow.",
            "executive_question": "If FDA, NRC, QA, or corporate audit walked in tomorrow, what would fail?"
        },
        {
            "number": "05",
            "name": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "category": "Radiopharma-Specific Governance",
            "score": 82,
            "status": "Material Lifecycle Ledger",
            "buyer_value": "Governs radioactive material receipt, storage, use, transfer, decay, waste, residual, disposal, and reconciliation.",
            "executive_question": "Can we prove radioactive material accountability across the full lifecycle?"
        },
        {
            "number": "06",
            "name": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "category": "QA Release Assurance",
            "score": 81,
            "status": "QA Decision Support",
            "buyer_value": "Connects QC, QA release, CAPA, EM, SOP, access, custody, material accountability, and evidence integrity into one release defensibility layer.",
            "executive_question": "Can QA defend this release decision with complete governed evidence?"
        },
        {
            "number": "07",
            "name": "Patient Slot Protection Engine™",
            "route": "/irlt-commercial-readiness/patient-slot-protection",
            "category": "Patient-Impact Governance",
            "score": 79,
            "status": "Slot Protection",
            "buyer_value": "Protects treatment-slot readiness using isotope timing, courier ETA, QA release, site readiness, appointment readiness, and evidence.",
            "executive_question": "Can the dose still protect the scheduled treatment window?"
        },
        {
            "number": "08",
            "name": "Cross-Site RLT Network Readiness Mesh™",
            "route": "/irlt-commercial-readiness/network-readiness-mesh",
            "category": "Enterprise Scale-Up",
            "score": 78,
            "status": "Network Mesh",
            "buyer_value": "Assesses commercial network readiness across sites, QC/QA lanes, hot cells, isotope supply, couriers, treatment hubs, fallback capacity, and evidence.",
            "executive_question": "Can the network support commercial demand if one node becomes constrained?"
        },
        {
            "number": "09",
            "name": "Commercialization Stress Test Simulator™",
            "route": "/irlt-commercial-readiness/commercialization-stress-test",
            "category": "What-If Failure Lab",
            "score": 76,
            "status": "Stress Test",
            "buyer_value": "Simulates QC delay, QA delay, hot-cell outage, isotope delay, courier failure, evidence loss, CAPA pressure, and treatment hub disruption.",
            "executive_question": "Can the commercial readiness model survive disruption?"
        },
        {
            "number": "10",
            "name": "Governance Black Box Recorder™",
            "route": "/irlt-commercial-readiness/governance-black-box",
            "category": "Inspection-Survivable Memory",
            "score": 86,
            "status": "Black Box Timeline",
            "buyer_value": "Records readiness signals, evidence changes, release decisions, custody movements, AI advisories, and human approvals into a tamper-evident timeline.",
            "executive_question": "Can we prove what happened, when, who owned it, what AI recommended, and what humans decided?"
        },
        {
            "number": "11",
            "name": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "category": "Inspection Response",
            "score": 85,
            "status": "Evidence Mapping",
            "buyer_value": "Maps auditor questions to evidence packets, owners, source engines, readiness gaps, and Governance Passport outputs.",
            "executive_question": "When an auditor asks a question, can we immediately map it to evidence?"
        },
        {
            "number": "12",
            "name": "Executive IRLT Governance Passport Factory™",
            "route": "/irlt-commercial-readiness/passport-factory",
            "category": "Executive Artifacts",
            "score": 88,
            "status": "Passport Factory",
            "buyer_value": "Generates commercial readiness, release, dose journey, material, inspection, patient slot, network, stress, black box, and auditor evidence passports.",
            "executive_question": "Can we convert readiness intelligence into executive and inspection artifacts?"
        },
        {
            "number": "13",
            "name": "Executive Buyer Demo Mode™",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "category": "Commercial Storytelling",
            "score": 92,
            "status": "Buyer Demo",
            "buyer_value": "Packages the product into a buyer-facing demo story for radiopharma leadership, QA, radiation safety, supply chain, and digital leaders.",
            "executive_question": "Why does this matter, what pain does it solve, and why would radiopharma leadership care?"
        },
        {
            "number": "14",
            "name": "Pilot Readiness & ROI Justification Engine™",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "category": "Pilot Proposal",
            "score": 84,
            "status": "ROI Engine",
            "buyer_value": "Creates pilot scope, implementation phases, evidence inputs, success metrics, ROI narrative, buyer value, and expansion path.",
            "executive_question": "What pilot should we approve, what value will it prove, and how do we justify ROI?"
        },
        {
            "number": "15",
            "name": "RLTTrust™ Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "category": "Product Navigation",
            "score": 95,
            "status": "Unified Product Home",
            "buyer_value": "Unifies all RLTTrust™ modules into one polished commercial platform entry point.",
            "executive_question": "Can this be presented as one complete enterprise product?"
        }
    ]

    journeys = [
        {
            "journey": "Executive Leadership Demo",
            "steps": [
                "Command Center",
                "Network Readiness Mesh",
                "Commercialization Stress Test",
                "Executive Passport Factory",
                "Pilot ROI"
            ],
            "message": "Shows whether commercial scale-up can be trusted, defended, and justified."
        },
        {
            "journey": "QA / Compliance Demo",
            "steps": [
                "Release Defensibility",
                "Inspection Tomorrow",
                "Auditor Question-to-Evidence",
                "Governance Black Box",
                "Passport Factory"
            ],
            "message": "Shows how QA can defend release, inspection response, evidence integrity, and human approval lineage."
        },
        {
            "journey": "Radiopharma Operations Demo",
            "steps": [
                "Can We Treat Tomorrow?",
                "Isotope-to-Patient Evidence Graph",
                "Radioactive Material Ledger",
                "Patient Slot Protection",
                "Stress Test"
            ],
            "message": "Shows how operational timing, material accountability, shipment, and treatment readiness are governed."
        },
        {
            "journey": "Buyer Pilot Demo",
            "steps": [
                "Buyer Demo",
                "Pilot ROI",
                "Release Defensibility",
                "Dose Journey",
                "Material Ledger",
                "Passport Factory"
            ],
            "message": "Shows the fastest path to a focused buyer pilot."
        }
    ]

    product_metrics = {
        "modules_built": len(modules),
        "average_readiness": round(sum(m["score"] for m in modules) / len(modules)),
        "radiopharma_specificity": 96,
        "inspection_readiness_value": 94,
        "buyer_demo_readiness": 92,
        "pilot_readiness": 86,
        "platform_unification": 95
    }

    product_layers = [
        {
            "layer": "Executive Trust Layer",
            "description": "Command Center, Buyer Demo, Pilot ROI, Passport Factory.",
            "value": "Helps leadership understand readiness, risk, value, and pilot justification."
        },
        {
            "layer": "Operational Readiness Layer",
            "description": "Can We Treat Tomorrow, Patient Slot Protection, Network Mesh, Stress Test.",
            "value": "Shows whether the operation can actually support release, delivery, treatment, and scale-up."
        },
        {
            "layer": "Radiopharma Evidence Layer",
            "description": "Isotope-to-Patient Graph, Material Ledger, Release Defensibility.",
            "value": "Makes the platform specific to IRLT and radiopharma operations."
        },
        {
            "layer": "Inspection Survivability Layer",
            "description": "Inspection Tomorrow, Auditor Evidence Engine, Governance Black Box, AuditVault-style evidence logic.",
            "value": "Turns readiness into defensible evidence and inspection response."
        },
        {
            "layer": "Human-Governed AI Layer",
            "description": "AI advisory output is recorded separately from human approval and never becomes the source of truth.",
            "value": "Supports explainable governance intelligence without replacing regulated human authority."
        }
    ]

    strongest_demo_path = [
        {
            "step": "1",
            "page": "Buyer Demo",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "purpose": "Start with the commercial pain and buyer story."
        },
        {
            "step": "2",
            "page": "Command Center",
            "route": "/irlt-commercial-readiness",
            "purpose": "Show the executive readiness cockpit."
        },
        {
            "step": "3",
            "page": "Can We Treat Tomorrow?",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "purpose": "Show decay-aware operational readiness."
        },
        {
            "step": "4",
            "page": "Isotope-to-Patient Graph",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "purpose": "Show end-to-end dose journey traceability."
        },
        {
            "step": "5",
            "page": "Material Ledger",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "purpose": "Show radiopharma-specific material accountability."
        },
        {
            "step": "6",
            "page": "Release Defensibility",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "purpose": "Show QA release defensibility."
        },
        {
            "step": "7",
            "page": "Inspection Tomorrow",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "purpose": "Show inspection survivability and findings."
        },
        {
            "step": "8",
            "page": "Auditor Evidence Engine",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "purpose": "Show how auditor questions become governed evidence maps."
        },
        {
            "step": "9",
            "page": "Passport Factory",
            "route": "/irlt-commercial-readiness/passport-factory",
            "purpose": "Show executive artifacts."
        },
        {
            "step": "10",
            "page": "Pilot ROI",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "purpose": "Close with pilot scope and business justification."
        }
    ]

    buyer_close = {
        "headline": "RLTTrust™ is now a coherent commercial product demo, not a collection of disconnected pages.",
        "message": "It shows one governance assurance layer for commercial IRLT scale-up: readiness, release, isotope-to-patient traceability, radioactive material accountability, patient-slot protection, inspection survivability, stress testing, black box evidence, auditor evidence mapping, executive passports, and pilot ROI.",
        "pilot_start": "The strongest pilot remains: Release Defensibility + Isotope-to-Patient Evidence Graph + Radioactive Material Accountability Ledger + Auditor Evidence Engine + Passport Factory.",
        "positioning": "RLTTrust™ does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics systems, or treatment scheduling. It overlays them with governed evidence, operational trust scoring, and inspection-survivable readiness."
    }

    return {
        "modules": modules,
        "journeys": journeys,
        "product_metrics": product_metrics,
        "product_layers": product_layers,
        "strongest_demo_path": strongest_demo_path,
        "buyer_close": buyer_close,
        "governance_note": "RLTTrust™ Product Launchpad is a product navigation and executive demonstration layer. AI remains advisory only. Human governance remains authoritative."
    }


@app.route("/irlt-commercial-readiness/launchpad")
@app.route("/irlt-commercial-readiness/product-home")
@app.route("/rlttrust/product-launchpad")
def rlttrust_product_home_launchpad():
    result = _rlttrust_product_launchpad_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>RLTTrust™ Product Launchpad | COBIT-Chain™</title>
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
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.28), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.18), transparent 34%),
                    radial-gradient(circle at 50% 32%, rgba(255,255,255,0.065), transparent 30%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1960px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero {
                position: relative;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.36);
                border-radius: 40px;
                padding: 40px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.22), rgba(20,24,33,0.94) 40%, rgba(7,8,12,0.97)),
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
                grid-template-columns: minmax(0, 1.65fr) minmax(380px, 0.72fr);
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
                margin: 12px 0;
                font-size: clamp(48px, 5.4vw, 96px);
                line-height: .9;
                letter-spacing: -.07em;
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
                border-radius: 32px;
                padding: 28px;
                background: linear-gradient(180deg, rgba(255,122,24,0.14), rgba(15,18,26,0.94));
                border: 1px solid rgba(255,122,24,0.38);
                box-shadow: 0 24px 86px rgba(0,0,0,0.44);
            }

            .score {
                font-size: clamp(78px, 7vw, 136px);
                line-height: .85;
                font-weight: 950;
                letter-spacing: -.07em;
                color: var(--orange2);
                text-shadow: 0 0 38px rgba(255,122,24,0.38);
                margin: 18px 0;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 24px;
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
                margin-top: 34px;
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

            .panel, .metric, .module-card, .journey-card, .path-card {
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
                font-size: 34px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 8px;
            }

            .metric span {
                color: var(--muted);
                font-size: 13px;
            }

            .module-grid {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 18px;
            }

            .module-card {
                position: relative;
                min-height: 300px;
                overflow: hidden;
            }

            .module-card:before {
                content: "";
                position: absolute;
                inset: 0;
                background: radial-gradient(circle at top right, rgba(255,122,24,0.16), transparent 34%);
                pointer-events: none;
            }

            .module-number {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 44px;
                height: 44px;
                border-radius: 16px;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                font-weight: 950;
                box-shadow: 0 14px 35px rgba(255,122,24,0.25);
                margin-bottom: 16px;
            }

            .module-title {
                color: #fff2e6;
                font-size: 22px;
                line-height: 1.12;
                letter-spacing: -.03em;
                margin-bottom: 10px;
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

            .open-link {
                display: inline-block;
                margin-top: 12px;
                text-decoration: none;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                border-radius: 999px;
                padding: 10px 14px;
                font-weight: 950;
                box-shadow: 0 16px 45px rgba(255,122,24,0.22);
            }

            .path-flow {
                display: grid;
                grid-template-columns: repeat(10, minmax(260px, 1fr));
                gap: 16px;
                overflow-x: auto;
                padding-bottom: 10px;
            }

            .path-card {
                position: relative;
                min-height: 210px;
            }

            .path-card:after {
                content: "→";
                position: absolute;
                right: -22px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--orange2);
                font-size: 34px;
                font-weight: 950;
                text-shadow: 0 0 20px rgba(255,122,24,0.40);
                z-index: 4;
            }

            .path-card:last-child:after {
                display: none;
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

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-3, .grid-4, .module-grid {
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
                        <div class="eyebrow">COBIT-Chain™ / AssuranceLayer™ Platform A</div>
                        <h1>RLTTrust™ Product Launchpad</h1>
                        <p>
                            One unified commercial product home for the IRLT Commercial Readiness Governance Command Center™.
                            This launchpad connects every module into one buyer-ready enterprise platform experience.
                        </p>
                        <p>
                            RLTTrust™ is a governance assurance and operational trust overlay for regulated radiopharma scale-up.
                            It does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics systems, or treatment scheduling.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>
                            <a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>
                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                            <a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence</a>
                            <a href="/irlt-commercial-readiness/launchpad/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Unified Product Readiness</div>
                        <div class="score">{{ result.product_metrics.platform_unification }}%</div>
                        <p>{{ result.buyer_close.headline }}</p>
                        <p>{{ result.buyer_close.message }}</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Product Metrics</h2>
                <div class="grid-4">
                    <div class="metric"><strong>{{ result.product_metrics.modules_built }}</strong><span>Modules Unified</span></div>
                    <div class="metric"><strong>{{ result.product_metrics.average_readiness }}%</strong><span>Average Module Readiness</span><div class="bar"><span style="width: {{ result.product_metrics.average_readiness }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.product_metrics.radiopharma_specificity }}%</strong><span>Radiopharma Specificity</span><div class="bar"><span style="width: {{ result.product_metrics.radiopharma_specificity }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.product_metrics.inspection_readiness_value }}%</strong><span>Inspection Readiness Value</span><div class="bar"><span style="width: {{ result.product_metrics.inspection_readiness_value }}%;"></span></div></div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">Recommended Buyer Demo Path</div>
                    <h2>Strongest 10-Step Demo Sequence</h2>
                    <div class="path-flow">
                        {% for step in result.strongest_demo_path %}
                        <div class="path-card">
                            <div class="module-number">{{ step.step }}</div>
                            <h3>{{ step.page }}</h3>
                            <p>{{ step.purpose }}</p>
                            <a class="open-link" href="{{ step.route }}">Open</a>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>All RLTTrust™ Modules</h2>
                <div class="module-grid">
                    {% for module in result.modules %}
                    <div class="module-card">
                        <div class="module-number">{{ module.number }}</div>
                        <div class="module-title">{{ module.name }}</div>
                        <span class="pill">{{ module.category }}</span>
                        <span class="pill">{{ module.status }}</span>
                        <div class="bar"><span style="width: {{ module.score }}%;"></span></div>
                        <p><strong style="color:#fff2e6;">Buyer Value:</strong> {{ module.buyer_value }}</p>
                        <p><strong style="color:#ffd7ad;">Executive Question:</strong> {{ module.executive_question }}</p>
                        <a class="open-link" href="{{ module.route }}">Open Module</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Product Layers</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Layer</th>
                                <th>Description</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for layer in result.product_layers %}
                            <tr>
                                <td><strong>{{ layer.layer }}</strong></td>
                                <td>{{ layer.description }}</td>
                                <td>{{ layer.value }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Buyer Journeys</h2>
                    {% for journey in result.journeys %}
                    <div class="journey-card" style="margin-bottom:14px;">
                        <h3>{{ journey.journey }}</h3>
                        <p>{{ journey.message }}</p>
                        {% for step in journey.steps %}
                        <span class="pill">{{ step }}</span>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Buyer Close</h2>
                    <p><strong style="color:#fff2e6;">Headline:</strong> {{ result.buyer_close.headline }}</p>
                    <p>{{ result.buyer_close.message }}</p>
                    <div class="note"><strong>Strongest Pilot:</strong> {{ result.buyer_close.pilot_start }}</div>
                </div>

                <div class="panel">
                    <h2>Positioning Guardrail</h2>
                    <p>{{ result.buyer_close.positioning }}</p>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/launchpad/api")
@app.route("/irlt-commercial-readiness/product-home/api")
@app.route("/rlttrust/product-launchpad/api")
def rlttrust_product_home_launchpad_api():
    return jsonify(_rlttrust_product_launchpad_data())

# ============================================================
# End RLTTrust™ Product Home / Launchpad
# ============================================================

'''

    # Add Launchpad link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_PRODUCT_LAUNCHPAD_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            '<!-- RLTTRUST_NAV_PRODUCT_LAUNCHPAD_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>\n                            ' + nav_anchor,
            1
        )
        print("Added Product Launchpad link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Product Home / Launchpad successfully.")

