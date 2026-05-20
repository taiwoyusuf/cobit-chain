from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_FINAL_INVENTORY_HANDOVER_SUMMARY_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Final Inventory + Handover Summary already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_FINAL_INVENTORY_HANDOVER_SUMMARY_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Final Inventory + Handover Summary
# Purpose: Final product inventory, demo sequence, buyer targets, pilot story,
#          roadmap, Azure/GitHub/Power BI next steps, and production hardening list.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify
from datetime import datetime

def _rlttrust_final_handover_summary_data():
    product_summary = {
        "product": "RLTTrust™ / IRLT Commercial Readiness Governance Command Center™",
        "platform": "COBIT-Chain™ / AssuranceLayer™ Platform A",
        "category": "Enterprise Governance Assurance Platform for regulated radiopharma and IRLT operations",
        "core_positioning": "RLTTrust™ is not a replacement for Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics systems, treatment scheduling, or manufacturing systems. It is a governance assurance and operational trust overlay.",
        "executive_question": "Can leadership operationally defend IRLT commercialization readiness with governed evidence?",
        "product_status": "Concept-to-commercial-demo build completed for Platform A RLTTrust™ thread.",
        "handover_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    }

    modules_built = [
        {
            "number": "01",
            "module": "IRLT Commercial Readiness Governance Command Center™",
            "route": "/irlt-commercial-readiness",
            "purpose": "Executive cockpit for commercial readiness, operational trust scoring, readiness gaps, and leadership defensibility.",
            "buyer_value": "Gives leadership one readiness control room."
        },
        {
            "number": "02",
            "module": "Can We Treat Tomorrow? Engine™",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "purpose": "Assesses whether treatment readiness is operationally defensible for tomorrow.",
            "buyer_value": "Shows time-sensitive isotope, release, custody, site, and evidence readiness."
        },
        {
            "number": "03",
            "module": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "purpose": "Maps dose journey evidence from isotope source to manufacturing, QC, QA release, shipment, receipt, and treatment-slot readiness.",
            "buyer_value": "Shows radiopharma-specific end-to-end traceability."
        },
        {
            "number": "04",
            "module": "Inspection Tomorrow Simulator™",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "purpose": "Simulates what would fail if FDA, NRC, QA, or corporate audit walked in tomorrow.",
            "buyer_value": "Creates urgency and inspection-readiness visibility."
        },
        {
            "number": "05",
            "module": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "purpose": "Tracks radioactive material receipt, use, transfer, decay, waste, residual activity, disposal, and reconciliation.",
            "buyer_value": "Strongest radiopharma-specific differentiator."
        },
        {
            "number": "06",
            "module": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "purpose": "Connects QC, QA release, CAPA, EM, SOP/training, access, custody, material accountability, and evidence integrity into release gates.",
            "buyer_value": "Helps QA defend release decisions with governed evidence."
        },
        {
            "number": "07",
            "module": "Patient Slot Protection Engine™",
            "route": "/irlt-commercial-readiness/patient-slot-protection",
            "purpose": "Protects treatment-window readiness using isotope timing, courier ETA, QA release, site readiness, appointment readiness, and evidence.",
            "buyer_value": "Links operational governance to patient-impact readiness without storing PHI."
        },
        {
            "number": "08",
            "module": "Cross-Site RLT Network Readiness Mesh™",
            "route": "/irlt-commercial-readiness/network-readiness-mesh",
            "purpose": "Assesses multi-site commercial readiness across manufacturing sites, QC/QA lanes, hot cells, isotope supply, couriers, treatment hubs, fallback capacity, and evidence.",
            "buyer_value": "Supports enterprise commercial scale-up."
        },
        {
            "number": "09",
            "module": "Commercialization Stress Test Simulator™",
            "route": "/irlt-commercial-readiness/commercialization-stress-test",
            "purpose": "Stress-tests QC delay, QA delay, hot-cell outage, isotope delay, courier failure, evidence loss, treatment hub constraint, and access failure.",
            "buyer_value": "Shows whether readiness survives realistic commercial disruption."
        },
        {
            "number": "10",
            "module": "Governance Black Box Recorder™",
            "route": "/irlt-commercial-readiness/governance-black-box",
            "purpose": "Records readiness signals, evidence changes, release decisions, custody events, AI advisories, and human approvals into a hash-style timeline.",
            "buyer_value": "Proves human-controlled AI and inspection-survivable decision lineage."
        },
        {
            "number": "11",
            "module": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "purpose": "Maps auditor, QA, compliance, and leadership questions to evidence packets, owners, source engines, gaps, and passports.",
            "buyer_value": "Turns inspection response into governed evidence retrieval."
        },
        {
            "number": "12",
            "module": "Executive IRLT Governance Passport Factory™",
            "route": "/irlt-commercial-readiness/passport-factory",
            "purpose": "Generates executive and inspection-ready passports for readiness, release, dose journey, inspection, material, patient slot, network, stress, black box, and auditor evidence.",
            "buyer_value": "Turns analytics into leadership artifacts."
        },
        {
            "number": "13",
            "module": "Executive Buyer Demo Mode™",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "purpose": "Packages the product into a buyer-facing commercial story with pains, personas, modules, objections, and pilot positioning.",
            "buyer_value": "Makes the product sellable."
        },
        {
            "number": "14",
            "module": "Pilot Readiness & ROI Justification Engine™",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "purpose": "Creates pilot scope, phases, evidence inputs, success metrics, ROI assumptions, buyer value, and expansion path.",
            "buyer_value": "Converts the demo into a practical pilot proposal."
        },
        {
            "number": "15",
            "module": "RLTTrust™ Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "purpose": "Unified product navigation home for all RLTTrust™ modules.",
            "buyer_value": "Makes the build feel like one complete product."
        },
        {
            "number": "16",
            "module": "Executive Summary One-Page View™",
            "route": "/irlt-commercial-readiness/executive-summary",
            "purpose": "One-screen boardroom summary for pitching, screenshots, and leadership explanation.",
            "buyer_value": "Explains the whole product quickly."
        },
        {
            "number": "17",
            "module": "Buyer Demo Flow™ / Navigation Hardening",
            "route": "/irlt-commercial-readiness/demo-flow",
            "purpose": "Defines presentation-safe demo paths and route order for executives, QA, operations, enterprise buyers, and pilot approval.",
            "buyer_value": "Prevents random demo navigation."
        },
        {
            "number": "18",
            "module": "Final Commercial Packaging Layer™",
            "route": "/irlt-commercial-readiness/commercial-package",
            "purpose": "Brochure-style commercial packaging page with problem, solution, differentiators, buyers, pilot offer, and expansion story.",
            "buyer_value": "Makes RLTTrust™ look commercially packaged."
        },
        {
            "number": "19",
            "module": "Final QA Smoke Test & Route Verification",
            "route": "/irlt-commercial-readiness/final-qa",
            "purpose": "Checks expected routes, APIs, inventory, demo risks, and final demo readiness.",
            "buyer_value": "Protects the demo from broken-route embarrassment."
        },
        {
            "number": "20",
            "module": "Final Inventory + Handover Summary",
            "route": "/irlt-commercial-readiness/handover-summary",
            "purpose": "Final handover inventory, demo sequence, buyer targets, pilot story, roadmap, and next-step plan.",
            "buyer_value": "Gives the project a clean closure and continuation path."
        }
    ]

    best_demo_order = [
        {"step": "1", "page": "Executive Summary", "route": "/irlt-commercial-readiness/executive-summary", "talk_track": "Start with the one-page boardroom explanation."},
        {"step": "2", "page": "Commercial Package", "route": "/irlt-commercial-readiness/commercial-package", "talk_track": "Show market problem, solution, differentiators, target buyers, and pilot offer."},
        {"step": "3", "page": "Product Launchpad", "route": "/irlt-commercial-readiness/launchpad", "talk_track": "Show that this is one unified product, not scattered pages."},
        {"step": "4", "page": "Buyer Demo", "route": "/irlt-commercial-readiness/buyer-demo", "talk_track": "Tell the buyer story and pain points."},
        {"step": "5", "page": "Command Center", "route": "/irlt-commercial-readiness", "talk_track": "Show executive commercial readiness cockpit."},
        {"step": "6", "page": "Isotope-to-Patient Graph", "route": "/irlt-commercial-readiness/isotope-to-patient", "talk_track": "Show dose journey traceability from isotope source to treatment readiness."},
        {"step": "7", "page": "Radioactive Material Ledger", "route": "/irlt-commercial-readiness/radioactive-material-ledger", "talk_track": "Show radiopharma-specific accountability."},
        {"step": "8", "page": "Release Defensibility", "route": "/irlt-commercial-readiness/release-defensibility", "talk_track": "Show QA release defensibility."},
        {"step": "9", "page": "Auditor Evidence Engine", "route": "/irlt-commercial-readiness/auditor-question-evidence", "talk_track": "Show how inspection questions map to evidence."},
        {"step": "10", "page": "Passport Factory", "route": "/irlt-commercial-readiness/passport-factory", "talk_track": "Show executive and inspection artifacts."},
        {"step": "11", "page": "Pilot ROI", "route": "/irlt-commercial-readiness/pilot-roi", "talk_track": "Close with the pilot scope and ROI justification."}
    ]

    strongest_pilot = {
        "name": "Focused RLTTrust™ Pilot",
        "scope": "One site, one product/dose journey, one release pathway, one shipment path, one treatment-site readiness scenario, and one inspection-readiness evidence pack.",
        "modules": [
            "Release Defensibility Engine™",
            "Isotope-to-Patient Evidence Graph™",
            "Radioactive Material Accountability Ledger™",
            "Auditor Question-to-Evidence Engine™",
            "Executive Governance Passport Factory™",
            "Pilot Readiness & ROI Engine™"
        ],
        "duration": "6–8 weeks",
        "success_metrics": [
            "Release Defensibility Passport generated",
            "Dose Journey Passport generated",
            "Radioactive Material Accountability Passport generated",
            "Auditor questions mapped to evidence",
            "Evidence maturity improved",
            "Manual evidence-search time reduced",
            "Executive pilot ROI story documented"
        ],
        "pilot_message": "Start small and prove high-value governance assurance without replacing existing systems."
    }

    buyer_targets = [
        {"buyer": "Radiopharma executives / site heads", "message": "One governed answer for commercial readiness and launch confidence."},
        {"buyer": "IRLT operations leadership", "message": "Operational readiness, treatment readiness, release timing, and scale-up risk visibility."},
        {"buyer": "QA / compliance leadership", "message": "Release defensibility, inspection readiness, evidence lineage, and audit response."},
        {"buyer": "QC leadership", "message": "QC readiness and release dependency visibility."},
        {"buyer": "Radiation safety teams", "message": "Radioactive material accountability, reconciliation, decay, waste, and disposal governance."},
        {"buyer": "Supply chain / logistics", "message": "Custody, cold-chain, courier route, receipt, and exception governance."},
        {"buyer": "Treatment coordination / nuclear medicine operations", "message": "Dose-to-slot readiness and treatment-window protection without PHI capture."},
        {"buyer": "Digital / IT governance teams", "message": "Evidence integrity, access governance, black box timeline, and human-governed AI."},
        {"buyer": "Operational excellence teams", "message": "Commercial scale-up stress testing, bottleneck visibility, and continuous readiness improvement."}
    ]

    next_steps = [
        {
            "area": "Azure App Service",
            "priority": "High",
            "next_action": "Deploy the latest committed app.py to Azure App Service and test all public routes using the Azure URL.",
            "why": "This makes the demo usable outside local 127.0.0.1."
        },
        {
            "area": "GitHub",
            "priority": "High",
            "next_action": "Confirm all RLTTrust™ commits and stable tags are pushed to GitHub main.",
            "why": "This preserves the build history and creates a defensible development record."
        },
        {
            "area": "Power BI",
            "priority": "High",
            "next_action": "Connect APIs from Command Center, Passport Factory, Pilot ROI, Route Health, and Final QA into a Power BI executive dashboard.",
            "why": "Power BI will make the product feel enterprise-ready for leadership."
        },
        {
            "area": "Data Model",
            "priority": "High",
            "next_action": "Convert hardcoded demo data into reusable JSON/config objects or Azure Blob-backed records.",
            "why": "This prepares the app for real pilot data without rewriting every page."
        },
        {
            "area": "Evidence Upload",
            "priority": "High",
            "next_action": "Add controlled evidence upload and hash verification for release packets, dose journey packets, and material accountability records.",
            "why": "This moves RLTTrust™ from demo intelligence to real evidence governance."
        },
        {
            "area": "Authentication",
            "priority": "Medium",
            "next_action": "Add protected login or role-based access for QA, operations, executive, and admin views.",
            "why": "Commercial users will expect access control before real deployment."
        },
        {
            "area": "Export",
            "priority": "Medium",
            "next_action": "Add PDF/CSV export for passports, final QA report, pilot ROI, and auditor evidence responses.",
            "why": "Executives and QA teams need portable artifacts."
        },
        {
            "area": "PowerPoint / Sales Deck",
            "priority": "Medium",
            "next_action": "Create a 10–12 slide RLTTrust™ buyer deck using the Commercial Package, Executive Summary, and Pilot ROI story.",
            "why": "This becomes the external-facing pitch material."
        },
        {
            "area": "Validation / QA Boundary",
            "priority": "Medium",
            "next_action": "Document that RLTTrust™ is advisory and non-GxP decision-making unless formally validated in a buyer environment.",
            "why": "This protects the product from overclaiming regulated authority."
        },
        {
            "area": "Pilot Package",
            "priority": "High",
            "next_action": "Prepare one pilot packet: pilot charter, scope, evidence inputs, RACI, timeline, success metrics, and ROI model.",
            "why": "This is the cleanest next commercial step."
        }
    ]

    production_hardening = [
        "Move demo data out of route functions into configuration/data files.",
        "Add persistent database or Azure Blob-backed data storage.",
        "Add real evidence upload, hashing, and verification.",
        "Add role-based access control.",
        "Add exportable passport PDFs.",
        "Add API schema documentation.",
        "Add Power BI-ready JSON endpoints for all executive metrics.",
        "Add error handling for missing or malformed query parameters.",
        "Create reusable CSS/template components to reduce duplicated HTML.",
        "Add automated route tests.",
        "Add unit tests for scoring functions.",
        "Add deployment smoke test workflow in GitHub Actions.",
        "Add privacy guardrails for patient-slot workflows to avoid PHI handling.",
        "Document validation boundary and advisory-only AI posture.",
        "Create a buyer-facing product deck and pilot proposal."
    ]

    strategic_assets = [
        {
            "asset": "Commercial Product Story",
            "description": "RLTTrust™ is now positioned as a commercial readiness governance overlay for IRLT/radiopharma."
        },
        {
            "asset": "Technical Demo",
            "description": "The Flask app now contains a complete demo suite with routes, APIs, and product navigation."
        },
        {
            "asset": "Buyer Narrative",
            "description": "The build explains the market problem, pain points, differentiators, personas, and pilot offer."
        },
        {
            "asset": "Pilot Path",
            "description": "The product has a practical 6–8 week pilot story."
        },
        {
            "asset": "Governance Philosophy",
            "description": "AI is advisory only, while human governance remains authoritative."
        },
        {
            "asset": "IP / Novelty Narrative",
            "description": "The build demonstrates governance-first operational trust for regulated radiopharma scale-up."
        }
    ]

    final_message = {
        "headline": "RLTTrust™ Platform A is now packaged as a complete IRLT commercial readiness governance product demo.",
        "summary": "The build now includes the operational cockpit, radiopharma-specific evidence engines, QA release defensibility, inspection survivability, patient-slot protection, commercial stress testing, executive passports, buyer demo story, pilot ROI, commercial packaging, final QA, and handover summary.",
        "recommended_next_work": "Move from demo build to deployment, evidence upload, Power BI executive dashboard, and buyer pilot package.",
        "strongest_sentence": "RLTTrust™ helps radiopharma leadership defend commercial IRLT readiness with governed evidence, not scattered confidence."
    }

    return {
        "product_summary": product_summary,
        "modules_built": modules_built,
        "best_demo_order": best_demo_order,
        "strongest_pilot": strongest_pilot,
        "buyer_targets": buyer_targets,
        "next_steps": next_steps,
        "production_hardening": production_hardening,
        "strategic_assets": strategic_assets,
        "final_message": final_message,
        "governance_note": "Final Inventory + Handover Summary is a product handover and planning layer. It does not replace regulated validation, QA approval, cybersecurity review, privacy review, production release governance, or human leadership approval."
    }


@app.route("/irlt-commercial-readiness/handover-summary")
@app.route("/irlt-commercial-readiness/final-inventory")
@app.route("/rlttrust/handover-summary")
def rlttrust_final_inventory_handover_summary():
    result = _rlttrust_final_handover_summary_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Final Inventory + Handover Summary | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --text: #f4f7fb;
                --muted: #aeb6c6;
                --green: #37d67a;
            }

            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.30), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.18), transparent 34%),
                    radial-gradient(circle at 52% 30%, rgba(255,255,255,0.065), transparent 30%),
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
                border: 1px solid rgba(255,122,24,0.38);
                border-radius: 42px;
                padding: 42px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.24), rgba(20,24,33,0.94) 39%, rgba(7,8,12,0.97)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.026) 0 1px, transparent 1px 76px);
                box-shadow: 0 40px 135px rgba(0,0,0,0.60);
            }

            .hero-grid {
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
            }

            h1 {
                margin: 10px 0;
                font-size: clamp(52px, 5.8vw, 104px);
                line-height: .86;
                letter-spacing: -.08em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 36px);
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
            }

            .score-card, .panel, .metric, .card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .score {
                font-size: clamp(76px, 7vw, 132px);
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
                margin-top: 22px;
            }

            .nav a, .open-link {
                text-decoration: none;
                color: #f4f7fb;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,122,24,0.25);
                display: inline-block;
                transition: transform .18s ease, border-color .18s ease, background .18s ease;
            }

            .nav a:hover, .open-link:hover {
                transform: translateY(-2px);
                border-color: rgba(255,122,24,0.75);
                background: rgba(255,122,24,0.14);
            }

            .section {
                margin-top: 32px;
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
                margin-top: 14px;
            }

            @media print {
                .nav { display: none; }
                body { background: white; color: #111; }
                .hero, .panel, .metric, .card, .score-card {
                    box-shadow: none;
                    background: white;
                    color: #111;
                    border-color: #ccc;
                }
                p, td, li { color: #333 !important; }
                h1, h2, h3, th { color: #111 !important; }
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-3, .grid-4 {
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
                        <div class="eyebrow">Final Product Handover</div>
                        <h1>Final Inventory + Handover Summary</h1>
                        <p class="hero-line">{{ result.final_message.headline }}</p>
                        <p>{{ result.final_message.summary }}</p>
                        <p><strong style="color:#ffd7ad;">Strongest Sentence:</strong> {{ result.final_message.strongest_sentence }}</p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>
                            <a href="/irlt-commercial-readiness/commercial-package">Commercial Package</a>
                            <a href="/irlt-commercial-readiness/launchpad">Launchpad</a>
                            <a href="/irlt-commercial-readiness/final-qa">Final QA</a>
                            <a href="/irlt-commercial-readiness/handover-summary/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Modules Packaged</div>
                        <div class="score">{{ result.modules_built|length }}</div>
                        <p>{{ result.product_summary.product_status }}</p>
                        <div class="note">{{ result.product_summary.executive_question }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="grid-4">
                    <div class="metric"><strong>20</strong><span>Product Assets</span></div>
                    <div class="metric"><strong>11</strong><span>Recommended Demo Steps</span></div>
                    <div class="metric"><strong>6–8</strong><span>Pilot Weeks</span></div>
                    <div class="metric"><strong>1</strong><span>Focused First Pilot</span></div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Product Summary</h2>
                    <p><strong style="color:#fff2e6;">Product:</strong> {{ result.product_summary.product }}</p>
                    <p><strong style="color:#fff2e6;">Platform:</strong> {{ result.product_summary.platform }}</p>
                    <p><strong style="color:#fff2e6;">Category:</strong> {{ result.product_summary.category }}</p>
                    <p><strong style="color:#fff2e6;">Core Positioning:</strong> {{ result.product_summary.core_positioning }}</p>
                    <p><strong style="color:#fff2e6;">Handover Date:</strong> {{ result.product_summary.handover_date }}</p>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Everything Built</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Module</th>
                                <th>Purpose</th>
                                <th>Buyer Value</th>
                                <th>Open</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.modules_built %}
                            <tr>
                                <td>{{ item.number }}</td>
                                <td><strong>{{ item.module }}</strong></td>
                                <td>{{ item.purpose }}</td>
                                <td>{{ item.buyer_value }}</td>
                                <td><a class="open-link" href="{{ item.route }}">Open</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Best Demo Order</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Step</th>
                                <th>Page</th>
                                <th>Talk Track</th>
                                <th>Open</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for step in result.best_demo_order %}
                            <tr>
                                <td>{{ step.step }}</td>
                                <td><strong>{{ step.page }}</strong></td>
                                <td>{{ step.talk_track }}</td>
                                <td><a class="open-link" href="{{ step.route }}">Open</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Strongest First Pilot</h2>
                    <p><strong style="color:#fff2e6;">Scope:</strong> {{ result.strongest_pilot.scope }}</p>
                    <p><strong style="color:#fff2e6;">Duration:</strong> {{ result.strongest_pilot.duration }}</p>
                    {% for module in result.strongest_pilot.modules %}
                    <span class="pill">{{ module }}</span>
                    {% endfor %}
                    <h3 style="margin-top:22px;">Success Metrics</h3>
                    <ul>
                        {% for metric in result.strongest_pilot.success_metrics %}
                        <li>{{ metric }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.strongest_pilot.pilot_message }}</div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Target Buyers</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Buyer</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for buyer in result.buyer_targets %}
                            <tr>
                                <td><strong>{{ buyer.buyer }}</strong></td>
                                <td>{{ buyer.message }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Next Steps: Azure / GitHub / Power BI / Productization</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Area</th>
                                <th>Priority</th>
                                <th>Next Action</th>
                                <th>Why</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for step in result.next_steps %}
                            <tr>
                                <td><strong>{{ step.area }}</strong></td>
                                <td>{{ step.priority }}</td>
                                <td>{{ step.next_action }}</td>
                                <td>{{ step.why }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Production Hardening Still Needed</h2>
                    <ul>
                        {% for item in result.production_hardening %}
                        <li>{{ item }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Strategic Assets Created</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Asset</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for asset in result.strategic_assets %}
                            <tr>
                                <td><strong>{{ asset.asset }}</strong></td>
                                <td>{{ asset.description }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Final Recommendation</h2>
                    <p>{{ result.final_message.recommended_next_work }}</p>
                    <div class="note">{{ result.final_message.strongest_sentence }}</div>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/handover-summary/api")
@app.route("/irlt-commercial-readiness/final-inventory/api")
@app.route("/rlttrust/handover-summary/api")
def rlttrust_final_inventory_handover_summary_api():
    return jsonify(_rlttrust_final_handover_summary_data())

# ============================================================
# End Final Inventory + Handover Summary
# ============================================================

'''

    # Add Handover Summary link to navigation where Final QA exists.
    nav_marker = "RLTTRUST_NAV_FINAL_HANDOVER_SUMMARY_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/final-qa">Final QA</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_FINAL_HANDOVER_SUMMARY_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/handover-summary">Handover Summary</a>',
            1
        )
        print("Added Handover Summary link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Final Inventory + Handover Summary successfully.")

