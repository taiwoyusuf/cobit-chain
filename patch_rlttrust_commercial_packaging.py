from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_FINAL_COMMERCIAL_PACKAGING_LAYER_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Final Commercial Packaging Layer already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_FINAL_COMMERCIAL_PACKAGING_LAYER_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Final Commercial Packaging Layer™
# Purpose: Buyer-facing commercial product packaging page with product story,
#          problem, solution, differentiators, buyers, pilot offer, and expansion path.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify

def _rlttrust_commercial_packaging_data():
    hero = {
        "product": "RLTTrust™",
        "subtitle": "IRLT Commercial Readiness Governance Command Center™",
        "category": "Enterprise Governance Assurance Platform for regulated radiopharma and IRLT operations",
        "headline": "Defend commercial IRLT readiness with governed evidence, not scattered confidence.",
        "one_liner": "RLTTrust™ gives radiopharma leadership one operational trust layer for commercialization readiness, release defensibility, isotope-to-patient traceability, radioactive material accountability, inspection survivability, patient-slot protection, and executive governance passports.",
        "positioning": "RLTTrust™ does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics platforms, treatment scheduling, or manufacturing systems. It overlays them with governed evidence, operational trust scoring, dependency intelligence, human approval lineage, and inspection-survivable artifacts."
    }

    market_problem = [
        {
            "problem": "Commercial readiness is fragmented.",
            "detail": "IRLT readiness often lives across QC, QA, manufacturing, radiation safety, supply chain, treatment coordination, digital systems, spreadsheets, meetings, and document repositories.",
            "business_impact": "Leadership may not know whether readiness is truly defensible or only operationally assumed."
        },
        {
            "problem": "IRLT operations are time-sensitive.",
            "detail": "Isotope timing, QC release, QA disposition, courier ETA, treatment-site readiness, and appointment windows can all change readiness quickly.",
            "business_impact": "A dose can be manufactured and still become operationally fragile before treatment."
        },
        {
            "problem": "Inspection evidence is hard to assemble.",
            "detail": "When auditors ask questions, teams manually search controlled documents, QMS records, access records, release evidence, material records, custody records, and emails.",
            "business_impact": "Audit response becomes reactive, slow, and dependent on tribal knowledge."
        },
        {
            "problem": "Release approval does not automatically prove release defensibility.",
            "detail": "Release decisions need connected evidence from QC, QA, deviations, CAPA, EM, SOP/training, access, custody, radioactive material, and data integrity.",
            "business_impact": "QA may have approval records but still lack a single defensible release narrative."
        },
        {
            "problem": "Radioactive material accountability is highly specific.",
            "detail": "Receipt, use, transfer, decay, waste, residual activity, disposal, and reconciliation must be provable across the lifecycle.",
            "business_impact": "Generic governance tools do not fully address radiopharma-specific accountability."
        },
        {
            "problem": "AI needs governance boundaries.",
            "detail": "Regulated companies want intelligence but cannot allow AI to become the quality, release, clinical, or compliance decision-maker.",
            "business_impact": "AI adoption stalls unless advisory output is clearly separated from human authority."
        }
    ]

    solution_pillars = [
        {
            "pillar": "Operational Trust Scoring",
            "description": "Converts fragmented readiness signals into governed readiness scores, warnings, blockers, and executive answers.",
            "modules": ["Command Center", "Can We Treat Tomorrow?", "Network Mesh", "Stress Test"]
        },
        {
            "pillar": "Governed Evidence Lineage",
            "description": "Links evidence packets, owners, source engines, human decisions, and passport outputs into defensible readiness artifacts.",
            "modules": ["Isotope-to-Patient Graph", "AuditVault-style Evidence Logic", "Governance Black Box"]
        },
        {
            "pillar": "Release Defensibility",
            "description": "Maps QA release confidence to QC, CAPA, EM, SOP/training, access, custody, radioactive material, and evidence integrity.",
            "modules": ["Release Defensibility Engine", "Inspection Tomorrow", "Passport Factory"]
        },
        {
            "pillar": "Radiopharma-Specific Accountability",
            "description": "Addresses isotope timing, radioactive material lifecycle, cold-chain, chain of custody, dose journey, and patient-slot readiness.",
            "modules": ["Material Ledger", "Patient Slot Protection", "Isotope-to-Patient Graph"]
        },
        {
            "pillar": "Inspection Survivability",
            "description": "Maps auditor questions to evidence packets, owners, gaps, source engines, and inspection-ready passports.",
            "modules": ["Auditor Evidence Engine", "Inspection Tomorrow", "Black Box Recorder"]
        },
        {
            "pillar": "Human-Governed AI",
            "description": "Keeps AI advisory only while recording human approval lineage and decision authority.",
            "modules": ["Governance Black Box", "Auditor Evidence", "Passport Factory"]
        }
    ]

    product_modules = [
        {
            "name": "Executive Summary One-Page View™",
            "route": "/irlt-commercial-readiness/executive-summary",
            "commercial_value": "Explains the whole product in one boardroom-ready screen."
        },
        {
            "name": "Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "commercial_value": "Unified product home for all modules."
        },
        {
            "name": "Buyer Demo Mode™",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "commercial_value": "Buyer-facing product story, pain points, objections, personas, and demo flow."
        },
        {
            "name": "Command Center™",
            "route": "/irlt-commercial-readiness",
            "commercial_value": "Executive cockpit for commercial readiness and operational trust."
        },
        {
            "name": "Can We Treat Tomorrow? Engine™",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "commercial_value": "Answers whether tomorrow’s treatment readiness is operationally defensible."
        },
        {
            "name": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "commercial_value": "Maps dose journey evidence from isotope source to treatment readiness."
        },
        {
            "name": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "commercial_value": "Radiopharma-specific material lifecycle accountability and reconciliation."
        },
        {
            "name": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "commercial_value": "Helps QA defend release decisions with governed evidence."
        },
        {
            "name": "Inspection Tomorrow Simulator™",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "commercial_value": "Shows inspection exposure before the inspector does."
        },
        {
            "name": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "commercial_value": "Maps auditor questions directly to evidence packets, owners, gaps, and passports."
        },
        {
            "name": "Governance Black Box Recorder™",
            "route": "/irlt-commercial-readiness/governance-black-box",
            "commercial_value": "Records readiness signals, AI advisories, human decisions, and evidence lineage."
        },
        {
            "name": "Patient Slot Protection Engine™",
            "route": "/irlt-commercial-readiness/patient-slot-protection",
            "commercial_value": "Protects treatment-window readiness without storing PHI."
        },
        {
            "name": "Cross-Site Network Readiness Mesh™",
            "route": "/irlt-commercial-readiness/network-readiness-mesh",
            "commercial_value": "Assesses multi-site commercial scale-up readiness and fallback capacity."
        },
        {
            "name": "Commercialization Stress Test Simulator™",
            "route": "/irlt-commercial-readiness/commercialization-stress-test",
            "commercial_value": "Tests readiness under QC delay, hot-cell outage, isotope delay, courier failure, and evidence loss."
        },
        {
            "name": "Executive Governance Passport Factory™",
            "route": "/irlt-commercial-readiness/passport-factory",
            "commercial_value": "Generates leadership-ready and inspection-ready governance passports."
        },
        {
            "name": "Pilot Readiness & ROI Engine™",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "commercial_value": "Turns the product into a practical pilot proposal and ROI justification."
        },
        {
            "name": "Buyer Demo Flow™",
            "route": "/irlt-commercial-readiness/demo-flow",
            "commercial_value": "Guided demo paths for executives, QA, operations, enterprise buyers, and pilot approval."
        }
    ]

    differentiators = [
        {
            "differentiator": "Built specifically for IRLT/radiopharma realities",
            "why_it_matters": "Generic GRC tools do not model isotope timing, dose journey, radioactive material reconciliation, treatment-slot protection, and cold-chain/custody readiness together."
        },
        {
            "differentiator": "Governance overlay, not system replacement",
            "why_it_matters": "Buyers can keep Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics, and scheduling systems while adding a governed trust layer."
        },
        {
            "differentiator": "Operational trust scoring with evidence lineage",
            "why_it_matters": "Scores are tied to evidence, owners, gaps, decisions, and passports rather than being decorative dashboard numbers."
        },
        {
            "differentiator": "Inspection-survivable artifacts",
            "why_it_matters": "The platform produces passports, black box timelines, evidence maps, and auditor question responses."
        },
        {
            "differentiator": "Human-governed AI architecture",
            "why_it_matters": "AI gives advisory intelligence while human QA, compliance, radiation safety, clinical, operations, and leadership authority remains the control layer."
        },
        {
            "differentiator": "Commercialization stress testing",
            "why_it_matters": "Leadership can see whether readiness survives realistic disruption before commercial launch pressure exposes the weakness."
        }
    ]

    buyer_personas = [
        {
            "buyer": "Radiopharma Executive / Site Head",
            "cares_about": "Launch confidence, readiness defensibility, scale-up, network resilience, and executive accountability.",
            "message": "RLTTrust™ gives you one governed readiness answer across the commercial operation."
        },
        {
            "buyer": "QA / Compliance Leadership",
            "cares_about": "Release defensibility, CAPA/EM impact, inspection response, evidence integrity, SOP/training, and audit readiness.",
            "message": "RLTTrust™ helps QA defend release and inspection readiness with connected evidence."
        },
        {
            "buyer": "Radiation Safety",
            "cares_about": "Radioactive material receipt, use, transfer, decay, waste, disposal, residual, and reconciliation.",
            "message": "RLTTrust™ creates a governed material accountability passport."
        },
        {
            "buyer": "Manufacturing / Operations",
            "cares_about": "Production readiness, hot-cell capacity, QC/QA timing, batch records, and operational continuity.",
            "message": "RLTTrust™ shows whether operational readiness is actually defensible."
        },
        {
            "buyer": "Supply Chain / Logistics",
            "cares_about": "Courier timing, custody, cold-chain, shipment exceptions, treatment-site receipt, and route resilience.",
            "message": "RLTTrust™ connects custody and shipment evidence to release and patient-slot readiness."
        },
        {
            "buyer": "Treatment Coordination / Nuclear Medicine",
            "cares_about": "Treatment window, authorized user readiness, site readiness, appointment alignment, and dose-to-slot match.",
            "message": "RLTTrust™ protects patient-slot readiness without replacing scheduling systems or storing PHI."
        },
        {
            "buyer": "IT / Digital / Data Integrity",
            "cares_about": "System evidence, audit trails, access governance, integrations, data integrity, backup/restore proof, and AI controls.",
            "message": "RLTTrust™ provides the governance assurance layer across systems."
        }
    ]

    pilot_offer = {
        "title": "Recommended First Pilot",
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
            "Evidence retrieval time reduced",
            "Readiness score improved",
            "Evidence maturity improved",
            "Release defensibility passport generated",
            "Dose journey passport generated",
            "Material accountability passport generated",
            "Auditor questions mapped to evidence",
            "Pilot ROI and expansion path documented"
        ],
        "why_it_works": "The pilot proves the strongest value quickly without replacing existing systems or touching clinical decision-making."
    }

    enterprise_expansion = [
        {
            "stage": "Pilot",
            "scope": "One site, one dose journey, one release pathway.",
            "outcome": "Prove evidence mapping, release defensibility, dose journey traceability, and passports."
        },
        {
            "stage": "Site Rollout",
            "scope": "One full site across multiple release pathways and evidence domains.",
            "outcome": "Operationalize readiness governance for QA, QC, manufacturing, radiation safety, supply chain, and treatment coordination."
        },
        {
            "stage": "Network Rollout",
            "scope": "Multiple sites, treatment hubs, courier lanes, release lanes, and fallback pathways.",
            "outcome": "Enable commercial scale-up assurance and cross-site readiness governance."
        },
        {
            "stage": "Enterprise Assurance Layer",
            "scope": "Multiple products, programs, sites, inspections, and governance domains.",
            "outcome": "Create an enterprise operational trust layer for regulated radiopharma operations."
        }
    ]

    competitive_positioning = [
        {
            "alternative": "Traditional dashboards",
            "limitation": "Show status but often lack evidence lineage, human approval context, and inspection survivability.",
            "rlttrust_edge": "RLTTrust™ ties readiness to evidence, owners, warnings, blockers, passports, and black box history."
        },
        {
            "alternative": "QMS / Veeva alone",
            "limitation": "Strong system of record, but not always a cross-system operational readiness command layer.",
            "rlttrust_edge": "RLTTrust™ overlays QMS evidence with operational readiness, release defensibility, and commercial scale-up intelligence."
        },
        {
            "alternative": "MES / LIMS alone",
            "limitation": "Strong execution and test data systems, but not designed to unify release, shipment, site readiness, inspection, and executive passports.",
            "rlttrust_edge": "RLTTrust™ connects manufacturing and QC evidence to broader governance defensibility."
        },
        {
            "alternative": "Spreadsheets and meetings",
            "limitation": "Flexible but fragile, hard to audit, hard to prove, and difficult to scale.",
            "rlttrust_edge": "RLTTrust™ converts readiness tracking into governed evidence, traceability, and executive artifacts."
        },
        {
            "alternative": "Generic GRC tools",
            "limitation": "Broad controls but not deeply tailored to IRLT timing, material lifecycle, custody, and patient-slot readiness.",
            "rlttrust_edge": "RLTTrust™ is purpose-built for radiopharma governance assurance."
        }
    ]

    sales_narrative = {
        "opening": "Commercial IRLT readiness is not one department’s status update. It is a governed evidence problem across QA, QC, manufacturing, radiation safety, logistics, treatment coordination, digital systems, and leadership.",
        "product_answer": "RLTTrust™ creates one operational trust layer that shows whether readiness can be defended, what evidence supports it, what remains weak, who owns closure, and which passport proves it.",
        "buyer_result": "Leadership gets an evidence-backed answer to the question: can we defend commercial readiness tomorrow?",
        "commercial_close": "Start with a focused pilot: one site, one dose journey, one release pathway, one evidence pack, and measurable inspection-readiness value."
    }

    metrics = {
        "commercial_packaging_score": 95,
        "buyer_clarity": 94,
        "radiopharma_specificity": 96,
        "pilot_readiness": 88,
        "enterprise_expansion_strength": 91,
        "inspection_defensibility_value": 94
    }

    return {
        "hero": hero,
        "market_problem": market_problem,
        "solution_pillars": solution_pillars,
        "product_modules": product_modules,
        "differentiators": differentiators,
        "buyer_personas": buyer_personas,
        "pilot_offer": pilot_offer,
        "enterprise_expansion": enterprise_expansion,
        "competitive_positioning": competitive_positioning,
        "sales_narrative": sales_narrative,
        "metrics": metrics,
        "governance_note": "Final Commercial Packaging Layer™ is a buyer-facing product packaging and storytelling layer. It does not replace regulated systems, QA release authority, radiation safety authority, clinical judgment, regulatory judgment, or human leadership approval."
    }


@app.route("/irlt-commercial-readiness/commercial-package")
@app.route("/irlt-commercial-readiness/brochure")
@app.route("/rlttrust/commercial-package")
def rlttrust_final_commercial_packaging_layer():
    result = _rlttrust_commercial_packaging_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Final Commercial Packaging Layer™ | RLTTrust™</title>
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

            .hero:after {
                content: "";
                position: absolute;
                right: -210px;
                top: -240px;
                width: 720px;
                height: 720px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.28);
                box-shadow: inset 0 0 90px rgba(255,122,24,0.12), 0 0 120px rgba(255,122,24,0.15);
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
                font-size: clamp(54px, 6vw, 112px);
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
                max-width: 1100px;
            }

            .score-card, .panel, .metric, .card, .module-card, .pillar-card {
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

            .metric p {
                margin: 8px 0 0;
                font-size: 13px;
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

            .card, .pillar-card {
                min-height: 230px;
            }

            .card h3, .pillar-card h3 {
                color: #fff2e6;
                font-size: 21px;
            }

            .module-grid {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 14px;
            }

            .module-card {
                min-height: 170px;
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
                margin-top: 8px;
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
                margin-top: 14px;
            }

            @media print {
                .nav { display: none; }
                body { background: white; color: #111; }
                .hero, .panel, .metric, .card, .module-card, .pillar-card, .score-card {
                    box-shadow: none;
                    background: white;
                    color: #111;
                    border-color: #ccc;
                }
                p, td, small, li { color: #333 !important; }
                h1, h2, h3, th { color: #111 !important; }
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
                        <div class="eyebrow">{{ result.hero.category }}</div>
                        <h1>{{ result.hero.product }}</h1>
                        <p class="hero-line">{{ result.hero.headline }}</p>
                        <p>{{ result.hero.one_liner }}</p>
                        <p>{{ result.hero.positioning }}</p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>
                            <a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>
                            <a href="/irlt-commercial-readiness/demo-flow">Demo Flow</a>
                            <a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>
                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                            <a href="/irlt-commercial-readiness/commercial-package/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Commercial Packaging Score</div>
                        <div class="score">{{ result.metrics.commercial_packaging_score }}%</div>
                        <p>{{ result.sales_narrative.product_answer }}</p>
                        <div class="note">{{ result.sales_narrative.commercial_close }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Commercial Readiness Metrics</h2>
                <div class="grid-4">
                    <div class="metric"><strong>{{ result.metrics.buyer_clarity }}%</strong><span>Buyer Clarity</span><div class="bar"><span style="width: {{ result.metrics.buyer_clarity }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.metrics.radiopharma_specificity }}%</strong><span>Radiopharma Specificity</span><div class="bar"><span style="width: {{ result.metrics.radiopharma_specificity }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.metrics.pilot_readiness }}%</strong><span>Pilot Readiness</span><div class="bar"><span style="width: {{ result.metrics.pilot_readiness }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.metrics.inspection_defensibility_value }}%</strong><span>Inspection Value</span><div class="bar"><span style="width: {{ result.metrics.inspection_defensibility_value }}%;"></span></div></div>
                </div>
            </section>

            <section class="section">
                <h2>Market Problem</h2>
                <div class="grid-3">
                    {% for item in result.market_problem %}
                    <div class="card">
                        <h3>{{ item.problem }}</h3>
                        <p><strong style="color:#fff2e6;">Detail:</strong> {{ item.detail }}</p>
                        <p><strong style="color:#ffd7ad;">Business Impact:</strong> {{ item.business_impact }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <h2>Solution Pillars</h2>
                <div class="grid-3">
                    {% for pillar in result.solution_pillars %}
                    <div class="pillar-card">
                        <h3>{{ pillar.pillar }}</h3>
                        <p>{{ pillar.description }}</p>
                        {% for module in pillar.modules %}
                        <span class="pill">{{ module }}</span>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Why RLTTrust™ Is Different</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Differentiator</th>
                                <th>Why It Matters</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.differentiators %}
                            <tr>
                                <td><strong>{{ item.differentiator }}</strong></td>
                                <td>{{ item.why_it_matters }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Target Buyers</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Buyer</th>
                                <th>Cares About</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for buyer in result.buyer_personas %}
                            <tr>
                                <td><strong>{{ buyer.buyer }}</strong></td>
                                <td>{{ buyer.cares_about }}</td>
                                <td>{{ buyer.message }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section">
                <h2>Product Modules</h2>
                <div class="module-grid">
                    {% for module in result.product_modules %}
                    <div class="module-card">
                        <h3><a href="{{ module.route }}">{{ module.name }}</a></h3>
                        <small>{{ module.commercial_value }}</small>
                        <a class="open-link" href="{{ module.route }}">Open</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Recommended First Pilot</h2>
                    <p><strong style="color:#fff2e6;">Scope:</strong> {{ result.pilot_offer.scope }}</p>
                    <p><strong style="color:#fff2e6;">Duration:</strong> {{ result.pilot_offer.duration }}</p>
                    {% for module in result.pilot_offer.modules %}
                    <span class="pill">{{ module }}</span>
                    {% endfor %}
                    <h3 style="margin-top:20px;">Success Metrics</h3>
                    <ul>
                        {% for metric in result.pilot_offer.success_metrics %}
                        <li>{{ metric }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.pilot_offer.why_it_works }}</div>
                </div>

                <div class="panel">
                    <h2>Enterprise Expansion Story</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Stage</th>
                                <th>Scope</th>
                                <th>Outcome</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for stage in result.enterprise_expansion %}
                            <tr>
                                <td><strong>{{ stage.stage }}</strong></td>
                                <td>{{ stage.scope }}</td>
                                <td>{{ stage.outcome }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Competitive Positioning</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Alternative</th>
                                <th>Limitation</th>
                                <th>RLTTrust™ Edge</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.competitive_positioning %}
                            <tr>
                                <td><strong>{{ item.alternative }}</strong></td>
                                <td>{{ item.limitation }}</td>
                                <td>{{ item.rlttrust_edge }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Sales Narrative</h2>
                    <p><strong style="color:#fff2e6;">Opening:</strong> {{ result.sales_narrative.opening }}</p>
                    <p><strong style="color:#fff2e6;">Product Answer:</strong> {{ result.sales_narrative.product_answer }}</p>
                    <p><strong style="color:#fff2e6;">Buyer Result:</strong> {{ result.sales_narrative.buyer_result }}</p>
                    <div class="note">{{ result.sales_narrative.commercial_close }}</div>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/commercial-package/api")
@app.route("/irlt-commercial-readiness/brochure/api")
@app.route("/rlttrust/commercial-package/api")
def rlttrust_final_commercial_packaging_api():
    return jsonify(_rlttrust_commercial_packaging_data())

# ============================================================
# End Final Commercial Packaging Layer™
# ============================================================

'''

    # Add Commercial Package link to navigation where Demo Flow exists.
    nav_marker = "RLTTRUST_NAV_COMMERCIAL_PACKAGING_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/demo-flow">Demo Flow</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_COMMERCIAL_PACKAGING_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/commercial-package">Commercial Package</a>',
            1
        )
        print("Added Commercial Package link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Final Commercial Packaging Layer successfully.")

