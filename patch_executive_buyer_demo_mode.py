from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_EXECUTIVE_BUYER_DEMO_MODE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Executive Buyer Demo Mode already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_EXECUTIVE_BUYER_DEMO_MODE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Executive Buyer Demo Mode™
# Purpose: Buyer-facing commercial demo story for radiopharma / IRLT leadership.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_executive_buyer_demo_data():
    product_positioning = {
        "product": "RLTTrust™ / IRLT Commercial Readiness Governance Command Center™",
        "category": "Enterprise Governance Assurance Platform for regulated radiopharma and IRLT operations",
        "one_liner": "RLTTrust™ gives radiopharma leadership one governed command layer to defend commercial readiness, release confidence, isotope-to-patient traceability, inspection survivability, and patient-slot protection.",
        "not_replacing": [
            "Veeva",
            "MES",
            "LIMS",
            "ERP",
            "ServiceNow",
            "CTMS",
            "Logistics platforms",
            "Treatment scheduling systems",
            "Manufacturing execution systems"
        ],
        "overlay_message": "RLTTrust™ is not the system of record. It is the governance assurance and operational trust overlay that connects evidence from existing systems into defensible executive readiness."
    }

    buyer_pain_points = [
        {
            "pain": "Commercial readiness is scattered across departments.",
            "current_state": "QC, QA, manufacturing, supply chain, radiation safety, IT, training, and treatment coordination often track readiness separately.",
            "rlttrust_answer": "RLTTrust™ creates one governed readiness truth layer with domain scores, dependencies, evidence packets, and executive passports.",
            "executive_value": "Leadership can see what is ready, what is weak, what is missing, and what must be closed before commercial confidence."
        },
        {
            "pain": "Radiopharma readiness decays with time.",
            "current_state": "Traditional dashboards treat readiness as static, but IRLT operations are time-sensitive because isotope usability, QC timing, QA release, courier ETA, and treatment windows change rapidly.",
            "rlttrust_answer": "The platform uses decay-aware readiness logic through Can We Treat Tomorrow? Engine™, Patient Slot Protection Engine™, and Stress Test Simulator™.",
            "executive_value": "Leadership sees how delay propagates into release, shipment, treatment, and patient-slot risk."
        },
        {
            "pain": "Release may be approved but not defensible.",
            "current_state": "QA may approve release, but evidence may be scattered, stale, incomplete, or not linked to CAPA, EM, OOS/OOT, custody, training, and material accountability.",
            "rlttrust_answer": "Release Defensibility Engine™ maps release readiness to evidence gates and generates a Release Defensibility Passport.",
            "executive_value": "QA can defend why release was appropriate using governed evidence and human approval lineage."
        },
        {
            "pain": "Inspection response is reactive and manual.",
            "current_state": "When auditors ask questions, teams manually search documents, trackers, emails, systems, and folders.",
            "rlttrust_answer": "Auditor Question-to-Evidence Engine™ maps auditor questions to evidence packets, owners, source engines, gaps, and passports.",
            "executive_value": "Inspection response becomes structured, fast, evidence-backed, and leadership-defensible."
        },
        {
            "pain": "Radioactive material accountability is high-risk.",
            "current_state": "Receipt, use, transfer, decay, waste, residual activity, disposal, and reconciliation must be provable across the lifecycle.",
            "rlttrust_answer": "Radioactive Material Accountability Ledger™ creates a governed material lifecycle with hash-linked event records and reconciliation logic.",
            "executive_value": "Radiation safety, QA, and compliance get one defensible material accountability artifact."
        },
        {
            "pain": "Commercial scale-up exposes hidden bottlenecks.",
            "current_state": "A site may look ready until QC capacity, QA release lanes, hot-cell capacity, courier routes, treatment hubs, or fallback capacity are stressed.",
            "rlttrust_answer": "Cross-Site RLT Network Readiness Mesh™ and Commercialization Stress Test Simulator™ expose scale-up weaknesses before launch.",
            "executive_value": "Leadership can test whether the network survives realistic commercial disruption."
        },
        {
            "pain": "AI creates regulatory anxiety.",
            "current_state": "Regulated teams worry that AI may be seen as making quality, release, clinical, or compliance decisions.",
            "rlttrust_answer": "Governance Black Box Recorder™ separates AI advisory output from human decision authority and records human approval lineage.",
            "executive_value": "The platform uses AI safely as advisory intelligence while humans remain the authoritative control layer."
        }
    ]

    demo_storyline = [
        {
            "scene": "Scene 1 — Executive Readiness Question",
            "buyer_question": "Are we truly ready to commercialize IRLT operations?",
            "demo_route": "/irlt-commercial-readiness",
            "what_to_show": "Open the executive command center and show commercial readiness domains, operational trust scoring, orange/grey executive cockpit, and readiness weaknesses.",
            "wow_line": "This is not a dashboard. This is the executive governance layer that tells leadership what readiness can be defended with evidence."
        },
        {
            "scene": "Scene 2 — Can We Treat Tomorrow?",
            "buyer_question": "Can we manufacture, release, ship, receive, and support treatment tomorrow?",
            "demo_route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "what_to_show": "Show isotope timing, QC, QA release, custody, cold-chain, treatment-site readiness, CAPA, EM, training, access, backup, and evidence scoring.",
            "wow_line": "RLTTrust™ understands that in radiopharma, readiness is time-sensitive and can decay operationally."
        },
        {
            "scene": "Scene 3 — Isotope-to-Patient Traceability",
            "buyer_question": "Can we prove the dose journey from isotope source to patient-slot readiness?",
            "demo_route": "/irlt-commercial-readiness/isotope-to-patient",
            "what_to_show": "Show isotope source, manufacturing, QC, QA release, shipment, treatment-site receipt, patient slot, and Governance Passport linkage.",
            "wow_line": "This creates an evidence graph from isotope to patient-impact readiness without replacing existing systems."
        },
        {
            "scene": "Scene 4 — Release Defensibility",
            "buyer_question": "Can QA defend this release decision?",
            "demo_route": "/irlt-commercial-readiness/release-defensibility",
            "what_to_show": "Show QC gates, QA release rationale, CAPA/EM impact, SOP/training, access, custody, material accountability, and evidence integrity.",
            "wow_line": "RLTTrust™ helps QA defend release with governed evidence, not just procedural approval."
        },
        {
            "scene": "Scene 5 — Radioactive Material Accountability",
            "buyer_question": "Can we prove radioactive material receipt, use, transfer, decay, waste, residual, disposal, and reconciliation?",
            "demo_route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "what_to_show": "Show the hash-chained material lifecycle, activity reconciliation, red flags, inspector questions, and material passport outputs.",
            "wow_line": "This is where the product becomes unmistakably radiopharma-specific."
        },
        {
            "scene": "Scene 6 — Inspection Tomorrow",
            "buyer_question": "If FDA, NRC, QA, or corporate audit walked in tomorrow, what would fail?",
            "demo_route": "/irlt-commercial-readiness/inspection-tomorrow",
            "what_to_show": "Show simulated inspection findings, severity, evidence gaps, inspector question mapping, and war-room actions.",
            "wow_line": "RLTTrust™ lets leadership see inspection exposure before the inspector does."
        },
        {
            "scene": "Scene 7 — Patient Slot Protection",
            "buyer_question": "Can the dose still protect the scheduled treatment window?",
            "demo_route": "/irlt-commercial-readiness/patient-slot-protection",
            "what_to_show": "Show isotope hours remaining, treatment window, courier delay, site readiness, authorized user readiness, appointment confirmation, dose activity margin, and evidence readiness.",
            "wow_line": "This connects operational governance to patient-impact readiness without storing PHI."
        },
        {
            "scene": "Scene 8 — Network Scale-Up",
            "buyer_question": "Can the network support commercial demand across sites, hubs, and release lanes?",
            "demo_route": "/irlt-commercial-readiness/network-readiness-mesh",
            "what_to_show": "Show primary site, secondary site, future capacity, QC/QA release mesh, hot-cell capacity, isotope supply resilience, courier network, treatment hubs, fallback capacity, and evidence governance.",
            "wow_line": "This moves RLTTrust™ from site readiness to enterprise commercial scale-up assurance."
        },
        {
            "scene": "Scene 9 — Stress Test the Launch",
            "buyer_question": "What happens if QC is delayed, a hot cell is down, isotope supply is delayed, or evidence is missing?",
            "demo_route": "/irlt-commercial-readiness/commercialization-stress-test",
            "what_to_show": "Show what-if failure scenarios, stress survival score, raw operational damage, resilience absorption, unabsorbed damage, and war-room actions.",
            "wow_line": "Leadership can test commercialization fragility before real patients, inspectors, or supply commitments are exposed."
        },
        {
            "scene": "Scene 10 — Governance Black Box",
            "buyer_question": "Can we prove what happened, when, who owned it, what AI recommended, and what humans decided?",
            "demo_route": "/irlt-commercial-readiness/governance-black-box",
            "what_to_show": "Show hash-chained readiness signals, AI advisory separation, human decisions, release events, custody events, stress events, and evidence packets.",
            "wow_line": "This is the black box recorder for regulated operational readiness."
        },
        {
            "scene": "Scene 11 — Auditor Question-to-Evidence",
            "buyer_question": "When an auditor asks a question, can we immediately map it to evidence?",
            "demo_route": "/irlt-commercial-readiness/auditor-question-evidence",
            "what_to_show": "Type a question about material reconciliation, release defensibility, custody, SOP training, AI governance, or inspection readiness.",
            "wow_line": "RLTTrust™ turns inspection questions into governed evidence maps."
        },
        {
            "scene": "Scene 12 — Executive Passport Factory",
            "buyer_question": "Can we turn all this into executive and inspection artifacts?",
            "demo_route": "/irlt-commercial-readiness/passport-factory",
            "what_to_show": "Generate commercial readiness, release, dose journey, material, inspection, network, stress, black box, and auditor evidence passports.",
            "wow_line": "The output is not just analytics. It is leadership-ready and inspection-ready evidence."
        }
    ]

    buyer_personas = [
        {
            "persona": "Radiopharma President / Site Head",
            "cares_about": "Commercial readiness, launch confidence, network scale-up, patient delivery risk, and executive accountability.",
            "message": "RLTTrust™ gives you one governed readiness truth layer across manufacturing, QA, QC, logistics, treatment coordination, and evidence."
        },
        {
            "persona": "QA / Quality Leadership",
            "cares_about": "Release defensibility, CAPA, EM, inspection readiness, SOP/training, evidence integrity, and audit response.",
            "message": "RLTTrust™ gives QA a defensible evidence map for release, inspection, and quality-event readiness."
        },
        {
            "persona": "Radiation Safety / Compliance",
            "cares_about": "Radioactive material accountability, custody, reconciliation, waste, decay, transfer, disposal, and inspection evidence.",
            "message": "RLTTrust™ creates a governed radioactive material lifecycle ledger and reconciliation passport."
        },
        {
            "persona": "Supply Chain / Logistics",
            "cares_about": "Courier timing, cold-chain, custody, site receipt, exceptions, and treatment-window protection.",
            "message": "RLTTrust™ connects shipment movement to release confidence, treatment-site readiness, and patient-slot protection."
        },
        {
            "persona": "Treatment Coordination / Nuclear Medicine Operations",
            "cares_about": "Dose-to-slot alignment, authorized user readiness, appointment timing, treatment-site readiness, and operational continuity.",
            "message": "RLTTrust™ protects treatment-slot readiness without storing PHI or replacing scheduling systems."
        },
        {
            "persona": "IT / Digital / Data Integrity",
            "cares_about": "System evidence, audit trails, access governance, backup/restore proof, integrations, data integrity, and AI governance.",
            "message": "RLTTrust™ overlays existing systems with evidence integrity, governance lineage, and human-controlled AI."
        }
    ]

    product_modules = [
        {"module": "Command Center", "route": "/irlt-commercial-readiness", "buyer_value": "One executive cockpit for commercial readiness."},
        {"module": "Can We Treat Tomorrow? Engine™", "route": "/irlt-commercial-readiness/can-we-treat-tomorrow", "buyer_value": "Answers tomorrow readiness using decay-aware operational governance."},
        {"module": "Isotope-to-Patient Evidence Graph™", "route": "/irlt-commercial-readiness/isotope-to-patient", "buyer_value": "Maps dose journey evidence from isotope source to patient-slot readiness."},
        {"module": "Inspection Tomorrow Simulator™", "route": "/irlt-commercial-readiness/inspection-tomorrow", "buyer_value": "Shows what fails and what survives if inspected tomorrow."},
        {"module": "Radioactive Material Accountability Ledger™", "route": "/irlt-commercial-readiness/radioactive-material-ledger", "buyer_value": "Controls radioactive material lifecycle evidence and reconciliation."},
        {"module": "Release Defensibility Engine™", "route": "/irlt-commercial-readiness/release-defensibility", "buyer_value": "Helps QA defend release decisions with governed evidence."},
        {"module": "Patient Slot Protection Engine™", "route": "/irlt-commercial-readiness/patient-slot-protection", "buyer_value": "Connects dose readiness to treatment-window protection."},
        {"module": "Cross-Site Network Readiness Mesh™", "route": "/irlt-commercial-readiness/network-readiness-mesh", "buyer_value": "Supports multi-site commercial scale-up assurance."},
        {"module": "Commercialization Stress Test Simulator™", "route": "/irlt-commercial-readiness/commercialization-stress-test", "buyer_value": "Tests readiness against real-world failure scenarios."},
        {"module": "Governance Black Box Recorder™", "route": "/irlt-commercial-readiness/governance-black-box", "buyer_value": "Records readiness events, AI advisories, human decisions, and evidence lineage."},
        {"module": "Auditor Question-to-Evidence Engine™", "route": "/irlt-commercial-readiness/auditor-question-evidence", "buyer_value": "Maps auditor questions to evidence packets, owners, engines, and passports."},
        {"module": "Executive Governance Passport Factory™", "route": "/irlt-commercial-readiness/passport-factory", "buyer_value": "Creates executive-readable and inspection-ready governance artifacts."}
    ]

    business_case = [
        {
            "value_driver": "Faster inspection response",
            "why_it_matters": "Auditor questions can be mapped to evidence packets instead of manually searching across systems.",
            "proof_point": "Auditor Question-to-Evidence Engine™ + Governance Black Box Recorder™ + AuditVault™"
        },
        {
            "value_driver": "Stronger QA release defensibility",
            "why_it_matters": "QA can connect release decisions to QC, CAPA, EM, SOP, training, access, custody, material accountability, and evidence integrity.",
            "proof_point": "Release Defensibility Engine™ + Release Defensibility Passport"
        },
        {
            "value_driver": "Reduced commercial launch risk",
            "why_it_matters": "Leadership can identify weak domains before commercialization pressure exposes them.",
            "proof_point": "Command Center + Network Mesh + Stress Test Simulator™"
        },
        {
            "value_driver": "Patient-slot protection",
            "why_it_matters": "IRLT operations can fail even after release if logistics, site readiness, timing, or appointment alignment breaks.",
            "proof_point": "Patient Slot Protection Engine™ + Dose Journey Passport"
        },
        {
            "value_driver": "Radiopharma-specific accountability",
            "why_it_matters": "Radioactive material lifecycle evidence is central to defensibility.",
            "proof_point": "Radioactive Material Accountability Ledger™"
        },
        {
            "value_driver": "Safe AI governance",
            "why_it_matters": "AI can advise without becoming the source of truth or decision authority.",
            "proof_point": "Governance Black Box Recorder™ + Human Decision Lineage"
        }
    ]

    buyer_objections = [
        {
            "objection": "We already have Veeva, MES, LIMS, ERP, ServiceNow, and logistics systems.",
            "response": "Exactly. RLTTrust™ does not replace them. It connects governed evidence from those systems into one operational trust and readiness layer."
        },
        {
            "objection": "We cannot let AI make regulated decisions.",
            "response": "RLTTrust™ does not allow AI to approve release, treatment readiness, inspection readiness, or commercial readiness. AI is advisory only, and human governance remains authoritative."
        },
        {
            "objection": "Our readiness process is already tracked in spreadsheets and meetings.",
            "response": "RLTTrust™ can consume structured trackers, but adds evidence integrity, lineage, dependency logic, risk propagation, passports, and inspection survivability."
        },
        {
            "objection": "Radiopharma operations are too specific for generic governance tools.",
            "response": "That is why RLTTrust™ includes isotope timing, radioactive material accountability, dose journey evidence, patient-slot protection, custody, and cold-chain governance."
        },
        {
            "objection": "How does this help executives?",
            "response": "Executives get one answer: are we operationally ready, what risks remain, what evidence supports readiness, and can we defend it tomorrow?"
        }
    ]

    demo_metrics = {
        "product_readiness_score": 86,
        "buyer_demo_strength": 92,
        "radiopharma_specificity": 95,
        "inspection_value": 94,
        "executive_clarity": 91,
        "differentiation_score": 96,
        "commercial_pilot_readiness": 84
    }

    closing_pitch = {
        "headline": "RLTTrust™ is the operational governance command layer for commercial IRLT scale-up.",
        "message": "The platform helps radiopharma leadership defend commercial readiness by connecting operational signals, governed evidence, release defensibility, radioactive material accountability, shipment custody, patient-slot readiness, inspection survivability, and human-controlled AI into one executive trust layer.",
        "pilot_offer": "A focused pilot can start with one product, one site, one dose journey, one release pathway, and one inspection-readiness evidence pack.",
        "strongest_pilot": "Start with Release Defensibility + Isotope-to-Patient Evidence Graph + Radioactive Material Accountability Ledger + Governance Passport Factory."
    }

    return {
        "product_positioning": product_positioning,
        "buyer_pain_points": buyer_pain_points,
        "demo_storyline": demo_storyline,
        "buyer_personas": buyer_personas,
        "product_modules": product_modules,
        "business_case": business_case,
        "buyer_objections": buyer_objections,
        "demo_metrics": demo_metrics,
        "closing_pitch": closing_pitch,
        "governance_note": "Executive Buyer Demo Mode™ is a commercial storytelling and demonstration layer. It does not replace regulated systems, QA release authority, radiation safety authority, clinical authority, regulatory judgment, or human leadership decision-making."
    }


@app.route("/irlt-commercial-readiness/buyer-demo")
@app.route("/rlttrust/buyer-demo")
@app.route("/rlttrust/executive-buyer-demo")
def rlttrust_executive_buyer_demo_mode():
    result = _rlttrust_executive_buyer_demo_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Executive Buyer Demo Mode™ | RLTTrust™</title>
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

            .panel, .card, .metric, .scene-card {
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

            .demo-flow {
                display: grid;
                grid-template-columns: repeat(12, minmax(320px, 1fr));
                gap: 16px;
                overflow-x: auto;
                padding-bottom: 10px;
            }

            .scene-card {
                min-height: 420px;
                position: relative;
            }

            .scene-card:after {
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

            .scene-card:last-child:after {
                display: none;
            }

            .route-link {
                display: inline-block;
                margin-top: 10px;
                text-decoration: none;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                border-radius: 999px;
                padding: 10px 14px;
                font-weight: 950;
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
                        <div class="eyebrow">RLTTrust™ Commercial Buyer Story</div>
                        <h1>Executive Buyer Demo Mode™</h1>
                        <p>{{ result.product_positioning.one_liner }}</p>
                        <p>{{ result.product_positioning.overlay_message }}</p>

                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                            <a href="/irlt-commercial-readiness/auditor-question-evidence">Auditor Evidence Engine</a>
                            <a href="/irlt-commercial-readiness/commercialization-stress-test">Stress Test</a>
                            <a href="/irlt-commercial-readiness/buyer-demo/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Buyer Demo Strength</div>
                        <div class="score">{{ result.demo_metrics.buyer_demo_strength }}%</div>
                        <p>{{ result.closing_pitch.headline }}</p>
                        <p>{{ result.closing_pitch.message }}</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Demo Strength Metrics</h2>
                <div class="grid-4">
                    <div class="metric"><strong>{{ result.demo_metrics.product_readiness_score }}%</strong><span>Product Readiness</span><div class="bar"><span style="width: {{ result.demo_metrics.product_readiness_score }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.demo_metrics.radiopharma_specificity }}%</strong><span>Radiopharma Specificity</span><div class="bar"><span style="width: {{ result.demo_metrics.radiopharma_specificity }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.demo_metrics.inspection_value }}%</strong><span>Inspection Value</span><div class="bar"><span style="width: {{ result.demo_metrics.inspection_value }}%;"></span></div></div>
                    <div class="metric"><strong>{{ result.demo_metrics.differentiation_score }}%</strong><span>Differentiation Score</span><div class="bar"><span style="width: {{ result.demo_metrics.differentiation_score }}%;"></span></div></div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">12-Step Buyer Demo Story</div>
                    <h2>How to Demo RLTTrust™ to Radiopharma Leadership</h2>
                    <div class="demo-flow">
                        {% for scene in result.demo_storyline %}
                        <div class="scene-card">
                            <div class="eyebrow">{{ scene.scene }}</div>
                            <h3>{{ scene.buyer_question }}</h3>
                            <p><strong style="color:#fff2e6;">Show:</strong> {{ scene.what_to_show }}</p>
                            <p><strong style="color:#ffd7ad;">Wow Line:</strong> {{ scene.wow_line }}</p>
                            <a class="route-link" href="{{ scene.demo_route }}">Open Demo Page</a>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Major Buyer Pain Points Solved</h2>
                <div class="grid-3">
                    {% for pain in result.buyer_pain_points %}
                    <div class="card">
                        <h3>{{ pain.pain }}</h3>
                        <p><strong style="color:#fff2e6;">Current State:</strong> {{ pain.current_state }}</p>
                        <p><strong style="color:#fff2e6;">RLTTrust™ Answer:</strong> {{ pain.rlttrust_answer }}</p>
                        <p><strong style="color:#ffd7ad;">Executive Value:</strong> {{ pain.executive_value }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Buyer Personas</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Persona</th>
                                <th>Cares About</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for persona in result.buyer_personas %}
                            <tr>
                                <td><strong>{{ persona.persona }}</strong></td>
                                <td>{{ persona.cares_about }}</td>
                                <td>{{ persona.message }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Business Case</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Value Driver</th>
                                <th>Why It Matters</th>
                                <th>Proof Point</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for value in result.business_case %}
                            <tr>
                                <td><strong>{{ value.value_driver }}</strong></td>
                                <td>{{ value.why_it_matters }}</td>
                                <td>{{ value.proof_point }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Product Modules in the Buyer Demo</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Module</th>
                                <th>Buyer Value</th>
                                <th>Route</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for module in result.product_modules %}
                            <tr>
                                <td><strong>{{ module.module }}</strong></td>
                                <td>{{ module.buyer_value }}</td>
                                <td><a class="route-link" href="{{ module.route }}">Open</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Common Buyer Objections</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Objection</th>
                                <th>Response</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for objection in result.buyer_objections %}
                            <tr>
                                <td><strong>{{ objection.objection }}</strong></td>
                                <td>{{ objection.response }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Strongest Pilot Offer</h2>
                    <p>{{ result.closing_pitch.pilot_offer }}</p>
                    <div class="note">
                        <strong>Recommended Pilot:</strong> {{ result.closing_pitch.strongest_pilot }}
                    </div>

                    <h3 style="margin-top:24px;">Systems RLTTrust™ Does Not Replace</h3>
                    {% for item in result.product_positioning.not_replacing %}
                    <span class="pill">{{ item }}</span>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Closing Buyer Message</h2>
                    <p style="font-size:20px; color:#fff2e6;">{{ result.closing_pitch.headline }}</p>
                    <p>{{ result.closing_pitch.message }}</p>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/buyer-demo/api")
@app.route("/rlttrust/buyer-demo/api")
@app.route("/rlttrust/executive-buyer-demo/api")
def rlttrust_executive_buyer_demo_mode_api():
    return jsonify(_rlttrust_executive_buyer_demo_data())

# ============================================================
# End Executive Buyer Demo Mode™
# ============================================================

'''

    # Add Executive Buyer Demo link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_EXECUTIVE_BUYER_DEMO_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_EXECUTIVE_BUYER_DEMO_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>',
            1
        )
        print("Added Executive Buyer Demo Mode link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Executive Buyer Demo Mode successfully.")

