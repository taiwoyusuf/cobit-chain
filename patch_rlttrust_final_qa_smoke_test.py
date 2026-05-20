from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_FINAL_QA_SMOKE_TEST_ROUTE_VERIFICATION_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Final QA Smoke Test & Route Verification already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_FINAL_QA_SMOKE_TEST_ROUTE_VERIFICATION_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Final QA Smoke Test & Route Verification
# Purpose: Verify RLTTrust™ pages, API endpoints, demo flow, commercial package,
#          launchpad, executive summary, and product inventory before demo use.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, current_app
from datetime import datetime

def _rlttrust_final_qa_route_exists(route):
    try:
        return any(str(rule.rule) == route for rule in current_app.url_map.iter_rules())
    except Exception:
        return False


def _rlttrust_final_qa_smoke_test_data():
    pages = [
        {
            "order": 1,
            "module": "Executive Summary One-Page View™",
            "route": "/irlt-commercial-readiness/executive-summary",
            "api": "/irlt-commercial-readiness/executive-summary/api",
            "category": "Boardroom / Executive",
            "criticality": "Critical",
            "demo_role": "Start here for the one-screen product explanation."
        },
        {
            "order": 2,
            "module": "RLTTrust™ Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "api": "/irlt-commercial-readiness/launchpad/api",
            "category": "Product Home",
            "criticality": "Critical",
            "demo_role": "Use as the unified product navigation hub."
        },
        {
            "order": 3,
            "module": "Final Commercial Packaging Layer™",
            "route": "/irlt-commercial-readiness/commercial-package",
            "api": "/irlt-commercial-readiness/commercial-package/api",
            "category": "Commercial Packaging",
            "criticality": "Critical",
            "demo_role": "Use as the brochure-style buyer/product page."
        },
        {
            "order": 4,
            "module": "Buyer Demo Flow™ / Navigation Hardening",
            "route": "/irlt-commercial-readiness/demo-flow",
            "api": "/irlt-commercial-readiness/demo-flow/api",
            "category": "Demo Control",
            "criticality": "Critical",
            "demo_role": "Use to run the demo in the right order."
        },
        {
            "order": 5,
            "module": "Executive Buyer Demo Mode™",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "api": "/irlt-commercial-readiness/buyer-demo/api",
            "category": "Buyer Story",
            "criticality": "Critical",
            "demo_role": "Use to explain buyer pain, value, objections, and pilot story."
        },
        {
            "order": 6,
            "module": "Pilot Readiness & ROI Justification Engine™",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "api": "/irlt-commercial-readiness/pilot-roi/api",
            "category": "Pilot / ROI",
            "criticality": "Critical",
            "demo_role": "Use to close with pilot scope, ROI, and buyer justification."
        },
        {
            "order": 7,
            "module": "IRLT Commercial Readiness Command Center™",
            "route": "/irlt-commercial-readiness",
            "api": None,
            "category": "Executive Cockpit",
            "criticality": "Critical",
            "demo_role": "Use as the main readiness cockpit."
        },
        {
            "order": 8,
            "module": "Can We Treat Tomorrow? Engine™",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "api": "/irlt-commercial-readiness/can-we-treat-tomorrow/api",
            "category": "Treatment Readiness",
            "criticality": "High",
            "demo_role": "Use to show time-sensitive treatment readiness."
        },
        {
            "order": 9,
            "module": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "api": "/irlt-commercial-readiness/isotope-to-patient/api",
            "category": "Dose Journey Traceability",
            "criticality": "High",
            "demo_role": "Use to prove end-to-end radiopharma traceability."
        },
        {
            "order": 10,
            "module": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "api": "/irlt-commercial-readiness/radioactive-material-ledger/api",
            "category": "Radiopharma-Specific Governance",
            "criticality": "High",
            "demo_role": "Use as the strongest radiopharma-specific differentiator."
        },
        {
            "order": 11,
            "module": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "api": "/irlt-commercial-readiness/release-defensibility/api",
            "category": "QA Release Assurance",
            "criticality": "High",
            "demo_role": "Use to show QA release defensibility."
        },
        {
            "order": 12,
            "module": "Inspection Tomorrow Simulator™",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "api": "/irlt-commercial-readiness/inspection-tomorrow/api",
            "category": "Inspection Survivability",
            "criticality": "High",
            "demo_role": "Use to show inspection exposure before the inspector does."
        },
        {
            "order": 13,
            "module": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "api": "/irlt-commercial-readiness/auditor-question-evidence/api",
            "category": "Audit Response",
            "criticality": "High",
            "demo_role": "Use to map inspection questions to evidence packets."
        },
        {
            "order": 14,
            "module": "Governance Black Box Recorder™",
            "route": "/irlt-commercial-readiness/governance-black-box",
            "api": "/irlt-commercial-readiness/governance-black-box/api",
            "category": "Governance Memory",
            "criticality": "High",
            "demo_role": "Use to prove human-controlled AI and decision lineage."
        },
        {
            "order": 15,
            "module": "Patient Slot Protection Engine™",
            "route": "/irlt-commercial-readiness/patient-slot-protection",
            "api": "/irlt-commercial-readiness/patient-slot-protection/api",
            "category": "Patient-Impact Governance",
            "criticality": "High",
            "demo_role": "Use to connect operations to treatment-window protection."
        },
        {
            "order": 16,
            "module": "Cross-Site RLT Network Readiness Mesh™",
            "route": "/irlt-commercial-readiness/network-readiness-mesh",
            "api": "/irlt-commercial-readiness/network-readiness-mesh/api",
            "category": "Commercial Scale-Up",
            "criticality": "Medium",
            "demo_role": "Use for enterprise/multi-site scale-up buyers."
        },
        {
            "order": 17,
            "module": "Commercialization Stress Test Simulator™",
            "route": "/irlt-commercial-readiness/commercialization-stress-test",
            "api": "/irlt-commercial-readiness/commercialization-stress-test/api",
            "category": "What-If Failure Lab",
            "criticality": "Medium",
            "demo_role": "Use to show readiness under disruption."
        },
        {
            "order": 18,
            "module": "Executive IRLT Governance Passport Factory™",
            "route": "/irlt-commercial-readiness/passport-factory",
            "api": "/irlt-commercial-readiness/passport-factory/api",
            "category": "Executive Artifacts",
            "criticality": "Critical",
            "demo_role": "Use to generate executive and inspection-ready passports."
        },
        {
            "order": 19,
            "module": "Routes Health API",
            "route": "/irlt-commercial-readiness/routes-health/api",
            "api": "/irlt-commercial-readiness/routes-health/api",
            "category": "QA / Health Check",
            "criticality": "Medium",
            "demo_role": "Use to verify route registration."
        },
        {
            "order": 20,
            "module": "Final QA Smoke Test & Route Verification",
            "route": "/irlt-commercial-readiness/final-qa",
            "api": "/irlt-commercial-readiness/final-qa/api",
            "category": "Final Verification",
            "criticality": "Critical",
            "demo_role": "Use before showing the platform to leadership or buyers."
        }
    ]

    checked_pages = []
    for page in pages:
        route_exists = _rlttrust_final_qa_route_exists(page["route"])
        api_exists = True if not page["api"] else _rlttrust_final_qa_route_exists(page["api"])

        if route_exists and api_exists:
            health = "Pass"
            health_class = "pass"
            action = "Ready for demo."
        elif route_exists and not api_exists:
            health = "Page OK / API Check"
            health_class = "warn"
            action = "Page exists, but API route should be checked if needed."
        else:
            health = "Check Route"
            health_class = "fail"
            action = "Route may be missing or previous patch may not have been applied."

        enriched = dict(page)
        enriched["route_exists"] = route_exists
        enriched["api_exists"] = api_exists
        enriched["health"] = health
        enriched["health_class"] = health_class
        enriched["action"] = action
        checked_pages.append(enriched)

    total = len(checked_pages)
    pass_count = sum(1 for item in checked_pages if item["health_class"] == "pass")
    warn_count = sum(1 for item in checked_pages if item["health_class"] == "warn")
    fail_count = sum(1 for item in checked_pages if item["health_class"] == "fail")
    readiness_percent = round((pass_count / total) * 100) if total else 0

    if fail_count == 0 and warn_count == 0:
        verdict = "DEMO READY"
        verdict_class = "ready"
        executive_answer = "All expected RLTTrust™ routes and APIs are registered. The platform is ready for internal or buyer-facing demonstration."
    elif fail_count == 0:
        verdict = "DEMO READY WITH API WARNINGS"
        verdict_class = "warning"
        executive_answer = "All main pages are available, but some API routes should be checked if the demo will include API output."
    elif fail_count <= 2:
        verdict = "MOSTLY READY — CHECK MISSING ROUTES"
        verdict_class = "gap"
        executive_answer = "The platform is mostly ready, but missing routes should be corrected before a polished buyer demo."
    else:
        verdict = "NOT DEMO READY"
        verdict_class = "blocked"
        executive_answer = "Several expected routes are missing. Run the missing patches or review route names before demo use."

    final_inventory = [
        "Executive Summary One-Page View™",
        "Product Launchpad",
        "Final Commercial Packaging Layer™",
        "Buyer Demo Flow™",
        "Executive Buyer Demo Mode™",
        "Pilot Readiness & ROI Justification Engine™",
        "IRLT Commercial Readiness Command Center™",
        "Can We Treat Tomorrow? Engine™",
        "Isotope-to-Patient Evidence Graph™",
        "Radioactive Material Accountability Ledger™",
        "Release Defensibility Engine™",
        "Inspection Tomorrow Simulator™",
        "Auditor Question-to-Evidence Engine™",
        "Governance Black Box Recorder™",
        "Patient Slot Protection Engine™",
        "Cross-Site RLT Network Readiness Mesh™",
        "Commercialization Stress Test Simulator™",
        "Executive IRLT Governance Passport Factory™",
        "Route Health API",
        "Final QA Smoke Test & Route Verification"
    ]

    recommended_demo_order = [
        {
            "step": 1,
            "page": "Executive Summary One-Page View™",
            "route": "/irlt-commercial-readiness/executive-summary",
            "reason": "Give the boardroom explanation first."
        },
        {
            "step": 2,
            "page": "Commercial Package",
            "route": "/irlt-commercial-readiness/commercial-package",
            "reason": "Show the market problem, solution, buyers, differentiators, and pilot offer."
        },
        {
            "step": 3,
            "page": "Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "reason": "Show that this is now one unified product."
        },
        {
            "step": 4,
            "page": "Buyer Demo",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "reason": "Tell the buyer story."
        },
        {
            "step": 5,
            "page": "Command Center",
            "route": "/irlt-commercial-readiness",
            "reason": "Show the executive cockpit."
        },
        {
            "step": 6,
            "page": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "reason": "Show end-to-end dose journey governance."
        },
        {
            "step": 7,
            "page": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "reason": "Show radiopharma-specific accountability."
        },
        {
            "step": 8,
            "page": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "reason": "Show QA release defensibility."
        },
        {
            "step": 9,
            "page": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "reason": "Show audit response power."
        },
        {
            "step": 10,
            "page": "Passport Factory",
            "route": "/irlt-commercial-readiness/passport-factory",
            "reason": "Show executive artifacts."
        },
        {
            "step": 11,
            "page": "Pilot ROI",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "reason": "Close with a focused pilot proposal."
        }
    ]

    demo_risks = []
    for item in checked_pages:
        if item["health_class"] == "fail":
            demo_risks.append({
                "risk": item["module"] + " route may be missing.",
                "route": item["route"],
                "action": item["action"]
            })
        elif item["health_class"] == "warn":
            demo_risks.append({
                "risk": item["module"] + " API route may need checking.",
                "route": item["api"],
                "action": item["action"]
            })

    if not demo_risks:
        demo_risks.append({
            "risk": "No route-level demo blockers detected.",
            "route": "All expected routes checked.",
            "action": "Proceed with buyer demo flow."
        })

    qa_checklist = [
        "Open Executive Summary and confirm it renders full width.",
        "Open Commercial Package and confirm product story reads like a brochure.",
        "Open Product Launchpad and confirm all important modules are visible.",
        "Open Demo Flow and confirm recommended demo paths are clear.",
        "Open Route Health API and confirm expected routes are available.",
        "Open Isotope-to-Patient, Material Ledger, Release Defensibility, and Auditor Evidence pages before any serious buyer demo.",
        "Do not present AI as an approver. Say AI is advisory only.",
        "Close every demo with Passport Factory and Pilot ROI.",
        "Use one pilot story: one site, one dose journey, one release pathway, one evidence pack.",
        "Keep repeating that RLTTrust™ is an overlay, not a replacement for existing systems."
    ]

    product_positioning = {
        "product": "RLTTrust™ / IRLT Commercial Readiness Governance Command Center™",
        "platform": "COBIT-Chain™ / AssuranceLayer™ Platform A",
        "core_message": "Governed evidence and operational trust overlay for commercial IRLT scale-up.",
        "not_replacing": "Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics platforms, treatment scheduling, or manufacturing execution systems.",
        "strongest_pilot": "Release Defensibility + Isotope-to-Patient Evidence Graph + Radioactive Material Accountability Ledger + Auditor Question-to-Evidence + Passport Factory + Pilot ROI."
    }

    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "verdict": verdict,
        "verdict_class": verdict_class,
        "executive_answer": executive_answer,
        "readiness_percent": readiness_percent,
        "total_routes_checked": total,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "checked_pages": checked_pages,
        "final_inventory": final_inventory,
        "recommended_demo_order": recommended_demo_order,
        "demo_risks": demo_risks,
        "qa_checklist": qa_checklist,
        "product_positioning": product_positioning,
        "governance_note": "Final QA Smoke Test & Route Verification checks expected Flask route registration. It does not replace functional validation, regulated QA validation, cybersecurity review, privacy review, or production release governance."
    }


@app.route("/irlt-commercial-readiness/final-qa")
@app.route("/irlt-commercial-readiness/final-smoke-test")
@app.route("/rlttrust/final-qa")
def rlttrust_final_qa_smoke_test_route_verification():
    result = _rlttrust_final_qa_smoke_test_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Final QA Smoke Test & Route Verification | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
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

            .pass {
                color: #b9ffd0;
                border-color: rgba(55,214,122,0.45);
                background: rgba(55,214,122,0.12);
            }

            .warn {
                color: #ffe6a8;
                border-color: rgba(255,209,102,0.45);
                background: rgba(255,209,102,0.12);
            }

            .fail {
                color: #ffc2c2;
                border-color: rgba(255,92,122,0.45);
                background: rgba(255,92,122,0.12);
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

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-4 {
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
                        <div class="eyebrow">RLTTrust™ Final Verification Layer</div>
                        <h1>Final QA Smoke Test & Route Verification</h1>
                        <p class="hero-line">
                            One final verification page for RLTTrust™ routes, APIs, product inventory, demo flow,
                            and buyer presentation readiness.
                        </p>
                        <p>{{ result.executive_answer }}</p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>
                            <a href="/irlt-commercial-readiness/commercial-package">Commercial Package</a>
                            <a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>
                            <a href="/irlt-commercial-readiness/demo-flow">Demo Flow</a>
                            <a href="/irlt-commercial-readiness/final-qa/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Route Readiness</div>
                        <div class="score">{{ result.readiness_percent }}%</div>
                        <span class="decision {{ result.verdict_class }}">{{ result.verdict }}</span>
                        <p>Generated: {{ result.generated_at }}</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="grid-4">
                    <div class="metric"><strong>{{ result.total_routes_checked }}</strong><span>Total Checks</span></div>
                    <div class="metric"><strong>{{ result.pass_count }}</strong><span>Passed</span></div>
                    <div class="metric"><strong>{{ result.warn_count }}</strong><span>Warnings</span></div>
                    <div class="metric"><strong>{{ result.fail_count }}</strong><span>Needs Check</span></div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Route Verification Table</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Module</th>
                                <th>Category</th>
                                <th>Page Route</th>
                                <th>API Route</th>
                                <th>Health</th>
                                <th>Demo Role</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.checked_pages %}
                            <tr>
                                <td>{{ item.order }}</td>
                                <td><strong>{{ item.module }}</strong></td>
                                <td>{{ item.category }}</td>
                                <td><a class="open-link" href="{{ item.route }}">Open Page</a></td>
                                <td>
                                    {% if item.api %}
                                    <a class="open-link" href="{{ item.api }}">Open API</a>
                                    {% else %}
                                    <span class="pill">No API expected</span>
                                    {% endif %}
                                </td>
                                <td><span class="pill {{ item.health_class }}">{{ item.health }}</span></td>
                                <td>{{ item.demo_role }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Recommended Demo Order</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Step</th>
                                <th>Page</th>
                                <th>Reason</th>
                                <th>Open</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for step in result.recommended_demo_order %}
                            <tr>
                                <td>{{ step.step }}</td>
                                <td><strong>{{ step.page }}</strong></td>
                                <td>{{ step.reason }}</td>
                                <td><a class="open-link" href="{{ step.route }}">Open</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>QA Checklist Before Demo</h2>
                    <ul>
                        {% for item in result.qa_checklist %}
                        <li>{{ item }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Demo Risks / Actions</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Risk</th>
                                <th>Route</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for risk in result.demo_risks %}
                            <tr>
                                <td><strong>{{ risk.risk }}</strong></td>
                                <td>{{ risk.route }}</td>
                                <td>{{ risk.action }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Final Product Inventory</h2>
                    {% for item in result.final_inventory %}
                    <span class="pill">{{ item }}</span>
                    {% endfor %}

                    <h3 style="margin-top:22px;">Product Positioning</h3>
                    <p><strong style="color:#fff2e6;">Product:</strong> {{ result.product_positioning.product }}</p>
                    <p><strong style="color:#fff2e6;">Core Message:</strong> {{ result.product_positioning.core_message }}</p>
                    <p><strong style="color:#fff2e6;">Not Replacing:</strong> {{ result.product_positioning.not_replacing }}</p>
                    <div class="note"><strong>Strongest Pilot:</strong> {{ result.product_positioning.strongest_pilot }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/final-qa/api")
@app.route("/irlt-commercial-readiness/final-smoke-test/api")
@app.route("/rlttrust/final-qa/api")
def rlttrust_final_qa_smoke_test_route_verification_api():
    return jsonify(_rlttrust_final_qa_smoke_test_data())

# ============================================================
# End Final QA Smoke Test & Route Verification
# ============================================================

'''

    # Add Final QA link to navigation where Commercial Package exists.
    nav_marker = "RLTTRUST_NAV_FINAL_QA_SMOKE_TEST_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/commercial-package">Commercial Package</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_FINAL_QA_SMOKE_TEST_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/final-qa">Final QA</a>',
            1
        )
        print("Added Final QA link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Final QA Smoke Test & Route Verification successfully.")

