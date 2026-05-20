from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_PRODUCT_POLISH_NAVIGATION_HARDENING_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Product Polish & Navigation Hardening already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_PRODUCT_POLISH_NAVIGATION_HARDENING_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Product Polish & Navigation Hardening
# Purpose: Add a polished buyer demo flow, route checklist, navigation order,
#          and presentation-safe launch structure for RLTTrust™.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, current_app

def _rlttrust_navigation_hardening_data():
    canonical_routes = [
        {
            "order": 1,
            "title": "Executive Summary One-Page View™",
            "route": "/irlt-commercial-readiness/executive-summary",
            "category": "Boardroom Start",
            "purpose": "One-screen executive summary for screenshots, leadership pitching, and quick explanation.",
            "demo_use": "Start here when the audience has only two minutes."
        },
        {
            "order": 2,
            "title": "RLTTrust™ Product Launchpad",
            "route": "/irlt-commercial-readiness/launchpad",
            "category": "Unified Product Home",
            "purpose": "Main navigation home for all RLTTrust™ modules.",
            "demo_use": "Use this as the central product menu."
        },
        {
            "order": 3,
            "title": "Executive Buyer Demo Mode™",
            "route": "/irlt-commercial-readiness/buyer-demo",
            "category": "Commercial Story",
            "purpose": "Buyer-facing story showing pain points, personas, modules, value, and objections.",
            "demo_use": "Use this to explain why a radiopharma buyer should care."
        },
        {
            "order": 4,
            "title": "IRLT Commercial Readiness Command Center™",
            "route": "/irlt-commercial-readiness",
            "category": "Executive Cockpit",
            "purpose": "Core readiness cockpit for commercialization readiness and operational trust.",
            "demo_use": "Use this to show the main command center."
        },
        {
            "order": 5,
            "title": "Can We Treat Tomorrow? Engine™",
            "route": "/irlt-commercial-readiness/can-we-treat-tomorrow",
            "category": "Treatment Readiness",
            "purpose": "Shows whether tomorrow treatment readiness is defensible.",
            "demo_use": "Use this to show time-sensitive IRLT readiness."
        },
        {
            "order": 6,
            "title": "Isotope-to-Patient Evidence Graph™",
            "route": "/irlt-commercial-readiness/isotope-to-patient",
            "category": "Dose Journey",
            "purpose": "Maps isotope source, manufacturing, QC, QA release, shipment, receipt, and treatment readiness.",
            "demo_use": "Use this to show radiopharma-specific traceability."
        },
        {
            "order": 7,
            "title": "Radioactive Material Accountability Ledger™",
            "route": "/irlt-commercial-readiness/radioactive-material-ledger",
            "category": "Material Accountability",
            "purpose": "Shows receipt, use, transfer, decay, waste, disposal, residual, and reconciliation governance.",
            "demo_use": "Use this as the strongest radiopharma-specific differentiator."
        },
        {
            "order": 8,
            "title": "Release Defensibility Engine™",
            "route": "/irlt-commercial-readiness/release-defensibility",
            "category": "QA Release",
            "purpose": "Shows whether QA can defend release with governed evidence.",
            "demo_use": "Use this for QA, compliance, and release leadership."
        },
        {
            "order": 9,
            "title": "Inspection Tomorrow Simulator™",
            "route": "/irlt-commercial-readiness/inspection-tomorrow",
            "category": "Inspection Survivability",
            "purpose": "Shows what would fail if inspection happened tomorrow.",
            "demo_use": "Use this to create urgency."
        },
        {
            "order": 10,
            "title": "Auditor Question-to-Evidence Engine™",
            "route": "/irlt-commercial-readiness/auditor-question-evidence",
            "category": "Audit Response",
            "purpose": "Maps auditor questions to evidence packets, owners, gaps, source engines, and passports.",
            "demo_use": "Use this to show inspection response speed."
        },
        {
            "order": 11,
            "title": "Governance Black Box Recorder™",
            "route": "/irlt-commercial-readiness/governance-black-box",
            "category": "Governance Memory",
            "purpose": "Records readiness events, AI advisories, human decisions, and evidence lineage.",
            "demo_use": "Use this to prove human-controlled AI and inspection-survivable timeline."
        },
        {
            "order": 12,
            "title": "Patient Slot Protection Engine™",
            "route": "/irlt-commercial-readiness/patient-slot-protection",
            "category": "Patient-Impact Governance",
            "purpose": "Protects dose-to-treatment-slot readiness without storing PHI.",
            "demo_use": "Use this to connect operations to patient-impact readiness."
        },
        {
            "order": 13,
            "title": "Cross-Site RLT Network Readiness Mesh™",
            "route": "/irlt-commercial-readiness/network-readiness-mesh",
            "category": "Commercial Scale-Up",
            "purpose": "Assesses readiness across sites, QC/QA lanes, hot cells, isotope supply, couriers, treatment hubs, and fallback capacity.",
            "demo_use": "Use this for enterprise-scale buyers."
        },
        {
            "order": 14,
            "title": "Commercialization Stress Test Simulator™",
            "route": "/irlt-commercial-readiness/commercialization-stress-test",
            "category": "What-If Failure Lab",
            "purpose": "Stress-tests QC delay, QA delay, hot-cell outage, isotope delay, courier failure, evidence loss, and hub constraints.",
            "demo_use": "Use this to show readiness under commercial pressure."
        },
        {
            "order": 15,
            "title": "Executive IRLT Governance Passport Factory™",
            "route": "/irlt-commercial-readiness/passport-factory",
            "category": "Executive Artifacts",
            "purpose": "Generates executive and inspection-ready passports.",
            "demo_use": "Use this to show final leadership artifacts."
        },
        {
            "order": 16,
            "title": "Pilot Readiness & ROI Justification Engine™",
            "route": "/irlt-commercial-readiness/pilot-roi",
            "category": "Pilot Proposal",
            "purpose": "Creates pilot scope, phases, success metrics, evidence inputs, ROI, and expansion path.",
            "demo_use": "Use this to close the pitch with a pilot ask."
        },
        {
            "order": 17,
            "title": "Buyer Demo Flow™",
            "route": "/irlt-commercial-readiness/demo-flow",
            "category": "Navigation Hardening",
            "purpose": "Polished guided demo flow and route checklist.",
            "demo_use": "Use this page to run the full demo safely."
        }
    ]

    demo_paths = [
        {
            "name": "Fast Executive Demo",
            "duration": "7–10 minutes",
            "best_for": "Site head, commercialization leader, radiopharma executive, investor-style conversation.",
            "steps": [
                "Executive Summary One-Page View™",
                "Product Launchpad",
                "Executive Buyer Demo Mode™",
                "Command Center",
                "Passport Factory",
                "Pilot ROI"
            ],
            "message": "RLTTrust™ is a commercial readiness assurance layer that turns scattered readiness into executive-defensible evidence."
        },
        {
            "name": "QA / Compliance Demo",
            "duration": "12–15 minutes",
            "best_for": "QA, compliance, internal audit, release governance, inspection readiness.",
            "steps": [
                "Release Defensibility Engine™",
                "Inspection Tomorrow Simulator™",
                "Auditor Question-to-Evidence Engine™",
                "Governance Black Box Recorder™",
                "Executive Passport Factory™"
            ],
            "message": "RLTTrust™ helps QA defend release, inspection response, evidence integrity, and human approval lineage."
        },
        {
            "name": "Radiopharma Operations Demo",
            "duration": "12–15 minutes",
            "best_for": "Operations, radiation safety, supply chain, treatment coordination, nuclear medicine operations.",
            "steps": [
                "Can We Treat Tomorrow? Engine™",
                "Isotope-to-Patient Evidence Graph™",
                "Radioactive Material Accountability Ledger™",
                "Patient Slot Protection Engine™",
                "Commercialization Stress Test Simulator™"
            ],
            "message": "RLTTrust™ governs the time-sensitive, material-sensitive, and patient-impact realities of IRLT operations."
        },
        {
            "name": "Enterprise Scale-Up Demo",
            "duration": "15–20 minutes",
            "best_for": "Large radiopharma companies, multi-site programs, commercial launch teams.",
            "steps": [
                "Command Center",
                "Network Readiness Mesh™",
                "Commercialization Stress Test Simulator™",
                "Governance Black Box Recorder™",
                "Pilot ROI"
            ],
            "message": "RLTTrust™ gives leadership a way to test whether commercial scale-up is operationally defensible."
        },
        {
            "name": "Pilot Close Demo",
            "duration": "10 minutes",
            "best_for": "Buyer decision meeting or pilot approval meeting.",
            "steps": [
                "Executive Buyer Demo Mode™",
                "Release Defensibility Engine™",
                "Isotope-to-Patient Evidence Graph™",
                "Radioactive Material Accountability Ledger™",
                "Passport Factory",
                "Pilot ROI"
            ],
            "message": "Start small: one site, one dose journey, one release pathway, one evidence pack, measurable pilot value."
        }
    ]

    route_groups = [
        {
            "group": "Start Here",
            "routes": [
                "/irlt-commercial-readiness/executive-summary",
                "/irlt-commercial-readiness/launchpad",
                "/irlt-commercial-readiness/buyer-demo"
            ]
        },
        {
            "group": "Core Operational Demo",
            "routes": [
                "/irlt-commercial-readiness",
                "/irlt-commercial-readiness/can-we-treat-tomorrow",
                "/irlt-commercial-readiness/isotope-to-patient",
                "/irlt-commercial-readiness/radioactive-material-ledger",
                "/irlt-commercial-readiness/release-defensibility"
            ]
        },
        {
            "group": "Inspection and Governance Demo",
            "routes": [
                "/irlt-commercial-readiness/inspection-tomorrow",
                "/irlt-commercial-readiness/auditor-question-evidence",
                "/irlt-commercial-readiness/governance-black-box",
                "/irlt-commercial-readiness/passport-factory"
            ]
        },
        {
            "group": "Scale-Up and Commercial Demo",
            "routes": [
                "/irlt-commercial-readiness/patient-slot-protection",
                "/irlt-commercial-readiness/network-readiness-mesh",
                "/irlt-commercial-readiness/commercialization-stress-test",
                "/irlt-commercial-readiness/pilot-roi"
            ]
        }
    ]

    presentation_rules = [
        "Start with the business pain before showing technical detail.",
        "Keep saying RLTTrust™ is an overlay, not a replacement for Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics, or scheduling systems.",
        "Do not claim AI approves anything. AI is advisory only.",
        "Always connect a score to evidence, owner, risk, and passport output.",
        "Use Radioactive Material Ledger™, Isotope-to-Patient Graph™, and Patient Slot Protection™ to prove radiopharma specificity.",
        "Use Release Defensibility™, Auditor Evidence™, and Black Box Recorder™ to prove QA/compliance value.",
        "Use Passport Factory™ and Pilot ROI™ to close the buyer conversation."
    ]

    buyer_pitch_order = [
        {
            "sequence": "Open",
            "line": "RLTTrust™ helps radiopharma leadership defend commercial readiness with governed evidence."
        },
        {
            "sequence": "Pain",
            "line": "Readiness is usually scattered across QC, QA, manufacturing, radiation safety, supply chain, treatment coordination, and compliance."
        },
        {
            "sequence": "Difference",
            "line": "RLTTrust™ does not replace existing systems. It overlays them with operational trust scoring, evidence lineage, and inspection-ready passports."
        },
        {
            "sequence": "Radiopharma Specificity",
            "line": "The product is built around isotope timing, dose journey traceability, radioactive material accountability, release defensibility, custody, and patient-slot protection."
        },
        {
            "sequence": "Governance",
            "line": "AI is advisory only. Human QA, compliance, radiation safety, clinical, and operations authority remains authoritative."
        },
        {
            "sequence": "Pilot",
            "line": "The first pilot should focus on one site, one dose journey, one release pathway, and one evidence pack."
        }
    ]

    product_status = {
        "modules_ready": len(canonical_routes),
        "demo_paths_ready": len(demo_paths),
        "route_groups_ready": len(route_groups),
        "recommended_start": "/irlt-commercial-readiness/executive-summary",
        "recommended_home": "/irlt-commercial-readiness/launchpad",
        "recommended_close": "/irlt-commercial-readiness/pilot-roi",
        "platform_story": "Commercial IRLT readiness, release defensibility, isotope-to-patient traceability, material accountability, inspection survivability, patient-slot protection, and executive passports."
    }

    return {
        "canonical_routes": canonical_routes,
        "demo_paths": demo_paths,
        "route_groups": route_groups,
        "presentation_rules": presentation_rules,
        "buyer_pitch_order": buyer_pitch_order,
        "product_status": product_status,
        "governance_note": "Product Polish & Navigation Hardening is a demonstration and navigation layer. AI remains advisory only. Human governance remains authoritative."
    }


def _rlttrust_route_exists(route):
    try:
        return any(str(rule.rule) == route for rule in current_app.url_map.iter_rules())
    except Exception:
        return False


@app.route("/irlt-commercial-readiness/demo-flow")
@app.route("/irlt-commercial-readiness/navigation")
@app.route("/rlttrust/demo-flow")
def rlttrust_product_polish_demo_flow():
    result = _rlttrust_navigation_hardening_data()

    checked_routes = []
    for item in result["canonical_routes"]:
        exists = _rlttrust_route_exists(item["route"])
        enriched = dict(item)
        enriched["exists"] = exists
        enriched["health"] = "Available" if exists else "Check Route"
        checked_routes.append(enriched)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Buyer Demo Flow™ | RLTTrust™</title>
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
                    linear-gradient(135deg, rgba(255,122,24,0.23), rgba(20,24,33,0.94) 39%, rgba(7,8,12,0.97)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.026) 0 1px, transparent 1px 76px);
                box-shadow: 0 38px 130px rgba(0,0,0,0.58);
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

            .score-card, .panel, .card, .route-card, .path-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .big {
                font-size: clamp(70px, 7vw, 130px);
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

            .path-flow {
                display: grid;
                grid-template-columns: repeat(5, minmax(320px, 1fr));
                gap: 16px;
                overflow-x: auto;
                padding-bottom: 10px;
            }

            .route-grid {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 16px;
            }

            .route-card {
                min-height: 250px;
            }

            .route-number {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 44px;
                height: 44px;
                border-radius: 16px;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                font-weight: 950;
                margin-bottom: 14px;
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

            .health-ok {
                color: #b9ffd0;
                border-color: rgba(55,214,122,0.45);
                background: rgba(55,214,122,0.12);
            }

            .health-check {
                color: #ffc2c2;
                border-color: rgba(255,92,122,0.45);
                background: rgba(255,92,122,0.12);
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

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-3, .route-grid {
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
                        <div class="eyebrow">RLTTrust™ Navigation Hardening</div>
                        <h1>Buyer Demo Flow™</h1>
                        <p>
                            A polished presentation-safe route for running RLTTrust™ demos without jumping randomly between modules.
                            Use this page to choose the right demo path for executives, QA, operations, enterprise scale-up, or pilot approval.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>
                            <a href="/irlt-commercial-readiness/launchpad">Product Launchpad</a>
                            <a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>
                            <a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>
                            <a href="/irlt-commercial-readiness/demo-flow/api">API Output</a>
                            <a href="/irlt-commercial-readiness/routes-health/api">Route Health API</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Presentation Readiness</div>
                        <div class="big">{{ result.product_status.modules_ready }}</div>
                        <p>Core modules are organized into a buyer-ready route order.</p>
                        <div class="note">{{ result.product_status.platform_story }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <h2>Recommended Demo Paths</h2>
                <div class="path-flow">
                    {% for path in result.demo_paths %}
                    <div class="path-card">
                        <div class="eyebrow">{{ path.duration }}</div>
                        <h3>{{ path.name }}</h3>
                        <p><strong style="color:#fff2e6;">Best For:</strong> {{ path.best_for }}</p>
                        <p>{{ path.message }}</p>
                        {% for step in path.steps %}
                        <span class="pill">{{ step }}</span>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Buyer Pitch Order</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Sequence</th>
                                <th>Line</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.buyer_pitch_order %}
                            <tr>
                                <td><strong>{{ item.sequence }}</strong></td>
                                <td>{{ item.line }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Presentation Rules</h2>
                    <ul>
                        {% for rule in result.presentation_rules %}
                        <li>{{ rule }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section">
                <h2>Canonical Route Order</h2>
                <div class="route-grid">
                    {% for route in checked_routes %}
                    <div class="route-card">
                        <div class="route-number">{{ route.order }}</div>
                        <h3>{{ route.title }}</h3>
                        <span class="pill">{{ route.category }}</span>
                        {% if route.exists %}
                        <span class="pill health-ok">{{ route.health }}</span>
                        {% else %}
                        <span class="pill health-check">{{ route.health }}</span>
                        {% endif %}
                        <p><strong style="color:#fff2e6;">Purpose:</strong> {{ route.purpose }}</p>
                        <p><strong style="color:#ffd7ad;">Demo Use:</strong> {{ route.demo_use }}</p>
                        <a class="open-link" href="{{ route.route }}">Open Page</a>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Route Groups</h2>
                    <div class="grid-2">
                        {% for group in result.route_groups %}
                        <div class="card">
                            <h3>{{ group.group }}</h3>
                            {% for route in group.routes %}
                            <p><a class="open-link" href="{{ route }}">{{ route }}</a></p>
                            {% endfor %}
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result, checked_routes=checked_routes)


@app.route("/irlt-commercial-readiness/demo-flow/api")
@app.route("/irlt-commercial-readiness/navigation/api")
@app.route("/rlttrust/demo-flow/api")
def rlttrust_product_polish_demo_flow_api():
    return jsonify(_rlttrust_navigation_hardening_data())


@app.route("/irlt-commercial-readiness/routes-health/api")
@app.route("/rlttrust/routes-health/api")
def rlttrust_routes_health_api():
    data = _rlttrust_navigation_hardening_data()
    checked = []
    for item in data["canonical_routes"]:
        enriched = dict(item)
        enriched["exists"] = _rlttrust_route_exists(item["route"])
        enriched["health"] = "Available" if enriched["exists"] else "Check Route"
        checked.append(enriched)

    total = len(checked)
    available = sum(1 for item in checked if item["exists"])
    return jsonify({
        "total_routes_checked": total,
        "available_routes": available,
        "missing_or_check_routes": total - available,
        "readiness_percent": round((available / total) * 100) if total else 0,
        "routes": checked,
        "recommended_start": "/irlt-commercial-readiness/executive-summary",
        "recommended_home": "/irlt-commercial-readiness/launchpad",
        "recommended_close": "/irlt-commercial-readiness/pilot-roi",
        "governance_note": "Route health checks expected Flask routes registered in the current app instance."
    })

# ============================================================
# End Product Polish & Navigation Hardening
# ============================================================

'''

    # Add Buyer Demo Flow link to navigation where Executive Summary link exists.
    nav_marker = "RLTTRUST_NAV_DEMO_FLOW_HARDENING_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/executive-summary">Executive Summary</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_DEMO_FLOW_HARDENING_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/demo-flow">Demo Flow</a>',
            1
        )
        print("Added Demo Flow link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Product Polish & Navigation Hardening successfully.")

